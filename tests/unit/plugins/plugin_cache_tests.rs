//! Tests for PluginCache — pre-resolved plugin instances per proxy

use chrono::Utc;
use ferrum_edge::_test_support::{
    incremental_plugin_rebuild_targets_for_test, plugin_cache_with_real_ip_header_for_test,
    reconcile_fault_plugin_generations_for_test,
    request_deduplication_logical_keys_from_context_for_test, run_after_proxy_hooks_for_test,
    set_grpc_deadline_budget_for_test, transform_buffered_response_body_with_deadline_for_test,
    validate_correlation_id_composition_with_real_ip_header_for_test,
    validate_plugin_composition_candidate_with_real_ip_header_for_test,
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext,
    apply_initial_response_header_policies,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use ferrum_edge::{PluginCache, PluginCapabilities};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

struct LegacyAuthorizePlugin;

#[async_trait::async_trait]
impl Plugin for LegacyAuthorizePlugin {
    fn name(&self) -> &str {
        "legacy_authorize"
    }

    async fn authorize(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }
}

struct RawCorrelationClaimPlugin {
    claim: &'static str,
}

#[async_trait::async_trait]
impl Plugin for RawCorrelationClaimPlugin {
    fn name(&self) -> &str {
        "raw_correlation_claim"
    }

    fn correlation_id_header_name(&self) -> Option<&str> {
        Some(self.claim)
    }
}

struct StalledDeadlineResponseTransformer;

#[async_trait::async_trait]
impl Plugin for StalledDeadlineResponseTransformer {
    fn name(&self) -> &str {
        "stalled_deadline_response_transformer"
    }

    async fn transform_response_body_with_context(
        &self,
        _ctx: &mut RequestContext,
        _body: &[u8],
        _content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        std::future::pending().await
    }
}

/// Returns the minimal valid config for a given plugin name so that `create_plugin` succeeds.
pub(crate) fn minimal_plugin_config(plugin_name: &str) -> serde_json::Value {
    match plugin_name {
        "access_control" => json!({"allowed_consumers": ["testuser"]}),
        "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
        "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
        "geo_restriction" => json!({
            "db_path": "/nonexistent/GeoIP2-Country.mmdb",
            "allow_countries": ["US"]
        }),
        "rate_limiting" => json!({
            "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
        }),
        "request_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "response_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "request_size_limiting" => json!({"max_bytes": 1048576}),
        "waf" => json!({}),
        "response_size_limiting" => json!({"max_bytes": 1048576}),
        "ws_message_size_limiting" => json!({"max_frame_bytes": 65536}),
        "ws_rate_limiting" => json!({"frames_per_second": 100}),
        "body_validator" => json!({"required_fields": ["name"]}),
        "graphql" => json!({"max_depth": 100}),
        "grpc_method_router" => json!({"allow_methods": ["test.Svc/Method"]}),
        "grpc_deadline" => json!({"max_deadline_ms": 30000}),
        "ai_rate_limiter" => json!({"token_limit": 100000}),
        "cors" => json!({"allowed_origins": ["*"]}),
        "response_caching" => json!({"ttl_seconds": 60}),
        "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
        "tcp_logging" => json!({"host": "localhost", "port": 5140}),
        "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
        "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
        "jwks_auth" => {
            json!({"providers": [{"jwks_uri": "http://127.0.0.1:9/.well-known/jwks.json"}]})
        }
        "oauth2_introspection" => json!({
            "providers": [{
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
        "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
        "serverless_function" => {
            json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
        }
        "request_mirror" => json!({"mirror_host": "mirror.local"}),
        "load_testing" => json!({
            "key": "test-load-key-0123456789abcdef!!",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 8000
        }),
        "fault_injection" => json!({
            "abort": {"status_code": 503, "percentage": 100.0},
            "runtime_overlay_scope": "checkout"
        }),
        "udp_logging" => json!({"host": "127.0.0.1", "port": 9514}),
        "statsd_logging" => json!({"host": "127.0.0.1", "port": 8125}),
        "loki_logging" => json!({"endpoint_url": "http://localhost:3100/loki/api/v1/push"}),
        "kafka_logging" => json!({"broker_list": "localhost:9092", "topic": "test-logs"}),
        "request_deduplication" => json!({}),
        "response_mock" => json!({"rules": [{"path": "/test", "body": "mock"}]}),
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
        "ai_transcript_audit" => json!({
            "sink": {"endpoint_url": "https://localhost:9200/audit"}
        }),
        "ldap_auth" => json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        "spec_expose" => json!({"spec_url": "https://example.com/openapi.yaml"}),
        "api_chargeback" => {
            json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]})
        }
        "api_chargeback_sink" => json!({
            "clickhouse": {
                "url": "http://127.0.0.1:8123",
                "database": "default",
                "table": "ferrum_charge_events"
            },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}],
            "spool": {"enabled": false}
        }),
        "ai_response_guard" => json!({"pii_patterns": ["ssn"], "action": "reject"}),
        "ai_request_guard" => json!({"max_messages": 100}),
        "transaction_log_schema" => {
            json!({"schemas": {"default": {"summary_type": "both"}}})
        }
        "mesh_route_dispatch" => json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "canary"}
            }]
        }),
        "mesh_outbound_registry" => {
            json!({"registry": ["reviews.default.svc.cluster.local"]})
        }
        "opa" => json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": "ferrum/authz/allow"
        }),
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
    }
}

fn make_proxy(id: &str, listen_path: &str, plugin_ids: Vec<&str>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Proxy {}", id)),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".to_string(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: plugin_ids
            .into_iter()
            .map(|id| PluginAssociation {
                plugin_config_id: id.to_string(),
            })
            .collect(),

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_tcp_proxy(id: &str, plugin_ids: Vec<&str>) -> Proxy {
    let mut proxy = make_proxy(id, "/", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(15432);
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy
}

fn make_udp_proxy(id: &str, plugin_ids: Vec<&str>, scheme: BackendScheme) -> Proxy {
    let mut proxy = make_proxy(id, "/", plugin_ids);
    proxy.listen_path = None;
    proxy.listen_port = Some(15353);
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy
}

fn make_tcp_stream_context(ip: &str) -> StreamConnectionContext {
    StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        "p1".to_string(),
        Some("Proxy p1".to_string()),
        15432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    )
}

async fn run_tcp_connect_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut StreamConnectionContext,
) -> bool {
    for plugin in plugins {
        if matches!(
            plugin.on_stream_connect(ctx).await,
            PluginResult::Reject { .. }
        ) {
            ctx.release_admission_permits();
            return false;
        }
    }
    true
}

fn make_plugin_config(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    enabled: bool,
) -> PluginConfig {
    // Some plugins now require non-empty config to be created successfully.
    let config = minimal_plugin_config(plugin_name);
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

async fn run_before_proxy_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> PluginResult {
    let mut headers = HashMap::new();
    for plugin in plugins {
        match plugin.before_proxy(ctx, &mut headers).await {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

async fn run_request_received_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
) -> PluginResult {
    for plugin in plugins {
        match plugin.on_request_received(ctx).await {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

async fn run_after_proxy_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
) -> PluginResult {
    for plugin in plugins {
        match plugin.after_proxy(ctx, 200, response_headers).await {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

fn cors_config(
    id: &str,
    methods: &[&str],
    headers: &[&str],
    priority_override: Option<u16>,
) -> PluginConfig {
    let mut config = make_plugin_config_with_json(
        id,
        "cors",
        json!({
            "allowed_origins": ["https://trusted.example"],
            "allowed_methods": methods,
            "allowed_headers": headers
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    config.priority_override = priority_override;
    config
}

#[tokio::test]
async fn multiple_cors_instances_intersect_preflight_without_rejecting_actual_requests() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["permissive", "strict"])],
        vec![
            cors_config(
                "permissive",
                &["GET", "DELETE"],
                &["X-Shared", "Authorization"],
                None,
            ),
            cors_config("strict", &["GET"], &["X-Shared"], None),
        ],
    );
    let cache = PluginCache::new(&config).expect("composed CORS cache");
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    assert_eq!(
        plugins
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["cors", "cors", "__cors_finalizer"]
    );
    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    assert_eq!(
        grpc_plugins
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["cors", "cors", "__cors_finalizer"],
        "the deferred chain must retain CORS gRPC-Web protocol support"
    );

    let mut method_conflict = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/api".to_string(),
    );
    method_conflict.headers.extend(HashMap::from([
        ("origin".to_string(), "https://trusted.example".to_string()),
        (
            "access-control-request-method".to_string(),
            "DELETE".to_string(),
        ),
    ]));
    assert!(matches!(
        run_request_received_chain(&plugins, &mut method_conflict).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let mut header_conflict = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/api".to_string(),
    );
    header_conflict.headers.extend(HashMap::from([
        ("origin".to_string(), "https://trusted.example".to_string()),
        (
            "access-control-request-method".to_string(),
            "GET".to_string(),
        ),
        (
            "access-control-request-headers".to_string(),
            "Authorization".to_string(),
        ),
    ]));
    assert!(matches!(
        run_request_received_chain(&plugins, &mut header_conflict).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let mut allowed = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/api".to_string(),
    );
    allowed.headers.extend(HashMap::from([
        ("origin".to_string(), "https://trusted.example".to_string()),
        (
            "access-control-request-method".to_string(),
            "GET".to_string(),
        ),
        (
            "access-control-request-headers".to_string(),
            "X-Shared".to_string(),
        ),
    ]));
    match run_request_received_chain(&plugins, &mut allowed).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 204);
            assert_eq!(headers["access-control-allow-methods"], "GET");
            assert_eq!(headers["access-control-allow-headers"], "X-Shared");
        }
        other => panic!("intersected preflight must be answered once, got {other:?}"),
    }

    let mut actual = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/api".to_string(),
    );
    actual
        .headers
        .insert("origin".to_string(), "https://trusted.example".to_string());
    assert!(matches!(
        run_request_received_chain(&plugins, &mut actual).await,
        PluginResult::Continue
    ));
    let mut actual_response_headers = HashMap::new();
    assert!(matches!(
        run_after_proxy_chain(&plugins, &mut actual, &mut actual_response_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        actual_response_headers["access-control-allow-origin"],
        "https://trusted.example"
    );
    assert!(!actual_response_headers.contains_key("access-control-allow-methods"));
    assert!(!actual_response_headers.contains_key("access-control-allow-headers"));

    let mut actual_header = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    actual_header.headers.extend(HashMap::from([
        ("origin".to_string(), "https://trusted.example".to_string()),
        ("authorization".to_string(), "Bearer test".to_string()),
    ]));
    assert!(matches!(
        run_request_received_chain(&plugins, &mut actual_header).await,
        PluginResult::Continue
    ));

    let reversed = make_config(
        vec![make_proxy("p1", "/api", vec!["strict", "permissive"])],
        vec![
            cors_config("strict", &["GET"], &["X-Shared"], None),
            cors_config(
                "permissive",
                &["GET", "DELETE"],
                &["X-Shared", "Authorization"],
                None,
            ),
        ],
    );
    cache
        .rebuild(&reversed)
        .expect("rebuild reversed CORS cache");
    let reversed_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let mut reversed_delete = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/api".to_string(),
    );
    reversed_delete.headers.extend(HashMap::from([
        ("origin".to_string(), "https://trusted.example".to_string()),
        (
            "access-control-request-method".to_string(),
            "DELETE".to_string(),
        ),
    ]));
    assert!(matches!(
        run_request_received_chain(&reversed_plugins, &mut reversed_delete).await,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));

    let three = make_config(
        vec![make_proxy("p1", "/api", vec!["wide", "middle", "narrow"])],
        vec![
            cors_config("wide", &["GET", "POST"], &["X-A", "X-B"], None),
            cors_config("middle", &["GET", "POST"], &["X-B"], None),
            cors_config("narrow", &["GET"], &["X-B"], None),
        ],
    );
    let three_cache = PluginCache::new(&three).expect("three-instance CORS cache");
    assert_eq!(
        three_cache
            .get_plugins("p1")
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["cors", "cors", "cors", "__cors_finalizer"]
    );

    for ids in [vec!["origin-a", "origin-b"], vec!["origin-b", "origin-a"]] {
        let mut origin_a = cors_config("origin-a", &["GET"], &["X-Test"], None);
        origin_a.config["allowed_origins"] = json!(["https://a.example"]);
        let mut origin_b = cors_config("origin-b", &["GET"], &["X-Test"], None);
        origin_b.config["allowed_origins"] = json!(["https://b.example"]);
        let disjoint = make_config(
            vec![make_proxy("p1", "/api", ids)],
            vec![origin_a, origin_b],
        );
        let disjoint_cache = PluginCache::new(&disjoint).expect("disjoint CORS cache");
        let disjoint_plugins = disjoint_cache.get_plugins("p1");
        let mut request = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        request
            .headers
            .insert("origin".to_string(), "https://a.example".to_string());
        assert!(matches!(
            run_request_received_chain(&disjoint_plugins, &mut request).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn mixed_native_and_istio_empty_lists_apply_only_to_preflight() {
    let mut native = cors_config("native", &["GET"], &["Authorization"], None);
    native.config["exposed_headers"] = json!(["X-Shared", "X-Native"]);
    native.config["allow_credentials"] = json!(true);
    let mut istio = cors_config("istio", &[], &[], None);
    istio.config["exposed_headers"] = json!(["X-Shared"]);
    istio.config["unmatched_preflights"] = json!("forward");

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["native", "istio"])],
        vec![native, istio],
    );
    let cache = PluginCache::new(&config).expect("mixed native/Istio CORS cache");

    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        let plugins = cache.get_plugins_for_protocol("p1", protocol);
        let mut actual = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        actual.headers.extend(HashMap::from([
            ("origin".to_string(), "https://trusted.example".to_string()),
            ("authorization".to_string(), "Bearer test".to_string()),
        ]));
        assert!(matches!(
            run_request_received_chain(&plugins, &mut actual).await,
            PluginResult::Continue
        ));

        let mut response_headers = HashMap::new();
        assert!(matches!(
            run_after_proxy_chain(&plugins, &mut actual, &mut response_headers).await,
            PluginResult::Continue
        ));
        assert_eq!(
            response_headers["access-control-allow-origin"],
            "https://trusted.example"
        );
        assert_eq!(
            response_headers["access-control-expose-headers"],
            "X-Shared"
        );
        assert!(!response_headers.contains_key("access-control-allow-credentials"));
        assert!(!response_headers.contains_key("access-control-allow-methods"));
        assert!(!response_headers.contains_key("access-control-allow-headers"));

        let mut preflight = RequestContext::new(
            "127.0.0.1".to_string(),
            "OPTIONS".to_string(),
            "/api".to_string(),
        );
        preflight.headers.extend(HashMap::from([
            ("origin".to_string(), "https://trusted.example".to_string()),
            (
                "access-control-request-method".to_string(),
                "GET".to_string(),
            ),
            (
                "access-control-request-headers".to_string(),
                "Authorization".to_string(),
            ),
        ]));
        assert!(matches!(
            run_request_received_chain(&plugins, &mut preflight).await,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ));
    }
}

#[test]
fn multiple_cors_instances_must_remain_contiguous() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-a", "ip", "cors-b"])],
        vec![
            cors_config("cors-a", &["GET"], &["X-Test"], Some(100)),
            make_plugin_config_with_priority(
                "ip",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(150),
            ),
            cors_config("cors-b", &["GET"], &["X-Test"], Some(200)),
        ],
    );
    let err = PluginCache::new(&config)
        .err()
        .expect("interleaved CORS instances must fail cache construction");
    assert!(
        err.contains("cors instances must remain contiguous"),
        "got: {err}"
    );
}

#[test]
fn stream_only_interloper_is_ignored_by_cors_contiguity_on_full_rebuild() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-a", "udp", "cors-b"])],
        vec![
            cors_config("cors-a", &["GET"], &["X-Test"], Some(100)),
            make_plugin_config_with_priority(
                "udp",
                "udp_rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(150),
            ),
            cors_config("cors-b", &["GET"], &["X-Test"], Some(200)),
        ],
    );
    let cache = PluginCache::new(&config).expect("stream-only CORS interloper is valid");

    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        assert_eq!(
            cache
                .get_plugins_for_protocol("p1", protocol)
                .iter()
                .map(|plugin| plugin.name())
                .collect::<Vec<_>>(),
            vec!["cors", "cors", "__cors_finalizer"]
        );
    }
    assert_eq!(
        cache
            .get_plugins_for_protocol("p1", ProxyProtocol::Udp)
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["udp_rate_limiting"]
    );
}

#[test]
fn cors_delta_reload_ignores_stream_interloper_and_rejects_http_interloper() {
    let initial = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-a", "udp"])],
        vec![
            cors_config("cors-a", &["GET"], &["X-Test"], Some(100)),
            make_plugin_config_with_priority(
                "udp",
                "udp_rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(150),
            ),
        ],
    );
    let cache = PluginCache::new(&initial).expect("initial cache");
    let stream_interleaved = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-a", "udp", "cors-b"])],
        vec![
            cors_config("cors-a", &["GET"], &["X-Test"], Some(100)),
            make_plugin_config_with_priority(
                "udp",
                "udp_rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(150),
            ),
            cors_config("cors-b", &["GET"], &["X-Test"], Some(200)),
        ],
    );
    let stream_delta = ConfigDelta::compute(&initial, &stream_interleaved);
    let stream_proxy_ids =
        stream_delta.proxy_ids_needing_plugin_rebuild(&initial, &stream_interleaved);
    cache
        .apply_delta(
            &stream_interleaved,
            &stream_proxy_ids,
            &stream_delta.removed_proxy_ids,
            stream_delta.global_plugin_configs_changed,
        )
        .expect("delta reload must ignore stream-only interloper");
    let last_good = cache.get_plugins("p1");
    assert_eq!(
        last_good
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["cors", "udp_rate_limiting", "cors", "__cors_finalizer"]
    );

    let http_interleaved = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-a", "ip", "cors-b"])],
        vec![
            cors_config("cors-a", &["GET"], &["X-Test"], Some(100)),
            make_plugin_config_with_priority(
                "ip",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(150),
            ),
            cors_config("cors-b", &["GET"], &["X-Test"], Some(200)),
        ],
    );
    let http_delta = ConfigDelta::compute(&stream_interleaved, &http_interleaved);
    let http_proxy_ids =
        http_delta.proxy_ids_needing_plugin_rebuild(&stream_interleaved, &http_interleaved);
    let err = cache
        .apply_delta(
            &http_interleaved,
            &http_proxy_ids,
            &http_delta.removed_proxy_ids,
            http_delta.global_plugin_configs_changed,
        )
        .expect_err("HTTP-overlapping interloper must reject delta reload");
    assert!(
        err.contains("cors instances must remain contiguous in HTTP/gRPC chains"),
        "got: {err}"
    );
    let after_reject = cache.get_plugins("p1");
    assert_eq!(after_reject.len(), last_good.len());
    assert!(Arc::ptr_eq(&after_reject[0], &last_good[0]));
}

#[test]
fn rejected_cors_reload_retains_the_last_good_snapshot() {
    let valid = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-wide", "cors-narrow"])],
        vec![
            cors_config("cors-wide", &["GET", "DELETE"], &["X-Test"], None),
            cors_config("cors-narrow", &["GET"], &["X-Test"], None),
        ],
    );
    let cache = PluginCache::new(&valid).expect("initial CORS cache");
    let before = cache.get_plugins("p1");

    let mut invalid = valid.clone();
    invalid.plugin_configs[0].config = json!({"origins": ["*"]});
    invalid.plugin_configs[0].updated_at = Utc::now();
    assert!(cache.rebuild(&invalid).is_err());

    let after = cache.get_plugins("p1");
    assert_eq!(after.len(), before.len());
    assert!(Arc::ptr_eq(&after[0], &before[0]));
}

#[test]
fn cors_delta_reload_installs_and_removes_the_aggregate_boundary() {
    let initial = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-wide"])],
        vec![cors_config(
            "cors-wide",
            &["GET", "DELETE"],
            &["X-Test"],
            None,
        )],
    );
    let cache = PluginCache::new(&initial).expect("initial single-CORS cache");
    assert_eq!(
        cache
            .get_plugins("p1")
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["cors"]
    );

    let composed = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-wide", "cors-narrow"])],
        vec![
            cors_config("cors-wide", &["GET", "DELETE"], &["X-Test"], None),
            cors_config("cors-narrow", &["GET"], &["X-Test"], None),
        ],
    );
    let composed_delta = ConfigDelta::compute(&initial, &composed);
    let composed_proxy_ids = composed_delta.proxy_ids_needing_plugin_rebuild(&initial, &composed);
    cache
        .apply_delta(
            &composed,
            &composed_proxy_ids,
            &composed_delta.removed_proxy_ids,
            composed_delta.global_plugin_configs_changed,
        )
        .expect("install composed CORS chain through delta reload");
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        assert_eq!(
            cache
                .get_plugins_for_protocol("p1", protocol)
                .iter()
                .map(|plugin| plugin.name())
                .collect::<Vec<_>>(),
            vec!["cors", "cors", "__cors_finalizer"]
        );
    }

    let reduced = make_config(
        vec![make_proxy("p1", "/api", vec!["cors-narrow"])],
        vec![cors_config("cors-narrow", &["GET"], &["X-Test"], None)],
    );
    let reduced_delta = ConfigDelta::compute(&composed, &reduced);
    let reduced_proxy_ids = reduced_delta.proxy_ids_needing_plugin_rebuild(&composed, &reduced);
    cache
        .apply_delta(
            &reduced,
            &reduced_proxy_ids,
            &reduced_delta.removed_proxy_ids,
            reduced_delta.global_plugin_configs_changed,
        )
        .expect("remove composed CORS boundary through delta reload");
    for protocol in [ProxyProtocol::Http, ProxyProtocol::Grpc] {
        assert_eq!(
            cache
                .get_plugins_for_protocol("p1", protocol)
                .iter()
                .map(|plugin| plugin.name())
                .collect::<Vec<_>>(),
            vec!["cors"],
            "a stale deferred wrapper/finalizer must not survive the reload"
        );
    }
}

#[tokio::test]
async fn mesh_route_dispatch_reject_unmatched_is_aggregated_across_instances() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["get-route", "post-route"])],
        vec![
            make_plugin_config_with_json(
                "get-route",
                "mesh_route_dispatch",
                json!({
                    "rules": [{
                        "match": {"methods": ["GET"]},
                        "destination": {"upstream_id": "get-backend"}
                    }],
                    "reject_unmatched": true
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "post-route",
                "mesh_route_dispatch",
                json!({
                    "rules": [{
                        "match": {"methods": ["POST"]},
                        "destination": {"upstream_id": "post-backend"}
                    }],
                    "reject_unmatched": true
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).expect("plugin cache");
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);

    for (method, expected_upstream) in [("GET", "get-backend"), ("POST", "post-backend")] {
        let mut request = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api".to_string(),
        );
        let result = run_before_proxy_chain(&plugins, &mut request).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "{method} must survive the other instance's local miss, got {result:?}"
        );
        assert_eq!(
            request.route_override_upstream_id.as_deref(),
            Some(expected_upstream)
        );
    }

    let mut unmatched = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/api".to_string(),
    );
    match run_before_proxy_chain(&plugins, &mut unmatched).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 404),
        other => panic!("an aggregate miss must fail closed, got {other:?}"),
    }

    let mut earlier_override = RequestContext::new(
        "127.0.0.1".to_string(),
        "DELETE".to_string(),
        "/api".to_string(),
    );
    earlier_override.route_override_upstream_id = Some("mcp-selected".to_string());
    let result = run_before_proxy_chain(&plugins, &mut earlier_override).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "an earlier successful route override must survive aggregate local misses"
    );
    assert_eq!(
        earlier_override.route_override_upstream_id.as_deref(),
        Some("mcp-selected")
    );
}

#[test]
fn mesh_route_dispatch_rejects_priority_interleaving_before_fail_closed_finalization() {
    let first_route = make_plugin_config_with_json(
        "first-route",
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "get-backend"}
            }],
            "reject_unmatched": true
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    let mut second_route = make_plugin_config_with_json(
        "second-route",
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"methods": ["POST"]},
                "destination": {"upstream_id": "post-backend"}
            }],
            "reject_unmatched": true
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    second_route.priority_override = Some(3040);
    let response_mock = make_plugin_config_with_json(
        "mock",
        "response_mock",
        json!({
            "rules": [{"path": "/api", "status_code": 200, "body": "mocked"}]
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["first-route", "mock", "second-route"],
        )],
        vec![first_route, response_mock, second_route],
    );

    let error = match PluginCache::new(&config) {
        Ok(_) => panic!("an interleaved short-circuit plugin must reject cache construction"),
        Err(error) => error,
    };
    assert!(error.contains("must remain contiguous"), "got: {error}");
    assert!(error.contains("priority overrides"), "got: {error}");
    assert!(error.contains("HTTP-family"), "got: {error}");
}

#[test]
fn mesh_route_dispatch_ignores_non_http_interleaving_when_finalizing() {
    let first_route = make_plugin_config_with_json(
        "first-route",
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "get-backend"}
            }],
            "reject_unmatched": true
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    let mut tcp_only = make_plugin_config(
        "tcp-throttle",
        "tcp_connection_throttle",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    tcp_only.priority_override = Some(3030);
    let mut second_route = make_plugin_config_with_json(
        "second-route",
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"methods": ["POST"]},
                "destination": {"upstream_id": "post-backend"}
            }],
            "reject_unmatched": true
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    second_route.priority_override = Some(3040);
    let config = make_config(
        vec![make_tcp_proxy(
            "p1",
            vec!["first-route", "tcp-throttle", "second-route"],
        )],
        vec![first_route, tcp_only, second_route],
    );

    let cache = PluginCache::new(&config)
        .expect("TCP-only plugins do not interleave the HTTP-family execution chain");
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<_> = http_plugins.iter().map(|plugin| plugin.name()).collect();
    assert_eq!(
        http_names,
        [
            "mesh_route_dispatch",
            "mesh_route_dispatch",
            "__mesh_route_dispatch_finalizer"
        ]
    );

    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<_> = tcp_plugins.iter().map(|plugin| plugin.name()).collect();
    assert_eq!(tcp_names, ["tcp_connection_throttle"]);
}

fn plugin_ptr_by_name(plugins: &[Arc<dyn Plugin>], name: &str) -> usize {
    let plugin = plugins
        .iter()
        .find(|plugin| plugin.name() == name)
        .unwrap_or_else(|| panic!("expected plugin named {name}"));
    Arc::as_ptr(plugin) as *const () as usize
}

// ---- Plugin caching correctness ----

#[test]
fn test_global_plugins_returned_for_all_proxies() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1_plugins = cache.get_plugins("p1");
    let p2_plugins = cache.get_plugins("p2");

    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "stdout_logging");
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "stdout_logging");
}

#[test]
fn test_prometheus_metrics_requires_global_and_unique_registry_owner() {
    let scoped = make_config(
        vec![make_proxy("p1", "/api", vec!["prometheus"])],
        vec![make_plugin_config(
            "prometheus",
            "prometheus_metrics",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let scoped_error = PluginCache::new(&scoped)
        .err()
        .expect("plugin cache must reject a scoped registry owner");
    assert!(scoped_error.contains("must have scope 'global'"));

    let duplicate = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            make_plugin_config(
                "prometheus-a",
                "prometheus_metrics",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config(
                "prometheus-b",
                "prometheus_metrics",
                PluginScope::Global,
                None,
                true,
            ),
        ],
    );
    let duplicate_error = PluginCache::new(&duplicate)
        .err()
        .expect("plugin cache must reject competing registry owners");
    assert!(duplicate_error.contains("at most one enabled global instance"));
}

#[test]
fn test_api_chargeback_rejects_duplicate_proxy_scoped_instances() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["charge-a", "charge-b"])],
        vec![
            make_plugin_config(
                "charge-a",
                "api_chargeback",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "charge-b",
                "api_chargeback",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("two proxy-scoped chargeback instances must be rejected");
    assert!(
        error.contains("at most one effective instance per proxy"),
        "unexpected error: {error}"
    );
    assert!(error.contains("charge-a") && error.contains("charge-b"));
}

#[test]
fn test_api_chargeback_rejects_duplicate_global_instances_without_proxies() {
    let config = make_config(
        vec![],
        vec![
            make_plugin_config(
                "charge-global-a",
                "api_chargeback",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config(
                "charge-global-b",
                "api_chargeback",
                PluginScope::Global,
                None,
                true,
            ),
        ],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("two process-global chargeback instances must be rejected");
    assert!(
        error.contains("at most one enabled global instance"),
        "unexpected error: {error}"
    );
    assert!(error.contains("charge-global-a") && error.contains("charge-global-b"));
}

#[test]
fn test_api_chargeback_rejects_duplicate_proxy_group_instances() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["group-a", "group-b"])],
        vec![
            make_plugin_config(
                "group-a",
                "api_chargeback",
                PluginScope::ProxyGroup,
                None,
                true,
            ),
            make_plugin_config(
                "group-b",
                "api_chargeback",
                PluginScope::ProxyGroup,
                None,
                true,
            ),
        ],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("two proxy-group chargeback instances must be rejected");
    assert!(
        error.contains("at most one effective instance per proxy"),
        "unexpected error: {error}"
    );
    assert!(error.contains("group-a") && error.contains("group-b"));
}

#[test]
fn test_api_chargeback_rejects_mixed_proxy_and_proxy_group_instances() {
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["charge-proxy", "charge-group"],
        )],
        vec![
            make_plugin_config(
                "charge-proxy",
                "api_chargeback",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "charge-group",
                "api_chargeback",
                PluginScope::ProxyGroup,
                None,
                true,
            ),
        ],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("mixed scoped chargeback instances must be rejected");
    assert!(
        error.contains("at most one effective instance per proxy"),
        "unexpected error: {error}"
    );
}

#[test]
fn test_api_chargeback_rejects_conflicting_shared_tunables_across_proxies() {
    let mut owner = make_plugin_config(
        "charge-owner",
        "api_chargeback",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    owner.config = json!({
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "render_cache_ttl_seconds": 5,
        "cleanup_interval_seconds": 0
    });
    let mut sibling = make_plugin_config(
        "charge-sibling",
        "api_chargeback",
        PluginScope::Proxy,
        Some("p2"),
        true,
    );
    sibling.config = json!({
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.02}],
        "currency": "EUR",
        "render_cache_ttl_seconds": 30,
        "cleanup_interval_seconds": 0
    });
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["charge-owner"]),
            make_proxy("p2", "/web", vec!["charge-sibling"]),
        ],
        vec![owner, sibling],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("disagreeing shared tunables must be rejected");
    assert!(
        error.contains("shared render/cleanup tunables must match"),
        "unexpected error: {error}"
    );
    assert!(error.contains("charge-owner") && error.contains("charge-sibling"));
}

#[test]
fn test_api_chargeback_allows_one_instance_per_proxy_with_mixed_currency() {
    let mut usd = make_plugin_config(
        "charge-usd",
        "api_chargeback",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    usd.config = json!({
        "currency": "USD",
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
        "cleanup_interval_seconds": 0
    });
    let mut eur = make_plugin_config(
        "charge-eur",
        "api_chargeback",
        PluginScope::Proxy,
        Some("p2"),
        true,
    );
    eur.config = json!({
        "currency": "EUR",
        "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.02}],
        "cleanup_interval_seconds": 0
    });
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["charge-usd"]),
            make_proxy("p2", "/web", vec!["charge-eur"]),
        ],
        vec![usd, eur],
    );
    let cache = PluginCache::new(&config).expect("one chargeback per proxy is valid");
    assert_eq!(
        cache
            .get_plugins("p1")
            .iter()
            .filter(|plugin| plugin.name() == "api_chargeback")
            .count(),
        1
    );
    assert_eq!(
        cache
            .get_plugins("p2")
            .iter()
            .filter(|plugin| plugin.name() == "api_chargeback")
            .count(),
        1
    );
}

#[test]
fn test_single_prometheus_metrics_instance_is_shared_once_across_protocols() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![make_plugin_config(
            "prometheus",
            "prometheus_metrics",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).expect("one global registry owner is valid");
    let p1_http = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let p1_tcp = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let p2_http = cache.get_plugins_for_protocol("p2", ProxyProtocol::Http);

    assert_eq!(
        p1_http
            .iter()
            .filter(|plugin| plugin.name() == "prometheus_metrics")
            .count(),
        1
    );
    assert_eq!(
        p1_tcp
            .iter()
            .filter(|plugin| plugin.name() == "prometheus_metrics")
            .count(),
        1
    );
    assert_eq!(
        p2_http
            .iter()
            .filter(|plugin| plugin.name() == "prometheus_metrics")
            .count(),
        1
    );
    let p1_http_prometheus = p1_http
        .iter()
        .find(|plugin| plugin.name() == "prometheus_metrics")
        .expect("HTTP plugin");
    let p1_tcp_prometheus = p1_tcp
        .iter()
        .find(|plugin| plugin.name() == "prometheus_metrics")
        .expect("TCP plugin");
    let p2_http_prometheus = p2_http
        .iter()
        .find(|plugin| plugin.name() == "prometheus_metrics")
        .expect("second proxy HTTP plugin");
    assert!(Arc::ptr_eq(p1_http_prometheus, p1_tcp_prometheus));
    assert!(Arc::ptr_eq(p1_http_prometheus, p2_http_prometheus));
}

#[test]
fn test_proxy_scoped_plugins_override_globals_of_same_name() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    // Should have 1 plugin (proxy-scoped replaces global of same name)
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_invalid_optional_proxy_scoped_plugin_still_shadows_global() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["ps1"]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config_with_json(
                "ps1",
                "stdout_logging",
                json!("bad-config"),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert!(
        cache.get_plugins("p1").is_empty(),
        "failed proxy-scoped optional plugin must shadow the same-name global"
    );
    assert_eq!(cache.get_plugins("p2").len(), 1);
    assert_eq!(cache.get_plugins("p2")[0].name(), "stdout_logging");
}

#[test]
fn test_disabled_plugins_excluded() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            false, // disabled
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 0);
}

#[test]
fn test_removed_security_plugin_fails_closed() {
    for plugin_name in ["oauth2_auth", "semantic_ai_firewall"] {
        let config = make_config(
            vec![make_proxy("p1", "/api", vec![])],
            vec![make_plugin_config(
                "legacy-auth",
                plugin_name,
                PluginScope::Global,
                None,
                true,
            )],
        );

        let err = match PluginCache::new(&config) {
            Ok(_) => panic!("expected fail-closed error for {plugin_name}"),
            Err(e) => e,
        };
        // PluginCache::new wraps per-plugin errors into an aggregate string
        // ("Gateway startup aborted: N plugin config(s) failed validation")
        // and emits the per-plugin "Removed security plugin ..."
        // message via `error!` (visible in test logs but not the returned
        // string). The wrapper format is the load-bearing fail-closed signal
        // for callers; the specific plugin name is preserved in the log
        // record. Assert that startup is aborted because of a security
        // plugin failure — that is what guards an upgrade that silently
        // drops auth.
        assert!(
            err.contains("security plugin"),
            "expected security-plugin fail-closed error for {plugin_name}, got {err:?}"
        );
        assert!(
            err.contains("aborted") || err.contains("rejected"),
            "expected aborted/rejected wrapper around the security failure for {plugin_name}, got {err:?}"
        );
    }
}

#[test]
fn test_builtin_plugin_registrations_are_unique_and_policy_backed() {
    use ferrum_edge::plugins::{
        BUILTIN_PLUGIN_REGISTRATIONS, PluginFailurePolicy, available_plugins, plugin_failure_policy,
    };

    let mut seen = std::collections::HashSet::new();
    let available = available_plugins();
    let mut saw_fail_closed = false;
    let mut saw_keep_last_known_good = false;
    let mut saw_optional_fail_open = false;

    for registration in BUILTIN_PLUGIN_REGISTRATIONS {
        assert!(
            seen.insert(registration.name),
            "duplicate built-in plugin registration for {}",
            registration.name
        );
        assert!(
            available.contains(&registration.name),
            "{} missing from available_plugins()",
            registration.name
        );
        assert_eq!(
            plugin_failure_policy(registration.name),
            Some(registration.failure_policy),
            "{} failure policy must come from registration metadata",
            registration.name
        );

        match registration.failure_policy {
            PluginFailurePolicy::FailClosed => saw_fail_closed = true,
            PluginFailurePolicy::KeepLastKnownGood => saw_keep_last_known_good = true,
            PluginFailurePolicy::OptionalFailOpen => saw_optional_fail_open = true,
        }
    }

    assert!(saw_fail_closed);
    assert!(saw_keep_last_known_good);
    assert!(saw_optional_fail_open);
    assert_eq!(
        plugin_failure_policy("api_chargeback"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
    assert_eq!(
        plugin_failure_policy("api_chargeback_sink"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
}

#[test]
fn test_optional_custom_plugin_validation_failure_is_omitted() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_audit_plugin") {
        return;
    }

    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("example_audit_plugin"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::OptionalFailOpen)
    );

    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "optional-audit",
            "example_audit_plugin",
            json!({"log_request_headers": "not-a-bool"}),
            PluginScope::Global,
            None,
        )],
    );

    let cache = PluginCache::new(&config).expect("optional plugin failure should not abort cache");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "failed optional custom plugin must be omitted"
    );
}

#[test]
fn test_ws_frame_logging_invalid_config_is_omitted_on_admission_and_reload() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("ws_frame_logging"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::OptionalFailOpen)
    );

    let invalid = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws-log"])],
        vec![make_plugin_config_with_json(
            "ws-log",
            "ws_frame_logging",
            json!({"log_levle": "debug"}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&invalid)
        .expect("OptionalFailOpen must admit snapshot despite bad config");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "invalid ws_frame_logging must be omitted from published cache"
    );
    assert!(
        !cache.requires_ws_frame_hooks("p1"),
        "omitted logger must not force frame-hook selection"
    );

    let valid = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws-log"])],
        vec![make_plugin_config_with_json(
            "ws-log",
            "ws_frame_logging",
            json!({}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&valid).expect("empty ws_frame_logging config is valid");
    assert_eq!(
        cache
            .get_plugins("p1")
            .iter()
            .map(|plugin| plugin.name())
            .collect::<Vec<_>>(),
        vec!["ws_frame_logging"]
    );
    assert!(cache.requires_ws_frame_hooks("p1"));

    let oversize = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws-log"])],
        vec![make_plugin_config_with_json(
            "ws-log",
            "ws_frame_logging",
            json!({
                "include_payload_preview": true,
                "payload_preview_bytes": 999999999
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let delta = ConfigDelta::compute(&valid, &oversize);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&valid, &oversize);
    cache
        .apply_delta(
            &oversize,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("OptionalFailOpen reload must publish by omitting the bad instance");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "reload must omit oversized payload_preview_bytes rather than clamp"
    );
    assert!(!cache.requires_ws_frame_hooks("p1"));
}

#[test]
fn test_unknown_enabled_plugin_rejects_initial_cache() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "unknown-1",
            "unknown_enforcer",
            PluginScope::Global,
            None,
            true,
        )],
    );

    let err = match PluginCache::new(&config) {
        Ok(_) => panic!("unknown enabled plugin must fail closed"),
        Err(err) => err,
    };
    assert!(err.contains("Unknown enabled plugin"), "{err}");
    assert!(err.contains("unknown_enforcer"), "{err}");
    assert!(err.contains("unknown-1"), "{err}");
}

#[test]
fn test_disabled_unknown_plugin_is_ignored() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["disabled-unknown"])],
        vec![make_plugin_config(
            "disabled-unknown",
            "unknown_enforcer",
            PluginScope::Proxy,
            Some("p1"),
            false,
        )],
    );

    let cache = PluginCache::new(&config).expect("disabled unknown plugin should be ignored");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "disabled plugin configs must not be instantiated"
    );
}

#[test]
fn test_registered_custom_plugin_is_resolved_before_unknown_rejection() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }

    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "custom-1",
            "example_plugin",
            json!({"header_value": "custom-ok"}),
            PluginScope::Global,
            None,
        )],
    );

    let cache = PluginCache::new(&config).expect("registered custom plugin should be accepted");
    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "example_plugin");
}

#[test]
fn test_example_plugin_rebuild_rejects_malformed_config_and_keeps_prior_instance() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }

    let valid = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "custom-1",
            "example_plugin",
            json!({"header_value": "accepted-generation"}),
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid example plugin cache");
    let before = cache.get_plugins("p1");
    assert_eq!(before.len(), 1);

    let malformed = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "custom-1",
            "example_plugin",
            json!({"header_value": 7}),
            PluginScope::Global,
            None,
        )],
    );
    let error = cache
        .rebuild(&malformed)
        .expect_err("malformed example config must reject cache publication");
    assert!(error.contains("example_plugin"), "got: {error}");

    let after = cache.get_plugins("p1");
    assert_eq!(after.len(), 1);
    assert!(
        Arc::ptr_eq(&before[0], &after[0]),
        "KeepLastKnownGood must retain the accepted example plugin instance"
    );
}

#[test]
fn test_response_caching_unknown_key_reload_keeps_last_known_good() {
    let valid = make_config(
        vec![make_proxy("p1", "/api", vec!["rc-1"])],
        vec![make_plugin_config_with_json(
            "rc-1",
            "response_caching",
            json!({
                "ttl_seconds": 60,
                "vary_by_headers": ["x-tenant"],
                "cache_key_include_consumer": true
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid response_caching must admit");
    let before = cache.get_plugins("p1");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].name(), "response_caching");

    let malformed = make_config(
        vec![make_proxy("p1", "/api", vec!["rc-1"])],
        vec![make_plugin_config_with_json(
            "rc-1",
            "response_caching",
            json!({
                "ttl_seconds": 60,
                "vary_by_header": ["x-tenant"],
                "cache_key_include_consumr": true
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let error = cache
        .rebuild(&malformed)
        .expect_err("unknown response_caching keys must reject reload");
    assert!(
        error.contains("unknown configuration key"),
        "unexpected reload error: {error}"
    );
    assert!(
        error.contains("'config.vary_by_header'"),
        "reload error must path-qualify Vary typo: {error}"
    );
    assert!(
        error.contains("'config.cache_key_include_consumr'"),
        "reload error must path-qualify consumer typo: {error}"
    );

    let after = cache.get_plugins("p1");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name(), "response_caching");
    assert!(
        Arc::ptr_eq(&before[0], &after[0]),
        "KeepLastKnownGood must retain the accepted response_caching instance"
    );
}

#[tokio::test]
async fn test_tcp_logging_unknown_key_reload_keeps_last_known_good() {
    let valid = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "tcp-logging-1",
            "tcp_logging",
            json!({"host": "127.0.0.1", "port": 5140, "tls": false}),
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid tcp_logging must admit");
    let before = cache.get_plugins("p1");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].name(), "tcp_logging");

    let typo = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "tcp-logging-1",
            "tcp_logging",
            json!({"host": "127.0.0.1", "port": 5140, "tlls": true}),
            PluginScope::Global,
            None,
        )],
    );
    let error = cache
        .rebuild(&typo)
        .expect_err("unknown tcp_logging key must reject cache publication");
    assert!(error.contains("config.tlls"), "got: {error}");

    let after = cache.get_plugins("p1");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name(), "tcp_logging");
    assert!(
        Arc::ptr_eq(&before[0], &after[0]),
        "KeepLastKnownGood must retain the accepted tcp_logging instance"
    );
}

#[test]
fn test_compression_rebuild_rejects_unknown_keys_and_keeps_last_known_good() {
    let valid = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "compression-1",
            "compression",
            json!({"min_content_length": 512, "gzip_level": 4}),
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid compression cache");
    let before = cache.get_plugins("p1");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].name(), "compression");

    let malformed = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "compression-1",
            "compression",
            json!({"min_content_lenght": 4096}),
            PluginScope::Global,
            None,
        )],
    );
    let error = cache
        .rebuild(&malformed)
        .expect_err("unknown compression key must reject cache publication");
    assert!(error.contains("config.min_content_lenght"), "got: {error}");

    let after = cache.get_plugins("p1");
    assert_eq!(after.len(), 1);
    assert!(
        Arc::ptr_eq(&before[0], &after[0]),
        "KeepLastKnownGood must retain the accepted compression instance"
    );
}

#[test]
fn test_proxy_alerts_rebuild_omits_malformed_optional_values() {
    let valid_cfg = json!({
        "channels": {
            "ops": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/x"
            }
        },
        "rules": [{
            "name": "errors",
            "type": "error_rate",
            "status_codes": [500],
            "threshold_percent": 5.0,
            "channels": ["ops"]
        }]
    });
    let valid = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "pa-1",
            "proxy_alerts",
            valid_cfg,
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid proxy_alerts cache");
    let before = cache.get_plugins("p1");
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].name(), "proxy_alerts");

    let malformed = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "pa-1",
            "proxy_alerts",
            json!({
                "enabled": "false",
                "max_concurrent_dispatches": 0,
                "quiet_hours_utc": null,
                "channels": {
                    "ops": {
                        "type": "slack",
                        "webhook_url": "https://hooks.slack.com/x"
                    }
                },
                "rules": [{
                    "name": "errors",
                    "type": "error_rate",
                    "status_codes": [500],
                    "threshold_percent": 5.0,
                    "min_request_count": "100",
                    "channels": ["ops"]
                }]
            }),
            PluginScope::Global,
            None,
        )],
    );
    cache
        .rebuild(&malformed)
        .expect("malformed optional proxy_alerts config must not abort cache publication");

    let after = cache.get_plugins("p1");
    assert!(
        after.is_empty(),
        "OptionalFailOpen must omit malformed proxy_alerts instead of retaining it"
    );
}

#[test]
fn test_rebuild_rejects_malformed_body_validator_and_keeps_prior_cache() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let pre_rebuild = cache.get_plugins("p1");
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc2"])],
        vec![make_plugin_config_with_json(
            "pc2",
            "body_validator",
            json!({}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    let err = cache
        .rebuild(&config2)
        .expect_err("malformed body_validator must reject reload");
    assert!(err.contains("body_validator"), "{err}");
    assert!(err.contains("pc2"), "{err}");
    assert!(err.contains("proxy_id=p1"), "{err}");

    let post_failure = cache.get_plugins("p1");
    assert_eq!(post_failure.len(), 1);
    assert_eq!(post_failure[0].name(), "stdout_logging");
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");

    let config3 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g2",
            "transaction_debugger",
            PluginScope::Global,
            None,
            true,
        )],
    );
    cache
        .rebuild(&config3)
        .expect("valid reload after a rejection should replace cache");
    let post_success = cache.get_plugins("p1");
    assert_eq!(post_success.len(), 1);
    assert_eq!(post_success[0].name(), "transaction_debugger");
}

#[test]
fn test_rebuild_produces_updated_plugin_set() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "stdout_logging");

    // Rebuild with different plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g2",
            "transaction_debugger",
            PluginScope::Global,
            None,
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();

    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "transaction_debugger");
}

#[test]
fn test_request_view_stays_on_single_generation_after_rebuild() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let request_view = cache.request_view("p1", ProxyProtocol::Http);

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2", "ps3"])],
        vec![
            make_plugin_config(
                "ps1",
                "request_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "ps2",
                "body_validator",
                json!({"required_fields": ["name"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "ps3",
                "response_size_limiting",
                json!({"max_bytes": 1048576, "require_buffered_check": true}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    cache.rebuild(&config2).unwrap();

    let view_plugins = request_view.plugins();
    let view_names: Vec<&str> = view_plugins.iter().map(|p| p.name()).collect();
    assert_eq!(view_names, vec!["stdout_logging"]);
    assert!(!request_view.requires_request_body_buffering());
    assert!(!request_view.requires_response_body_buffering());
    assert!(
        !request_view
            .capabilities()
            .has(PluginCapabilities::MODIFIES_REQUEST_HEADERS)
    );

    let current_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let current_names: Vec<&str> = current_plugins.iter().map(|p| p.name()).collect();
    assert!(current_names.contains(&"request_transformer"));
    assert!(current_names.contains(&"body_validator"));
    assert!(current_names.contains(&"response_size_limiting"));
    assert!(cache.requires_request_body_buffering("p1"));
    assert!(cache.requires_response_body_buffering("p1"));
    assert!(
        cache
            .get_capabilities("p1", ProxyProtocol::Http)
            .has(PluginCapabilities::MODIFIES_REQUEST_HEADERS)
    );
}

#[tokio::test]
async fn test_request_view_precomputes_response_committed_hook_capability() {
    let mut audit = make_plugin_config_with_json(
        "audit",
        "ai_transcript_audit",
        json!({
            "capture": { "request": true, "response": true },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/ingest"
            }
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    audit.priority_override = Some(125);
    let config = make_config(vec![make_proxy("p1", "/api", vec!["audit"])], vec![audit]);
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("p1", ProxyProtocol::Http);

    assert!(
        view.capabilities()
            .has(PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK)
    );
    assert_eq!(view.response_committed_plugins().len(), 1);
    assert_eq!(
        view.response_committed_plugins()[0].name(),
        "ai_transcript_audit"
    );
    assert_eq!(view.response_committed_plugins()[0].priority(), 125);
    assert!(
        !cache
            .request_view("missing", ProxyProtocol::Http)
            .capabilities()
            .has(PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK)
    );
}

#[test]
fn test_request_view_precomputes_grpc_deadline_policy_plugins() {
    let mut deadline = make_plugin_config_with_json(
        "deadline",
        "grpc_deadline",
        json!({"default_deadline_ms": 1000}),
        PluginScope::Proxy,
        Some("p1"),
    );
    deadline.priority_override = Some(120);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["deadline"])],
        vec![deadline],
    );
    let cache = PluginCache::new(&config).unwrap();

    let grpc_view = cache.request_view("p1", ProxyProtocol::Grpc);
    assert_eq!(grpc_view.grpc_deadline_plugins().len(), 1);
    assert_eq!(grpc_view.grpc_deadline_plugins()[0].name(), "grpc_deadline");
    assert_eq!(grpc_view.grpc_deadline_plugins()[0].priority(), 120);
    assert!(
        cache
            .request_view("p1", ProxyProtocol::Http)
            .grpc_deadline_plugins()
            .is_empty()
    );
}

#[test]
fn test_request_view_precomputes_authorize_plugins() {
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["acl", "rate_ip", "rate_consumer"],
        )],
        vec![
            make_plugin_config(
                "acl",
                "access_control",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "rate_ip",
                "rate_limiting",
                json!({
                    "limit_by": "ip",
                    "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "rate_consumer",
                "rate_limiting",
                json!({
                    "limit_by": "consumer",
                    "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let request_view = cache.request_view("p1", ProxyProtocol::Http);

    let authorize_plugins = request_view.authorize_plugins();
    let names: Vec<&str> = authorize_plugins.iter().map(|p| p.name()).collect();
    assert_eq!(names, vec!["access_control", "rate_limiting"]);
}

#[test]
fn test_request_view_precomputes_key_auth_header_redaction() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["keyauth"])],
        vec![make_plugin_config_with_json(
            "keyauth",
            "key_auth",
            json!({"key_location": "header:X-Tenant-Credential"}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("p1", ProxyProtocol::Http);

    assert_eq!(
        view.request_headers_to_redact().as_ref(),
        &["x-tenant-credential"]
    );
}

#[test]
fn test_authorize_plugin_default_preserves_legacy_custom_plugins() {
    let plugin: Arc<dyn Plugin> = Arc::new(LegacyAuthorizePlugin);

    assert!(plugin.is_authorize_plugin());
}

#[test]
fn test_plugins_persist_across_get_calls() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "rate_limiting",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let call1 = cache.get_plugins("p1");
    let call2 = cache.get_plugins("p1");

    // Same Arc pointer — same plugin instance, not a copy
    assert!(std::sync::Arc::ptr_eq(&call1[0], &call2[0]));
}

#[test]
fn test_unknown_proxy_falls_back_to_globals() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // "unknown" proxy not in config — should get global plugins
    let plugins = cache.get_plugins("unknown");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_multiple_global_and_proxy_plugins() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "g2",
                "transaction_debugger",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    // 2 global + 1 proxy-scoped = 3
    assert_eq!(plugins.len(), 3);

    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"stdout_logging"));
    assert!(names.contains(&"transaction_debugger"));
    assert!(names.contains(&"key_auth"));
}

#[tokio::test]
async fn serverless_instances_keep_independent_transaction_metadata() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let first_server = MockServer::start().await;
    let second_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {"decision": "first"}
        })))
        .mount(&first_server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "metadata": {"decision": "second"}
        })))
        .mount(&second_server)
        .await;

    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["policy.primary", "policy-secondary"],
        )],
        vec![
            make_plugin_config_with_json(
                "policy.primary",
                "serverless_function",
                json!({
                    "provider": "azure_functions",
                    "function_url": format!("{}/first", first_server.uri())
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "policy-secondary",
                "serverless_function",
                json!({
                    "provider": "azure_functions",
                    "function_url": format!("{}/second", second_server.uri())
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );

    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("serverless_function.policy%2Eprimary.metadata.decision")
            .map(String::as_str),
        Some("first")
    );
    assert_eq!(
        ctx.metadata
            .get("serverless_function.policy-secondary.metadata.decision")
            .map(String::as_str),
        Some("second")
    );
    assert_eq!(
        ctx.metadata
            .get("serverless_function.policy%2Eprimary.status")
            .map(String::as_str),
        Some("200")
    );
    assert_eq!(
        ctx.metadata
            .get("serverless_function.policy-secondary.status")
            .map(String::as_str),
        Some("200")
    );
}

#[tokio::test]
#[serial_test::serial(api_chargeback_sink_active_sink)]
async fn chargeback_sink_cache_construction_preserves_plugin_config_id() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["chargeback-stable-id"])],
        vec![make_plugin_config(
            "chargeback-stable-id",
            "api_chargeback_sink",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).expect("chargeback sink cache");
    let status: serde_json::Value =
        serde_json::from_str(&ferrum_edge::plugins::api_chargeback_sink::render_status_json())
            .expect("chargeback status");

    assert_eq!(status["instance_count"], 1);
    assert_eq!(
        status["instances"][0]["plugin_config_id"], "chargeback-stable-id",
        "production PluginCache must pass the stable resource id"
    );

    drop(cache);
}

#[tokio::test]
async fn request_mirror_cache_construction_preserves_plugin_config_id() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let server_url = url::Url::parse(&server.uri()).expect("mirror URL");
    let proxy = make_proxy("p1", "/api", vec!["mirror-stable-id"]);
    let config = make_config(
        vec![proxy.clone()],
        vec![make_plugin_config_with_json(
            "mirror-stable-id",
            "request_mirror",
            json!({
                "mirror_host": server_url.host_str().expect("mirror host"),
                "mirror_port": server_url.port().expect("mirror port"),
                "percentage": 100,
                "mirror_request_body": false
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).expect("request mirror cache");
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let mirror = plugins
        .iter()
        .find(|plugin| plugin.name() == "request_mirror")
        .expect("request mirror plugin");
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/widgets".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(proxy));
    let mut headers = HashMap::new();

    assert!(matches!(
        mirror.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        ctx.collect_mirror_result(),
    )
    .await
    .expect("mirror completion")
    .expect("mirror metadata");
    assert_eq!(
        result.mirror_plugin_id.as_deref(),
        Some("mirror-stable-id"),
        "production PluginCache must pass the stable resource id"
    );
}

#[test]
fn serverless_body_egress_rejects_request_body_transform_composition() {
    let mut transform_cases = vec![
        (
            "body-transform",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "trusted",
                    "value": true
                }]
            }),
        ),
        (
            "request-decompression",
            "compression",
            json!({"decompress_request": true}),
        ),
    ];
    if ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        transform_cases.push((
            "custom-body-transform",
            "example_plugin",
            json!({"request_body_prefix": "governed:"}),
        ));
    }

    for (transform_id, transform_name, transform_config) in transform_cases {
        let config = make_config(
            vec![make_proxy(
                "p1",
                "/api",
                vec!["external-policy", transform_id],
            )],
            vec![
                make_plugin_config_with_json(
                    "external-policy",
                    "serverless_function",
                    json!({
                        "provider": "azure_functions",
                        "function_url": "https://example.com/policy",
                        "forward_body": true
                    }),
                    PluginScope::Proxy,
                    Some("p1"),
                ),
                make_plugin_config_with_json(
                    transform_id,
                    transform_name,
                    transform_config,
                    PluginScope::Proxy,
                    Some("p1"),
                ),
            ],
        );

        let error = match PluginCache::new(&config) {
            Ok(_) => panic!("serverless body egress plus {transform_name} must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.contains("request-body") || error.contains("validation"),
            "transform={transform_name}, got: {error}"
        );
    }
}

#[test]
fn candidate_security_validation_constructs_custom_capabilities_without_builtin_gate() {
    let source = include_str!("../../../src/plugin_cache.rs");
    let start = source
        .find("pub(crate) fn validate_plugin_security_composition_candidate(")
        .expect("candidate security validator must exist");
    let end = source[start..]
        .find("\nfn remove_shadowed_global_plugin(")
        .map(|offset| start + offset)
        .expect("candidate security validator boundary must exist");
    let candidate = &source[start..end];

    assert!(candidate.contains("crate::custom_plugins::custom_plugin_names()"));
    assert!(candidate.contains("is_security_composition_candidate_plugin("));
    assert!(candidate.contains("security_composition_capabilities("));
    assert!(candidate.contains("ServerlessSecurityCompositionPlugin"));
    assert!(candidate.contains("validate_plugin_security_composition(&merged)"));
    assert!(candidate.contains("validate_plugin_security_composition(plugins)"));
}

#[tokio::test]
async fn transcript_audit_must_precede_every_request_deduplication_instance() {
    let audit_config = || {
        make_plugin_config_with_json(
            "audit",
            "ai_transcript_audit",
            json!({
                "capture": {
                    "request": true,
                    "response": true
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/ingest"
                }
            }),
            PluginScope::Proxy,
            Some("p1"),
        )
    };
    let dedup_config = || {
        make_plugin_config(
            "dedup",
            "request_deduplication",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )
    };

    let valid = make_config(
        vec![make_proxy("p1", "/api", vec!["audit", "dedup"])],
        vec![audit_config(), dedup_config()],
    );
    validate_plugin_composition_candidate_with_real_ip_header_for_test(&valid, None)
        .expect("default audit priority must stage before deduplication");
    PluginCache::new(&valid).expect("runtime cache must accept the safe order");

    for invalid_priority in [2750, 2800] {
        let mut audit = audit_config();
        audit.priority_override = Some(invalid_priority);
        let invalid = make_config(
            vec![make_proxy("p1", "/api", vec!["audit", "dedup"])],
            vec![audit, dedup_config()],
        );
        let candidate_error =
            validate_plugin_composition_candidate_with_real_ip_header_for_test(&invalid, None)
                .expect_err("candidate write must reject audit after/equal to deduplication");
        assert!(
            candidate_error.contains("must run before every request_deduplication"),
            "priority={invalid_priority}, got: {candidate_error}"
        );
        let runtime_error = PluginCache::new(&invalid)
            .err()
            .expect("runtime cache must repeat the fail-closed ordering check");
        assert!(
            runtime_error.contains("must run before every request_deduplication"),
            "priority={invalid_priority}, got: {runtime_error}"
        );
    }
}

#[test]
fn candidate_serverless_composition_uses_pure_capabilities_not_runtime_credentials() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["dedup", "function"])],
        vec![
            make_plugin_config(
                "dedup",
                "request_deduplication",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "function",
                "serverless_function",
                json!({
                    "provider": "aws_lambda",
                    "mode": "terminate",
                    // Pin an explicit region so runtime construction reaches the
                    // malformed-credential check deterministically instead of
                    // depending on an ambient AWS_REGION / AWS_DEFAULT_REGION.
                    "aws_region": "us-east-1",
                    "aws_access_key_id": 7
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );

    validate_plugin_composition_candidate_with_real_ip_header_for_test(&config, None)
        .expect("candidate composition must not construct an environment-bound AWS client");
    let runtime_error = PluginCache::new(&config)
        .err()
        .expect("runtime construction must still reject malformed credentials");
    assert!(
        runtime_error.contains("aws_access_key_id"),
        "{runtime_error}"
    );
}

#[test]
fn candidate_serverless_pure_capabilities_still_reject_unsafe_order_and_body_egress() {
    let mut terminal = make_plugin_config_with_json(
        "function",
        "serverless_function",
        json!({
            "provider": "aws_lambda",
            "mode": "terminate",
            "aws_access_key_id": 7
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    terminal.priority_override = Some(2700);
    let unsafe_order = make_config(
        vec![make_proxy("p1", "/api", vec!["function", "dedup"])],
        vec![
            terminal,
            make_plugin_config(
                "dedup",
                "request_deduplication",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let order_error =
        validate_plugin_composition_candidate_with_real_ip_header_for_test(&unsafe_order, None)
            .expect_err("pure terminate capability must retain dedup ordering enforcement");
    assert!(
        order_error.contains("request_deduplication"),
        "{order_error}"
    );

    let unsafe_body = make_config(
        vec![make_proxy("p1", "/api", vec!["function", "transform"])],
        vec![
            make_plugin_config_with_json(
                "function",
                "serverless_function",
                json!({
                    "provider": "aws_lambda",
                    "forward_body": true,
                    "aws_access_key_id": 7
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "transform",
                "request_transformer",
                json!({
                    "rules": [{
                        "operation": "add",
                        "target": "body",
                        "key": "x",
                        "value": true
                    }]
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let body_error =
        validate_plugin_composition_candidate_with_real_ip_header_for_test(&unsafe_body, None)
            .expect_err("pure forward_body capability must retain body-view enforcement");
    assert!(body_error.contains("request-body"), "{body_error}");
}

#[test]
fn terminate_serverless_must_run_after_every_request_deduplication_instance() {
    for serverless_priority in [2700, 2750] {
        let mut serverless = make_plugin_config_with_json(
            "terminal-function",
            "serverless_function",
            json!({
                "provider": "azure_functions",
                "function_url": "https://example.com/function",
                "mode": "terminate"
            }),
            PluginScope::Proxy,
            Some("p1"),
        );
        serverless.priority_override = Some(serverless_priority);
        let config = make_config(
            vec![make_proxy("p1", "/api", vec!["dedup", "terminal-function"])],
            vec![
                make_plugin_config(
                    "dedup",
                    "request_deduplication",
                    PluginScope::Proxy,
                    Some("p1"),
                    true,
                ),
                serverless,
            ],
        );

        let error = PluginCache::new(&config)
            .err()
            .unwrap_or_else(|| panic!("unsafe serverless priority {serverless_priority} admitted"));
        assert!(error.contains("serverless_function"), "{error}");
        assert!(error.contains("request_deduplication"), "{error}");
    }
}

#[test]
fn safe_serverless_dedup_order_and_pre_proxy_override_are_admitted() {
    let terminate_default = make_config(
        vec![make_proxy("p1", "/api", vec!["dedup", "terminal-function"])],
        vec![
            make_plugin_config(
                "dedup",
                "request_deduplication",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "terminal-function",
                "serverless_function",
                json!({
                    "provider": "azure_functions",
                    "function_url": "https://example.com/function",
                    "mode": "terminate"
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    PluginCache::new(&terminate_default).expect("default dedup order is safe");

    let mut pre_proxy = make_plugin_config_with_json(
        "policy-function",
        "serverless_function",
        json!({
            "provider": "azure_functions",
            "function_url": "https://example.com/function",
            "mode": "pre_proxy"
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    pre_proxy.priority_override = Some(2700);
    let pre_proxy_config = make_config(
        vec![make_proxy("p1", "/api", vec!["dedup", "policy-function"])],
        vec![
            make_plugin_config(
                "dedup",
                "request_deduplication",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            pre_proxy,
        ],
    );
    PluginCache::new(&pre_proxy_config)
        .expect("pre_proxy serverless does not produce a terminal replay obligation");
}

#[test]
fn test_proxy_count() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
            make_proxy("p3", "/admin", vec![]),
        ],
        vec![],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert_eq!(cache.proxy_count(), 3);
}

#[test]
fn test_request_body_buffering_upper_bound_is_config_sensitive() {
    let config = make_config(
        vec![
            make_proxy("cors-no-body", "/cors", vec!["cors-no-body-plugin"]),
            make_proxy(
                "graphql-guarded",
                "/gql-guarded",
                vec!["graphql-guarded-plugin"],
            ),
            make_proxy(
                "response-only",
                "/response-only",
                vec!["response-only-plugin"],
            ),
            make_proxy("request-xml", "/request-xml", vec!["request-xml-plugin"]),
        ],
        vec![
            PluginConfig {
                id: "cors-no-body-plugin".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "cors".to_string(),
                config: json!({"allowed_origins": ["*"]}),
                scope: PluginScope::Proxy,
                proxy_id: Some("cors-no-body".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "graphql-guarded-plugin".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "graphql".to_string(),
                config: json!({"max_depth": 4}),
                scope: PluginScope::Proxy,
                proxy_id: Some("graphql-guarded".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "response-only-plugin".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "body_validator".to_string(),
                config: json!({"response_required_fields": ["id"]}),
                scope: PluginScope::Proxy,
                proxy_id: Some("response-only".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "request-xml-plugin".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "body_validator".to_string(),
                config: json!({"validate_xml": true}),
                scope: PluginScope::Proxy,
                proxy_id: Some("request-xml".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
    );

    let cache = PluginCache::new(&config).unwrap();

    assert!(!cache.requires_request_body_buffering("cors-no-body"));
    assert!(cache.requires_request_body_buffering("graphql-guarded"));
    assert!(!cache.requires_request_body_buffering("response-only"));
    assert!(cache.requires_request_body_buffering("request-xml"));
}

// ---- Plugin priority ordering ----

#[test]
fn test_plugins_sorted_by_priority() {
    // Add plugins in reverse priority order — cache should sort them
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 3);
    // CORS (100) < key_auth (1200) < stdout_logging (9000)
    assert_eq!(plugins[0].name(), "cors");
    assert_eq!(plugins[1].name(), "key_auth");
    assert_eq!(plugins[2].name(), "stdout_logging");
}

#[test]
fn test_full_plugin_priority_chain() {
    // All major plugin types — verify the complete ordering
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["ps1", "ps2", "ps3", "ps4", "ps5", "ps6"],
        )],
        vec![
            // Global: logging
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            // Proxy-scoped: add in scrambled order
            make_plugin_config(
                "ps1",
                "access_control",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "request_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("ps3", "cors", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps4", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps5", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps6",
                "response_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert_eq!(
        names,
        vec![
            "cors",                 // 100  — Early
            "key_auth",             // 1200 — AuthN
            "access_control",       // 2000 — AuthZ
            "rate_limiting",        // 2900 — AuthZ (tail)
            "request_transformer",  // 3000 — Transform
            "response_transformer", // 4000 — Response
            "stdout_logging",       // 9000 — Logging
        ]
    );
}

#[tokio::test]
async fn test_cors_preflight_runs_before_request_termination() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            PluginConfig {
                id: "ps1".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "request_termination".to_string(),
                config: json!({"status_code": 503, "message": "maintenance"}),
                scope: PluginScope::Proxy,
                proxy_id: Some("p1".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            PluginConfig {
                id: "ps2".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "cors".to_string(),
                config: json!({"allowed_origins": ["https://app.example.com"]}),
                scope: PluginScope::Proxy,
                proxy_id: Some("p1".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");
    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();

    assert_eq!(names, vec!["cors", "request_termination"]);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "OPTIONS".to_string(),
        "/api/status".to_string(),
    );
    ctx.headers
        .insert("origin".to_string(), "https://app.example.com".to_string());
    ctx.headers.insert(
        "access-control-request-method".to_string(),
        "GET".to_string(),
    );

    for plugin in plugins.iter() {
        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Continue => continue,
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(plugin.name(), "cors");
                assert_eq!(status_code, 204);
                assert!(body.is_empty());
                assert_eq!(
                    headers
                        .get("access-control-allow-origin")
                        .map(String::as_str),
                    Some("https://app.example.com")
                );
                return;
            }
            PluginResult::RejectBinary { .. } => {
                panic!("cors preflight should reject with an empty text body");
            }
        }
    }

    panic!("expected preflight to be handled before request termination");
}

#[test]
fn test_global_plugins_also_sorted() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("g2", "cors", PluginScope::Global, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Even for unknown proxy (global fallback), should be sorted
    let plugins = cache.get_plugins("unknown");
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].name(), "cors"); // 100
    assert_eq!(plugins[1].name(), "stdout_logging"); // 9000
}

// ---- Rate limiting state persistence ----

#[tokio::test]
async fn test_rate_limiter_state_persists_across_calls() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![PluginConfig {
            id: "g1".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "rate_limiting".to_string(),
            config: json!({
                "limit_by": "ip",
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 2}]
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
    );
    let cache = PluginCache::new(&config).unwrap();

    let plugins = cache.get_plugins("p1");
    let rate_limiter = &plugins[0];
    assert_eq!(rate_limiter.name(), "rate_limiting");

    // Simulate 3 requests from the same IP
    for i in 0..3 {
        let mut ctx = ferrum_edge::plugins::RequestContext::new(
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/api/test".to_string(),
        );
        let result = rate_limiter.on_request_received(&mut ctx).await;

        if i < 2 {
            // First 2 should pass
            assert!(
                matches!(result, ferrum_edge::plugins::PluginResult::Continue),
                "Request {} should have been allowed",
                i
            );
        } else {
            // 3rd should be rate limited
            assert!(
                matches!(
                    result,
                    ferrum_edge::plugins::PluginResult::Reject {
                        status_code: 429,
                        ..
                    }
                ),
                "Request {} should have been rate limited",
                i
            );
        }
    }
}

// ---- Concurrency ----

#[tokio::test]
async fn test_concurrent_get_plugins() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = std::sync::Arc::new(PluginCache::new(&config).unwrap());

    let mut handles = vec![];
    for _ in 0..10 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            let plugins = cache.get_plugins("p1");
            assert_eq!(plugins.len(), 1);
            assert_eq!(plugins[0].name(), "stdout_logging");
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_rebuild_during_reads() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = std::sync::Arc::new(PluginCache::new(&config1).unwrap());

    // Snapshot before rebuild
    let pre_rebuild = cache.get_plugins("p1");
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");

    // Rebuild with different plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g2",
            "transaction_debugger",
            PluginScope::Global,
            None,
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();

    // Post-rebuild should see new plugin
    let post_rebuild = cache.get_plugins("p1");
    assert_eq!(post_rebuild[0].name(), "transaction_debugger");

    // Pre-rebuild snapshot still valid (Arc keeps it alive)
    assert_eq!(pre_rebuild[0].name(), "stdout_logging");
}

// ---- apply_delta security error propagation ----

#[test]
fn test_apply_delta_rejects_invalid_security_plugin() {
    // Start with a valid config
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    // Delta with an invalid security plugin (ip_restriction with empty config
    // fails validation because it requires at least one allow/deny rule)
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1", "pc2"])],
        vec![
            make_plugin_config(
                "pc1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            PluginConfig {
                id: "pc2".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "ip_restriction".to_string(),
                config: json!({}), // empty — ip_restriction requires allow/deny
                scope: PluginScope::Proxy,
                proxy_id: Some("p1".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let result = cache.apply_delta(&config2, &proxy_ids, &[], false);
    assert!(
        result.is_err(),
        "apply_delta should reject invalid security plugin config"
    );
    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_apply_delta_rejects_unknown_jwt_auth_key_and_keeps_last_known_good() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1", "pc2"])],
        vec![
            make_plugin_config(
                "pc1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            PluginConfig {
                id: "pc2".to_string(),
                namespace: ferrum_edge::config::types::default_namespace(),
                plugin_name: "jwt_auth".to_string(),
                config: json!({"audience": ["payments-api"]}),
                scope: PluginScope::Proxy,
                proxy_id: Some("p1".to_string()),
                enabled: true,
                priority_override: None,
                api_spec_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
    );

    let proxy_ids = std::collections::HashSet::from(["p1".to_string()]);
    let error = cache
        .apply_delta(&config2, &proxy_ids, &[], false)
        .expect_err("unknown jwt_auth key must reject the reload");
    assert!(
        error
            .to_string()
            .contains("jwt_auth: unknown config key 'audience'"),
        "unexpected reload error: {error}"
    );

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_apply_delta_rejects_unknown_load_testing_key_and_keeps_last_known_good() {
    let good = json!({
        "key": "stable-load-key-0123456789abcdef!",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "ramp": true,
        "gateway_port": 8000
    });
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-load"])],
        vec![make_plugin_config_with_json(
            "pc-load",
            "load_testing",
            good.clone(),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config1).expect("valid load_testing must admit");
    assert!(
        cache
            .get_plugins("p1")
            .iter()
            .any(|plugin| plugin.name() == "load_testing"),
        "baseline cache must include load_testing"
    );

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-load"])],
        vec![make_plugin_config_with_json(
            "pc-load",
            "load_testing",
            json!({
                "key": "must-not-publish-load-key-0123456789!",
                "concurrent_clients": 50,
                "duration_seconds": 30,
                "request_timeot_ms": 5000
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    let proxy_ids = std::collections::HashSet::from(["p1".to_string()]);
    let error = cache
        .apply_delta(&config2, &proxy_ids, &[], false)
        .expect_err("unknown load_testing key must reject the reload");
    assert!(
        error.to_string().contains("request_timeot_ms"),
        "unexpected reload error: {error}"
    );

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "load_testing");
    assert!(
        ferrum_edge::plugins::validate_plugin_config("load_testing", &good).is_ok(),
        "baseline good config must remain valid"
    );
}

#[test]
fn test_apply_delta_rejects_unknown_ai_stream_router_keys_and_keeps_last_known_good() {
    let good_router = json!({
        "enabled": true,
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "api_key": "sk-good",
            "model_patterns": ["gpt-*"]
        }]
    });
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-router"])],
        vec![make_plugin_config_with_json(
            "pc-router",
            "ai_stream_router",
            good_router,
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config1).expect("valid ai_stream_router must admit");
    assert!(
        cache
            .get_plugins("p1")
            .iter()
            .any(|plugin| plugin.name() == "ai_stream_router"),
        "baseline cache must include ai_stream_router"
    );

    for (label, bad_config, needle) in [
        (
            "enabled-typo",
            json!({
                "enabeld": false,
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-bad",
                    "model_patterns": ["gpt-*"]
                }]
            }),
            "config.enabeld",
        ),
        (
            "provider-tls-typo",
            json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-bad",
                    "model_patterns": ["gpt-*"],
                    "inherit_backend_tl": true
                }]
            }),
            "config.providers[0].inherit_backend_tl",
        ),
        (
            "fallback-typo",
            json!({
                "providers": [{
                    "name": "openai",
                    "provider_type": "openai",
                    "endpoint": "https://api.openai.com/v1/chat/completions",
                    "api_key": "sk-bad",
                    "model_patterns": ["gpt-*"]
                }],
                "fallback": {"on_connect_erro": true}
            }),
            "config.fallback.on_connect_erro",
        ),
    ] {
        let config2 = make_config(
            vec![make_proxy("p1", "/api", vec!["pc-router"])],
            vec![make_plugin_config_with_json(
                "pc-router",
                "ai_stream_router",
                bad_config,
                PluginScope::Proxy,
                Some("p1"),
            )],
        );
        let proxy_ids = std::collections::HashSet::from(["p1".to_string()]);
        let error = match cache.apply_delta(&config2, &proxy_ids, &[], false) {
            Err(error) => error,
            Ok(()) => panic!("{label}: unknown ai_stream_router key must reject reload"),
        };
        let message = error.to_string();
        assert!(
            message.contains("unknown configuration key") && message.contains(needle),
            "{label}: unexpected reload error: {message}"
        );
        assert!(
            cache
                .get_plugins("p1")
                .iter()
                .any(|plugin| plugin.name() == "ai_stream_router"),
            "{label}: rejected candidate must retain last-known-good ai_stream_router"
        );
    }
}

#[test]
fn test_apply_delta_rejects_unknown_ai_tool_governor_keys_and_keeps_last_known_good() {
    let good_governor = json!({
        "default_action": "deny",
        "tools": {
            "github.create_pr": {
                "action": "allow",
                "required_args": ["ticket_id"]
            }
        }
    });
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-gov"])],
        vec![make_plugin_config_with_json(
            "pc-gov",
            "ai_tool_governor",
            good_governor.clone(),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config1).expect("valid governor config constructs");

    let mut bad_governor = good_governor.clone();
    bad_governor["tools"]["github.create_pr"]
        .as_object_mut()
        .unwrap()
        .insert("required_arg".into(), json!(["ticket_id"]));
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-gov"])],
        vec![make_plugin_config_with_json(
            "pc-gov",
            "ai_tool_governor",
            bad_governor,
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    let proxy_ids = std::collections::HashSet::from(["p1".to_string()]);
    let error = cache
        .apply_delta(&config2, &proxy_ids, &[], false)
        .expect_err("unknown ai_tool_governor key must reject the reload");
    let message = error.to_string();
    assert!(
        message.contains("unknown configuration key")
            && message.contains("config.tools.github.create_pr.required_arg"),
        "unexpected reload error: {message}"
    );

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "ai_tool_governor");
    assert_eq!(
        config1.plugin_configs[0].config["tools"]["github.create_pr"]["required_args"],
        json!(["ticket_id"]),
        "last-known-good required_args policy must remain installed"
    );
}

#[test]
fn test_apply_delta_rejects_unknown_mesh_route_nested_keys_and_keeps_last_known_good() {
    let good_route = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "api"},
            "retry": {
                "max_retries": 1,
                "backoff": {"fixed": {"delay_ms": 10}},
                "retry_on_connect_failure": true
            }
        }],
        "reject_unmatched": true
    });
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc-route"])],
        vec![make_plugin_config_with_json(
            "pc-route",
            "mesh_route_dispatch",
            good_route,
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config1).expect("valid mesh_route_dispatch must admit");
    assert!(
        cache
            .get_plugins("p1")
            .iter()
            .any(|plugin| plugin.name() == "mesh_route_dispatch"),
        "baseline cache must include mesh_route_dispatch"
    );

    for bad_route in [
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "api"},
                "retry": {"max_retry": 2}
            }],
            "reject_unmatched": true
        }),
        json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "api.internal",
                    "backend_port": 443,
                    "backend_tls": {"verify_server_certificate": false}
                }
            }],
            "reject_unmatched": true
        }),
    ] {
        let config2 = make_config(
            vec![make_proxy("p1", "/api", vec!["pc-route"])],
            vec![make_plugin_config_with_json(
                "pc-route",
                "mesh_route_dispatch",
                bad_route,
                PluginScope::Proxy,
                Some("p1"),
            )],
        );
        let proxy_ids = std::collections::HashSet::from(["p1".to_string()]);
        let error = cache
            .apply_delta(&config2, &proxy_ids, &[], false)
            .expect_err("unknown nested mesh_route_dispatch keys must reject the reload");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected reload error: {error}"
        );
        assert!(
            cache
                .get_plugins("p1")
                .iter()
                .any(|plugin| plugin.name() == "mesh_route_dispatch"),
            "rejected candidate must retain the last-known-good mesh_route_dispatch generation"
        );
    }
}

#[test]
fn test_plugin_cache_rejects_invalid_waf_config_as_security_plugin() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![PluginConfig {
            id: "pc1".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "waf".to_string(),
            config: json!({"max_scan_bytes": 0}),
            scope: PluginScope::Proxy,
            proxy_id: Some("p1".to_string()),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
    );

    let err = PluginCache::new(&config)
        .err()
        .expect("invalid WAF config should be rejected");
    assert!(err.contains("waf"));
    assert!(err.contains("max_scan_bytes"));
}

#[test]
fn test_apply_delta_rejects_malformed_request_size_limiting_and_keeps_prior_cache() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc2"])],
        vec![make_plugin_config_with_json(
            "pc2",
            "request_size_limiting",
            json!({"max_bytes": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let err = cache
        .apply_delta(&config2, &proxy_ids, &[], false)
        .expect_err("malformed request_size_limiting must reject delta reload");
    assert!(err.contains("request_size_limiting"), "{err}");
    assert!(err.contains("pc2"), "{err}");
    assert!(err.contains("proxy_id=p1"), "{err}");

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_apply_delta_rejects_unknown_enabled_plugin_and_keeps_prior_cache() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc2"])],
        vec![make_plugin_config(
            "pc2",
            "unknown_enforcer",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let err = cache
        .apply_delta(&config2, &proxy_ids, &[], false)
        .expect_err("unknown enabled plugin must reject delta reload");
    assert!(err.contains("unknown_enforcer"), "{err}");
    assert!(err.contains("pc2"), "{err}");
    assert!(err.contains("proxy_id=p1"), "{err}");

    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[test]
fn test_apply_delta_accepts_valid_config() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1"])],
        vec![make_plugin_config(
            "pc1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    // Delta adding a non-security plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["pc1", "pc2"])],
        vec![
            make_plugin_config(
                "pc1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("pc2", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );

    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    let result = cache.apply_delta(&config2, &proxy_ids, &[], false);
    assert!(result.is_ok(), "apply_delta should accept valid config");
}

#[test]
fn test_apply_delta_preserves_proxy_group_instance_for_unchanged_group_config() {
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec!["group1"]),
        ],
        vec![make_plugin_config(
            "group1",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let p1_before = cache.get_plugins("p1");
    let p2_before = cache.get_plugins("p2");
    let group_ptr_before = plugin_ptr_by_name(&p1_before, "rate_limiting");
    assert_eq!(
        group_ptr_before,
        plugin_ptr_by_name(&p2_before, "rate_limiting"),
        "initial proxy-group plugin instance should be shared"
    );

    let config2 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1", "ps1"]),
            make_proxy("p2", "/web", vec!["group1"]),
        ],
        vec![
            make_plugin_config(
                "group1",
                "rate_limiting",
                PluginScope::ProxyGroup,
                None,
                true,
            ),
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();

    let p1_after = cache.get_plugins("p1");
    let p2_after = cache.get_plugins("p2");
    assert_eq!(
        plugin_ptr_by_name(&p1_after, "rate_limiting"),
        group_ptr_before,
        "rebuilt proxy should reuse the existing proxy-group instance"
    );
    assert_eq!(
        plugin_ptr_by_name(&p1_after, "rate_limiting"),
        plugin_ptr_by_name(&p2_after, "rate_limiting"),
        "partial proxy rebuild must not split proxy-group state"
    );
    assert!(
        p1_after
            .iter()
            .any(|plugin| plugin.name() == "stdout_logging"),
        "rebuilt proxy should still pick up its new proxy-scoped plugin"
    );
}

#[test]
fn test_apply_delta_prunes_global_proxy_alerts_lifecycle_on_proxy_removal() {
    let alerts = make_plugin_config("g-alerts", "proxy_alerts", PluginScope::Global, None, true);
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let global_before = cache.get_plugins("p1");
    let alerts_plugin = global_before
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("global proxy_alerts");
    let p1_gen = cache
        .proxy_lifecycle_generation("p1")
        .expect("p1 generation");
    let p2_gen = cache
        .proxy_lifecycle_generation("p2")
        .expect("p2 generation");
    alerts_plugin.seed_proxy_lifecycle_state_for_test("p1", p1_gen);
    alerts_plugin.seed_proxy_lifecycle_state_for_test("p2", p2_gen);
    assert!(alerts_plugin.has_proxy_lifecycle_state_for_test("p1"));
    assert!(alerts_plugin.has_proxy_lifecycle_state_for_test("p2"));

    let config2 = make_config(vec![make_proxy("p2", "/web", vec![])], vec![alerts]);
    let mut proxy_ids = HashSet::new();
    // p1 removed; p2 unchanged so the global instance is preserved.
    cache
        .apply_delta(&config2, &proxy_ids, &["p1".to_string()], false)
        .unwrap();

    let global_after = cache.get_plugins("p2");
    assert_eq!(
        plugin_ptr_by_name(&global_before, "proxy_alerts"),
        plugin_ptr_by_name(&global_after, "proxy_alerts"),
        "unchanged global proxy_alerts instance must be preserved"
    );
    let alerts_after = global_after
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved global proxy_alerts");
    assert!(
        !alerts_after.has_proxy_lifecycle_state_for_test("p1"),
        "removed proxy must retire cooldown/recovery ownership"
    );
    assert!(alerts_after.has_proxy_lifecycle_state_for_test("p2"));

    // ID reuse after removal must not inherit prior lifecycle state.
    let config3 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![make_plugin_config(
            "g-alerts",
            "proxy_alerts",
            PluginScope::Global,
            None,
            true,
        )],
    );
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();
    let recreated = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("global proxy_alerts after recreate")
        .clone();
    assert_eq!(
        plugin_ptr_by_name(&global_after, "proxy_alerts"),
        Arc::as_ptr(&recreated) as *const () as usize,
        "re-adding a proxy must keep the preserved global instance"
    );
    assert!(
        !recreated.has_proxy_lifecycle_state_for_test("p1"),
        "recreated proxy ID must start without inherited lifecycle state"
    );
    let p1_gen_after = cache
        .proxy_lifecycle_generation("p1")
        .expect("recreated p1 generation");
    assert_ne!(
        p1_gen, p1_gen_after,
        "delete→recreate must advance ownership generation for the same proxy ID"
    );

    // Old in-flight sample admitted under the removed generation finishes after
    // recreate; a current-active-ID gate would incorrectly accept it.
    let stale = ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(p1_gen),
        response_status_code: 500,
        ..ferrum_edge::plugins::TransactionSummary::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    rt.block_on(ferrum_edge::plugins::Plugin::log(
        recreated.as_ref(),
        &stale,
    ));
    assert!(
        !recreated.has_proxy_lifecycle_state_for_test("p1"),
        "stale generation must not repopulate lifecycle state after identical-ID recreate"
    );
}

#[test]
fn test_apply_delta_prunes_proxy_group_proxy_alerts_on_membership_churn() {
    let group_alerts = make_plugin_config(
        "group-alerts",
        "proxy_alerts",
        PluginScope::ProxyGroup,
        None,
        true,
    );
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let p1_before = cache.get_plugins("p1");
    let group_ptr_before = plugin_ptr_by_name(&p1_before, "proxy_alerts");
    let alerts_plugin = p1_before
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("group proxy_alerts");
    alerts_plugin.seed_proxy_lifecycle_state_for_test(
        "p1",
        cache
            .proxy_lifecycle_generation("p1")
            .expect("p1 generation"),
    );
    alerts_plugin.seed_proxy_lifecycle_state_for_test(
        "p2",
        cache
            .proxy_lifecycle_generation("p2")
            .expect("p2 generation"),
    );

    // Rename p1 → p1b while keeping the group config unchanged so the shared
    // instance is preserved; only membership identities change.
    let config2 = make_config(
        vec![
            make_proxy("p1b", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts],
    );
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1b".to_string());
    cache
        .apply_delta(&config2, &proxy_ids, &["p1".to_string()], false)
        .unwrap();

    let p2_after = cache.get_plugins("p2");
    assert_eq!(
        plugin_ptr_by_name(&p2_after, "proxy_alerts"),
        group_ptr_before,
        "unchanged proxy-group proxy_alerts instance must be preserved"
    );
    let alerts_after = p2_after
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved group proxy_alerts");
    assert!(
        !alerts_after.has_proxy_lifecycle_state_for_test("p1"),
        "renamed-away proxy ID must leave the preserved group instance"
    );
    assert!(alerts_after.has_proxy_lifecycle_state_for_test("p2"));
    assert!(
        !alerts_after.has_proxy_lifecycle_state_for_test("p1b"),
        "renamed-in proxy ID starts without inherited lifecycle state"
    );
}

#[test]
fn test_apply_delta_proxy_group_rejects_stale_generation_after_identical_id_recreate() {
    let group_alerts = make_plugin_config(
        "group-alerts",
        "proxy_alerts",
        PluginScope::ProxyGroup,
        None,
        true,
    );
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let shared = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("group proxy_alerts")
        .clone();
    let p1_gen = cache
        .proxy_lifecycle_generation("p1")
        .expect("p1 generation");
    shared.seed_proxy_lifecycle_state_for_test("p1", p1_gen);
    shared.seed_proxy_lifecycle_state_for_test(
        "p2",
        cache
            .proxy_lifecycle_generation("p2")
            .expect("p2 generation"),
    );
    let shared_ptr = Arc::as_ptr(&shared) as *const () as usize;

    let config2 = make_config(
        vec![make_proxy("p2", "/web", vec!["group-alerts"])],
        vec![group_alerts.clone()],
    );
    cache
        .apply_delta(&config2, &HashSet::new(), &["p1".to_string()], false)
        .unwrap();

    let config3 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts],
    );
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();

    let after = cache
        .get_plugins("p2")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved group proxy_alerts")
        .clone();
    assert_eq!(Arc::as_ptr(&after) as *const () as usize, shared_ptr);
    let p1_gen_after = cache
        .proxy_lifecycle_generation("p1")
        .expect("recreated p1 generation");
    assert_ne!(p1_gen, p1_gen_after);
    assert!(!after.has_proxy_lifecycle_state_for_test("p1"));
    assert!(after.has_proxy_lifecycle_state_for_test("p2"));

    let stale = ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(p1_gen),
        response_status_code: 500,
        ..ferrum_edge::plugins::TransactionSummary::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    rt.block_on(ferrum_edge::plugins::Plugin::log(after.as_ref(), &stale));
    assert!(
        !after.has_proxy_lifecycle_state_for_test("p1"),
        "preserved proxy-group instance must reject stale generation after ID recreate"
    );
}

#[test]
fn test_apply_delta_proxy_group_member_leave_rejoin_advances_alert_ownership() {
    let group_alerts = make_plugin_config(
        "group-alerts",
        "proxy_alerts",
        PluginScope::ProxyGroup,
        None,
        true,
    );
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let shared = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("group proxy_alerts")
        .clone();
    let p1_initial_generation = cache
        .proxy_lifecycle_generation("p1")
        .expect("initial p1 generation");
    shared.seed_proxy_lifecycle_state_for_test("p1", p1_initial_generation);
    shared.seed_proxy_lifecycle_state_for_test(
        "p2",
        cache
            .proxy_lifecycle_generation("p2")
            .expect("p2 generation"),
    );
    let shared_ptr = Arc::as_ptr(&shared) as *const () as usize;

    // p1 remains in the gateway but leaves the group; p2 keeps the shared
    // instance and must lose only p1's lifecycle rows.
    let config2 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts.clone()],
    );
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();

    let p2_after = cache.get_plugins("p2");
    assert_eq!(plugin_ptr_by_name(&p2_after, "proxy_alerts"), shared_ptr);
    let alerts_after = p2_after
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved group proxy_alerts");
    assert!(!alerts_after.has_proxy_lifecycle_state_for_test("p1"));
    assert!(alerts_after.has_proxy_lifecycle_state_for_test("p2"));
    let p1_left_generation = cache
        .proxy_lifecycle_generation("p1")
        .expect("generation after leaving group");
    assert_ne!(
        p1_initial_generation, p1_left_generation,
        "leaving the effective proxy_alerts instance must advance ownership"
    );

    // Rejoining the same preserved group instance is another ownership
    // boundary. An in-flight sample admitted before the leave must not write
    // into the new membership after rejoin.
    let config3 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts],
    );
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();
    let p1_rejoined_generation = cache
        .proxy_lifecycle_generation("p1")
        .expect("generation after rejoining group");
    assert_ne!(p1_left_generation, p1_rejoined_generation);

    let rejoined = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("rejoined group proxy_alerts")
        .clone();
    assert_eq!(Arc::as_ptr(&rejoined) as *const () as usize, shared_ptr);
    let stale = ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(p1_initial_generation),
        response_status_code: 500,
        ..ferrum_edge::plugins::TransactionSummary::default()
    };
    let current = ferrum_edge::plugins::TransactionSummary {
        proxy_id: Some("p1".to_string()),
        proxy_lifecycle_generation: Some(p1_rejoined_generation),
        response_status_code: 500,
        ..ferrum_edge::plugins::TransactionSummary::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    rt.block_on(ferrum_edge::plugins::Plugin::log(rejoined.as_ref(), &stale));
    assert!(
        !rejoined.has_proxy_lifecycle_state_for_test("p1"),
        "pre-leave in-flight sample must not repopulate a rejoined membership"
    );
    rt.block_on(ferrum_edge::plugins::Plugin::log(
        rejoined.as_ref(),
        &current,
    ));
    assert!(
        rejoined.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_rejoined_generation,),
        "rejoined membership must accept its current ownership generation"
    );
}

#[test]
fn test_apply_delta_rebuild_globals_resets_proxy_alerts_lifecycle() {
    let alerts = make_plugin_config("g-alerts", "proxy_alerts", PluginScope::Global, None, true);
    let config1 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![alerts]);
    let cache = PluginCache::new(&config1).unwrap();
    let before = cache.get_plugins("p1");
    let alerts_before = before
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("global proxy_alerts");
    alerts_before.seed_proxy_lifecycle_state_for_test(
        "p1",
        cache
            .proxy_lifecycle_generation("p1")
            .expect("p1 generation"),
    );
    assert!(alerts_before.has_proxy_lifecycle_state_for_test("p1"));
    let ptr_before = plugin_ptr_by_name(&before, "proxy_alerts");

    let mut rebuilt =
        make_plugin_config("g-alerts", "proxy_alerts", PluginScope::Global, None, true);
    // Touch the JSON so the global plugin config is considered changed.
    rebuilt.config = json!({
        "channels": {
            "ops": { "type": "slack", "webhook_url": "https://hooks.slack.com/y" }
        },
        "rules": [{
            "name": "r", "type": "error_rate",
            "status_codes": [500], "threshold_percent": 5.0,
            "channels": ["ops"]
        }]
    });
    let config2 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![rebuilt]);
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config2, &proxy_ids, &[], true).unwrap();

    let after = cache.get_plugins("p1");
    assert_ne!(
        plugin_ptr_by_name(&after, "proxy_alerts"),
        ptr_before,
        "global plugin rebuild must construct a fresh proxy_alerts instance"
    );
    let alerts_after = after
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("rebuilt global proxy_alerts");
    assert!(
        !alerts_after.has_proxy_lifecycle_state_for_test("p1"),
        "rebuilt instance must not carry prior lifecycle state"
    );
}

#[test]
fn test_proxy_lifecycle_generations_remove_to_empty_then_recreate_advances() {
    let config1 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![]);
    let (gens1, high1) = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &std::collections::HashMap::new(),
        0,
        &config1,
    )
    .expect("initial allocation");
    assert_eq!(gens1.get("p1").copied(), Some(1));
    assert_eq!(high1, 1);

    let empty = make_config(vec![], vec![]);
    let (gens_empty, high_empty) =
        ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
            &gens1, high1, &empty,
        )
        .expect("empty map must preserve high-water");
    assert!(gens_empty.is_empty());
    assert_eq!(
        high_empty, 1,
        "empty active map must not reset the allocator"
    );

    let config2 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![]);
    let (gens2, high2) = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &gens_empty,
        high_empty,
        &config2,
    )
    .expect("recreate after empty");
    assert_eq!(
        gens2.get("p1").copied(),
        Some(2),
        "identical-ID recreate after empty map must not reuse generation 1"
    );
    assert_eq!(high2, 2);
}

#[test]
fn test_proxy_lifecycle_generations_stable_presence_and_multi_id() {
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![],
    );
    let (gens1, high1) = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &std::collections::HashMap::new(),
        0,
        &config1,
    )
    .expect("initial multi-id allocation");
    let p1 = *gens1.get("p1").expect("p1");
    let p2 = *gens1.get("p2").expect("p2");
    assert_ne!(p1, p2);
    assert_eq!(high1, p1.max(p2));

    let (gens2, high2) = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &gens1, high1, &config1,
    )
    .expect("stable presence");
    assert_eq!(gens2.get("p1").copied(), Some(p1));
    assert_eq!(gens2.get("p2").copied(), Some(p2));
    assert_eq!(high2, high1);

    let config_add = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
            make_proxy("p3", "/ops", vec![]),
        ],
        vec![],
    );
    let (gens3, high3) = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &gens2,
        high2,
        &config_add,
    )
    .expect("new id advances high-water");
    assert_eq!(gens3.get("p1").copied(), Some(p1));
    assert_eq!(gens3.get("p2").copied(), Some(p2));
    let p3 = *gens3.get("p3").expect("p3");
    assert_eq!(p3, high2 + 1);
    assert_eq!(high3, p3);
}

#[test]
fn test_proxy_lifecycle_generations_exhaustion_fails_closed() {
    let config = make_config(vec![make_proxy("p1", "/api", vec![])], vec![]);
    let err = ferrum_edge::_test_support::build_proxy_lifecycle_generations_for_test(
        &std::collections::HashMap::new(),
        u64::MAX,
        &config,
    )
    .expect_err("exhausted counter must fail closed");
    assert!(
        err.contains("exhausted"),
        "unexpected exhaustion error: {err}"
    );
}

#[test]
fn test_apply_delta_proxy_lifecycle_high_water_survives_empty_active_set() {
    let config1 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![]);
    let cache = PluginCache::new(&config1).unwrap();
    let p1_gen = cache
        .proxy_lifecycle_generation("p1")
        .expect("p1 generation");

    let empty = make_config(vec![], vec![]);
    cache
        .apply_delta(&empty, &HashSet::new(), &["p1".to_string()], false)
        .unwrap();
    assert_eq!(cache.proxy_lifecycle_generation("p1"), None);

    let config2 = make_config(vec![make_proxy("p1", "/api", vec![])], vec![]);
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();
    let p1_gen_after = cache
        .proxy_lifecycle_generation("p1")
        .expect("recreated p1 generation");
    assert_ne!(
        p1_gen, p1_gen_after,
        "cache high-water must survive remove-to-empty so recreate advances"
    );
}

#[test]
fn test_apply_delta_global_proxy_alerts_generation_keyed_race_isolation() {
    let alerts = make_plugin_config("g-alerts", "proxy_alerts", PluginScope::Global, None, true);
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let alerts_plugin = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("global proxy_alerts")
        .clone();
    let p1_gen = cache
        .proxy_lifecycle_generation("p1")
        .expect("p1 generation");
    let p2_gen = cache
        .proxy_lifecycle_generation("p2")
        .expect("p2 generation");
    alerts_plugin.seed_proxy_lifecycle_state_for_test("p1", p1_gen);
    alerts_plugin.seed_proxy_lifecycle_state_for_test("p2", p2_gen);

    // Remove+recreate p1 while preserving the global instance.
    let config2 = make_config(vec![make_proxy("p2", "/web", vec![])], vec![alerts.clone()]);
    cache
        .apply_delta(&config2, &HashSet::new(), &["p1".to_string()], false)
        .unwrap();
    let config3 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![alerts],
    );
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();

    let after = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved global proxy_alerts")
        .clone();
    let p1_gen_after = cache
        .proxy_lifecycle_generation("p1")
        .expect("recreated p1 generation");
    assert_ne!(p1_gen, p1_gen_after);
    assert!(after.has_proxy_lifecycle_state_for_generation_for_test("p2", p2_gen));
    assert!(!after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen));
    assert!(!after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen_after));

    // Direct store write under the old generation after replacement publication.
    after.write_proxy_lifecycle_state_for_test("p1", p1_gen);
    assert!(after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen));
    assert!(
        !after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen_after),
        "old-generation write after retain must not populate the replacement"
    );

    after.write_proxy_lifecycle_state_for_test("p1", p1_gen_after);
    assert!(after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen_after));
}

#[test]
fn test_apply_delta_proxy_group_proxy_alerts_generation_keyed_race_isolation() {
    let group_alerts = make_plugin_config(
        "group-alerts",
        "proxy_alerts",
        PluginScope::ProxyGroup,
        None,
        true,
    );
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts.clone()],
    );
    let cache = PluginCache::new(&config1).unwrap();
    let shared = cache
        .get_plugins("p1")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("group proxy_alerts")
        .clone();
    let p1_gen = cache
        .proxy_lifecycle_generation("p1")
        .expect("p1 generation");
    let p2_gen = cache
        .proxy_lifecycle_generation("p2")
        .expect("p2 generation");
    shared.seed_proxy_lifecycle_state_for_test("p1", p1_gen);
    shared.seed_proxy_lifecycle_state_for_test("p2", p2_gen);
    let shared_ptr = Arc::as_ptr(&shared) as *const () as usize;

    let config2 = make_config(
        vec![make_proxy("p2", "/web", vec!["group-alerts"])],
        vec![group_alerts.clone()],
    );
    cache
        .apply_delta(&config2, &HashSet::new(), &["p1".to_string()], false)
        .unwrap();
    let config3 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group-alerts"]),
            make_proxy("p2", "/web", vec!["group-alerts"]),
        ],
        vec![group_alerts],
    );
    let mut proxy_ids = HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();

    let after = cache
        .get_plugins("p2")
        .iter()
        .find(|plugin| plugin.name() == "proxy_alerts")
        .expect("preserved group proxy_alerts")
        .clone();
    assert_eq!(Arc::as_ptr(&after) as *const () as usize, shared_ptr);
    let p1_gen_after = cache
        .proxy_lifecycle_generation("p1")
        .expect("recreated p1 generation");
    assert_ne!(p1_gen, p1_gen_after);
    assert!(after.has_proxy_lifecycle_state_for_generation_for_test("p2", p2_gen));

    after.write_proxy_lifecycle_state_for_test("p1", p1_gen);
    assert!(
        !after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen_after),
        "proxy-group stale generation write must stay isolated from replacement"
    );
    after.write_proxy_lifecycle_state_for_test("p1", p1_gen_after);
    assert!(after.has_proxy_lifecycle_state_for_generation_for_test("p1", p1_gen_after));
}

#[test]
fn test_apply_delta_prunes_proxy_group_instance_after_last_association_removed() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["group1"])],
        vec![make_plugin_config(
            "group1",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let p1_before = cache.get_plugins("p1");
    let held_group_plugin = Arc::clone(
        p1_before
            .iter()
            .find(|plugin| plugin.name() == "rate_limiting")
            .unwrap_or_else(|| panic!("expected initial proxy-group rate limiter")),
    );

    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "group1",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());

    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();

    let p1_after_removal = cache.get_plugins("p1");
    assert!(
        p1_after_removal
            .iter()
            .all(|plugin| plugin.name() != "rate_limiting"),
        "last association removal should remove the proxy-group plugin from the proxy"
    );

    let config3 = make_config(
        vec![make_proxy("p1", "/api", vec!["group1"])],
        vec![make_plugin_config(
            "group1",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    cache.apply_delta(&config3, &proxy_ids, &[], false).unwrap();

    let p1_after_reattach = cache.get_plugins("p1");
    let reattached_group_plugin = p1_after_reattach
        .iter()
        .find(|plugin| plugin.name() == "rate_limiting")
        .unwrap_or_else(|| panic!("expected reattached proxy-group rate limiter"));

    assert!(
        !Arc::ptr_eq(&held_group_plugin, reattached_group_plugin),
        "reattaching a previously unused proxy-group config should create fresh state"
    );
}

#[test]
fn test_apply_delta_global_to_proxy_scope_refreshes_all_proxy_views() {
    let old_global = make_plugin_config("pc1", "stdout_logging", PluginScope::Global, None, true);
    let old_config = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![old_global.clone()],
    );
    let cache = PluginCache::new(&old_config).unwrap();

    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p2").len(), 1);
    assert_eq!(cache.get_plugins("unknown").len(), 1);

    let mut proxy_scoped = make_plugin_config(
        "pc1",
        "stdout_logging",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    proxy_scoped.updated_at = old_global.updated_at + chrono::Duration::seconds(5);
    let new_config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["pc1"]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![proxy_scoped],
    );
    let delta = ConfigDelta::compute(&old_config, &new_config);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&old_config, &new_config);

    assert!(delta.global_plugin_configs_changed);
    cache
        .apply_delta(
            &new_config,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .unwrap();

    let p1_plugins = cache.get_plugins("p1");
    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "stdout_logging");
    assert!(
        cache.get_plugins("p2").is_empty(),
        "known proxies that no longer reference the plugin must drop stale global instances"
    );
    assert!(
        cache.get_plugins("unknown").is_empty(),
        "global fallback must drop plugins that changed away from global scope"
    );
}

#[test]
fn fault_delta_proxy_id_move_rebuilds_former_and_new_placements() {
    let old_fault = make_plugin_config(
        "fault",
        "fault_injection",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    let p1 = make_proxy("p1", "/one", vec!["fault"]);
    let p2 = make_proxy("p2", "/two", vec![]);
    let old_config = make_config(vec![p1.clone(), p2.clone()], vec![old_fault.clone()]);
    let cache = PluginCache::new(&old_config).expect("initial fault cache");
    assert_eq!(cache.get_plugins("p1")[0].name(), "fault_injection");
    assert!(cache.get_plugins("p2").is_empty());

    let mut moved_from = p1;
    moved_from.plugins.clear();
    let mut moved_to = p2;
    moved_to.plugins.push(PluginAssociation {
        plugin_config_id: "fault".to_string(),
    });
    let mut moved_fault = old_fault;
    moved_fault.proxy_id = Some("p2".to_string());
    moved_fault.updated_at += chrono::Duration::seconds(1);
    let new_config = make_config(vec![moved_from, moved_to], vec![moved_fault]);

    let delta = ConfigDelta::compute(&old_config, &new_config);
    assert!(delta.modified_proxies.is_empty());
    assert_eq!(delta.modified_plugin_configs.len(), 1);
    assert_eq!(
        delta
            .plugin_association_changed_proxy_ids
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        HashSet::from(["p1".to_string(), "p2".to_string()])
    );
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&old_config, &new_config);
    assert_eq!(
        proxy_ids,
        HashSet::from(["p1".to_string(), "p2".to_string()])
    );

    cache
        .apply_delta(
            &new_config,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("proxy_id move should rebuild both placements");

    assert!(
        cache.get_plugins("p1").is_empty(),
        "former proxy must not retain the moved fault plugin"
    );
    assert_eq!(cache.get_plugins("p2")[0].name(), "fault_injection");
}

#[test]
fn fault_delta_scope_moves_rebuild_proxy_and_proxy_group_placements() {
    let proxy_fault = make_plugin_config(
        "fault",
        "fault_injection",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    let p1 = make_proxy("p1", "/one", vec!["fault"]);
    let p2 = make_proxy("p2", "/two", vec![]);
    let p3 = make_proxy("p3", "/three", vec![]);
    let proxy_config = make_config(
        vec![p1.clone(), p2.clone(), p3.clone()],
        vec![proxy_fault.clone()],
    );
    let cache = PluginCache::new(&proxy_config).expect("initial proxy-scoped fault cache");

    let mut former_proxy = p1.clone();
    former_proxy.plugins.clear();
    let mut group_member_one = p2.clone();
    group_member_one.plugins.push(PluginAssociation {
        plugin_config_id: "fault".to_string(),
    });
    let mut group_member_two = p3.clone();
    group_member_two.plugins.push(PluginAssociation {
        plugin_config_id: "fault".to_string(),
    });
    let mut group_fault = proxy_fault;
    group_fault.scope = PluginScope::ProxyGroup;
    group_fault.proxy_id = None;
    group_fault.updated_at += chrono::Duration::seconds(1);
    let group_config = make_config(
        vec![former_proxy, group_member_one, group_member_two],
        vec![group_fault.clone()],
    );
    let to_group = ConfigDelta::compute(&proxy_config, &group_config);
    let to_group_ids = to_group.proxy_ids_needing_plugin_rebuild(&proxy_config, &group_config);
    assert_eq!(
        to_group_ids,
        HashSet::from(["p1".to_string(), "p2".to_string(), "p3".to_string()])
    );
    cache
        .apply_delta(
            &group_config,
            &to_group_ids,
            &to_group.removed_proxy_ids,
            to_group.global_plugin_configs_changed,
        )
        .expect("proxy-to-group scope move");
    assert!(cache.get_plugins("p1").is_empty());
    assert_eq!(cache.get_plugins("p2")[0].name(), "fault_injection");
    assert_eq!(cache.get_plugins("p3")[0].name(), "fault_injection");

    let mut new_proxy = p1;
    new_proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "fault".to_string(),
    }];
    let former_group_one = p2;
    let former_group_two = p3;
    let mut moved_back = group_fault;
    moved_back.scope = PluginScope::Proxy;
    moved_back.proxy_id = Some("p1".to_string());
    moved_back.updated_at += chrono::Duration::seconds(1);
    let moved_back_config = make_config(
        vec![new_proxy, former_group_one, former_group_two],
        vec![moved_back],
    );
    let from_group = ConfigDelta::compute(&group_config, &moved_back_config);
    let from_group_ids =
        from_group.proxy_ids_needing_plugin_rebuild(&group_config, &moved_back_config);
    assert_eq!(
        from_group_ids,
        HashSet::from(["p1".to_string(), "p2".to_string(), "p3".to_string()])
    );
    cache
        .apply_delta(
            &moved_back_config,
            &from_group_ids,
            &from_group.removed_proxy_ids,
            from_group.global_plugin_configs_changed,
        )
        .expect("group-to-proxy scope move");
    assert_eq!(cache.get_plugins("p1")[0].name(), "fault_injection");
    assert!(cache.get_plugins("p2").is_empty());
    assert!(cache.get_plugins("p3").is_empty());
}

#[test]
fn fault_delta_group_membership_move_and_removal_invalidate_former_associations() {
    let group_fault = make_plugin_config(
        "fault",
        "fault_injection",
        PluginScope::ProxyGroup,
        None,
        true,
    );
    let p1 = make_proxy("p1", "/one", vec!["fault"]);
    let p2 = make_proxy("p2", "/two", vec!["fault"]);
    let p3 = make_proxy("p3", "/three", vec![]);
    let old_config = make_config(
        vec![p1.clone(), p2.clone(), p3.clone()],
        vec![group_fault.clone()],
    );
    let cache = PluginCache::new(&old_config).expect("initial group fault cache");
    let unchanged_before = cache.get_plugins("p2");

    let mut former_member = p1;
    former_member.plugins.clear();
    let unchanged_member = p2;
    let mut new_member = p3;
    new_member.plugins.push(PluginAssociation {
        plugin_config_id: "fault".to_string(),
    });
    let moved_config = make_config(
        vec![former_member, unchanged_member, new_member],
        vec![group_fault],
    );
    let moved_delta = ConfigDelta::compute(&old_config, &moved_config);
    assert!(moved_delta.modified_plugin_configs.is_empty());
    assert!(!moved_delta.is_empty());
    let moved_ids = moved_delta.proxy_ids_needing_plugin_rebuild(&old_config, &moved_config);
    assert_eq!(
        moved_ids,
        HashSet::from(["p1".to_string(), "p3".to_string()])
    );
    cache
        .apply_delta(
            &moved_config,
            &moved_ids,
            &moved_delta.removed_proxy_ids,
            moved_delta.global_plugin_configs_changed,
        )
        .expect("group association move");
    assert!(cache.get_plugins("p1").is_empty());
    assert!(Arc::ptr_eq(&unchanged_before, &cache.get_plugins("p2")));
    assert_eq!(cache.get_plugins("p3")[0].name(), "fault_injection");

    let mut removed_proxies = moved_config.proxies.clone();
    for proxy in &mut removed_proxies {
        proxy.plugins.clear();
    }
    let removed_config = make_config(removed_proxies, vec![]);
    let removed_delta = ConfigDelta::compute(&moved_config, &removed_config);
    let removed_ids =
        removed_delta.proxy_ids_needing_plugin_rebuild(&moved_config, &removed_config);
    cache
        .apply_delta(
            &removed_config,
            &removed_ids,
            &removed_delta.removed_proxy_ids,
            removed_delta.global_plugin_configs_changed,
        )
        .expect("fault plugin removal");
    assert!(cache.get_plugins("p2").is_empty());
    assert!(cache.get_plugins("p3").is_empty());
}

#[test]
fn fault_delta_priority_change_is_targeted_and_unchanged_config_is_noop() {
    let fault = make_plugin_config(
        "fault",
        "fault_injection",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    let config = make_config(
        vec![
            make_proxy("p1", "/one", vec!["fault"]),
            make_proxy("p2", "/two", vec![]),
        ],
        vec![fault],
    );
    let cache = PluginCache::new(&config).expect("initial priority fault cache");
    let p1_before = cache.get_plugins("p1");
    let p2_before = cache.get_plugins("p2");

    let unchanged = ConfigDelta::compute(&config, &config);
    assert!(unchanged.is_empty());
    assert!(
        unchanged
            .proxy_ids_needing_plugin_rebuild(&config, &config)
            .is_empty()
    );
    assert!(Arc::ptr_eq(&p1_before, &cache.get_plugins("p1")));

    let mut reprioritized = config.clone();
    reprioritized.plugin_configs[0].priority_override = Some(42);
    reprioritized.plugin_configs[0].updated_at += chrono::Duration::seconds(1);
    let delta = ConfigDelta::compute(&config, &reprioritized);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&config, &reprioritized);
    assert_eq!(proxy_ids, HashSet::from(["p1".to_string()]));
    cache
        .apply_delta(
            &reprioritized,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("fault priority change");

    let p1_after = cache.get_plugins("p1");
    assert!(!Arc::ptr_eq(&p1_before[0], &p1_after[0]));
    assert!(Arc::ptr_eq(&p2_before, &cache.get_plugins("p2")));
}

#[test]
fn fault_reconciliation_scope_move_advances_the_actual_generation() {
    let generation = Utc::now() - chrono::Duration::seconds(10);
    let mut fault = make_plugin_config("fault", "fault_injection", PluginScope::Global, None, true);
    fault.created_at = generation;
    fault.updated_at = generation;
    let accepted = make_config(vec![], vec![fault]);

    let mut candidate = accepted.clone();
    candidate.plugin_configs[0].scope = PluginScope::Proxy;
    candidate.plugin_configs[0].proxy_id = Some("p1".to_string());
    reconcile_fault_plugin_generations_for_test(&mut candidate, &accepted);

    assert!(candidate.plugin_configs[0].updated_at > generation);
    let delta = ConfigDelta::compute(&accepted, &candidate);
    assert_eq!(delta.modified_plugin_configs.len(), 1);
    assert!(delta.global_plugin_configs_changed);
}

#[test]
fn fault_reconciliation_priority_change_advances_the_actual_generation() {
    let generation = Utc::now() - chrono::Duration::seconds(10);
    let mut fault = make_plugin_config(
        "fault",
        "fault_injection",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    fault.created_at = generation;
    fault.updated_at = generation;
    let accepted = make_config(vec![make_proxy("p1", "/one", vec!["fault"])], vec![fault]);

    let mut candidate = accepted.clone();
    candidate.plugin_configs[0].priority_override = Some(42);
    reconcile_fault_plugin_generations_for_test(&mut candidate, &accepted);

    assert!(candidate.plugin_configs[0].updated_at > generation);
    let delta = ConfigDelta::compute(&accepted, &candidate);
    assert_eq!(delta.modified_plugin_configs.len(), 1);
    assert_eq!(
        incremental_plugin_rebuild_targets_for_test(&accepted, &candidate),
        HashSet::from(["p1".to_string()]),
        "the staged rebuild count and targets must come from this accepted snapshot"
    );
}

#[test]
fn fault_reconciliation_comparison_is_schema_complete_and_normalizes_only_timestamps() {
    let generation = Utc::now() - chrono::Duration::seconds(10);
    let mut fault = make_plugin_config("fault", "fault_injection", PluginScope::Global, None, true);
    fault.created_at = generation;
    fault.updated_at = generation;
    let accepted = make_config(vec![], vec![fault]);

    let mut persistence_only = accepted.clone();
    persistence_only.plugin_configs[0].created_at += chrono::Duration::seconds(1);
    reconcile_fault_plugin_generations_for_test(&mut persistence_only, &accepted);
    assert_eq!(persistence_only.plugin_configs[0].updated_at, generation);

    let mut metadata_changed = accepted.clone();
    metadata_changed.plugin_configs[0].api_spec_id = Some("spec-owner".to_string());
    reconcile_fault_plugin_generations_for_test(&mut metadata_changed, &accepted);
    assert!(metadata_changed.plugin_configs[0].updated_at > generation);
    assert_eq!(
        ConfigDelta::compute(&accepted, &metadata_changed)
            .modified_plugin_configs
            .len(),
        1,
        "a field outside the former hand-written list must not retain a stale generation"
    );
}

#[test]
fn test_apply_delta_invalid_optional_proxy_scoped_plugin_shadows_global() {
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![make_plugin_config(
            "global-stdout",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let config2 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["bad-stdout"]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![
            make_plugin_config(
                "global-stdout",
                "stdout_logging",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config_with_json(
                "bad-stdout",
                "stdout_logging",
                json!("bad-config"),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let delta = ConfigDelta::compute(&config1, &config2);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&config1, &config2);

    cache
        .apply_delta(
            &config2,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .unwrap();

    assert!(
        cache.get_plugins("p1").is_empty(),
        "failed proxy-scoped optional plugin must shadow the same-name global on delta reload"
    );
    assert_eq!(
        cache.get_plugins("p2").len(),
        1,
        "unrelated proxies keep the global plugin"
    );
}

#[test]
fn test_apply_delta_invalid_optional_proxy_group_plugin_shadows_global() {
    let config1 = make_config(
        vec![
            make_proxy("p1", "/api", vec![]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![make_plugin_config(
            "global-stdout",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let config2 = make_config(
        vec![
            make_proxy("p1", "/api", vec!["bad-group"]),
            make_proxy("p2", "/other", vec![]),
        ],
        vec![
            make_plugin_config(
                "global-stdout",
                "stdout_logging",
                PluginScope::Global,
                None,
                true,
            ),
            make_plugin_config_with_json(
                "bad-group",
                "stdout_logging",
                json!("bad-config"),
                PluginScope::ProxyGroup,
                None,
            ),
        ],
    );
    let delta = ConfigDelta::compute(&config1, &config2);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&config1, &config2);

    cache
        .apply_delta(
            &config2,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .unwrap();

    assert!(
        cache.get_plugins("p1").is_empty(),
        "failed proxy-group optional plugin must shadow the same-name global on delta reload"
    );
    assert_eq!(
        cache.get_plugins("p2").len(),
        1,
        "unrelated proxies keep the global plugin"
    );
}

// ---- Protocol-filtered plugin lookup tests ----

#[test]
fn transaction_log_schema_only_cache_preserves_no_plugin_fast_path_for_all_protocols() {
    use ferrum_edge::plugins::utils::log_schema::registry;

    let _guard = registry::lock_for_tests();
    registry::reset_for_tests();
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            make_plugin_config_with_json(
                "schemas-a",
                "transaction_log_schema",
                json!({"schemas": {"audit-a": {"summary_type": "both"}}}),
                PluginScope::Global,
                None,
            ),
            make_plugin_config_with_json(
                "schemas-b",
                "transaction_log_schema",
                json!({"schemas": {"audit-b": {"summary_type": "both"}}}),
                PluginScope::Global,
                None,
            ),
        ],
    );
    let cache = PluginCache::new(&config).expect("schema-only cache must build");

    assert!(cache.get_plugins("p1").is_empty());
    assert!(cache.get_plugins("unknown").is_empty());
    for protocol in [
        ProxyProtocol::Http,
        ProxyProtocol::Grpc,
        ProxyProtocol::WebSocket,
        ProxyProtocol::Tcp,
        ProxyProtocol::Udp,
    ] {
        let first_view = cache.request_view("p1", protocol);
        let second_view = cache.request_view("p1", protocol);
        let first_plugins = first_view.plugins();
        let second_plugins = second_view.plugins();
        assert!(
            first_plugins.is_empty(),
            "config-only schema instances leaked into the {protocol:?} runtime list"
        );
        assert!(
            Arc::ptr_eq(&first_plugins, &second_plugins),
            "{protocol:?} request views must reuse the precomputed plugin list instead of allocating per request"
        );

        let first_auth = first_view.auth_plugins();
        let second_auth = second_view.auth_plugins();
        let first_authorize = first_view.authorize_plugins();
        let second_authorize = second_view.authorize_plugins();
        let first_backend_admission = first_view.backend_admission_plugins();
        let second_backend_admission = second_view.backend_admission_plugins();
        let first_redactions = first_view.request_headers_to_redact();
        let second_redactions = second_view.request_headers_to_redact();
        let first_initial_response = first_view.initial_response_header_policy_plugins();
        let second_initial_response = second_view.initial_response_header_policy_plugins();
        let first_initial_names = first_view.initial_response_header_policy_names();
        let second_initial_names = second_view.initial_response_header_policy_names();
        assert!(Arc::ptr_eq(&first_auth, &second_auth));
        assert!(Arc::ptr_eq(&first_authorize, &second_authorize));
        assert!(Arc::ptr_eq(
            &first_backend_admission,
            &second_backend_admission
        ));
        assert!(Arc::ptr_eq(&first_redactions, &second_redactions));
        assert!(Arc::ptr_eq(
            &first_initial_response,
            &second_initial_response
        ));
        assert!(Arc::ptr_eq(&first_initial_names, &second_initial_names));
        assert!(!first_view.requires_response_body_buffering());
        assert!(!first_view.requires_request_body_buffering());
        assert!(!first_view.requires_ws_frame_hooks());
    }
    assert!(registry::lookup_named("audit-a").is_some());
    assert!(registry::lookup_named("audit-b").is_some());
}

#[test]
fn transaction_log_schema_delta_reload_updates_registry_without_runtime_entries() {
    use ferrum_edge::plugins::utils::log_schema::registry;

    let _guard = registry::lock_for_tests();
    registry::reset_for_tests();
    let old_schema = make_plugin_config_with_json(
        "schemas",
        "transaction_log_schema",
        json!({"schemas": {"before": {}}}),
        PluginScope::Global,
        None,
    );
    let old_config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![old_schema.clone()],
    );
    let cache = PluginCache::new(&old_config).expect("initial schema cache");

    let mut new_schema = old_schema;
    new_schema.config = json!({"schemas": {"after": {}}});
    new_schema.updated_at += chrono::Duration::seconds(1);
    let new_config = make_config(vec![make_proxy("p1", "/api", vec![])], vec![new_schema]);
    let delta = ConfigDelta::compute(&old_config, &new_config);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&old_config, &new_config);
    cache
        .apply_delta(
            &new_config,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("schema delta reload");

    assert!(registry::lookup_named("before").is_none());
    assert!(registry::lookup_named("after").is_some());
    assert!(cache.get_plugins("p1").is_empty());
    for protocol in [
        ProxyProtocol::Http,
        ProxyProtocol::Grpc,
        ProxyProtocol::WebSocket,
        ProxyProtocol::Tcp,
        ProxyProtocol::Udp,
    ] {
        assert!(cache.get_plugins_for_protocol("p1", protocol).is_empty());
    }
}

fn make_plugin_config_with_json(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
    scope: PluginScope,
    proxy_id: Option<&str>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_get_plugins_for_protocol_filters_by_protocol() {
    // ip_restriction = ALL_PROTOCOLS, cors = HTTP_ONLY
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config(
                "ps1",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "ps2",
                "cors",
                json!({"allowed_origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // HTTP — both present
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<&str> = http_plugins.iter().map(|p| p.name()).collect();
    assert!(http_names.contains(&"ip_restriction"));
    assert!(http_names.contains(&"cors"));
    assert_eq!(http_names.len(), 2);

    // TCP — only ip_restriction (cors is HTTP_ONLY)
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<&str> = tcp_plugins.iter().map(|p| p.name()).collect();
    assert!(tcp_names.contains(&"ip_restriction"));
    assert!(!tcp_names.contains(&"cors"));
    assert_eq!(tcp_names.len(), 1);

    // UDP — only ip_restriction
    let udp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Udp);
    assert_eq!(udp_plugins.len(), 1);
    assert_eq!(udp_plugins[0].name(), "ip_restriction");

    // WebSocket — only ip_restriction (cors is HTTP_ONLY, not HTTP_FAMILY)
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    assert_eq!(ws_plugins.len(), 1);
    assert_eq!(ws_plugins[0].name(), "ip_restriction");
}

#[test]
fn test_get_plugins_for_protocol_tcp_excludes_http_family() {
    // cors = HTTP_ONLY, key_auth = HTTP_FAMILY, rate_limiting = ALL, stdout_logging = ALL
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/tcp-svc",
            vec!["ps1", "ps2", "ps3", "ps4"],
        )],
        vec![
            make_plugin_config_with_json(
                "ps1",
                "cors",
                json!({"allowed_origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config("ps2", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps3", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps4",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<&str> = tcp_plugins.iter().map(|p| p.name()).collect();
    assert!(tcp_names.contains(&"rate_limiting"));
    assert!(tcp_names.contains(&"stdout_logging"));
    assert!(
        !tcp_names.contains(&"cors"),
        "cors should be excluded for TCP"
    );
    assert!(
        !tcp_names.contains(&"key_auth"),
        "key_auth should be excluded for TCP"
    );
    assert_eq!(tcp_names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_falls_back_to_globals() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config(
            "g1",
            "stdout_logging",
            PluginScope::Global,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Proxy with no associations — should get global stdout_logging for TCP
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(tcp_plugins.len(), 1);
    assert_eq!(tcp_plugins[0].name(), "stdout_logging");

    // Nonexistent proxy — falls back to global plugins
    let fallback = cache.get_plugins_for_protocol("nonexistent", ProxyProtocol::Http);
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback[0].name(), "stdout_logging");
}

#[test]
fn test_get_plugins_for_protocol_rebuild_updates_maps() {
    let config1 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();

    let tcp_before = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(tcp_before.len(), 1);

    // Rebuild with an additional plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps2",
                "ip_restriction",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    cache.rebuild(&config2).unwrap();

    let tcp_after = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let names: Vec<&str> = tcp_after.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"rate_limiting"));
    assert!(names.contains(&"ip_restriction"));
    assert_eq!(names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_websocket_includes_auth_excludes_cors() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ps2", "ps3"])],
        vec![
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config_with_json(
                "ps3",
                "cors",
                json!({"allowed_origins": ["*"]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let names: Vec<&str> = ws_plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"key_auth"), "WebSocket should include auth");
    assert!(
        names.contains(&"rate_limiting"),
        "WebSocket should include rate_limiting"
    );
    assert!(!names.contains(&"cors"), "WebSocket should exclude CORS");
    assert_eq!(names.len(), 2);
}

#[test]
fn test_get_plugins_for_protocol_grpc_excludes_http_only() {
    let config = make_config(
        vec![make_proxy("p1", "/grpc", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config_with_json(
                "ps1",
                "response_caching",
                json!({"ttl_seconds": 60}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config("ps2", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    let names: Vec<&str> = grpc_plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"rate_limiting"));
    assert!(
        !names.contains(&"response_caching"),
        "gRPC should exclude response_caching (HTTP_ONLY)"
    );
    assert_eq!(names.len(), 1);
}

#[test]
fn response_mock_excluded_from_native_grpc_protocol_view() {
    // Issue #2442: H2 and H3 native gRPC both use ProxyProtocol::Grpc. The
    // mock plugin must not appear in that view — Reject normalization would
    // otherwise turn default status 200 into grpc-status 13 and drop the body.
    let config = make_config(
        vec![make_proxy("p1", "/grpc", vec!["mock", "limiter"])],
        vec![
            make_plugin_config_with_json(
                "mock",
                "response_mock",
                json!({"rules": [{"path": "/helloworld.Greeter/SayHello", "body": "mocked-response"}]}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config(
                "limiter",
                "rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).expect("plugin cache");

    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<&str> = http_plugins.iter().map(|p| p.name()).collect();
    assert!(http_names.contains(&"response_mock"));
    assert!(http_names.contains(&"rate_limiting"));

    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let ws_names: Vec<&str> = ws_plugins.iter().map(|p| p.name()).collect();
    assert!(
        ws_names.contains(&"response_mock"),
        "WebSocket handshake view must retain response_mock"
    );

    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    let grpc_names: Vec<&str> = grpc_plugins.iter().map(|p| p.name()).collect();
    assert!(
        !grpc_names.contains(&"response_mock"),
        "native gRPC protocol view must exclude response_mock"
    );
    assert!(grpc_names.contains(&"rate_limiting"));

    let grpc_web_view = ferrum_edge::_test_support::grpc_web_request_view_for_test(&cache, "p1");
    assert!(
        grpc_web_view
            .plugins
            .iter()
            .any(|name| name == "response_mock"),
        "gRPC-Web composed view must retain response_mock HTTP guardrails"
    );
    assert!(
        grpc_web_view
            .plugins
            .iter()
            .any(|name| name == "rate_limiting")
    );
}

#[test]
fn ai_prompt_shield_excluded_from_native_grpc_but_retained_on_grpc_web_view() {
    // GHSA-j7hv-p57w-p3vr / #2668: H2 and H3 native gRPC both use
    // ProxyProtocol::Grpc, so excluding the shield from that view covers both
    // transports. The composed gRPC-Web view keeps HTTP guardrails, which then
    // skip framed bodies without decoding.
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/ai",
            vec!["shield", "grpc-web", "limiter"],
        )],
        vec![
            make_plugin_config(
                "shield",
                "ai_prompt_shield",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("grpc-web", "grpc_web", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "limiter",
                "rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).expect("plugin cache");

    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<&str> = http_plugins.iter().map(|p| p.name()).collect();
    assert!(http_names.contains(&"ai_prompt_shield"));
    assert!(http_names.contains(&"rate_limiting"));

    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    let grpc_names: Vec<&str> = grpc_plugins.iter().map(|p| p.name()).collect();
    assert!(
        !grpc_names.contains(&"ai_prompt_shield"),
        "native gRPC protocol view must exclude HTTP-only ai_prompt_shield"
    );
    assert!(grpc_names.contains(&"rate_limiting"));

    let grpc_web_view = ferrum_edge::_test_support::grpc_web_request_view_for_test(&cache, "p1");
    assert!(
        grpc_web_view
            .plugins
            .iter()
            .any(|name| name == "ai_prompt_shield"),
        "gRPC-Web composed view must retain the HTTP shield for explicit framed-body skip"
    );
    assert!(grpc_web_view.plugins.iter().any(|name| name == "grpc_web"));
}

// ---- WebSocket per-frame plugin hook infrastructure ----

#[tokio::test]
async fn test_requires_ws_frame_hooks_defaults_false_for_all_plugins() {
    use ferrum_edge::plugins::available_plugins;
    use ferrum_edge::plugins::create_plugin;

    // Every non-message-hook built-in plugin must return false for
    // requires_ws_frame_hooks(). Parser-only policies use the independent
    // requires_websocket_framing() aggregate.
    const WS_FRAME_PLUGINS: &[&str] = &["ws_frame_logging", "ws_rate_limiting"];

    for name in available_plugins() {
        if WS_FRAME_PLUGINS.contains(&name) {
            continue; // These intentionally return true
        }
        let config = minimal_plugin_config(name);
        if let Ok(Some(plugin)) = create_plugin(name, &config) {
            assert!(
                !plugin.requires_ws_frame_hooks(),
                "Plugin '{}' should default requires_ws_frame_hooks() to false",
                name
            );
        }
    }
}

#[tokio::test]
async fn test_pre_auth_body_buffering_plugins_are_explicitly_tracked_for_hbone() {
    use ferrum_edge::plugins::{available_plugins, create_plugin};

    const HBONE_PRE_AUTH_BODY_PLUGINS: &[&str] = &["hmac_auth"];

    // PR #1067 narrowed `hmac_auth.should_buffer_request_body` to only ask
    // for body buffering when the request is actually carrying an HMAC
    // authorization header. So this enumeration must hand each candidate
    // plugin a request that *could* trigger its pre-auth buffering — for
    // hmac_auth that means an `Authorization: hmac …` header — otherwise
    // hmac_auth (the only currently-tracked plugin) returns false and the
    // assertion below sees an empty list.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "CONNECT".to_string(),
        "/".to_string(),
    );
    ctx.headers.insert(
        "authorization".to_string(),
        "hmac username=\"u\", algorithm=\"hmac-sha256\", headers=\"\", signature=\"\"".to_string(),
    );
    let mut pre_auth_body_plugins = Vec::new();

    for name in available_plugins() {
        let config = minimal_plugin_config(name);
        if let Ok(Some(plugin)) = create_plugin(name, &config)
            && plugin.requires_request_body_before_authenticate()
            && plugin.should_buffer_request_body(&ctx)
        {
            pre_auth_body_plugins.push(name);
        }
    }

    assert_eq!(
        pre_auth_body_plugins, HBONE_PRE_AUTH_BODY_PLUGINS,
        "new pre-auth body-buffering plugins must update HBONE CONNECT coverage"
    );
}

#[tokio::test]
async fn test_on_ws_frame_default_returns_none() {
    use ferrum_edge::plugins::{WebSocketFrameDirection, create_plugin};
    use tokio_tungstenite::tungstenite::Message;

    // The default on_ws_frame() implementation must return None (passthrough).
    let plugin = create_plugin("stdout_logging", &serde_json::json!({}))
        .unwrap()
        .unwrap();

    let msg = Message::Text("hello".to_string().into());
    let result = plugin
        .on_ws_frame("proxy-1", 1, WebSocketFrameDirection::ClientToBackend, &msg)
        .await;
    assert!(
        result.is_none(),
        "Default on_ws_frame() must return None (passthrough)"
    );

    let result = plugin
        .on_ws_frame("proxy-1", 1, WebSocketFrameDirection::BackendToClient, &msg)
        .await;
    assert!(
        result.is_none(),
        "Default on_ws_frame() must return None (passthrough) for BackendToClient"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_false_when_no_plugins_opt_in() {
    // When no plugins opt in, requires_ws_frame_hooks() must return false for any proxy.
    let config = make_config(
        vec![
            make_proxy("p1", "/ws", vec!["ps1"]),
            make_proxy("p2", "/api", vec![]),
        ],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Known proxy — no plugin opts in
    assert!(
        !cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks should be false when no plugin opts in"
    );
    // Another proxy — no plugin opts in
    assert!(
        !cache.requires_ws_frame_hooks("p2"),
        "requires_ws_frame_hooks should be false for proxy with no plugins"
    );
    // Unknown proxy — falls back to global, still false
    assert!(
        !cache.requires_ws_frame_hooks("unknown"),
        "requires_ws_frame_hooks should be false for unknown proxy (global fallback)"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_rebuild_updates_flag() {
    let config1 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Rebuild with different config — flag should still be false (no plugin opts in)
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    cache.rebuild(&config2).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_apply_delta_preserves_false() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Delta adding a non-ws-frame plugin
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "key_auth", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let mut proxy_ids = std::collections::HashSet::new();
    proxy_ids.insert("p1".to_string());
    cache.apply_delta(&config2, &proxy_ids, &[], false).unwrap();

    // Still false — neither rate_limiting nor key_auth opt into ws_frame hooks
    assert!(
        !cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks should remain false after delta with non-frame plugins"
    );
}

#[test]
fn test_ws_frame_direction_debug_and_equality() {
    use ferrum_edge::plugins::WebSocketFrameDirection;

    let ctb = WebSocketFrameDirection::ClientToBackend;
    let btc = WebSocketFrameDirection::BackendToClient;

    assert_eq!(ctb, WebSocketFrameDirection::ClientToBackend);
    assert_eq!(btc, WebSocketFrameDirection::BackendToClient);
    assert_ne!(ctb, btc);

    // Debug formatting should not panic
    let _ = format!("{:?}", ctb);
    let _ = format!("{:?}", btc);
}

#[test]
fn test_priority_override_preserves_ws_parser_policy_and_framing() {
    // A parser-policy-only plugin must select the framed relay even though it
    // does not opt into the post-reassembly message hook. Priority overrides
    // must not hide either capability behind their wrapper.
    let mut limiter = make_plugin_config(
        "ws1",
        "ws_message_size_limiting",
        PluginScope::Proxy,
        Some("p1"),
        true,
    );
    limiter.priority_override = Some(101);
    let config = make_config(vec![make_proxy("p1", "/ws", vec!["ws1"])], vec![limiter]);
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "parser size policy must select the framed relay"
    );
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let limiter = ws_plugins
        .iter()
        .find(|plugin| plugin.name() == "ws_message_size_limiting")
        .expect("wrapped limiter remains in WebSocket chain");
    assert_eq!(limiter.priority(), 101);
    assert!(!limiter.requires_ws_frame_hooks());
    assert!(limiter.requires_websocket_framing());
    let limits = limiter
        .websocket_size_limits()
        .expect("priority wrapper delegates parser policy");
    assert_eq!(limits.max_frame_bytes, 65_536);
    assert_eq!(limits.max_message_bytes, 262_144);
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_rate_plugin() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_rate_limiting is attached"
    );
}

#[test]
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_logging_plugin() {
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_frame_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_frame_logging is attached"
    );
}

#[test]
fn test_plugin_cache_ws_plugins_filtered_to_websocket_protocol_only() {
    // WS-only plugins should NOT appear in the HTTP plugin list for a proxy.
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1", "http1"])],
        vec![
            make_plugin_config(
                "ws1",
                "ws_message_size_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "http1",
                "rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // HTTP protocol should only include rate_limiting, not ws_message_size_limiting
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    assert_eq!(
        http_plugins.len(),
        1,
        "HTTP should have only rate_limiting, not WS plugins"
    );
    assert_eq!(http_plugins[0].name(), "rate_limiting");

    // WebSocket protocol should include both
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    let ws_names: Vec<&str> = ws_plugins.iter().map(|p| p.name()).collect();
    assert!(
        ws_names.contains(&"ws_message_size_limiting"),
        "WebSocket protocol should include ws_message_size_limiting"
    );
    assert!(
        ws_names.contains(&"rate_limiting"),
        "WebSocket protocol should include rate_limiting (ALL_PROTOCOLS)"
    );
}

#[test]
fn test_plugin_cache_rebuild_adds_ws_frame_hooks_flag() {
    // Start with no WS plugins → flag is false
    let config1 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config1).unwrap();
    assert!(!cache.requires_ws_frame_hooks("p1"));

    // Rebuild with WS plugin → flag must become true
    let config2 = make_config(
        vec![make_proxy("p1", "/ws", vec!["ps1", "ws1"])],
        vec![
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ws1",
                "ws_frame_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    cache.rebuild(&config2).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE after rebuild adds ws_frame_logging"
    );
}

// ---- Multi-instance same-type plugins ----

fn make_plugin_config_with_priority(
    id: &str,
    plugin_name: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    enabled: bool,
    priority_override: Option<u16>,
) -> PluginConfig {
    let config = minimal_plugin_config(plugin_name);
    PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope,
        proxy_id: proxy_id.map(|s| s.to_string()),
        enabled,
        priority_override,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_multiple_same_type_proxy_plugins_both_present() {
    // Two proxy-scoped stdout_logging plugins on the same proxy — both should be present
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    // Both instances should be present
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].name(), "stdout_logging");
    assert_eq!(plugins[1].name(), "stdout_logging");
}

#[tokio::test]
async fn correlation_id_priority_overrides_select_canonical_without_collapsing_instances() {
    for internal_priority in [40, 60] {
        let external_priority = if internal_priority == 40 { 60 } else { 40 };
        let mut internal = make_plugin_config_with_priority(
            "internal-correlation",
            "correlation_id",
            PluginScope::Proxy,
            Some("p1"),
            true,
            Some(internal_priority),
        );
        internal.config = json!({"header_name": "x-internal-request-id"});
        let mut external = make_plugin_config_with_priority(
            "external-correlation",
            "correlation_id",
            PluginScope::Proxy,
            Some("p1"),
            true,
            Some(external_priority),
        );
        external.config = json!({"header_name": "x-external-request-id"});
        let config = make_config(
            vec![make_proxy(
                "p1",
                "/api",
                vec!["external-correlation", "internal-correlation"],
            )],
            vec![external, internal],
        );
        let cache = PluginCache::new(&config).expect("multi-instance correlation cache");
        let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
        assert_eq!(plugins.len(), 2);
        assert_eq!(
            plugins[0].priority(),
            internal_priority.min(external_priority)
        );

        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/api".to_string(),
        );
        ctx.headers.insert(
            "x-external-request-id".to_string(),
            "priority-preserved-id".to_string(),
        );
        assert!(matches!(
            run_request_received_chain(&plugins, &mut ctx).await,
            PluginResult::Continue
        ));

        let internal_id = ctx.headers.get("x-internal-request-id").unwrap();
        assert!(uuid::Uuid::parse_str(internal_id).is_ok());
        assert_ne!(internal_id, "priority-preserved-id");
        let expected_canonical = if internal_priority < external_priority {
            internal_id.as_str()
        } else {
            "priority-preserved-id"
        };
        assert_eq!(
            ctx.metadata
                .get(ferrum_edge::plugins::REQUEST_ID_METADATA_KEY)
                .map(String::as_str),
            Some(expected_canonical)
        );

        let mut handshake_headers = HashMap::new();
        for plugin in plugins.iter() {
            plugin.apply_websocket_handshake_response_headers(&ctx, 101, &mut handshake_headers);
        }
        assert_eq!(
            handshake_headers.get("x-internal-request-id"),
            Some(internal_id)
        );
        assert_eq!(
            handshake_headers
                .get("x-external-request-id")
                .map(String::as_str),
            Some("priority-preserved-id")
        );
    }
}

#[test]
fn test_proxy_scoped_plugin_removes_only_global_of_same_name() {
    // A global stdout_logging and two proxy-scoped stdout_logging instances.
    // The global should be replaced but both proxy-scoped should remain.
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    // Global is removed, both proxy-scoped remain = 2
    assert_eq!(plugins.len(), 2);
    assert!(plugins.iter().all(|p| p.name() == "stdout_logging"));
}

#[test]
fn test_proxy_without_scoped_keeps_global() {
    // Proxy p2 has no proxy-scoped plugins, so it should keep the global
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["ps1"]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // p1: proxy-scoped replaces global = 1
    assert_eq!(cache.get_plugins("p1").len(), 1);
    // p2: keeps global = 1
    assert_eq!(cache.get_plugins("p2").len(), 1);
}

#[test]
fn test_priority_override_changes_sort_order() {
    // Two stdout_logging instances with priority overrides that reverse their order
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config_with_priority(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(9200), // higher = runs later
            ),
            make_plugin_config_with_priority(
                "ps2",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(9000), // lower = runs first
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 2);
    // ps2 (priority 9000) should come first, ps1 (priority 9200) second
    assert_eq!(plugins[0].priority(), 9000);
    assert_eq!(plugins[1].priority(), 9200);
}

#[test]
fn test_priority_override_applied_correctly() {
    // A single plugin with priority_override should report the overridden value
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_priority(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
            Some(100),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 100);
    assert_eq!(plugins[0].name(), "stdout_logging");
}

#[tokio::test]
async fn priority_overridden_correlation_retains_owned_deadline_header() {
    let mut correlation = make_plugin_config_with_json(
        "correlation",
        "correlation_id",
        json!({ "header_name": "x-correlation-id" }),
        PluginScope::Proxy,
        Some("p1"),
    );
    correlation.priority_override = Some(777);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["correlation"])],
        vec![correlation],
    );
    let cache = PluginCache::new(&config).expect("priority-overridden correlation cache");
    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 777);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    ctx.headers.insert(
        "x-correlation-id".to_string(),
        "client-request-id".to_string(),
    );
    assert!(matches!(
        run_request_received_chain(&plugins, &mut ctx).await,
        PluginResult::Continue
    ));
    set_grpc_deadline_budget_for_test(&mut ctx, Some(1_000));

    let mut headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        (
            "x-correlation-id".to_string(),
            "client-request-id".to_string(),
        ),
    ]);
    assert!(
        !run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await,
        "correlation decoration must not reject the backend response"
    );
    set_grpc_deadline_budget_for_test(&mut ctx, Some(0));
    let mut status = 200;
    let mut body = b"discarded backend response".to_vec();
    let transform_plugins: Vec<Arc<dyn Plugin>> =
        vec![Arc::new(StalledDeadlineResponseTransformer)];

    assert!(
        transform_buffered_response_body_with_deadline_for_test(
            &transform_plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
        )
        .await
    );
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("x-correlation-id").map(String::as_str),
        Some("client-request-id"),
        "the real priority wrapper must delegate exact-value deadline ownership"
    );
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("4"));
    assert!(body.is_empty());
}

#[tokio::test]
async fn test_priority_override_delegates_deadline_rejection_replacement_capability() {
    let mut audit = make_plugin_config_with_json(
        "audit",
        "ai_transcript_audit",
        json!({
            "capture": { "request": true, "response": true },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/ingest"
            }
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    audit.priority_override = Some(100);
    let config = make_config(vec![make_proxy("p1", "/api", vec!["audit"])], vec![audit]);
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 100);
    assert!(plugins[0].may_replace_rejection_response());
    assert!(
        plugins[0].defers_response_stream_termination_until_after_peers(),
        "priority override wrappers must preserve audit terminal-observer ordering"
    );
}

#[test]
fn test_priority_override_delegates_spec_rejection_replacement_capability() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "spec_expose",
        json!({"spec_url": "https://example.com/openapi.json"}),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(211);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "spec_expose");
    assert_eq!(plugins[0].priority(), 211);
    assert!(plugins[0].applies_after_proxy_on_reject());
    assert!(plugins[0].may_replace_rejection_response());
    assert!(!plugins[0].warn_on_rejection_response_replacement());
}

#[test]
fn test_grpc_backend_path_plugins_are_precomputed_with_priority_override() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["router"])],
        vec![make_plugin_config_with_priority(
            "router",
            "grpc_method_router",
            PluginScope::Proxy,
            Some("p1"),
            true,
            Some(300),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let grpc_view = cache.request_view("p1", ProxyProtocol::Grpc);
    assert!(
        grpc_view
            .capabilities()
            .has(PluginCapabilities::HAS_BACKEND_PATH_PLUGINS)
    );
    assert_eq!(grpc_view.backend_path_plugins().len(), 1);
    assert_eq!(
        grpc_view.backend_path_plugins()[0].name(),
        "grpc_method_router"
    );
    assert_eq!(grpc_view.backend_path_plugins()[0].priority(), 300);

    let http_view = cache.request_view("p1", ProxyProtocol::Http);
    assert!(
        !http_view
            .capabilities()
            .has(PluginCapabilities::HAS_BACKEND_PATH_PLUGINS)
    );
    assert!(http_view.backend_path_plugins().is_empty());
}

#[tokio::test]
async fn test_priority_override_delegates_response_stream_termination_hook() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_priority(
            "ps1",
            "request_deduplication",
            PluginScope::Proxy,
            Some("p1"),
            true,
            Some(100),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "request_deduplication");
    assert_eq!(plugins[0].priority(), 100);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "idempotency-key".to_string(),
        "priority-stream-key".to_string(),
    );
    let result = plugins[0].before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(plugins[0].tracked_keys_count(), Some(1));

    plugins[0]
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    assert_eq!(
        plugins[0].tracked_keys_count(),
        Some(0),
        "priority override wrapper must forward streamed-response terminal cleanup"
    );

    let mut retry_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/api".to_string(),
    );
    let mut retry_headers = HashMap::new();
    retry_headers.insert(
        "idempotency-key".to_string(),
        "priority-stream-key".to_string(),
    );
    let result = plugins[0]
        .before_proxy(&mut retry_ctx, &mut retry_headers)
        .await;
    assert!(
        matches!(result, PluginResult::Continue),
        "stream-end cleanup should let the next keyed request execute, got {result:?}"
    );
}

#[tokio::test]
async fn plugin_cache_wires_stable_plugin_config_id_into_dedup_logical_keys() {
    // Production PluginCache must pass each plugin-config resource id through
    // the factory so sibling Redis instances stay partitioned under a shared
    // default prefix, while corresponding copies of one config share identity.
    let first_gateway = make_config(
        vec![make_proxy(
            "orders",
            "/orders",
            vec!["dedup-short", "dedup-long"],
        )],
        vec![
            make_plugin_config(
                "dedup-short",
                "request_deduplication",
                PluginScope::Proxy,
                Some("orders"),
                true,
            ),
            make_plugin_config(
                "dedup-long",
                "request_deduplication",
                PluginScope::Proxy,
                Some("orders"),
                true,
            ),
        ],
    );
    let second_gateway = make_config(
        vec![make_proxy("orders", "/orders", vec!["dedup-short"])],
        vec![make_plugin_config(
            "dedup-short",
            "request_deduplication",
            PluginScope::Proxy,
            Some("orders"),
            true,
        )],
    );

    let first_cache = PluginCache::new(&first_gateway).unwrap();
    let second_cache = PluginCache::new(&second_gateway).unwrap();
    let first_plugins = first_cache.get_plugins("orders");
    let second_plugins = second_cache.get_plugins("orders");
    assert_eq!(first_plugins.len(), 2);
    assert_eq!(second_plugins.len(), 1);
    assert!(
        first_plugins
            .iter()
            .all(|plugin| plugin.name() == "request_deduplication")
    );

    async fn logical_key(plugin: &Arc<dyn Plugin>) -> String {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/orders".to_string(),
        );
        ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"{}"));
        let mut headers = HashMap::new();
        headers.insert("idempotency-key".to_string(), "order-1".to_string());
        headers.insert("host".to_string(), "api.example".to_string());
        headers.insert("content-length".to_string(), "2".to_string());
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let keys = request_deduplication_logical_keys_from_context_for_test(&ctx);
        assert_eq!(keys.len(), 1);
        keys.into_iter().next().unwrap()
    }

    let sibling_a = logical_key(&first_plugins[0]).await;
    let sibling_b = logical_key(&first_plugins[1]).await;
    let peer_key = logical_key(&second_plugins[0]).await;
    assert_ne!(
        sibling_a, sibling_b,
        "PluginCache must partition sibling request_deduplication config ids"
    );
    assert!(
        peer_key == sibling_a || peer_key == sibling_b,
        "PluginCache must preserve cross-gateway identity for one plugin_config_id"
    );
}

#[test]
fn test_priority_override_delegates_stream_first_byte_requirements() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "waf",
        json!({
            "include_default_rules": false,
            "stream": {
                "signatures": [{
                    "id": "STREAM-SQLI-1",
                    "pattern": "(?i)union\\s+select"
                }]
            }
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(100);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 100);
    assert!(plugins[0].requires_stream_first_bytes());
    assert!(plugins[0].requires_stream_first_bytes_decrypted());
    assert_eq!(plugins[0].stream_first_bytes_min_len(), 0);
}

#[test]
fn test_priority_override_delegates_response_buffering_refinement() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "response_size_limiting",
        json!({"max_bytes": 1024, "require_buffered_check": true}),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(100);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 100);
    assert!(plugins[0].requires_response_body_buffering());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/events".to_string(),
    );
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(
        plugins[0].should_buffer_response_body(&ctx),
        "priority override wrapper must preserve conservative pre-header buffering"
    );

    let response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(plugins[0].may_release_response_body_under_retries(&ctx));
    assert!(plugins[0].should_release_response_body_under_retries(&ctx, 200, &response_headers));
    assert!(
        plugins[0].should_release_response_body_before_content_type_rewrite(
            &ctx,
            200,
            &response_headers
        )
    );
    assert!(
        !plugins[0].should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &response_headers
        ),
        "priority override wrapper must preserve backend-content-type refinement"
    );
}

#[test]
fn test_priority_override_delegates_request_buffering_refinement() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "graphql",
        json!({"max_depth": 4}),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(100);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].priority(), 100);
    assert!(plugins[0].requires_request_body_buffering());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/graphql".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());

    assert!(
        !plugins[0].should_buffer_request_body(&ctx),
        "priority override wrapper must preserve plugin-specific GET buffering skip"
    );
}

#[tokio::test]
async fn test_priority_override_delegates_context_response_body_transform() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "compression",
        json!({"min_content_length": 10, "algorithms": ["gzip"]}),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(100);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "compression");
    assert_eq!(plugins[0].priority(), 100);
    assert!(plugins[0].needs_later_response_strong_etag());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    ctx.max_response_body_size_bytes = 10 * 1024 * 1024;

    let mut request_headers = HashMap::new();
    request_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugins[0]
        .before_proxy(&mut ctx, &mut request_headers)
        .await;
    assert!(
        !request_headers.contains_key("accept-encoding"),
        "compression should strip Accept-Encoding before proxying"
    );

    let body = r#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"},{"name":"frank","email":"frank@example.com","role":"admin"}]}"#.as_bytes();
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "application/json".to_string());
    response_headers.insert("content-length".to_string(), body.len().to_string());
    assert!(
        plugins[0]
            .should_release_response_body_for_later_strong_etag(&ctx, 200, &response_headers,)
    );

    plugins[0]
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert_eq!(
        response_headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );

    let compressed = plugins[0]
        .transform_response_body_with_context(
            &mut ctx,
            body,
            Some("application/json"),
            &response_headers,
        )
        .await
        .expect("priority override wrapper should forward the context-aware transform");

    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, body);
}

#[test]
fn test_priority_override_delegates_response_header_refinement_hooks() {
    let mut transformer_config = make_plugin_config_with_json(
        "rt1",
        "response_transformer",
        json!({
            "rules": [{
                "operation": "update",
                "target": "header",
                "key": "Content-Type",
                "value": "application/json"
            }]
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    transformer_config.priority_override = Some(100);
    let mut security_config = make_plugin_config_with_json(
        "sh1",
        "security_headers",
        json!({"set": {"Cache-Control": "no-transform", "ETag": "\"late\""}}),
        PluginScope::Proxy,
        Some("p1"),
    );
    security_config.priority_override = Some(200);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["rt1", "sh1"])],
        vec![transformer_config, security_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");
    let ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/users".to_string(),
    );
    let response_headers = HashMap::new();

    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].name(), "response_transformer");
    assert!(plugins[0].may_modify_response_content_type(&ctx, Some("application/octet-stream")));
    assert_eq!(plugins[1].name(), "security_headers");
    assert!(plugins[1].may_add_response_cache_control_no_transform(&ctx, &response_headers));
    assert!(plugins[1].may_add_response_strong_etag(&ctx, &response_headers));

    let policy_plugins = cache
        .request_view("p1", ProxyProtocol::Grpc)
        .initial_response_header_policy_plugins();
    assert_eq!(policy_plugins.len(), 1);
    assert_eq!(policy_plugins[0].name(), "security_headers");
    let mut policy_headers = HashMap::new();
    apply_initial_response_header_policies(&policy_plugins, &mut policy_headers);
    assert_eq!(
        policy_headers.get("cache-control").map(String::as_str),
        Some("no-transform")
    );
}

#[test]
fn test_initial_response_policy_plan_preserves_multiple_instance_priority_order() {
    let mut first = make_plugin_config_with_json(
        "sh-first",
        "security_headers",
        json!({ "set": { "X-Order": "first", "X-Removed": "first" }, "remove": [] }),
        PluginScope::Proxy,
        Some("p1"),
    );
    first.priority_override = Some(100);
    let mut second = make_plugin_config_with_json(
        "sh-second",
        "security_headers",
        json!({ "set": { "X-Order": "second" }, "remove": ["X-Removed"] }),
        PluginScope::Proxy,
        Some("p1"),
    );
    second.priority_override = Some(200);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["sh-second", "sh-first"])],
        vec![second, first],
    );
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("p1", ProxyProtocol::WebSocket);
    let policy_plugins = view.initial_response_header_policy_plugins();
    let mut headers = HashMap::new();

    assert_eq!(policy_plugins.len(), 2);
    let policy_names = view.initial_response_header_policy_names();
    assert_eq!(
        policy_names
            .iter()
            .filter(|name| name.as_str() == "x-order")
            .count(),
        1,
        "multiple policy instances must share one precomputed provenance name"
    );
    assert!(policy_names.iter().any(|name| name == "x-removed"));
    apply_initial_response_header_policies(&policy_plugins, &mut headers);
    assert_eq!(headers.get("x-order").map(String::as_str), Some("second"));
    assert!(!headers.contains_key("x-removed"));
}

#[test]
fn test_multiple_same_type_with_different_plugins_mixed() {
    // Two stdout_logging + one cors on the same proxy — all three should be present
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2", "ps3"])],
        vec![
            make_plugin_config(
                "ps1",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("ps3", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 3);
    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert_eq!(names.iter().filter(|&&n| n == "stdout_logging").count(), 2);
    assert_eq!(names.iter().filter(|&&n| n == "cors").count(), 1);
}

#[test]
fn test_multiple_global_same_type_plugins() {
    // Two global stdout_logging plugins — both should be present on all proxies
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("g2", "stdout_logging", PluginScope::Global, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 2);
    assert!(plugins.iter().all(|p| p.name() == "stdout_logging"));
}

// ---- ProxyGroup scope tests ----

#[test]
fn test_proxy_group_plugin_shared_across_multiple_proxies() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec!["group1"]),
            make_proxy("p3", "/admin", vec![]), // no association
        ],
        vec![make_plugin_config(
            "group1",
            "cors",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1_plugins = cache.get_plugins("p1");
    let p2_plugins = cache.get_plugins("p2");
    let p3_plugins = cache.get_plugins("p3");

    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "cors");
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "cors");
    // p3 does not reference the group plugin — should have none
    assert_eq!(p3_plugins.len(), 0);
}

#[test]
fn test_proxy_group_plugin_shares_same_arc_instance() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec!["group1"]),
        ],
        vec![make_plugin_config(
            "group1",
            "cors",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1_plugins = cache.get_plugins("p1");
    let p2_plugins = cache.get_plugins("p2");

    // Both proxies should share the exact same Arc<dyn Plugin> instance
    let p1_ptr = std::sync::Arc::as_ptr(&p1_plugins[0]) as *const () as usize;
    let p2_ptr = std::sync::Arc::as_ptr(&p2_plugins[0]) as *const () as usize;
    assert_eq!(p1_ptr, p2_ptr, "ProxyGroup plugin instances must be shared");
}

#[test]
fn test_proxy_group_plugin_overrides_global_of_same_name() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec![]), // no group association
        ],
        vec![
            make_plugin_config("g1", "cors", PluginScope::Global, None, true),
            make_plugin_config("group1", "cors", PluginScope::ProxyGroup, None, true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1_plugins = cache.get_plugins("p1");
    let p2_plugins = cache.get_plugins("p2");

    // p1 gets the group plugin (replaces global cors)
    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "cors");

    // p2 still gets the global cors
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "cors");

    // The two should be different instances since one is global, one is group
    let p1_ptr = std::sync::Arc::as_ptr(&p1_plugins[0]) as *const () as usize;
    let p2_ptr = std::sync::Arc::as_ptr(&p2_plugins[0]) as *const () as usize;
    assert_ne!(p1_ptr, p2_ptr);
}

#[test]
fn test_invalid_optional_proxy_group_plugin_still_shadows_global() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config_with_json(
                "group1",
                "stdout_logging",
                json!("bad-config"),
                PluginScope::ProxyGroup,
                None,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert!(
        cache.get_plugins("p1").is_empty(),
        "failed proxy-group optional plugin must shadow the same-name global"
    );
    assert_eq!(cache.get_plugins("p2").len(), 1);
    assert_eq!(cache.get_plugins("p2")[0].name(), "stdout_logging");
}

#[test]
fn test_proxy_group_with_proxy_scoped_and_global() {
    // Test that all three scopes work together correctly
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["group1", "ps1"])],
        vec![
            make_plugin_config("g1", "stdout_logging", PluginScope::Global, None, true),
            make_plugin_config("group1", "cors", PluginScope::ProxyGroup, None, true),
            make_plugin_config("ps1", "rate_limiting", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 3);
    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"stdout_logging"));
    assert!(names.contains(&"cors"));
    assert!(names.contains(&"rate_limiting"));
}

#[test]
fn test_disabled_proxy_group_plugin_excluded() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["group1"])],
        vec![make_plugin_config(
            "group1",
            "cors",
            PluginScope::ProxyGroup,
            None,
            false, // disabled
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 0);
}

// ---- Construction tests ----

#[test]
fn test_empty_config_produces_empty_cache() {
    let config = make_config(vec![], vec![]);
    let cache = PluginCache::new(&config).unwrap();

    assert_eq!(cache.proxy_count(), 0);
    // Unknown proxy falls back to globals, which are also empty
    let plugins = cache.get_plugins("nonexistent");
    assert_eq!(plugins.len(), 0);
    assert!(!cache.requires_response_body_buffering("nonexistent"));
    assert!(!cache.requires_request_body_buffering("nonexistent"));
    assert!(!cache.requires_ws_frame_hooks("nonexistent"));
}

#[test]
fn test_single_proxy_single_plugin_cached() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "cors",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert_eq!(cache.proxy_count(), 1);
    let plugins = cache.get_plugins("p1");
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0].name(), "cors");
}

#[test]
fn test_multiple_proxies_with_different_plugins() {
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["ps1"]),
            make_proxy("p2", "/web", vec!["ps2"]),
        ],
        vec![
            make_plugin_config("ps1", "cors", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "rate_limiting", PluginScope::Proxy, Some("p2"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert_eq!(cache.proxy_count(), 2);

    let p1_plugins = cache.get_plugins("p1");
    assert_eq!(p1_plugins.len(), 1);
    assert_eq!(p1_plugins[0].name(), "cors");

    let p2_plugins = cache.get_plugins("p2");
    assert_eq!(p2_plugins.len(), 1);
    assert_eq!(p2_plugins[0].name(), "rate_limiting");
}

// ---- Protocol filtering: TCP-only / UDP-only exclusion ----

#[test]
fn test_tcp_only_plugin_excluded_from_http() {
    // tcp_connection_throttle supports TCP_ONLY_PROTOCOLS
    let config = make_config(
        vec![make_tcp_proxy("p1", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "tcp_connection_throttle",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // tcp_connection_throttle should be in the unfiltered list
    let all = cache.get_plugins("p1");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name(), "tcp_connection_throttle");

    // HTTP should NOT include tcp_connection_throttle
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    assert_eq!(
        http_plugins.len(),
        0,
        "tcp_connection_throttle must be excluded from HTTP"
    );

    // gRPC should NOT include tcp_connection_throttle
    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    assert_eq!(
        grpc_plugins.len(),
        0,
        "tcp_connection_throttle must be excluded from gRPC"
    );

    // WebSocket should NOT include tcp_connection_throttle
    let ws_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::WebSocket);
    assert_eq!(
        ws_plugins.len(),
        0,
        "tcp_connection_throttle must be excluded from WebSocket"
    );

    // UDP should NOT include tcp_connection_throttle
    let udp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Udp);
    assert_eq!(
        udp_plugins.len(),
        0,
        "tcp_connection_throttle must be excluded from UDP"
    );

    // TCP SHOULD include tcp_connection_throttle
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(tcp_plugins.len(), 1);
    assert_eq!(tcp_plugins[0].name(), "tcp_connection_throttle");
}

#[test]
fn test_udp_only_plugin_included_for_udp_excluded_from_others() {
    // udp_rate_limiting supports UDP_ONLY_PROTOCOLS
    let config = make_config(
        vec![make_proxy("p1", "/udp-svc", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "udp_rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // UDP should include udp_rate_limiting
    let udp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Udp);
    assert_eq!(udp_plugins.len(), 1);
    assert_eq!(udp_plugins[0].name(), "udp_rate_limiting");

    // HTTP should NOT include udp_rate_limiting
    let http_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    assert_eq!(
        http_plugins.len(),
        0,
        "udp_rate_limiting must be excluded from HTTP"
    );

    // TCP should NOT include udp_rate_limiting
    let tcp_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(
        tcp_plugins.len(),
        0,
        "udp_rate_limiting must be excluded from TCP"
    );

    // gRPC should NOT include udp_rate_limiting
    let grpc_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Grpc);
    assert_eq!(
        grpc_plugins.len(),
        0,
        "udp_rate_limiting must be excluded from gRPC"
    );
}

#[test]
fn test_all_protocols_plugin_included_for_all_protocol_types() {
    // stdout_logging supports ALL_PROTOCOLS
    let config = make_config(
        vec![make_proxy("p1", "/svc", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    for protocol in &[
        ProxyProtocol::Http,
        ProxyProtocol::Grpc,
        ProxyProtocol::WebSocket,
        ProxyProtocol::Tcp,
        ProxyProtocol::Udp,
    ] {
        let plugins = cache.get_plugins_for_protocol("p1", *protocol);
        assert_eq!(
            plugins.len(),
            1,
            "stdout_logging (ALL_PROTOCOLS) must be included for {:?}",
            protocol
        );
        assert_eq!(plugins[0].name(), "stdout_logging");
    }
}

#[test]
fn test_mixed_protocol_plugins_filtered_correctly_per_protocol() {
    // tcp_connection_throttle = TCP_ONLY, udp_rate_limiting = UDP_ONLY,
    // cors = HTTP_ONLY, stdout_logging = ALL_PROTOCOLS
    let config = make_config(
        vec![make_tcp_proxy("p1", vec!["ps1", "ps2", "ps3", "ps4"])],
        vec![
            make_plugin_config(
                "ps1",
                "tcp_connection_throttle",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "ps2",
                "udp_rate_limiting",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("ps3", "cors", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps4",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    // HTTP: only cors + stdout_logging
    let http = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let http_names: Vec<&str> = http.iter().map(|p| p.name()).collect();
    assert!(http_names.contains(&"cors"));
    assert!(http_names.contains(&"stdout_logging"));
    assert!(!http_names.contains(&"tcp_connection_throttle"));
    assert!(!http_names.contains(&"udp_rate_limiting"));
    assert_eq!(http_names.len(), 2);

    // TCP: only tcp_connection_throttle + stdout_logging
    let tcp = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let tcp_names: Vec<&str> = tcp.iter().map(|p| p.name()).collect();
    assert!(tcp_names.contains(&"tcp_connection_throttle"));
    assert!(tcp_names.contains(&"stdout_logging"));
    assert!(!tcp_names.contains(&"cors"));
    assert!(!tcp_names.contains(&"udp_rate_limiting"));
    assert_eq!(tcp_names.len(), 2);

    // UDP: only udp_rate_limiting + stdout_logging
    let udp = cache.get_plugins_for_protocol("p1", ProxyProtocol::Udp);
    let udp_names: Vec<&str> = udp.iter().map(|p| p.name()).collect();
    assert!(udp_names.contains(&"udp_rate_limiting"));
    assert!(udp_names.contains(&"stdout_logging"));
    assert!(!udp_names.contains(&"cors"));
    assert!(!udp_names.contains(&"tcp_connection_throttle"));
    assert_eq!(udp_names.len(), 2);
}

#[test]
fn test_tcp_connection_throttle_rejects_udp_and_dtls_attachments() {
    for scheme in [BackendScheme::Udp, BackendScheme::Dtls] {
        let config = make_config(
            vec![make_udp_proxy("p1", vec!["throttle"], scheme)],
            vec![make_plugin_config_with_json(
                "throttle",
                "tcp_connection_throttle",
                json!({"max_connections_per_key": 1}),
                PluginScope::Proxy,
                Some("p1"),
            )],
        );
        let error = PluginCache::new(&config)
            .err()
            .expect("UDP/DTLS attachment must fail visibly");
        assert!(error.contains("unsupported UDP/DTLS"), "{error}");
        assert!(error.contains("udp_rate_limiting"), "{error}");
    }

    let global_only_udp = make_config(
        vec![make_udp_proxy("p1", vec![], BackendScheme::Udp)],
        vec![make_plugin_config_with_json(
            "global-throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::Global,
            None,
        )],
    );
    let error = PluginCache::new(&global_only_udp)
        .err()
        .expect("a global throttle with only UDP coverage must fail visibly");
    assert!(error.contains("has no TCP/TCP+TLS proxy"), "{error}");

    let http_attachment = make_config(
        vec![make_proxy("p1", "/api", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let error = PluginCache::new(&http_attachment)
        .err()
        .expect("HTTP-family attachment must fail visibly");
    assert!(error.contains("HTTP-family"), "{error}");
}

#[test]
fn test_tcp_connection_throttle_accepts_tcp_and_tcp_tls_attachments() {
    for scheme in [BackendScheme::Tcp, BackendScheme::Tcps] {
        let mut proxy = make_tcp_proxy("p1", vec!["throttle"]);
        proxy.backend_scheme = Some(scheme);
        proxy.dispatch_kind = DispatchKind::from(scheme);
        let config = make_config(
            vec![proxy],
            vec![make_plugin_config_with_json(
                "throttle",
                "tcp_connection_throttle",
                json!({"max_connections_per_key": 1}),
                PluginScope::Proxy,
                Some("p1"),
            )],
        );
        let cache = PluginCache::new(&config)
            .unwrap_or_else(|error| panic!("{scheme} attachment was rejected: {error}"));
        let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name(), "tcp_connection_throttle");
    }
}

#[test]
fn test_tcp_connection_throttle_global_mixed_protocol_scope_protects_only_tcp() {
    let config = make_config(
        vec![
            make_tcp_proxy("tcp", vec![]),
            make_udp_proxy("udp", vec![], BackendScheme::Udp),
        ],
        vec![make_plugin_config_with_json(
            "global-throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&config).expect("mixed global scope has TCP coverage");
    assert_eq!(
        cache
            .get_plugins_for_protocol("tcp", ProxyProtocol::Tcp)
            .len(),
        1
    );
    assert!(
        cache
            .get_plugins_for_protocol("udp", ProxyProtocol::Udp)
            .is_empty()
    );
}

#[test]
fn test_tcp_connection_throttle_proxy_group_rejects_mixed_protocol_attachment() {
    let config = make_config(
        vec![
            make_tcp_proxy("tcp", vec!["group-throttle"]),
            make_udp_proxy("udp", vec!["group-throttle"], BackendScheme::Dtls),
        ],
        vec![make_plugin_config_with_json(
            "group-throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1}),
            PluginScope::ProxyGroup,
            None,
        )],
    );
    let error = PluginCache::new(&config)
        .err()
        .expect("mixed-protocol proxy-group attachment must fail closed");
    assert!(error.contains("udp (dtls)"), "{error}");
    assert!(error.contains("only TCP/TCP+TLS is supported"), "{error}");
}

#[test]
fn test_tcp_connection_throttle_global_validation_is_namespace_scoped() {
    let mut tenant_a_http = make_proxy("shared-id", "/tenant-a", vec![]);
    tenant_a_http.namespace = "tenant-a".to_string();
    let mut tenant_b_tcp = make_tcp_proxy("shared-id", vec![]);
    tenant_b_tcp.namespace = "tenant-b".to_string();
    let mut tenant_a_throttle = make_plugin_config_with_json(
        "global-throttle",
        "tcp_connection_throttle",
        json!({"max_connections_per_key": 1}),
        PluginScope::Global,
        None,
    );
    tenant_a_throttle.namespace = "tenant-a".to_string();

    let config = make_config(vec![tenant_a_http, tenant_b_tcp], vec![tenant_a_throttle]);
    let error = PluginCache::new(&config)
        .err()
        .expect("another namespace's TCP proxy must not satisfy global coverage");
    assert!(error.contains("has no TCP/TCP+TLS proxy"), "{error}");
}

#[tokio::test]
async fn test_tcp_connection_throttle_partial_rejection_rolls_back_all_instances() {
    let mut wide = make_plugin_config_with_json(
        "wide",
        "tcp_connection_throttle",
        json!({"max_connections_per_key": 2, "cleanup_interval_seconds": 0}),
        PluginScope::Proxy,
        Some("p1"),
    );
    wide.priority_override = Some(1000);
    let mut strict = make_plugin_config_with_json(
        "strict",
        "tcp_connection_throttle",
        json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
        PluginScope::Proxy,
        Some("p1"),
    );
    strict.priority_override = Some(2000);
    let config = make_config(
        vec![make_tcp_proxy("p1", vec!["wide", "strict"])],
        vec![wide, strict],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    assert_eq!(plugins.len(), 2);
    assert_eq!(plugins[0].priority(), 1000);
    assert_eq!(plugins[1].priority(), 2000);

    let mut first = make_tcp_stream_context("10.0.0.1");
    assert!(run_tcp_connect_chain(&plugins, &mut first).await);
    assert_eq!(first.admission_permits.len(), 2);

    let mut rejected = make_tcp_stream_context("10.0.0.1");
    assert!(!run_tcp_connect_chain(&plugins, &mut rejected).await);
    assert!(rejected.admission_permits.is_empty());
    assert_eq!(cache.total_rate_limiter_keys(), 2);

    first.release_admission_permits();
    assert_eq!(cache.total_rate_limiter_keys(), 0);
}

#[tokio::test]
async fn test_tcp_connection_throttle_full_reload_preserves_live_admissions() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let old_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut old_connection = make_tcp_stream_context("10.0.0.2");
    assert!(run_tcp_connect_chain(&old_plugins, &mut old_connection).await);

    let mut replacement = initial.clone();
    replacement.plugin_configs[0].priority_override = Some(1800);
    replacement.plugin_configs[0].updated_at = Utc::now();
    cache.rebuild(&replacement).unwrap();
    let new_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut blocked = make_tcp_stream_context("10.0.0.2");
    assert!(!run_tcp_connect_chain(&new_plugins, &mut blocked).await);

    old_connection.release_admission_permits();
    let mut admitted = make_tcp_stream_context("10.0.0.2");
    assert!(run_tcp_connect_chain(&new_plugins, &mut admitted).await);
    admitted.release_admission_permits();
    assert_eq!(cache.total_rate_limiter_keys(), 0);
}

#[tokio::test]
async fn test_tcp_connection_throttle_delta_reload_applies_new_limit_to_shared_state() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let old_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut old_connection = make_tcp_stream_context("10.0.0.3");
    assert!(run_tcp_connect_chain(&old_plugins, &mut old_connection).await);

    let mut replacement = initial.clone();
    replacement.plugin_configs[0].config =
        json!({"max_connections_per_key": 2, "cleanup_interval_seconds": 0});
    replacement.plugin_configs[0].updated_at = Utc::now();
    cache
        .apply_delta(&replacement, &HashSet::from(["p1".to_string()]), &[], false)
        .unwrap();
    let new_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut second = make_tcp_stream_context("10.0.0.3");
    assert!(run_tcp_connect_chain(&new_plugins, &mut second).await);
    let mut third = make_tcp_stream_context("10.0.0.3");
    assert!(!run_tcp_connect_chain(&new_plugins, &mut third).await);

    old_connection.release_admission_permits();
    second.release_admission_permits();
    assert_eq!(cache.total_rate_limiter_keys(), 0);
}

#[tokio::test]
async fn test_tcp_connection_throttle_decreased_limit_waits_for_old_permits_to_drain() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 2, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let old_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut first = make_tcp_stream_context("10.0.0.5");
    let mut second = make_tcp_stream_context("10.0.0.5");
    assert!(run_tcp_connect_chain(&old_plugins, &mut first).await);
    assert!(run_tcp_connect_chain(&old_plugins, &mut second).await);

    let mut replacement = initial.clone();
    replacement.plugin_configs[0].config =
        json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0});
    cache.rebuild(&replacement).unwrap();
    let new_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut blocked = make_tcp_stream_context("10.0.0.5");
    assert!(!run_tcp_connect_chain(&new_plugins, &mut blocked).await);
    first.release_admission_permits();
    assert!(!run_tcp_connect_chain(&new_plugins, &mut blocked).await);
    second.release_admission_permits();
    assert!(run_tcp_connect_chain(&new_plugins, &mut blocked).await);
    blocked.release_admission_permits();
}

#[tokio::test]
async fn test_tcp_connection_throttle_scope_move_keeps_same_proxy_accounting() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let old_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut old_connection = make_tcp_stream_context("10.0.0.6");
    assert!(run_tcp_connect_chain(&old_plugins, &mut old_connection).await);

    let mut moved = initial.clone();
    moved.plugin_configs[0].scope = PluginScope::ProxyGroup;
    moved.plugin_configs[0].proxy_id = None;
    cache.rebuild(&moved).unwrap();
    let moved_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut blocked = make_tcp_stream_context("10.0.0.6");
    assert!(!run_tcp_connect_chain(&moved_plugins, &mut blocked).await);
    old_connection.release_admission_permits();
    assert!(run_tcp_connect_chain(&moved_plugins, &mut blocked).await);
    blocked.release_admission_permits();
}

#[tokio::test]
async fn test_tcp_connection_throttle_rejected_reload_keeps_old_generation() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut existing = make_tcp_stream_context("10.0.0.7");
    assert!(run_tcp_connect_chain(&plugins, &mut existing).await);

    let mut invalid = initial.clone();
    invalid.plugin_configs[0].config = json!({"max_connections_per_key": 0});
    assert!(cache.rebuild(&invalid).is_err());
    let still_current = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut blocked = make_tcp_stream_context("10.0.0.7");
    assert!(!run_tcp_connect_chain(&still_current, &mut blocked).await);
    existing.release_admission_permits();
    assert!(run_tcp_connect_chain(&still_current, &mut blocked).await);
    blocked.release_admission_permits();
}

#[tokio::test]
async fn test_tcp_connection_throttle_removed_policy_is_generation_isolated() {
    let initial = make_config(
        vec![make_tcp_proxy("p1", vec!["throttle"])],
        vec![make_plugin_config_with_json(
            "throttle",
            "tcp_connection_throttle",
            json!({"max_connections_per_key": 1, "cleanup_interval_seconds": 0}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&initial).unwrap();
    let old_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut old_connection = make_tcp_stream_context("10.0.0.4");
    assert!(run_tcp_connect_chain(&old_plugins, &mut old_connection).await);

    let removed = make_config(vec![make_tcp_proxy("p1", vec![])], vec![]);
    cache.rebuild(&removed).unwrap();
    cache.rebuild(&initial).unwrap();
    let recreated_plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Tcp);
    let mut recreated = make_tcp_stream_context("10.0.0.4");
    assert!(run_tcp_connect_chain(&recreated_plugins, &mut recreated).await);

    old_connection.release_admission_permits();
    let mut still_blocked = make_tcp_stream_context("10.0.0.4");
    assert!(!run_tcp_connect_chain(&recreated_plugins, &mut still_blocked).await);
    recreated.release_admission_permits();
    assert_eq!(cache.total_rate_limiter_keys(), 0);
}

// ---- Body buffering flag tests ----

#[test]
fn test_no_body_buffering_plugins_returns_false() {
    // stdout_logging does not require any body buffering
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert!(
        !cache.requires_request_body_buffering("p1"),
        "stdout_logging should not require request body buffering"
    );
    assert!(
        !cache.requires_response_body_buffering("p1"),
        "stdout_logging should not require response body buffering"
    );
}

#[test]
fn test_body_validator_requires_request_body_buffering() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_json(
            "ps1",
            "body_validator",
            json!({"validate_xml": true}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert!(
        cache.requires_request_body_buffering("p1"),
        "body_validator with request validation should require request body buffering"
    );
}

#[test]
fn test_response_caching_requires_response_body_buffering() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_json(
            "ps1",
            "response_caching",
            json!({"ttl_seconds": 60}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    assert!(
        cache.requires_response_body_buffering("p1"),
        "response_caching should require response body buffering"
    );
}

#[test]
fn test_buffering_flags_use_global_fallback_for_unknown_proxy() {
    // Global response_caching should make the fallback return true
    let config = make_config(
        vec![make_proxy("p1", "/api", vec![])],
        vec![make_plugin_config_with_json(
            "g1",
            "response_caching",
            json!({"ttl_seconds": 60}),
            PluginScope::Global,
            None,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // Unknown proxy uses global fallback
    assert!(
        cache.requires_response_body_buffering("unknown"),
        "unknown proxy should use global fallback for response buffering"
    );
}

// ---- Metadata flag tests ----

#[test]
fn test_modifies_request_headers_flag_computed() {
    // request_transformer with header rules modifies request headers
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "request_transformer",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::MODIFIES_REQUEST_HEADERS),
        "request_transformer should set MODIFIES_REQUEST_HEADERS"
    );
}

#[test]
fn test_hmac_auth_rejects_request_body_transformer_composition() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["hmac", "transform"])],
        vec![
            make_plugin_config("hmac", "hmac_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config_with_json(
                "transform",
                "request_transformer",
                json!({
                    "rules": [{
                        "operation": "add",
                        "target": "body",
                        "key": "gateway",
                        "value": "ferrum"
                    }]
                }),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );

    let error = PluginCache::new(&config)
        .err()
        .expect("composition must fail closed");
    assert!(error.contains("hmac_auth cannot be combined"));
    assert!(error.contains("request_transformer"));
    assert!(error.contains("protocol Http"));
}

#[test]
fn test_hmac_auth_allows_header_only_request_transformer() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["hmac", "transform"])],
        vec![
            make_plugin_config("hmac", "hmac_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "transform",
                "request_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );

    assert!(PluginCache::new(&config).is_ok());
}

#[test]
fn test_duplicate_effective_correlation_headers_are_rejected() {
    let first = make_plugin_config_with_json(
        "corr-first",
        "correlation_id",
        json!({}),
        PluginScope::Proxy,
        Some("p1"),
    );
    let mut second = make_plugin_config_with_json(
        "corr-second",
        "correlation_id",
        json!({"header_name": " X-Request-ID "}),
        PluginScope::Proxy,
        Some("p1"),
    );
    second.priority_override = Some(75);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["corr-first", "corr-second"])],
        vec![first, second],
    );

    let error = PluginCache::new(&config)
        .err()
        .expect("duplicate normalized correlation headers must fail closed");
    assert!(error.contains("duplicate effective header_name \"x-request-id\""));
    assert!(error.contains("proxy_id=p1"));
}

#[test]
fn test_real_ip_header_collision_is_rejected_by_candidate_and_runtime_cache() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["corr"])],
        vec![make_plugin_config_with_json(
            "corr",
            "correlation_id",
            json!({"header_name": " CF-Connecting-IP "}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    let candidate_error = validate_plugin_composition_candidate_with_real_ip_header_for_test(
        &config,
        Some("cf-connecting-ip"),
    )
    .expect_err("candidate admission must reject the real-IP header collision");
    assert!(candidate_error.contains("FERRUM_REAL_IP_HEADER"));

    let cache_error = plugin_cache_with_real_ip_header_for_test(&config, Some("cf-connecting-ip"))
        .err()
        .expect("runtime cache construction must reject the real-IP header collision");
    assert!(cache_error.contains("FERRUM_REAL_IP_HEADER"));
}

#[test]
fn test_real_ip_header_non_collision_is_accepted_by_candidate_and_runtime_cache() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["corr"])],
        vec![make_plugin_config_with_json(
            "corr",
            "correlation_id",
            json!({"header_name": "X-Request-ID"}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );

    validate_plugin_composition_candidate_with_real_ip_header_for_test(
        &config,
        Some("cloudfront-viewer-address"),
    )
    .expect("distinct candidate headers must be accepted");
    plugin_cache_with_real_ip_header_for_test(&config, Some("cloudfront-viewer-address"))
        .expect("distinct runtime headers must be accepted");
}

#[test]
fn test_equal_effective_correlation_priorities_are_rejected() {
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["corr-internal", "corr-external"],
        )],
        vec![
            make_plugin_config_with_json(
                "corr-internal",
                "correlation_id",
                json!({"header_name": "x-internal-request-id"}),
                PluginScope::Proxy,
                Some("p1"),
            ),
            make_plugin_config_with_json(
                "corr-external",
                "correlation_id",
                json!({"header_name": "x-external-request-id"}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );

    let error = PluginCache::new(&config)
        .err()
        .expect("equal correlation priorities must fail closed");
    assert!(error.contains("duplicate effective priority 50"));
    assert!(error.contains("priority_override"));
    assert!(error.contains("proxy_id=p1"));
}

#[test]
fn test_same_correlation_header_on_disjoint_proxy_chains_is_allowed() {
    let config = make_config(
        vec![
            make_proxy("p1", "/one", vec!["corr-one"]),
            make_proxy("p2", "/two", vec!["corr-two"]),
        ],
        vec![
            make_plugin_config(
                "corr-one",
                "correlation_id",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config(
                "corr-two",
                "correlation_id",
                PluginScope::Proxy,
                Some("p2"),
                true,
            ),
        ],
    );

    assert!(PluginCache::new(&config).is_ok());
}

#[test]
fn test_custom_only_duplicate_effective_correlation_headers_are_rejected() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }

    // The example plugin retains configured whitespace and casing at the
    // capability boundary, modeling a third-party implementation that did not
    // pre-normalize its correlation_id_header_name() result. Core validation
    // must still trim and compare these two claims case-insensitively.
    let first = make_plugin_config_with_json(
        "custom-corr-first",
        "example_plugin",
        json!({"correlation_header_name": "x-custom-correlation-id"}),
        PluginScope::Proxy,
        Some("p1"),
    );
    let mut second = make_plugin_config_with_json(
        "custom-corr-second",
        "example_plugin",
        json!({"correlation_header_name": " X-Custom-Correlation-ID "}),
        PluginScope::Proxy,
        Some("p1"),
    );
    second.priority_override = Some(5001);
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["custom-corr-first", "custom-corr-second"],
        )],
        vec![first, second],
    );

    let error = PluginCache::new(&config)
        .err()
        .expect("mixed-whitespace/case correlation claims must fail closed");
    assert!(error.contains("duplicate effective header_name \"x-custom-correlation-id\""));
    assert!(error.contains("proxy_id=p1"));
}

#[test]
fn test_empty_third_party_correlation_capability_claims_fail_closed_clearly() {
    for claim in ["", " \t "] {
        let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RawCorrelationClaimPlugin { claim })];
        let error =
            ferrum_edge::_test_support::validate_correlation_id_composition_for_test(&plugins)
                .expect_err("one empty normalized capability claim must fail closed");

        assert!(
            error.contains("plugin \"raw_correlation_claim\" returned an empty correlation_id_header_name capability claim"),
            "unexpected empty-claim error for {claim:?}: {error}"
        );
        assert!(error.contains("return None"), "got: {error}");
        assert!(
            !error.contains("duplicate effective header_name"),
            "got: {error}"
        );
    }
}

#[test]
fn test_third_party_correlation_capability_cannot_claim_real_ip_header() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RawCorrelationClaimPlugin {
        claim: " CF-Connecting-IP ",
    })];
    let error = validate_correlation_id_composition_with_real_ip_header_for_test(
        &plugins,
        Some("cf-connecting-ip"),
    )
    .expect_err("third-party real-IP header collision must fail closed");
    assert!(error.contains("FERRUM_REAL_IP_HEADER"), "got: {error}");
    assert!(error.contains("cf-connecting-ip"), "got: {error}");
}

#[test]
fn test_third_party_correlation_capability_cannot_claim_reserved_header() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RawCorrelationClaimPlugin {
        claim: " AuThOrIzAtIoN ",
    })];
    let error = ferrum_edge::_test_support::validate_correlation_id_composition_for_test(&plugins)
        .expect_err("third-party reserved header ownership must fail closed");

    assert!(
        error.contains("effective header_name \"authorization\""),
        "got: {error}"
    );
    assert!(
        error.contains("plugin \"raw_correlation_claim\""),
        "got: {error}"
    );
    assert!(error.contains("protocol Http"), "got: {error}");
    assert!(
        error.contains("reserved protocol-managed or security-sensitive header ownership"),
        "got: {error}"
    );
}

#[test]
fn test_shipped_custom_correlation_plugin_cannot_claim_reserved_header() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }

    let custom_owner = make_plugin_config_with_json(
        "custom-corr-reserved",
        "example_plugin",
        json!({"correlation_header_name": " AuThOrIzAtIoN "}),
        PluginScope::Proxy,
        Some("p1"),
    );
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["custom-corr-reserved"])],
        vec![custom_owner],
    );

    let error = PluginCache::new(&config)
        .err()
        .expect("shipped custom plugin must not claim reserved correlation headers");
    assert!(
        error.contains("effective header_name \"authorization\""),
        "got: {error}"
    );
    assert!(error.contains("plugin \"example_plugin\""), "got: {error}");
    assert!(error.contains("protocol Http"), "got: {error}");
    assert!(error.contains("proxy_id=p1"), "got: {error}");
    assert!(error.contains("reserved"), "got: {error}");
}

#[test]
fn test_custom_correlation_owners_on_disjoint_protocols_are_allowed() {
    if !ferrum_edge::custom_plugins::custom_plugin_names().contains(&"example_plugin") {
        return;
    }

    let http_owner = make_plugin_config_with_json(
        "custom-corr-http",
        "example_plugin",
        json!({"correlation_header_name": "x-custom-correlation-id"}),
        PluginScope::Proxy,
        Some("p1"),
    );
    let tcp_owner = make_plugin_config_with_json(
        "custom-corr-tcp",
        "example_plugin",
        json!({
            "correlation_header_name": " X-Custom-Correlation-ID ",
            "protocol": "tcp"
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["custom-corr-http", "custom-corr-tcp"],
        )],
        vec![http_owner, tcp_owner],
    );

    let cache = PluginCache::new(&config)
        .expect("disjoint protocol owners cannot contend for correlation ownership");
    assert_eq!(
        cache
            .get_plugins_for_protocol("p1", ProxyProtocol::Http)
            .len(),
        1
    );
    assert_eq!(
        cache
            .get_plugins_for_protocol("p1", ProxyProtocol::Tcp)
            .len(),
        1
    );
}

#[test]
fn test_modifies_request_headers_flag_false_when_no_plugin_modifies() {
    // stdout_logging does not modify request headers
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        !caps.has(PluginCapabilities::MODIFIES_REQUEST_HEADERS),
        "stdout_logging should not set MODIFIES_REQUEST_HEADERS"
    );
}

#[test]
fn test_decoded_query_params_capability_preserved_with_priority_override() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "mesh_route_dispatch",
        json!({
            "rules": [{
                "match": {"query_params": {"variant": "beta"}},
                "destination": {"upstream_id": "canary"}
            }]
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(2990);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS),
        "mesh_route_dispatch query-param rules must opt HTTP/3 into decoded query materialization"
    );
}

#[test]
fn test_key_auth_query_location_enables_decoded_h3_query_capability() {
    let query_config = make_config(
        vec![make_proxy("p1", "/api", vec!["keyauth"])],
        vec![make_plugin_config_with_json(
            "keyauth",
            "key_auth",
            json!({"key_location": "query:api_key"}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let query_cache = PluginCache::new(&query_config).unwrap();
    assert!(
        query_cache
            .get_capabilities("p1", ProxyProtocol::Http)
            .has(PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS)
    );

    let header_config = make_config(
        vec![make_proxy("p1", "/api", vec!["keyauth"])],
        vec![make_plugin_config_with_json(
            "keyauth",
            "key_auth",
            json!({"key_location": "header:X-API-Key"}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let header_cache = PluginCache::new(&header_config).unwrap();
    assert!(
        !header_cache
            .get_capabilities("p1", ProxyProtocol::Http)
            .has(PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS)
    );
}

#[test]
fn test_opa_body_buffering_is_deferred_until_after_authentication() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "opa",
        json!({
            "opa_host": "http://opa.internal:8181",
            "policy_path": "ferrum/authz/allow",
            "include_body": true,
            "max_body_bytes": 4096
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    plugin_config.priority_override = Some(2081);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::HAS_BODY_BEFORE_AUTHORIZE),
        "OPA include_body must advertise post-authentication authorize buffering"
    );
    assert!(
        !caps.has(PluginCapabilities::HAS_BODY_BEFORE_AUTHENTICATE),
        "OPA must not force unauthenticated body buffering"
    );
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let opa = plugins
        .iter()
        .find(|plugin| plugin.name() == "opa")
        .expect("OPA plugin is cached");
    assert_eq!(
        opa.request_body_buffer_limit(),
        Some(4096),
        "priority wrappers must preserve OPA's positive local body ceiling"
    );
}

#[test]
fn test_waf_sets_needs_final_request_body_context_capability() {
    // WAF returns true for `needs_final_request_body_context()` because it
    // annotates request metadata (`waf.rule_hits`, `waf.action`, etc.) from
    // the body-scan hook. The proxy hot path reads this bit instead of
    // iterating plugins per request — make sure the bit is set when WAF is
    // configured.
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_json(
            "ps1",
            "waf",
            json!({}),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT),
        "WAF plugin must set NEEDS_FINAL_REQUEST_BODY_CONTEXT so the proxy \
         passes a mutable RequestContext into on_final_request_body hooks"
    );
}

#[test]
fn test_ai_federation_sets_terminal_final_body_dispatch_capability() {
    let mut plugin_config = make_plugin_config_with_json(
        "ps1",
        "ai_federation",
        json!({
            "providers": [{
                "name": "openai",
                "provider_type": "openai",
                "api_key": "sk-test-key",
                "model_patterns": ["gpt-*"]
            }]
        }),
        PluginScope::Proxy,
        Some("p1"),
    );
    // Exercise the priority wrapper too: it must forward the terminal dispatch
    // contract or the proxy would run federation inside backend accounting.
    plugin_config.priority_override = Some(2099);
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::FINAL_BODY_BEFORE_BACKEND_DISPATCH),
        "AI federation must finalize and dispatch before backend-only preflights and accounting"
    );
}

#[test]
fn test_decoded_query_params_capability_false_for_method_only_route_dispatch() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1"])],
        vec![make_plugin_config_with_json(
            "ps1",
            "mesh_route_dispatch",
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "canary"}
                }]
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        !caps.has(PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS),
        "method/header-only route dispatch must preserve HTTP/3 raw query materialization"
    );
}

#[test]
fn test_requires_udp_datagram_hooks_flag_with_udp_rate_limiting() {
    // udp_rate_limiting returns true for requires_udp_datagram_hooks()
    let config = make_config(
        vec![make_proxy("p1", "/udp-svc", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "udp_rate_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // The unfiltered plugin list should contain udp_rate_limiting
    let all = cache.get_plugins("p1");
    assert_eq!(all.len(), 1);
    assert!(
        all[0].requires_udp_datagram_hooks(),
        "udp_rate_limiting must opt into UDP datagram hooks"
    );
}

#[test]
fn test_requires_udp_datagram_hooks_false_for_non_udp_plugin() {
    // stdout_logging does not opt into UDP datagram hooks
    let config = make_config(
        vec![make_proxy("p1", "/svc", vec!["ps1"])],
        vec![make_plugin_config(
            "ps1",
            "stdout_logging",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    let all = cache.get_plugins("p1");
    assert_eq!(all.len(), 1);
    assert!(
        !all[0].requires_udp_datagram_hooks(),
        "stdout_logging must not opt into UDP datagram hooks"
    );
}

// ---- Auth plugin phase data precomputation ----

#[test]
fn test_auth_plugins_precomputed_for_protocol() {
    // key_auth is an auth plugin (HTTP_FAMILY), should be in auth_plugins for HTTP
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps2",
                "stdout_logging",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let auth = cache.get_auth_plugins("p1", ProxyProtocol::Http);
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].name(), "key_auth");

    let caps = cache.get_capabilities("p1", ProxyProtocol::Http);
    assert!(
        caps.has(PluginCapabilities::HAS_AUTH_PLUGINS),
        "key_auth should set HAS_AUTH_PLUGINS"
    );

    // TCP should not have key_auth (HTTP_FAMILY only)
    let tcp_auth = cache.get_auth_plugins("p1", ProxyProtocol::Tcp);
    assert_eq!(
        tcp_auth.len(),
        0,
        "key_auth must not appear in TCP auth plugins"
    );
}

// ---- Scope resolution edge cases ----

#[test]
fn test_proxy_group_only_applies_to_associated_proxies() {
    // p1 is associated, p2 is not, p3 is associated
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["group1"]),
            make_proxy("p2", "/web", vec![]),
            make_proxy("p3", "/admin", vec!["group1"]),
        ],
        vec![make_plugin_config(
            "group1",
            "rate_limiting",
            PluginScope::ProxyGroup,
            None,
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();

    // p1 and p3 should have the group plugin
    let p1 = cache.get_plugins("p1");
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].name(), "rate_limiting");

    let p3 = cache.get_plugins("p3");
    assert_eq!(p3.len(), 1);
    assert_eq!(p3[0].name(), "rate_limiting");

    // p2 should have no plugins (no global, no association)
    let p2 = cache.get_plugins("p2");
    assert_eq!(
        p2.len(),
        0,
        "proxy without group association must not receive group plugin"
    );

    // p1 and p3 should share the same Arc instance
    let p1_ptr = Arc::as_ptr(&p1[0]) as *const () as usize;
    let p3_ptr = Arc::as_ptr(&p3[0]) as *const () as usize;
    assert_eq!(
        p1_ptr, p3_ptr,
        "proxy-group plugin must be shared across associated proxies"
    );
}

#[test]
fn test_proxy_scoped_overrides_global_for_specific_proxy_only() {
    // Global cors, proxy-scoped cors on p1 only — p2 should keep global
    let config = make_config(
        vec![
            make_proxy("p1", "/api", vec!["ps1"]),
            make_proxy("p2", "/web", vec![]),
        ],
        vec![
            make_plugin_config("g1", "cors", PluginScope::Global, None, true),
            make_plugin_config("ps1", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();

    let p1 = cache.get_plugins("p1");
    let p2 = cache.get_plugins("p2");

    // Both should have exactly one cors plugin
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].name(), "cors");
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].name(), "cors");

    // But they should be different instances (proxy-scoped vs global)
    let p1_ptr = Arc::as_ptr(&p1[0]) as *const () as usize;
    let p2_ptr = Arc::as_ptr(&p2[0]) as *const () as usize;
    assert_ne!(
        p1_ptr, p2_ptr,
        "p1 should have proxy-scoped cors, p2 should have global cors"
    );
}

// ---- Request view consistency ----

#[test]
fn test_request_view_contains_all_precomputed_fields() {
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2", "ps3"])],
        vec![
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "ps2",
                "request_transformer",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "ps3",
                "response_caching",
                json!({"ttl_seconds": 60}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("p1", ProxyProtocol::Http);

    // Plugins should be filtered for HTTP protocol
    let plugins = view.plugins();
    let names: Vec<&str> = plugins.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"key_auth"));
    assert!(names.contains(&"request_transformer"));
    assert!(names.contains(&"response_caching"));

    // Auth plugins precomputed
    let auth = view.auth_plugins();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].name(), "key_auth");

    // Capabilities
    assert!(
        view.capabilities()
            .has(PluginCapabilities::MODIFIES_REQUEST_HEADERS)
    );
    assert!(
        view.capabilities()
            .has(PluginCapabilities::HAS_AUTH_PLUGINS)
    );

    // Buffering flags
    assert!(view.requires_response_body_buffering());
    assert!(!view.requires_ws_frame_hooks());
}

// ---- Priority with default vs override ----

#[test]
fn test_default_priority_used_when_no_override() {
    // cors has default priority 100, key_auth has default priority 1200
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config("ps1", "key_auth", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config("ps2", "cors", PluginScope::Proxy, Some("p1"), true),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 2);
    // cors (100) should come before key_auth (1200)
    assert_eq!(plugins[0].name(), "cors");
    assert_eq!(plugins[1].name(), "key_auth");
}

#[test]
fn h3_grpc_web_view_retains_http_guardrails_and_adds_only_compatible_grpc_policies() {
    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["dedup", "grpc-web", "method-router", "deadline"],
        )],
        vec![
            make_plugin_config(
                "dedup",
                "request_deduplication",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config("grpc-web", "grpc_web", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "method-router",
                "grpc_method_router",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "deadline",
                "grpc_deadline",
                json!({"default_deadline_ms": 1000}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    let cache = PluginCache::new(&config).expect("plugin cache");
    let view = ferrum_edge::_test_support::grpc_web_request_view_for_test(&cache, "p1");

    assert!(
        view.plugins
            .iter()
            .any(|name| name == "request_deduplication")
    );
    assert!(view.plugins.iter().any(|name| name == "grpc_web"));
    assert_eq!(
        view.plugins
            .iter()
            .filter(|name| name.as_str() == "grpc_method_router")
            .count(),
        1
    );
    assert_eq!(
        view.plugins
            .iter()
            .filter(|name| name.as_str() == "grpc_deadline")
            .count(),
        1
    );
    assert_eq!(view.grpc_deadline_plugins, vec!["grpc_deadline"]);
    assert_eq!(view.backend_path_plugins, vec!["grpc_method_router"]);

    let merged_names = cache
        .get_plugins("p1")
        .iter()
        .filter(|plugin| {
            plugin.supported_protocols().contains(&ProxyProtocol::Http)
                || (["grpc_method_router", "grpc_deadline"].contains(&plugin.name())
                    && plugin.supported_protocols().contains(&ProxyProtocol::Grpc))
        })
        .map(|plugin| plugin.name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        view.plugins, merged_names,
        "the precomputed composed view must preserve merged priority/config order"
    );

    let reloaded = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["grpc-web", "method-router", "deadline"],
        )],
        vec![
            make_plugin_config("grpc-web", "grpc_web", PluginScope::Proxy, Some("p1"), true),
            make_plugin_config(
                "method-router",
                "grpc_method_router",
                PluginScope::Proxy,
                Some("p1"),
                true,
            ),
            make_plugin_config_with_json(
                "deadline",
                "grpc_deadline",
                json!({"default_deadline_ms": 1000}),
                PluginScope::Proxy,
                Some("p1"),
            ),
        ],
    );
    cache
        .apply_delta(
            &reloaded,
            &std::collections::HashSet::from(["p1".to_string()]),
            &[],
            false,
        )
        .expect("gRPC-Web composed view delta rebuild");
    let reloaded_view = ferrum_edge::_test_support::grpc_web_request_view_for_test(&cache, "p1");
    assert!(
        !reloaded_view
            .plugins
            .iter()
            .any(|name| name == "request_deduplication")
    );
    assert_eq!(
        reloaded_view
            .plugins
            .iter()
            .filter(|name| name.as_str() == "grpc_deadline")
            .count(),
        1
    );
}

#[test]
fn test_priority_override_reverses_default_order() {
    // Give cors a higher priority number than key_auth via override
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "ps2"])],
        vec![
            make_plugin_config_with_priority(
                "ps1",
                "key_auth",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(50), // lower than cors's default
            ),
            make_plugin_config_with_priority(
                "ps2",
                "cors",
                PluginScope::Proxy,
                Some("p1"),
                true,
                Some(5000), // higher than key_auth's override
            ),
        ],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 2);
    // key_auth (50) should now come before cors (5000)
    assert_eq!(plugins[0].name(), "key_auth");
    assert_eq!(plugins[0].priority(), 50);
    assert_eq!(plugins[1].name(), "cors");
    assert_eq!(plugins[1].priority(), 5000);
}

#[tokio::test]
async fn rejected_ai_semantic_cache_unknown_key_reload_retains_last_known_good() {
    assert_eq!(
        ferrum_edge::plugins::plugin_failure_policy("ai_semantic_cache"),
        Some(ferrum_edge::plugins::PluginFailurePolicy::KeepLastKnownGood)
    );

    let valid = make_config(
        vec![make_proxy("p1", "/api", vec!["ai-cache"])],
        vec![make_plugin_config_with_json(
            "ai-cache",
            "ai_semantic_cache",
            json!({
                "ttl_seconds": 60,
                "cache_multimodal": "reject",
                "scope_by_consumer": true
            }),
            PluginScope::Proxy,
            Some("p1"),
        )],
    );
    let cache = PluginCache::new(&valid).expect("valid ai_semantic_cache must admit");
    let last_good = cache.get_plugins("p1");
    assert_eq!(last_good.len(), 1);
    assert_eq!(last_good[0].name(), "ai_semantic_cache");

    for bad_config in [
        json!({"ttl_second": 30, "cache_multimodal": "reject"}),
        json!({"ttl_seconds": 30, "cache_multimoda": "reject"}),
        json!({"ttl_seconds": 30, "sync_mod": "redis", "redis_url": "redis://127.0.0.1:6379/0"}),
        json!({"ttl_seconds": 30, "semantic_similarity_enable": true}),
    ] {
        let invalid = make_config(
            vec![make_proxy("p1", "/api", vec!["ai-cache"])],
            vec![make_plugin_config_with_json(
                "ai-cache",
                "ai_semantic_cache",
                bad_config.clone(),
                PluginScope::Proxy,
                Some("p1"),
            )],
        );
        let delta = ConfigDelta::compute(&valid, &invalid);
        let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&valid, &invalid);
        let error = cache
            .apply_delta(
                &invalid,
                &proxy_ids,
                &delta.removed_proxy_ids,
                delta.global_plugin_configs_changed,
            )
            .expect_err("unknown ai_semantic_cache key must reject reload");
        assert!(
            error.contains("ai_semantic_cache: unknown configuration key(s):"),
            "unexpected reload error for {bad_config}: {error}"
        );
        let after_reject = cache.get_plugins("p1");
        assert_eq!(after_reject.len(), 1);
        assert!(
            Arc::ptr_eq(&after_reject[0], &last_good[0]),
            "rejected candidate must retain the last-known-good ai_semantic_cache generation"
        );
    }
}

#[tokio::test]
async fn grpc_web_global_shadowed_by_two_scoped_instances_unions_expose_headers_once() {
    // Global grpc_web is replaced by same-named scoped instances; both scoped
    // configs remain effective. Distinct priority_override values make the
    // earlier instance (250) claim translation ownership while the later one
    // (270) only unions expose_headers — body translation stays exactly once.
    let global = make_plugin_config_with_json(
        "grpc-web-global",
        "grpc_web",
        json!({"expose_headers": ["x-global-only"]}),
        PluginScope::Global,
        None,
    );
    let mut early = make_plugin_config_with_json(
        "grpc-web-early",
        "grpc_web",
        json!({"expose_headers": ["x-early"]}),
        PluginScope::Proxy,
        Some("p1"),
    );
    early.priority_override = Some(250);
    let mut late = make_plugin_config_with_json(
        "grpc-web-late",
        "grpc_web",
        json!({"expose_headers": ["x-late"]}),
        PluginScope::Proxy,
        Some("p1"),
    );
    late.priority_override = Some(270);

    let config = make_config(
        vec![make_proxy(
            "p1",
            "/api",
            vec!["grpc-web-early", "grpc-web-late"],
        )],
        vec![global, early, late],
    );
    let cache = PluginCache::new(&config).expect("multi-instance grpc_web cache");
    let plugins = cache.get_plugins_for_protocol("p1", ProxyProtocol::Http);
    let grpc_web_plugins: Vec<_> = plugins
        .iter()
        .filter(|plugin| plugin.name() == "grpc_web")
        .cloned()
        .collect();
    assert_eq!(
        grpc_web_plugins.len(),
        2,
        "scoped instances replace the global; both scoped remain"
    );
    assert!(grpc_web_plugins[0].priority() < grpc_web_plugins[1].priority());

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/svc.Method".to_string(),
    );
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web".to_string(),
    );
    assert!(matches!(
        run_request_received_chain(&grpc_web_plugins, &mut ctx).await,
        PluginResult::Continue
    ));
    assert!(ctx.metadata.contains_key("grpc_web.owner"));
    assert_eq!(
        ctx.metadata.get("grpc_web_mode").map(String::as_str),
        Some("binary")
    );

    let mut response_headers =
        HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
    response_headers.insert("grpc-status".to_string(), "0".to_string());
    assert!(matches!(
        run_after_proxy_chain(&grpc_web_plugins, &mut ctx, &mut response_headers).await,
        PluginResult::Continue
    ));

    let expose = response_headers
        .get("access-control-expose-headers")
        .expect("expose headers");
    assert!(expose.contains("x-early"), "got {expose}");
    assert!(expose.contains("x-late"), "got {expose}");
    assert!(
        !expose.contains("x-global-only"),
        "shadowed global expose list must not apply: {expose}"
    );

    let mut body = Vec::new();
    for plugin in &grpc_web_plugins {
        if let Some(next) = plugin
            .transform_response_body_with_context(
                &mut ctx,
                &body,
                response_headers.get("content-type").map(String::as_str),
                &response_headers,
            )
            .await
        {
            body = next;
        }
    }
    assert_eq!(body[0], 0x80);
    // Empty backend body → a single trailer frame (flag + 4-byte length + payload).
    assert_eq!(body.iter().filter(|b| **b == 0x80).count(), 1);
    assert!(body.len() >= 5);
}

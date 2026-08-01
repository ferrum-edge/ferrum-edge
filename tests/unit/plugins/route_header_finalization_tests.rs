//! Chain-level route-header finalization (GHSA-3xxr-xhhj-9962).
//!
//! Multiple same-type transformer instances must apply every static header
//! rule first; the matched route list applies exactly once afterward so a
//! later static add/update/remove/rename cannot undo route policy.

use chrono::Utc;
use ferrum_edge::_test_support::{
    apply_replaceable_after_proxy_hooks_to_rejection_for_test, plugins_for_protocol_for_test,
    run_after_proxy_hooks_for_test, run_before_proxy_hooks_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DEFAULT_NAMESPACE, DispatchKind, GatewayConfig, PluginAssociation,
    PluginConfig, PluginScope, Proxy, default_namespace,
};
use ferrum_edge::plugins::utils::route_header_transform::{
    RawRouteHeaderTransformRule, RouteHeaderTransformRule, parse_route_header_transforms,
};
use ferrum_edge::plugins::{Plugin, PluginResult, ProxyProtocol, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_proxy(id: &str, plugin_ids: &[&str]) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(format!("Proxy {id}")),
        hosts: vec![],
        listen_path: Some("/api".to_string()),
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
            .iter()
            .map(|id| PluginAssociation {
                plugin_config_id: (*id).to_string(),
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

fn plugin_config(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
    priority_override: Option<u16>,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".to_string()),
        enabled: true,
        priority_override,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_config(plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy(
            "p1",
            &plugin_configs
                .iter()
                .map(|pc| pc.id.as_str())
                .collect::<Vec<_>>(),
        )],
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn route_request_rules(raw: serde_json::Value) -> Arc<Vec<RouteHeaderTransformRule>> {
    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(raw).unwrap();
    Arc::new(parse_route_header_transforms(&raw, "test.request_route").unwrap())
}

fn route_response_rules(raw: serde_json::Value) -> Arc<Vec<RouteHeaderTransformRule>> {
    let raw: Vec<RawRouteHeaderTransformRule> = serde_json::from_value(raw).unwrap();
    Arc::new(parse_route_header_transforms(&raw, "test.response_route").unwrap())
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    )
}

async fn run_request_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) {
    let result = run_before_proxy_hooks_for_test(plugins, ctx, headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "before_proxy chain must continue"
    );
}

#[tokio::test]
async fn cache_backed_stable_order_route_remove_survives_later_request_rename() {
    // Bypass #1: route removes X-Internal-Role; later transformer renames
    // attacker-controlled X-Requested-Role into that destination.
    let config = make_config(vec![
        plugin_config(
            "rt-a",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-First",
                    "value": "a"
                }]
            }),
            None,
        ),
        plugin_config(
            "rt-b",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "rename",
                    "target": "header",
                    "key": "X-Requested-Role",
                    "new_key": "X-Internal-Role"
                }]
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    assert_eq!(
        plugins
            .iter()
            .filter(|p| p.name() == "request_transformer")
            .count(),
        2
    );

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_request_rules(json!([
        {"operation": "remove", "target": "header", "key": "X-Internal-Role"}
    ])));
    let mut headers = HashMap::from([
        ("x-internal-role".to_string(), "admin".to_string()),
        ("x-requested-role".to_string(), "attacker".to_string()),
    ]);
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert_eq!(headers.get("x-first").map(String::as_str), Some("a"));
    assert!(
        !headers.contains_key("x-internal-role"),
        "route remove must win over later static rename; got {:?}",
        headers.get("x-internal-role")
    );
    assert!(
        !headers.contains_key("x-requested-role"),
        "rename source is consumed by the later static rule before route finalization"
    );
    assert!(ctx.route_override_request_transform.is_none());
}

#[tokio::test]
async fn cache_backed_priority_override_order_route_set_survives_later_static_update() {
    // Lower priority_override runs first. rt-late has higher effective priority
    // so it runs after rt-early despite configuration order.
    let config = make_config(vec![
        plugin_config(
            "rt-late",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "update",
                    "target": "header",
                    "key": "X-Tenant",
                    "value": "shared"
                }]
            }),
            Some(3010),
        ),
        plugin_config(
            "rt-early",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Early",
                    "value": "1"
                }]
            }),
            Some(2990),
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    let names: Vec<&str> = plugins
        .iter()
        .filter(|p| p.name() == "request_transformer")
        .map(|p| p.name())
        .collect();
    assert_eq!(names.len(), 2);
    assert!(plugins[0].priority() <= plugins[1].priority());

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_request_rules(json!([
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route-a"}
    ])));
    let mut headers = HashMap::new();
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert_eq!(headers.get("x-early").map(String::as_str), Some("1"));
    assert_eq!(
        headers.get("x-tenant").map(String::as_str),
        Some("route-a"),
        "route set must win over later static update"
    );
}

#[tokio::test]
async fn cache_backed_auto_emit_consumer_then_operator_keeps_route_final() {
    // Bypass #4: auto-emitted rules:[] + apply_route_overrides:true runs first;
    // a later operator transformer must not undo the route list.
    let config = make_config(vec![
        plugin_config(
            "rt-auto",
            "request_transformer",
            json!({
                "rules": [],
                "apply_route_overrides": true
            }),
            None,
        ),
        plugin_config(
            "rt-op",
            "request_transformer",
            json!({
                "rules": [
                    {
                        "operation": "add",
                        "target": "header",
                        "key": "X-Internal-Role",
                        "value": "from-operator"
                    },
                    {
                        "operation": "update",
                        "target": "header",
                        "key": "X-Tenant",
                        "value": "shared"
                    }
                ]
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_request_rules(json!([
        {"operation": "remove", "target": "header", "key": "X-Internal-Role"},
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route-a"},
        {"operation": "add", "target": "header", "key": "X-Route-Add", "value": "once"}
    ])));
    let mut headers = HashMap::from([("x-internal-role".to_string(), "seed".to_string())]);
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert!(
        !headers.contains_key("x-internal-role"),
        "route remove must clear the operator static add"
    );
    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("route-a"));
    assert_eq!(
        headers.get("x-route-add").map(String::as_str),
        Some("once"),
        "non-idempotent route add must apply exactly once"
    );
}

#[tokio::test]
async fn cache_backed_disabled_rtds_instance_does_not_suppress_route_final() {
    let config = make_config(vec![
        plugin_config(
            "rt-disabled",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Disabled",
                    "value": "no"
                }],
                "runtime_overlay_scope": "gate",
                "runtime_overlay_resolved_enabled": false
            }),
            None,
        ),
        plugin_config(
            "rt-enabled",
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Enabled",
                    "value": "yes"
                }]
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    assert!(
        plugins
            .iter()
            .any(|p| p.participates_in_route_request_header_finalization()),
        "enabled transformer must remain eligible"
    );
    assert!(
        plugins
            .iter()
            .any(|p| !p.participates_in_route_request_header_finalization()
                && p.name() == "request_transformer"),
        "disabled RTDS instance must not participate"
    );

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_request_rules(json!([
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route"}
    ])));
    let mut headers = HashMap::new();
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert!(!headers.contains_key("x-disabled"));
    assert_eq!(headers.get("x-enabled").map(String::as_str), Some("yes"));
    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("route"));
    assert!(ctx.route_override_request_transform.is_none());
}

#[tokio::test]
async fn cache_backed_response_route_remove_survives_later_backend_rename() {
    // Bypass #2: route removes X-Internal-Debug; later response transformer
    // renames a backend-controlled field into that destination.
    let config = make_config(vec![
        plugin_config(
            "resp-a",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-First-Resp",
                    "value": "a"
                }]
            }),
            None,
        ),
        plugin_config(
            "resp-b",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "rename",
                    "target": "header",
                    "key": "X-Backend-Debug",
                    "new_key": "X-Internal-Debug"
                }]
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    assert_eq!(
        plugins
            .iter()
            .filter(|p| p.name() == "response_transformer")
            .count(),
        2
    );

    let mut ctx = make_ctx();
    ctx.route_override_response_transform = Some(route_response_rules(json!([
        {"operation": "remove", "target": "header", "key": "X-Internal-Debug"}
    ])));
    let mut headers = HashMap::from([
        ("x-internal-debug".to_string(), "seed".to_string()),
        ("x-backend-debug".to_string(), "backend-secret".to_string()),
    ]);
    assert!(
        !run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await,
        "response transformers must not reject"
    );

    assert_eq!(headers.get("x-first-resp").map(String::as_str), Some("a"));
    assert!(
        !headers.contains_key("x-internal-debug"),
        "route remove must win over later static rename; got {:?}",
        headers.get("x-internal-debug")
    );
    assert!(ctx.route_override_response_transform.is_none());
}

#[tokio::test]
async fn cache_backed_response_route_set_and_add_apply_exactly_once() {
    let config = make_config(vec![
        plugin_config(
            "resp-a",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "update",
                    "target": "header",
                    "key": "X-Tenant",
                    "value": "shared"
                }]
            }),
            None,
        ),
        plugin_config(
            "resp-b",
            "response_transformer",
            json!({
                "apply_route_overrides": true,
                "rules": []
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);

    let mut ctx = make_ctx();
    ctx.route_override_response_transform = Some(route_response_rules(json!([
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route-a"},
        {"operation": "add", "target": "header", "key": "X-Route-Add", "value": "once"}
    ])));
    let mut headers = HashMap::new();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await);

    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("route-a"));
    assert_eq!(
        headers.get("x-route-add").map(String::as_str),
        Some("once"),
        "route add must not duplicate across instances"
    );
}

#[tokio::test]
async fn cache_backed_synthetic_rejection_path_applies_response_route_final() {
    let config = make_config(vec![
        plugin_config(
            "resp-a",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "X-Static",
                    "value": "1"
                }]
            }),
            None,
        ),
        plugin_config(
            "resp-b",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "rename",
                    "target": "header",
                    "key": "X-Leak",
                    "new_key": "X-Internal-Debug"
                }]
            }),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);

    let mut ctx = make_ctx();
    ctx.route_override_response_transform = Some(route_response_rules(json!([
        {"operation": "remove", "target": "header", "key": "X-Internal-Debug"},
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route"}
    ])));
    let mut headers = HashMap::from([
        ("x-leak".to_string(), "backend".to_string()),
        ("x-internal-debug".to_string(), "seed".to_string()),
    ]);
    // Rejection-path after_proxy uses the same chain-level finalizer.
    let mut status = 403u16;
    let mut body = bytes::Bytes::from_static(b"{\"error\":\"denied\"}");
    apply_replaceable_after_proxy_hooks_to_rejection_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut body,
        &mut headers,
    )
    .await;

    assert_eq!(headers.get("x-static").map(String::as_str), Some("1"));
    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("route"));
    assert!(
        !headers.contains_key("x-internal-debug"),
        "rejection path must still honor route remove after later rename"
    );
    assert!(ctx.route_override_response_transform.is_none());
}

#[tokio::test]
async fn no_eligible_consumer_leaves_route_override_unused() {
    // Preserve documented behavior when the chain has no enabled transformer.
    let config = make_config(vec![plugin_config(
        "rt-disabled",
        "request_transformer",
        json!({
            "rules": [{
                "operation": "add",
                "target": "header",
                "key": "X-Disabled",
                "value": "no"
            }],
            "runtime_overlay_scope": "gate",
            "runtime_overlay_resolved_enabled": false
        }),
        None,
    )]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    assert!(
        !plugins
            .iter()
            .any(|p| p.participates_in_route_request_header_finalization())
    );

    let mut ctx = make_ctx();
    ctx.route_override_request_transform = Some(route_request_rules(json!([
        {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route"}
    ])));
    let mut headers = HashMap::new();
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert!(
        ctx.route_override_request_transform.is_some(),
        "without an eligible consumer the Arc must remain unused"
    );
    assert!(!headers.contains_key("x-tenant"));
    assert!(!headers.contains_key("x-disabled"));
}

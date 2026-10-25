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
use ferrum_edge::config::plugin_trigger::PluginTrigger;
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
        labels: Default::default(),
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
        websocket_permessage_deflate: Default::default(),
        allow_path_parameters: false,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn plugin_config(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
    priority_override: Option<u16>,
    trigger: Option<PluginTrigger>,
) -> PluginConfig {
    PluginConfig {
        labels: Default::default(),
        id: id.to_string(),
        namespace: default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".to_string()),
        enabled: true,
        priority_override,
        trigger,
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
            None,
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
            None,
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

#[test]
fn route_transform_diagnostics_keep_indexes_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_ROUTE_TOKEN\\tail";
    for (rule, field, reason) in [
        (
            json!({"target": token, "operation": "add", "key": "x-test", "value": "ok"}),
            "target",
            "must be `header`",
        ),
        (
            json!({"target": "header", "operation": token, "key": "x-test"}),
            "operation",
            "must be one of",
        ),
        (
            json!({"target": "header", "operation": "add", "key": token, "value": "ok"}),
            "key",
            "must be a valid HTTP header name",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config(
            "mesh_route_dispatch",
            &json!({"rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": "backend"},
                "request_transform": [rule]
            }]}),
        )
        .expect_err("invalid route transform must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        let path = format!("`mesh_route_dispatch.rules[0].request_transform[0].{field}`");
        assert!(rendered.contains(&path), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        assert!(!rendered.contains("UNREGISTERED_ROUTE_TOKEN"), "{rendered}");
    }
}

fn route_dispatch_config(transform_field: &str) -> serde_json::Value {
    json!({"rules": [{
        "match": {"methods": ["GET"]},
        "destination": {"backend_host": "backend.internal", "backend_port": 8080},
        transform_field: [
            {"operation": "remove", "target": "header", "key": "X-Internal-Role"},
            {"operation": "update", "target": "header", "key": "X-Tenant", "value": "route-a"},
            {"operation": "add", "target": "header", "key": "X-Route-Add", "value": "once"}
        ]
    }]})
}

#[tokio::test]
async fn cache_backed_route_request_policy_applies_when_consumer_precedes_dispatch() {
    // mesh_route_dispatch-SOL-1: a priority override places the sole consumer
    // BEFORE the dispatcher publishes its list. Finalizing at the consumer
    // took an empty slot and silently forwarded the attacker header.
    let config = make_config(vec![
        plugin_config(
            "rt-early",
            "request_transformer",
            json!({"rules": [], "apply_route_overrides": true}),
            Some(2990),
            None,
        ),
        plugin_config(
            "mrd",
            "mesh_route_dispatch",
            route_dispatch_config("request_transform"),
            None,
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    let consumer = plugins
        .iter()
        .position(|p| p.name() == "request_transformer")
        .expect("consumer in chain");
    let producer = plugins
        .iter()
        .position(|p| p.name() == "mesh_route_dispatch")
        .expect("producer in chain");
    assert!(
        consumer < producer,
        "the scenario requires the consumer to run before the dispatcher"
    );
    assert!(plugins[producer].publishes_route_request_header_transforms());

    let mut ctx = make_ctx();
    let mut headers = HashMap::from([
        ("x-internal-role".to_string(), "admin".to_string()),
        ("x-tenant".to_string(), "client".to_string()),
    ]);
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("backend.internal")
    );
    assert!(
        !headers.contains_key("x-internal-role"),
        "route remove must apply even though the consumer ran first; got {:?}",
        headers.get("x-internal-role")
    );
    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("route-a"));
    assert_eq!(
        headers.get("x-route-add").map(String::as_str),
        Some("once"),
        "non-idempotent route add must apply exactly once"
    );
    assert!(ctx.route_override_request_transform.is_none());
}

fn cache_build_error(config: &GatewayConfig) -> String {
    match PluginCache::new(config) {
        Ok(_) => panic!("cache construction must refuse the composition"),
        Err(error) => error,
    }
}

#[test]
fn cache_refuses_route_transforms_without_a_configured_consumer() {
    // mesh_route_dispatch-CLAUDE-2: with no transformer on the chain the
    // published lists were silently dropped (a strip rule forwarded the
    // header untouched).
    let request_only = make_config(vec![plugin_config(
        "mrd",
        "mesh_route_dispatch",
        route_dispatch_config("request_transform"),
        None,
        None,
    )]);
    let error = cache_build_error(&request_only);
    assert!(
        error.contains("no request_transformer to apply them"),
        "{error}"
    );

    let response_only = make_config(vec![plugin_config(
        "mrd",
        "mesh_route_dispatch",
        route_dispatch_config("response_transform"),
        None,
        None,
    )]);
    let error = cache_build_error(&response_only);
    assert!(
        error.contains("no response_transformer to apply them"),
        "{error}"
    );

    // The translator-shaped empty consumer satisfies each direction.
    for (field, consumer) in [
        ("request_transform", "request_transformer"),
        ("response_transform", "response_transformer"),
    ] {
        let config = make_config(vec![
            plugin_config(
                "consumer",
                consumer,
                json!({"rules": [], "apply_route_overrides": true}),
                None,
                None,
            ),
            plugin_config(
                "mrd",
                "mesh_route_dispatch",
                route_dispatch_config(field),
                None,
                None,
            ),
        ]);
        assert!(PluginCache::new(&config).is_ok(), "{field} with {consumer}");
    }

    // An RTDS-disabled transformer is still the operator's configured
    // consumer: its kill switch must not wedge the reload.
    let rtds_disabled = make_config(vec![
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
            None,
        ),
        plugin_config(
            "mrd",
            "mesh_route_dispatch",
            route_dispatch_config("request_transform"),
            None,
            None,
        ),
    ]);
    assert!(PluginCache::new(&rtds_disabled).is_ok());
}

#[tokio::test]
async fn cache_backed_route_request_policy_waits_for_the_whole_dispatch_block() {
    // PR6821-SOL-1: dispatcher B publishes no request transforms but still
    // replaces the route decision. Finalizing right after dispatcher A applied
    // A's credential before B won, and let B's predicates see it.
    let config = make_config(vec![
        plugin_config(
            "rt-early",
            "request_transformer",
            json!({"rules": [], "apply_route_overrides": true}),
            Some(2990),
            None,
        ),
        plugin_config(
            "mrd-a",
            "mesh_route_dispatch",
            json!({"rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "backend-a.internal", "backend_port": 8080},
                "request_transform": [
                    {"operation": "update", "target": "header", "key": "X-Backend-Key", "value": "backend-a-only"}
                ]
            }]}),
            None,
            None,
        ),
        plugin_config(
            "mrd-b",
            "mesh_route_dispatch",
            json!({"rules": [{
                "match": {
                    "headers": {"x-route": "b"},
                    "without_headers": {"x-backend-key": {"regex": ".*"}}
                },
                "destination": {"backend_host": "backend-b.internal", "backend_port": 8080}
            }]}),
            Some(2996),
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::Http);
    let consumer = plugins
        .iter()
        .position(|p| p.name() == "request_transformer")
        .expect("consumer in chain");
    let dispatchers: Vec<usize> = plugins
        .iter()
        .enumerate()
        .filter(|(_, p)| p.name() == "mesh_route_dispatch")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(dispatchers.len(), 2);
    assert!(consumer < dispatchers[0] && dispatchers[0] < dispatchers[1]);
    assert!(!plugins[dispatchers[1]].publishes_route_request_header_transforms());
    assert!(plugins[dispatchers[1]].replaces_route_request_header_transforms());

    let mut ctx = make_ctx();
    let mut headers = HashMap::from([("x-route".to_string(), "b".to_string())]);
    run_request_chain(&plugins, &mut ctx, &mut headers).await;

    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("backend-b.internal"),
        "dispatcher B must not observe A's route header before the block ends"
    );
    assert!(
        !headers.contains_key("x-backend-key"),
        "the superseded rule's credential must never reach backend B; got {:?}",
        headers.get("x-backend-key")
    );
    assert!(ctx.route_override_request_transform.is_none());
}

fn websocket_route_transform_config() -> GatewayConfig {
    make_config(vec![
        plugin_config(
            "rt",
            "request_transformer",
            json!({"rules": [], "apply_route_overrides": true}),
            None,
            None,
        ),
        plugin_config(
            "resp",
            "response_transformer",
            json!({"rules": [], "apply_route_overrides": true}),
            None,
            None,
        ),
        plugin_config(
            "mrd",
            "mesh_route_dispatch",
            json!({"rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"backend_host": "ws.internal", "backend_port": 8080},
                "request_transform": [
                    {"operation": "remove", "target": "header", "key": "X-Internal-Role"}
                ],
                "response_transform": [
                    {"operation": "update", "target": "header", "key": "X-Route", "value": "ws"}
                ]
            }]}),
            None,
            None,
        ),
    ])
}

#[tokio::test]
async fn websocket_view_applies_route_request_policy_to_the_handshake() {
    // PR6821-SOL-2: the transformers run on HTTP/gRPC only, so the WebSocket
    // view used to lose the consumer and forward the stripped header.
    let cache = PluginCache::new(&websocket_route_transform_config()).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::WebSocket);
    assert!(
        plugins
            .iter()
            .all(|p| p.name() != "request_transformer" && p.name() != "response_transformer"),
        "the transformers themselves never run on WebSocket"
    );
    assert!(
        plugins
            .iter()
            .any(|p| p.participates_in_route_request_header_finalization()),
        "the WebSocket view keeps an eligible route request consumer"
    );

    let mut ctx = make_ctx();
    let mut headers = HashMap::from([("x-internal-role".to_string(), "admin".to_string())]);
    run_request_chain(&plugins, &mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("ws.internal")
    );
    assert!(
        !headers.contains_key("x-internal-role"),
        "route remove must apply to the WebSocket handshake"
    );

    let mut response_headers = HashMap::new();
    ferrum_edge::_test_support::finalize_successful_websocket_response_headers_for_test(
        &plugins,
        &ctx,
        101,
        &mut response_headers,
    );
    assert_eq!(
        response_headers.get("x-route").map(String::as_str),
        Some("ws"),
        "route response policy must decorate the successful upgrade"
    );
}

#[tokio::test]
async fn websocket_view_keeps_rtds_disabled_consumers_ineligible() {
    // A disabled RTDS transformer is not eligible on HTTP, so its WebSocket
    // stand-in must not exist either: the route list stays unused.
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
            None,
        ),
        plugin_config(
            "mrd",
            "mesh_route_dispatch",
            route_dispatch_config("request_transform"),
            None,
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::WebSocket);
    assert!(
        !plugins
            .iter()
            .any(|p| p.participates_in_route_request_header_finalization())
    );
}

#[tokio::test]
async fn websocket_rejection_finalizes_route_response_list_before_later_policy() {
    // PR6821-SOL-4: the WebSocket stand-in for `response_transformer` must
    // keep its chain position on rejection answers. Finalizing in the
    // end-of-chain fallback ran the route list after `security_headers`
    // (4080), so a later scrub lost to an earlier route write.
    let config = make_config(vec![
        plugin_config(
            "resp",
            "response_transformer",
            json!({"rules": [], "apply_route_overrides": true}),
            None,
            None,
        ),
        plugin_config(
            "sec",
            "security_headers",
            json!({"remove": ["x-route-debug"]}),
            None,
            None,
        ),
        plugin_config(
            "mrd",
            "mesh_route_dispatch",
            json!({"rules": [{
                "match": {"methods": ["GET"]},
                "redirect": {"uri": "/new", "redirect_code": 302},
                "response_transform": [
                    {"operation": "update", "target": "header", "key": "X-Route-Debug", "value": "internal-route-detail"},
                    {"operation": "remove", "target": "header", "key": "X-Frame-Options"},
                    {"operation": "add", "target": "header", "key": "X-Route-Add", "value": "once"}
                ]
            }]}),
            None,
            None,
        ),
    ]);
    let cache = PluginCache::new(&config).expect("cache");
    let plugins =
        plugins_for_protocol_for_test(&cache, DEFAULT_NAMESPACE, "p1", ProxyProtocol::WebSocket);
    assert!(plugins.iter().all(|p| p.name() != "response_transformer"));
    let stand_in = plugins
        .iter()
        .position(|p| p.participates_in_route_response_header_finalization())
        .expect("response consumer stand-in in the WebSocket view");
    let scrub = plugins
        .iter()
        .position(|p| p.name() == "security_headers")
        .expect("security_headers in the WebSocket view");
    assert!(stand_in < scrub);
    assert!(plugins[stand_in].applies_after_proxy_on_reject());

    let mut ctx = make_ctx();
    let mut request_headers = HashMap::new();
    let PluginResult::Reject {
        status_code,
        body,
        headers: mut response_headers,
    } = run_before_proxy_hooks_for_test(&plugins, &mut ctx, &mut request_headers).await
    else {
        panic!("the redirect rule must answer the handshake");
    };
    assert_eq!(status_code, 302);
    let mut status = status_code;
    let mut body = bytes::Bytes::from(body);
    apply_replaceable_after_proxy_hooks_to_rejection_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut body,
        &mut response_headers,
    )
    .await;

    assert!(
        !response_headers.contains_key("x-route-debug"),
        "the later security_headers scrub must win over the earlier route write; got {:?}",
        response_headers.get("x-route-debug")
    );
    assert_eq!(
        response_headers.get("x-frame-options").map(String::as_str),
        Some("SAMEORIGIN"),
        "the later security_headers set must win over the earlier route remove"
    );
    assert_eq!(
        response_headers.get("x-route-add").map(String::as_str),
        Some("once"),
        "a non-idempotent route add must apply exactly once"
    );
    assert!(ctx.route_override_response_transform.is_none());
}

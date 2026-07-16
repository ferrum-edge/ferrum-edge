//! Tests for PluginCache — pre-resolved plugin instances per proxy

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, PluginAssociation, PluginConfig,
    PluginScope, Proxy,
};
use ferrum_edge::config_delta::ConfigDelta;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext, apply_initial_response_header_policies,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use ferrum_edge::{PluginCache, PluginCapabilities};
use serde_json::json;
use std::collections::HashMap;
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

/// Returns the minimal valid config for a given plugin name so that `create_plugin` succeeds.
pub(crate) fn minimal_plugin_config(plugin_name: &str) -> serde_json::Value {
    match plugin_name {
        "access_control" => json!({"allowed_consumers": ["testuser"]}),
        "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
        "ip_restriction" => json!({"allow": ["0.0.0.0/0"]}),
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
        "ai_rate_limiter" => json!({"token_limit": 100000}),
        "cors" => json!({"origins": ["*"]}),
        "response_caching" => json!({"ttl_seconds": 60}),
        "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
        "tcp_logging" => json!({"host": "localhost", "port": 5140}),
        "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
        "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
        "jwks_auth" => {
            json!({"providers": [{"jwks_uri": "http://127.0.0.1:9/.well-known/jwks.json"}]})
        }
        "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
        "serverless_function" => {
            json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
        }
        "request_mirror" => json!({"mirror_host": "mirror.local"}),
        "udp_logging" => json!({"host": "127.0.0.1", "port": 9514}),
        "kafka_logging" => json!({"broker_list": "localhost:9092", "topic": "test-logs"}),
        "request_deduplication" => json!({}),
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
        vec![make_proxy(
            "p1",
            "/api",
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
    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["audit"])],
        vec![make_plugin_config_with_json(
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
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    let view = cache.request_view("p1", ProxyProtocol::Http);

    assert!(
        view.capabilities()
            .has(PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK)
    );
    assert!(
        !cache
            .request_view("missing", ProxyProtocol::Http)
            .capabilities()
            .has(PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK)
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
                config: json!({"origins": ["*"]}),
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
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&new_config);

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
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&config2);

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
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&config2);

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
                json!({"origins": ["*"]}),
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
                json!({"origins": ["*"]}),
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
                json!({"origins": ["*"]}),
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

// ---- WebSocket per-frame plugin hook infrastructure ----

#[tokio::test]
async fn test_requires_ws_frame_hooks_defaults_false_for_all_plugins() {
    use ferrum_edge::plugins::available_plugins;
    use ferrum_edge::plugins::create_plugin;

    // Every non-WS-frame built-in plugin must return false for requires_ws_frame_hooks().
    // This is the zero-overhead guarantee — only explicit WS frame plugins opt in.
    const WS_FRAME_PLUGINS: &[&str] = &[
        "ws_message_size_limiting",
        "ws_frame_logging",
        "ws_rate_limiting",
    ];

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
fn test_plugin_cache_requires_ws_frame_hooks_true_with_ws_size_plugin() {
    // When a WS frame plugin is assigned to a proxy, requires_ws_frame_hooks must be TRUE.
    let config = make_config(
        vec![make_proxy("p1", "/ws", vec!["ws1"])],
        vec![make_plugin_config(
            "ws1",
            "ws_message_size_limiting",
            PluginScope::Proxy,
            Some("p1"),
            true,
        )],
    );
    let cache = PluginCache::new(&config).unwrap();
    assert!(
        cache.requires_ws_frame_hooks("p1"),
        "requires_ws_frame_hooks must be TRUE when ws_message_size_limiting is attached"
    );
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
async fn test_priority_override_preserves_rejection_replacement_capabilities() {
    let mut spec_plugin_config = make_plugin_config_with_json(
        "ps1",
        "spec_expose",
        json!({"spec_url": "https://example.com/openapi.json"}),
        PluginScope::Proxy,
        Some("p1"),
    );
    spec_plugin_config.priority_override = Some(211);

    let mut audit_plugin_config = make_plugin_config_with_json(
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
    audit_plugin_config.priority_override = Some(212);

    let config = make_config(
        vec![make_proxy("p1", "/api", vec!["ps1", "audit"])],
        vec![spec_plugin_config, audit_plugin_config],
    );
    let cache = PluginCache::new(&config).unwrap();
    let plugins = cache.get_plugins("p1");

    assert_eq!(plugins.len(), 2);
    let spec = plugins
        .iter()
        .find(|plugin| plugin.name() == "spec_expose")
        .expect("spec_expose plugin");
    assert_eq!(spec.priority(), 211);
    assert!(!spec.applies_after_proxy_on_reject());
    assert!(!spec.may_replace_rejection_response());

    let audit = plugins
        .iter()
        .find(|plugin| plugin.name() == "ai_transcript_audit")
        .expect("ai_transcript_audit plugin");
    assert_eq!(audit.priority(), 212);
    assert!(audit.applies_after_proxy_on_reject());
    assert!(audit.may_replace_rejection_response());
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
        !plugins[0].should_buffer_response_body(&ctx),
        "priority override wrapper must preserve plugin-specific SSE buffering skip"
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
        vec![make_proxy("p1", "/api", vec!["ps1"])],
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
        vec![make_proxy("p1", "/svc", vec!["ps1", "ps2", "ps3", "ps4"])],
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

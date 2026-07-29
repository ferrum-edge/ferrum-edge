//! Tests for `RequestContext::apply_route_overrides` and the `effective_*`
//! helpers — the plumbing that lets `mesh_route_dispatch` rewrite the
//! routing decision per request without mutating the matched `Proxy` in
//! shared `ArcSwap` state.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use ferrum_edge::config::types::{
    BackendTlsConfig, GatewayConfig, PluginConfig, PluginScope, Proxy, ResolvedPortOverride,
    RetryConfig, Upstream, UpstreamPortOverride,
};
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

fn test_proxy() -> Arc<Proxy> {
    let p: Proxy = serde_json::from_value(serde_json::json!({
        "backend_host": "stable.svc",
        "backend_port": 8080,
    }))
    .expect("minimal proxy should deserialize");
    Arc::new(p)
}

fn upstream_proxy() -> Arc<Proxy> {
    let p: Proxy = serde_json::from_value(serde_json::json!({
        "backend_host": "",
        "backend_port": 0,
        "upstream_id": "stable",
    }))
    .expect("minimal upstream proxy should deserialize");
    Arc::new(p)
}

fn upstream_with_port_overrides(id: &str, overrides: &[(u16, u64)]) -> Arc<Upstream> {
    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": id,
        "targets": [{"host": "127.0.0.1", "port": 8080}],
        "algorithm": "round_robin",
    }))
    .expect("minimal upstream should deserialize");
    upstream.port_overrides = overrides
        .iter()
        .map(|(port, timeout)| {
            (
                *port,
                UpstreamPortOverride {
                    connect_timeout_ms: Some(*timeout),
                    ..Default::default()
                },
            )
        })
        .collect();
    Arc::new(upstream)
}

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    )
}

fn mesh_route_plugin_config(config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: "mesh-route".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn mesh_route_dispatch_rejects_empty_backend_tls_paths_at_admission() {
    let invalid_tls_configs = [
        json!({"client_cert_path": ""}),
        json!({"client_key_path": ""}),
        json!({"client_cert_path": "", "client_key_path": ""}),
        json!({"server_ca_cert_path": ""}),
    ];

    for backend_tls in invalid_tls_configs {
        let config = json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {
                    "backend_host": "secure.internal",
                    "backend_port": 443,
                    "backend_tls": backend_tls
                }
            }]
        });
        let error = MeshRouteDispatch::new(&config)
            .expect_err("an explicitly empty TLS material path must fail admission");
        assert!(error.contains("must not be empty"), "got: {error}");
        assert!(
            ferrum_edge::plugins::validate_plugin_config("mesh_route_dispatch", &config).is_err(),
            "the shared file/admin plugin admission path must reject {config}"
        );
    }
}

#[test]
fn mesh_route_dispatch_file_dependency_validation_reports_empty_tls_paths() {
    let config = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {
                "backend_host": "secure.internal",
                "backend_port": 443,
                "backend_tls": {
                    "client_cert_path": "",
                    "client_key_path": "",
                    "server_ca_cert_path": ""
                }
            }
        }]
    });
    let gateway = GatewayConfig {
        plugin_configs: vec![mesh_route_plugin_config(config)],
        ..Default::default()
    };

    let errors = gateway.validate_plugin_file_dependencies();
    for field in ["client_cert_path", "client_key_path", "server_ca_cert_path"] {
        assert!(
            errors
                .iter()
                .any(|error| error.contains(field) && error.contains("must not be empty")),
            "missing {field} error in {errors:?}"
        );
    }
}

#[test]
fn mesh_route_dispatch_rejects_unknown_fields_at_every_owned_object_boundary() {
    let invalid_configs = [
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"}
                }],
                "reject_unmtached": true
            }),
            "reject_unmtached",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "timeout_millis": 100
                }]
            }),
            "timeout_millis",
        ),
        (
            json!({
                "rules": [{
                    "match": {"method": ["GET"], "methods": ["GET"]},
                    "destination": {"upstream_id": "api"}
                }]
            }),
            "method",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "upstream_id": "api",
                        "requires_node_waypoint_auth": true
                    }
                }]
            }),
            "requires_node_waypoint_auth",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "fault": {
                        "delay": {"duration_ms": 1, "percentage": 1.0},
                        "delai": {"duration_ms": 1, "percentage": 1.0}
                    }
                }]
            }),
            "delai",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "fault": {
                        "delay": {"duration_ms": 1, "percentage": 1.0, "percent": 1.0}
                    }
                }]
            }),
            "percent",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "fault": {
                        "abort": {"status_code": 503, "percentage": 1.0, "status": 503}
                    }
                }]
            }),
            "status",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "rewrite": {"uri": "/v2", "authorit": "api.internal"}
                }]
            }),
            "authorit",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "request_transform": [{
                        "operation": "update",
                        "key": "x-route",
                        "value": "api",
                        "new_key": "x-route-new"
                    }]
                }]
            }),
            "new_key",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "redirect": {"redirect_code": 308, "redirect_cod": 307}
                }]
            }),
            "redirect_cod",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {"max_retry": 2}
                }]
            }),
            "max_retry",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {"retry_on_connect_failur": false}
                }]
            }),
            "retry_on_connect_failur",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {
                        "backoff": {"fixed": {"delay_ms": 25, "delay_millis": 25}}
                    }
                }]
            }),
            "delay_millis",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {
                        "backoff": {
                            "exponential": {"base_ms": 10, "max_ms": 100, "max_millis": 100}
                        }
                    }
                }]
            }),
            "max_millis",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {
                        "backoff": {
                            "exponentiall": {"base_ms": 10, "max_ms": 100}
                        }
                    }
                }]
            }),
            "exponentiall",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {"upstream_id": "api"},
                    "retry": {
                        "backoff": {
                            "fixed": {"delay_ms": 25},
                            "exponential": {"base_ms": 10, "max_ms": 100}
                        }
                    }
                }]
            }),
            "expected map with a single key",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "api.internal",
                        "backend_port": 443,
                        "backend_tls": {"client_certpath": "/tls/client.pem"}
                    }
                }]
            }),
            "client_certpath",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "api.internal",
                        "backend_port": 443,
                        "backend_tls": {"verify_server_certificate": false}
                    }
                }]
            }),
            "verify_server_certificate",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "api.internal",
                        "backend_port": 443,
                        "backend_tls": {"sni_name": "api.internal"}
                    }
                }]
            }),
            "sni_name",
        ),
        (
            json!({
                "rules": [{
                    "match": {"methods": ["GET"]},
                    "destination": {
                        "backend_host": "api.internal",
                        "backend_port": 443,
                        "backend_tls": {"san_allowlist": ["api.internal"]}
                    }
                }]
            }),
            "san_allowlist",
        ),
    ];

    for (config, expected_fragment) in invalid_configs {
        let error = MeshRouteDispatch::new(&config)
            .expect_err("unknown mesh_route_dispatch fields must fail closed");
        assert!(
            error.contains(expected_fragment),
            "expected {expected_fragment:?} in: {error}"
        );
        assert!(
            ferrum_edge::plugins::validate_plugin_config("mesh_route_dispatch", &config).is_err(),
            "shared file/admin plugin admission must reject {config}"
        );
    }
}

#[tokio::test]
async fn mesh_route_dispatch_accepts_valid_retry_and_backend_tls_controls() {
    let config = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {
                "backend_host": "api.internal",
                "backend_port": 443,
                "backend_tls": {
                    "client_cert_path": "/tls/client.pem",
                    "client_key_path": "/tls/client.key",
                    "server_ca_cert_path": "/tls/ca.pem",
                    "verify_server_cert": true,
                    "sni": "api.internal",
                    "san_allow_list": ["api.internal"]
                }
            },
            "retry": {
                "max_retries": 2,
                "retryable_status_codes": [502, 503],
                "retryable_methods": ["GET"],
                "backoff": {"exponential": {"base_ms": 10, "max_ms": 100}},
                "retry_on_connect_failure": false
            }
        }],
        "reject_unmatched": true
    });

    let plugin = MeshRouteDispatch::new(&config).expect("valid nested route policy must admit");
    assert!(
        ferrum_edge::plugins::validate_plugin_config("mesh_route_dispatch", &config).is_ok(),
        "shared admission must accept the same valid nested controls"
    );

    let mut request = ctx();
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut request, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(
        request.route_override_backend_host.as_deref(),
        Some("api.internal")
    );
    assert_eq!(request.route_override_backend_port, Some(443));
    let tls = request
        .route_override_resolved_tls
        .as_ref()
        .expect("valid backend_tls must publish a resolved override");
    assert_eq!(tls.client_cert_path.as_deref(), Some("/tls/client.pem"));
    assert_eq!(tls.client_key_path.as_deref(), Some("/tls/client.key"));
    assert_eq!(tls.server_ca_cert_path.as_deref(), Some("/tls/ca.pem"));
    assert!(tls.verify_server_cert);
    assert_eq!(tls.sni.as_deref(), Some("api.internal"));
    assert_eq!(tls.san_allow_list, vec!["api.internal".to_string()]);
    let retry = request
        .route_override_retry
        .clone()
        .flatten()
        .expect("valid retry must publish a route override");
    assert_eq!(retry.max_retries, 2);
    assert_eq!(retry.retryable_status_codes, vec![502, 503]);
    assert_eq!(retry.retryable_methods, vec!["GET".to_string()]);
    assert!(!retry.retry_on_connect_failure);
}

#[test]
fn mesh_route_dispatch_strict_nested_policy_does_not_change_shared_types() {
    let retry = serde_json::from_value::<RetryConfig>(json!({"max_retry": 2}))
        .expect("shared retry config keeps its existing compatibility boundary");
    assert_eq!(retry, RetryConfig::default());

    let tls =
        serde_json::from_value::<BackendTlsConfig>(json!({"client_certpath": "/tls/client.pem"}))
            .expect("shared backend TLS config keeps its existing compatibility boundary");
    assert_eq!(tls, BackendTlsConfig::default_verify());
}

#[tokio::test]
async fn mesh_route_dispatch_method_regex_requires_a_full_match() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": [{"regex": "GET|GETTING|POST"}]},
            "destination": {"upstream_id": "sensitive"}
        }]
    }))
    .expect("plugin config");

    for method in ["GET", "GETTING", "POST"] {
        let mut request = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api".to_string(),
        );
        let result = plugin.before_proxy(&mut request, &mut HashMap::new()).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            request.route_override_upstream_id.as_deref(),
            Some("sensitive")
        );
    }

    for method in ["XGET", "GETX", "XPOSTY"] {
        let mut request = RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            "/api".to_string(),
        );
        let result = plugin.before_proxy(&mut request, &mut HashMap::new()).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(
            request.route_override_upstream_id.is_none(),
            "substring method {method} must not select the sensitive route"
        );
    }
}

#[tokio::test]
async fn mesh_route_dispatch_uri_regex_requires_a_full_match() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"uri": {"regex": "/admin|/admin/settings"}},
            "destination": {"upstream_id": "admin"}
        }]
    }))
    .expect("plugin config");

    for path in ["/admin", "/admin/settings"] {
        let mut exact =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
        assert!(matches!(
            plugin.before_proxy(&mut exact, &mut HashMap::new()).await,
            PluginResult::Continue
        ));
        assert_eq!(exact.route_override_upstream_id.as_deref(), Some("admin"));
    }

    for path in ["/public/admin", "/admin/settings/child", "x/admin"] {
        let mut request =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
        let result = plugin.before_proxy(&mut request, &mut HashMap::new()).await;
        assert!(matches!(result, PluginResult::Continue));
        assert!(
            request.route_override_upstream_id.is_none(),
            "substring URI {path} must not select the admin route"
        );
    }
}

#[tokio::test]
async fn mesh_route_dispatch_anchored_regexes_allow_longer_alternatives() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {
                "authority": {"regex": "api|api\\.internal"},
                "headers": {"x-tier": {"regex": "gold|gold-plus"}}
            },
            "destination": {"upstream_id": "specific"}
        }]
    }))
    .expect("plugin config");
    let mut request = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api".to_string(),
    );
    let mut headers = HashMap::from([
        ("host".to_string(), "api.internal".to_string()),
        ("x-tier".to_string(), "gold-plus".to_string()),
    ]);

    let result = plugin.before_proxy(&mut request, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        request.route_override_upstream_id.as_deref(),
        Some("specific"),
        "a shorter first alternative must not hide a later full-input match"
    );
}

#[tokio::test]
async fn mesh_route_dispatch_precomputed_node_waypoint_key_preserves_canonical_matching() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {
                "backend_host": "Stable.Default.Svc.Cluster.Local.",
                "backend_port": 80
            }
        }]
    }))
    .expect("plugin config");
    let mut request = ctx();
    request.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".to_string(),
        "stable.default.svc.cluster.local|80".to_string(),
    );

    let result = plugin.before_proxy(&mut request, &mut HashMap::new()).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        request.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local.")
    );
    assert_eq!(request.route_override_backend_port, Some(80));
}

#[tokio::test]
async fn mesh_route_dispatch_allows_node_waypoint_authorized_upstream_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "stable"}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_upstream_id".to_string(),
        "stable".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(ctx.route_override_upstream_id.as_deref(), Some("stable"));
}

#[tokio::test]
async fn mesh_route_dispatch_rejects_node_waypoint_unauthorized_upstream_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "canary"}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_upstream_id".to_string(),
        "stable".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("unauthorized NodeWaypoint route override must reject, got {other:?}"),
    }
    assert!(ctx.route_override_upstream_id.is_none());
}

#[tokio::test]
async fn mesh_route_dispatch_rejects_node_waypoint_direct_backend_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "direct.svc", "backend_port": 8080}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_upstream_id".to_string(),
        "stable".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("NodeWaypoint authz must forbid direct backend overrides, got {other:?}"),
    }
    assert!(ctx.route_override_backend_host.is_none());
    assert!(ctx.route_override_backend_port.is_none());
}

#[tokio::test]
async fn mesh_route_dispatch_allows_node_waypoint_authorized_backend_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "stable.default.svc.cluster.local", "backend_port": 80}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".to_string(),
        "stable.default.svc.cluster.local|80".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(80));
}

#[tokio::test]
async fn mesh_route_dispatch_allows_node_waypoint_authorized_backend_alias_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "stable.default.svc.cluster.local", "backend_port": 80}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".to_string(),
        "stable|80".to_string(),
    );
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend_aliases".to_string(),
        "stable|80,stable.default|80,stable.default.svc|80,stable.default.svc.cluster.local|80"
            .to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("stable.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(80));
}

#[tokio::test]
async fn mesh_route_dispatch_rejects_node_waypoint_authorized_backend_to_upstream_override() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"upstream_id": "canary"}
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_authorized_backend".to_string(),
        "stable.default.svc.cluster.local|80".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("authorized backend must not be rerouted to an upstream, got {other:?}"),
    }
    assert!(ctx.route_override_upstream_id.is_none());
}

#[tokio::test]
async fn mesh_route_dispatch_rejects_node_waypoint_scoped_service_override_without_authz_stamp() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {
                "backend_host": "protected.default.svc.cluster.local",
                "backend_port": 80,
                "requires_node_waypoint_authz": true
            }
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    ctx.metadata.insert(
        "mesh_authz.node_waypoint_scoped_authz_active".to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "NodeWaypoint scoped Service override without destination authz stamp must reject, got {other:?}"
        ),
    }
    assert!(ctx.route_override_backend_host.is_none());
    assert!(ctx.route_override_backend_port.is_none());
}

#[tokio::test]
async fn mesh_route_dispatch_allows_marked_service_override_outside_node_waypoint_authz() {
    let plugin = MeshRouteDispatch::new(&json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {
                "backend_host": "protected.default.svc.cluster.local",
                "backend_port": 80,
                "requires_node_waypoint_authz": true
            }
        }]
    }))
    .expect("plugin config");
    let mut ctx = ctx();
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("protected.default.svc.cluster.local")
    );
    assert_eq!(ctx.route_override_backend_port, Some(80));
}

#[test]
fn no_overrides_returns_same_arc() {
    let proxy = test_proxy();
    let ctx = ctx();
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert!(
        Arc::ptr_eq(&proxy, &result),
        "no overrides should return the same Arc — no per-request allocation"
    );
}

#[test]
fn no_op_overrides_return_same_arc() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("stable.svc".to_string());
    ctx.route_override_backend_port = Some(8080);

    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert!(
        Arc::ptr_eq(&proxy, &result),
        "overrides equal to the current proxy should stay allocation-free"
    );
}

#[test]
fn upstream_override_swaps_arc_and_sets_upstream_id() {
    let proxy = test_proxy();
    assert!(proxy.upstream_id.is_none());
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert!(
        !Arc::ptr_eq(&proxy, &result),
        "override should allocate a fresh Arc"
    );
    assert_eq!(result.upstream_id.as_deref(), Some("canary"));
    // Original Arc is untouched — shared ArcSwap state is unaffected.
    assert!(proxy.upstream_id.is_none());
}

#[test]
fn upstream_override_clears_inherited_subset() {
    let mut proxy_template = (*upstream_proxy()).clone();
    proxy_template.upstream_subset = Some("stable-v1".to_string());
    let proxy = Arc::new(proxy_template);
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());

    let result = ctx.apply_route_overrides(Arc::clone(&proxy));

    assert_eq!(result.upstream_id.as_deref(), Some("canary"));
    assert_eq!(
        result.upstream_subset, None,
        "a subset selected on the original upstream must not leak onto a different override upstream"
    );
}

#[test]
fn backend_host_and_port_override_apply_to_clone() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_backend_port = Some(9090);
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(result.backend_port, 9090);
    // Original Arc retains template values.
    assert_eq!(proxy.backend_host, "stable.svc");
    assert_eq!(proxy.backend_port, 8080);
}

#[test]
fn direct_backend_override_clears_existing_upstream_id() {
    let mut proxy_template = (*upstream_proxy()).clone();
    proxy_template.backend_tls_client_cert_path = Some("/certs/direct.pem".to_string());
    proxy_template.backend_tls_client_key_path = Some("/certs/direct.key".to_string());
    proxy_template.backend_tls_server_ca_cert_path = Some("/certs/direct-ca.pem".to_string());
    proxy_template.resolved_tls = BackendTlsConfig {
        client_cert_path: Some("/certs/upstream.pem".to_string()),
        client_key_path: Some("/certs/upstream.key".to_string()),
        server_ca_cert_path: Some("/certs/upstream-ca.pem".to_string()),
        verify_server_cert: false,
        sni: None,
        san_allow_list: Vec::new(),
        san_allow_list_key_digest: None,
    };
    let proxy = Arc::new(proxy_template);
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_backend_port = Some(9090);

    assert_eq!(ctx.effective_upstream_id(&proxy), None);
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.upstream_id, None);
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(result.backend_port, 9090);
    assert_eq!(
        result.resolved_tls.client_cert_path.as_deref(),
        Some("/certs/direct.pem")
    );
    assert_eq!(
        result.resolved_tls.client_key_path.as_deref(),
        Some("/certs/direct.key")
    );
    assert_eq!(
        result.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/certs/direct-ca.pem")
    );
    assert!(
        result.resolved_tls.verify_server_cert,
        "direct backend override should reset inherited upstream verify policy"
    );
}

#[test]
fn upstream_override_recomputes_dispatch_port_overrides() {
    let mut proxy_template = (*upstream_proxy()).clone();
    proxy_template.dispatch_port_overrides = Some(HashMap::from([(
        8080,
        ResolvedPortOverride {
            connect_timeout_ms: Some(1_500),
            ..Default::default()
        },
    )]));
    let proxy = Arc::new(proxy_template);
    let upstreams = HashMap::from([(
        "canary".to_string(),
        upstream_with_port_overrides("canary", &[(9090, 250)]),
    )]);
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());

    let result = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);

    assert_eq!(result.upstream_id.as_deref(), Some("canary"));
    assert_eq!(
        result
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&9090))
            .and_then(|override_config| override_config.connect_timeout_ms),
        Some(250),
        "route override should project the destination upstream's port overrides"
    );
    assert!(
        !result
            .dispatch_port_overrides
            .as_ref()
            .is_some_and(|overrides| overrides.contains_key(&8080)),
        "route override must not retain the original upstream's port overrides"
    );
}

#[test]
fn direct_backend_override_clears_dispatch_port_overrides() {
    let mut proxy_template = (*upstream_proxy()).clone();
    proxy_template.dispatch_port_overrides = Some(HashMap::from([(
        8080,
        ResolvedPortOverride {
            connect_timeout_ms: Some(1_500),
            ..Default::default()
        },
    )]));
    let proxy = Arc::new(proxy_template);
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("direct.svc".to_string());
    ctx.route_override_backend_port = Some(9090);

    let result = ctx.apply_route_overrides(Arc::clone(&proxy));

    assert_eq!(result.upstream_id, None);
    assert_eq!(result.dispatch_port_overrides, None);
}

#[test]
fn explicit_tls_override_applies_to_clone() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_resolved_tls = Some(BackendTlsConfig {
        client_cert_path: Some("/certs/canary.pem".to_string()),
        client_key_path: Some("/certs/canary.key".to_string()),
        server_ca_cert_path: Some("/certs/canary-ca.pem".to_string()),
        verify_server_cert: false,
        sni: None,
        san_allow_list: Vec::new(),
        san_allow_list_key_digest: None,
    });

    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(
        result.resolved_tls.client_cert_path.as_deref(),
        Some("/certs/canary.pem")
    );
    assert_eq!(
        result.resolved_tls.client_key_path.as_deref(),
        Some("/certs/canary.key")
    );
    assert_eq!(
        result.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/certs/canary-ca.pem")
    );
    assert!(!result.resolved_tls.verify_server_cert);
}

#[test]
fn partial_override_only_swaps_specified_fields() {
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    // No port override.
    let result = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(result.backend_host, "canary.svc");
    assert_eq!(
        result.backend_port, 8080,
        "port should fall back to proxy.backend_port"
    );
}

#[test]
fn has_route_overrides_reflects_field_set() {
    let mut ctx = ctx();
    assert!(!ctx.has_route_overrides());
    ctx.route_override_upstream_id = Some("x".to_string());
    assert!(ctx.has_route_overrides());
    ctx.route_override_upstream_id = None;
    ctx.route_override_backend_port = Some(443);
    assert!(ctx.has_route_overrides());
}

#[test]
fn effective_helpers_match_apply_route_overrides() {
    // The `effective_*` helpers must agree with `apply_route_overrides`
    // — both are paths to the same effective destination.
    let proxy = test_proxy();
    let mut ctx = ctx();
    ctx.route_override_upstream_id = Some("canary".to_string());
    ctx.route_override_backend_host = Some("canary.svc".to_string());
    ctx.route_override_backend_port = Some(9090);

    let overridden = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(
        ctx.effective_upstream_id(&proxy),
        overridden.upstream_id.as_deref()
    );
    assert_eq!(ctx.effective_backend_host(&proxy), overridden.backend_host);
    assert_eq!(ctx.effective_backend_port(&proxy), overridden.backend_port);
}

// ---- Pool-key partitioning -------------------------------------------------
//
// CLAUDE.md mandates that every connection-pool key include every field
// affecting connection identity ("Missing field = pool poisoning"). After
// `apply_route_overrides`, two requests through the SAME matched proxy with
// DIFFERENT override hosts/ports/upstream-ids must land in DIFFERENT pool
// entries. These tests exercise the capability registry and the HTTP/3
// pool key helpers — the same `proxy.backend_host`/`backend_port`/
// `upstream_id` fields that `connection_pool.rs`, `http2_pool.rs`, and
// `grpc_proxy.rs` derive their pool keys from.

#[test]
fn pool_key_partitions_on_backend_host_override() {
    // Two override sets for the SAME matched proxy must produce DIFFERENT
    // capability keys, because the capability registry is keyed by deduped
    // backend identity (`scheme|host|port|...`). If the override didn't
    // partition, both requests would share a registry record and traffic
    // for canary.svc would be classified by the probe of stable.svc.
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = capability_key(&canary_proxy);
    let stable_key = capability_key(&stable_proxy);
    assert_ne!(
        canary_key, stable_key,
        "different backend_host overrides must produce different pool keys — \
         pool-poisoning invariant violated"
    );
}

#[test]
fn pool_key_partitions_on_backend_port_override() {
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let mut ctx_a = ctx();
    ctx_a.route_override_backend_port = Some(9090);
    let proxy_a = ctx_a.apply_route_overrides(Arc::clone(&proxy));

    let mut ctx_b = ctx();
    ctx_b.route_override_backend_port = Some(9091);
    let proxy_b = ctx_b.apply_route_overrides(Arc::clone(&proxy));

    let key_a = capability_key(&proxy_a);
    let key_b = capability_key(&proxy_b);
    assert_ne!(
        key_a, key_b,
        "different backend_port overrides must produce different pool keys"
    );
}

#[test]
fn pool_key_matches_baseline_when_no_overrides() {
    // The no-override path must produce the same capability key as the
    // unmodified proxy — guarantees zero behavior change for deployments
    // where the override channel is unused.
    use ferrum_edge::proxy::backend_capabilities::capability_key;

    let proxy = test_proxy();
    let ctx = ctx();
    let unchanged = ctx.apply_route_overrides(Arc::clone(&proxy));

    let baseline_key = capability_key(&proxy);
    let after_apply_key = capability_key(&unchanged);
    assert_eq!(
        baseline_key, after_apply_key,
        "no-override path must produce the baseline pool key"
    );
}

#[test]
fn http3_pool_key_partitions_on_backend_host_override() {
    // The H3 pool key helper takes `&Proxy` so the shadowed override flows
    // through naturally. Different override hosts → different H3 pool slots,
    // matching `Http3ConnectionPool::pool_key`'s contract.
    use ferrum_edge::http3::client::Http3ConnectionPool;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = Http3ConnectionPool::pool_key(&canary_proxy, 0);
    let stable_key = Http3ConnectionPool::pool_key(&stable_proxy, 0);
    assert_ne!(
        canary_key, stable_key,
        "H3 pool key must partition on backend_host override"
    );
}

#[test]
fn http2_pool_key_partitions_on_backend_host_override() {
    use ferrum_edge::proxy::http2_pool::Http2ConnectionPool;

    let proxy = test_proxy();
    let mut canary_ctx = ctx();
    canary_ctx.route_override_backend_host = Some("canary.svc".to_string());
    let canary_proxy = canary_ctx.apply_route_overrides(Arc::clone(&proxy));

    let mut stable_ctx = ctx();
    stable_ctx.route_override_backend_host = Some("stable.svc".to_string());
    let stable_proxy = stable_ctx.apply_route_overrides(Arc::clone(&proxy));

    let canary_key = Http2ConnectionPool::pool_key_for_warmup(&canary_proxy);
    let stable_key = Http2ConnectionPool::pool_key_for_warmup(&stable_proxy);
    assert_ne!(
        canary_key, stable_key,
        "H2 pool key must partition on backend_host override"
    );
}

#[test]
fn screen_mesh_route_dispatch_egress_rejects_metadata_destination() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::plugins::screen_mesh_route_dispatch_egress;
    use serde_json::json;

    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid policy");

    // A rule overriding the backend to the cloud-metadata address must be
    // rejected at admin/config-admission time, not only at dial time.
    let denied = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "169.254.169.254", "backend_port": 80}
        }]
    });
    let errs = screen_mesh_route_dispatch_egress(&denied, &default_policy)
        .expect_err("metadata destination must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("169.254.169.254") && e.contains("backend egress policy")),
        "got: {errs:?}"
    );

    // A loopback / RFC1918 destination still validates by default.
    let allowed = json!({
        "rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "10.0.0.5", "backend_port": 80}
        }]
    });
    assert!(screen_mesh_route_dispatch_egress(&allowed, &default_policy).is_ok());
}

// ── GRPCRoute pathless-predicate live data path (issue #3271) ─────────────
//
// These drive the *translator-emitted* `mesh_route_dispatch` config, so the
// CRD → dispatch-rule → request-time-decision chain is covered end to end
// rather than only asserting the translated JSON shape.

mod grpc_route_predicate_dispatch {
    use std::collections::HashMap;

    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
    use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
    use serde_json::{Value, json};

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    fn grpc_route(name: &str, rules: Value) -> K8sObject {
        K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "GRPCRoute".to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: json!({"hostnames": ["grpc.example.com"], "rules": rules}),
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn http_catch_all_route(name: &str) -> K8sObject {
        let mut route = grpc_route(name, json!([]));
        route.kind = "HTTPRoute".to_string();
        route.spec = json!({
            "hostnames": ["grpc.example.com"],
            "rules": [{"backendRefs": [{"name": "web", "port": 8080}]}]
        });
        route
    }

    /// Build the live plugin from the dispatch config the translator emitted
    /// for `listen_path`, failing loudly if no such listener exists.
    fn dispatch_plugin_for_path(objects: &[K8sObject], listen_path: &str) -> MeshRouteDispatch {
        let translation =
            translate_k8s_objects(objects, options()).expect("translation should succeed");
        let proxy = translation
            .config
            .proxies
            .iter()
            .find(|proxy| proxy.listen_path.as_deref() == Some(listen_path))
            .unwrap_or_else(|| panic!("expected a `{listen_path}` listener"));
        let plugin = translation
            .config
            .plugin_configs
            .iter()
            .find(|plugin| {
                plugin.plugin_name == "mesh_route_dispatch"
                    && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
            })
            .unwrap_or_else(|| {
                panic!("the `{listen_path}` listener carries a mesh_route_dispatch instance")
            });
        MeshRouteDispatch::new(&plugin.config).expect("translated dispatch config is valid")
    }

    /// Build the live plugin from the dispatch config the translator emitted
    /// for the `/` listener, failing loudly if no such listener exists.
    fn dispatch_plugin_for_catch_all(objects: &[K8sObject]) -> MeshRouteDispatch {
        dispatch_plugin_for_path(objects, "/")
    }

    fn grpc_headers() -> HashMap<String, String> {
        HashMap::from([(
            "content-type".to_string(),
            "application/grpc+proto".to_string(),
        )])
    }

    async fn resolved_backend(
        plugin: &MeshRouteDispatch,
        path: &str,
        headers: &mut HashMap<String, String>,
    ) -> (Option<String>, Option<u16>, bool) {
        let mut request = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            path.to_string(),
        );
        let rejected = !matches!(
            plugin.before_proxy(&mut request, headers).await,
            PluginResult::Continue
        );
        (
            request.route_override_backend_host.clone(),
            request.route_override_backend_port,
            rejected,
        )
    }

    #[tokio::test]
    async fn method_only_predicate_routes_matching_rpc_and_rejects_everything_else() {
        let plugin = dispatch_plugin_for_catch_all(&[grpc_route(
            "hello",
            json!([{
                "matches": [{"method": {"method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]),
        )]);

        // Positive: any service, the named method, over gRPC.
        let (host, port, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut grpc_headers()).await;
        assert!(!rejected);
        assert_eq!(port, Some(50051));
        assert!(
            host.as_deref()
                .is_some_and(|host| host.contains("grpc-api")),
            "expected the GRPCRoute backend, got {host:?}"
        );

        // Negative: a different method on the same service.
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayBye", &mut grpc_headers()).await;
        assert!(
            rejected,
            "an unrelated gRPC method must not reach the backend"
        );

        // Negative: a plain HTTP request whose path happens to share the
        // two-segment gRPC shape must not be captured by a pathless gRPC rule.
        let mut html = HashMap::from([("content-type".to_string(), "text/html".to_string())]);
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut html).await;
        assert!(
            rejected,
            "a non-gRPC request must not match a pathless GRPCRoute predicate"
        );

        // Negative: a gRPC call whose path is not the two-segment shape.
        let (_, _, rejected) = resolved_backend(&plugin, "/SayHello", &mut grpc_headers()).await;
        assert!(rejected);
    }

    #[tokio::test]
    async fn exact_service_and_method_route_rejects_plain_http_on_the_same_path() {
        // The predicate is carried by the proxy's exact listen path, but a
        // GRPCRoute still selects gRPC calls only — a plain HTTP request to
        // `/helloworld.Greeter/SayHello` must not reach the gRPC backend.
        let objects = [grpc_route(
            "hello",
            json!([{
                "matches": [{
                    "method": {"service": "helloworld.Greeter", "method": "SayHello"}
                }],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]),
        )];
        let plugin = dispatch_plugin_for_path(&objects, "=/helloworld.Greeter/SayHello");

        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc; charset=utf-8",
            "application/grpc ; charset=utf-8",
            // HTTP media types are case-insensitive; a gRPC client that
            // capitalizes must still be routed.
            "Application/GRPC",
        ] {
            let mut headers =
                HashMap::from([("content-type".to_string(), content_type.to_string())]);
            let (_, port, rejected) =
                resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut headers).await;
            assert!(!rejected, "{content_type} is a gRPC call");
            assert_eq!(port, Some(50051), "{content_type} must reach the backend");
        }

        // The emitted gate is the regex transcription of Ferrum's canonical
        // native-gRPC dispatcher contract, so raw lookalikes are refused. A
        // real gRPC-Web request reaches a native `application/grpc` only via a
        // trusted, explicitly configured `grpc_web` plugin.
        for content_type in [
            "application/grpcfoo",
            "application/grpc-web",
            "application/grpc-website",
            "application/grpc-web-text",
            "text/plain",
            "application/json",
            "text/html",
        ] {
            let mut headers =
                HashMap::from([("content-type".to_string(), content_type.to_string())]);
            let (_, _, rejected) =
                resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut headers).await;
            assert!(
                rejected,
                "plain HTTP ({content_type}) must not match an exact GRPCRoute path"
            );
        }

        // No content-type at all is not a gRPC call either.
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut HashMap::new()).await;
        assert!(rejected, "a request without a content-type is not gRPC");
    }

    #[tokio::test]
    async fn service_only_route_rejects_plain_http_under_the_service_prefix() {
        let objects = [grpc_route(
            "greeter",
            json!([{
                "matches": [{"method": {"service": "helloworld.Greeter"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]),
        )];
        let plugin = dispatch_plugin_for_path(&objects, "/helloworld.Greeter/");

        let (_, port, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut grpc_headers()).await;
        assert!(!rejected);
        assert_eq!(port, Some(50051));

        let mut html = HashMap::from([("content-type".to_string(), "text/html".to_string())]);
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut html).await;
        assert!(
            rejected,
            "plain HTTP under the service prefix must not reach the gRPC backend"
        );
    }

    #[tokio::test]
    async fn authored_content_type_narrows_the_gate_and_text_plain_is_refused() {
        // A gRPC media type authored on the route replaces the canonical gate
        // and only narrows it: `+proto` matches, bare `application/grpc` does
        // not.
        let objects = [grpc_route(
            "hello",
            json!([{
                "matches": [{
                    "method": {"method": "SayHello"},
                    "headers": [{"name": "content-type", "value": "application/grpc+proto"}]
                }],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]),
        )];
        let plugin = dispatch_plugin_for_catch_all(&objects);
        let (_, port, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut grpc_headers()).await;
        assert!(!rejected);
        assert_eq!(port, Some(50051));

        let mut bare =
            HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut bare).await;
        assert!(rejected, "the authored predicate narrows the gate");

        // A non-gRPC authored content-type would widen the route onto plain
        // HTTP, so the match is refused during translation and nothing
        // materializes at all.
        let widening = translate_k8s_objects(
            &[grpc_route(
                "widen",
                json!([{
                    "matches": [{
                        "method": {"service": "helloworld.Greeter", "method": "SayHello"},
                        "headers": [{"name": "content-type", "value": "text/plain"}]
                    }],
                    "backendRefs": [{"name": "grpc-api", "port": 50051}]
                }]),
            )],
            options(),
        )
        .expect("translation should succeed");
        assert!(
            widening.config.proxies.is_empty(),
            "a text/plain content-type predicate must not materialize a GRPCRoute"
        );
    }

    #[tokio::test]
    async fn regular_expression_method_matches_never_materialize() {
        // Ferrum cannot constrain a regex operand to one gRPC path segment,
        // so `RegularExpression` predicates are refused rather than compiled
        // into a matcher that could widen across service/method boundaries.
        for operand in [".*", "a\\x2Fb", "a[/]b", "helloworld\\..*"] {
            let translation = translate_k8s_objects(
                &[grpc_route(
                    "regex",
                    json!([{
                        "matches": [{"method": {
                            "type": "RegularExpression",
                            "service": operand,
                            "method": operand
                        }}],
                        "backendRefs": [{"name": "grpc-api", "port": 50051}]
                    }]),
                )],
                options(),
            )
            .expect("translation should succeed");
            assert!(
                translation.config.proxies.is_empty(),
                "`{operand}` must not materialize a route"
            );
            assert!(
                !translation
                    .config
                    .plugin_configs
                    .iter()
                    .any(|plugin| plugin.plugin_name == "mesh_route_dispatch"),
                "`{operand}` must not leave a dispatch rule behind"
            );
        }
    }

    #[tokio::test]
    async fn header_predicate_wins_over_the_broader_later_rule() {
        let plugin = dispatch_plugin_for_catch_all(&[grpc_route(
            "tenants",
            json!([
                {
                    "matches": [{
                        "method": {"method": "SayHello"},
                        "headers": [{"name": "x-tenant", "value": "a"}]
                    }],
                    "backendRefs": [{"name": "tenant-a", "port": 50051}]
                },
                {
                    "matches": [{"method": {"method": "SayHello"}}],
                    "backendRefs": [{"name": "shared", "port": 50052}]
                }
            ]),
        )]);

        let mut tenant = grpc_headers();
        tenant.insert("x-tenant".to_string(), "a".to_string());
        let (_, port, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut tenant).await;
        assert!(!rejected);
        assert_eq!(port, Some(50051), "the tenant rule is more specific");

        let (_, port, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut grpc_headers()).await;
        assert!(!rejected);
        assert_eq!(
            port,
            Some(50052),
            "untagged calls fall through to the broader rule"
        );
    }

    /// Gateway API v1.5.1 `GRPCRouteSpec` / `GRPCRouteRule`: an HTTPRoute and a
    /// GRPCRoute attached to the same listener with intersecting hostnames must
    /// resolve to exactly one accepted Route (oldest `creationTimestamp`, then
    /// `{namespace}/{name}`), and rules must never be merged between the two
    /// kinds. The loser must materialize no traffic state at all.
    ///
    /// `grpc-api:50051` is only ever the GRPCRoute's backend and `web:8080` is
    /// only ever the HTTPRoute's, so "did the losing route materialize
    /// anything?" is answered behaviorally rather than by parsing proxy ids.
    fn backend_ports(objects: &[K8sObject]) -> Vec<u16> {
        let translation =
            translate_k8s_objects(objects, options()).expect("translation should succeed");
        let mut ports: Vec<u16> = translation
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.backend_port)
            .collect();
        for upstream in &translation.config.upstreams {
            ports.extend(upstream.targets.iter().map(|target| target.port));
        }
        for plugin in &translation.config.plugin_configs {
            for rule in plugin
                .config
                .get("rules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(port) = rule
                    .get("destination")
                    .and_then(|destination| destination.get("backend_port"))
                    .and_then(Value::as_u64)
                {
                    ports.push(u16::try_from(port).expect("a translated backend port fits u16"));
                }
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn dated(mut route: K8sObject, timestamp: &str) -> K8sObject {
        route.metadata.creation_timestamp = Some(timestamp.to_string());
        route
    }

    fn grpc_hello(name: &str) -> K8sObject {
        grpc_route(
            name,
            json!([{
                "matches": [{"method": {"method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-api", "port": 50051}]
            }]),
        )
    }

    #[test]
    fn cross_kind_listener_overlap_accepts_exactly_one_route_by_creation_timestamp() {
        let http = dated(http_catch_all_route("web"), "2024-01-01T00:00:00Z");
        let grpc = dated(grpc_hello("grpc"), "2024-02-01T00:00:00Z");

        // The older HTTPRoute wins the listener outright; the GRPCRoute
        // contributes no proxy, no upstream, and no dispatch destination.
        for objects in [
            vec![http.clone(), grpc.clone()],
            vec![grpc.clone(), http.clone()],
        ] {
            assert_eq!(
                backend_ports(&objects),
                vec![8080],
                "the older HTTPRoute wins regardless of input order"
            );
        }

        // Flip the timestamps and the GRPCRoute wins instead — the rule is the
        // creation order, not the kind.
        let http_newer = dated(http_catch_all_route("web"), "2024-03-01T00:00:00Z");
        for objects in [
            vec![http_newer.clone(), grpc.clone()],
            vec![grpc.clone(), http_newer.clone()],
        ] {
            assert_eq!(
                backend_ports(&objects),
                vec![50051],
                "the older GRPCRoute wins regardless of input order"
            );
        }
    }

    #[test]
    fn cross_kind_tie_on_timestamp_breaks_on_namespace_and_name() {
        // Same creationTimestamp: `{namespace}/{name}` decides. Both routes are
        // in `default`, so `aaa-http` sorts before `zzz-grpc`.
        let http = dated(http_catch_all_route("aaa-http"), "2024-01-01T00:00:00Z");
        let grpc = dated(grpc_hello("zzz-grpc"), "2024-01-01T00:00:00Z");
        for objects in [
            vec![http.clone(), grpc.clone()],
            vec![grpc.clone(), http.clone()],
        ] {
            assert_eq!(backend_ports(&objects), vec![8080]);
        }

        let http = dated(http_catch_all_route("zzz-http"), "2024-01-01T00:00:00Z");
        let grpc = dated(grpc_hello("aaa-grpc"), "2024-01-01T00:00:00Z");
        for objects in [
            vec![http.clone(), grpc.clone()],
            vec![grpc.clone(), http.clone()],
        ] {
            assert_eq!(backend_ports(&objects), vec![50051]);
        }
    }

    /// `{namespace}/{name}` is unique *within* a kind but not across kinds, and
    /// `metadata.creationTimestamp` has second granularity — so one
    /// `kubectl apply` of an HTTPRoute and a GRPCRoute that share a name ties
    /// on every Gateway API ordering field. The accepted Route must still be
    /// the same one regardless of the order the objects are observed in.
    #[test]
    fn cross_kind_tie_on_timestamp_and_name_is_still_order_independent() {
        let http = dated(http_catch_all_route("echo"), "2024-01-01T00:00:00Z");
        let grpc = dated(grpc_hello("echo"), "2024-01-01T00:00:00Z");

        let forward = backend_ports(&[http.clone(), grpc.clone()]);
        let reverse = backend_ports(&[grpc, http]);
        assert_eq!(
            forward, reverse,
            "a total tie must not resolve by watch arrival order"
        );
        assert_eq!(
            forward.len(),
            1,
            "exactly one Route may be accepted on the listener, got {forward:?}"
        );
    }

    #[test]
    fn cross_kind_routes_on_disjoint_hostnames_both_materialize() {
        // The rejection is hostname-scoped: no intersection, no conflict.
        let http = dated(http_catch_all_route("web"), "2024-01-01T00:00:00Z");
        let mut grpc = dated(grpc_hello("grpc"), "2024-02-01T00:00:00Z");
        grpc.spec["hostnames"] = json!(["rpc.example.com"]);

        assert_eq!(
            backend_ports(&[http, grpc]),
            vec![8080, 50051],
            "disjoint hostnames are different listeners' worth of traffic"
        );
    }

    #[tokio::test]
    async fn a_cross_kind_losing_grpc_route_cannot_route_traffic() {
        let objects = [
            dated(http_catch_all_route("web"), "2024-01-01T00:00:00Z"),
            dated(grpc_hello("grpc"), "2024-02-01T00:00:00Z"),
        ];
        let translation =
            translate_k8s_objects(&objects, options()).expect("translation should succeed");

        // No rule anywhere can send `/helloworld.Greeter/SayHello` to the gRPC
        // backend, because the GRPCRoute never materialized.
        for plugin in translation
            .config
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        {
            let dispatch = MeshRouteDispatch::new(&plugin.config)
                .expect("translated dispatch config is valid");
            let (_, port, _) = resolved_backend(
                &dispatch,
                "/helloworld.Greeter/SayHello",
                &mut grpc_headers(),
            )
            .await;
            assert_ne!(
                port,
                Some(50051),
                "the rejected GRPCRoute must not route any traffic"
            );
        }

        assert!(
            translation.warnings.iter().any(|warning| {
                warning.contains("GRPCRoute default/grpc")
                    && warning.contains("Gateway API forbids merging")
            }),
            "the rejection must be reported: {:?}",
            translation.warnings
        );
    }

    #[tokio::test]
    async fn updating_and_deleting_the_route_republishes_the_dispatch_generation() {
        let initial = [grpc_route(
            "hello",
            json!([{
                "matches": [{"method": {"method": "SayHello"}}],
                "backendRefs": [{"name": "grpc-v1", "port": 50051}]
            }]),
        )];
        let (_, port, _) = resolved_backend(
            &dispatch_plugin_for_catch_all(&initial),
            "/helloworld.Greeter/SayHello",
            &mut grpc_headers(),
        )
        .await;
        assert_eq!(port, Some(50051));

        // Update: the same route now names a different method and backend.
        // The regenerated plugin must serve the new predicate and reject the
        // old one — no stale rule survives the reload.
        let updated = [grpc_route(
            "hello",
            json!([{
                "matches": [{"method": {"method": "SayGoodbye"}}],
                "backendRefs": [{"name": "grpc-v2", "port": 50052}]
            }]),
        )];
        let plugin = dispatch_plugin_for_catch_all(&updated);
        let (_, port, rejected) = resolved_backend(
            &plugin,
            "/helloworld.Greeter/SayGoodbye",
            &mut grpc_headers(),
        )
        .await;
        assert!(!rejected);
        assert_eq!(port, Some(50052));
        let (_, _, rejected) =
            resolved_backend(&plugin, "/helloworld.Greeter/SayHello", &mut grpc_headers()).await;
        assert!(rejected, "the replaced predicate must no longer match");

        // Delete: with the route gone the `/` listener and its dispatch
        // instance disappear entirely.
        let empty: [K8sObject; 0] = [];
        let translation =
            translate_k8s_objects(&empty, options()).expect("translation should succeed");
        assert!(translation.config.proxies.is_empty());
        assert!(
            !translation
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "mesh_route_dispatch")
        );
    }
}

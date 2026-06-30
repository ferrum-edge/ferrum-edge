//! Tests for `RequestContext::apply_route_overrides` and the `effective_*`
//! helpers — the plumbing that lets `mesh_route_dispatch` rewrite the
//! routing decision per request without mutating the matched `Proxy` in
//! shared `ArcSwap` state.

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::types::{
    BackendTlsConfig, Proxy, ResolvedPortOverride, Upstream, UpstreamPortOverride,
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

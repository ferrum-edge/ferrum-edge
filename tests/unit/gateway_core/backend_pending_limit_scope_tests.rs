//! External coverage for H1 pending-admission logical scope identity
//! (issue #3778).
//!
//! Inline `backend_pending_limit` tests already exercise concurrent acquire /
//! drop / zero-count eviction. This module focuses on cross-Service isolation,
//! endpoint-fan-out non-multiplication, namespace isolation, UID recreate
//! fencing, additive UID+upstream identity, deterministic cap-update
//! semantics, and request-time upstream route-override rebind of the
//! precomputed scope that the acceptance contract requires to be visible
//! outside the production module.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use ferrum_edge::backend_pending_limit::{BackendPendingLimiter, BackendPendingScopeBase};
use ferrum_edge::config::types::{
    BackendTlsConfig, GatewayConfig, Proxy, ResolvedPortOverride, Upstream, UpstreamPortOverride,
};
use ferrum_edge::plugins::RequestContext;

fn namespaced_snapshot(
    namespace: &str,
    id: &str,
    upstream: Arc<Upstream>,
) -> HashMap<String, Arc<Upstream>> {
    HashMap::from([(
        ferrum_edge::config::db_backend::namespaced_runtime_key(namespace, id),
        upstream,
    )])
}

fn source_upstream_tls() -> BackendTlsConfig {
    BackendTlsConfig {
        client_cert_path: Some("/certs/source.pem".to_string()),
        client_key_path: Some("/certs/source.key".to_string()),
        server_ca_cert_path: Some("/certs/source-ca.pem".to_string()),
        verify_server_cert: false,
        sni: None,
        san_allow_list: Vec::new(),
        san_allow_list_key_digest: None,
        tls_refused: false,
    }
}

fn source_port_overlay() -> HashMap<u16, ResolvedPortOverride> {
    HashMap::from([(
        8080,
        ResolvedPortOverride {
            connect_timeout_ms: Some(1_000),
            ..Default::default()
        },
    )])
}

fn source_port_fallback() -> ResolvedPortOverride {
    ResolvedPortOverride {
        http1_max_pending_requests: Some(11),
        ..Default::default()
    }
}

fn scope(ns: &str, id: &str, uid: Option<&str>, sub: Option<&str>) -> BackendPendingScopeBase {
    BackendPendingScopeBase::new(ns, id, uid, sub)
}

#[test]
fn independent_services_same_endpoint_and_subset_stay_isolated() {
    let limiter = BackendPendingLimiter::new();
    let public = scope("shop", "checkout-public", None, Some("v1"));
    let internal = scope("shop", "checkout-internal", None, Some("v1"));

    let _a = limiter
        .try_acquire(&public, 8080, Some(1))
        .expect("public")
        .expect("guard");
    limiter
        .try_acquire(&public, 8080, Some(1))
        .expect_err("public saturated");

    // Same pod IP / subset name would previously collide on a host key.
    let _b = limiter
        .try_acquire(&internal, 8080, Some(10))
        .expect("internal must remain independent under cap 10")
        .expect("guard");
    let mut internal_guards = Vec::new();
    for _ in 0..9 {
        internal_guards.push(
            limiter
                .try_acquire(&internal, 8080, Some(10))
                .expect("internal admits up to 10")
                .expect("guard"),
        );
    }
    limiter
        .try_acquire(&internal, 8080, Some(10))
        .expect_err("internal at its own cap");
    assert_eq!(limiter.current(&public, 8080), 1);
    assert_eq!(limiter.current(&internal, 8080), 10);
}

#[test]
fn saturating_high_cap_service_does_not_reject_low_cap_sibling() {
    let limiter = BackendPendingLimiter::new();
    let low = scope("shop", "a", None, Some("v1"));
    let high = scope("shop", "b", None, Some("v1"));

    let mut high_guards = Vec::new();
    for _ in 0..5 {
        high_guards.push(
            limiter
                .try_acquire(&high, 80, Some(10))
                .expect("high")
                .expect("guard"),
        );
    }
    let _low = limiter
        .try_acquire(&low, 80, Some(1))
        .expect("low-cap Service must not see the sibling's count")
        .expect("guard");
}

#[test]
fn namespaces_sharing_endpoint_subset_string_remain_isolated() {
    let limiter = BackendPendingLimiter::new();
    let a = scope("tenant-a", "reviews", None, Some("v1"));
    let b = scope("tenant-b", "reviews", None, Some("v1"));
    let _ga = limiter
        .try_acquire(&a, 9080, Some(1))
        .expect("a")
        .expect("guard");
    let _gb = limiter
        .try_acquire(&b, 9080, Some(1))
        .expect("b")
        .expect("guard");
    assert_eq!(limiter.current(&a, 9080), 1);
    assert_eq!(limiter.current(&b, 9080), 1);
}

#[test]
fn multi_endpoint_selection_shares_one_logical_lane() {
    let limiter = BackendPendingLimiter::new();
    let svc = scope("default", "reviews", None, Some("v1"));
    // Endpoint rotation is not part of the key — only scope + policy port.
    let _g = limiter
        .try_acquire(&svc, 9080, Some(1))
        .expect("first endpoint")
        .expect("guard");
    limiter
        .try_acquire(&svc, 9080, Some(1))
        .expect_err("sibling endpoint / retry must share the logical lane");
}

#[test]
fn intentional_shared_upstream_shares_one_lane_across_proxies() {
    let limiter = BackendPendingLimiter::new();
    // Two proxies intentionally targeting the same upstream/subset/port.
    let shared = scope("default", "reviews-upstream", None, Some("v1"));
    let _from_proxy_a = limiter
        .try_acquire(&shared, 80, Some(1))
        .expect("a")
        .expect("guard");
    limiter
        .try_acquire(&shared, 80, Some(1))
        .expect_err("proxy B must share proxy A's logical lane");
}

#[test]
fn same_upstream_and_uid_shares_lane_across_endpoint_and_config_churn() {
    let limiter = BackendPendingLimiter::new();
    let lane = scope("default", "reviews", Some("uid-1"), Some("v1"));
    let _g = limiter
        .try_acquire(&lane, 80, Some(1))
        .expect("first")
        .expect("guard");
    // Same upstream + UID across churn retains one counter; host is absent.
    limiter
        .try_acquire(&lane, 80, Some(1))
        .expect_err("endpoint/config churn must retain the same lane");
    assert!(!lane.prefix().contains("10.0.0.5"));
    assert!(lane.prefix().contains("id"));
    assert!(lane.prefix().contains("uid"));
}

#[test]
fn k8s_uid_recreate_does_not_inherit_stale_lane() {
    let limiter = BackendPendingLimiter::new();
    let old = scope("default", "reviews", Some("uid-old"), Some("v1"));
    let new = scope("default", "reviews", Some("uid-new"), Some("v1"));
    let old_guard = limiter
        .try_acquire(&old, 80, Some(1))
        .expect("old")
        .expect("guard");
    let _new_guard = limiter
        .try_acquire(&new, 80, Some(1))
        .expect("recreate")
        .expect("guard");
    drop(old_guard);
    assert_eq!(limiter.current(&old, 80), 0);
    assert_eq!(limiter.current(&new, 80), 1);
}

#[test]
fn matching_optional_uid_does_not_collapse_distinct_upstreams() {
    let limiter = BackendPendingLimiter::new();
    let a = scope("default", "reviews-a", Some("shared-uid"), Some("v1"));
    let b = scope("default", "reviews-b", Some("shared-uid"), Some("v1"));
    let _ga = limiter
        .try_acquire(&a, 80, Some(1))
        .expect("a")
        .expect("guard");
    let _gb = limiter
        .try_acquire(&b, 80, Some(1))
        .expect("distinct upstream ids stay isolated even when optional UID matches")
        .expect("guard");
    assert_eq!(limiter.current(&a, 80), 1);
    assert_eq!(limiter.current(&b, 80), 1);
    assert_ne!(a.prefix(), b.prefix());
}

#[test]
fn cap_update_preserves_count_and_releases_exactly_once() {
    let limiter = BackendPendingLimiter::new();
    let svc = scope("default", "reviews", None, None);
    let g1 = limiter
        .try_acquire(&svc, 80, Some(1))
        .expect("cap1")
        .expect("guard");
    let g2 = limiter
        .try_acquire(&svc, 80, Some(2))
        .expect("raised cap")
        .expect("guard");
    assert_eq!(limiter.current(&svc, 80), 2);
    let err = limiter
        .try_acquire(&svc, 80, Some(1))
        .expect_err("lowered cap rejects against shared count");
    assert_eq!(err.cap, 1, "rejection reports the requesting epoch's cap");
    assert_eq!(err.current, 2);
    drop(g1);
    assert_eq!(limiter.current(&svc, 80), 1);
    drop(g2);
    assert_eq!(limiter.current(&svc, 80), 0);
}

#[test]
fn concurrent_mixed_scope_churn_evicts_idle_keys() {
    let limiter = Arc::new(BackendPendingLimiter::new());
    let scopes: Vec<Arc<BackendPendingScopeBase>> = (0..4)
        .map(|i| Arc::new(scope("default", &format!("svc-{i}"), None, Some("v1"))))
        .collect();
    let granted = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for scope in &scopes {
        for _ in 0..4 {
            let limiter = Arc::clone(&limiter);
            let scope = Arc::clone(scope);
            let granted = Arc::clone(&granted);
            handles.push(thread::spawn(move || {
                for _ in 0..2_000 {
                    if let Ok(Some(guard)) = limiter.try_acquire(&scope, 80, Some(2)) {
                        granted.fetch_add(1, Ordering::Relaxed);
                        for _ in 0..8 {
                            std::hint::spin_loop();
                        }
                        drop(guard);
                    }
                }
            }));
        }
    }
    for h in handles {
        h.join().expect("join");
    }
    assert!(granted.load(Ordering::Relaxed) > 0);
    for scope in &scopes {
        assert_eq!(limiter.current(scope, 80), 0);
    }
}

#[test]
fn resolve_pending_limit_scopes_interns_upstream_and_optional_uid_not_host() {
    // Mirror GatewayConfig::resolve_pending_limit_scopes identity selection:
    // stable upstream id is always present; optional UID is additive; host
    // never enters the key.
    let svc = scope("default", "reviews", Some("uid-reviews"), Some("v1"));
    assert!(
        svc.prefix().contains("id"),
        "stable upstream id must always participate in the interned identity"
    );
    assert!(
        svc.prefix().contains("uid"),
        "K8s Service UID must participate alongside the upstream id"
    );
    assert!(
        !svc.prefix().contains("10.0.0.5"),
        "selected/backend host must not enter the pending scope key"
    );
    let host_keyed_collision = scope("default", "10.0.0.5", None, Some("v1"));
    assert_ne!(
        svc.prefix(),
        host_keyed_collision.prefix(),
        "UID-backed Service identity must not collapse to a host-shaped upstream id"
    );
}

#[test]
fn mesh_service_scope_converges_vip_and_direct_workload_upstreams() {
    fn upstream(id: &str, name: &str, uid: Option<&str>) -> Upstream {
        let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
            "id": id,
            "name": name,
            "namespace": "default",
            "targets": [{"host": "10.0.0.1", "port": 8080}],
        }))
        .expect("upstream");
        upstream.k8s_service_uid = uid.map(str::to_string);
        upstream
    }

    fn proxy(id: &str, upstream_id: &str) -> Proxy {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "namespace": "default",
            "backend_host": "10.0.0.1",
            "backend_port": 8080,
            "upstream_id": upstream_id,
        }))
        .expect("proxy")
    }

    let reviews_vip_id = "__mesh-out-upstream-default-reviews-8080";
    let reviews_pod_a_id = "__mesh-out-http-bywl-upstream-default-reviews-8080-10-0-0-1";
    let reviews_pod_b_id = "__mesh-out-http-bywl-upstream-default-reviews-8080-10-0-0-2";
    let ratings_id = "__mesh-out-upstream-default-ratings-8080";
    let recreated_reviews_id = "__mesh-out-upstream-default-reviews-9090";
    let file_mesh_vip_id = "__mesh-out-upstream-default-catalog-8080";
    let file_mesh_pod_id = "__mesh-out-http-bywl-upstream-default-catalog-8080-10-0-0-3";

    let mut config = GatewayConfig {
        upstreams: vec![
            upstream(
                reviews_vip_id,
                "reviews.default.svc.cluster.local",
                Some("uid-reviews"),
            ),
            upstream(
                reviews_pod_a_id,
                "reviews.default.svc.cluster.local",
                Some("uid-reviews"),
            ),
            upstream(
                reviews_pod_b_id,
                "reviews.default.svc.cluster.local",
                Some("uid-reviews"),
            ),
            upstream(
                ratings_id,
                "ratings.default.svc.cluster.local",
                Some("uid-reviews"),
            ),
            upstream(
                recreated_reviews_id,
                "reviews.default.svc.cluster.local",
                Some("uid-reviews-new"),
            ),
            upstream("native-a", "shared display name", None),
            upstream("native-b", "shared display name", None),
            upstream(file_mesh_vip_id, "catalog.default.svc.cluster.local", None),
            upstream(file_mesh_pod_id, "catalog.default.svc.cluster.local", None),
        ],
        proxies: vec![
            proxy("reviews-vip", reviews_vip_id),
            proxy("reviews-pod-a", reviews_pod_a_id),
            proxy("reviews-pod-b", reviews_pod_b_id),
        ],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    fn upstream_scope(config: &GatewayConfig, index: usize) -> &str {
        config.upstreams[index]
            .pending_limit_scope
            .as_ref()
            .expect("upstream scope")
            .prefix()
    }
    fn proxy_scope(config: &GatewayConfig, index: usize) -> &str {
        config.proxies[index]
            .pending_limit_scope
            .as_ref()
            .expect("proxy scope")
            .prefix()
    }

    assert_eq!(upstream_scope(&config, 0), upstream_scope(&config, 1));
    assert_eq!(upstream_scope(&config, 0), upstream_scope(&config, 2));
    assert_eq!(proxy_scope(&config, 0), proxy_scope(&config, 1));
    assert_eq!(proxy_scope(&config, 0), proxy_scope(&config, 2));
    assert_eq!(proxy_scope(&config, 0), upstream_scope(&config, 0));
    assert_ne!(upstream_scope(&config, 0), upstream_scope(&config, 3));
    assert_ne!(upstream_scope(&config, 0), upstream_scope(&config, 4));
    assert_ne!(upstream_scope(&config, 5), upstream_scope(&config, 6));
    assert_eq!(upstream_scope(&config, 7), upstream_scope(&config, 8));
}

#[test]
fn upstream_route_override_rebinds_pending_scope_away_from_source_lane() {
    // A→B upstream override must Arc-clone B's precomputed top-level scope
    // (including K8s Service UID) and must not retain A's capped lane —
    // including A's selected subset, which runtime clears on upstream change.
    let mut upstream_a: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-a",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream A");
    upstream_a.k8s_service_uid = Some("uid-a".to_string());

    let mut upstream_b: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-b",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream B");
    upstream_b.k8s_service_uid = Some("uid-b".to_string());

    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
        "upstream_subset": "v1",
    }))
    .expect("proxy");

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream_a, upstream_b],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let proxy = Arc::new(config.proxies[0].clone());
    let source_scope = proxy
        .pending_limit_scope
        .as_ref()
        .expect("proxy A scope interned");
    assert!(
        source_scope.prefix().contains("upstream-a"),
        "source lane must bind upstream A"
    );
    assert!(
        source_scope.prefix().contains("uid-a"),
        "source lane must bind Service UID A"
    );
    assert!(
        source_scope.prefix().contains("v1"),
        "source lane must bind selected subset v1"
    );

    let upstream_b = Arc::new(config.upstreams[1].clone());
    let dest_scope = upstream_b
        .pending_limit_scope
        .as_ref()
        .expect("upstream B top-level scope interned");
    assert!(
        dest_scope.prefix().contains("upstream-b") && dest_scope.prefix().contains("uid-b"),
        "destination carrier must include B id + UID"
    );
    assert!(
        !dest_scope.prefix().contains("v1"),
        "upstream carrier is top-level only (subset cleared on override)"
    );

    let upstreams = namespaced_snapshot("shop", "upstream-b", Arc::clone(&upstream_b));

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_upstream_id = Some("upstream-b".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);

    assert_eq!(effective.upstream_id.as_deref(), Some("upstream-b"));
    assert!(
        effective.upstream_subset.is_none(),
        "upstream change clears selected subset"
    );
    let effective_scope = effective
        .pending_limit_scope
        .as_ref()
        .expect("override must rebind pending scope");
    assert!(
        Arc::ptr_eq(effective_scope, dest_scope),
        "override must Arc-clone B's precomputed scope (no per-request rebuild)"
    );
    assert_ne!(
        effective_scope.prefix(),
        source_scope.prefix(),
        "effective proxy must not retain A's logical lane"
    );
    assert!(
        !effective_scope.prefix().contains("upstream-a")
            && !effective_scope.prefix().contains("uid-a"),
        "A's id/UID must not remain on the rebound scope"
    );
    assert!(
        effective_scope.prefix().contains("upstream-b")
            && effective_scope.prefix().contains("uid-b"),
        "rebound scope must carry B's id + UID"
    );
}

#[test]
fn upstream_route_override_rebinds_all_destination_derived_fields() {
    // One namespaced snapshot lookup must drive TLS, per-port overlays,
    // fallback, and pending-limit scope together. Bare-id maps must not be
    // able to supply a different destination's security/policy state.
    let mut upstream_a: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-a",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream A");
    upstream_a.k8s_service_uid = Some("uid-a".to_string());

    let mut upstream_b: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-b",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/dest.pem",
        "backend_tls_client_key_path": "/certs/dest.key",
        "backend_tls_server_ca_cert_path": "/certs/dest-ca.pem",
        "backend_tls_verify_server_cert": true,
    }))
    .expect("upstream B");
    upstream_b.k8s_service_uid = Some("uid-b".to_string());
    upstream_b.port_overrides = HashMap::from([(
        9090,
        UpstreamPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        },
    )]);
    upstream_b.dispatch_port_override_fallback = Some(UpstreamPortOverride {
        http1_max_pending_requests: Some(22),
        ..Default::default()
    });

    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
        "upstream_subset": "v1",
    }))
    .expect("proxy");

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream_a, upstream_b],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let mut proxy = config.proxies[0].clone();
    proxy.resolved_tls = source_upstream_tls();
    proxy.dispatch_port_overrides = Some(source_port_overlay());
    proxy.dispatch_port_override_fallback = Some(source_port_fallback());
    let proxy = Arc::new(proxy);

    let dest = Arc::new(config.upstreams[1].clone());
    let dest_scope = dest
        .pending_limit_scope
        .as_ref()
        .expect("destination pending scope");
    let upstreams = namespaced_snapshot("shop", "upstream-b", Arc::clone(&dest));

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_upstream_id = Some("upstream-b".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);

    assert_eq!(effective.upstream_id.as_deref(), Some("upstream-b"));
    assert_eq!(
        effective.resolved_tls.client_cert_path.as_deref(),
        Some("/certs/dest.pem")
    );
    assert_eq!(
        effective.resolved_tls.client_key_path.as_deref(),
        Some("/certs/dest.key")
    );
    assert_eq!(
        effective.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/certs/dest-ca.pem")
    );
    assert!(effective.resolved_tls.verify_server_cert);
    assert_eq!(
        effective
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&9090))
            .and_then(|override_config| override_config.connect_timeout_ms),
        Some(250)
    );
    assert!(
        !effective
            .dispatch_port_overrides
            .as_ref()
            .is_some_and(|overrides| overrides.contains_key(&8080)),
        "source port overlay must not survive a destination rebind"
    );
    assert_eq!(
        effective
            .dispatch_port_override_fallback
            .as_ref()
            .and_then(|fallback| fallback.http1_max_pending_requests),
        Some(22)
    );
    assert!(
        Arc::ptr_eq(
            effective
                .pending_limit_scope
                .as_ref()
                .expect("destination pending scope"),
            dest_scope
        ),
        "pending-limit lane must come from the same destination snapshot"
    );
}

#[test]
fn explicit_tls_override_wins_over_destination_snapshot() {
    let dest: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-b",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/dest.pem",
        "backend_tls_client_key_path": "/certs/dest.key",
        "backend_tls_verify_server_cert": true,
    }))
    .expect("destination upstream");

    let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
    }))
    .expect("proxy");
    proxy.resolved_tls = source_upstream_tls();
    let proxy = Arc::new(proxy);
    let upstreams = namespaced_snapshot("shop", "upstream-b", Arc::new(dest));

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_upstream_id = Some("upstream-b".to_string());
    ctx.route_override_resolved_tls = Some(BackendTlsConfig {
        client_cert_path: Some("/certs/explicit.pem".to_string()),
        client_key_path: Some("/certs/explicit.key".to_string()),
        server_ca_cert_path: Some("/certs/explicit-ca.pem".to_string()),
        verify_server_cert: false,
        sni: None,
        san_allow_list: Vec::new(),
        san_allow_list_key_digest: None,
        tls_refused: false,
    });

    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);
    assert_eq!(
        effective.resolved_tls.client_cert_path.as_deref(),
        Some("/certs/explicit.pem")
    );
    assert_eq!(
        effective.resolved_tls.client_key_path.as_deref(),
        Some("/certs/explicit.key")
    );
    assert!(!effective.resolved_tls.verify_server_cert);
}

#[test]
fn upstream_route_override_missing_snapshot_clears_pending_scope() {
    // Production upstream snapshots are keyed by namespace|id. A bare-id entry
    // (or an absent destination) must fail closed: drop source TLS, port
    // overlays, fallback, and the stale pending-limit lane.
    let mut upstream_a: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-a",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream A");
    upstream_a.k8s_service_uid = Some("uid-a".to_string());

    let mut upstream_b: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-b",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/dest.pem",
        "backend_tls_client_key_path": "/certs/dest.key",
        "backend_tls_verify_server_cert": false,
    }))
    .expect("upstream B");
    upstream_b.k8s_service_uid = Some("uid-b".to_string());
    upstream_b.port_overrides = HashMap::from([(
        9090,
        UpstreamPortOverride {
            connect_timeout_ms: Some(250),
            ..Default::default()
        },
    )]);
    upstream_b.dispatch_port_override_fallback = Some(UpstreamPortOverride {
        http1_max_pending_requests: Some(22),
        ..Default::default()
    });

    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
        "upstream_subset": "v1",
    }))
    .expect("proxy");

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream_a, upstream_b],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let mut proxy = config.proxies[0].clone();
    proxy.resolved_tls = source_upstream_tls();
    proxy.dispatch_port_overrides = Some(source_port_overlay());
    proxy.dispatch_port_override_fallback = Some(source_port_fallback());
    let proxy = Arc::new(proxy);
    assert!(
        proxy.pending_limit_scope.is_some(),
        "source proxy must carry A's interned scope"
    );

    // Wrong key shape: bare id instead of the runtime namespaced key.
    let mut upstreams = HashMap::new();
    upstreams.insert(
        "upstream-b".to_string(),
        Arc::new(config.upstreams[1].clone()),
    );

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_upstream_id = Some("upstream-b".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);

    assert_eq!(effective.upstream_id.as_deref(), Some("upstream-b"));
    assert!(
        effective.pending_limit_scope.is_none(),
        "missing namespaced snapshot lookup must clear the stale capped lane"
    );
    assert!(
        effective.resolved_tls.client_cert_path.is_none()
            && effective.resolved_tls.verify_server_cert,
        "missing destination must reset source upstream TLS rather than keep it"
    );
    assert!(
        effective.dispatch_port_overrides.is_none(),
        "missing destination must drop source per-port overlays"
    );
    assert!(
        effective.dispatch_port_override_fallback.is_none(),
        "missing destination must drop source dispatch-port fallback"
    );
}

#[test]
fn upstream_route_override_resolves_proxy_namespace_not_colliding_id() {
    // Same upstream id in two namespaces must not cross-pollinate when the
    // override lookup uses the proxy's namespace with the canonical runtime key.
    let mut checkout: Upstream = serde_json::from_value(serde_json::json!({
        "id": "checkout",
        "namespace": "tenant-a",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/checkout.pem",
        "backend_tls_verify_server_cert": false,
    }))
    .expect("tenant-a source upstream");
    checkout.k8s_service_uid = Some("uid-checkout".to_string());

    let mut upstream_a: Upstream = serde_json::from_value(serde_json::json!({
        "id": "reviews",
        "namespace": "tenant-a",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/tenant-a.pem",
        "backend_tls_client_key_path": "/certs/tenant-a.key",
        "backend_tls_verify_server_cert": true,
    }))
    .expect("tenant-a upstream");
    upstream_a.k8s_service_uid = Some("uid-a".to_string());
    upstream_a.port_overrides = HashMap::from([(
        9080,
        UpstreamPortOverride {
            connect_timeout_ms: Some(100),
            ..Default::default()
        },
    )]);
    upstream_a.dispatch_port_override_fallback = Some(UpstreamPortOverride {
        http1_max_pending_requests: Some(7),
        ..Default::default()
    });

    let mut upstream_b: Upstream = serde_json::from_value(serde_json::json!({
        "id": "reviews",
        "namespace": "tenant-b",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
        "backend_tls_client_cert_path": "/certs/tenant-b.pem",
        "backend_tls_client_key_path": "/certs/tenant-b.key",
        "backend_tls_verify_server_cert": false,
    }))
    .expect("tenant-b upstream");
    upstream_b.k8s_service_uid = Some("uid-b".to_string());
    upstream_b.port_overrides = HashMap::from([(
        9090,
        UpstreamPortOverride {
            connect_timeout_ms: Some(999),
            ..Default::default()
        },
    )]);
    upstream_b.dispatch_port_override_fallback = Some(UpstreamPortOverride {
        http1_max_pending_requests: Some(99),
        ..Default::default()
    });

    let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "tenant-a",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "checkout",
    }))
    .expect("proxy");
    proxy.resolved_tls = source_upstream_tls();
    proxy.dispatch_port_overrides = Some(source_port_overlay());
    proxy.dispatch_port_override_fallback = Some(source_port_fallback());

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![checkout, upstream_a, upstream_b],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let proxy = Arc::new(config.proxies[0].clone());
    let scope_a = Arc::clone(
        config.upstreams[1]
            .pending_limit_scope
            .as_ref()
            .expect("tenant-a reviews scope"),
    );
    let scope_b = config.upstreams[2]
        .pending_limit_scope
        .as_ref()
        .expect("tenant-b reviews scope");
    assert_ne!(
        scope_a.prefix(),
        scope_b.prefix(),
        "same id in different namespaces must stay isolated"
    );

    let mut upstreams = HashMap::new();
    upstreams.insert(
        ferrum_edge::config::db_backend::namespaced_runtime_key("tenant-a", "reviews"),
        Arc::new(config.upstreams[1].clone()),
    );
    upstreams.insert(
        ferrum_edge::config::db_backend::namespaced_runtime_key("tenant-b", "reviews"),
        Arc::new(config.upstreams[2].clone()),
    );

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_upstream_id = Some("reviews".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);

    let effective_scope = effective
        .pending_limit_scope
        .as_ref()
        .expect("tenant-a override must rebind scope");
    assert!(
        Arc::ptr_eq(effective_scope, &scope_a),
        "override must clone tenant-a's precomputed scope, not tenant-b's"
    );
    assert!(
        effective_scope.prefix().contains("uid-a") && !effective_scope.prefix().contains("uid-b"),
        "rebound scope must stay in the proxy namespace"
    );
    assert_eq!(
        effective.resolved_tls.client_cert_path.as_deref(),
        Some("/certs/tenant-a.pem")
    );
    assert!(
        effective.resolved_tls.verify_server_cert,
        "tenant-b's verify=false TLS must not cross-bind"
    );
    assert_eq!(
        effective
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&9080))
            .and_then(|override_config| override_config.connect_timeout_ms),
        Some(100)
    );
    assert!(
        !effective
            .dispatch_port_overrides
            .as_ref()
            .is_some_and(|overrides| overrides.contains_key(&9090)),
        "tenant-b per-port overlay must not bind a tenant-a proxy"
    );
    assert_eq!(
        effective
            .dispatch_port_override_fallback
            .as_ref()
            .and_then(|fallback| fallback.http1_max_pending_requests),
        Some(7)
    );
}

#[test]
fn direct_backend_override_clears_stale_upstream_pending_scope() {
    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-a",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream");
    upstream.k8s_service_uid = Some("uid-a".to_string());

    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
    }))
    .expect("proxy");

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let proxy = Arc::new(config.proxies[0].clone());
    assert!(proxy.pending_limit_scope.is_some());

    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.route_override_backend_host = Some("direct.svc".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(proxy, &HashMap::new());

    assert!(effective.upstream_id.is_none());
    assert!(
        effective.pending_limit_scope.is_none(),
        "direct-backend override must clear the stale capped upstream lane"
    );
}

#[test]
fn no_route_override_preserves_proxy_pending_scope_arc() {
    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "upstream-a",
        "namespace": "shop",
        "targets": [{"host": "10.0.0.1", "port": 8080}],
    }))
    .expect("upstream");
    upstream.k8s_service_uid = Some("uid-a".to_string());

    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "route-a",
        "namespace": "shop",
        "backend_host": "10.0.0.1",
        "backend_port": 8080,
        "upstream_id": "upstream-a",
    }))
    .expect("proxy");

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };
    config.resolve_pending_limit_scopes();

    let proxy = Arc::new(config.proxies[0].clone());
    let upstreams =
        namespaced_snapshot("shop", "upstream-a", Arc::new(config.upstreams[0].clone()));
    let ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    let effective = ctx.apply_route_overrides_with_upstreams(Arc::clone(&proxy), &upstreams);
    assert!(
        Arc::ptr_eq(&effective, &proxy),
        "ordinary no-override path must remain a no-op (same Proxy Arc)"
    );
}

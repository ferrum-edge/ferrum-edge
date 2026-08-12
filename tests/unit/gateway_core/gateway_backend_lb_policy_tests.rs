//! Live LB-path coverage for Gateway API BackendLBPolicy /
//! XBackendTrafficPolicy session persistence (#3278).
//!
//! Translation alone is covered in `gateway_api.rs`. These tests feed the
//! translated Upstream through `LoadBalancerCache` so the persistence data path
//! is exercised end to end:
//!
//! - the token the gateway would emit on the initial response resolves back to
//!   the EXACT target that produced it (`LoadBalancer::select_sticky`), which is
//!   what Gateway API session persistence actually requires;
//! - the consistent-hash ring underneath stays deterministic, which is the
//!   *fallback* used for unbound requests — deterministic re-hashing is NOT by
//!   itself session persistence and is asserted as such.
//!
//! Full-foreign `status.ancestors` capacity is also covered here: a MaxItems=16
//! third-party map must not suppress session-persistence translation, must not
//! produce a seventeenth Ferrum ancestor, and must not mark a valid policy
//! rejected (#3665).
//!
//! Token validation, foreign/stale/removed/unhealthy bindings, and
//! subset/port isolation live in `sticky_session_binding_tests.rs`.

use std::collections::HashMap;

use ferrum_edge::config::types::{
    HashOnCookieConfig, LoadBalancerAlgorithm, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use ferrum_edge::load_balancer::{HashOnStrategy, LoadBalancerCache};
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, api_version: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
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
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Extract the `name=value` pair's value from a `Set-Cookie` header value.
fn set_cookie_value(header: &str, name: &str) -> String {
    let pair = header
        .split(';')
        .next()
        .map(str::trim)
        .expect("cookie pair");
    pair.strip_prefix(&format!("{name}="))
        .unwrap_or_else(|| panic!("expected cookie named {name}, got {header}"))
        .to_string()
}

#[test]
fn backend_lb_policy_cookie_affinity_selects_stable_target_on_lb_path() {
    let policy = object(
        "BackendLBPolicy",
        "gateway.networking.k8s.io/v1alpha2",
        "sticky",
        json!({
            "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
            "sessionPersistence": {
                "sessionName": "lb-affinity",
                "type": "Cookie",
                "cookieConfig": {"lifetimeType": "Session"}
            }
        }),
    );
    // Headless multi-endpoint Service so sticky hashing has >1 target.
    let service = object(
        "Service",
        "v1",
        "api",
        json!({
            "clusterIP": "None",
            "selector": {"app": "api"},
            "ports": [{
                "name": "http",
                "port": 8080,
                "targetPort": 8080
            }]
        }),
    );
    let mut endpoints = object(
        "EndpointSlice",
        "discovery.k8s.io/v1",
        "api-slices",
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
            "endpoints": [
                {"addresses": ["10.1.0.10"], "conditions": {"ready": true}},
                {"addresses": ["10.1.0.11"], "conditions": {"ready": true}},
                {"addresses": ["10.1.0.12"], "conditions": {"ready": true}}
            ]
        }),
    );
    endpoints
        .metadata
        .labels
        .insert("kubernetes.io/service-name".to_string(), "api".to_string());
    let route = object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        "sample",
        json!({
            "hostnames": ["api.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                "backendRefs": [{"name": "api", "port": 8080}]
            }]
        }),
    );

    let result = translate_k8s_objects(
        &[policy, service, endpoints, route],
        options().with_pod_discovery_enabled(true),
    )
    .expect("BackendLBPolicy + multi-endpoint Service should translate");

    assert_eq!(result.config.upstreams.len(), 1);
    let upstream = &result.config.upstreams[0];
    assert_eq!(upstream.algorithm, LoadBalancerAlgorithm::ConsistentHashing);
    let cookie_name = upstream
        .hash_on
        .as_deref()
        .and_then(|value| value.strip_prefix("cookie:"))
        .expect("cookie hash strategy");
    assert!(
        cookie_name.starts_with("lb-affinity-fe-"),
        "cookie must be scoped to the route rule: {cookie_name}"
    );
    assert!(
        upstream
            .hash_on_cookie_config
            .as_ref()
            .is_some_and(|c| c.session_cookie),
        "Session lifetime must set session_cookie"
    );
    assert!(
        upstream.targets.len() >= 2,
        "need multiple endpoints for sticky affinity proof, got {}",
        upstream.targets.len()
    );

    let cache = LoadBalancerCache::new(&result.config);
    assert_eq!(
        cache.get_hash_on_strategy(&upstream.namespace, &upstream.id),
        HashOnStrategy::Cookie(cookie_name.to_string())
    );

    // `get_balancer` lives on the inner snapshot, so reach it through the
    // `ArcSwap` load the same way the other load-balancer tests do.
    let lb = cache
        .load()
        .get_balancer(&upstream.namespace, &upstream.id)
        .expect("translated upstream must be in LB cache");

    // The real persistence contract: for EVERY target the initial response
    // could have been served by, the cookie the gateway would emit must resolve
    // back to that same target. Determinism of the ring below is a weaker,
    // separate property.
    let cookie_config = upstream
        .hash_on_cookie_config
        .clone()
        .expect("cookie config projected");
    for target in &upstream.targets {
        let header = ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
            cookie_name,
            &upstream.namespace,
            &upstream.id,
            target,
            &cookie_config,
        );
        let token = set_cookie_value(&header, cookie_name);
        // Opaque: a fixed-width lowercase hex digest that cannot contain the
        // backend address (target hosts carry `.` / `:`, which hex cannot).
        assert!(
            ferrum_edge::load_balancer::is_sticky_session_token(&token),
            "token must be an opaque hex digest: {token}"
        );
        assert!(
            !token.contains(&target.host),
            "token must not disclose backend topology: {token}"
        );
        for _ in 0..5 {
            let bound = lb
                .select_sticky(&token, None, None, None)
                .expect("emitted token must resolve to its backend");
            assert_eq!(bound.host, target.host);
            assert_eq!(bound.port, target.port);
        }
    }

    // Fallback ring: an UNBOUND opaque value still hashes deterministically so
    // an unbound client is not reshuffled request to request. This is the
    // fallback path, not session persistence.
    let first = lb
        .select("cookie-value-abc", None)
        .expect("selection succeeds");
    for _ in 0..50 {
        let next = lb
            .select("cookie-value-abc", None)
            .expect("selection succeeds");
        assert_eq!(next.target.host, first.target.host);
        assert_eq!(next.target.port, first.target.port);
    }

    // A different cookie value must be able to land on a different pod
    // (otherwise the "sticky" assertion above is vacuously true).
    let mut other_hosts = std::collections::HashSet::new();
    for i in 0..40 {
        let key = format!("other-cookie-{i}");
        let sel = lb.select(&key, None).expect("selection succeeds");
        other_hosts.insert(sel.target.host.clone());
    }
    assert!(
        other_hosts.len() > 1,
        "diverse cookie keys should spread across endpoints, got {other_hosts:?}"
    );
}

#[test]
fn sticky_session_cookie_omits_max_age_on_set_cookie() {
    let target = UpstreamTarget {
        host: "10.1.0.10".into(),
        port: 8080,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
        service_port_policy_key: None,
    };
    let session = HashOnCookieConfig {
        session_cookie: true,
        ttl_seconds: 3600,
        ..HashOnCookieConfig::default()
    };
    let header = ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        "lb-affinity",
        &ferrum_edge::config::types::default_namespace(),
        "u1",
        &target,
        &session,
    );
    assert!(
        header.starts_with("lb-affinity="),
        "cookie name must be present: {header}"
    );
    assert!(
        !header.contains("Max-Age="),
        "Session lifetimeType must omit Max-Age: {header}"
    );
    assert!(header.contains("Path=/"));
    assert!(header.contains("HttpOnly"));

    let permanent = HashOnCookieConfig {
        session_cookie: false,
        ttl_seconds: 7200,
        ..HashOnCookieConfig::default()
    };
    let permanent_header = ferrum_edge::_test_support::build_sticky_cookie_header_for_test(
        "lb-affinity",
        &ferrum_edge::config::types::default_namespace(),
        "u1",
        &target,
        &permanent,
    );
    assert!(
        permanent_header.contains("Max-Age=7200"),
        "Permanent cookies must set Max-Age: {permanent_header}"
    );

    // Translated Upstream shape must still pass field validation.
    let upstream = Upstream {
        id: "u1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("u1".into()),
        targets: vec![target],
        algorithm: LoadBalancerAlgorithm::ConsistentHashing,
        hash_on: Some("cookie:lb-affinity".into()),
        hash_on_cookie_config: Some(session),
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: HashMap::new(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    };
    assert!(upstream.validate_fields().is_ok());
}

/// Gateway API `PolicyStatus.ancestors` MaxItems=16.
const POLICY_ANCESTOR_MAX_ITEMS: usize = 16;

fn http_route_to_service(service: &str) -> K8sObject {
    object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        "sample",
        json!({
            "hostnames": ["api.example.com"],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/api"}}],
                "backendRefs": [{"name": service, "port": 8080}]
            }]
        }),
    )
}

fn sticky_cookie_policy(kind: &str, api_version: &str) -> K8sObject {
    object(
        kind,
        api_version,
        "sticky",
        json!({
            "targetRefs": [{"group": "", "kind": "Service", "name": "api"}],
            "sessionPersistence": {"type": "Cookie", "sessionName": "lb-affinity"}
        }),
    )
}

/// Sixteen ancestors owned by other controllers — the CRD MaxItems ceiling.
fn full_foreign_ancestors() -> Value {
    Value::Array(
        (0..POLICY_ANCESTOR_MAX_ITEMS)
            .map(|index| {
                json!({
                    "ancestorRef": {
                        "group": "",
                        "kind": "Service",
                        "name": format!("foreign-{index}"),
                        "namespace": "default"
                    },
                    "controllerName": format!("example.com/controller-{index}"),
                    "conditions": []
                })
            })
            .collect(),
    )
}

fn policy_status_update(
    objects: &[K8sObject],
    kind: &str,
    name: &str,
) -> Option<GatewayApiStatusUpdate> {
    let translated = translate_k8s_objects(objects, options()).expect("translate");
    plan_gateway_api_status_updates(objects, options(), &translated.route_conflicts)
        .into_iter()
        .find(|update| update.kind == kind && update.name == name)
}

fn ferrum_ancestors(update: &GatewayApiStatusUpdate) -> Vec<&Value> {
    update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|ancestor| {
            ancestor.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        })
        .collect()
}

/// A live status already carrying sixteen third-party ancestors leaves Ferrum
/// no representable slot. Gateway API forbids adding a seventeenth entry, so
/// Ferrum writes nothing — but third-party status must not suppress
/// session-persistence translation or mark the valid policy rejected.
fn assert_full_foreign_ancestors_apply_without_ferrum_status_write(
    mut policy: K8sObject,
    kind: &str,
) {
    policy.status = json!({ "ancestors": full_foreign_ancestors() });
    let objects = vec![policy, http_route_to_service("api")];

    let translated = translate_k8s_objects(&objects, options())
        .expect("a full foreign ancestor map must not suppress session-persistence translation");
    assert_eq!(translated.config.upstreams.len(), 1);
    assert!(
        translated.config.upstreams[0]
            .hash_on
            .as_deref()
            .is_some_and(|value| value.starts_with("cookie:lb-affinity-fe-")),
        "session persistence must still reach the data plane: {:?}",
        translated.config.upstreams[0].hash_on
    );
    assert!(
        translated
            .warnings
            .iter()
            .all(|warning| !warning.contains("status.ancestors")),
        "a status reporting gap must not mark the valid policy rejected: {:?}",
        translated.warnings
    );

    match policy_status_update(&objects, kind, "sticky") {
        None => {
            // Desired status equals the live full-foreign map — no patch.
        }
        Some(update) => {
            let ancestors = update
                .status
                .get("ancestors")
                .and_then(Value::as_array)
                .expect("status.ancestors");
            assert_eq!(
                ancestors.len(),
                POLICY_ANCESTOR_MAX_ITEMS,
                "Ferrum must never write a seventeenth status ancestor"
            );
            assert!(
                ferrum_ancestors(&update).is_empty(),
                "a full foreign ancestor map must leave Ferrum with no status slot: {update:?}"
            );
            assert!(
                ancestors.iter().all(|entry| {
                    entry["controllerName"]
                        .as_str()
                        .is_some_and(|name| name.starts_with("example.com/controller-"))
                }),
                "Ferrum must not evict foreign status entries"
            );
        }
    }
}

#[test]
fn backend_lb_policy_full_foreign_ancestors_applies_and_writes_no_ferrum_status() {
    assert_full_foreign_ancestors_apply_without_ferrum_status_write(
        sticky_cookie_policy("BackendLBPolicy", "gateway.networking.k8s.io/v1alpha2"),
        "BackendLBPolicy",
    );
}

#[test]
fn x_backend_traffic_policy_full_foreign_ancestors_applies_and_writes_no_ferrum_status() {
    assert_full_foreign_ancestors_apply_without_ferrum_status_write(
        sticky_cookie_policy(
            "XBackendTrafficPolicy",
            "gateway.networking.x-k8s.io/v1alpha1",
        ),
        "XBackendTrafficPolicy",
    );
}

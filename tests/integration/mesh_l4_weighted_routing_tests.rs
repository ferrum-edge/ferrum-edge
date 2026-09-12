//! VirtualService `tcp[]`/`tls[]` weighted multi-destination routing (issue #3251).

use std::collections::HashMap;

use ferrum_edge::config::types::{
    LoadBalancerAlgorithm, UPSTREAM_TARGET_SERVICE_NAME_TAG, UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG,
    UPSTREAM_TARGET_SERVICE_PORT_TAG,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::health_check::ActiveUnhealthyTargets;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::load_balancer::{HealthContext, LoadBalancerCache, target_key};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use serde_json::Value;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, name: &str, namespace: &str, api_version: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn vs(name: &str, spec: Value) -> K8sObject {
    object(
        "VirtualService",
        name,
        "default",
        "networking.istio.io/v1beta1",
        spec,
    )
}

#[test]
fn virtual_service_tcp_weighted_split_uses_generated_upstream_weights() {
    let result = translate_k8s_objects(
        &[vs(
            "db-split",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "mysql-v1.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 900},
                        {"destination": {"host": "mysql-v2.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 90},
                        {"destination": {"host": "mysql-v3.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 10}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(3306))
        .expect("tcp proxy");
    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|upstream| proxy.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("weighted L4 upstream");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::WeightedRoundRobin
    );
    assert_eq!(
        upstream
            .targets
            .iter()
            .map(|t| t.weight)
            .collect::<Vec<_>>(),
        vec![900, 90, 10]
    );

    let lb = LoadBalancerCache::new(&result.config);
    let mut counts: HashMap<String, usize> = HashMap::new();
    for i in 0..1000 {
        let target = lb
            .select_target("default", &upstream.id, &i.to_string(), None)
            .expect("target")
            .target;
        *counts.entry(target.host.clone()).or_default() += 1;
    }
    assert_eq!(
        counts
            .get("mysql-v1.default.svc.cluster.local")
            .copied()
            .unwrap_or_default(),
        900
    );
    assert_eq!(
        counts
            .get("mysql-v2.default.svc.cluster.local")
            .copied()
            .unwrap_or_default(),
        90
    );
    assert_eq!(
        counts
            .get("mysql-v3.default.svc.cluster.local")
            .copied()
            .unwrap_or_default(),
        10
    );
}

#[test]
fn virtual_service_tcp_weighted_split_skips_zero_weight_and_fails_closed_on_invalid() {
    let skipped = translate_k8s_objects(
        &[vs(
            "db-skip-zero",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "dark.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0},
                        {"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 100}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("zero-weight leg is skipped");
    let proxy = skipped
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(3306))
        .expect("one positive-weight destination remains");
    assert_eq!(proxy.backend_host, "stable.default.svc.cluster.local");
    assert_eq!(
        proxy.upstream_id, None,
        "one remaining leg needs no upstream"
    );
    assert!(
        skipped.config.upstreams.is_empty(),
        "a split collapsed to one active destination must not leave an orphan upstream"
    );
    assert!(
        skipped
            .warnings
            .iter()
            .any(|warning| warning.contains("zero-weight split destination"))
    );

    let all_zero = translate_k8s_objects(
        &[vs(
            "db-all-zero",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0},
                        {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("all-zero split remains traffic-capturing");
    let all_zero_proxy = all_zero
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(3306))
        .expect("all-zero tcp[] block must still materialize on match.port");
    assert_eq!(
        all_zero_proxy.backend_host, "ferrum-zero-weight.invalid.",
        "all-zero split must fail closed to the reserved blackhole host"
    );
    assert_eq!(
        all_zero_proxy.backend_port, 3306,
        "blackhole backend port must retain the destination port for listen inference"
    );
    assert!(
        all_zero_proxy.upstream_id.is_none(),
        "agreeing all-zero destinations collapse to a direct blackhole binding"
    );
    assert!(
        all_zero.warnings.iter().any(|warning| {
            warning.contains("only zero-weight") && warning.contains("blackhole")
        })
    );

    let invalid = translate_k8s_objects(
        &[vs(
            "db-bad-weight",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 70000},
                        {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 1}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect_err("weight above MAX_TARGET_WEIGHT fails closed");
    assert!(
        format!("{invalid:?}").contains("weight must be between 0 and"),
        "{invalid:?}"
    );

    let subset = translate_k8s_objects(
        &[vs(
            "db-subset",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}, "subset": "v1"}, "weight": 80},
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}, "subset": "v2"}, "weight": 20}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect_err("destination.subset is unrepresentable for L4 weighted routes");
    assert!(
        format!("{subset:?}").contains("destination.subset is not supported"),
        "{subset:?}"
    );

    let zero_weight_subset = translate_k8s_objects(
        &[vs(
            "db-zero-weight-subset",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}, "subset": "v1"}, "weight": 0},
                        {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 100}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect_err("a zero-weight leg must not bypass destination validation");
    assert!(
        format!("{zero_weight_subset:?}").contains("destination.subset is not supported"),
        "{zero_weight_subset:?}"
    );
}

#[test]
fn virtual_service_tcp_weighted_split_failover_skips_unhealthy_target() {
    let result = translate_k8s_objects(
        &[vs(
            "db-failover",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": [
                        {"destination": {"host": "mysql-v1.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 50},
                        {"destination": {"host": "mysql-v2.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 50}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");
    let upstream = &result.config.upstreams[0];
    let unhealthy = &upstream.targets[0];
    let lb = LoadBalancerCache::new(&result.config);
    let namespaced_id =
        ferrum_edge::config::db_backend::namespaced_runtime_key("default", &upstream.id);
    let active_unhealthy = ActiveUnhealthyTargets::new();
    active_unhealthy.insert(target_key(&namespaced_id, unhealthy), 1u64);
    let health = HealthContext {
        active_unhealthy: &active_unhealthy,
        proxy_passive: None,
        max_ejection_percent: None,
    };

    let mut counts: HashMap<String, usize> = HashMap::new();
    for i in 0..40 {
        let target = lb
            .select_target("default", &upstream.id, &i.to_string(), Some(&health))
            .expect("healthy target")
            .target;
        *counts.entry(target.host.clone()).or_default() += 1;
    }
    assert_eq!(
        counts
            .get("mysql-v1.default.svc.cluster.local")
            .copied()
            .unwrap_or_default(),
        0,
        "unhealthy destination must receive no selections: {counts:?}"
    );
    assert_eq!(
        counts
            .get("mysql-v2.default.svc.cluster.local")
            .copied()
            .unwrap_or_default(),
        40
    );
}

#[test]
fn virtual_service_tcp_weighted_split_reload_and_delete_update_slice_upstreams() {
    let initial = translate_k8s_objects(
        &[vs(
            "db-live",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306, "gateways": ["mesh"]}],
                    "route": [
                        {"destination": {"host": "mysql-v1.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 70},
                        {"destination": {"host": "mysql-v2.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 30}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("initial translate");
    let initial_slice = MeshSlice::from_gateway_config(
        &initial.config,
        MeshSliceRequest {
            node_id: "sidecar-a".to_string(),
            namespace: "default".to_string(),
            ..MeshSliceRequest::default()
        },
    );
    assert_eq!(initial_slice.virtual_service_l4_proxies.len(), 1);
    assert_eq!(initial_slice.virtual_service_l4_upstreams.len(), 1);
    assert_eq!(
        initial_slice.virtual_service_l4_upstreams[0]["targets"][0]["weight"],
        70
    );

    let updated = translate_k8s_objects(
        &[vs(
            "db-live",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306, "gateways": ["mesh"]}],
                    "route": [
                        {"destination": {"host": "mysql-v1.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 20},
                        {"destination": {"host": "mysql-v2.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 80}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("updated translate");
    let updated_slice = MeshSlice::from_gateway_config(
        &updated.config,
        MeshSliceRequest {
            node_id: "sidecar-a".to_string(),
            namespace: "default".to_string(),
            ..MeshSliceRequest::default()
        },
    );
    assert!(
        !initial_slice.content_eq(&updated_slice),
        "weight change must invalidate slice content equality"
    );
    assert_eq!(
        updated_slice.virtual_service_l4_upstreams[0]["targets"][0]["weight"],
        20
    );
    assert_eq!(
        updated_slice.virtual_service_l4_upstreams[0]["targets"][1]["weight"],
        80
    );

    let deleted = translate_k8s_objects(&[], options()).expect("delete translate");
    let deleted_slice = MeshSlice::from_gateway_config(
        &deleted.config,
        MeshSliceRequest {
            node_id: "sidecar-a".to_string(),
            namespace: "default".to_string(),
            ..MeshSliceRequest::default()
        },
    );
    assert!(deleted_slice.virtual_service_l4_proxies.is_empty());
    assert!(deleted_slice.virtual_service_l4_upstreams.is_empty());
}

#[test]
fn virtual_service_tls_weighted_split_preserves_passthrough_and_service_identity_tags() {
    let result = translate_k8s_objects(
        &[
            object(
                "Service",
                "secure-v1",
                "default",
                "v1",
                serde_json::json!({
                    "ports": [{"name": "https", "port": 443}]
                }),
            ),
            object(
                "Service",
                "secure-v2",
                "default",
                "v1",
                serde_json::json!({
                    "ports": [{"name": "https", "port": 443}]
                }),
            ),
            vs(
                "secure-split",
                serde_json::json!({
                    "hosts": ["secure.example.com"],
                    "tls": [{
                        "match": [{"sniHosts": ["secure.example.com"], "port": 443}],
                        "route": [
                            {"destination": {"host": "secure-v1", "port": {"number": 443}}, "weight": 60},
                            {"destination": {"host": "secure-v2", "port": {"number": 443}}, "weight": 40}
                        ]
                    }]
                }),
            ),
        ],
        options(),
    )
    .expect("weighted tls[] translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(443))
        .expect("tls proxy");
    assert!(proxy.passthrough);
    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|upstream| proxy.upstream_id.as_deref() == Some(upstream.id.as_str()))
        .expect("tls weighted upstream");
    assert_eq!(upstream.targets.len(), 2);
    for target in &upstream.targets {
        assert_eq!(
            target
                .tags
                .get(UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG)
                .map(String::as_str),
            Some("default")
        );
        assert!(
            target.tags.contains_key(UPSTREAM_TARGET_SERVICE_NAME_TAG),
            "service name tag missing: {target:?}"
        );
        assert_eq!(
            target
                .tags
                .get(UPSTREAM_TARGET_SERVICE_PORT_TAG)
                .map(String::as_str),
            Some("443")
        );
    }
}

#[test]
fn virtual_service_tcp_all_zero_weight_remains_fail_closed_and_does_not_fall_through() {
    // An earlier all-zero block must still own the match; dropping it would let
    // the later positive-weight block capture the same port.
    let result = translate_k8s_objects(
        &[vs(
            "db-all-zero-order",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [
                    {
                        "match": [{"port": 3306}],
                        "route": [
                            {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0},
                            {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0}
                        ]
                    },
                    {
                        "match": [{"port": 3306}],
                        "route": [
                            {"destination": {"host": "stable.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 100}
                        ]
                    }
                ]
            }),
        )],
        options(),
    )
    .expect("ordered tcp[] with leading all-zero translates");
    let on_port: Vec<_> = result
        .config
        .proxies
        .iter()
        .filter(|proxy| proxy.listen_port == Some(3306))
        .collect();
    assert_eq!(
        on_port.len(),
        2,
        "both tcp[] blocks must materialize: {on_port:?}"
    );
    assert!(
        on_port
            .iter()
            .any(|proxy| proxy.backend_host == "ferrum-zero-weight.invalid."),
        "first (all-zero) block must remain present as blackhole, not disappear: {on_port:?}"
    );
    assert!(
        on_port
            .iter()
            .any(|proxy| proxy.backend_host == "stable.default.svc.cluster.local"),
        "later positive-weight block must still exist alongside the blackhole: {on_port:?}"
    );
    let blackhole = on_port
        .iter()
        .find(|proxy| proxy.backend_host == "ferrum-zero-weight.invalid.")
        .expect("blackhole");
    assert!(
        blackhole.id.contains("__0-"),
        "all-zero block must keep declaration-order proxy id, got {}",
        blackhole.id
    );
}

#[test]
fn virtual_service_tls_all_zero_weight_remains_fail_closed_blackhole() {
    let result = translate_k8s_objects(
        &[vs(
            "secure-all-zero",
            serde_json::json!({
                "hosts": ["secure.example.com"],
                "tls": [{
                    "match": [{"sniHosts": ["secure.example.com"], "port": 443}],
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 443}}, "weight": 0},
                        {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 443}}, "weight": 0}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("all-zero tls[] remains traffic-capturing");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(443))
        .expect("all-zero tls[] block must still materialize");
    assert!(proxy.passthrough);
    assert_eq!(proxy.backend_host, "ferrum-zero-weight.invalid.");
    assert_eq!(proxy.backend_port, 443);
    assert_eq!(proxy.hosts, vec!["secure.example.com".to_string()]);
    assert!(
        result.warnings.iter().any(|warning| {
            warning.contains("only zero-weight") && warning.contains("blackhole")
        })
    );
}

#[test]
fn virtual_service_tcp_all_zero_without_match_port_keeps_destination_listen_port() {
    // Omitted match.port must infer listen from destination ports, not from a
    // sentinel blackhole port like Gateway API's 65535.
    let result = translate_k8s_objects(
        &[vs(
            "db-all-zero-inferred-port",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "route": [
                        {"destination": {"host": "a.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0},
                        {"destination": {"host": "b.default.svc.cluster.local", "port": {"number": 3306}}, "weight": 0}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("all-zero without match.port still translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.backend_host == "ferrum-zero-weight.invalid.")
        .expect("blackhole proxy");
    assert_eq!(
        proxy.listen_port,
        Some(3306),
        "listen port must follow destination agreement, not a sentinel"
    );
    assert_eq!(proxy.backend_port, 3306);
}

#[test]
fn virtual_service_l4_route_rejects_more_than_max_targets_per_upstream() {
    let routes: Vec<Value> = (0..=ferrum_edge::config::types::MAX_TARGETS_PER_UPSTREAM)
        .map(|i| {
            serde_json::json!({
                "destination": {
                    "host": format!("mysql-{i}.default.svc.cluster.local"),
                    "port": {"number": 3306}
                },
                "weight": 1
            })
        })
        .collect();
    assert_eq!(
        routes.len(),
        ferrum_edge::config::types::MAX_TARGETS_PER_UPSTREAM + 1
    );
    let err = translate_k8s_objects(
        &[vs(
            "db-too-many",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "tcp": [{
                    "match": [{"port": 3306}],
                    "route": routes
                }]
            }),
        )],
        options(),
    )
    .expect_err("MAX_TARGETS_PER_UPSTREAM + 1 destinations must fail closed");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("VirtualService tcp[].route")
            && msg.contains("at most")
            && msg.contains(&ferrum_edge::config::types::MAX_TARGETS_PER_UPSTREAM.to_string()),
        "{msg}"
    );
}

#[test]
fn virtual_service_tcp_weighted_export_projects_upstream_into_consumer_namespace() {
    let result = translate_k8s_objects(
        &[vs(
            "db-export",
            serde_json::json!({
                "hosts": ["db.example.com"],
                "exportTo": ["consumer"],
                "tcp": [{
                    "match": [{"port": 3306, "gateways": ["mesh"]}],
                    "route": [
                        {"destination": {"host": "mysql-v1", "port": {"number": 3306}}, "weight": 50},
                        {"destination": {"host": "mysql-v2", "port": {"number": 3306}}, "weight": 50}
                    ]
                }]
            }),
        )],
        options(),
    )
    .expect("exportTo weighted L4 translates");
    let proxy = result
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_port == Some(3306))
        .expect("projected proxy");
    assert_eq!(proxy.namespace, "consumer");
    let upstream = result
        .config
        .upstreams
        .iter()
        .find(|upstream| {
            upstream.namespace == "consumer"
                && proxy.upstream_id.as_deref() == Some(upstream.id.as_str())
        })
        .expect("projected upstream must share the consumer namespace for LB lookup");
    assert_eq!(upstream.targets.len(), 2);
}

/// Namespace `team-a` + name `db` and namespace `team` + name `a-db` join to
/// the same `namespace-name` string, so a `-`-delimited generated id derives
/// ONE upstream id for two unrelated VirtualServices. Both export into
/// `consumer`, where projected upstreams are keyed by (namespace, id) — a
/// collision therefore lets one tenant's VirtualService silently REPLACE the
/// other tenant's L4 destination.
///
/// The two resources are otherwise fully independent (distinct hosts, distinct
/// listen ports), so the generated-id derivation is the only thing under test.
#[test]
fn virtual_service_l4_exported_upstream_ids_preserve_source_boundaries() {
    let weighted_spec = |host: &str, port: u16, backend: &str| {
        serde_json::json!({
            "hosts": [host],
            "exportTo": ["consumer"],
            "tcp": [{
                "match": [{"port": port, "gateways": ["mesh"]}],
                "route": [
                    {"destination": {"host": backend, "port": {"number": port}}, "weight": 50},
                    {"destination": {"host": format!("backup-{backend}"), "port": {"number": port}}, "weight": 50}
                ]
            }]
        })
    };
    let result = translate_k8s_objects(
        &[
            object(
                "VirtualService",
                "db",
                "team-a",
                "networking.istio.io/v1beta1",
                weighted_spec("victim.example.com", 3306, "victim.example.internal"),
            ),
            object(
                "VirtualService",
                "a-db",
                "team",
                "networking.istio.io/v1beta1",
                weighted_spec("attacker.example.com", 3307, "attacker.example.internal"),
            ),
        ],
        // The shared `options()` helper scopes translation to `default`; these
        // fixtures deliberately live in two other namespaces, and an
        // out-of-scope object is dropped before it ever reaches translation.
        options().with_source_namespaces(vec!["team-a".to_string(), "team".to_string()]),
    )
    .expect("colliding hyphenated source names translate safely");

    let upstreams: Vec<_> = result
        .config
        .upstreams
        .iter()
        .filter(|upstream| upstream.namespace == "consumer")
        .collect();
    assert_eq!(upstreams.len(), 2, "neither projected upstream is replaced");
    assert_ne!(upstreams[0].id, upstreams[1].id);
    for upstream in &upstreams {
        assert!(
            upstream.id.starts_with("istio-vs-l4-upstream-"),
            "generated id must keep the prefix listed in \
             K8S_MANAGED_UPSTREAM_ID_PREFIXES so reconcile withdraws it, got {}",
            upstream.id
        );
        ferrum_edge::config::types::validate_resource_id(&upstream.id)
            .expect("generated upstream id must satisfy resource-id admission");
    }

    let proxies: Vec<_> = result
        .config
        .proxies
        .iter()
        .filter(|proxy| proxy.namespace == "consumer" && proxy.upstream_id.is_some())
        .collect();
    assert_eq!(proxies.len(), 2, "both exported routes remain materialized");

    // Each projected proxy must still reach its OWN source VirtualService's
    // destinations. Under a shared id both proxies resolve to whichever
    // upstream was written last — the cross-tenant takeover.
    for (listen_port, backend) in [
        (3306u16, "victim.example.internal"),
        (3307, "attacker.example.internal"),
    ] {
        let proxy = proxies
            .iter()
            .find(|proxy| proxy.listen_port == Some(listen_port))
            .expect("projected proxy for the exported listen port");
        let upstream_id = proxy
            .upstream_id
            .as_deref()
            .expect("weighted proxy references an upstream");
        let upstream = upstreams
            .iter()
            .find(|upstream| upstream.id == upstream_id)
            .expect("each proxy keeps its own projected upstream");
        let hosts: Vec<&str> = upstream.targets.iter().map(|t| t.host.as_str()).collect();
        let backup = format!("backup-{backend}");
        assert_eq!(
            hosts,
            vec![backend, backup.as_str()],
            "projected upstream must keep its own source's destinations"
        );
    }
}

//! External tests for VirtualService L4 `Proxy.stream_match` predicates.

use ferrum_edge::proxy::stream_match::{
    CompiledStreamMatch, StreamMatchArm, StreamMatchCriteria, StreamMatchEvidence,
    canonicalize_gateway_name, resolve_shared_stream_proxy_in_epoch, source_namespace_from_spiffe,
    trustworthy_source_labels, validate_canonical_gateway_ref,
};
use std::collections::BTreeMap;
use std::net::IpAddr;

fn workload(
    address: &str,
    labels: serde_json::Value,
) -> ferrum_edge::modes::mesh::config::Workload {
    serde_json::from_value(serde_json::json!({
        "spiffe_id": "spiffe://cluster.local/ns/prod/sa/client",
        "selector": {"labels": labels},
        "service_name": "client",
        "addresses": [address],
        "trust_domain": "cluster.local",
        "namespace": "prod"
    }))
    .unwrap()
}

fn passthrough_proxy_with_hosts(
    id: &str,
    hosts: &[&str],
    criteria: StreamMatchCriteria,
) -> ferrum_edge::config::types::Proxy {
    let mut proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": "default",
        "hosts": hosts,
        "backend_scheme": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": 9443,
        "listen_port": 8443,
        "passthrough": true,
        "stream_match": criteria
    }))
    .unwrap();
    proxy.normalize_fields();
    proxy
}

fn passthrough_proxy(id: &str, criteria: StreamMatchCriteria) -> ferrum_edge::config::types::Proxy {
    passthrough_proxy_with_hosts(id, &["secure.example.com"], criteria)
}

fn epoch_for(
    proxies: Vec<ferrum_edge::config::types::Proxy>,
) -> ferrum_edge::request_epoch::RequestEpochStore {
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::consumer_index::ConsumerIndex;
    use ferrum_edge::load_balancer::LoadBalancerCache;
    use ferrum_edge::plugin_cache::PluginCache;

    let config = GatewayConfig {
        proxies,
        ..Default::default()
    };
    let plugin_cache = PluginCache::new(&config).unwrap();
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let load_balancer = LoadBalancerCache::new(&config);
    ferrum_edge::request_epoch::RequestEpochStore::from_runtime_parts(
        config,
        &plugin_cache,
        &consumer_index,
        &load_balancer,
    )
}

#[test]
fn stream_match_criteria_round_trips_through_json() {
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app".into(), "billing".into())]),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.1.0/24".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let json = serde_json::to_value(&criteria).expect("serialize");
    let back: StreamMatchCriteria = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back, criteria);
    let compiled: CompiledStreamMatch = back.compile().expect("compile");
    assert!(!compiled.is_empty());
}

#[test]
fn missing_evidence_denies_each_predicate() {
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app".into(), "billing".into())]),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.0.0/16".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let compiled = criteria.compile().unwrap();
    assert!(!compiled.matches(&StreamMatchEvidence::default()));
}

#[test]
fn combined_predicates_require_all_evidence() {
    let mut labels = BTreeMap::new();
    labels.insert("app".into(), "billing".into());
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: labels.clone(),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.0.0/16".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let compiled = criteria.compile().unwrap();
    let evidence = StreamMatchEvidence {
        source_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
        destination_ip: Some("192.168.1.9".parse::<IpAddr>().unwrap()),
        source_namespace: Some("prod"),
        source_labels: Some(&labels),
        trusted_gateway_ref: Some("mesh"),
    };
    assert!(compiled.matches(&evidence));
}

#[test]
fn gateway_canonicalize_and_validate_binding() {
    assert_eq!(
        canonicalize_gateway_name("ingress", "bookinfo").unwrap(),
        "bookinfo/ingress"
    );
    assert!(validate_canonical_gateway_ref("mesh").is_ok());
    assert!(validate_canonical_gateway_ref("bookinfo/ingress").is_ok());
    assert!(validate_canonical_gateway_ref("ingress").is_err());
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/sa/web").as_deref(),
        Some("prod")
    );
}

#[test]
fn shared_spiffe_divergent_labels_fail_closed_without_exact_evidence() {
    let workloads = vec![
        workload("10.0.0.1", serde_json::json!({"app": "billing"})),
        workload("10.0.0.2", serde_json::json!({"app": "reporting"})),
    ];
    assert!(
        trustworthy_source_labels(
            &workloads,
            "spiffe://cluster.local/ns/prod/sa/client",
            None,
            None,
        )
        .is_none()
    );
}

#[test]
fn canonical_source_ip_selects_exact_shared_spiffe_workload() {
    let workloads = vec![
        workload("10.0.0.1", serde_json::json!({"app": "billing"})),
        workload("10.0.0.2", serde_json::json!({"app": "reporting"})),
    ];
    let labels = trustworthy_source_labels(
        &workloads,
        "spiffe://cluster.local/ns/prod/sa/client",
        Some("::ffff:10.0.0.2".parse().unwrap()),
        None,
    )
    .unwrap();
    assert_eq!(labels.get("app").map(String::as_str), Some("reporting"));
}

#[test]
fn identical_shared_spiffe_replica_labels_are_safe_evidence() {
    let workloads = vec![
        workload("10.0.0.1", serde_json::json!({"app": "billing"})),
        workload("10.0.0.2", serde_json::json!({"app": "billing"})),
    ];
    let labels = trustworthy_source_labels(
        &workloads,
        "spiffe://cluster.local/ns/prod/sa/client",
        None,
        None,
    )
    .unwrap();
    assert_eq!(labels.get("app").map(String::as_str), Some("billing"));
}

#[test]
fn exact_node_waypoint_scope_overrides_shared_spiffe_ambiguity() {
    use ferrum_edge::identity::spiffe::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
    use std::collections::HashMap;

    let workloads = vec![
        workload("10.0.0.1", serde_json::json!({"app": "billing"})),
        workload("10.0.0.2", serde_json::json!({"app": "reporting"})),
    ];
    let scope = PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/prod/sa/client").unwrap(),
        "prod",
        HashMap::from([("app".to_string(), "reporting".to_string())]),
    );
    let labels = trustworthy_source_labels(
        &workloads,
        "spiffe://cluster.local/ns/prod/sa/client",
        None,
        Some(&scope),
    )
    .unwrap();
    assert_eq!(labels.get("app").map(String::as_str), Some("reporting"));
}

#[test]
fn passthrough_same_sni_uses_semantic_candidate_order_with_double_digits() {
    use ferrum_edge::config::db_backend::NamespacedResourceId;

    let match_two = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_subnets: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        }],
    };
    let match_ten = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_subnets: vec!["127.0.0.1/32".to_string()],
            ..Default::default()
        }],
    };
    let epoch_store = epoch_for(vec![
        passthrough_proxy("route-match-2", match_two),
        passthrough_proxy("route-match-10", match_ten),
    ]);
    let epoch = epoch_store.load();
    let candidates = vec![
        NamespacedResourceId::new("default".to_string(), "route-match-2".to_string()),
        NamespacedResourceId::new("default".to_string(), "route-match-10".to_string()),
    ];
    let evidence = StreamMatchEvidence {
        source_ip: Some("127.0.0.1".parse().unwrap()),
        ..Default::default()
    };
    let selected = resolve_shared_stream_proxy_in_epoch(
        Some("secure.example.com"),
        &candidates,
        &evidence,
        &epoch,
        true,
    )
    .unwrap();
    assert_eq!(selected.id, "route-match-2");
}

#[test]
fn virtual_service_tls_order_precedes_generic_sni_specificity() {
    use ferrum_edge::config::db_backend::NamespacedResourceId;

    let criteria = || StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            gateways: vec!["mesh".to_string()],
            ..Default::default()
        }],
    };
    let epoch_store = epoch_for(vec![
        passthrough_proxy_with_hosts("earlier-wildcard", &["*.example.com"], criteria()),
        passthrough_proxy_with_hosts("later-exact", &["secure.example.com"], criteria()),
    ]);
    let epoch = epoch_store.load();
    let candidates = vec![
        NamespacedResourceId::new("default".to_string(), "earlier-wildcard".to_string()),
        NamespacedResourceId::new("default".to_string(), "later-exact".to_string()),
    ];
    let selected = resolve_shared_stream_proxy_in_epoch(
        Some("secure.example.com"),
        &candidates,
        &StreamMatchEvidence {
            trusted_gateway_ref: Some("mesh"),
            ..Default::default()
        },
        &epoch,
        true,
    )
    .unwrap();
    assert_eq!(selected.id, "earlier-wildcard");
}

#[test]
fn source_namespace_requires_canonical_unambiguous_istio_spiffe_path() {
    for account in ["backend", "frontend", "sa"] {
        assert_eq!(
            source_namespace_from_spiffe(&format!("spiffe://cluster.local/ns/sa/sa/{account}"))
                .as_deref(),
            Some("sa")
        );
    }
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/sa/client").as_deref(),
        Some("prod")
    );
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/prefix/ns/prod/sa/client"),
        None
    );
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/ns/other/sa/client"),
        None
    );
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/workload/client"),
        None
    );
}

#[test]
fn configured_but_uncompiled_passthrough_matcher_fails_closed() {
    use ferrum_edge::config::db_backend::NamespacedResourceId;

    let invalid = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_subnets: vec!["not-a-cidr".to_string()],
            ..Default::default()
        }],
    };
    let epoch_store = epoch_for(vec![
        passthrough_proxy("invalid", invalid),
        passthrough_proxy("fallback", StreamMatchCriteria::default()),
    ]);
    let epoch = epoch_store.load();
    let candidates = vec![
        NamespacedResourceId::new("default".to_string(), "invalid".to_string()),
        NamespacedResourceId::new("default".to_string(), "fallback".to_string()),
    ];
    assert!(
        resolve_shared_stream_proxy_in_epoch(
            Some("secure.example.com"),
            &candidates,
            &StreamMatchEvidence {
                source_ip: Some("127.0.0.1".parse().unwrap()),
                ..Default::default()
            },
            &epoch,
            true,
        )
        .is_none()
    );
}

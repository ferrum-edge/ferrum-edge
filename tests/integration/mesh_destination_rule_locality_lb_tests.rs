//! Integration coverage for
//! `DestinationRule.trafficPolicy.loadBalancer.localityLbSetting` flowing
//! from the Istio K8s translator through `MeshSlice` and onto a resolved
//! `Upstream.locality_lb_setting`. Verifies both the schema projection and
//! the operator-disabled escape hatch.

use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshLocalityLbSetting, OutboundTrafficPolicy};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

fn istio_object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn k8s_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn matching_upstream(id: &str, host_fqdn: &str) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: "default".to_string(),
        name: Some(id.to_string()),
        targets: vec![UpstreamTarget {
            host: host_fqdn.to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: Some("us-west/us-west-1/a".to_string()),
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
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
        created_at: now,
        updated_at: now,
    }
}

fn translate_dr_locality(spec: serde_json::Value) -> (GatewayConfig, MeshLocalityLbSetting) {
    let result = translate_k8s_objects(
        &[istio_object("DestinationRule", "reviews", spec)],
        k8s_options(),
    )
    .expect("translation should succeed");
    let mesh = result.config.mesh.as_ref().expect("mesh present");
    let setting = mesh.destination_rules[0]
        .traffic_policy
        .as_ref()
        .expect("traffic policy")
        .locality_lb_setting
        .clone()
        .expect("localityLbSetting parsed");
    (result.config, setting)
}

#[test]
fn k8s_translator_parses_distribute_entries() {
    let (_, setting) = translate_dr_locality(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "loadBalancer": {
                "localityLbSetting": {
                    "distribute": [
                        {
                            "from": "us-west/us-west-1/a",
                            "to": {
                                "us-west": 80,
                                "us-east": 20
                            }
                        }
                    ]
                }
            }
        }
    }));
    assert!(setting.enabled, "enabled defaults to true when omitted");
    assert_eq!(setting.distribute.len(), 1);
    assert_eq!(setting.distribute[0].from, "us-west/us-west-1/a");
    let mut expected_to = BTreeMap::new();
    expected_to.insert("us-west".to_string(), 80u32);
    expected_to.insert("us-east".to_string(), 20u32);
    assert_eq!(setting.distribute[0].to, expected_to);
    assert!(setting.failover.is_empty());
}

#[test]
fn k8s_translator_parses_failover_entries() {
    let (_, setting) = translate_dr_locality(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "loadBalancer": {
                "localityLbSetting": {
                    "failover": [
                        { "from": "us-west", "to": "us-east" },
                        { "from": "us-east", "to": "us-west" }
                    ]
                }
            }
        }
    }));
    assert_eq!(setting.failover.len(), 2);
    assert_eq!(setting.failover[0].from, "us-west");
    assert_eq!(setting.failover[0].to, "us-east");
    assert!(setting.distribute.is_empty());
}

#[test]
fn k8s_translator_rejects_combined_locality_lb_modes() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "distribute": [{
                            "from": "us-west",
                            "to": { "us-east": 100 }
                        }],
                        "failover": [{ "from": "us-west", "to": "us-east" }]
                    }
                }
            }
        }),
    );
    let err = translate_k8s_objects(&[object], k8s_options())
        .expect_err("combined locality LB modes must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("must set only one of distribute, failover, or failoverPriority"),
        "expected mutually-exclusive locality mode rejection, got: {msg}"
    );
}

#[test]
fn k8s_translator_rejects_unsupported_failover_priority() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failoverPriority": ["topology.kubernetes.io/region"]
                    }
                }
            }
        }),
    );
    let err = translate_k8s_objects(&[object], k8s_options())
        .expect_err("unsupported failoverPriority must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("localityLbSetting.failoverPriority is not supported"),
        "expected failoverPriority unsupported rejection, got: {msg}"
    );
}

#[test]
fn k8s_translator_rejects_distribute_failing_over_to_self() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failover": [{ "from": "us-west", "to": "us-west" }]
                    }
                }
            }
        }),
    );
    let err = translate_k8s_objects(&[object], k8s_options())
        .expect_err("self-failover must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("cannot fail over a region to itself"),
        "expected self-failover rejection, got: {msg}"
    );
}

#[test]
fn k8s_translator_rejects_failover_regions_with_slashes_or_whitespace() {
    for (field, value) in [
        ("from", "us-west/us-west-1"),
        ("to", "us-east/us-east-1"),
        ("from", "us-west/"),
        ("to", "us-east/"),
        ("from", " us-west "),
        ("to", " us-east "),
    ] {
        let object = istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "loadBalancer": {
                        "localityLbSetting": {
                            "failover": [{
                                "from": if field == "from" { value } else { "us-west" },
                                "to": if field == "to" { value } else { "us-east" }
                            }]
                        }
                    }
                }
            }),
        );
        let err = translate_k8s_objects(&[object], k8s_options())
            .expect_err("malformed failover region must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("is not a valid region name"),
            "expected invalid failover-region rejection for {field}={value:?}, got: {msg}"
        );
    }
}

#[test]
fn k8s_translator_rejects_invalid_distribute_from_locality() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "distribute": [
                            { "from": "", "to": { "us-east": 100 } }
                        ]
                    }
                }
            }
        }),
    );
    let err =
        translate_k8s_objects(&[object], k8s_options()).expect_err("empty from must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a valid region"),
        "expected invalid-locality rejection, got: {msg}"
    );
}

#[test]
fn k8s_translator_rejects_malformed_distribute_locality_patterns() {
    for (field, value) in [
        ("from", "us-west/"),
        ("from", "us-west//"),
        ("from", " us-west"),
        ("to", "us-east/"),
        ("to", "us-east//"),
        ("to", "us-east/us-east-1/a/b"),
    ] {
        let to_key = if field == "to" { value } else { "us-east" };
        let mut to = serde_json::Map::new();
        to.insert(to_key.to_string(), serde_json::json!(100));
        let object = istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "loadBalancer": {
                        "localityLbSetting": {
                            "distribute": [{
                                "from": if field == "from" { value } else { "us-west" },
                                "to": serde_json::Value::Object(to)
                            }]
                        }
                    }
                }
            }),
        );
        let err = translate_k8s_objects(&[object], k8s_options())
            .expect_err("malformed distribute locality must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("not a valid region[/zone[/subzone]] locality"),
            "expected invalid distribute-locality rejection for {field}={value:?}, got: {msg}"
        );
    }
}

#[test]
fn k8s_translator_honors_enabled_false() {
    let (_, setting) = translate_dr_locality(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "loadBalancer": {
                "localityLbSetting": {
                    "enabled": false,
                    "distribute": [
                        { "from": "us-west", "to": { "us-east": 100 } }
                    ]
                }
            }
        }
    }));
    assert!(!setting.enabled);
    assert_eq!(setting.distribute.len(), 1);
}

#[test]
fn locality_only_destination_rule_preserves_existing_upstream_algorithm() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failover": [
                            { "from": "us-west", "to": "us-east" }
                        ]
                    }
                }
            }
        }),
    );
    let result = translate_k8s_objects(&[object], k8s_options()).expect("translation");
    let mut config = result.config;
    let mut upstream = matching_upstream("reviews-u", "reviews.default.svc.cluster.local");
    upstream.algorithm = LoadBalancerAlgorithm::LeastConnections;
    config.upstreams.push(upstream);
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh apply");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream projected");

    assert_eq!(upstream.algorithm, LoadBalancerAlgorithm::LeastConnections);
    assert!(
        upstream.locality_lb_setting.is_some(),
        "locality policy should still project without changing LB algorithm"
    );
}

#[test]
fn k8s_translator_accepts_port_level_locality_lb_setting() {
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "portLevelSettings": [
                    {
                        "port": { "number": 8080 },
                        "loadBalancer": {
                            "localityLbSetting": {
                                "failover": [
                                    { "from": "us-west", "to": "us-east" }
                                ]
                            }
                        }
                    }
                ]
            }
        }),
    );
    let result =
        translate_k8s_objects(&[object], k8s_options()).expect("port-level locality must parse");
    let mesh = result.config.mesh.as_ref().expect("mesh present");
    let rule = mesh
        .destination_rules
        .iter()
        .find(|r| r.name == "reviews")
        .expect("DR present");
    let port_policy = rule
        .port_level_settings
        .get(&8080)
        .expect("port 8080 entry present");
    let setting = port_policy
        .locality_lb_setting
        .as_ref()
        .expect("per-port localityLbSetting parsed");
    assert_eq!(setting.failover.len(), 1);
    assert_eq!(setting.failover[0].from, "us-west");
    assert_eq!(setting.failover[0].to, "us-east");
}

#[test]
fn k8s_translator_rejects_malformed_port_level_locality_lb_setting() {
    // Uses the shared `is_valid_locality_pattern` validator — a bare `*` zone
    // with a non-wildcard region is rejected.
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "portLevelSettings": [
                    {
                        "port": { "number": 8080 },
                        "loadBalancer": {
                            "localityLbSetting": {
                                "distribute": [
                                    {
                                        "from": "us-west/*/sub",
                                        "to": { "us-east": 100 }
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        }),
    );
    let err = translate_k8s_objects(&[object], k8s_options())
        .expect_err("malformed per-port locality must be rejected by shared validator");
    let msg = format!("{err}");
    assert!(
        msg.contains("localityLbSetting.distribute"),
        "expected distribute rejection from shared validator, got: {msg}"
    );
}

#[test]
fn distribute_projects_through_mesh_apply_onto_upstream_locality_lb_setting() {
    // End-to-end: K8s DR → mesh slice → cold-path apply → Upstream field.
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failover": [
                            { "from": "us-west", "to": "us-east" }
                        ]
                    }
                }
            }
        }),
    );
    let result = translate_k8s_objects(&[object], k8s_options()).expect("translation");
    let mut config = result.config;
    config.upstreams.push(matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh apply");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream projected");
    let setting = upstream
        .locality_lb_setting
        .as_ref()
        .expect("locality_lb_setting projected");
    assert!(setting.enabled);
    assert!(setting.distribute.is_empty());
    assert_eq!(setting.failover.len(), 1);
    assert_eq!(setting.failover[0].from, "us-west");
    assert_eq!(setting.failover[0].to, "us-east");
}

fn multi_port_upstream(id: &str, host_fqdn: &str) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: "default".to_string(),
        name: Some(id.to_string()),
        targets: vec![
            UpstreamTarget {
                host: host_fqdn.to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-west/us-west-1/a".to_string()),
                path: None,
            },
            UpstreamTarget {
                host: host_fqdn.to_string(),
                port: 9090,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-west/us-west-1/a".to_string()),
                path: None,
            },
        ],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
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
        created_at: now,
        updated_at: now,
    }
}

#[test]
fn port_level_locality_lb_projects_onto_upstream_port_overrides() {
    // K8s DR with port-level locality on 8080 only must (a) project onto
    // Upstream.port_overrides[8080].locality_lb_setting and (b) leave port
    // 9090's override slot unaffected. Combined with a top-level
    // localityLbSetting, the top-level value lands on Upstream.locality_lb_setting
    // so dispatch on port 9090 falls back to upstream-level locality.
    let object = istio_object(
        "DestinationRule",
        "reviews",
        serde_json::json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failover": [
                            { "from": "us-west", "to": "us-east" }
                        ]
                    }
                },
                "portLevelSettings": [
                    {
                        "port": { "number": 8080 },
                        "loadBalancer": {
                            "localityLbSetting": {
                                "distribute": [
                                    {
                                        "from": "us-west/us-west-1/a",
                                        "to": { "us-west/us-west-1/a": 100 }
                                    }
                                ]
                            }
                        }
                    }
                ]
            }
        }),
    );

    let result = translate_k8s_objects(&[object], k8s_options()).expect("translation");
    let mut config = result.config;
    config.upstreams.push(multi_port_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh apply");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream projected");

    // Upstream-level locality_lb_setting from the top-level DR block.
    let top_level = upstream
        .locality_lb_setting
        .as_ref()
        .expect("top-level locality_lb_setting projected");
    assert_eq!(top_level.failover.len(), 1);
    assert!(top_level.distribute.is_empty());

    // Port 8080 carries the per-port distribute override.
    let port8080 = upstream
        .port_overrides
        .get(&8080)
        .expect("port 8080 override populated");
    let port8080_locality = port8080
        .locality_lb_setting
        .as_ref()
        .expect("per-port localityLbSetting projected for port 8080");
    assert!(port8080_locality.enabled);
    assert_eq!(port8080_locality.distribute.len(), 1);
    assert_eq!(port8080_locality.distribute[0].from, "us-west/us-west-1/a");
    assert!(port8080_locality.failover.is_empty());

    // Port 9090 has no DR portLevelSettings entry — no per-port override slot
    // should be created. Dispatch on this port will fall through to the
    // upstream-level locality_lb_setting via the LB's per-port resolution.
    assert!(
        !upstream.port_overrides.contains_key(&9090),
        "phantom port 9090 must not create an override slot"
    );
}

#[test]
fn port_level_locality_lb_drives_distribute_at_dispatch() {
    // Build an upstream where two targets serve port 8080 in different
    // localities, and a DR's per-port localityLbSetting distributes traffic
    // 100% to one of them. The LB must honour the per-port setting and
    // never route to the other locality.
    use ferrum_edge::config::types::{
        LocalityDistribute, UpstreamLocalityLbSetting, UpstreamPortOverride,
    };
    use ferrum_edge::load_balancer::LoadBalancerCache;
    use std::collections::BTreeMap;

    let now = Utc::now();
    let mut upstream = Upstream {
        id: "reviews-u".to_string(),
        namespace: "default".to_string(),
        name: Some("reviews-u".to_string()),
        targets: vec![
            UpstreamTarget {
                host: "exact.local".to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-west/us-west-1/a".to_string()),
                path: None,
            },
            UpstreamTarget {
                host: "other.local".to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-east/us-east-1/a".to_string()),
                path: None,
            },
            UpstreamTarget {
                host: "fallback-9090.local".to_string(),
                port: 9090,
                service_port_policy_key: None,
                weight: 1,
                tags: HashMap::new(),
                locality: Some("us-east/us-east-1/a".to_string()),
                path: None,
            },
        ],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: Some("us-west/us-west-1/a".to_string()),
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
        created_at: now,
        updated_at: now,
    };

    let mut distribute_to = BTreeMap::new();
    distribute_to.insert("us-west/us-west-1/a".to_string(), 100u32);
    upstream.port_overrides.insert(
        8080,
        UpstreamPortOverride {
            locality_lb_setting: Some(UpstreamLocalityLbSetting {
                enabled: true,
                distribute: vec![LocalityDistribute {
                    from: "us-west/us-west-1/a".to_string(),
                    to: distribute_to,
                }],
                failover: Vec::new(),
            }),
            ..UpstreamPortOverride::default()
        },
    );
    // Port 9090 has a non-locality override slot — exercises the per-port
    // selector with `port_state.locality_lb = None`, which must fall through
    // to the upstream-level locality (also None here) and stay scoped to
    // port-9090 targets only.
    upstream.port_overrides.insert(
        9090,
        UpstreamPortOverride {
            connect_timeout_ms: Some(1234),
            ..UpstreamPortOverride::default()
        },
    );

    let cache = LoadBalancerCache::new(&GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    });
    let snapshot = cache.load();

    // Per-port locality on 8080 forces every selection into the exact-tier
    // target, even though both are healthy and unweighted at upstream level.
    for i in 0..16 {
        let selection = LoadBalancerCache::select_target_for_port_from(
            &snapshot,
            "default",
            "reviews-u",
            &format!("k-{i}"),
            8080,
            None,
        )
        .expect("per-port selection");
        assert_eq!(
            selection.target.host, "exact.local",
            "per-port distribute must keep traffic on us-west even though both 8080 targets are healthy"
        );
    }

    // Port 9090 has an override slot without locality — the per-port selector
    // restricts candidates to port-9090 targets, so the per-port locality
    // settings from port 8080 must NOT leak across ports.
    let selection = LoadBalancerCache::select_target_for_port_from(
        &snapshot,
        "default",
        "reviews-u",
        "k-9090",
        9090,
        None,
    )
    .expect("port 9090 still selectable");
    assert_eq!(selection.target.host, "fallback-9090.local");
}

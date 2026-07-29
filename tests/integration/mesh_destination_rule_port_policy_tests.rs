use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshCorsUnmatchedPreflights, MeshDestinationRule, MeshLoadBalancer,
    MeshOutlierDetection, MeshSimpleLb, MeshTrafficPolicy, cors_plugin_config_from_mesh_policy,
};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

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
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn upstream() -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "reviews-u".to_string(),
        namespace: "default".to_string(),
        name: Some("reviews".to_string()),
        targets: vec![UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
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

fn proxy() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "reviews-p",
        "namespace": "default",
        "hosts": ["reviews.example.com"],
        "backend_host": "reviews.default.svc.cluster.local",
        "backend_port": 0,
        "backend_scheme": "http",
        "upstream_id": "reviews-u"
    }))
    .expect("proxy fixture")
}

fn k8s_object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
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

#[test]
fn destination_rule_port_level_load_balancer_projects_to_upstream_override() {
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("port override projected");
    assert_eq!(port_override.algorithm, Some(LoadBalancerAlgorithm::Random));
}

#[test]
fn destination_rule_max_requests_only_rule_does_not_clear_prior_locality_policy() {
    let mut translated = translate_k8s_objects(
        &[
            k8s_object(
                "DestinationRule",
                "a-locality",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "loadBalancer": {
                            "localityLbSetting": {
                                "enabled": true,
                                "distribute": [
                                    {
                                        "from": "us-west/us-west-1/a",
                                        "to": {"us-west/us-west-1/a": 100}
                                    }
                                ]
                            }
                        }
                    }
                }),
            ),
            k8s_object(
                "DestinationRule",
                "z-max-requests-only",
                serde_json::json!({
                    "host": "reviews.default.svc.cluster.local",
                    "trafficPolicy": {
                        "connectionPool": {
                            "http": {"maxRequestsPerConnection": 2}
                        }
                    }
                }),
            ),
        ],
        k8s_options(),
    )
    .expect("DestinationRules translate");

    let mesh = translated.config.mesh.as_ref().expect("mesh config");
    let later = mesh
        .destination_rules
        .iter()
        .find(|dr| dr.name == "z-max-requests-only")
        .expect("later DR translated");
    assert!(
        later.traffic_policy.is_none(),
        "a deferred-only later DR must not carry an empty effective traffic policy"
    );

    translated.config.upstreams.push(upstream());
    translated.config.proxies.push(proxy());
    translated.config.normalize_fields();

    let prepared =
        prepare_gateway_config_for_mesh(translated.config, &runtime()).expect("mesh config");
    let locality = prepared.upstreams[0]
        .locality_lb_setting
        .as_ref()
        .expect("earlier locality policy must survive deferred-only later DR");
    assert!(locality.enabled);
    assert_eq!(locality.distribute.len(), 1);
}

#[test]
fn destination_rule_port_level_outlier_detection_projects_to_dispatch_override() {
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
            outlier_detection: Some(MeshOutlierDetection {
                consecutive_errors: Some(5),
                interval_seconds: Some(11),
                base_ejection_seconds: Some(17),
                max_ejection_percent: Some(50),
            }),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let upstream_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("upstream port override projected");
    assert_eq!(
        upstream_override.algorithm,
        Some(LoadBalancerAlgorithm::Random)
    );
    let upstream_passive = upstream_override
        .passive_health_check
        .as_ref()
        .expect("upstream passive health projected");
    assert_eq!(upstream_passive.unhealthy_threshold, 5);
    assert_eq!(upstream_passive.unhealthy_window_seconds, 11);
    assert_eq!(upstream_passive.healthy_after_seconds, 17);
    assert_eq!(upstream_passive.max_ejection_percent, Some(50));

    let dispatch_override = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .expect("proxy dispatch port override projected");
    assert_eq!(
        dispatch_override.algorithm,
        Some(LoadBalancerAlgorithm::Random)
    );
    let dispatch_passive = dispatch_override
        .passive_health_check
        .as_ref()
        .expect("dispatch passive health projected");
    assert_eq!(dispatch_passive.unhealthy_threshold, 5);
    assert_eq!(dispatch_passive.unhealthy_window_seconds, 11);
    assert_eq!(dispatch_passive.healthy_after_seconds, 17);
    assert_eq!(dispatch_passive.max_ejection_percent, Some(50));
}

#[test]
fn destination_rule_top_level_max_connections_fans_out_to_all_target_ports() {
    use ferrum_edge::config::types::TcpKeepaliveCfg;

    // Upstream serves a single target port; top-level
    // `connectionPool.tcp.maxConnections` and `tcpKeepalive` MUST land on
    // `port_overrides[target_port]` and project through to the proxy's
    // `dispatch_port_overrides` so the L4 dispatch can see them.
    let config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    max_connections: Some(50),
                    tcp_keepalive: Some(TcpKeepaliveCfg {
                        time_seconds: Some(300),
                        interval_seconds: Some(30),
                        probes: Some(3),
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let mut config = config;
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let upstream_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("top-level fan-out must populate port 8080");
    assert_eq!(upstream_override.max_connections, Some(50));
    let keepalive = upstream_override
        .tcp_keepalive
        .as_ref()
        .expect("keepalive must land on port slot");
    assert_eq!(keepalive.time_seconds, Some(300));
    assert_eq!(keepalive.interval_seconds, Some(30));
    assert_eq!(keepalive.probes, Some(3));

    let dispatch = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|map| map.get(&8080))
        .expect("dispatch port override projected");
    assert_eq!(dispatch.max_connections, Some(50));
    let dispatch_keepalive = dispatch
        .tcp_keepalive
        .as_ref()
        .expect("dispatch keepalive projected");
    assert_eq!(dispatch_keepalive.time_seconds, Some(300));
}

#[test]
fn destination_rule_port_level_max_connections_overrides_top_level() {
    // Per-port `connectionPool.tcp.maxConnections` overrides the top-level
    // fan-out for that specific port; ports not enumerated in
    // `portLevelSettings` keep the top-level cap.
    use ferrum_edge::config::types::TcpKeepaliveCfg;

    let mut upstream_with_two_ports = upstream();
    upstream_with_two_ports.targets.push({
        let mut second = upstream_with_two_ports.targets[0].clone();
        second.port = 9090;
        second
    });

    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            max_connections: Some(10),
            tcp_keepalive: Some(TcpKeepaliveCfg {
                time_seconds: Some(60),
                interval_seconds: None,
                probes: None,
            }),
            ..MeshTrafficPolicy::default()
        },
    );

    let config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream_with_two_ports],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    max_connections: Some(100),
                    tcp_keepalive: Some(TcpKeepaliveCfg {
                        time_seconds: Some(900),
                        interval_seconds: Some(60),
                        probes: Some(9),
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let mut config = config;
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");

    // Port 8080: per-port overrides BOTH fields. The unset
    // `interval_seconds` / `probes` on the per-port keepalive replace the
    // top-level keepalive — Istio's per-port-overrides-top-level shape.
    let p8080 = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("port 8080 entry");
    assert_eq!(p8080.max_connections, Some(10), "per-port cap wins");
    let p8080_keepalive = p8080.tcp_keepalive.as_ref().expect("keepalive present");
    assert_eq!(p8080_keepalive.time_seconds, Some(60));
    assert!(p8080_keepalive.interval_seconds.is_none());
    assert!(p8080_keepalive.probes.is_none());

    // Port 9090: top-level fan-out applies because no per-port entry
    // overrides it.
    let p9090 = prepared.upstreams[0]
        .port_overrides
        .get(&9090)
        .expect("port 9090 entry from top-level fan-out");
    assert_eq!(p9090.max_connections, Some(100));
    let p9090_keepalive = p9090.tcp_keepalive.as_ref().expect("keepalive present");
    assert_eq!(p9090_keepalive.time_seconds, Some(900));
    assert_eq!(p9090_keepalive.interval_seconds, Some(60));
    assert_eq!(p9090_keepalive.probes, Some(9));
}

#[test]
fn destination_rule_top_level_max_connections_skips_phantom_ports() {
    // Top-level fan-out targets only ports actually served by the upstream.
    // Without this guard, a typo (or wider DR than needed) would silently
    // create `port_overrides` entries for unreferenced ports.
    use ferrum_edge::config::types::TcpKeepaliveCfg;

    let config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()], // only target port 8080
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    max_connections: Some(20),
                    tcp_keepalive: Some(TcpKeepaliveCfg {
                        time_seconds: Some(120),
                        ..TcpKeepaliveCfg::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let mut config = config;
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    // Only port 8080 should have an entry; no phantom ports.
    assert_eq!(prepared.upstreams[0].port_overrides.len(), 1);
    assert!(prepared.upstreams[0].port_overrides.contains_key(&8080));
}

// ── T1-C: connectionPool.http per-port projection ───────────────────────

#[test]
fn destination_rule_top_level_connection_pool_http_fans_out_to_target_ports() {
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // Single target on port 8080. A top-level `trafficPolicy.connectionPool.http`
    // block should fan out onto every port served by an upstream's targets,
    // mirroring the T1-D `connectionPool.tcp.{maxConnections,tcpKeepalive}`
    // fan-out pattern. Without service discovery the fan-out is bounded to
    // the static target ports; here we expect exactly port 8080 to receive
    // the overlay.
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connection_pool_http: Some(MeshConnectionPoolHttp {
                        max_requests_per_connection: Some(75),
                        idle_timeout_ms: Some(45_000),
                        http2_max_requests: Some(250),
                        // F5.1: the two newly-projected knobs also fan out.
                        h2_upgrade_policy: Some(
                            ferrum_edge::config::types::H2UpgradePolicy::DoNotUpgrade,
                        ),
                        max_retries: Some(2),
                        http1_max_pending_requests: Some(128),
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("top-level http overlay fan-out lands on every target port");
    assert!(
        port_override.http_max_requests_per_connection.is_none(),
        "maxRequestsPerConnection is deferred and must not project into port overrides"
    );
    assert_eq!(port_override.http_idle_timeout_ms, Some(45_000));
    assert_eq!(port_override.h2_max_concurrent_streams, Some(250));
    assert_eq!(
        port_override.h2_upgrade_policy,
        Some(ferrum_edge::config::types::H2UpgradePolicy::DoNotUpgrade)
    );
    assert_eq!(port_override.max_retries, Some(2));

    // Dispatch projection: the per-port overlay reaches every referencing
    // proxy via `resolve_dispatch_port_overrides`.
    let dispatch_override = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .expect("proxy dispatch port override projected");
    assert!(
        dispatch_override.http_max_requests_per_connection.is_none(),
        "maxRequestsPerConnection must not project into dispatch overrides"
    );
    assert_eq!(dispatch_override.http_idle_timeout_ms, Some(45_000));
    assert_eq!(dispatch_override.h2_max_concurrent_streams, Some(250));
    assert_eq!(
        dispatch_override.h2_upgrade_policy,
        Some(ferrum_edge::config::types::H2UpgradePolicy::DoNotUpgrade)
    );
    assert_eq!(dispatch_override.max_retries, Some(2));
}

#[test]
fn destination_rule_top_level_connection_pool_http_on_sd_upstream_goes_to_fallback() {
    use ferrum_edge::config::types::{DnsSdConfig, SdProvider, ServiceDiscoveryConfig};
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // #1806: a SERVICE-DISCOVERY upstream cannot fan the top-level
    // `connectionPool.http` overlay onto a known apply-time port set (targets
    // resolve at runtime). The overlay must instead be captured on
    // `dispatch_port_override_fallback` and projected onto the referencing
    // proxy, where the HTTP dispatch resolvers apply it by the LB-selected
    // port. It must NOT silently land on (or skip) `port_overrides`.
    let mut sd_upstream = upstream();
    sd_upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::DnsSd,
        dns_sd: Some(DnsSdConfig {
            service_name: "_http._tcp.reviews.default.svc.cluster.local".to_string(),
            poll_interval_seconds: 30,
        }),
        kubernetes: None,
        consul: None,
        mesh: None,
        default_weight: 1,
    });

    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![sd_upstream],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connection_pool_http: Some(MeshConnectionPoolHttp {
                        idle_timeout_ms: Some(45_000),
                        http2_max_requests: Some(250),
                        max_retries: Some(2),
                        ..MeshConnectionPoolHttp::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings: HashMap::new(),
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");

    // The SD upstream's top-level overlay landed on the fallback, NOT fanned
    // onto a (declared static target) port_overrides entry.
    let fallback = prepared.upstreams[0]
        .dispatch_port_override_fallback
        .as_ref()
        .expect("SD top-level connectionPool.http must populate the fallback overlay");
    assert_eq!(fallback.http_idle_timeout_ms, Some(45_000));
    assert_eq!(fallback.h2_max_concurrent_streams, Some(250));
    assert_eq!(fallback.max_retries, Some(2));
    assert!(
        prepared.upstreams[0].port_overrides.is_empty(),
        "SD upstream top-level overlay must not fan out onto port_overrides"
    );

    // The fallback is projected onto the referencing proxy for runtime
    // resolution; the per-port dispatch map stays None (no explicit port entries).
    assert!(prepared.proxies[0].dispatch_port_overrides.is_none());
    let proxy_fallback = prepared.proxies[0]
        .dispatch_port_override_fallback
        .as_ref()
        .expect("SD fallback must project onto the referencing proxy");
    assert_eq!(proxy_fallback.http_idle_timeout_ms, Some(45_000));
    assert_eq!(proxy_fallback.h2_max_concurrent_streams, Some(250));
    assert_eq!(proxy_fallback.max_retries, Some(2));
}

#[test]
fn destination_rule_named_target_port_sd_keeps_per_port_and_fallback_separate() {
    use ferrum_edge::config::types::{DnsSdConfig, SdProvider, ServiceDiscoveryConfig};
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // SD upstreams keep explicit per-port policy keyed by the declared Service
    // port and keep the top-level `connectionPool.http` overlay as the fallback.
    // Runtime target materialization now carries the owning Service port on each
    // discovered target, so the hot path can apply the explicit entry without
    // folding it into the fallback and leaking it to sibling ports.
    let mut sd_upstream = upstream();
    // Resolved workload target port differs from the declared service port (80).
    sd_upstream.targets[0].port = 8080;
    sd_upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::DnsSd,
        dns_sd: Some(DnsSdConfig {
            service_name: "_http._tcp.reviews.default.svc.cluster.local".to_string(),
            poll_interval_seconds: 30,
        }),
        kubernetes: None,
        consul: None,
        mesh: None,
        default_weight: 1,
    });

    // Per-port entry on the DECLARED service port (80): conflicting maxRetries (5)
    // that must WIN over the top-level (2), plus an inherited-only field.
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        80,
        MeshTrafficPolicy {
            connection_pool_http: Some(MeshConnectionPoolHttp {
                max_retries: Some(5),
                ..MeshConnectionPoolHttp::default()
            }),
            ..MeshTrafficPolicy::default()
        },
    );

    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![sd_upstream],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connection_pool_http: Some(MeshConnectionPoolHttp {
                        idle_timeout_ms: Some(45_000),
                        max_retries: Some(2),
                        ..MeshConnectionPoolHttp::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");

    let per_port = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&80))
        .expect("declared service port entry must project to the proxy");
    assert_eq!(
        per_port.max_retries,
        Some(5),
        "explicit per-port maxRetries stays keyed by the declared service port"
    );

    // The projected proxy fallback carries the TOP-LEVEL overlay ONLY (no
    // per-port folding): the top-level maxRetries (2) and idleTimeout (45s).
    let proxy_fallback = prepared.proxies[0]
        .dispatch_port_override_fallback
        .as_ref()
        .expect("SD fallback must project onto the referencing proxy");
    assert_eq!(
        proxy_fallback.max_retries,
        Some(2),
        "top-level fallback remains separate from explicit per-port policy"
    );
    assert_eq!(
        proxy_fallback.http_idle_timeout_ms,
        Some(45_000),
        "a top-level-only field is inherited by the fallback"
    );
}

#[test]
fn destination_rule_port_level_connection_pool_http_overrides_top_level_fan_out() {
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // Top-level fan-out sets every field; per-port `portLevelSettings.http`
    // overrides just one of them. The other two fields must survive the
    // per-port apply (Istio "per-port settings layer over top-level"
    // semantics).
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            connection_pool_http: Some(MeshConnectionPoolHttp {
                // Only override http2_max_requests; the other two fields stay
                // from the top-level fan-out.
                http2_max_requests: Some(999),
                ..MeshConnectionPoolHttp::default()
            }),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connection_pool_http: Some(MeshConnectionPoolHttp {
                        max_requests_per_connection: Some(75),
                        idle_timeout_ms: Some(45_000),
                        http2_max_requests: Some(250),
                        h2_upgrade_policy: None,
                        max_retries: None,
                        http1_max_pending_requests: None,
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("per-port overlay present");
    // Per-port wins for the field it sets:
    assert_eq!(port_override.h2_max_concurrent_streams, Some(999));
    // Supported fields not respecified by per-port survive from the fan-out;
    // maxRequestsPerConnection is intentionally deferred and not projected.
    assert!(
        port_override.http_max_requests_per_connection.is_none(),
        "unsupported maxRequestsPerConnection must not survive as effective policy"
    );
    assert_eq!(port_override.http_idle_timeout_ms, Some(45_000));
}

#[test]
fn destination_rule_connection_pool_http_only_per_port_no_fan_out() {
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // No top-level overlay; only port 8080 carries the HTTP block via
    // `portLevelSettings`. The single-port overlay should land only on
    // port 8080 and not bleed onto any other port.
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            connection_pool_http: Some(MeshConnectionPoolHttp {
                max_requests_per_connection: Some(10),
                idle_timeout_ms: Some(30_000),
                http2_max_requests: Some(20),
                h2_upgrade_policy: None,
                max_retries: None,
                http1_max_pending_requests: None,
            }),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: None,
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("per-port overlay present");
    assert!(
        port_override.http_max_requests_per_connection.is_none(),
        "unsupported maxRequestsPerConnection must not project at port level"
    );
    assert_eq!(port_override.http_idle_timeout_ms, Some(30_000));
    assert_eq!(port_override.h2_max_concurrent_streams, Some(20));

    // Phantom-port guard: 9090 isn't on any target, so it must NOT receive
    // the per-port overlay either (would be a phantom-port skip with warn).
    assert!(!prepared.upstreams[0].port_overrides.contains_key(&9090));
}

#[test]
fn destination_rule_port_level_explicit_default_clears_inherited_h2_upgrade_policy() {
    use ferrum_edge::config::types::H2UpgradePolicy;
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;

    // codex round-1 Finding 3: a top-level `UPGRADE` fans out to every port,
    // but an EXPLICIT port-level `DEFAULT` on 8080 must CLEAR the inherited
    // `UPGRADE` for that port (operator explicitly chose probe-driven), not
    // leave it inherited. `H2UpgradePolicy::Default` is carried (not collapsed
    // to `None`) precisely so the apply layer can distinguish explicit-DEFAULT
    // from absent.
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            connection_pool_http: Some(MeshConnectionPoolHttp {
                // Explicit DEFAULT: clears the inherited top-level UPGRADE.
                h2_upgrade_policy: Some(H2UpgradePolicy::Default),
                ..MeshConnectionPoolHttp::default()
            }),
            ..MeshTrafficPolicy::default()
        },
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy()],
        upstreams: vec![upstream()],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: vec![MeshDestinationRule {
                name: "reviews-dr".to_string(),
                namespace: "default".to_string(),
                host: "reviews.default.svc.cluster.local".to_string(),
                traffic_policy: Some(MeshTrafficPolicy {
                    connection_pool_http: Some(MeshConnectionPoolHttp {
                        // Top-level UPGRADE fans out to every port first.
                        h2_upgrade_policy: Some(H2UpgradePolicy::Upgrade),
                        ..MeshConnectionPoolHttp::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
                port_level_settings,
                subsets: Vec::new(),
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");
    let port_override = prepared.upstreams[0]
        .port_overrides
        .get(&8080)
        .expect("per-port overlay present");
    // Explicit port-level DEFAULT overwrote the inherited UPGRADE → Default
    // (probe-driven), NOT Upgrade.
    assert_eq!(
        port_override.h2_upgrade_policy,
        Some(H2UpgradePolicy::Default),
        "explicit port-level DEFAULT must clear the inherited top-level UPGRADE"
    );

    // Dispatch projection carries the cleared value, so dispatch is
    // probe-driven for that port (Default and None are identical at the fork).
    let dispatch_override = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .expect("proxy dispatch port override projected");
    assert_eq!(
        dispatch_override.h2_upgrade_policy,
        Some(H2UpgradePolicy::Default)
    );
}

// `resolve_effective_proxy_for_target` is `pub(crate)`, so the per-field
// projection and Cow::Borrowed/Owned branches are tested inline in
// `src/proxy/mod.rs` (see the `resolve_effective_proxy_*` tests block).

// ── VirtualService-derived CORS on materialized mesh outbound routes ────────
//
// Issue #1973 coverage. These live here (rather than mesh_l7_routing_tests)
// to reuse this file's `runtime()` + `prepare_gateway_config_for_mesh`
// harness — the property under test is route-policy application at mesh
// prepare time, the same layer the DR tests above exercise.

#[test]
fn virtual_service_cors_policy_synthesizes_cors_plugin_on_mesh_outbound_route() {
    // The mesh document shape is exactly what the file source accepts —
    // doubling as a schema pin for the live fixture's client config. The
    // bare-name `host: svc` must resolve with DestinationRule host semantics.
    let mesh: MeshConfig = serde_yaml::from_str(
        r#"
workloads:
  - spiffe_id: spiffe://cluster.local/ns/default/sa/svc
    service_name: svc
    namespace: default
    trust_domain: cluster.local
    service_account: svc
    addresses: ["10.0.0.9"]
    ports:
      - port: 8080
        protocol: http
        name: http
    selector:
      namespace: default
services:
  - name: svc
    namespace: default
    ports:
      - port: 8080
        protocol: http
        name: http
    workloads:
      - spiffe_id: spiffe://cluster.local/ns/default/sa/svc
virtual_service_cors_policies:
  - name: svc-cors
    namespace: default
    host: svc
    cors:
      allowed_origins:
        - exact: "https://fixture.example"
      allowed_methods: ["GET", "OPTIONS"]
      max_age_seconds: 600
"#,
    )
    .expect("mesh yaml parses");
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };

    let prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh config");

    let proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "__mesh-outbound-default-svc-8080")
        .expect("materialized outbound route");
    let plugin = prepared
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == "__mesh-cors-default-svc-8080")
        .expect("synthesized cors plugin config");
    assert_eq!(plugin.plugin_name, "cors");
    assert_eq!(plugin.proxy_id.as_deref(), Some(proxy.id.as_str()));
    assert!(plugin.enabled);
    assert_eq!(
        plugin.config["allowed_origins"],
        serde_json::json!([{ "exact": "https://fixture.example" }])
    );
    assert_eq!(
        plugin.config["allowed_methods"],
        serde_json::json!(["GET", "OPTIONS"])
    );
    assert_eq!(plugin.config["max_age"], serde_json::json!(600));
    assert_eq!(plugin.config["allowed_headers"], serde_json::json!([]));
    assert_eq!(plugin.config["exposed_headers"], serde_json::json!([]));
    assert_eq!(
        plugin.config["unmatched_preflights"],
        serde_json::json!("forward")
    );
    assert!(
        plugin.config.get("preflight_continue").is_none(),
        "the plugin must answer preflights itself (Istio semantics)"
    );
    assert!(
        proxy
            .plugins
            .iter()
            .any(|association| association.plugin_config_id == plugin.id),
        "route must carry the plugin association"
    );
}

#[test]
fn virtual_service_cors_policy_rides_the_mesh_block_and_matches_gateway_projection() {
    let translated = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-cors",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local", "svc"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {
                        "allowOrigins": [
                            {"exact": "https://fixture.example"},
                            {"prefix": "https://app."},
                            {"regex": "https://.*\\.example\\.com"}
                        ],
                        "allowMethods": ["GET", "POST"],
                        "allowHeaders": ["x-fixture"],
                        "exposeHeaders": ["x-out"],
                        "maxAge": "10m",
                        "allowCredentials": true,
                        "unmatchedPreflights": "IGNORE"
                    }
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");

    let mesh = translated.config.mesh.as_ref().expect("mesh block");
    assert_eq!(
        mesh.virtual_service_cors_policies.len(),
        2,
        "one carried policy per VS host"
    );
    let policy = &mesh.virtual_service_cors_policies[0];
    assert_eq!(policy.name, "vs-cors");
    assert_eq!(policy.namespace, "default");
    assert_eq!(policy.host, "svc.default.svc.cluster.local");
    assert_eq!(
        policy.export_to,
        vec!["*".to_string()],
        "an omitted spec.exportTo must be carried as Istio's explicit public default"
    );

    // Single-source-of-truth pin: the slice-carried typed policy must project
    // to EXACTLY the plugin config the gateway-side translation emits for the
    // same corsPolicy — if either projection drifts, this fails.
    let gateway_cors = translated
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "cors")
        .expect("gateway-side cors plugin emitted");
    assert_eq!(
        cors_plugin_config_from_mesh_policy(&policy.cors),
        gateway_cors.config,
        "slice-carried and gateway-projected CORS configs must be identical"
    );
}

#[test]
fn virtual_service_cors_unmatched_modes_survive_gateway_and_mesh_projection() {
    for (source, carried, projected) in [
        (None, None, "forward"),
        (
            Some("UNSPECIFIED"),
            Some(MeshCorsUnmatchedPreflights::Forward),
            "forward",
        ),
        (
            Some("FORWARD"),
            Some(MeshCorsUnmatchedPreflights::Forward),
            "forward",
        ),
        (
            Some("IGNORE"),
            Some(MeshCorsUnmatchedPreflights::Ignore),
            "ignore",
        ),
    ] {
        let mut cors_policy = serde_json::json!({
            "allowOrigins": [{"exact": "https://app.example"}]
        });
        if let Some(source) = source {
            cors_policy["unmatchedPreflights"] = serde_json::json!(source);
        }
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-unmatched-cors",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": cors_policy
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("CORS unmatched mode translates");
        let gateway = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "cors")
            .expect("gateway CORS plugin");
        let mesh = translated
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .first()
            .expect("mesh CORS policy");
        assert_eq!(mesh.cors.unmatched_preflights, carried);
        assert_eq!(
            gateway.config["unmatched_preflights"],
            serde_json::json!(projected)
        );
        assert_eq!(
            cors_plugin_config_from_mesh_policy(&mesh.cors),
            gateway.config
        );
    }
}

/// Issue #3254: an Istio exact that is wildcard-shaped or not the canonical
/// browser serialization is projected LITERALLY on BOTH paths — it must reach
/// the plugin as `{"exact": <source string>}`, never as the plugin's
/// plain-string form (which canonicalizes and reads a leading `*` as native
/// wildcard-subdomain syntax, widening the source matcher).
#[test]
fn virtual_service_cors_literal_exact_origin_survives_both_projections_unwidened() {
    for source_origin in [
        "https://example.com:443",
        "HTTPS://EXAMPLE.COM",
        "https://bücher.example",
        "*.example.com",
    ] {
        for cors_policy in [
            serde_json::json!({"allowOrigins": [{"exact": source_origin}]}),
            serde_json::json!({"allowOrigin": [source_origin]}),
        ] {
            let translated = translate_k8s_objects(
                &[k8s_object(
                    "VirtualService",
                    "vs-literal-cors",
                    serde_json::json!({
                        "hosts": ["svc.default.svc.cluster.local"],
                        "http": [{
                            "route": [{"destination": {
                                "host": "svc.default.svc.cluster.local",
                                "port": {"number": 8080}
                            }}],
                            "corsPolicy": cors_policy
                        }]
                    }),
                )],
                k8s_options(),
            )
            .expect("literal exact translates");

            let gateway = translated
                .config
                .plugin_configs
                .iter()
                .find(|plugin| plugin.plugin_name == "cors")
                .expect("literal Istio exact must project a gateway CORS plugin");
            assert_eq!(
                gateway.config["allowed_origins"],
                serde_json::json!([{ "exact": source_origin }]),
                "the source string must be preserved byte-for-byte as a literal matcher"
            );
            ferrum_edge::plugins::validate_plugin_config("cors", &gateway.config)
                .expect("projected literal CORS config constructs");

            let mesh = translated
                .config
                .mesh
                .as_ref()
                .expect("mesh block")
                .virtual_service_cors_policies
                .first()
                .expect("literal Istio exact must ride the mesh slice");
            assert_eq!(
                cors_plugin_config_from_mesh_policy(&mesh.cors),
                gateway.config,
                "slice-carried and gateway-projected CORS configs must be identical"
            );
        }
    }
}

/// Reload / update / delete: a route-local CORS policy must follow its source
/// through re-translation, and rule ordering must be preserved. Each pass is a
/// full re-translate — the same path a config reload or a K8s watch event takes
/// — so a stale or leaked route-local plugin would show up here.
#[test]
fn virtual_service_cors_policy_follows_updates_and_deletes_preserving_rule_order() {
    let translate = |first_cors: Option<serde_json::Value>| {
        let mut api_rule = serde_json::json!({
            "match": [{"uri": {"prefix": "/api"}}],
            "route": [{"destination": {
                "host": "svc.default.svc.cluster.local",
                "port": {"number": 8080}
            }}]
        });
        if let Some(cors) = first_cors {
            api_rule["corsPolicy"] = cors;
        }
        translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-cors-lifecycle",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [
                        api_rule,
                        {
                            "match": [{"uri": {"prefix": "/"}}],
                            "route": [{"destination": {
                                "host": "svc.default.svc.cluster.local",
                                "port": {"number": 8080}
                            }}]
                        }
                    ]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates")
    };

    let cors_plugins = |translated: &ferrum_edge::config_sources::k8s::K8sTranslation| {
        translated
            .config
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.plugin_name == "cors")
            .map(|plugin| {
                (
                    plugin.proxy_id.clone(),
                    plugin.config["allowed_origins"].clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let listen_paths = |translated: &ferrum_edge::config_sources::k8s::K8sTranslation| {
        translated
            .config
            .proxies
            .iter()
            .map(|proxy| proxy.listen_path.clone())
            .collect::<Vec<_>>()
    };

    // ADD: the policy lands on the `/api` route's own proxy only.
    let added = translate(Some(
        serde_json::json!({"allowOrigins": [{"exact": "https://one.example"}]}),
    ));
    let added_plugins = cors_plugins(&added);
    assert_eq!(added_plugins.len(), 1, "{added_plugins:?}");
    let scoped_proxy = added_plugins[0].0.clone().expect("cors is proxy-scoped");
    assert_eq!(
        added_plugins[0].1,
        serde_json::json!([{ "exact": "https://one.example" }])
    );
    let order = listen_paths(&added);

    // UPDATE: re-translating with a changed matcher replaces the projection in
    // place — same route scope, new origins, no second instance.
    let updated = translate(Some(serde_json::json!({
        "allowOrigins": [
            {"exact": "*.two.example"},
            {"regex": "https://[a-z]+\\.two\\.example"}
        ]
    })));
    let updated_plugins = cors_plugins(&updated);
    assert_eq!(updated_plugins.len(), 1, "{updated_plugins:?}");
    assert_eq!(updated_plugins[0].0.as_deref(), Some(scoped_proxy.as_str()));
    assert_eq!(
        updated_plugins[0].1,
        serde_json::json!([
            { "exact": "*.two.example" },
            { "regex": "https://[a-z]+\\.two\\.example" }
        ])
    );
    assert_eq!(
        listen_paths(&updated),
        order,
        "rule ordering must survive a CORS-only update"
    );

    // DELETE: removing the corsPolicy leaves no residual route-local plugin.
    let deleted = translate(None);
    assert!(
        cors_plugins(&deleted).is_empty(),
        "a removed corsPolicy must leave no route-local plugin behind"
    );
    let deleted_paths = listen_paths(&deleted);
    for path in &order {
        assert!(
            deleted_paths.contains(path),
            "rule `{path:?}` must survive a CORS delete: {deleted_paths:?}"
        );
    }
}

/// Issue #3253: matcher shapes outside the explicit byte / complexity / count
/// bounds stay fail-closed on BOTH projections — unprojected and uncarried,
/// never truncated, approximated, or widened.
#[test]
fn virtual_service_cors_out_of_bounds_matchers_are_deferred_across_both_projections() {
    let oversized = "a".repeat(600);
    let too_many: Vec<serde_json::Value> = (0..65)
        .map(|i| serde_json::json!({"exact": format!("https://app{i}.example.com")}))
        .collect();
    for cors_policy in [
        serde_json::json!({"allowOrigins": [{"exact": &oversized}]}),
        serde_json::json!({"allowOrigins": [{"prefix": &oversized}]}),
        serde_json::json!({"allowOrigins": [{"regex": &oversized}]}),
        serde_json::json!({"allowOrigins": [{"regex": "((((((((((((((((((((((((((((a))))))))))))))))))))))))))))"}]}),
        serde_json::json!({"allowOrigins": too_many}),
        serde_json::json!({"allowOrigins": [{"exact": "   "}]}),
    ] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-out-of-bounds-cors",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": cors_policy
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("an unrepresentable corsPolicy still leaves routing translated");
        assert!(
            translated
                .config
                .mesh
                .as_ref()
                .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
                .unwrap_or(true),
            "an out-of-bounds Istio CORS matcher must not ride the mesh slice"
        );
        assert!(
            !translated
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "cors"),
            "an out-of-bounds Istio CORS matcher must not project a gateway CORS plugin"
        );
    }
}

#[test]
fn virtual_service_cors_policy_respects_gateways_and_first_bearing_route() {
    // Bound only to an ingress gateway (no reserved `mesh` entry): Istio never
    // applies this VS to sidecars, so nothing may ride the mesh slice.
    let ingress_only = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-ingress-only",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "gateways": ["ingress-gw"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "https://a.example"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert!(
        ingress_only
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
            .unwrap_or(true),
        "an ingress-gateway-only VS must not carry mesh CORS"
    );

    // Explicitly including the reserved `mesh` gateway keeps the carry path.
    let mesh_bound = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-mesh-bound",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "gateways": ["mesh", "ingress-gw"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "https://a.example"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert_eq!(
        mesh_bound
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .len(),
        1
    );

    // The FIRST corsPolicy-bearing http[] entry decides: if ITS policy is not
    // translatable (bad regex), NOTHING is carried -- promoting the later
    // route's valid policy host-wide would enforce the wrong CORS on paths
    // whose own policy was deferred.
    let first_untranslatable = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-first-bad",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"regex": "("}]}
                    },
                    {
                        "match": [{"uri": {"prefix": "/b"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://b.example"}]}
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert!(
        first_untranslatable
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
            .unwrap_or(true),
        "a later route's policy must not be promoted host-wide over an untranslatable first"
    );
}

#[test]
fn virtual_service_cors_policy_earlier_corsless_catch_all_suppresses_later_policy() {
    // Istio evaluates http[] in order: an earlier host-wide catch-all WITHOUT
    // corsPolicy wins all host traffic, so a later route's CORS never applies
    // in Istio — carrying it host-wide would answer preflights and reject
    // disallowed Origins on traffic whose winning route has no CORS at all.
    let translated = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-corsless-catch-all-first",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [
                    {
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}]
                    },
                    {
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://later.example"}]}
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert!(
        translated
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
            .unwrap_or(true),
        "a later route's CORS must not override an earlier corsless host-wide catch-all"
    );

    // `ignoreUriCase` is URI-comparison metadata, not a scoping predicate: a
    // catch-all `/` prefix carrying it is still host-wide-representable.
    let ignore_uri_case = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-ignore-uri-case",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}, "ignoreUriCase": true}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "https://a.example"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert_eq!(
        ignore_uri_case
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .len(),
        1,
        "ignoreUriCase on a catch-all match must not make host-wide CORS disappear"
    );
}

#[test]
fn virtual_service_cors_policy_match_level_mesh_gateway_overrides_ingress_only_vs() {
    // Istio `HTTPMatchRequest.gateways` OVERRIDE the top-level `spec.gateways`
    // list: an ingress-only VS whose catch-all match names the reserved `mesh`
    // gateway still applies that route to sidecars, so its CORS must ride the
    // slice. (The inherit direction — a match WITHOUT `gateways` under an
    // ingress-only VS carries nothing — is pinned by
    // `virtual_service_cors_policy_respects_gateways_and_first_bearing_route`.)
    let translated = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-match-mesh-override",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "gateways": ["ingress-gw"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}, "gateways": ["mesh"]}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "https://a.example"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert_eq!(
        translated
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .len(),
        1,
        "a mesh-scoped match must override the ingress-only VS-level gateways"
    );
}

#[test]
fn virtual_service_cors_policy_legacy_allow_origin_shares_the_exact_gate() {
    // The deprecated `allowOrigin` string list projects through the SAME
    // literal `{exact}` matcher as `allowOrigins[].exact`, so it shares that
    // gate exactly: only values the plugin itself refuses (empty /
    // whitespace-only / over-budget) defer.
    for invalid in ["", "   "] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-legacy-invalid",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigin": [invalid]}
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        assert!(
            translated
                .config
                .mesh
                .as_ref()
                .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
                .unwrap_or(true),
            "legacy allowOrigin `{invalid}` must not ride the mesh slice"
        );
        assert!(
            !translated
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "cors"),
            "legacy allowOrigin `{invalid}` must not project a gateway cors plugin"
        );
    }

    // A valid legacy list still translates and carries.
    let valid = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-legacy-valid",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigin": ["*"]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert_eq!(
        valid
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .len(),
        1
    );
    let plugin = valid
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "cors")
        .expect("legacy wildcard projects a CORS plugin");
    assert_eq!(
        plugin.config["allowed_origins"],
        serde_json::json!([{ "exact": "*" }])
    );

    // A padded / non-origin legacy entry is a valid LITERAL matcher now: it is
    // carried verbatim and matches only that exact string, never trimmed or
    // canonicalized into a wider matcher.
    for literal in [" https://app.example", "https://app.example/"] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-legacy-literal",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigin": [literal]}
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        let plugin = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "cors")
            .unwrap_or_else(|| panic!("legacy literal `{literal}` must project"));
        assert_eq!(
            plugin.config["allowed_origins"],
            serde_json::json!([{ "exact": literal }])
        );
    }
}

#[test]
fn virtual_service_cors_policy_invalid_methods_and_headers_defer() {
    // allowMethods/allowHeaders/exposeHeaders are copied verbatim into the
    // plugin config, whose construction rejects invalid tokens — such a
    // policy must be non-translatable (deferred) everywhere instead of
    // failing CorsPlugin construction after translation.
    for (key, value) in [
        ("allowMethods", "not a method"),
        ("allowHeaders", "bad header"),
        ("exposeHeaders", "bad header"),
    ] {
        let mut cors_policy = serde_json::json!({
            "allowOrigins": [{"exact": "https://a.example"}]
        });
        cors_policy[key] = serde_json::json!([value]);
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-bad-tokens",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": cors_policy
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        assert!(
            translated
                .config
                .mesh
                .as_ref()
                .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
                .unwrap_or(true),
            "invalid {key} `{value}` must not ride the mesh slice"
        );
        assert!(
            !translated
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "cors"),
            "invalid {key} `{value}` must not project a gateway cors plugin"
        );
    }
}

#[test]
fn virtual_service_cors_policy_export_to_gates_slice_visibility() {
    use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

    let mesh_yaml = |export_to: &str| -> MeshConfig {
        serde_yaml::from_str(&format!(
            r#"
workloads:
  - spiffe_id: spiffe://cluster.local/ns/producer/sa/svc
    service_name: svc
    namespace: producer
    trust_domain: cluster.local
    service_account: svc
    addresses: ["10.0.0.9"]
    ports:
      - port: 8080
        protocol: http
        name: http
    selector:
      namespace: producer
services:
  - name: svc
    namespace: producer
    ports:
      - port: 8080
        protocol: http
        name: http
    workloads:
      - spiffe_id: spiffe://cluster.local/ns/producer/sa/svc
virtual_service_cors_policies:
  - name: svc-cors
    namespace: producer
    host: svc.producer.svc.cluster.local
{export_to}
    cors:
      allowed_origins:
        - exact: "https://fixture.example"
"#
        ))
        .expect("mesh yaml parses")
    };
    let request = |namespace: &str| MeshSliceRequest {
        node_id: "n1".to_string(),
        namespace: namespace.to_string(),
        ..MeshSliceRequest::default()
    };
    let config_for = |export_to: &str| GatewayConfig {
        mesh: Some(Box::new(mesh_yaml(export_to))),
        ..GatewayConfig::default()
    };

    // exportTo ["."] is namespace-local: a consumer slice in another
    // namespace must NOT receive the policy, the producer's own must.
    let consumer =
        MeshSlice::from_gateway_config(&config_for("    export_to: [\".\"]"), request("consumer"));
    assert!(
        consumer.virtual_service_cors_policies.is_empty(),
        "namespace-local VS CORS must not leak to another namespace's slice"
    );
    let producer =
        MeshSlice::from_gateway_config(&config_for("    export_to: [\".\"]"), request("producer"));
    assert_eq!(producer.virtual_service_cors_policies.len(), 1);

    // "*" is public; an OMITTED export_to on the native/file source is
    // namespace-local by Ferrum convention (matching ServiceEntry).
    let public =
        MeshSlice::from_gateway_config(&config_for("    export_to: [\"*\"]"), request("consumer"));
    assert_eq!(public.virtual_service_cors_policies.len(), 1);
    let omitted = MeshSlice::from_gateway_config(&config_for(""), request("consumer"));
    assert!(omitted.virtual_service_cors_policies.is_empty());
}

#[test]
fn virtual_service_cors_policy_exact_star_projects_and_other_wildcards_stay_literal() {
    let translated_star = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-exact-star",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [{
                    "match": [{"uri": {"prefix": "/"}}],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "*"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("exact star translates");
    assert_eq!(
        translated_star
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .len(),
        1
    );
    let star_plugin = translated_star
        .config
        .plugin_configs
        .iter()
        .find(|plugin| plugin.plugin_name == "cors")
        .expect("exact star projects a gateway CORS plugin");
    assert_eq!(
        star_plugin.config["allowed_origins"],
        serde_json::json!([{ "exact": "*" }])
    );
    assert_eq!(
        star_plugin.config["unmatched_preflights"],
        serde_json::json!("forward")
    );

    // The native cors plugin cannot combine `Access-Control-Allow-Origin: *`
    // with credentials and would silently disable the credential flag. Keep
    // both Istio spellings deferred until the concrete request origin can be
    // reflected safely, rather than weakening the source policy in transit.
    for cors_policy in [
        serde_json::json!({
            "allowOrigins": [{"exact": "*"}],
            "allowCredentials": true
        }),
        serde_json::json!({
            "allowOrigin": ["*"],
            "allowCredentials": true
        }),
    ] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-credentialed-star",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": cors_policy
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("credentialed exact star leaves routing translated");
        assert!(
            translated
                .config
                .mesh
                .as_ref()
                .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
                .unwrap_or(true),
            "credentialed exact star must not ride the mesh slice"
        );
        assert!(
            !translated
                .config
                .plugin_configs
                .iter()
                .any(|plugin| plugin.plugin_name == "cors"),
            "credentialed exact star must not project a credential-stripping cors plugin"
        );
    }

    // Issue #3254: every OTHER wildcard-shaped exact is a LITERAL matcher. It
    // projects (it is not deferred) and must reach the plugin as
    // `{"exact": <source>}` — never allow-all, and never the plain-string form
    // that would read it as native wildcard-subdomain syntax.
    for wildcard in ["*.example.com", "**"] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-wildcard-exact",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": wildcard}]}
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        let plugin = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "cors")
            .unwrap_or_else(|| panic!("literal wildcard exact `{wildcard}` must project"));
        assert_eq!(
            plugin.config["allowed_origins"],
            serde_json::json!([{ "exact": wildcard }]),
            "wildcard-shaped exact `{wildcard}` must stay a literal matcher"
        );
        let carried = translated
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .first()
            .unwrap_or_else(|| panic!("literal wildcard exact `{wildcard}` must ride the slice"));
        assert_eq!(
            cors_plugin_config_from_mesh_policy(&carried.cors),
            plugin.config
        );
    }
}

#[test]
fn virtual_service_cors_policy_skips_gateway_scoped_matches() {
    // http[0]'s CORS is scoped to an ingress gateway via match[].gateways —
    // it must neither donate its policy to the mesh slice nor suppress the
    // later mesh-bound http[1] policy.
    let translated = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-match-gateways",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "gateways": ["mesh", "ingress-gw"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/ingress"}, "gateways": ["ingress-gw"]}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://ingress-only.example"}]}
                    },
                    {
                        "match": [{"uri": {"prefix": "/"}, "gateways": ["mesh"]}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://mesh.example"}]}
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    let mesh = translated.config.mesh.as_ref().expect("mesh block");
    assert_eq!(mesh.virtual_service_cors_policies.len(), 1);
    assert_eq!(
        cors_plugin_config_from_mesh_policy(&mesh.virtual_service_cors_policies[0].cors)["allowed_origins"],
        serde_json::json!([{ "exact": "https://mesh.example" }]),
        "the mesh-bound entry's policy must be carried, not the ingress-scoped first entry's"
    );
}

#[test]
fn virtual_service_cors_synthesis_is_sidecar_topology_only() {
    // Ambient also materializes __mesh-outbound-* routes, but VS CORS is a
    // client-SIDECAR behavior (the GA row's scope) — no plugin may be
    // synthesized for sidecarless topologies.
    let mesh: MeshConfig = serde_yaml::from_str(
        r#"
workloads:
  - spiffe_id: spiffe://cluster.local/ns/default/sa/svc
    service_name: svc
    namespace: default
    trust_domain: cluster.local
    service_account: svc
    addresses: ["10.0.0.9"]
    ports:
      - port: 8080
        protocol: http
        name: http
    selector:
      namespace: default
services:
  - name: svc
    namespace: default
    ports:
      - port: 8080
        protocol: http
        name: http
    workloads:
      - spiffe_id: spiffe://cluster.local/ns/default/sa/svc
virtual_service_cors_policies:
  - name: svc-cors
    namespace: default
    host: svc
    cors:
      allowed_origins:
        - exact: "https://fixture.example"
"#,
    )
    .expect("mesh yaml parses");
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let ambient_runtime = MeshRuntimeConfig {
        topology: MeshTopology::Ambient,
        ..runtime()
    };
    let prepared = prepare_gateway_config_for_mesh(config, &ambient_runtime).expect("mesh config");
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.id.starts_with("__mesh-outbound-")),
        "ambient still materializes outbound routes"
    );
    assert!(
        !prepared
            .plugin_configs
            .iter()
            .any(|plugin| plugin.id.starts_with("__mesh-cors-")),
        "no cors plugin may be synthesized for a sidecarless topology"
    );
}

#[test]
fn virtual_service_cors_policy_wildcard_padding_and_predicate_scoping() {
    // A whitespace-padded exact is a LITERAL matcher carried byte-for-byte
    // (issue #3254). The security property is that padding can never be
    // trimmed into something WIDER: " *" must stay the literal string " *",
    // never Istio's allow-all `*`, and a padded wildcard shape must never
    // become the plugin's native wildcard-subdomain syntax.
    for padded in [" *", " *.example.com", "*.example.com "] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-padded-wildcard",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": padded}]}
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        let plugin = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "cors")
            .unwrap_or_else(|| panic!("padded literal exact `{padded}` must project"));
        assert_eq!(
            plugin.config["allowed_origins"],
            serde_json::json!([{ "exact": padded }]),
            "padded exact `{padded}` must be carried verbatim, never trimmed into a wider matcher"
        );
        let carried = translated
            .config
            .mesh
            .as_ref()
            .expect("mesh block")
            .virtual_service_cors_policies
            .first()
            .unwrap_or_else(|| panic!("padded literal exact `{padded}` must ride the slice"));
        assert_eq!(
            cors_plugin_config_from_mesh_policy(&carried.cors),
            plugin.config
        );
    }

    // Values that are not `scheme://host[:port]` origins are still valid
    // LITERAL matchers: they are carried verbatim and can only ever match an
    // Origin header equal to that exact string. The origin grammar belongs to
    // the plugin's NATIVE plain-string form, which this path no longer uses,
    // so nothing here can be canonicalized into a wider matcher.
    for literal in [
        " https://app.example",
        "https://app.example ",
        "https://app.example/",
        "https://app.example/path",
        "https://app.example/foo/..",
        "https://app.example/%2e%2e",
        "https://user:pw@app.example",
        "ftp://app.example",
        "not a url",
    ] {
        let translated = translate_k8s_objects(
            &[k8s_object(
                "VirtualService",
                "vs-invalid-exact",
                serde_json::json!({
                    "hosts": ["svc.default.svc.cluster.local"],
                    "http": [{
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": literal}]}
                    }]
                }),
            )],
            k8s_options(),
        )
        .expect("VirtualService translates");
        let plugin = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "cors")
            .unwrap_or_else(|| panic!("literal exact `{literal}` must project"));
        assert_eq!(
            plugin.config["allowed_origins"],
            serde_json::json!([{ "exact": literal }])
        );
        ferrum_edge::plugins::validate_plugin_config("cors", &plugin.config)
            .expect("projected literal CORS config constructs");
    }

    // An EARLIER sidecar-applicable predicate-scoped entry SUPPRESSES the
    // carry (codex round 7): Istio routes `/api` through the scoped entry
    // (its own CORS), so promoting the later catch-all's policy host-wide
    // would enforce the wrong CORS on `/api` traffic — the materialized mesh
    // route has no path predicates to keep the two apart.
    let predicate_scoped = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-predicate-scoped",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://api-only.example"}]}
                    },
                    {
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://host-wide.example"}]}
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert!(
        predicate_scoped
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
            .unwrap_or(true),
        "an earlier scoped entry must suppress a later host-wide carry"
    );

    // Reversed order: the catch-all comes FIRST, so it wins all host traffic
    // in Istio's in-order evaluation and its policy carries — the later
    // scoped entry can never win traffic and is irrelevant.
    let host_wide_first = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-host-wide-first",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{"uri": {"prefix": "/"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://host-wide.example"}]}
                    },
                    {
                        "match": [{"uri": {"prefix": "/api"}}],
                        "route": [{"destination": {
                            "host": "svc.default.svc.cluster.local",
                            "port": {"number": 8080}
                        }}],
                        "corsPolicy": {"allowOrigins": [{"exact": "https://api-only.example"}]}
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    let mesh = host_wide_first.config.mesh.as_ref().expect("mesh block");
    assert_eq!(mesh.virtual_service_cors_policies.len(), 1);
    assert_eq!(
        cors_plugin_config_from_mesh_policy(&mesh.virtual_service_cors_policies[0].cors)["allowed_origins"],
        serde_json::json!([{ "exact": "https://host-wide.example" }]),
        "a first host-wide entry's policy carries; later scoped entries are unreachable"
    );

    // A VS whose ONLY corsPolicy-bearing entries are predicate-scoped carries
    // nothing (header-predicate variant exercises the fail-closed default arm).
    let scoped_only = translate_k8s_objects(
        &[k8s_object(
            "VirtualService",
            "vs-scoped-only",
            serde_json::json!({
                "hosts": ["svc.default.svc.cluster.local"],
                "http": [{
                    "match": [{
                        "uri": {"prefix": "/"},
                        "headers": {"x-canary": {"exact": "true"}}
                    }],
                    "route": [{"destination": {
                        "host": "svc.default.svc.cluster.local",
                        "port": {"number": 8080}
                    }}],
                    "corsPolicy": {"allowOrigins": [{"exact": "https://canary.example"}]}
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("VirtualService translates");
    assert!(
        scoped_only
            .config
            .mesh
            .as_ref()
            .map(|mesh| mesh.virtual_service_cors_policies.is_empty())
            .unwrap_or(true),
        "a header-scoped corsPolicy must not be promoted host-wide"
    );
}

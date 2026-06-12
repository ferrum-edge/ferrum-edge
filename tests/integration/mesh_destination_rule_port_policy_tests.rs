use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshDestinationRule, MeshLoadBalancer, MeshOutlierDetection, MeshSimpleLb,
    MeshTrafficPolicy,
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
        egress_stream_enabled: false,
        request_auth_require_exp: true,
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
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
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
    assert_eq!(port_override.http_max_requests_per_connection, Some(75));
    assert_eq!(port_override.http_idle_timeout_ms, Some(45_000));
    assert_eq!(port_override.h2_max_concurrent_streams, Some(250));

    // Dispatch projection: the per-port overlay reaches every referencing
    // proxy via `resolve_dispatch_port_overrides`.
    let dispatch_override = prepared.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&8080))
        .expect("proxy dispatch port override projected");
    assert_eq!(dispatch_override.http_max_requests_per_connection, Some(75));
    assert_eq!(dispatch_override.http_idle_timeout_ms, Some(45_000));
    assert_eq!(dispatch_override.h2_max_concurrent_streams, Some(250));
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
    // Fields not respecified by per-port survive from the fan-out:
    assert_eq!(port_override.http_max_requests_per_connection, Some(75));
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
    assert_eq!(port_override.http_max_requests_per_connection, Some(10));
    assert_eq!(port_override.http_idle_timeout_ms, Some(30_000));
    assert_eq!(port_override.h2_max_concurrent_streams, Some(20));

    // Phantom-port guard: 9090 isn't on any target, so it must NOT receive
    // the per-port overlay either (would be a phantom-port skip with warn).
    assert!(!prepared.upstreams[0].port_overrides.contains_key(&9090));
}

// `resolve_effective_proxy_for_target` is `pub(crate)`, so the per-field
// projection and Cow::Borrowed/Owned branches are tested inline in
// `src/proxy/mod.rs` (see the `resolve_effective_proxy_*` tests block).

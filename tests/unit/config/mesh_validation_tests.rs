//! `validate_mesh_config()` tests.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, ConditionMatch, EastWestGateway, IngressListenerUnsupported, JwtHeader,
    MAX_MESH_REMOTE_CLUSTERS, MeshConfig, MeshDestinationRule, MeshEndpoint, MeshJwtRule,
    MeshOutlierDetection, MeshPolicy, MeshProxyConfig, MeshRequestAuthentication, MeshRule,
    MeshService, MeshSidecar, MeshSidecarEgress, MeshSidecarIngress, MeshSubset,
    MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MtlsMode, MultiClusterConfig, NodeWaypointEndpoint, ParsedCidr,
    PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RemoteCluster, RequestMatch,
    Resolution, ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle, TrustBundleSet,
    Workload, WorkloadPort, WorkloadRef, WorkloadSelector, validate_mesh_config,
};
use std::collections::HashMap;
use std::net::IpAddr;

fn fresh_workload() -> Workload {
    let td = TrustDomain::new("prod.example.com").unwrap();
    Workload {
        spiffe_id: SpiffeId::from_parts(&td, "ns/svc/sa/api").unwrap(),
        selector: WorkloadSelector::default(),
        service_name: "api".into(),
        addresses: Vec::new(),
        ports: vec![WorkloadPort {
            port: 8443,
            protocol: AppProtocol::Http2,
            name: Some("https".into()),
        }],
        trust_domain: td,
        namespace: "svc".into(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: None,
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

#[test]
fn empty_mesh_config_passes_validation() {
    let errors = validate_mesh_config(&[], &[], &[], &[], &[], &[], None);
    assert!(errors.is_empty());
}

#[test]
fn workload_validates_trust_domain_consistency() {
    let mut wl = fresh_workload();
    // Replace spiffe_id with one in a DIFFERENT trust domain.
    wl.spiffe_id = SpiffeId::new("spiffe://other.example/ns/svc/sa/api").unwrap();
    let errors = validate_mesh_config(&[wl], &[], &[], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| e.contains("trust domain")),
        "expected trust-domain mismatch error, got: {:?}",
        errors
    );
}

#[test]
fn workload_rejects_empty_namespace() {
    let mut wl = fresh_workload();
    wl.namespace = String::new();
    let errors = validate_mesh_config(&[wl], &[], &[], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains(".namespace") && e.contains("must not be empty"))
    );
}

#[test]
fn workload_rejects_empty_service_name() {
    let mut wl = fresh_workload();
    wl.service_name = String::new();
    let errors = validate_mesh_config(&[wl], &[], &[], &[], &[], &[], None);
    assert!(errors.iter().any(|e| e.contains("service_name")));
}

#[test]
fn workload_validates_node_waypoint_endpoint() {
    let mut wl = fresh_workload();
    wl.node_waypoint = Some(NodeWaypointEndpoint {
        address: " ".into(),
        hbone_port: 0,
        spiffe_id: SpiffeId::new("spiffe://prod.example.com/ns/ferrum-system/sa/node-waypoint")
            .unwrap(),
        node_name: Some(" ".into()),
        node_uid: Some(" ".into()),
        network: Some(" ".into()),
        cluster: Some(" ".into()),
    });

    let errors = validate_mesh_config(&[wl], &[], &[], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("node_waypoint.address") && e.contains("must not be empty")),
        "expected address validation error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("node_waypoint.hbone_port") && e.contains("greater than 0")),
        "expected hbone_port validation error, got: {errors:?}"
    );
    for field in ["node_name", "node_uid", "network", "cluster"] {
        assert!(
            errors.iter().any(|e| e.contains(field)),
            "expected {field} validation error, got: {errors:?}"
        );
    }
}

#[test]
fn mesh_service_rejects_empty_name() {
    let svc = MeshService {
        cluster_ips: Vec::new(),
        name: String::new(),
        namespace: "default".into(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    };
    let errors = validate_mesh_config(&[], &[svc], &[], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("MeshService.name") && e.contains("must not be empty"))
    );
}

#[test]
fn mesh_ports_reject_zero_on_core_resources() {
    let mut wl = fresh_workload();
    wl.ports[0].port = 0;

    let mut service = MeshService {
        cluster_ips: Vec::new(),
        name: "svc".into(),
        namespace: "default".into(),
        ports: vec![ServicePort {
            port: 0,
            protocol: AppProtocol::Http,
            name: Some("http".into()),
            target_port: None,
        }],
        workloads: Vec::new(),
        protocol_overrides: HashMap::from([(0, AppProtocol::Grpc)]),
    };
    service.protocol_overrides.insert(8080, AppProtocol::Http2);

    let mut peer_auth = PeerAuthentication {
        name: "pa".into(),
        namespace: "default".into(),
        scope: None,
        selector: None,
        mtls_mode: MtlsMode::Strict,
        port_overrides: HashMap::from([(0, MtlsMode::Permissive)]),
    };
    peer_auth.port_overrides.insert(15006, MtlsMode::Strict);

    let service_entry = ServiceEntry {
        name: "se".into(),
        namespace: "default".into(),
        hosts: vec!["api.external.test".into()],
        endpoints: vec![MeshEndpoint {
            address: "".into(),
            ports: HashMap::from([("http".into(), 0)]),
            labels: HashMap::new(),
            network: None,
        }],
        resolution: Resolution::Static,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 0,
            protocol: AppProtocol::Http,
            name: Some("http".into()),
            target_port: None,
        }],
        export_to: Vec::new(),
        workload_selector: None,
    };

    let errors = validate_mesh_config(
        &[wl],
        &[service],
        &[],
        &[peer_auth],
        &[service_entry],
        &[],
        None,
    );

    assert!(
        errors
            .iter()
            .any(|e| e.contains("Workload") && e.contains("port must be greater than 0")),
        "expected workload port error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("MeshService") && e.contains("ports[0]")),
        "expected mesh service port error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("protocol_overrides[0]")),
        "expected protocol override port error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("port_overrides[0]")),
        "expected peer auth port override error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("ServiceEntry") && e.contains("ports[0]")),
        "expected service entry port error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("endpoints[0].address")),
        "expected endpoint address error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("endpoints[0].ports['http']")),
        "expected endpoint named port error, got: {errors:?}"
    );
}

#[test]
fn mesh_config_validate_rejects_zero_ports_on_full_mesh_resources() {
    let mesh = MeshConfig {
        destination_rules: vec![MeshDestinationRule {
            name: "dr".into(),
            namespace: "default".into(),
            host: "api.default.svc.cluster.local".into(),
            traffic_policy: None,
            port_level_settings: HashMap::from([(0, MeshTrafficPolicy::default())]),
            subsets: Vec::new(),
        }],
        sidecars: vec![MeshSidecar {
            name: "sc".into(),
            namespace: "default".into(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: vec![MeshSidecarEgress {
                hosts: vec!["./*".into()],
                port: Some(0),
            }],
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        }],
        ..MeshConfig::default()
    };

    let errors = mesh.validate();

    assert!(
        errors.iter().any(|e| e.contains("port_level_settings[0]")),
        "expected DestinationRule port-level settings error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("MeshSidecar") && e.contains("egress[0].port")),
        "expected Sidecar egress port error, got: {errors:?}"
    );
}

#[test]
fn mesh_config_validate_rejects_empty_destination_rule_and_sidecar_fields() {
    let mesh = MeshConfig {
        destination_rules: vec![MeshDestinationRule {
            name: "".into(),
            namespace: "".into(),
            host: "".into(),
            traffic_policy: None,
            port_level_settings: HashMap::new(),
            subsets: vec![MeshSubset {
                name: "".into(),
                labels: HashMap::new(),
                traffic_policy: None,
            }],
        }],
        sidecars: vec![MeshSidecar {
            name: "".into(),
            namespace: "".into(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: vec![
                MeshSidecarEgress {
                    hosts: Vec::new(),
                    port: None,
                },
                MeshSidecarEgress {
                    hosts: vec!["".into(), "alpha/".into(), "alpha/reviews/extra".into()],
                    port: None,
                },
            ],
            ingress_declared: false,
            ingress: Vec::new(),
            outbound_traffic_policy: None,
        }],
        ..MeshConfig::default()
    };

    let errors = mesh.validate();

    for expected in [
        "MeshDestinationRule.name",
        "MeshDestinationRule ''.namespace",
        "MeshDestinationRule ''.host",
        "subsets[0].name",
        "MeshSidecar.name",
        "MeshSidecar ''.namespace",
        "egress[0].hosts must not be empty",
        "egress[1].hosts[0]",
        "egress[1].hosts[1]",
        "egress[1].hosts[2]",
    ] {
        assert!(
            errors.iter().any(|e| e.contains(expected)),
            "expected error containing {expected:?}, got: {errors:?}"
        );
    }
}

#[test]
fn mesh_policy_principal_must_have_at_least_one_field() {
    let policy = MeshPolicy {
        name: "p".into(),
        namespace: "default".into(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: None,
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                ..Default::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| e.contains("at least one of")),
        "expected principal-empty error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_request_match_must_have_at_least_one_constraint() {
    let policy = MeshPolicy {
        name: "p".into(),
        namespace: "default".into(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://td/*".into()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch::default()],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| e.contains("methods/paths/hosts")),
        "expected to-empty error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_glob_pattern_must_be_valid() {
    let policy = MeshPolicy {
        name: "p".into(),
        namespace: "default".into(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                // "[" without closing bracket is invalid glob.
                spiffe_id_pattern: Some("spiffe://prod/[unclosed".into()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                ..Default::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| e.contains("not a valid glob")),
        "expected glob error, got: {:?}",
        errors
    );
}

fn policy_with_request_match(request: RequestMatch) -> MeshPolicy {
    MeshPolicy {
        name: "p".into(),
        namespace: "default".into(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://td/*".into()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            to: vec![request],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

#[test]
fn mesh_policy_rejects_unsupported_when_condition_key() {
    let mut policy = policy_with_request_match(RequestMatch {
        methods: vec!["GET".into()],
        ..RequestMatch::default()
    });
    policy.rules[0].when.push(ConditionMatch {
        key: "destination.labels[app]".into(),
        values: vec!["payments".into()],
        not_values: Vec::new(),
    });

    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| {
            e.contains("rules[0].when[0].key")
                && e.contains("destination.labels[app]")
                && e.contains("unsupported")
        }),
        "expected unsupported when-key error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_when_condition_without_values() {
    let mut policy = policy_with_request_match(RequestMatch {
        methods: vec!["GET".into()],
        ..RequestMatch::default()
    });
    policy.rules[0].when.push(ConditionMatch {
        key: "connection.sni".into(),
        values: Vec::new(),
        not_values: Vec::new(),
    });

    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| { e.contains("rules[0].when[0]") && e.contains("values or not_values") }),
        "expected missing condition values error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_malformed_ip_when_condition_values() {
    let mut policy = policy_with_request_match(RequestMatch {
        methods: vec!["GET".into()],
        ..RequestMatch::default()
    });
    policy.rules[0].when.push(ConditionMatch {
        key: "source.ip".into(),
        values: vec!["10.0.0.0/40".into()],
        not_values: Vec::new(),
    });

    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| {
            e.contains("rules[0].when[0].values[0]")
                && e.contains("10.0.0.0/40")
                && e.contains("prefix length")
        }),
        "expected invalid source.ip condition error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_mapped_ipv6_when_condition_prefix_below_mapping_bits() {
    let mut policy = policy_with_request_match(RequestMatch {
        methods: vec!["GET".into()],
        ..RequestMatch::default()
    });
    policy.rules[0].when.push(ConditionMatch {
        key: "remote.ip".into(),
        values: vec!["::ffff:10.0.0.0/95".into()],
        not_values: Vec::new(),
    });

    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.iter().any(|e| {
            e.contains("rules[0].when[0].values[0]")
                && e.contains("::ffff:10.0.0.0/95")
                && e.contains("IPv4-mapped IPv6")
        }),
        "expected invalid mapped IPv6 condition error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_malformed_source_negation_ip_blocks() {
    let err = ParsedCidr::parse("10.0.0.0/40").unwrap_err();
    assert!(
        err.contains("10.0.0.0/40") && err.contains("prefix length"),
        "expected prefix-length error, got: {err}"
    );
    let err = ParsedCidr::parse("::ffff:10.0.0.0/95").unwrap_err();
    assert!(
        err.contains("::ffff:10.0.0.0/95") && err.contains("IPv4-mapped IPv6"),
        "expected IPv4-mapped IPv6 error, got: {err}"
    );
}

#[test]
fn mesh_policy_rejects_host_pattern_with_empty_port() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["example.com:".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid host pattern")),
        "expected host-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_host_pattern_with_non_numeric_port() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["example.com:abc".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid host pattern")),
        "expected host-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_host_pattern_with_out_of_range_port() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["example.com:70000".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid host pattern")),
        "expected host-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_bracketed_host_pattern_with_out_of_range_port() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["[2001:db8::1]:70000".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid host pattern")),
        "expected host-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_host_pattern_with_multiple_unbracketed_colons() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["api.default:443:abc".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid host pattern")),
        "expected host-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_accepts_wildcard_host_port_pattern() {
    let policy = policy_with_request_match(RequestMatch {
        hosts: vec!["api.default:*".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors.is_empty(),
        "expected no errors for `host:*`, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_mid_string_port_pattern() {
    let policy = policy_with_request_match(RequestMatch {
        port_patterns: vec!["8*9".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid port pattern")),
        "expected port-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn mesh_policy_rejects_named_port_pattern() {
    let policy = policy_with_request_match(RequestMatch {
        port_patterns: vec!["http".into()],
        ..RequestMatch::default()
    });
    let errors = validate_mesh_config(&[], &[], &[policy], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("not a valid port pattern")),
        "expected port-pattern error, got: {:?}",
        errors
    );
}

#[test]
fn peer_authentication_requires_namespace() {
    let pa = PeerAuthentication {
        name: "pa".into(),
        namespace: String::new(),
        scope: None,
        selector: None,
        mtls_mode: ferrum_edge::modes::mesh::config::MtlsMode::Strict,
        port_overrides: HashMap::new(),
    };
    let errors = validate_mesh_config(&[], &[], &[], &[pa], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains(".namespace") && e.contains("must not be empty"))
    );
}

#[test]
fn peer_authentication_rejects_client_side_mtls_mode() {
    let pa = PeerAuthentication {
        name: "pa".into(),
        namespace: "default".into(),
        scope: None,
        selector: None,
        mtls_mode: ferrum_edge::modes::mesh::config::MtlsMode::Simple,
        port_overrides: HashMap::new(),
    };
    let errors = validate_mesh_config(&[], &[], &[], &[pa], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("mtls_mode") && e.contains("invalid for server-side policy")),
        "expected invalid mtls_mode error, got: {:?}",
        errors
    );
}

#[test]
fn peer_authentication_rejects_client_side_port_override_mtls_mode() {
    let mut port_overrides = HashMap::new();
    port_overrides.insert(
        15006,
        ferrum_edge::modes::mesh::config::MtlsMode::IstioMutual,
    );
    let pa = PeerAuthentication {
        name: "pa".into(),
        namespace: "default".into(),
        scope: None,
        selector: None,
        mtls_mode: ferrum_edge::modes::mesh::config::MtlsMode::Strict,
        port_overrides,
    };
    let errors = validate_mesh_config(&[], &[], &[], &[pa], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("port_overrides[15006]")
                && e.contains("invalid for server-side policy")),
        "expected invalid port override mtls_mode error, got: {:?}",
        errors
    );
}

#[test]
fn request_authentication_accepts_inline_jwks_multi_audience_and_custom_locations() {
    let ra = MeshRequestAuthentication {
        name: "jwt".into(),
        namespace: "default".into(),
        scope: PolicyScope::MeshWide,
        jwt_rules: vec![MeshJwtRule {
            issuer: "https://issuer.example.com".into(),
            audiences: vec!["api-a".into(), "api-b".into()],
            jwks_uri: None,
            jwks: Some(r#"{"keys":[]}"#.into()),
            from_headers: vec![JwtHeader {
                name: "X-Token".into(),
                prefix: Some("Token ".into()),
            }],
            from_params: vec!["access_token".into()],
            forward_original_token: false,
        }],
    };

    let errors = validate_mesh_config(&[], &[], &[], &[], &[], &[ra], None);
    assert!(
        errors.is_empty(),
        "expected inline jwks, multi-audience, and custom locations to validate, got: {errors:?}"
    );
}

#[test]
fn service_entry_requires_hosts() {
    let se = ServiceEntry {
        name: "se".into(),
        namespace: "default".into(),
        hosts: Vec::new(),
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: Vec::new(),
        export_to: Vec::new(),
        workload_selector: None,
    };
    let errors = validate_mesh_config(&[], &[], &[], &[], &[se], &[], None);
    assert!(errors.iter().any(|e| e.contains("hosts must not be empty")));
}

#[test]
fn service_entry_endpoints_only_with_static_resolution() {
    let se = ServiceEntry {
        name: "se".into(),
        namespace: "default".into(),
        hosts: vec!["api.example.com".into()],
        endpoints: vec![MeshEndpoint {
            address: "10.0.0.1".into(),
            ports: HashMap::new(),
            labels: HashMap::new(),
            network: None,
        }],
        // DNS resolution + endpoints = invalid.
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: Vec::new(),
        export_to: Vec::new(),
        workload_selector: None,
    };
    let errors = validate_mesh_config(&[], &[], &[], &[], &[se], &[], None);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("endpoints are only valid")),
        "expected resolution error, got: {:?}",
        errors
    );
}

#[test]
fn trust_bundle_set_must_have_authorities() {
    let tbs = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("td.test").unwrap(),
            x509_authorities: Vec::new(),
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };
    let errors = validate_mesh_config(&[], &[], &[], &[], &[], &[], Some(&tbs));
    assert!(
        errors.iter().any(|e| e.contains("no authorities")),
        "expected empty-bundle error, got: {:?}",
        errors
    );
}

#[test]
fn trust_bundle_set_rejects_invalid_base64() {
    let tbs = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("td.test").unwrap(),
            x509_authorities: vec!["not base64!".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };
    let errors = validate_mesh_config(&[], &[], &[], &[], &[], &[], Some(&tbs));
    assert!(
        errors.iter().any(|e| e.contains("invalid base64")),
        "expected base64 error, got: {:?}",
        errors
    );
}

#[test]
fn multi_cluster_remote_cluster_requires_federated_trust_bundle_when_bundles_are_configured() {
    use base64::Engine;

    let engine = base64::engine::general_purpose::STANDARD;
    let trust_bundles = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("local.test").unwrap(),
            x509_authorities: vec![engine.encode(b"local-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };
    let mut mesh = MeshConfig {
        trust_bundles: Some(trust_bundles),
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "cluster-b".to_string(),
                trust_domain: TrustDomain::new("remote.test").unwrap(),
                network: Some("network-b".to_string()),
                control_plane_url: None,
                federation_endpoint: None,
                discovery_credential_ref: None,
            }],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("no matching federated trust bundle")),
        "expected federated bundle error, got: {errors:?}"
    );

    mesh.trust_bundles
        .as_mut()
        .unwrap()
        .federated
        .push(TrustBundle {
            trust_domain: TrustDomain::new("remote.test").unwrap(),
            x509_authorities: vec![engine.encode(b"remote-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        });
    assert!(mesh.validate().is_empty());
}

#[test]
fn multi_cluster_rejects_blank_discovery_credential_ref() {
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "cluster-b".to_string(),
                trust_domain: TrustDomain::new("remote.test").unwrap(),
                network: None,
                control_plane_url: None,
                federation_endpoint: None,
                // Blank-when-set must fail the slice at validation rather than
                // resolving to a credential that cannot be found at runtime.
                discovery_credential_ref: Some("   ".to_string()),
            }],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("discovery_credential_ref") && e.contains("must not be empty")),
        "blank discovery_credential_ref must be rejected at validation, got: {errors:?}"
    );
}

fn remote_cluster(name: &str) -> RemoteCluster {
    RemoteCluster {
        name: name.to_string(),
        trust_domain: TrustDomain::new("remote.test").unwrap(),
        network: None,
        control_plane_url: None,
        federation_endpoint: None,
        discovery_credential_ref: None,
    }
}

#[test]
fn multi_cluster_rejects_remote_cluster_name_with_surrounding_whitespace() {
    // `remote_discovery_audience` trims the cluster id into the JWT `aud`, so a
    // padded `RemoteCluster.name` would mint the same audience as its trimmed
    // form while still keying discovery state under the raw spelling. Reject
    // the padded spelling at validation (no silent rewrite) before any poller
    // is spawned.
    for padded in [" cluster-b", "cluster-b ", "\tcluster-b\n"] {
        let mesh = MeshConfig {
            multi_cluster: Some(MultiClusterConfig {
                remote_clusters: vec![remote_cluster(padded)],
                ..MultiClusterConfig::default()
            }),
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        assert!(
            errors
                .iter()
                .any(|err| err.contains("leading/trailing whitespace")),
            "padded RemoteCluster.name `{padded:?}` must be rejected, got: {errors:?}"
        );
    }
}

#[test]
fn multi_cluster_rejects_whitespace_aliased_remote_cluster_names() {
    // `"cluster-b"` and `" cluster-b "` are distinct raw strings but collapse to
    // the same JWT audience after trim. Uniqueness must run in that canonical
    // identity domain so the pair cannot be admitted as two destinations.
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters: vec![remote_cluster("cluster-b"), remote_cluster(" cluster-b ")],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("leading/trailing whitespace")),
        "whitespace alias must be rejected, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|err| err.contains("duplicate name")),
        "whitespace alias must also collide in the canonical audience identity domain, got: {errors:?}"
    );
}

#[test]
fn multi_cluster_rejects_local_cluster_with_surrounding_whitespace() {
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            local_cluster: Some(" cluster-a ".to_string()),
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| {
            err.contains("local_cluster") && err.contains("leading/trailing whitespace")
        }),
        "padded local_cluster must be rejected, got: {errors:?}"
    );
}

#[test]
fn multi_cluster_rejects_exact_duplicate_remote_cluster_names() {
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters: vec![remote_cluster("cluster-b"), remote_cluster("cluster-b")],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| err.contains("duplicate name")),
        "exact duplicate RemoteCluster.name must be rejected, got: {errors:?}"
    );
}

#[test]
fn multi_cluster_rejects_too_many_remote_clusters() {
    let remote_clusters: Vec<RemoteCluster> = (0..=MAX_MESH_REMOTE_CLUSTERS)
        .map(|index| RemoteCluster {
            name: format!("cluster-{index}"),
            trust_domain: TrustDomain::new(format!("remote-{index}.test")).unwrap(),
            network: None,
            control_plane_url: None,
            federation_endpoint: None,
            discovery_credential_ref: None,
        })
        .collect();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            remote_clusters,
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|err| err.contains("remote_clusters") && err.contains("max")),
        "expected remote cluster cap error, got: {errors:?}"
    );
}

#[test]
fn multi_cluster_rejects_duplicate_east_west_sni_hosts_on_same_backend_port() {
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "cluster-b".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: None,
                    network: None,
                },
                EastWestGateway {
                    name: "cluster-c".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-c.example".to_string(),
                    port: 443,
                    sni_hosts: vec!["API.Global".to_string()],
                    trust_domain: None,
                    network: None,
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "expected overlapping-SNI error, got: {errors:?}"
    );
}

/// Duplicate-SNI detection is scoped to `(network, trust_domain, sni)`, so two
/// east-west gateways claiming the SAME SNI host on DIFFERENT networks (or
/// different trust domains) are NOT a collision — on a Sidecar/Ambient CLIENT
/// the same service can be hosted by multiple remote networks/clusters, each
/// fronted by its own east-west gateway claiming that service's FQDN. The client
/// routes them to distinct `(network, trust_domain)` groups. Only the same SNI
/// on the SAME network AND trust domain is a duplicate (covered by the test
/// above).
#[test]
fn multi_cluster_allows_same_east_west_sni_on_different_network_or_trust_domain() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let td_c = TrustDomain::new("cluster-c.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                // Same SNI, DIFFERENT network (net-b vs net-c), same TD.
                EastWestGateway {
                    name: "ew-net-b".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-net-c".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-c.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-c".to_string()),
                },
                // Same SNI, same network (net-b), DIFFERENT trust domain.
                EastWestGateway {
                    name: "ew-net-b-td-c".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-bc.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: Some(td_c.clone()),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        !errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "same SNI on different (network, trust_domain) must NOT be an overlap, got: {errors:?}"
    );
}

/// A gateway that OMITS `trust_domain` is a wildcard candidate for EVERY trust
/// domain at selection time, so on a given network it OVERLAPS a specific-TD
/// gateway claiming the same SNI — list order would silently decide which wins,
/// and a remote workload in the specific TD could be routed to the wrong gateway.
/// Such an overlap is rejected as a duplicate (treat `None` as overlapping every
/// trust domain), forcing the operator to disambiguate.
#[test]
fn multi_cluster_rejects_wildcard_and_specific_trust_domain_same_sni_same_network() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                // Specific-TD gateway for net-b claiming api.global.
                EastWestGateway {
                    name: "ew-net-b-specific".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                // TD-LESS (wildcard) gateway for net-b claiming the SAME SNI —
                // it overlaps the specific-TD gateway above on (net-b, api.global).
                EastWestGateway {
                    name: "ew-net-b-wildcard".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["api.global".to_string()],
                    trust_domain: None,
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors.iter().any(
            |err| err.contains("sni_hosts overlap") && err.contains("overlapping trust domain")
        ),
        "a TD-less wildcard overlapping a specific-TD gateway on the same network+SNI must be \
         rejected, got: {errors:?}"
    );
}

/// [R4-1] The overlap check uses the SAME wildcard-aware `hosts_overlap`
/// semantics the selector uses, so a `*.default.svc.cluster.local` wildcard
/// gateway and a `reviews.default.svc.cluster.local` exact gateway on the same
/// network + trust domain — which BOTH route `reviews.default.svc.cluster.local`
/// — are rejected even though their literal SNI strings differ.
#[test]
fn multi_cluster_rejects_wildcard_sni_overlapping_exact_sni_same_network() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "ew-wildcard".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["*.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-exact".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["reviews.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "a wildcard SNI overlapping an exact SNI on the same network+TD must be rejected (literal \
         strings differ but both route the same FQDN), got: {errors:?}"
    );
}

/// East-west gateway selection accepts both a service base FQDN and its generated
/// `p<port>.<base>` alias for multi-port cross-cluster dials. A same-network,
/// overlapping-trust-domain base gateway and alias gateway would therefore both
/// be candidates for alias traffic, so validation rejects the ambiguous pair.
#[test]
fn multi_cluster_rejects_base_fqdn_and_per_port_alias_same_network() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "ew-base".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["reviews.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-alias".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["p9090.reviews.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "base FQDN and derived per-port alias on the same network+TD must be rejected, got: \n         {errors:?}"
    );
}

fn mesh_with_same_scope_east_west_snis(first: &str, second: &str) -> MeshConfig {
    let trust_domain = TrustDomain::new("cluster-b.local").unwrap();
    MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "ew-first".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec![first.to_string()],
                    trust_domain: Some(trust_domain.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-second".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec![second.to_string()],
                    trust_domain: Some(trust_domain),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    }
}

#[test]
fn multi_cluster_rejects_base_fqdn_and_wildcard_alias_owner() {
    let mesh = mesh_with_same_scope_east_west_snis(
        "reviews.default.svc.cluster.local",
        "*.reviews.default.svc.cluster.local",
    );

    let errors = mesh.validate();
    assert!(
        errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "a wildcard that owns every per-port alias overlaps the base-FQDN gateway, got: \
         {errors:?}"
    );
}

#[test]
fn multi_cluster_keeps_non_service_prefixed_hosts_distinct() {
    let mesh = mesh_with_same_scope_east_west_snis("example.com", "p9090.example.com");

    let errors = mesh.validate();
    assert!(
        !errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "explicit non-service hosts do not participate in generated alias ownership, got: \
         {errors:?}"
    );
}

#[test]
fn multi_cluster_does_not_treat_noncanonical_port_label_as_generated_alias() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "ew-base".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["reviews.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-noncanonical".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["p65536.reviews.default.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        !errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "an out-of-range port label is not generated by the runtime and must remain an ordinary, \
         distinct hostname, got: {errors:?}"
    );
}

/// A wildcard and exact SNI that DON'T overlap (different subdomains) on the same
/// network + trust domain are NOT a collision.
#[test]
fn multi_cluster_allows_non_overlapping_wildcard_and_exact_sni() {
    let td_b = TrustDomain::new("cluster-b.local").unwrap();
    let mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![
                EastWestGateway {
                    name: "ew-wildcard-foo".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["*.foo.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
                EastWestGateway {
                    name: "ew-exact-bar".to_string(),
                    namespace: "mesh-system".to_string(),
                    host: "eastwest-b2.example".to_string(),
                    port: 15443,
                    sni_hosts: vec!["reviews.bar.svc.cluster.local".to_string()],
                    trust_domain: Some(td_b.clone()),
                    network: Some("net-b".to_string()),
                },
            ],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        !errors.iter().any(|err| err.contains("sni_hosts overlap")),
        "non-overlapping wildcard/exact SNIs must NOT be a collision, got: {errors:?}"
    );
}

#[test]
fn gateway_config_validate_mesh_fields_dispatches() {
    let cfg = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![Workload {
                spiffe_id: SpiffeId::new("spiffe://other/ns/foo/sa/bar").unwrap(),
                selector: WorkloadSelector::default(),
                service_name: "x".into(),
                addresses: Vec::new(),
                ports: Vec::new(),
                trust_domain: TrustDomain::new("td").unwrap(),
                namespace: "default".into(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            }],
            ..Default::default()
        })),
        ..Default::default()
    };
    let errors = cfg.validate_mesh_fields();
    assert!(!errors.is_empty(), "expected at least one error");
}

#[test]
fn sidecar_host_pattern_accepts_valid_patterns() {
    let valid_patterns = [
        "*/*",
        "*/host.example.com",
        "./host.example.com",
        "default/*",
        "default/reviews.default.svc.cluster.local",
        "~/*",
        "bare-host",
        "*.example.com",
    ];
    for pattern in valid_patterns {
        let mesh = MeshConfig {
            sidecars: vec![MeshSidecar {
                name: "sc".into(),
                namespace: "default".into(),
                workload_selector: None,
                egress_inherits_defaults: false,
                egress: vec![MeshSidecarEgress {
                    hosts: vec![pattern.to_string()],
                    port: None,
                }],
                ingress_declared: false,
                ingress: Vec::new(),
                outbound_traffic_policy: None,
            }],
            ..MeshConfig::default()
        };
        let errors = mesh.validate();
        let host_errors: Vec<_> = errors
            .iter()
            .filter(|e| e.contains("not a valid Sidecar host pattern"))
            .collect();
        assert!(
            host_errors.is_empty(),
            "pattern {pattern:?} should be accepted, but got: {host_errors:?}"
        );
    }
}

#[test]
fn workload_ref_serializes_only_spiffe_id_field() {
    let r = WorkloadRef {
        spiffe_id: SpiffeId::new("spiffe://td/ns/foo").unwrap(),
    };
    let s = serde_json::to_value(&r).unwrap();
    assert!(s.is_object());
    assert_eq!(s.as_object().unwrap().len(), 1);
}

// ── ParsedCidr::contains / canonicalization tests ─────────────────────────

#[test]
fn parsed_cidr_ipv4_slash8_contains_and_rejects() {
    let cidr = ParsedCidr::parse("10.0.0.0/8").unwrap();
    let inside: IpAddr = "10.1.2.3".parse().unwrap();
    let outside: IpAddr = "11.0.0.1".parse().unwrap();
    assert!(
        cidr.contains(inside),
        "10.1.2.3 should be inside 10.0.0.0/8"
    );
    assert!(
        !cidr.contains(outside),
        "11.0.0.1 should not be inside 10.0.0.0/8"
    );
}

#[test]
fn parsed_cidr_ipv4_slash32_host_route() {
    let cidr = ParsedCidr::parse("192.168.1.5/32").unwrap();
    let exact: IpAddr = "192.168.1.5".parse().unwrap();
    let other: IpAddr = "192.168.1.6".parse().unwrap();
    assert!(cidr.contains(exact), "/32 should match the exact IP");
    assert!(!cidr.contains(other), "/32 should not match adjacent IP");
}

#[test]
fn parsed_cidr_slash0_matches_everything() {
    let cidr_v4 = ParsedCidr::parse("0.0.0.0/0").unwrap();
    let any_v4: IpAddr = "1.2.3.4".parse().unwrap();
    assert!(cidr_v4.contains(any_v4), "0.0.0.0/0 should match any IPv4");

    let cidr_v6 = ParsedCidr::parse("::/0").unwrap();
    let any_v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(cidr_v6.contains(any_v6), "::/0 should match any IPv6");
}

#[test]
fn parsed_cidr_ipv4_mapped_ipv6_canonicalized_to_v4() {
    // ::ffff:10.0.0.0/104 is IPv4-mapped and should canonicalize to 10.0.0.0/8.
    let cidr = ParsedCidr::parse("::ffff:10.0.0.0/104").unwrap();
    // A plain IPv4 address inside the block should match.
    let inside_v4: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        cidr.contains(inside_v4),
        "10.0.0.1 should be inside ::ffff:10.0.0.0/104 (≡ 10.0.0.0/8)"
    );
    // A mapped IPv6 form of the same address should also match.
    let inside_mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
    assert!(
        cidr.contains(inside_mapped),
        "::ffff:10.0.0.1 should be inside the canonicalized block"
    );
    // An address outside the /8 should not match.
    let outside: IpAddr = "11.0.0.1".parse().unwrap();
    assert!(
        !cidr.contains(outside),
        "11.0.0.1 should not be inside 10.0.0.0/8"
    );
}

#[test]
fn parsed_cidr_family_mismatch_returns_false() {
    let v4_cidr = ParsedCidr::parse("10.0.0.0/8").unwrap();
    let v6_addr: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(
        !v4_cidr.contains(v6_addr),
        "IPv4 block should not match a non-mapped IPv6 address"
    );

    let v6_cidr = ParsedCidr::parse("2001:db8::/32").unwrap();
    let v4_addr: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        !v6_cidr.contains(v4_addr),
        "IPv6 block should not match an IPv4 address"
    );
}

#[test]
fn parsed_cidr_parse_trims_surrounding_whitespace() {
    let cidr = ParsedCidr::parse("  10.0.0.0/8  ").unwrap();
    let inside: IpAddr = "10.1.2.3".parse().unwrap();
    assert!(cidr.contains(inside));
}

#[test]
fn parsed_cidr_bare_ip_treated_as_host_route() {
    let cidr_v4 = ParsedCidr::parse("192.168.1.1").unwrap();
    let exact: IpAddr = "192.168.1.1".parse().unwrap();
    let other: IpAddr = "192.168.1.2".parse().unwrap();
    assert!(cidr_v4.contains(exact));
    assert!(!cidr_v4.contains(other));
}

// ── Sidecar ingress[] listener resolution (F6 §6.2) ──────────────────────

fn ingress_entry(port: u16, protocol: AppProtocol, endpoint: &str) -> MeshSidecarIngress {
    MeshSidecarIngress {
        port,
        protocol,
        name: None,
        bind: None,
        default_endpoint: endpoint.to_string(),
    }
}

#[test]
fn ingress_resolve_accepts_loopback_v4_endpoint() {
    let resolved = ingress_entry(8443, AppProtocol::Http, "127.0.0.1:8080")
        .resolve()
        .expect("loopback v4 endpoint resolves");
    assert_eq!(resolved.port, 8443);
    assert_eq!(resolved.endpoint_host, "127.0.0.1");
    assert_eq!(resolved.endpoint_port, 8080);
}

#[test]
fn ingress_resolve_maps_unspecified_v4_to_loopback() {
    // 0.0.0.0 (instance IP) maps to loopback for a co-located sidecar app.
    let resolved = ingress_entry(8443, AppProtocol::Http2, "0.0.0.0:9090")
        .resolve()
        .expect("0.0.0.0 endpoint resolves to loopback");
    assert_eq!(resolved.endpoint_host, "127.0.0.1");
    assert_eq!(resolved.endpoint_port, 9090);
}

#[test]
fn ingress_resolve_preserves_v6_address_family() {
    let resolved = ingress_entry(8443, AppProtocol::Grpc, "[::1]:7000")
        .resolve()
        .expect("v6 loopback resolves");
    assert_eq!(resolved.endpoint_host, "::1");
    assert_eq!(resolved.endpoint_port, 7000);
    // The unspecified v6 address maps to ::1 too.
    let resolved6 = ingress_entry(8443, AppProtocol::Http, "[::]:7000")
        .resolve()
        .expect("v6 unspecified resolves to loopback");
    assert_eq!(resolved6.endpoint_host, "::1");
}

#[test]
fn ingress_resolve_rejects_unknown_protocol() {
    // Codex round-3 P2: a Sidecar `ingress[]` listener whose protocol is
    // `AppProtocol::Unknown` must FAIL CLOSED (defer), not be routed as HTTP. On
    // the native/file/xDS path `MeshSidecarIngress.protocol` deserializes
    // directly: an OMITTED `protocol` falls back to `AppProtocol::default()`
    // (`Unknown`) and an explicit `"unknown"` parses to `Unknown`. Either way the
    // source did not declare a routable HTTP-family listener, so `resolve()`
    // defers it as a non-HTTP listener — matching the K8s translator (which maps
    // a missing/garbled protocol to a non-HTTP `AppProtocol`) and the documented
    // fail-closed rule. This is independent of the service-port default path's
    // `unknown → HTTP` convention (a separate predicate).
    assert_eq!(
        ingress_entry(8443, AppProtocol::Unknown, "127.0.0.1:8080").resolve(),
        Err(IngressListenerUnsupported::NonHttpProtocol),
        "an Unknown-protocol ingress listener must defer, never route as HTTP"
    );
}

#[test]
fn ingress_omitted_protocol_deserializes_to_unknown_then_defers() {
    // Native/file/xDS parity with the K8s path: a Sidecar `ingress[]` entry that
    // OMITS `protocol` must deserialize (the field is `#[serde(default)]`), land
    // on `AppProtocol::Unknown`, and DEFER at `resolve()` — never be guessed onto
    // the HTTP request path. Mirrors `sidecar_ingress_missing_protocol_is_deferred`
    // on the K8s translator side.
    let entry: MeshSidecarIngress = serde_json::from_value(serde_json::json!({
        "port": 8443,
        "default_endpoint": "127.0.0.1:8080"
        // protocol intentionally omitted
    }))
    .expect("an omitted protocol must still deserialize (defaulted field)");
    assert_eq!(
        entry.protocol,
        AppProtocol::Unknown,
        "an omitted ingress protocol defaults to Unknown"
    );
    assert_eq!(
        entry.resolve(),
        Err(IngressListenerUnsupported::NonHttpProtocol),
        "an omitted (Unknown) protocol defers fail-closed, it does not route"
    );

    // An explicit `"unknown"` string parses to `Unknown` and defers identically.
    let explicit: MeshSidecarIngress = serde_json::from_value(serde_json::json!({
        "port": 8443,
        "protocol": "unknown",
        "default_endpoint": "127.0.0.1:8080"
    }))
    .expect("an explicit unknown protocol deserializes");
    assert_eq!(explicit.protocol, AppProtocol::Unknown);
    assert_eq!(
        explicit.resolve(),
        Err(IngressListenerUnsupported::NonHttpProtocol)
    );
}

#[test]
fn ingress_resolved_listener_endpoint_revalidation() {
    use ferrum_edge::modes::mesh::config::ResolvedIngressListener;
    let valid = ResolvedIngressListener {
        port: 8443,
        endpoint_host: "127.0.0.1".to_string(),
        endpoint_port: 8080,
        owner_namespace: "default".to_string(),
        owner_service: "reviews".to_string(),
    };
    assert!(valid.endpoint_is_valid(), "loopback v4 host:port is valid");

    let v6 = ResolvedIngressListener {
        endpoint_host: "::1".to_string(),
        ..valid.clone()
    };
    assert!(v6.endpoint_is_valid(), "loopback v6 host:port is valid");

    // Codex round-2 P2: a carried OFF-BOX host must fail re-validation.
    let off_box = ResolvedIngressListener {
        endpoint_host: "10.0.0.5".to_string(),
        ..valid.clone()
    };
    assert!(
        !off_box.endpoint_is_valid(),
        "an off-box backend host must fail re-validation"
    );

    // A carried `:0` backend port fails.
    let zero_backend = ResolvedIngressListener {
        endpoint_port: 0,
        ..valid.clone()
    };
    assert!(!zero_backend.endpoint_is_valid());

    // A carried `:0` listener port fails.
    let zero_listener = ResolvedIngressListener {
        port: 0,
        ..valid.clone()
    };
    assert!(!zero_listener.endpoint_is_valid());

    // A non-IP / unparseable host fails.
    let bogus_host = ResolvedIngressListener {
        endpoint_host: "example.com".to_string(),
        ..valid.clone()
    };
    assert!(!bogus_host.endpoint_is_valid());
}

#[test]
fn ingress_resolve_rejects_unix_socket_endpoint() {
    assert_eq!(
        ingress_entry(8443, AppProtocol::Http, "unix:///var/run/app.sock").resolve(),
        Err(IngressListenerUnsupported::UnixSocketEndpoint)
    );
}

#[test]
fn ingress_resolve_rejects_non_http_protocol() {
    assert_eq!(
        ingress_entry(8443, AppProtocol::Tcp, "127.0.0.1:8080").resolve(),
        Err(IngressListenerUnsupported::NonHttpProtocol)
    );
    assert_eq!(
        ingress_entry(8443, AppProtocol::Mongo, "127.0.0.1:8080").resolve(),
        Err(IngressListenerUnsupported::NonHttpProtocol)
    );
}

#[test]
fn ingress_resolve_rejects_arbitrary_ip_endpoint() {
    // Istio: "Arbitrary IPs are not supported." Ferrum's loopback-only model
    // fails closed rather than dialing an off-box address.
    assert_eq!(
        ingress_entry(8443, AppProtocol::Http, "10.0.0.5:8080").resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint)
    );
}

#[test]
fn ingress_resolve_rejects_unparseable_and_portless_endpoints() {
    assert_eq!(
        ingress_entry(8443, AppProtocol::Http, "not-a-socket").resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint)
    );
    // host without a port
    assert_eq!(
        ingress_entry(8443, AppProtocol::Http, "127.0.0.1").resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint)
    );
    // zero endpoint port
    assert_eq!(
        ingress_entry(8443, AppProtocol::Http, "127.0.0.1:0").resolve(),
        Err(IngressListenerUnsupported::ZeroPort)
    );
}

#[test]
fn ingress_resolve_rejects_zero_listener_port() {
    assert_eq!(
        ingress_entry(0, AppProtocol::Http, "127.0.0.1:8080").resolve(),
        Err(IngressListenerUnsupported::ZeroPort)
    );
}

#[test]
fn ingress_omitted_default_endpoint_deserializes_then_defers() {
    // F6 §6.2 (Finding 3): Istio treats `defaultEndpoint` as OPTIONAL. The
    // native model must DESERIALIZE an entry that omits it (it must not be a
    // required serde field), defaulting to the empty string, which then defers
    // at `resolve()` — matching the K8s translation path (which fills an empty
    // string for an omitted field).
    let entry: MeshSidecarIngress = serde_json::from_value(serde_json::json!({
        "port": 8443,
        "protocol": "http"
        // defaultEndpoint intentionally omitted
    }))
    .expect("an omitted defaultEndpoint must still deserialize (optional field)");
    assert_eq!(
        entry.default_endpoint, "",
        "omitted endpoint defaults to empty"
    );
    assert_eq!(
        entry.resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint),
        "an empty defaultEndpoint defers (fail-closed), it is not a hard error"
    );
}

#[test]
fn validate_rejects_zero_ingress_port() {
    // A zero listener port is structurally invalid. An empty/absent
    // defaultEndpoint is NOT a hard error (Istio allows omitting it) — it is
    // deferred and skipped at materialization.
    let mesh = MeshConfig {
        sidecars: vec![MeshSidecar {
            name: "sc".into(),
            namespace: "default".into(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: Vec::new(),
            ingress_declared: false,
            ingress: vec![
                ingress_entry(0, AppProtocol::Http, "127.0.0.1:8080"),
                ingress_entry(8443, AppProtocol::Http, ""),
            ],
            outbound_traffic_policy: None,
        }],
        ..MeshConfig::default()
    };
    let errors = mesh.validate();
    assert!(
        errors.iter().any(|e| e.contains("ingress[0].port")),
        "zero ingress port must be a validation error: {errors:?}"
    );
    assert!(
        !errors.iter().any(|e| e.contains("default_endpoint")),
        "empty defaultEndpoint is deferred, not a validation error: {errors:?}"
    );
}

#[test]
fn validate_accepts_unsupported_ingress_shapes_for_deferral() {
    // Unix sockets / non-HTTP protocols are NOT validation errors — they are
    // accepted (and reported as deferred by the status writer), then skipped
    // fail-closed at materialization.
    let mesh = MeshConfig {
        sidecars: vec![MeshSidecar {
            name: "sc".into(),
            namespace: "default".into(),
            workload_selector: None,
            egress_inherits_defaults: false,
            egress: Vec::new(),
            ingress_declared: false,
            ingress: vec![
                ingress_entry(8443, AppProtocol::Http, "unix:///var/run/app.sock"),
                ingress_entry(9000, AppProtocol::Tcp, "127.0.0.1:9000"),
            ],
            outbound_traffic_policy: None,
        }],
        ..MeshConfig::default()
    };
    assert!(
        mesh.validate().is_empty(),
        "unsupported-but-well-formed ingress entries are accepted (deferred), not rejected"
    );
}

#[test]
fn mesh_config_validate_rejects_destination_rule_outlier_range_gaps() {
    let mesh = MeshConfig {
        destination_rules: vec![MeshDestinationRule {
            name: "dr".into(),
            namespace: "default".into(),
            host: "reviews.default.svc.cluster.local".into(),
            traffic_policy: Some(MeshTrafficPolicy {
                outlier_detection: Some(MeshOutlierDetection {
                    // `consecutive_errors: 0` is Istio's "disable 5xx ejection"
                    // sentinel, not an out-of-range value, so it must NOT be
                    // rejected (see below).
                    consecutive_errors: None,
                    interval_seconds: Some(0),
                    base_ejection_seconds: Some(0),
                    max_ejection_percent: Some(200),
                }),
                ..MeshTrafficPolicy::default()
            }),
            port_level_settings: HashMap::new(),
            subsets: Vec::new(),
        }],
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("interval_seconds") && e.contains("greater than 0")),
        "expected interval_seconds lower-bound error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("base_ejection_seconds") && e.contains("greater than 0")),
        "expected base_ejection_seconds lower-bound error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("max_ejection_percent") && e.contains("0 to 100")),
        "expected max_ejection_percent range error, got: {errors:?}"
    );
}

#[test]
fn mesh_config_validate_accepts_zero_consecutive_errors_as_disabled() {
    // Istio treats `outlierDetection.consecutive5xxErrors: 0` as *disabling*
    // 5xx-based ejection rather than as a lower-bound violation, and the K8s
    // translator preserves the value as `Some(0)`. The native/file/xDS boundary
    // validator must accept it so a valid Istio config does not make mesh
    // startup/reload fail.
    let mesh = MeshConfig {
        destination_rules: vec![MeshDestinationRule {
            name: "dr".into(),
            namespace: "default".into(),
            host: "reviews.default.svc.cluster.local".into(),
            traffic_policy: Some(MeshTrafficPolicy {
                outlier_detection: Some(MeshOutlierDetection {
                    consecutive_errors: Some(0),
                    interval_seconds: Some(30),
                    base_ejection_seconds: Some(30),
                    max_ejection_percent: Some(50),
                }),
                ..MeshTrafficPolicy::default()
            }),
            port_level_settings: HashMap::new(),
            subsets: Vec::new(),
        }],
        ..MeshConfig::default()
    };

    assert!(
        mesh.validate().is_empty(),
        "consecutive_errors: 0 (disable 5xx ejection) must be accepted, got: {:?}",
        mesh.validate()
    );
}

#[test]
fn mesh_config_validate_rejects_destination_rule_tls_inconsistency() {
    let mut port_level_settings = HashMap::new();
    port_level_settings.insert(
        8080,
        MeshTrafficPolicy {
            tls: Some(MeshTrafficPolicyTls {
                mode: MtlsMode::Strict,
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        },
    );

    let mesh = MeshConfig {
        destination_rules: vec![MeshDestinationRule {
            name: "dr".into(),
            namespace: "default".into(),
            host: "reviews.default.svc.cluster.local".into(),
            traffic_policy: Some(MeshTrafficPolicy {
                tls: Some(MeshTrafficPolicyTls {
                    mode: MtlsMode::Mutual,
                    client_certificate: Some("/cert.pem".into()),
                    private_key: None,
                    ..MeshTrafficPolicyTls::default()
                }),
                ..MeshTrafficPolicy::default()
            }),
            port_level_settings,
            subsets: vec![MeshSubset {
                name: "v1".into(),
                labels: HashMap::new(),
                traffic_policy: Some(MeshTrafficPolicy {
                    tls: Some(MeshTrafficPolicyTls {
                        mode: MtlsMode::IstioMutual,
                        client_certificate: Some("/operator-cert.pem".into()),
                        ca_certificates: Some("/operator-ca.pem".into()),
                        ..MeshTrafficPolicyTls::default()
                    }),
                    ..MeshTrafficPolicy::default()
                }),
            }],
        }],
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("private_key") && e.contains("must be set")),
        "expected MUTUAL private_key error, got: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("port_level_settings[8080].tls.mode")),
        "expected server-side mode error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| {
            e.contains("subsets[0].traffic_policy.tls.client_certificate")
                && e.contains("must be absent")
        }),
        "expected ISTIO_MUTUAL explicit-cert error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| {
            e.contains("subsets[0].traffic_policy.tls.ca_certificates")
                && e.contains("must be absent")
        }),
        "expected ISTIO_MUTUAL explicit-CA error, got: {errors:?}"
    );
}

#[test]
fn mesh_config_validate_rejects_tracing_percentage_bounds() {
    let mesh = MeshConfig {
        telemetry_resources: vec![MeshTelemetryResource {
            name: "telemetry".into(),
            namespace: "default".into(),
            scope: PolicyScope::MeshWide,
            config: MeshTelemetryConfig {
                tracing: Some(MeshTracingConfig {
                    mode: None,
                    sampling_percentage: Some(101.0),
                    disable_span_reporting: None,
                    custom_tags: HashMap::new(),
                    custom_header_tags: HashMap::new(),
                    custom_env_tags: HashMap::new(),
                    providers: Vec::new(),
                }),
                ..MeshTelemetryConfig::default()
            },
        }],
        proxy_configs: vec![MeshProxyConfig {
            name: "proxy".into(),
            namespace: "default".into(),
            tracing_sampling: Some(f64::NAN),
            ..MeshProxyConfig::default()
        }],
        ..MeshConfig::default()
    };

    let errors = mesh.validate();
    assert!(
        errors.iter().any(|e| {
            e.contains("MeshTelemetryResource 'telemetry'")
                && e.contains("sampling_percentage")
                && e.contains("0 to 100")
        }),
        "expected Telemetry sampling range error, got: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| {
            e.contains("MeshProxyConfig 'proxy'")
                && e.contains("tracing_sampling")
                && e.contains("0 to 100")
        }),
        "expected ProxyConfig sampling range error, got: {errors:?}"
    );
}

// ── VirtualService-derived CORS policies (issue #1973) ─────────────────────

mod virtual_service_cors {
    use ferrum_edge::modes::mesh::config::{
        MeshConfig, MeshCorsOriginMatch, MeshCorsPolicy, MeshVirtualServiceCorsPolicy,
        cors_plugin_config_from_mesh_policy, virtual_service_cors_policy_exported_to_namespace,
    };

    fn policy(origins: Vec<MeshCorsOriginMatch>) -> MeshVirtualServiceCorsPolicy {
        MeshVirtualServiceCorsPolicy {
            name: "vs-cors".into(),
            namespace: "default".into(),
            host: "svc.default.svc.cluster.local".into(),
            export_to: Vec::new(),
            cors: MeshCorsPolicy {
                allowed_origins: origins,
                allowed_methods: Vec::new(),
                allowed_headers: Vec::new(),
                exposed_headers: Vec::new(),
                max_age_seconds: None,
                allow_credentials: None,
                unmatched_preflights: None,
            },
        }
    }

    fn validate(policies: Vec<MeshVirtualServiceCorsPolicy>) -> Vec<String> {
        MeshConfig {
            virtual_service_cors_policies: policies,
            ..MeshConfig::default()
        }
        .validate()
    }

    #[test]
    fn valid_policy_passes() {
        let errors = validate(vec![policy(vec![MeshCorsOriginMatch::Exact(
            "https://a.example".into(),
        )])]);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn originless_policy_rejected() {
        let errors = validate(vec![policy(Vec::new())]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("at least one origin matcher")),
            "{errors:?}"
        );
    }

    #[test]
    fn empty_matcher_values_rejected() {
        for matcher in [
            MeshCorsOriginMatch::Exact("  ".into()),
            MeshCorsOriginMatch::Prefix(String::new()),
            MeshCorsOriginMatch::Regex(String::new()),
        ] {
            let errors = validate(vec![policy(vec![matcher.clone()])]);
            assert!(
                errors.iter().any(|error| error.contains("non-empty")),
                "matcher {matcher:?} must be rejected: {errors:?}"
            );
        }
    }

    /// Issue #3254: exact `*` keeps Istio's allow-all meaning, and every OTHER
    /// exact — including one shaped like the plugin's native wildcard-subdomain
    /// syntax — is carried as a LITERAL matcher instead of being rejected.
    /// The synthesized plugin config must select the object matcher, because
    /// the plain-string form would read `*.example.com` as native wildcard
    /// syntax and authorize every subdomain the source never matched.
    #[test]
    fn exact_star_is_istio_allow_all_and_other_wildcard_exacts_stay_literal() {
        let exact_star = validate(vec![policy(vec![MeshCorsOriginMatch::Exact("*".into())])]);
        assert!(exact_star.is_empty(), "{exact_star:?}");

        let wildcard_shaped = policy(vec![MeshCorsOriginMatch::Exact("*.example.com".into())]);
        let errors = validate(vec![wildcard_shaped.clone()]);
        assert!(
            errors.is_empty(),
            "a wildcard-shaped exact is literal, not invalid: {errors:?}"
        );
        assert_eq!(
            cors_plugin_config_from_mesh_policy(&wildcard_shaped.cors)["allowed_origins"],
            serde_json::json!([{ "exact": "*.example.com" }]),
            "a wildcard-shaped exact must project as a literal matcher object"
        );

        // Wildcard-looking PREFIX matchers are fine — prefix is a literal
        // byte-prefix in both Istio and the plugin object form.
        let errors = validate(vec![policy(vec![MeshCorsOriginMatch::Prefix(
            "https://app.".into(),
        )])]);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn credentialed_exact_star_is_rejected_without_weakening_source_policy() {
        let mut credentialed = policy(vec![MeshCorsOriginMatch::Exact("*".into())]);
        credentialed.cors.allow_credentials = Some(true);
        let errors = validate(vec![credentialed]);
        assert!(
            errors.iter().any(|error| error
                .contains("allow_credentials must not be true with an exact `*` origin")),
            "{errors:?}"
        );

        let mut uncredentialed = policy(vec![MeshCorsOriginMatch::Exact("*".into())]);
        uncredentialed.cors.allow_credentials = Some(false);
        let errors = validate(vec![uncredentialed]);
        assert!(errors.is_empty(), "{errors:?}");
    }

    /// A padded literal is preserved verbatim under literal-exact semantics
    /// (issue #3254). It matches no real `Origin` header, which is exactly what
    /// Istio's literal `StringMatch.exact` does — the previous rejection existed
    /// only because the plain-string plugin form TRIMMED it and thereby widened
    /// the matcher to the trimmed origin.
    #[test]
    fn padded_exact_origin_is_carried_verbatim_without_trimming() {
        for padded in [" https://a.example", "https://a.example "] {
            let carried = policy(vec![MeshCorsOriginMatch::Exact(padded.into())]);
            let errors = validate(vec![carried.clone()]);
            assert!(errors.is_empty(), "exact `{padded}`: {errors:?}");
            assert_eq!(
                cors_plugin_config_from_mesh_policy(&carried.cors)["allowed_origins"],
                serde_json::json!([{ "exact": padded }]),
                "a padded exact must not be trimmed into a wider matcher"
            );
        }
    }

    #[test]
    fn invalid_methods_and_headers_rejected() {
        // Method/header lists are copied verbatim into the synthesized cors
        // plugin, whose construction rejects invalid tokens — the boundary
        // must reject them too, not fail plugin-cache construction on the DP.
        let mut bad_method = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        bad_method.cors.allowed_methods = vec!["GET".into(), "not a method".into()];
        let errors = validate(vec![bad_method]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("invalid HTTP method")),
            "{errors:?}"
        );

        let mut bad_header = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        bad_header.cors.allowed_headers = vec!["bad header".into()];
        let errors = validate(vec![bad_header]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("invalid HTTP header name")),
            "{errors:?}"
        );

        let mut bad_exposed = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        bad_exposed.cors.exposed_headers = vec!["bad header".into()];
        let errors = validate(vec![bad_exposed]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("invalid HTTP header name")),
            "{errors:?}"
        );

        let mut empty_method = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        empty_method.cors.allowed_methods = vec![" ".into()];
        let errors = validate(vec![empty_method]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("allowed_methods[0] must not be empty")),
            "{errors:?}"
        );

        let mut padded_method =
            policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        padded_method.cors.allowed_methods = vec!["GET".into(), " POST ".into()];
        let errors = validate(vec![padded_method]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("leading/trailing whitespace")),
            "{errors:?}"
        );

        // Valid token lists pass unchanged through the shared plugin
        // admission gate.
        let mut ok = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        ok.cors.allowed_methods = vec!["GET".into(), "POST".into()];
        ok.cors.allowed_headers = vec!["x-requested-with".into()];
        ok.cors.exposed_headers = vec!["x-trace-id".into()];
        let errors = validate(vec![ok]);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn normalize_trims_and_lowercases_carried_host() {
        // Synthesis matches `policy.host` against service FQDNs with
        // `destination_rule_host_matches` (no trimming there); a padded or
        // mixed-case native/file host must be normalized like DR hosts or the
        // policy silently attaches no plugin.
        let mut config = MeshConfig {
            virtual_service_cors_policies: vec![policy(vec![MeshCorsOriginMatch::Exact(
                "https://a.example".into(),
            )])],
            ..MeshConfig::default()
        };
        config.virtual_service_cors_policies[0].host = " Svc.Default.SVC.Cluster.Local. ".into();
        config.normalize();
        assert_eq!(
            config.virtual_service_cors_policies[0].host,
            "svc.default.svc.cluster.local"
        );
    }

    /// Issue #3254: an exact that is not a canonical `scheme://host[:port]`
    /// origin, or not the canonical browser serialization, is still a valid
    /// LITERAL matcher. It is carried verbatim and matches only that exact
    /// `Origin` string — never widened to the canonical origin, and never
    /// rejected as "not an origin" (that predicate belongs to the plugin's
    /// NATIVE plain-string form, which this path no longer uses).
    #[test]
    fn noncanonical_and_non_origin_exacts_are_carried_literally() {
        for literal in [
            "https://a.example/",
            "https://a.example/path",
            "https://user:pw@a.example",
            "ftp://a.example",
            "not a url",
            "https://example.com:443",
            "HTTPS://EXAMPLE.COM",
            "https://bücher.example",
        ] {
            let carried = policy(vec![MeshCorsOriginMatch::Exact(literal.into())]);
            let errors = validate(vec![carried.clone()]);
            assert!(errors.is_empty(), "exact `{literal}`: {errors:?}");
            assert_eq!(
                cors_plugin_config_from_mesh_policy(&carried.cors)["allowed_origins"],
                serde_json::json!([{ "exact": literal }]),
                "exact `{literal}` must be carried byte-for-byte"
            );
        }
    }

    #[test]
    fn uncompilable_regex_rejected() {
        let errors = validate(vec![policy(vec![MeshCorsOriginMatch::Regex("(".into())])]);
        assert!(
            errors.iter().any(|error| error.contains("is invalid")),
            "{errors:?}"
        );
    }

    /// Issue #3253: matchers outside the explicit byte / complexity / count
    /// bounds reject the slice at the config boundary with a field-specific
    /// diagnostic — they are never silently dropped or truncated.
    #[test]
    fn out_of_bounds_origin_matchers_rejected_with_field_specific_diagnostics() {
        let oversized = "a".repeat(600);
        for (matcher, needle) in [
            (
                MeshCorsOriginMatch::Exact(oversized.clone()),
                "byte matcher limit",
            ),
            (
                MeshCorsOriginMatch::Prefix(oversized.clone()),
                "byte matcher limit",
            ),
            (
                MeshCorsOriginMatch::Regex(oversized.clone()),
                "byte matcher limit",
            ),
            (
                MeshCorsOriginMatch::Regex(
                    "((((((((((((((((((((((((((((a))))))))))))))))))))))))))))".into(),
                ),
                "complexity bounds",
            ),
        ] {
            let errors = validate(vec![policy(vec![matcher.clone()])]);
            assert!(
                errors
                    .iter()
                    .any(|error| error.contains(needle) && error.contains("allowed_origins[0]")),
                "matcher {matcher:?} must be rejected with `{needle}`: {errors:?}"
            );
        }

        let too_many: Vec<MeshCorsOriginMatch> = (0..65)
            .map(|i| MeshCorsOriginMatch::Exact(format!("https://app{i}.example")))
            .collect();
        let errors = validate(vec![policy(too_many)]);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("at most 64 entries")),
            "{errors:?}"
        );
    }

    #[test]
    fn empty_host_and_name_rejected() {
        let mut bad = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        bad.host = String::new();
        bad.name = " ".into();
        let errors = validate(vec![bad]);
        assert!(
            errors.iter().any(|error| error.contains(".host")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| error.contains(".name")),
            "{errors:?}"
        );
    }

    #[test]
    fn origin_matcher_serde_is_single_key_map_and_fail_closed() {
        // YAML single-key maps parse to the right variants…
        let parsed: Vec<MeshCorsOriginMatch> = serde_yaml::from_str(
            "- exact: \"https://a.example\"\n- prefix: \"https://app.\"\n- regex: \"https://.*\"\n",
        )
        .expect("single-key maps parse");
        assert_eq!(
            parsed,
            vec![
                MeshCorsOriginMatch::Exact("https://a.example".into()),
                MeshCorsOriginMatch::Prefix("https://app.".into()),
                MeshCorsOriginMatch::Regex("https://.*".into()),
            ]
        );
        // …serialization round-trips through the same shape…
        let json = serde_json::to_value(&parsed).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!([
                {"exact": "https://a.example"},
                {"prefix": "https://app."},
                {"regex": "https://.*"}
            ])
        );
        // …and malformed matchers fail closed instead of dropping a key.
        assert!(
            serde_yaml::from_str::<MeshCorsOriginMatch>("exact: a\nregex: b\n").is_err(),
            "two keys must be rejected"
        );
        assert!(
            serde_yaml::from_str::<MeshCorsOriginMatch>("suffix: a\n").is_err(),
            "unknown key must be rejected"
        );
        assert!(
            serde_yaml::from_str::<MeshCorsOriginMatch>("{}").is_err(),
            "empty map must be rejected"
        );
    }

    #[test]
    fn plugin_projection_covers_all_fields() {
        let full = MeshCorsPolicy {
            allowed_origins: vec![
                MeshCorsOriginMatch::Exact("https://a.example".into()),
                MeshCorsOriginMatch::Prefix("https://app.".into()),
                MeshCorsOriginMatch::Regex("https://.*".into()),
            ],
            allowed_methods: vec!["GET".into()],
            allowed_headers: vec!["x-a".into()],
            exposed_headers: vec!["x-b".into()],
            max_age_seconds: Some(600),
            allow_credentials: Some(true),
            unmatched_preflights: Some(
                ferrum_edge::modes::mesh::config::MeshCorsUnmatchedPreflights::Ignore,
            ),
        };
        let config = cors_plugin_config_from_mesh_policy(&full);
        assert_eq!(
            config["allowed_origins"],
            serde_json::json!([
                {"exact": "https://a.example"},
                {"prefix": "https://app."},
                {"regex": "https://.*"}
            ])
        );
        assert_eq!(config["allowed_methods"], serde_json::json!(["GET"]));
        assert_eq!(config["allowed_headers"], serde_json::json!(["x-a"]));
        assert_eq!(config["exposed_headers"], serde_json::json!(["x-b"]));
        assert_eq!(config["max_age"], serde_json::json!(600));
        assert_eq!(config["allow_credentials"], serde_json::json!(true));
        assert_eq!(config["unmatched_preflights"], serde_json::json!("ignore"));
        // Sparse Istio policies preserve empty lists and omitted max age while
        // synthesizing the source API's default FORWARD behavior.
        let sparse = cors_plugin_config_from_mesh_policy(&MeshCorsPolicy {
            allowed_origins: vec![MeshCorsOriginMatch::Exact("https://a.example".into())],
            allowed_methods: Vec::new(),
            allowed_headers: Vec::new(),
            exposed_headers: Vec::new(),
            max_age_seconds: None,
            allow_credentials: None,
            unmatched_preflights: None,
        });
        assert_eq!(sparse["allowed_methods"], serde_json::json!([]));
        assert_eq!(sparse["allowed_headers"], serde_json::json!([]));
        assert_eq!(sparse["exposed_headers"], serde_json::json!([]));
        assert_eq!(sparse["unmatched_preflights"], serde_json::json!("forward"));
        assert!(sparse.get("max_age").is_none());
        assert!(sparse.get("allow_credentials").is_none());
        assert!(sparse.get("preflight_continue").is_none());
    }

    #[test]
    fn export_visibility_follows_service_entry_semantics() {
        let mut p = policy(vec![MeshCorsOriginMatch::Exact("https://a.example".into())]);
        // Empty export_to is namespace-local.
        assert!(virtual_service_cors_policy_exported_to_namespace(
            &p, "default"
        ));
        assert!(!virtual_service_cors_policy_exported_to_namespace(
            &p, "other"
        ));
        // "." is the policy's own namespace.
        p.export_to = vec![".".into()];
        assert!(virtual_service_cors_policy_exported_to_namespace(
            &p, "default"
        ));
        assert!(!virtual_service_cors_policy_exported_to_namespace(
            &p, "other"
        ));
        // "*" is public; explicit namespaces grant exactly themselves.
        p.export_to = vec!["*".into()];
        assert!(virtual_service_cors_policy_exported_to_namespace(
            &p, "other"
        ));
        p.export_to = vec!["team-a".into()];
        assert!(virtual_service_cors_policy_exported_to_namespace(
            &p, "team-a"
        ));
        assert!(!virtual_service_cors_policy_exported_to_namespace(
            &p, "team-b"
        ));
    }
}

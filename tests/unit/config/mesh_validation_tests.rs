//! `validate_mesh_config()` tests.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, ConditionMatch, EastWestGateway, JwtHeader, MeshConfig, MeshDestinationRule,
    MeshEndpoint, MeshJwtRule, MeshPolicy, MeshRequestAuthentication, MeshRule, MeshService,
    MeshSidecar, MeshSidecarEgress, MeshSubset, MeshTrafficPolicy, MtlsMode, MultiClusterConfig,
    ParsedCidr, PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RemoteCluster,
    RequestMatch, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle,
    TrustBundleSet, Workload, WorkloadPort, WorkloadRef, WorkloadSelector, validate_mesh_config,
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
        errors.iter().any(|err| err.contains("duplicate SNI host")),
        "expected duplicate SNI error, got: {errors:?}"
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

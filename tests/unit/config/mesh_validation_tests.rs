//! `validate_mesh_config()` tests.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, JwtHeader, MeshConfig, MeshEndpoint, MeshJwtRule, MeshPolicy,
    MeshRequestAuthentication, MeshRule, MeshService, MultiClusterConfig, PeerAuthentication,
    PolicyAction, PolicyScope, PrincipalMatch, RemoteCluster, RequestMatch, Resolution,
    ServiceEntry, ServiceEntryLocation, TrustBundle, TrustBundleSet, Workload, WorkloadPort,
    WorkloadRef, WorkloadSelector, validate_mesh_config,
};
use std::collections::HashMap;

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
            .any(|e| e.contains("namespace must not be empty"))
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
        name: String::new(),
        namespace: "default".into(),
        ports: Vec::new(),
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
    };
    let errors = validate_mesh_config(&[], &[svc], &[], &[], &[], &[], None);
    assert!(errors.iter().any(|e| e.contains("name must not be empty")));
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
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                ..Default::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
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
            }],
            to: vec![RequestMatch::default()],
            when: Vec::new(),
            request_principals: Vec::new(),
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
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                ..Default::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
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
            }],
            to: vec![request],
            when: Vec::new(),
            request_principals: Vec::new(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
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
            .any(|e| e.contains("namespace must not be empty"))
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
    port_overrides.insert(15006, ferrum_edge::modes::mesh::config::MtlsMode::IstioMutual);
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
            .any(|e| e.contains("port_overrides[15006]") && e.contains("invalid for server-side policy")),
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
            }],
            ..Default::default()
        })),
        ..Default::default()
    };
    let errors = cfg.validate_mesh_fields();
    assert!(!errors.is_empty(), "expected at least one error");
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

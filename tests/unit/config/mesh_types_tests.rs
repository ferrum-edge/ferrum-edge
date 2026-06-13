//! Layer-2 mesh type tests: serde round-trips and decode helpers.

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, JwtHeader, MeshConfig, MeshEndpoint, MeshJwtRule, MeshPolicy,
    MeshRequestAuthentication, MeshRule, MeshService, MtlsMode, MultiClusterConfig,
    PeerAuthentication, PolicyAction, PolicyScope, PrincipalMatch, RemoteCluster, RequestMatch,
    Resolution, ServiceEntry, ServiceEntryLocation, ServicePort, TrustBundle, TrustBundleSet,
    Workload, WorkloadPort, WorkloadRef, WorkloadSelector,
};
use std::collections::HashMap;

// ── Backwards-compat (byte-identical) ────────────────────────────────────

/// A non-mesh `GatewayConfig` must round-trip through JSON without ANY of
/// the new mesh fields appearing in the output. This is the critical
/// guarantee that lets file/DB users adopt the binary upgrade transparently.
#[test]
fn non_mesh_config_round_trips_without_mesh_fields() {
    let cfg = GatewayConfig::default();
    let json = serde_json::to_value(&cfg).unwrap();
    let obj = json.as_object().expect("object");
    assert!(
        !obj.contains_key("mesh"),
        "non-mesh config serialised an empty `mesh` field",
    );
}

#[test]
fn mesh_config_round_trips_through_serde() {
    let td = TrustDomain::new("prod.example.com").unwrap();
    let id = SpiffeId::from_parts(&td, "ns/svc/sa/api").unwrap();
    let cfg = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![Workload {
                spiffe_id: id.clone(),
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".into(), "api".into())]),
                    namespace: Some("svc".into()),
                },
                service_name: "api".into(),
                addresses: Vec::new(),
                ports: vec![WorkloadPort {
                    port: 8443,
                    protocol: AppProtocol::Http2,
                    name: Some("https".into()),
                }],
                trust_domain: td.clone(),
                namespace: "svc".into(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
            }],
            services: vec![MeshService {
                cluster_ips: Vec::new(),
                name: "api".into(),
                namespace: "svc".into(),
                ports: vec![ServicePort {
                    port: 8443,
                    protocol: AppProtocol::Http2,
                    name: None,
                    target_port: None,
                }],
                workloads: vec![WorkloadRef { spiffe_id: id }],
                protocol_overrides: HashMap::new(),
            }],
            ..Default::default()
        })),
        ..GatewayConfig::default()
    };
    let json = serde_json::to_string(&cfg).expect("serialises");
    let back: GatewayConfig = serde_json::from_str(&json).expect("deserialises");
    let mesh = back.mesh.as_ref().expect("mesh present");
    assert_eq!(mesh.workloads.len(), 1);
    assert_eq!(mesh.services.len(), 1);
    assert_eq!(mesh.workloads[0].service_name, "api");
}

#[test]
fn mesh_config_defaults_istio_root_namespace_for_old_slices() {
    let mesh: MeshConfig = serde_json::from_value(serde_json::json!({})).unwrap();
    assert_eq!(mesh.istio_root_namespace, "istio-system");

    let json = serde_json::to_value(&mesh).unwrap();
    let obj = json.as_object().expect("mesh object");
    assert!(
        !obj.contains_key("istio_root_namespace"),
        "default root namespace should stay wire-compatible"
    );
}

#[test]
fn mesh_config_round_trips_custom_istio_root_namespace() {
    let mesh: MeshConfig =
        serde_json::from_value(serde_json::json!({"istio_root_namespace": "mesh-root"})).unwrap();
    assert_eq!(mesh.istio_root_namespace, "mesh-root");

    let json = serde_json::to_value(&mesh).unwrap();
    assert_eq!(json["istio_root_namespace"], "mesh-root");
}

#[test]
fn unknown_mesh_fields_are_tolerated() {
    // Forwards-compat: a newer ferrum schema may add fields under a mesh
    // resource. Older binaries must ignore them. Serde's default-on-unknown
    // is fine for our struct shape; this test confirms that.
    let json = r#"{
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [],
        "loaded_at": "2026-04-28T00:00:00Z",
        "known_namespaces": [],
        "mesh": {
            "workloads": [
                {
                    "spiffe_id": "spiffe://td/ns/foo/sa/bar",
                    "selector": {"labels": {}, "namespace": null},
                    "service_name": "svc",
                    "ports": [],
                    "trust_domain": "td",
                    "namespace": "default",
                    "future_field_that_does_not_exist": "ignored"
                }
            ]
        }
    }"#;
    let cfg: GatewayConfig = serde_json::from_str(json).expect("future fields are tolerated");
    let mesh = cfg.mesh.as_ref().expect("mesh present");
    assert_eq!(mesh.workloads.len(), 1);
}

// ── Per-type smoke tests ─────────────────────────────────────────────────

#[test]
fn mesh_policy_serializes_with_oneof_scope() {
    let policy = MeshPolicy {
        name: "deny-cross-ns".into(),
        namespace: "default".into(),
        scope: PolicyScope::Namespace {
            namespace: "default".into(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://prod/ns/ext/sa/*".into()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            to: vec![RequestMatch {
                methods: vec!["GET".into()],
                paths: vec!["/api/*".into()],
                ports: Vec::new(),
                ..Default::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    };
    let s = serde_json::to_string(&policy).unwrap();
    let back: MeshPolicy = serde_json::from_str(&s).unwrap();
    assert_eq!(back, policy);
}

#[test]
fn peer_authentication_default_mtls_mode_is_permissive() {
    let pa = PeerAuthentication {
        name: "allow-mixed".into(),
        namespace: "default".into(),
        scope: None,
        selector: None,
        mtls_mode: MtlsMode::default(),
        port_overrides: HashMap::new(),
    };
    assert_eq!(pa.mtls_mode, MtlsMode::Permissive);
}

#[test]
fn service_entry_static_resolution_with_endpoints() {
    let entry = ServiceEntry {
        name: "external-api".into(),
        namespace: "default".into(),
        hosts: vec!["api.partner.example".into()],
        endpoints: vec![MeshEndpoint {
            address: "10.0.0.1".into(),
            ports: HashMap::from([("https".into(), 443u16)]),
            labels: HashMap::new(),
            network: None,
        }],
        resolution: Resolution::Static,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 443,
            protocol: AppProtocol::Http2,
            name: Some("https".into()),
            target_port: None,
        }],
        export_to: Vec::new(),
        workload_selector: None,
    };
    let s = serde_json::to_string(&entry).unwrap();
    let back: ServiceEntry = serde_json::from_str(&s).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn trust_bundle_decodes_base64_authorities() {
    use base64::Engine;
    let raw_der = b"fake DER blob";
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_der);
    let bundle = TrustBundle {
        trust_domain: TrustDomain::new("td").unwrap(),
        x509_authorities: vec![b64],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    };
    let decoded = bundle.decode_x509_authorities().unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0], raw_der);
}

#[test]
fn trust_bundle_set_to_runtime_fills_local_and_federated() {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let bundle = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("local.test").unwrap(),
            x509_authorities: vec![engine.encode(b"local-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: vec![TrustBundle {
            trust_domain: TrustDomain::new("partner.test").unwrap(),
            x509_authorities: vec![engine.encode(b"partner-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: Some(300),
        }],
    };
    let runtime = bundle.to_runtime().unwrap();
    assert_eq!(runtime.local.x509_authorities.len(), 1);
    assert_eq!(runtime.federated.len(), 1);
    let partner_td = TrustDomain::new("partner.test").unwrap();
    assert!(runtime.federated.contains_key(&partner_td));
}

#[test]
fn multi_cluster_config_round_trips_through_serde() {
    let cfg = MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: Some("https://eastwest-a.example/.well-known/spiffe".to_string()),
        remote_clusters: vec![RemoteCluster {
            name: "cluster-b".to_string(),
            trust_domain: TrustDomain::new("remote.test").unwrap(),
            network: Some("network-b".to_string()),
            control_plane_url: Some("https://cp-b.example:50051".to_string()),
            federation_endpoint: Some("https://eastwest-b.example/.well-known/spiffe".to_string()),
        }],
        east_west_gateways: vec![EastWestGateway {
            name: "cluster-b".to_string(),
            namespace: "mesh-system".to_string(),
            host: "eastwest-b.example".to_string(),
            port: 15443,
            sni_hosts: vec!["*.global".to_string()],
            trust_domain: Some(TrustDomain::new("remote.test").unwrap()),
            network: Some("network-b".to_string()),
        }],
    };

    let json = serde_json::to_string(&cfg).unwrap();
    let back: MultiClusterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn mesh_normalize_strips_trailing_dot_from_request_match_hosts() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "p".into(),
            namespace: "default".into(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    hosts: vec!["Example.COM.".to_string()],
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }],
        ..MeshConfig::default()
    };

    mesh.normalize();
    let request = &mesh.mesh_policies[0].rules[0].to[0];
    assert_eq!(request.hosts, vec!["example.com"]);
}

#[test]
fn mesh_normalize_preserves_request_match_host_port() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "p".into(),
            namespace: "default".into(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    hosts: vec!["API.Default.:8443".to_string()],
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }],
        ..MeshConfig::default()
    };

    mesh.normalize();
    let request = &mesh.mesh_policies[0].rules[0].to[0];
    assert_eq!(request.hosts, vec!["api.default:8443"]);
}

#[test]
fn mesh_normalize_trims_request_match_port_pattern_whitespace() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "p".into(),
            namespace: "default".into(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    port_patterns: vec![" 8* ".to_string()],
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }],
        ..MeshConfig::default()
    };

    mesh.normalize();
    let request = &mesh.mesh_policies[0].rules[0].to[0];
    assert_eq!(request.port_patterns, vec!["8*"]);
}

#[test]
fn mesh_normalize_lowercases_multi_cluster_sni_hosts() {
    let mut mesh = MeshConfig {
        multi_cluster: Some(MultiClusterConfig {
            east_west_gateways: vec![EastWestGateway {
                name: "cluster-b".to_string(),
                namespace: "mesh-system".to_string(),
                host: "EastWest-B.Example".to_string(),
                port: 15443,
                sni_hosts: vec!["API.Global".to_string()],
                trust_domain: None,
                network: None,
            }],
            ..MultiClusterConfig::default()
        }),
        ..MeshConfig::default()
    };

    mesh.normalize();
    let gateway = &mesh.multi_cluster.as_ref().unwrap().east_west_gateways[0];
    assert_eq!(gateway.host, "eastwest-b.example");
    assert_eq!(gateway.sni_hosts, vec!["api.global"]);
}

#[test]
fn mesh_normalize_lowercases_policy_header_names() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "tenant".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: HashMap::from([("X-Tenant".to_string(), "prod".to_string())]),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }],
        ..MeshConfig::default()
    };

    mesh.normalize();

    let headers = &mesh.mesh_policies[0].rules[0].to[0].headers;
    assert_eq!(headers.get("x-tenant").map(String::as_str), Some("prod"));
    assert!(!headers.contains_key("X-Tenant"));
}

#[test]
fn mesh_normalize_collapses_policy_header_case_collisions() {
    // Spec change (PR #992 / commit 8cdba9d8): case-colliding policy header
    // entries were previously preserved verbatim, leaving deny rules
    // unmatchable. Normalization now canonicalises every entry to lowercase
    // so authorization evaluation is deterministic; the collision is
    // collapsed to a single entry (HashMap iteration order picks the
    // surviving value, so the test only asserts that the lower-cased key
    // exists and the upper-cased duplicate is gone).
    let mut mesh = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "tenant".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::MeshWide,
            rules: vec![MeshRule {
                from: Vec::new(),
                to: vec![RequestMatch {
                    headers: HashMap::from([
                        ("X-Tenant".to_string(), "prod".to_string()),
                        ("x-tenant".to_string(), "dev".to_string()),
                    ]),
                    ..RequestMatch::default()
                }],
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }],
        ..MeshConfig::default()
    };

    mesh.normalize();

    let headers = &mesh.mesh_policies[0].rules[0].to[0].headers;
    assert!(
        !headers.contains_key("X-Tenant"),
        "upper-cased entry must be canonicalised away"
    );
    assert!(
        headers.contains_key("x-tenant"),
        "lower-cased entry must remain after canonicalisation"
    );
    assert_eq!(
        headers.len(),
        1,
        "case-colliding entries must collapse to a single canonical entry"
    );
}

#[test]
fn app_protocol_default_is_unknown() {
    assert_eq!(AppProtocol::default(), AppProtocol::Unknown);
}

// ── MeshRequestAuthentication ────────────────────────────────────────────

#[test]
fn request_authentication_round_trips_through_serde() {
    let ra = MeshRequestAuthentication {
        name: "jwt-auth".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "httpbin".to_string())]),
                namespace: Some("default".to_string()),
            },
        },
        jwt_rules: vec![MeshJwtRule {
            issuer: "https://accounts.google.com".to_string(),
            audiences: vec!["my-app".to_string()],
            jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
            jwks: None,
            from_headers: vec![
                JwtHeader {
                    name: "Authorization".to_string(),
                    prefix: Some("Bearer ".to_string()),
                },
                JwtHeader {
                    name: "X-Custom-Token".to_string(),
                    prefix: None,
                },
            ],
            from_params: vec!["access_token".to_string()],
            forward_original_token: true,
        }],
    };

    let json = serde_json::to_string(&ra).unwrap();
    let back: MeshRequestAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ra);
}

#[test]
fn request_authentication_empty_jwt_rules_round_trips() {
    let ra = MeshRequestAuthentication {
        name: "no-rules".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::Namespace {
            namespace: "default".to_string(),
        },
        jwt_rules: Vec::new(),
    };

    let json = serde_json::to_string(&ra).unwrap();
    let back: MeshRequestAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ra);
    // Empty jwt_rules should be omitted from serialized output
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value.get("jwt_rules").is_none());
}

#[test]
fn request_authentication_optional_fields_omitted_when_default() {
    let rule = MeshJwtRule {
        issuer: "https://auth.example.com".to_string(),
        audiences: Vec::new(),
        jwks_uri: None,
        jwks: None,
        from_headers: Vec::new(),
        from_params: Vec::new(),
        forward_original_token: false,
    };

    let json = serde_json::to_string(&rule).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Only issuer should be present; optional/empty fields should be omitted
    assert!(value.get("issuer").is_some());
    assert!(value.get("audiences").is_none());
    assert!(value.get("jwks_uri").is_none());
    assert!(value.get("jwks").is_none());
    assert!(value.get("from_headers").is_none());
    assert!(value.get("from_params").is_none());
}

#[test]
fn request_authentication_meshwide_scope() {
    let ra = MeshRequestAuthentication {
        name: "global-jwt".to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::MeshWide,
        jwt_rules: vec![MeshJwtRule {
            issuer: "https://global.example.com".to_string(),
            audiences: Vec::new(),
            jwks_uri: Some("https://global.example.com/.well-known/jwks.json".to_string()),
            jwks: None,
            from_headers: Vec::new(),
            from_params: Vec::new(),
            forward_original_token: false,
        }],
    };

    let json = serde_json::to_string(&ra).unwrap();
    let back: MeshRequestAuthentication = serde_json::from_str(&json).unwrap();
    assert_eq!(back.scope, PolicyScope::MeshWide);
}

#[test]
fn mesh_config_with_request_authentications_round_trips() {
    let cfg = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            request_authentications: vec![MeshRequestAuthentication {
                name: "test-ra".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::Namespace {
                    namespace: "default".to_string(),
                },
                jwt_rules: vec![MeshJwtRule {
                    issuer: "https://issuer.example.com".to_string(),
                    audiences: vec!["aud1".to_string()],
                    jwks_uri: Some("https://issuer.example.com/jwks".to_string()),
                    jwks: None,
                    from_headers: Vec::new(),
                    from_params: Vec::new(),
                    forward_original_token: false,
                }],
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };

    let json = serde_json::to_string(&cfg).unwrap();
    let back: GatewayConfig = serde_json::from_str(&json).unwrap();
    let mesh = back.mesh.as_ref().unwrap();
    assert_eq!(mesh.request_authentications.len(), 1);
    assert_eq!(mesh.request_authentications[0].name, "test-ra");
    assert_eq!(mesh.request_authentications[0].jwt_rules.len(), 1);
}

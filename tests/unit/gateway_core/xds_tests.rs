use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use prost::Message;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshPolicy, MeshRule, MeshService, MtlsMode, PeerAuthentication,
    PolicyAction, PolicyScope, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
    TrustBundle, TrustBundleSet, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshExtensionConfig;
use ferrum_edge::xds::conformance::{XdsConformanceCase, required_phase_b_cases};
use ferrum_edge::xds::proto;
use ferrum_edge::xds::{
    AckOutcome, CDS_TYPE_URL, ECDS_TYPE_URL, EDS_TYPE_URL, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
    FERRUM_ECDS_MESH_POLICIES_TYPE_URL, LDS_TYPE_URL, MeshSlice, MeshSliceRequest, RDS_TYPE_URL,
    RTDS_TYPE_URL, SDS_TYPE_URL, XdsNonceTracker, XdsSnapshotCache,
    translate_mesh_slice_to_snapshot, translate_rtds_layer,
};

fn workload(name: &str, app: &str) -> Workload {
    let trust_domain = TrustDomain::new("cluster.local").expect("valid trust domain");
    let spiffe_id = SpiffeId::new(format!("spiffe://cluster.local/ns/default/sa/{name}"))
        .expect("valid spiffe id");
    Workload {
        spiffe_id,
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: Some("default".to_string()),
        },
        service_name: name.to_string(),
        addresses: Vec::new(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain,
        namespace: "default".to_string(),
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

fn mesh_config() -> MeshConfig {
    MeshConfig {
        workloads: vec![workload("api", "api"), workload("worker", "worker")],
        services: vec![MeshService {
            cluster_ips: Vec::new(),
            name: "api".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }],
        mesh_policies: vec![
            MeshPolicy {
                name: "api-only".to_string(),
                namespace: "default".to_string(),
                scope: PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                rules: vec![MeshRule {
                    from: Vec::new(),
                    to: Vec::new(),
                    when: Vec::new(),
                    request_principals: Vec::new(),
                    not_request_principals: Vec::new(),
                    source_negation: Default::default(),
                    never_matches: false,
                    action: PolicyAction::Allow,
                }],
            },
            MeshPolicy {
                name: "other-namespace".to_string(),
                namespace: "other".to_string(),
                scope: PolicyScope::MeshWide,
                rules: Vec::new(),
            },
        ],
        peer_authentications: vec![PeerAuthentication {
            name: "default-mtls".to_string(),
            namespace: "default".to_string(),
            scope: None,
            selector: None,
            mtls_mode: MtlsMode::Strict,
            port_overrides: HashMap::new(),
        }],
        service_entries: Vec::new(),
        request_authentications: Vec::new(),
        telemetry_resources: Vec::new(),
        destination_rules: Vec::new(),
        proxy_configs: Vec::new(),
        sidecars: Vec::new(),
        trust_bundles: None,
        multi_cluster: None,
        outbound_traffic_policy: None,
        ..MeshConfig::default()
    }
}

fn gateway_config() -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(mesh_config())),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    }
}

#[test]
fn mesh_slice_is_per_namespace_and_policy_scoped() {
    let request = MeshSliceRequest {
        node_id: "sidecar-api".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/api".to_string()),
        labels: BTreeMap::new(),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: false,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        waypoint_name: None,
    };
    let slice = MeshSlice::from_gateway_config(&gateway_config(), request);

    assert_eq!(slice.namespace, "default");
    assert_eq!(slice.workloads.len(), 2);
    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.mesh_policies.len(), 2);
    assert_eq!(slice.mesh_policies[0].name, "api-only");
    assert_eq!(slice.mesh_policies[1].name, "other-namespace");
    assert_eq!(slice.peer_authentications.len(), 1);
    assert_eq!(slice.labels.get("app").map(String::as_str), Some("api"));
}

#[test]
fn translators_emit_all_phase_b_type_urls() {
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&gateway_config(), request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    assert_eq!(snapshot.resources(LDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(RDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(CDS_TYPE_URL).len(), 1);
    assert_eq!(snapshot.resources(EDS_TYPE_URL).len(), 1);
    assert!(snapshot.resources(SDS_TYPE_URL).is_empty());

    let listener_resource = snapshot.resources(LDS_TYPE_URL)[0].clone();
    let listener = proto::Listener::decode(listener_resource.value.as_slice())
        .expect("minimal listener should decode");
    assert_eq!(listener.name, "listener/default/api/8080");
}

#[test]
fn mesh_config_extension_configs_are_served_as_ecds_resources() {
    let mut config = gateway_config();
    config.mesh.as_mut().expect("mesh config").extension_configs = vec![MeshExtensionConfig {
        name: "dr-carrier-api".to_string(),
        namespace: "default".to_string(),
        type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
        value: b"{\"name\":\"api\"}".to_vec(),
    }];

    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    assert_eq!(slice.extension_configs.len(), 1);

    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    // GAP-1a: `gateway_config()` also carries mesh_policies / peer_authentications /
    // services / workloads, which now ride ECDS as Ferrum mesh-slice carriers
    // (`ferrum-mesh-carrier/*`). The operator's own extension config still
    // appears as its own ECDS resource under its declared name; filter for it
    // explicitly rather than asserting the total ECDS count.
    let ecds = snapshot.resources(ECDS_TYPE_URL);
    let operator_configs: Vec<&str> = ecds
        .iter()
        .map(|r| r.name.as_str())
        .filter(|name| !name.starts_with("ferrum-mesh-carrier/"))
        .collect();
    assert_eq!(operator_configs, vec!["dr-carrier-api"]);
}

#[test]
fn translators_deduplicate_colliding_cluster_resources() {
    let mut mesh = mesh_config();
    mesh.service_entries.push(ServiceEntry {
        name: "api".to_string(),
        namespace: "default".to_string(),
        hosts: vec!["api.example.test".to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        export_to: Vec::new(),
        workload_selector: None,
    });
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let cds = snapshot.resources(CDS_TYPE_URL);
    assert_eq!(cds.len(), 1);
    assert_eq!(cds[0].name, "cluster/default/api/8080");

    let eds = snapshot.resources(EDS_TYPE_URL);
    assert_eq!(eds.len(), 1);
    assert_eq!(eds[0].name, "cluster/default/api/8080");
}

#[test]
fn service_entry_workload_selector_does_not_hide_visible_entry() {
    let mut mesh = mesh_config();
    mesh.service_entries.push(ServiceEntry {
        name: "vm-backed-api".to_string(),
        namespace: "default".to_string(),
        hosts: vec!["vm.example.test".to_string()],
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        export_to: Vec::new(),
        workload_selector: Some(WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "vm-backend".to_string())]),
            namespace: Some("default".to_string()),
        }),
    });
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest {
        node_id: "sidecar-api".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: Some("spiffe://cluster.local/ns/default/sa/api".to_string()),
        labels: BTreeMap::new(),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: false,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        waypoint_name: None,
    };

    let slice = MeshSlice::from_gateway_config(&config, request);

    assert_eq!(slice.service_entries.len(), 1);
    assert_eq!(slice.service_entries[0].name, "vm-backed-api");
}

#[test]
fn translators_deduplicate_colliding_listener_and_route_resources() {
    let mut mesh = mesh_config();
    mesh.services.push(mesh.services[0].clone());
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let lds = snapshot.resources(LDS_TYPE_URL);
    assert_eq!(lds.len(), 1);
    assert_eq!(lds[0].name, "listener/default/api/8080");

    let rds = snapshot.resources(RDS_TYPE_URL);
    assert_eq!(rds.len(), 1);
    assert_eq!(rds[0].name, "route/default/api");
}

#[test]
fn translator_deduplicates_colliding_sds_resources() {
    let mut mesh = mesh_config();
    let cluster_local = TrustDomain::new("cluster.local").expect("valid trust domain");
    let partner = TrustDomain::new("partner.local").expect("valid trust domain");
    mesh.trust_bundles = Some(TrustBundleSet {
        local: TrustBundle {
            trust_domain: cluster_local.clone(),
            x509_authorities: vec!["local-ca".to_string()],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: vec![
            TrustBundle {
                trust_domain: partner.clone(),
                x509_authorities: vec!["partner-ca".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            TrustBundle {
                trust_domain: partner,
                x509_authorities: vec!["partner-ca-duplicate".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            TrustBundle {
                trust_domain: cluster_local,
                x509_authorities: vec!["local-ca-duplicate".to_string()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
        ],
    });
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let slice = MeshSlice::from_gateway_config(&config, request);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);

    let secrets = snapshot.resources(SDS_TYPE_URL);
    let secret_names: std::collections::HashSet<_> = secrets
        .iter()
        .map(|resource| resource.name.as_str())
        .collect();

    assert_eq!(secrets.len(), 2);
    assert!(secret_names.contains("secret/spiffe-bundle/cluster.local"));
    assert!(secret_names.contains("secret/spiffe-bundle/partner.local"));
}

#[test]
fn mesh_slice_content_eq_ignores_only_version() {
    let config = gateway_config();
    let request = MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string());
    let mut left = MeshSlice::from_gateway_config(&config, request.clone());
    let mut right = MeshSlice::from_gateway_config(&config, request);

    right.version = "different-version".to_string();
    assert!(left.content_eq(&right));

    left.namespace = "other".to_string();
    assert!(!left.content_eq(&right));

    left.namespace = right.namespace.clone();
    right.multi_cluster = Some(ferrum_edge::modes::mesh::config::MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        ..Default::default()
    });
    assert!(!left.content_eq(&right));
}

#[test]
fn snapshot_cache_is_keyed_by_node_id() {
    let cache = XdsSnapshotCache::new();
    let mut slice_a = MeshSlice::from_gateway_config(
        &gateway_config(),
        MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string()),
    );
    let mut slice_b = slice_a.clone();
    slice_b.node_id = "node-b".to_string();
    slice_a.version = "v1".to_string();
    slice_b.version = "v2".to_string();

    cache.insert(translate_mesh_slice_to_snapshot(&slice_a));
    cache.insert(translate_mesh_slice_to_snapshot(&slice_b));

    assert_eq!(cache.len(), 2);
    assert!(cache.get("node-a").unwrap().version.starts_with("v1:"));
    assert!(cache.get("node-b").unwrap().version.starts_with("v2:"));
}

#[test]
fn snapshot_reports_resource_removal_by_type_url() {
    let slice = MeshSlice::from_gateway_config(
        &gateway_config(),
        MeshSliceRequest::from_xds_node("node-a".to_string(), "default".to_string()),
    );
    let before = translate_mesh_slice_to_snapshot(&slice);
    let mut after_slice = slice.clone();
    after_slice.services.clear();
    let after = translate_mesh_slice_to_snapshot(&after_slice);

    assert_eq!(
        before.removed_resource_names(&after, CDS_TYPE_URL),
        vec!["cluster/default/api/8080".to_string()]
    );
}

#[test]
fn nonce_tracker_keeps_ack_state_per_node_and_type_url() {
    let tracker = XdsNonceTracker::new();
    let lds_nonce = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v1");
    let rds_nonce = tracker.issue_nonce("node-a", RDS_TYPE_URL, "v1");

    assert_eq!(
        tracker.record_response(
            "node-a",
            LDS_TYPE_URL,
            &lds_nonce,
            "v1",
            Some("bad listener")
        ),
        AckOutcome::Nacked {
            message: "bad listener".to_string()
        }
    );
    assert_eq!(
        tracker.record_response("node-a", RDS_TYPE_URL, &rds_nonce, "v1", None),
        AckOutcome::Acked
    );
    assert_eq!(
        tracker.last_error("node-a", LDS_TYPE_URL),
        Some("bad listener".to_string())
    );
    assert_eq!(tracker.last_error("node-a", RDS_TYPE_URL), None);
}

#[test]
fn nonce_tracker_rejects_version_drift() {
    let tracker = XdsNonceTracker::new();
    let nonce = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v2");

    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &nonce, "v1", None),
        AckOutcome::VersionDrift {
            expected: "v2".to_string(),
            actual: "v1".to_string()
        }
    );
}

#[test]
fn nonce_tracker_rejects_missing_unknown_and_stale_nonces() {
    let tracker = XdsNonceTracker::new();
    let initial = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v1");

    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, "", "v1", None),
        AckOutcome::MissingNonce
    );
    assert_eq!(
        tracker.record_response("node-b", LDS_TYPE_URL, &initial, "v1", None),
        AckOutcome::UnknownNonce
    );

    let current = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v2");
    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &initial, "v1", None),
        AckOutcome::StaleNonce {
            expected: current.clone(),
            actual: initial
        }
    );

    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &current, "v2", None),
        AckOutcome::Acked
    );
}

#[test]
fn nonce_tracker_clears_error_on_new_issue_and_removes_one_node_only() {
    let tracker = XdsNonceTracker::new();
    let failed = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v1");
    let node_b = tracker.issue_nonce("node-b", LDS_TYPE_URL, "v1");

    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &failed, "v1", Some("bad listener")),
        AckOutcome::Nacked {
            message: "bad listener".to_string()
        }
    );
    assert_eq!(
        tracker.last_error("node-a", LDS_TYPE_URL),
        Some("bad listener".to_string())
    );

    let corrected = tracker.issue_nonce("node-a", LDS_TYPE_URL, "v2");
    assert_eq!(tracker.last_error("node-a", LDS_TYPE_URL), None);
    assert_eq!(tracker.len(), 2);
    assert_eq!(
        tracker.record_response("node-a", LDS_TYPE_URL, &corrected, "v2", None),
        AckOutcome::Acked
    );

    tracker.remove_node("node-a");
    assert_eq!(tracker.len(), 1);
    assert_eq!(
        tracker.record_response("node-b", LDS_TYPE_URL, &node_b, "v1", None),
        AckOutcome::Acked
    );
}

#[test]
fn phase_b_conformance_stubs_cover_known_xds_edges() {
    let cases = required_phase_b_cases();
    assert!(cases.contains(&XdsConformanceCase::ResourceRemovalDuringUpdate));
    assert!(cases.contains(&XdsConformanceCase::PartialNackPerTypeUrl));
    assert!(cases.contains(&XdsConformanceCase::VersionDriftRejected));
    assert!(cases.contains(&XdsConformanceCase::DeltaSubscribeUnsubscribe));
}

// ── GAP-2L.3: ECDS (Extension Config Discovery Service) ──
//
// Operators ship typed extension configs through xDS by populating
// `MeshSlice.extension_configs`. The translator emits one ECDS resource per
// entry; downstream xDS consumers subscribe under `ECDS_TYPE_URL` and
// dispatch on the inner `typed_config.type_url`. The DR-carrier path
// (GAP-2K) uses `FERRUM_ECDS_DESTINATION_RULE_TYPE_URL` to wrap the original
// DestinationRule JSON when full DR semantics are required across xDS.

fn slice_with_extension_configs(configs: Vec<MeshExtensionConfig>) -> MeshSlice {
    let request = MeshSliceRequest {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: None,
        labels: BTreeMap::new(),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: false,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
        waypoint_name: None,
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig::default())),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let mut slice = MeshSlice::from_gateway_config(&config, request);
    slice.extension_configs = configs;
    slice
}

#[test]
fn translator_emits_labels_carrier_when_slice_has_no_extension_configs() {
    let slice = slice_with_extension_configs(Vec::new());
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let names: Vec<_> = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(names, vec!["ferrum-mesh-carrier/workload-labels"]);
}

#[test]
fn translator_emits_one_ecds_resource_per_extension_config() {
    let slice = slice_with_extension_configs(vec![
        MeshExtensionConfig {
            name: "dr-carrier-api".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: b"{\"name\":\"api\"}".to_vec(),
        },
        MeshExtensionConfig {
            name: "dr-carrier-admin".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: b"{\"name\":\"admin\"}".to_vec(),
        },
    ]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let names: Vec<_> = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .map(|r| r.name.clone())
        .filter(|name| !name.starts_with("ferrum-mesh-carrier/"))
        .collect();
    assert_eq!(names, vec!["dr-carrier-admin", "dr-carrier-api"]);
}

#[test]
fn translator_skips_duplicate_extension_config_names() {
    let slice = slice_with_extension_configs(vec![
        MeshExtensionConfig {
            name: "dup".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: b"{\"name\":\"first\"}".to_vec(),
        },
        MeshExtensionConfig {
            name: "dup".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: b"{\"name\":\"second\"}".to_vec(),
        },
    ]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let operator_resources = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .filter(|resource| !resource.name.starts_with("ferrum-mesh-carrier/"))
        .count();
    assert_eq!(operator_resources, 1);
}

#[test]
fn translator_skips_extension_configs_that_impersonate_slice_carriers() {
    let slice = slice_with_extension_configs(vec![
        MeshExtensionConfig {
            name: "operator-mesh-policies".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_MESH_POLICIES_TYPE_URL.to_string(),
            value: b"[]".to_vec(),
        },
        MeshExtensionConfig {
            name: "ferrum-mesh-carrier/services".to_string(),
            namespace: "default".to_string(),
            type_url: "type.googleapis.com/example.OperatorExtension".to_string(),
            value: b"{}".to_vec(),
        },
        MeshExtensionConfig {
            name: "dr-carrier-api".to_string(),
            namespace: "default".to_string(),
            type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
            value: b"{\"name\":\"api\"}".to_vec(),
        },
    ]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let names: Vec<_> = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .map(|r| r.name.clone())
        .filter(|name| !name.starts_with("ferrum-mesh-carrier/"))
        .collect();
    assert_eq!(names, vec!["dr-carrier-api"]);
}

#[test]
fn translator_round_trips_typed_extension_config_payload() {
    let inner_value = b"{\"trafficPolicy\":{\"tls\":{\"mode\":\"ISTIO_MUTUAL\"}}}";
    let slice = slice_with_extension_configs(vec![MeshExtensionConfig {
        name: "dr-carrier-reviews".to_string(),
        namespace: "default".to_string(),
        type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
        value: inner_value.to_vec(),
    }]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let resources = snapshot.resources(ECDS_TYPE_URL);
    let entry = resources.first().expect("ECDS resource");
    let decoded = proto::TypedExtensionConfig::decode(entry.value.as_slice())
        .expect("ECDS payload should decode as TypedExtensionConfig");
    assert_eq!(decoded.name, "dr-carrier-reviews");
    let typed_config = decoded.typed_config.expect("inner Any should be set");
    assert_eq!(typed_config.type_url, FERRUM_ECDS_DESTINATION_RULE_TYPE_URL);
    assert_eq!(typed_config.value, inner_value.to_vec());
}

#[test]
fn ecds_type_url_appears_in_xds_type_urls_inventory() {
    let inventory: Vec<&str> = ferrum_edge::xds::XDS_TYPE_URLS.to_vec();
    assert!(
        inventory.contains(&ECDS_TYPE_URL),
        "ECDS_TYPE_URL must be in XDS_TYPE_URLS"
    );
}
#[test]
fn translator_round_trips_binary_value_bytes() {
    // Binary payload with NULs and high bytes — exercises the base64 codec.
    let binary: Vec<u8> = (0u8..=255).collect();
    let slice = slice_with_extension_configs(vec![MeshExtensionConfig {
        name: "binary".to_string(),
        namespace: "default".to_string(),
        type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
        value: binary.clone(),
    }]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let entry = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .find(|resource| resource.name == "binary")
        .cloned()
        .expect("ECDS resource");
    let decoded = proto::TypedExtensionConfig::decode(entry.value.as_slice())
        .expect("TypedExtensionConfig decode");
    assert_eq!(decoded.typed_config.expect("inner Any").value, binary);
}

#[test]
fn translator_emits_empty_value_when_extension_has_no_inner_bytes() {
    let slice = slice_with_extension_configs(vec![MeshExtensionConfig {
        name: "no-bytes".to_string(),
        namespace: "default".to_string(),
        type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
        value: Vec::new(),
    }]);
    let snapshot = translate_mesh_slice_to_snapshot(&slice);
    let entry = snapshot
        .resources(ECDS_TYPE_URL)
        .iter()
        .find(|resource| resource.name == "no-bytes")
        .cloned()
        .expect("ECDS resource");
    let decoded = proto::TypedExtensionConfig::decode(entry.value.as_slice())
        .expect("TypedExtensionConfig decode");
    assert_eq!(decoded.name, "no-bytes");
    let typed_config = decoded.typed_config.expect("inner Any should be set");
    assert!(typed_config.value.is_empty());
}

#[test]
fn mesh_extension_config_serde_round_trips_base64_value() {
    // Mixed binary payload — exercises the base64 STANDARD codec inside
    // `MeshExtensionConfig::value`. CPs and DPs both serialize through serde
    // (gRPC JSON / native config), so the codec must round-trip arbitrary
    // bytes without corruption.
    let original = MeshExtensionConfig {
        name: "binary".to_string(),
        namespace: "default".to_string(),
        type_url: FERRUM_ECDS_DESTINATION_RULE_TYPE_URL.to_string(),
        value: vec![0u8, 1, 2, 0xff, 0xfe, 0x7f, 0x00],
    };
    let json = serde_json::to_string(&original).expect("serialize");
    // value field must be a base64 STANDARD string, not raw bytes / array.
    assert!(json.contains("\"value\":\"AAEC//5/AA==\""));
    let parsed: MeshExtensionConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original);
}

#[test]
fn mesh_extension_config_deserialize_accepts_unpadded_base64() {
    // Some CPs strip base64 padding; the decoder must accept both forms so
    // a payload encoded by an upstream Envoy / Istio CP still round-trips.
    let canonical = serde_json::json!({
        "name": "pad",
        "type_url": FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
        "value": "AAEC//5/AA==",
    });
    let stripped = serde_json::json!({
        "name": "pad",
        "type_url": FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
        "value": "AAEC//5/AA",
    });
    let from_padded: MeshExtensionConfig =
        serde_json::from_value(canonical).expect("padded decode");
    let from_unpadded: MeshExtensionConfig =
        serde_json::from_value(stripped).expect("unpadded decode");
    assert_eq!(from_padded.value, from_unpadded.value);
    assert_eq!(from_padded.value, vec![0u8, 1, 2, 0xff, 0xfe, 0x7f, 0x00]);
}

#[test]
fn mesh_extension_config_deserialize_accepts_empty_value() {
    let json = serde_json::json!({
        "name": "empty",
        "type_url": FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
        "value": "",
    });
    let parsed: MeshExtensionConfig = serde_json::from_value(json).expect("empty decode");
    assert!(parsed.value.is_empty());
}

#[test]
fn mesh_extension_config_default_value_when_field_omitted() {
    // Schema-level default keeps backward compat for callers that build the
    // type programmatically without the inner bytes.
    let json = serde_json::json!({
        "name": "omitted",
        "type_url": FERRUM_ECDS_DESTINATION_RULE_TYPE_URL,
    });
    let parsed: MeshExtensionConfig = serde_json::from_value(json).expect("omitted decode");
    assert!(parsed.value.is_empty());
}

// ── GAP-3E: RTDS subscription + MeshRuntimeOverlay round-trip ─────────────

#[test]
fn rtds_type_url_is_registered_for_subscription() {
    let inventory: Vec<&str> = ferrum_edge::xds::XDS_TYPE_URLS.to_vec();
    assert!(
        inventory.contains(&RTDS_TYPE_URL),
        "RTDS_TYPE_URL must be in XDS_TYPE_URLS so the ADS client subscribes to runtime layers"
    );
}

#[test]
fn translate_rtds_layer_maps_numeric_string_bool_and_fractional_percent() {
    use ferrum_edge::modes::mesh::config::{
        FractionalPercentDenominator, RuntimeFractionalPercent, RuntimeValue,
    };
    use ferrum_edge::xds::runtime_proto;
    use runtime_proto::value::Kind;

    let mut fields = std::collections::HashMap::new();
    fields.insert(
        "envoy.reloadable_features.allow_multiplexed_response".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::BoolValue(true)),
        },
    );
    fields.insert(
        "envoy.reloadable_features.use_observable_cluster_name".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(0.25)),
        },
    );
    fields.insert(
        "envoy.access_loggers.json_default_log_level".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("warn".to_string())),
        },
    );
    let mut fractional_fields = std::collections::HashMap::new();
    fractional_fields.insert(
        "numerator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(30.0)),
        },
    );
    fractional_fields.insert(
        "denominator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("HUNDRED".to_string())),
        },
    );
    fields.insert(
        "ferrum.testing.fault_injection".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StructValue(runtime_proto::Struct {
                fields: fractional_fields,
            })),
        },
    );
    // Unsupported kinds (null + list) should be silently skipped, not
    // produce placeholder entries — GAP-3E intentionally avoids fabricating
    // a semantics until a consumer needs it.
    fields.insert(
        "ferrum.testing.null".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NullValue(0)),
        },
    );
    fields.insert(
        "ferrum.testing.list".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::ListValue(runtime_proto::ListValue {
                values: Vec::new(),
            })),
        },
    );

    let layer = runtime_proto::Runtime {
        name: "rtds_layer0".to_string(),
        layer: Some(runtime_proto::Struct { fields }),
    };

    let overlay = translate_rtds_layer(&layer);
    assert_eq!(overlay.fields.len(), 4, "5th + 6th entries are skipped");

    assert_eq!(
        overlay
            .fields
            .get("envoy.reloadable_features.allow_multiplexed_response"),
        Some(&RuntimeValue::Bool(true))
    );
    assert_eq!(
        overlay
            .fields
            .get("envoy.reloadable_features.use_observable_cluster_name"),
        Some(&RuntimeValue::Number(0.25))
    );
    assert_eq!(
        overlay
            .fields
            .get("envoy.access_loggers.json_default_log_level"),
        Some(&RuntimeValue::String("warn".to_string()))
    );
    assert_eq!(
        overlay.fields.get("ferrum.testing.fault_injection"),
        Some(&RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
            numerator: 30,
            denominator: FractionalPercentDenominator::Hundred,
        }))
    );
}

#[test]
fn translate_rtds_layer_skips_malformed_fractional_percent_structs() {
    use ferrum_edge::xds::runtime_proto;
    use runtime_proto::value::Kind;

    let mut malformed_fields = std::collections::HashMap::new();
    malformed_fields.insert(
        "numerator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("not-a-number".to_string())),
        },
    );
    malformed_fields.insert(
        "denominator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("HUNDRED".to_string())),
        },
    );
    let mut wrong_denominator = std::collections::HashMap::new();
    wrong_denominator.insert(
        "numerator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(10.0)),
        },
    );
    wrong_denominator.insert(
        "denominator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("UNKNOWN".to_string())),
        },
    );
    let mut extra_field = std::collections::HashMap::new();
    extra_field.insert(
        "numerator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(10.0)),
        },
    );
    extra_field.insert(
        "denominator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StringValue("HUNDRED".to_string())),
        },
    );
    extra_field.insert(
        "extra".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::NumberValue(1.0)),
        },
    );

    let mut layer_fields = std::collections::HashMap::new();
    layer_fields.insert(
        "bad_numerator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StructValue(runtime_proto::Struct {
                fields: malformed_fields,
            })),
        },
    );
    layer_fields.insert(
        "bad_denominator".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StructValue(runtime_proto::Struct {
                fields: wrong_denominator,
            })),
        },
    );
    layer_fields.insert(
        "extra_struct_field".to_string(),
        runtime_proto::Value {
            kind: Some(Kind::StructValue(runtime_proto::Struct {
                fields: extra_field,
            })),
        },
    );

    let overlay = translate_rtds_layer(&runtime_proto::Runtime {
        name: "rtds_layer_malformed".to_string(),
        layer: Some(runtime_proto::Struct {
            fields: layer_fields,
        }),
    });
    assert!(overlay.is_empty(), "malformed structs must be dropped");
}

#[test]
fn translate_rtds_layer_with_empty_payload_yields_empty_overlay() {
    use ferrum_edge::xds::runtime_proto;
    let layer = runtime_proto::Runtime {
        name: "rtds_layer_empty".to_string(),
        layer: None,
    };
    assert!(translate_rtds_layer(&layer).is_empty());
}

#[test]
fn mesh_slice_serde_round_trips_runtime_overlay() {
    use ferrum_edge::modes::mesh::config::{
        FractionalPercentDenominator, MeshRuntimeOverlay, RuntimeFractionalPercent, RuntimeValue,
    };

    let mut fields = std::collections::HashMap::new();
    fields.insert("k_bool".to_string(), RuntimeValue::Bool(true));
    fields.insert("k_num".to_string(), RuntimeValue::Number(0.5));
    fields.insert(
        "k_str".to_string(),
        RuntimeValue::String("info".to_string()),
    );
    fields.insert(
        "k_frac".to_string(),
        RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
            numerator: 42,
            denominator: FractionalPercentDenominator::TenThousand,
        }),
    );
    let original = MeshSlice {
        version: "v-runtime".to_string(),
        runtime_overlay: MeshRuntimeOverlay { fields },
        ..MeshSlice::default()
    };

    let json = serde_json::to_string(&original).expect("serialize");
    let parsed: MeshSlice = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.runtime_overlay, original.runtime_overlay);
    assert!(
        json.contains("\"runtime_overlay\""),
        "non-empty overlay must serialize"
    );
}

#[test]
fn mesh_slice_without_runtime_overlay_decodes_via_serde_default() {
    // The legacy slice payload (no `runtime_overlay` key at all) must keep
    // decoding so a DP running an older CP or an older serialized blob
    // doesn't crash on `Missing field`. The default is an empty overlay.
    let legacy_payload = serde_json::json!({
        "node_id": "node-a",
        "namespace": "default",
        "version": "v1",
    });
    let parsed: MeshSlice =
        serde_json::from_value(legacy_payload).expect("legacy slice must round-trip");
    assert!(
        parsed.runtime_overlay.is_empty(),
        "missing field must default to empty overlay"
    );
    // Re-serialize: empty overlay must be elided (skip_serializing_if).
    let json = serde_json::to_string(&parsed).expect("re-serialize");
    assert!(
        !json.contains("runtime_overlay"),
        "empty overlay must be elided to keep non-RTDS deployments byte-identical"
    );
}

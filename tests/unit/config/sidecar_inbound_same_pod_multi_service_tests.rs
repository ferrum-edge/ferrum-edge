//! Same-pod multi-Service inbound identity: one pod selected by several
//! Services must stay in the local-inbound view when every record carries the
//! same non-empty pod UID. Missing or divergent UIDs stay fail-closed even
//! when addresses match; addresses and labels are not same-pod proof.

use std::collections::{BTreeMap, HashMap};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarEgress, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

const POD_UID: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
const OTHER_POD_UID: &str = "16b2c3d4-9dad-11d1-80b4-00c04fd430c8";

fn trust_domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

fn local_workload(
    service_name: &str,
    spiffe: &str,
    addresses: &[&str],
    pod_uid: Option<&str>,
) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(spiffe).expect("spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "shared-app".to_string())]),
            namespace: Some("default".to_string()),
        },
        service_name: service_name.to_string(),
        service_namespace: None,
        addresses: addresses
            .iter()
            .map(|address| (*address).to_string())
            .collect(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: trust_domain(),
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("shared".to_string()),
        pod_uid: pod_uid.map(str::to_string),
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn mesh_service(name: &str, spiffe: &str) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: SpiffeId::new(spiffe).expect("spiffe"),
        }],
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    }
}

fn namespace_sidecar() -> MeshSidecar {
    MeshSidecar {
        name: "default-sc".to_string(),
        namespace: "default".to_string(),
        workload_selector: None,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: vec!["./*".to_string()],
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: None,
    }
}

fn enforced_slice_request(spiffe: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-1".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: Some(spiffe.to_string()),
        waypoint_name: None,
        labels: BTreeMap::new(),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: true,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
    }
}

fn slice_for(workloads: Vec<Workload>, services: Vec<MeshService>, spiffe: &str) -> MeshSlice {
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            sidecars: vec![namespace_sidecar()],
            workloads,
            services,
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    MeshSlice::from_gateway_config(&config, enforced_slice_request(spiffe))
}

fn inbound_service_names(slice: &MeshSlice) -> Vec<String> {
    let mut names: Vec<String> = slice
        .local_inbound_services
        .iter()
        .map(|service| service.name.clone())
        .collect();
    names.sort();
    names
}

fn inbound_workload_services(slice: &MeshSlice) -> Vec<String> {
    let mut names: Vec<String> = slice
        .local_inbound_workloads
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|workload| workload.service_name.clone())
        .collect();
    names.sort();
    names
}

fn assert_slice_validates_as_mesh_config(slice: &MeshSlice) {
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: slice.workloads.clone(),
            services: slice.services.clone(),
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let errors = config.validate_mesh_fields();
    assert!(
        errors.is_empty(),
        "the projected slice must validate exactly as the proxy apply path \
         validates it, got {errors:?}"
    );
}

fn assert_inbound_is_empty(slice: &MeshSlice, reason: &str) {
    assert_eq!(
        slice
            .local_inbound_workloads
            .as_deref()
            .map(|workloads| workloads.len()),
        Some(0),
        "{reason}"
    );
    assert!(
        slice.local_inbound_services.is_empty(),
        "an ambiguous local identity must not keep either Service as an inbound anchor"
    );
    assert_slice_validates_as_mesh_config(slice);
}

#[test]
fn same_nonempty_pod_uid_across_multiple_services_materializes_all_inbound_hosts() {
    let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
    let slice = slice_for(
        vec![
            local_workload("reviews", spiffe, &["10.0.0.7"], Some(POD_UID)),
            local_workload("ratings", spiffe, &["10.0.0.7"], Some(POD_UID)),
        ],
        vec![
            mesh_service("reviews", spiffe),
            mesh_service("ratings", spiffe),
        ],
        spiffe,
    );

    assert_eq!(
        inbound_workload_services(&slice),
        vec!["ratings".to_string(), "reviews".to_string()],
        "one pod selected by two Services must keep both workload records in the inbound view"
    );
    assert_eq!(
        inbound_service_names(&slice),
        vec!["ratings".to_string(), "reviews".to_string()],
        "inbound services must include every Service that pod backs"
    );
    assert_slice_validates_as_mesh_config(&slice);
}

#[test]
fn divergent_pod_uids_with_the_same_address_fail_closed() {
    let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
    let slice = slice_for(
        vec![
            local_workload("reviews", spiffe, &["10.0.0.7"], Some(POD_UID)),
            local_workload("ratings", spiffe, &["10.0.0.7"], Some(OTHER_POD_UID)),
        ],
        vec![
            mesh_service("reviews", spiffe),
            mesh_service("ratings", spiffe),
        ],
        spiffe,
    );

    assert_inbound_is_empty(
        &slice,
        "divergent pod UIDs are distinct pods even when addresses match; \
         hostNetwork sharing an IP must not materialize inbound Hosts",
    );
}

#[test]
fn missing_pod_uids_with_the_same_address_fail_closed() {
    let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
    let slice = slice_for(
        vec![
            local_workload("reviews", spiffe, &["10.0.0.7"], None),
            local_workload("ratings", spiffe, &["10.0.0.7"], None),
        ],
        vec![
            mesh_service("reviews", spiffe),
            mesh_service("ratings", spiffe),
        ],
        spiffe,
    );

    assert_inbound_is_empty(
        &slice,
        "missing pod UIDs cannot prove sameness from a shared address set",
    );
}

#[test]
fn mixed_missing_and_divergent_pod_uids_cannot_fall_back_to_addresses() {
    let spiffe = "spiffe://cluster.local/ns/default/sa/shared";
    let slice = slice_for(
        vec![
            local_workload("reviews", spiffe, &["10.0.0.7"], Some(POD_UID)),
            local_workload("ratings", spiffe, &["10.0.0.7"], None),
            local_workload("details", spiffe, &["10.0.0.7"], Some(OTHER_POD_UID)),
        ],
        vec![
            mesh_service("reviews", spiffe),
            mesh_service("ratings", spiffe),
            mesh_service("details", spiffe),
        ],
        spiffe,
    );

    assert_inbound_is_empty(
        &slice,
        "a set mixing missing UIDs with divergent known UIDs must stay \
         ambiguous even when every address set matches",
    );
}

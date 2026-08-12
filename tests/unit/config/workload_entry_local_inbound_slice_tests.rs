//! Local inbound slice resolution for authorized cross-namespace WorkloadEntry
//! attachments (issue #3244): service identity keys by attached Service namespace,
//! not the WorkloadEntry identity namespace.

use std::collections::{BTreeMap, HashMap};

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarEgress, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

fn trust_domain() -> TrustDomain {
    TrustDomain::new("cluster.local").expect("trust domain")
}

fn cross_namespace_workload(
    identity_namespace: &str,
    service_name: &str,
    attached_service_namespace: &str,
    spiffe: &str,
    labels: HashMap<String, String>,
) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(spiffe).expect("spiffe"),
        selector: WorkloadSelector {
            labels,
            namespace: Some(identity_namespace.to_string()),
        },
        service_name: service_name.to_string(),
        service_namespace: Some(attached_service_namespace.to_string()),
        addresses: vec!["10.9.0.5".to_string()],
        ports: vec![WorkloadPort {
            port: 9080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: trust_domain(),
        namespace: identity_namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews-vm".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn mesh_service(namespace: &str, name: &str, workload_spiffe: Option<&str>) -> MeshService {
    MeshService {
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 9080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: workload_spiffe
            .map(|spiffe| {
                vec![WorkloadRef {
                    spiffe_id: SpiffeId::new(spiffe).expect("spiffe"),
                }]
            })
            .unwrap_or_default(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    }
}

fn egress_narrowing_sidecar(namespace: &str) -> MeshSidecar {
    MeshSidecar {
        name: "default-sc".to_string(),
        namespace: namespace.to_string(),
        workload_selector: None,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: vec!["./checkout".to_string()],
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: None,
    }
}

fn enforced_slice_request(
    namespace: &str,
    spiffe: &str,
    waypoint_name: Option<&str>,
) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-1".to_string(),
        namespace: namespace.to_string(),
        workload_spiffe_id: Some(spiffe.to_string()),
        waypoint_name: waypoint_name.map(str::to_string),
        labels: BTreeMap::new(),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: true,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
    }
}

#[test]
fn sidecar_narrowing_retains_cross_namespace_attached_local_inbound_service() {
    // WorkloadEntry identity stays in `vms` while the authorized Service lives in
    // `prod`. Egress narrowing drops `reviews` from `services`; the inbound-only
    // view must still anchor the attached `prod/reviews` Service without requiring
    // a service-waypoint subscription (which would strip egress-admitted peers).
    let spiffe = "spiffe://cluster.local/ns/vms/sa/reviews-vm";
    let workload = cross_namespace_workload(
        "vms",
        "reviews",
        "prod",
        spiffe,
        HashMap::from([("app".to_string(), "reviews".to_string())]),
    );
    let mesh = MeshConfig {
        sidecars: vec![egress_narrowing_sidecar("vms")],
        workloads: vec![workload],
        services: vec![
            mesh_service("prod", "reviews", Some(spiffe)),
            mesh_service("vms", "checkout", None),
            // Decoy same-name Service in the identity namespace must not satisfy
            // the local inbound anchor for the cross-namespace attachment.
            mesh_service("vms", "reviews", None),
        ],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let slice =
        MeshSlice::from_gateway_config(&config, enforced_slice_request("vms", spiffe, None));

    assert!(
        !slice
            .services
            .iter()
            .any(|service| service.name == "reviews"),
        "egress-narrowed services must not include the local attached service"
    );
    assert!(
        slice
            .services
            .iter()
            .any(|service| service.name == "checkout"),
        "egress-admitted services remain in the outbound view"
    );
    assert!(
        slice
            .local_inbound_services
            .iter()
            .any(|service| { service.name == "reviews" && service.namespace == "prod" }),
        "local inbound must retain the authorized attached Service in its target namespace"
    );
    assert!(
        !slice
            .local_inbound_services
            .iter()
            .any(|service| service.namespace == "vms" && service.name == "reviews"),
        "must not anchor inbound traffic to a same-name Service in the identity namespace"
    );
}

#[test]
fn shared_spiffe_same_service_name_different_attached_namespaces_is_ambiguous() {
    // Two authorized cross-namespace attachments share one service-account SPIFFE
    // and `service_name` but attach to distinct target Service namespaces. That
    // must fail closed rather than collapse to one unambiguous local service.
    let spiffe = "spiffe://cluster.local/ns/vms/sa/shared";
    let prod_workload = cross_namespace_workload("vms", "reviews", "prod", spiffe, HashMap::new());
    let default_workload =
        cross_namespace_workload("vms", "reviews", "default", spiffe, HashMap::new());
    let mesh = MeshConfig {
        sidecars: vec![egress_narrowing_sidecar("vms")],
        workloads: vec![prod_workload, default_workload],
        services: vec![
            mesh_service("prod", "reviews", Some(spiffe)),
            mesh_service("default", "reviews", Some(spiffe)),
            mesh_service("vms", "checkout", None),
        ],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let slice =
        MeshSlice::from_gateway_config(&config, enforced_slice_request("vms", spiffe, None));

    assert_eq!(
        slice.local_inbound_workloads,
        Some(Vec::new()),
        "distinct attached Service namespaces must not collapse into one unambiguous local workload"
    );
    assert!(
        slice.local_inbound_services.is_empty(),
        "ambiguous local workload resolution must not materialize inbound service anchors"
    );
}

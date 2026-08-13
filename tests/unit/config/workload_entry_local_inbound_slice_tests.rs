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

/// An ordinary subscription: no Sidecar, no waypoint, so `services` narrow by
/// plain namespace visibility.
fn plain_slice_request(namespace: &str) -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "node-1".to_string(),
        namespace: namespace.to_string(),
        cluster_domain: "cluster.local".to_string(),
        ..MeshSliceRequest::default()
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
    let anchored = slice
        .local_inbound_workloads
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|workload| workload.spiffe_id.as_str() == spiffe);
    assert!(
        anchored,
        "the inbound anchor keeps the local workload even though the routing view \
         narrows its out-of-view attachment away"
    );
    assert!(
        slice.workloads.is_empty(),
        "the ROUTING view drops an attachment it cannot authorize; the anchor above \
         is what serves this workload's own inbound traffic"
    );
    assert_slice_validates_as_mesh_config(&slice);
}

/// Rebuild the mesh view the proxy apply path validates before it swaps a slice
/// in (`prepare_normalized_gateway_config_for_mesh`), and assert it is valid.
///
/// A slice that fails this is not merely missing one resource: the apply is
/// rejected and the runtime rolls back to the last applied generation, so every
/// later generation — including a legitimate withdrawal — stops being applied.
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

#[test]
fn cross_namespace_attachment_outside_the_view_narrows_out_of_the_slice() {
    // The attaching Service lives outside this subscription's namespace view, so
    // service narrowing drops it. Keeping the workload alone would leave an
    // attachment nothing in the slice can authorize — `validate_mesh_config`
    // refuses exactly that shape, and the apply-time refusal rolls the runtime
    // back to the last applied generation, so one out-of-view discovery
    // resource would block every later update. The endpoint narrows instead:
    // without its Service this view has no route to it either way.
    let spiffe = "spiffe://cluster.local/ns/default/sa/payments";
    let workload = cross_namespace_workload(
        "default",
        "payments",
        "other",
        spiffe,
        HashMap::from([("app".to_string(), "payments".to_string())]),
    );
    let mesh = MeshConfig {
        workloads: vec![workload],
        services: vec![
            // Authorized where it was authored: the target Service does list the
            // workload. It is still outside THIS workload's namespace view.
            mesh_service("other", "payments", Some(spiffe)),
            mesh_service("default", "checkout", None),
        ],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let slice = MeshSlice::from_gateway_config(&config, plain_slice_request("default"));

    assert!(
        slice
            .services
            .iter()
            .all(|service| service.namespace == "default"),
        "a Service outside the namespace view must not enter the slice"
    );
    assert!(
        slice.workloads.is_empty(),
        "the endpoint must narrow with the Service that authorizes its attachment"
    );
    assert_slice_validates_as_mesh_config(&slice);
}

#[test]
fn same_namespace_attachment_is_unaffected_by_the_cross_namespace_narrowing() {
    // The overwhelmingly common shape: no `service_namespace` stamp at all. It
    // must be untouched by the cross-namespace narrowing above.
    let spiffe = "spiffe://cluster.local/ns/default/sa/checkout";
    let mut workload = cross_namespace_workload(
        "default",
        "checkout",
        "default",
        spiffe,
        HashMap::from([("app".to_string(), "checkout".to_string())]),
    );
    workload.service_namespace = None;
    let mesh = MeshConfig {
        workloads: vec![workload],
        services: vec![mesh_service("default", "checkout", Some(spiffe))],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let slice = MeshSlice::from_gateway_config(&config, plain_slice_request("default"));

    assert_eq!(
        slice.workloads.len(),
        1,
        "a same-namespace attachment stays dialable"
    );
    assert_eq!(slice.services.len(), 1);
    assert_slice_validates_as_mesh_config(&slice);
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

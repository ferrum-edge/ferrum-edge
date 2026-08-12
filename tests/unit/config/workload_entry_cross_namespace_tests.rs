//! Cross-namespace WorkloadEntry → Service attachment (issue #3244).
//!
//! Contract: a WorkloadEntry whose `spec.service` host resolves to a Service in
//! another namespace attaches only when a Gateway API ReferenceGrant in the
//! *target* Service namespace permits WorkloadEntry → Service and the Service
//! exists in the translated inventory. Same-namespace hosts keep prior
//! behavior. Missing, unauthorized, or stale targets fail closed.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshService, ServicePort, Workload, WorkloadRef, WorkloadSelector,
    validate_mesh_config,
};
use ferrum_edge::xds::carrier::MeshSliceCarrier;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
}

fn object(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: None,
            labels: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: HashMap::new(),
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn service(name: &str, namespace: &str) -> K8sObject {
    object(
        "v1",
        "Service",
        name,
        namespace,
        json!({ "ports": [{ "port": 9080, "name": "http", "targetPort": 9080 }] }),
    )
}

fn reference_grant(from_namespace: &str, to_namespace: &str, service_name: &str) -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        "allow-we",
        to_namespace,
        json!({
            "from": [{
                "group": "networking.istio.io",
                "kind": "WorkloadEntry",
                "namespace": from_namespace
            }],
            "to": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }]
        }),
    )
}

fn workload_entry(namespace: &str, service_host: &str, address: &str) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "WorkloadEntry",
        "vm-reviews",
        namespace,
        json!({
            "address": address,
            "serviceAccount": "reviews-vm",
            "service": service_host,
            "ports": { "http": 9080 }
        }),
    )
}

fn ready_service_pod(namespace: &str) -> K8sObject {
    let mut pod = object(
        "v1",
        "Pod",
        "reviews-v1",
        namespace,
        json!({
            "serviceAccountName": "reviews",
            "nodeName": "node-a",
            "containers": [{
                "ports": [{"name": "http", "containerPort": 9080, "protocol": "TCP"}]
            }]
        }),
    );
    pod.metadata
        .labels
        .insert("app".to_string(), "reviews".to_string());
    pod.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.10",
        "conditions": [{"type": "Ready", "status": "True"}]
    });
    pod
}

fn service_endpoint_slice(namespace: &str) -> K8sObject {
    let mut slice = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "reviews-abc",
        namespace,
        json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.1.0.10"],
                "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": namespace},
                "conditions": {"ready": true}
            }],
            "ports": [{"name": "http", "port": 9080}]
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "reviews".to_string(),
    );
    slice
}

#[test]
fn same_namespace_workload_entry_still_attaches_without_reference_grant() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "default"),
            workload_entry("default", "reviews", "10.2.0.9"),
        ],
        options(),
    )
    .expect("same-namespace WorkloadEntry must remain valid without a ReferenceGrant");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.2.0.9"))
        .expect("workload");
    assert_eq!(workload.service_name, "reviews");
    assert_eq!(workload.service_namespace, None);
    assert_eq!(workload.attached_service_namespace(), "default");
    let service = mesh
        .services
        .iter()
        .find(|service| service.namespace == "default" && service.name == "reviews")
        .expect("service");
    assert!(
        service
            .workloads
            .iter()
            .any(|reference| reference.spiffe_id == workload.spiffe_id)
    );
}

#[test]
fn cross_namespace_workload_entry_attaches_only_to_granted_service() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            service("reviews", "default"),
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect("authorized cross-namespace WorkloadEntry");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.9.0.5"))
        .expect("workload");
    assert_eq!(workload.namespace, "vms");
    assert_eq!(workload.service_namespace.as_deref(), Some("prod"));
    assert_eq!(
        workload.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/vms/sa/reviews-vm"
    );

    let prod = mesh
        .services
        .iter()
        .find(|service| service.namespace == "prod" && service.name == "reviews")
        .expect("prod service");
    assert_eq!(prod.workloads.len(), 1);
    assert_eq!(prod.workloads[0].spiffe_id, workload.spiffe_id);

    let local = mesh
        .services
        .iter()
        .find(|service| service.namespace == "default" && service.name == "reviews")
        .expect("default service");
    assert!(
        local.workloads.is_empty(),
        "must not attach to an unintended same-name Service"
    );
}

#[test]
fn cross_namespace_host_casing_normalizes_deterministically() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "Reviews.PROD.svc.Cluster.Local.", "10.9.0.8"),
        ],
        options(),
    )
    .expect("cased FQDN must normalize to the authorized Service key");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.9.0.8"))
        .expect("workload");
    assert_eq!(workload.service_name, "reviews");
    assert_eq!(workload.service_namespace.as_deref(), Some("prod"));
}

#[test]
fn cross_namespace_workload_entry_without_grant_is_rejected() {
    let err = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect_err("missing ReferenceGrant must fail closed");
    let err = err.to_string();
    assert!(err.contains("ReferenceGrant"), "{err}");
    assert!(err.contains("cross-namespace"), "{err}");
}

#[test]
fn cross_namespace_workload_entry_with_grant_but_missing_service_is_rejected() {
    let err = translate_k8s_objects(
        &[
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect_err("missing Service must fail closed");
    assert!(
        err.to_string()
            .contains("not present in the translated inventory"),
        "{err}"
    );
}

#[test]
fn cross_namespace_workload_entry_delete_withdraws_service_attachment() {
    let objects_with_we = [
        service("reviews", "prod"),
        reference_grant("vms", "prod", "reviews"),
        workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
    ];
    let created = translate_k8s_objects(&objects_with_we, options()).expect("create");
    let mesh = created.config.mesh.as_ref().expect("mesh");
    assert_eq!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .len(),
        1
    );

    let withdrawn = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            reference_grant("vms", "prod", "reviews"),
        ],
        options(),
    )
    .expect("delete");
    let mesh = withdrawn.config.mesh.expect("mesh");
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| !workload.addresses.iter().any(|a| a == "10.9.0.5"))
    );
    assert!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .is_empty()
    );
}

#[test]
fn reference_grant_withdrawal_removes_cross_namespace_association() {
    let authorized = [
        service("reviews", "prod"),
        reference_grant("vms", "prod", "reviews"),
        workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
    ];
    let created = translate_k8s_objects(&authorized, options()).expect("authorized create");
    assert!(
        created
            .config
            .mesh
            .as_ref()
            .expect("mesh")
            .workloads
            .iter()
            .any(|workload| workload.service_namespace.as_deref() == Some("prod"))
    );

    let (withdrawn, skipped) = translate_k8s_objects_collecting_skips(
        &[
            service("reviews", "prod"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect("grant withdrawal must skip the WorkloadEntry fail-closed");
    assert!(
        !skipped.is_empty(),
        "withdrawn grant must record a skip error"
    );
    assert!(
        skipped
            .values()
            .any(|error| error.to_string().contains("ReferenceGrant")),
        "{skipped:?}"
    );
    let mesh = withdrawn.config.mesh.expect("mesh");
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| !workload.addresses.iter().any(|a| a == "10.9.0.5")),
        "grant withdrawal must remove the WorkloadEntry from the mesh"
    );
    assert!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .is_empty(),
        "grant withdrawal must clear Service workload refs"
    );
}

#[test]
fn target_service_withdrawal_removes_cross_namespace_association() {
    let authorized = [
        service("reviews", "prod"),
        reference_grant("vms", "prod", "reviews"),
        workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
    ];
    let created = translate_k8s_objects(&authorized, options()).expect("authorized create");
    assert!(
        created
            .config
            .mesh
            .as_ref()
            .expect("mesh")
            .workloads
            .iter()
            .any(|workload| {
                workload.addresses.iter().any(|a| a == "10.9.0.5")
                    && workload.service_namespace.as_deref() == Some("prod")
            })
    );

    let (withdrawn, skipped) = translate_k8s_objects_collecting_skips(
        &[
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect("missing target Service must skip fail-closed");
    assert!(
        skipped.values().any(|error| {
            error
                .to_string()
                .contains("not present in the translated inventory")
        }),
        "{skipped:?}"
    );
    // With the target Service gone, the WorkloadEntry is skipped and the
    // remaining ReferenceGrant does not populate mesh state. An empty overlay
    // serializes as `None`, which is itself proof the association withdrew.
    assert!(
        withdrawn.config.mesh.as_ref().is_none_or(|mesh| {
            mesh.workloads
                .iter()
                .all(|workload| !workload.addresses.iter().any(|a| a == "10.9.0.5"))
                && mesh
                    .services
                    .iter()
                    .filter(|service| service.name == "reviews")
                    .all(|service| service.workloads.is_empty())
        }),
        "target Service withdrawal must clear the cross-namespace association"
    );
}

#[test]
fn watcher_ordering_workload_entry_before_grant_then_succeeds() {
    // Simulate a WorkloadEntry arriving before its grant/Service (watcher
    // ordering): first reconcile skips fail-closed; a later reconcile with the
    // full inventory attaches.
    let early = [
        workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        service("reviews", "prod"),
    ];
    let (early_translation, skipped) =
        translate_k8s_objects_collecting_skips(&early, options()).expect("early reconcile");
    assert!(
        skipped
            .values()
            .any(|error| error.to_string().contains("ReferenceGrant")),
        "early WorkloadEntry without grant must be skipped: {skipped:?}"
    );
    assert!(
        early_translation
            .config
            .mesh
            .as_ref()
            .expect("mesh")
            .workloads
            .iter()
            .all(|workload| !workload.addresses.iter().any(|a| a == "10.9.0.5"))
    );

    let later = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
        ],
        options(),
    )
    .expect("later reconcile with grant+service must attach");
    let mesh = later.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.9.0.5"))
        .expect("workload");
    assert_eq!(workload.service_namespace.as_deref(), Some("prod"));
}

#[test]
fn full_inventory_order_cannot_widen_explicit_cross_namespace_membership() {
    // Informer snapshots have no kind ordering. Put the WorkloadEntry before
    // both admission dependencies and include a selectable Pod/EndpointSlice:
    // the accepted explicit attachment must still suppress auto-derived Pod
    // membership for the target Service.
    let result = translate_k8s_objects(
        &[
            workload_entry("vms", "reviews.prod.svc.cluster.local", "10.9.0.5"),
            ready_service_pod("prod"),
            service_endpoint_slice("prod"),
            reference_grant("vms", "prod", "reviews"),
            service("reviews", "prod"),
        ],
        options(),
    )
    .expect("complete shuffled inventory must attach deterministically");

    let mesh = result.config.mesh.expect("mesh");
    let service = mesh
        .services
        .iter()
        .find(|service| service.namespace == "prod" && service.name == "reviews")
        .expect("target service");
    assert_eq!(
        service.workloads.len(),
        1,
        "explicit WorkloadEntry ownership must not widen to the selectable Pod"
    );
    assert_eq!(
        service.workloads[0].spiffe_id.as_str(),
        "spiffe://cluster.local/ns/vms/sa/reviews-vm"
    );
}

#[test]
fn ambiguous_two_label_host_does_not_spoof_cross_namespace_attachment() {
    let result = translate_k8s_objects(
        &[
            service("reviews", "prod"),
            reference_grant("vms", "prod", "reviews"),
            workload_entry("vms", "reviews.prod", "10.9.0.7"),
        ],
        options(),
    )
    .expect("ambiguous two-label DNS must stay literal");

    let mesh = result.config.mesh.expect("mesh");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.addresses.iter().any(|a| a == "10.9.0.7"))
        .expect("workload");
    assert_eq!(workload.service_name, "reviews.prod");
    assert_eq!(workload.service_namespace, None);
    assert!(
        mesh.services
            .iter()
            .find(|service| service.namespace == "prod" && service.name == "reviews")
            .expect("service")
            .workloads
            .is_empty(),
        "two-label DNS must not attach via confused-deputy namespace spoofing"
    );
}

#[test]
fn workloads_carrier_round_trips_service_namespace() {
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let workload = Workload {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/vms/sa/reviews-vm").expect("spiffe"),
        selector: WorkloadSelector::default(),
        service_name: "reviews".to_string(),
        service_namespace: Some("prod".to_string()),
        addresses: vec!["10.9.0.5".to_string()],
        ports: Vec::new(),
        trust_domain,
        namespace: "vms".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews-vm".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let carrier = MeshSliceCarrier::Workloads(vec![workload]);
    let encoded = carrier.encode_value().expect("encode");
    let decoded = MeshSliceCarrier::decode(carrier.type_url(), &encoded)
        .expect("decode")
        .expect("recognized");
    match decoded {
        MeshSliceCarrier::Workloads(workloads) => {
            assert_eq!(workloads.len(), 1);
            assert_eq!(workloads[0].service_namespace.as_deref(), Some("prod"));
            assert_eq!(workloads[0].attached_service_namespace(), "prod");
            assert_eq!(workloads[0].namespace, "vms");
        }
        other => panic!("unexpected carrier: {other:?}"),
    }
}

#[test]
fn mesh_validation_rejects_spoofed_cross_namespace_service_namespace() {
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let spiffe = SpiffeId::new("spiffe://cluster.local/ns/vms/sa/reviews-vm").expect("spiffe");
    let workload = Workload {
        spiffe_id: spiffe,
        selector: WorkloadSelector::default(),
        service_name: "reviews".to_string(),
        service_namespace: Some("prod".to_string()),
        addresses: vec!["10.9.0.5".to_string()],
        ports: Vec::new(),
        trust_domain,
        namespace: "vms".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews-vm".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        name: "reviews".to_string(),
        namespace: "prod".to_string(),
        ports: vec![ServicePort {
            port: 9080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        // No authoritative membership — stamp alone must fail closed.
        workloads: Vec::new(),
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    };

    let errors = validate_mesh_config(&[workload], &[service], &[], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("service_namespace") && error.contains("requires")),
        "{errors:?}"
    );
}

#[test]
fn mesh_validation_accepts_authorized_cross_namespace_service_namespace() {
    let trust_domain = TrustDomain::new("cluster.local").expect("trust domain");
    let spiffe = SpiffeId::new("spiffe://cluster.local/ns/vms/sa/reviews-vm").expect("spiffe");
    let workload = Workload {
        spiffe_id: spiffe.clone(),
        selector: WorkloadSelector::default(),
        service_name: "reviews".to_string(),
        service_namespace: Some("prod".to_string()),
        addresses: vec!["10.9.0.5".to_string()],
        ports: Vec::new(),
        trust_domain,
        namespace: "vms".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews-vm".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        name: "reviews".to_string(),
        namespace: "prod".to_string(),
        ports: vec![ServicePort {
            port: 9080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef { spiffe_id: spiffe }],
        protocol_overrides: HashMap::new(),
        cluster_ips: Vec::new(),
        uid: None,
    };

    let errors = validate_mesh_config(&[workload], &[service], &[], &[], &[], &[], None);
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("service_namespace")),
        "{errors:?}"
    );
}

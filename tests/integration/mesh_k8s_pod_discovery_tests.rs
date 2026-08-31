use std::collections::{BTreeMap, HashMap};

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslation, K8sTranslationOptions, NodeWaypointInventory,
    translate_k8s_objects,
};
use ferrum_edge::ebpf::pod_watcher::build_excluded_namespaces;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::NodeWaypointEndpoint;
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    options_for_namespace("ferrum-system")
}

fn options_for_namespace(namespace: &str) -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        namespace.to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
    .with_pod_discovery_enabled(true)
}

fn object(kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "EndpointSlice" {
            "discovery.k8s.io/v1".to_string()
        } else {
            "v1".to_string()
        },
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

fn service() -> K8sObject {
    object(
        "Service",
        "default",
        "reviews",
        json!({
            "ports": [{
                "name": "http",
                "port": 9080,
                "appProtocol": "http"
            }]
        }),
    )
}

fn ready_pod() -> K8sObject {
    let mut pod = object(
        "Pod",
        "default",
        "reviews-v1",
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

fn node(name: &str, uid: &str) -> K8sObject {
    let mut node = object("Node", "", name, json!({}));
    node.metadata.uid = uid.to_string();
    node
}

fn node_waypoint_pod(node_name: &str, ip: &str, ready: bool, hbone_port: u16) -> K8sObject {
    let mut pod = object(
        "Pod",
        "ferrum-system",
        &format!("ferrum-node-waypoint-{node_name}"),
        json!({
            "serviceAccountName": "ferrum-mesh",
            "nodeName": node_name,
            "hostNetwork": true,
            "containers": [{
                "env": [{
                    "name": "FERRUM_MESH_TOPOLOGY",
                    "value": "node_waypoint"
                }],
                "ports": [{
                    "name": "hbone",
                    "containerPort": hbone_port,
                    "protocol": "TCP"
                }]
            }]
        }),
    );
    pod.metadata.labels.insert(
        "app.kubernetes.io/name".to_string(),
        "ferrum-mesh-ambient".to_string(),
    );
    pod.status = json!({
        "phase": "Running",
        "podIP": ip,
        "conditions": [{
            "type": "Ready",
            "status": if ready { "True" } else { "False" }
        }]
    });
    pod
}

fn push_pod_env(pod: &mut K8sObject, name: &str, value: &str) {
    pod.spec["containers"][0]["env"]
        .as_array_mut()
        .expect("env array")
        .push(json!({
            "name": name,
            "value": value
        }));
}

fn push_pod_env_field_ref(pod: &mut K8sObject, name: &str, field_path: &str) {
    pod.spec["containers"][0]["env"]
        .as_array_mut()
        .expect("env array")
        .push(json!({
            "name": name,
            "valueFrom": {
                "fieldRef": {
                    "fieldPath": field_path
                }
            }
        }));
}

fn node_waypoint_pod_with_spiffe(
    node_name: &str,
    ip: &str,
    ready: bool,
    hbone_port: u16,
    spiffe_id: &str,
) -> K8sObject {
    let mut pod = node_waypoint_pod(node_name, ip, ready, hbone_port);
    push_pod_env(&mut pod, "FERRUM_MESH_WORKLOAD_SPIFFE_ID", spiffe_id);
    pod
}

fn named_node_waypoint_pod(
    name: &str,
    node_name: &str,
    ip: &str,
    ready: bool,
    hbone_port: u16,
    spiffe_id: &str,
) -> K8sObject {
    let mut pod = node_waypoint_pod_with_spiffe(node_name, ip, ready, hbone_port, spiffe_id);
    pod.metadata.name = name.to_string();
    pod
}

fn terminating_node_waypoint_pod(
    name: &str,
    node_name: &str,
    ip: &str,
    hbone_port: u16,
    spiffe_id: &str,
) -> K8sObject {
    let mut pod = named_node_waypoint_pod(name, node_name, ip, true, hbone_port, spiffe_id);
    pod.metadata.deletion_timestamp = Some("2026-08-29T00:00:00Z".to_string());
    pod
}

fn scoped_prod_service_inputs() -> (K8sObject, K8sObject, K8sObject) {
    let mut service = service();
    service.metadata.namespace = "prod".to_string();
    let mut pod = ready_pod();
    pod.metadata.namespace = "prod".to_string();
    let mut slice = endpoint_slice();
    slice.metadata.namespace = "prod".to_string();
    slice.spec["endpoints"][0]["targetRef"]["namespace"] = json!("prod");
    (service, pod, slice)
}

fn endpoint_slice() -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        "default",
        "reviews-abc",
        json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["10.1.0.10"],
                "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
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

fn node_waypoint_service() -> K8sObject {
    object(
        "Service",
        "ferrum-system",
        "ferrum-mesh-ambient",
        json!({
            "ports": [{
                "name": "hbone",
                "port": 15008,
                "appProtocol": "http"
            }]
        }),
    )
}

fn node_waypoint_endpoint_slice() -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        "ferrum-system",
        "ferrum-mesh-ambient-abc",
        json!({
            "addressType": "IPv4",
            "endpoints": [{
                "addresses": ["192.0.2.10"],
                "targetRef": {
                    "kind": "Pod",
                    "name": "ferrum-node-waypoint-node-a",
                    "namespace": "ferrum-system"
                },
                "conditions": {"ready": true},
                "nodeName": "node-a"
            }],
            "ports": [{"name": "hbone", "port": 15008}]
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "ferrum-mesh-ambient".to_string(),
    );
    slice
}

#[test]
fn k8s_pod_discovery_translation_survives_mesh_slice_projection() {
    let translation = translate_k8s_objects(&[service(), ready_pod(), endpoint_slice()], options())
        .expect("K8s core translation succeeds");
    let slice = MeshSlice::from_gateway_config(
        &translation.config,
        MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            ..MeshSliceRequest::default()
        },
    );

    assert_eq!(slice.services.len(), 1);
    assert_eq!(slice.services[0].name, "reviews");
    assert_eq!(slice.services[0].ports[0].port, 9080);
    assert_eq!(slice.services[0].workloads.len(), 1);
    assert_eq!(slice.workloads.len(), 1);
    assert_eq!(slice.workloads[0].addresses, vec!["10.1.0.10"]);
    assert_eq!(
        slice.workloads[0].spiffe_id.as_str(),
        "spiffe://cluster.local/ns/default/sa/reviews"
    );
}

#[test]
fn k8s_pod_discovery_attaches_ready_node_waypoint_metadata() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    waypoint.spec["containers"][0]["env"]
        .as_array_mut()
        .expect("env array")
        .extend([
            json!({
                "name": "FERRUM_MESH_HBONE_LISTEN_ADDR",
                "value": "0.0.0.0:16008"
            }),
            json!({
                "name": "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
                "value": "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint"
            }),
        ]);

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            waypoint,
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");
    let node_waypoint = workload
        .node_waypoint
        .as_ref()
        .expect("same-node NodeWaypoint endpoint");

    assert_eq!(node_waypoint.address, "192.0.2.10");
    assert_eq!(node_waypoint.hbone_port, 16008);
    assert_eq!(
        node_waypoint.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint"
    );
    assert_eq!(node_waypoint.node_name.as_deref(), Some("node-a"));
    assert_eq!(node_waypoint.node_uid.as_deref(), Some("node-uid-a"));

    let slice = MeshSlice::from_gateway_config(
        &translation.config,
        MeshSliceRequest {
            node_id: "node-a".to_string(),
            namespace: "default".to_string(),
            labels: BTreeMap::from([("app".to_string(), "reviews".to_string())]),
            ..MeshSliceRequest::default()
        },
    );
    let slice_workload = slice
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("projected reviews workload");
    let slice_node_waypoint = slice_workload
        .node_waypoint
        .as_ref()
        .expect("projected NodeWaypoint endpoint");
    assert_eq!(slice_node_waypoint.address, "192.0.2.10");
    assert_eq!(
        slice_node_waypoint.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint"
    );
}

#[test]
fn k8s_pod_discovery_resolves_node_waypoint_downward_api_spiffe_id() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    push_pod_env_field_ref(&mut waypoint, "FERRUM_K8S_NODE_NAME", "spec.nodeName");
    push_pod_env(
        &mut waypoint,
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/$(FERRUM_K8S_NODE_NAME)",
    );

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            waypoint,
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");
    let node_waypoint = workload
        .node_waypoint
        .as_ref()
        .expect("same-node NodeWaypoint endpoint");

    assert_eq!(
        node_waypoint.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/node-a"
    );
    assert_eq!(node_waypoint.node_name.as_deref(), Some("node-a"));
}

#[test]
fn k8s_pod_discovery_attaches_node_waypoint_metadata_to_identity_only_sources() {
    // Live NodeWaypoint same-node Service allow: src-a is a captured client
    // with a ServiceAccount and no Service. Issue #4274's per-assertor grant
    // is derived from Workload.node_waypoint bindings, so identity-only
    // sources must carry the same per-node SVID as service-backed destinations.
    let waypoint_spiffe = "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/node-a";
    let source_spiffe = "spiffe://cluster.local/ns/default/sa/frontend";
    let dest_spiffe = "spiffe://cluster.local/ns/default/sa/reviews";
    let mut source = object(
        "Pod",
        "default",
        "frontend-v1",
        json!({
            "serviceAccountName": "frontend",
            "nodeName": "node-a",
            "containers": [{"name": "curl"}]
        }),
    );
    source.metadata.uid = "frontend-pod-uid".to_string();
    source
        .metadata
        .labels
        .insert("app".to_string(), "frontend".to_string());
    source
        .metadata
        .labels
        .insert("ferrum.io/mesh".to_string(), "enabled".to_string());
    source.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.20",
        "conditions": [{"type": "Ready", "status": "True"}]
    });

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            source,
            node_waypoint_pod_with_spiffe("node-a", "192.0.2.10", true, 15008, waypoint_spiffe),
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let source_workload = mesh
        .workloads
        .iter()
        .find(|workload| {
            workload.namespace == "default"
                && workload.service_account.as_deref() == Some("frontend")
                && workload.addresses.is_empty()
        })
        .expect("identity-only frontend source");
    assert_eq!(source_workload.spiffe_id.as_str(), source_spiffe);
    let source_node_waypoint = source_workload
        .node_waypoint
        .as_ref()
        .expect("identity-only source must carry NodeWaypoint metadata");
    assert_eq!(source_node_waypoint.spiffe_id.as_str(), waypoint_spiffe);
    assert_eq!(source_node_waypoint.node_name.as_deref(), Some("node-a"));

    let dest_workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");
    assert_eq!(
        dest_workload
            .node_waypoint
            .as_ref()
            .map(|endpoint| endpoint.spiffe_id.as_str()),
        Some(waypoint_spiffe)
    );

    // NodeWaypoint subscribes in its own mesh namespace; assertor inventory
    // is derived before that narrowing so the destination still trusts the
    // source identities this NodeWaypoint fronts.
    let slice = MeshSlice::from_gateway_config(
        &translation.config,
        MeshSliceRequest {
            node_id: waypoint_spiffe.to_string(),
            namespace: "ferrum-system".to_string(),
            workload_spiffe_id: Some(waypoint_spiffe.to_string()),
            ..MeshSliceRequest::default()
        },
    );
    assert!(
        slice
            .workloads
            .iter()
            .all(|workload| workload.namespace == "ferrum-system"),
        "visible routing workloads remain the NodeWaypoint subscription namespace"
    );
    assert_eq!(slice.node_waypoint_assertors.len(), 1);
    let assertor = &slice.node_waypoint_assertors[0];
    assert_eq!(assertor.spiffe_id.as_str(), waypoint_spiffe);
    let asserted: Vec<&str> = assertor.asserts.iter().map(|id| id.as_str()).collect();
    assert_eq!(
        asserted,
        vec![source_spiffe, dest_spiffe],
        "per-assertor inventory must include identity-only sources and service-backed destinations"
    );
}

#[test]
fn k8s_pod_discovery_does_not_grant_unenrolled_identity_only_sources() {
    let waypoint_spiffe = "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/node-a";
    let source_spiffe = "spiffe://cluster.local/ns/default/sa/frontend";
    let mut source = object(
        "Pod",
        "default",
        "frontend-v1",
        json!({
            "serviceAccountName": "frontend",
            "nodeName": "node-a",
            "containers": [{"name": "curl"}]
        }),
    );
    source.metadata.uid = "frontend-pod-uid".to_string();
    source.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.20",
        "conditions": [{"type": "Ready", "status": "True"}]
    });

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            source,
            node_waypoint_pod_with_spiffe("node-a", "192.0.2.10", true, 15008, waypoint_spiffe),
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let source_workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.spiffe_id.as_str() == source_spiffe)
        .expect("identity-only source remains available for identity lookup");
    assert!(
        source_workload.node_waypoint.is_none(),
        "a same-node pod without ambient opt-in must not enter the assertion grant"
    );

    let slice = MeshSlice::from_gateway_config(
        &translation.config,
        MeshSliceRequest {
            node_id: waypoint_spiffe.to_string(),
            namespace: "ferrum-system".to_string(),
            workload_spiffe_id: Some(waypoint_spiffe.to_string()),
            ..MeshSliceRequest::default()
        },
    );
    assert!(
        slice.node_waypoint_assertors.iter().all(|assertor| assertor
            .asserts
            .iter()
            .all(|id| id.as_str() != source_spiffe)),
        "the NodeWaypoint must not be authorized to assert an unenrolled pod identity"
    );
}

#[test]
fn k8s_pod_discovery_does_not_grant_identity_only_sources_in_excluded_namespaces() {
    let waypoint_spiffe = "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/node-a";
    let source_spiffe = "spiffe://cluster.local/ns/monitoring/sa/frontend";
    let mut source = object(
        "Pod",
        "monitoring",
        "frontend-v1",
        json!({
            "serviceAccountName": "frontend",
            "nodeName": "node-a",
            "containers": [{"name": "curl"}]
        }),
    );
    source.metadata.uid = "frontend-pod-uid".to_string();
    source
        .metadata
        .labels
        .insert("ferrum.io/mesh".to_string(), "enabled".to_string());
    source.status = json!({
        "phase": "Running",
        "podIP": "10.1.0.20",
        "conditions": [{"type": "Ready", "status": "True"}]
    });

    let options =
        options().with_excluded_namespaces(build_excluded_namespaces(&["monitoring".to_string()]));
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            source,
            node_waypoint_pod_with_spiffe("node-a", "192.0.2.10", true, 15008, waypoint_spiffe),
        ],
        options,
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let source_workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.spiffe_id.as_str() == source_spiffe)
        .expect("identity-only source remains available for identity lookup");
    assert!(
        source_workload.node_waypoint.is_none(),
        "an opted-in pod in a node-agent excluded namespace must not enter the assertion grant"
    );
}

#[test]
fn k8s_pod_discovery_does_not_recursively_expand_node_waypoint_spiffe_env() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    push_pod_env(
        &mut waypoint,
        "FERRUM_NODE_NAME_ALIAS",
        "$(FERRUM_K8S_NODE_NAME)",
    );
    push_pod_env_field_ref(&mut waypoint, "FERRUM_K8S_NODE_NAME", "spec.nodeName");
    push_pod_env(
        &mut waypoint,
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/$(FERRUM_NODE_NAME_ALIAS)",
    );

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            waypoint,
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");

    assert!(
        workload.node_waypoint.is_none(),
        "discovery should not recursively resolve a token kubelet leaves literal"
    );
}

#[test]
fn k8s_pod_discovery_collects_waypoint_from_controller_namespace_when_workloads_are_scoped() {
    let (service, pod, slice) = scoped_prod_service_inputs();
    let waypoint = node_waypoint_pod_with_spiffe(
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint",
    );

    let translation = translate_k8s_objects(
        &[node("node-a", "node-uid-a"), service, pod, slice, waypoint],
        options_for_namespace("prod")
            .with_source_namespaces(vec!["prod".to_string()])
            .with_node_waypoint_namespace("ferrum-system".to_string()),
    )
    .expect("K8s core translation succeeds");

    assert_eq!(translation.config.known_namespaces, vec!["prod"]);
    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "prod" && workload.service_name == "reviews")
        .expect("reviews workload");
    let node_waypoint = workload
        .node_waypoint
        .as_ref()
        .expect("controller-namespace NodeWaypoint endpoint");
    assert_eq!(node_waypoint.address, "192.0.2.10");
    assert_eq!(
        node_waypoint.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint"
    );
}

#[test]
fn k8s_pod_discovery_omits_node_waypoint_metadata_without_explicit_svid() {
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            node_waypoint_pod("node-a", "192.0.2.10", true, 15008),
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");

    assert!(
        workload.node_waypoint.is_none(),
        "without an explicit waypoint SVID env, discovery must preserve the plaintext compatibility fallback instead of pinning the service account"
    );
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| workload.namespace != "ferrum-system"),
        "trusted NodeWaypoint pods without publishable metadata must still stay out of identity-only workloads"
    );
}

#[test]
fn k8s_pod_discovery_omits_node_waypoint_metadata_when_allow_no_ca_is_enabled() {
    let mut waypoint = node_waypoint_pod_with_spiffe(
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint",
    );
    push_pod_env(&mut waypoint, "FERRUM_MESH_ALLOW_NO_CA", "true");

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            waypoint,
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let workload = mesh
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");

    assert!(
        workload.node_waypoint.is_none(),
        "no-CA NodeWaypoint pods must not force mesh.hbone=true targets without an outbound SVID"
    );
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| workload.namespace != "ferrum-system"),
        "no-CA NodeWaypoint pods must still be recognized as proxy pods and excluded"
    );
}

#[test]
fn k8s_pod_discovery_does_not_materialize_node_waypoint_service_backends() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    waypoint.metadata.uid = "waypoint-pod-uid".to_string();

    let translation = translate_k8s_objects(
        &[
            node_waypoint_service(),
            waypoint,
            node_waypoint_endpoint_slice(),
        ],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let service = mesh
        .services
        .iter()
        .find(|service| {
            service.namespace == "ferrum-system" && service.name == "ferrum-mesh-ambient"
        })
        .expect("waypoint service");
    assert!(
        service.workloads.is_empty(),
        "waypoint pod must not materialize as a service backend"
    );
    assert!(
        mesh.workloads.is_empty(),
        "waypoint pod must not materialize as an identity-only workload"
    );
}

#[test]
fn k8s_pod_discovery_does_not_attach_unready_or_different_node_waypoint() {
    for waypoint in [
        node_waypoint_pod("node-a", "192.0.2.10", false, 15008),
        node_waypoint_pod("node-b", "192.0.2.11", true, 15008),
    ] {
        let translation = translate_k8s_objects(
            &[
                node("node-a", "node-uid-a"),
                service(),
                ready_pod(),
                endpoint_slice(),
                waypoint,
            ],
            options(),
        )
        .expect("K8s core translation succeeds");

        let mesh = translation.config.mesh.as_ref().expect("mesh config");
        let workload = mesh
            .workloads
            .iter()
            .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
            .expect("reviews workload");
        assert!(workload.node_waypoint.is_none());
    }
}

fn reviews_workload_node_waypoint(translation: &K8sTranslation) -> Option<&NodeWaypointEndpoint> {
    translation
        .config
        .mesh
        .as_ref()?
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")?
        .node_waypoint
        .as_ref()
}

#[test]
fn k8s_pod_discovery_retains_last_ready_node_waypoint_for_same_node_unready_replacement() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);

    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");
    assert_eq!(
        reviews_workload_node_waypoint(&translation)
            .expect("ready waypoint publishes destination metadata")
            .address,
        "192.0.2.10"
    );

    let unready_replacement = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a-replacement",
        "node-a",
        "192.0.2.99",
        false,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a-next",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            unready_replacement,
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    let retained = reviews_workload_node_waypoint(&translation)
        .expect("same-node unready replacement must keep last Ready endpoint");
    assert_eq!(
        retained.address, "192.0.2.10",
        "sticky inventory is last Ready, not the current unready pod address"
    );
    assert_eq!(
        retained.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
        "fail-closed identity pin must keep the last Ready SVID"
    );
}

#[test]
fn k8s_pod_discovery_retains_last_ready_node_waypoint_for_same_node_terminating_replacement() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);

    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");

    let terminating_replacement = terminating_node_waypoint_pod(
        "ferrum-node-waypoint-node-a-old",
        "node-a",
        "192.0.2.99",
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a-old",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            terminating_replacement,
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    let retained = reviews_workload_node_waypoint(&translation)
        .expect("same-node terminating replacement must keep last Ready endpoint");
    assert_eq!(retained.address, "192.0.2.10");
    assert_eq!(
        retained.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a"
    );
}

#[test]
fn k8s_pod_discovery_does_not_retain_withdrawn_node_because_another_node_has_trusted_pod() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);

    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");

    let ready_b = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-b",
        "node-b",
        "192.0.2.11",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-b",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            node("node-b", "node-uid-b"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_b,
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    assert!(
        reviews_workload_node_waypoint(&translation).is_none(),
        "another node's trusted pod must not retain a withdrawn node's endpoint"
    );
}

#[test]
fn k8s_pod_discovery_clears_sticky_node_waypoint_when_no_trusted_proxy_remains() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);
    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    assert!(
        reviews_workload_node_waypoint(&translation).is_none(),
        "withdrawing every trusted waypoint pod must clear destination metadata"
    );
}

#[test]
fn k8s_pod_discovery_clears_sticky_node_waypoint_for_ready_proxy_without_svid() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);
    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");

    let ready_without_svid = node_waypoint_pod("node-a", "192.0.2.20", true, 15008);
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_without_svid,
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    assert!(
        reviews_workload_node_waypoint(&translation).is_none(),
        "a Ready proxy without valid SVID material must withdraw stale destination metadata"
    );
}

#[test]
fn k8s_pod_discovery_replaces_retained_node_waypoint_when_same_node_becomes_ready() {
    let inventory = NodeWaypointInventory::new();
    let options = options().with_node_waypoint_inventory(inventory);

    let ready_a = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a",
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a",
    );
    translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            ready_a,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");

    let unready_replacement = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a-replacement",
        "node-a",
        "192.0.2.99",
        false,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a-next",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            unready_replacement,
        ],
        options.clone(),
    )
    .expect("K8s core translation succeeds");
    assert_eq!(
        reviews_workload_node_waypoint(&translation)
            .expect("unready replacement retains last Ready")
            .address,
        "192.0.2.10"
    );

    let newly_ready = named_node_waypoint_pod(
        "ferrum-node-waypoint-node-a-replacement",
        "node-a",
        "192.0.2.20",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a-next",
    );
    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            newly_ready,
        ],
        options,
    )
    .expect("K8s core translation succeeds");
    let replaced = reviews_workload_node_waypoint(&translation)
        .expect("newly Ready same-node endpoint must replace the retained one");
    assert_eq!(replaced.address, "192.0.2.20");
    assert_eq!(
        replaced.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-a-next"
    );
}

#[test]
fn k8s_pod_discovery_rejects_untrusted_node_waypoint_looking_pods() {
    let mut wrong_namespace = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    wrong_namespace.metadata.namespace = "default".to_string();
    let mut missing_label = node_waypoint_pod("node-a", "192.0.2.11", true, 15008);
    missing_label
        .metadata
        .labels
        .remove("app.kubernetes.io/name");

    for waypoint in [wrong_namespace, missing_label] {
        let translation = translate_k8s_objects(
            &[
                node("node-a", "node-uid-a"),
                service(),
                ready_pod(),
                endpoint_slice(),
                waypoint,
            ],
            options_for_namespace("ferrum-system")
                .with_source_namespaces(vec!["default".to_string()]),
        )
        .expect("K8s core translation succeeds");

        let mesh = translation.config.mesh.as_ref().expect("mesh config");
        let workload = mesh
            .workloads
            .iter()
            .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
            .expect("reviews workload");
        assert!(workload.node_waypoint.is_none());
    }
}

#[test]
fn k8s_pod_discovery_rejects_ambient_controller_namespace_pods() {
    let mut ambient = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    ambient.metadata.uid = "ambient-pod-uid".to_string();
    ambient.spec["containers"][0]["env"][0]["value"] = json!("ambient");

    let translation = translate_k8s_objects(
        &[service(), ready_pod(), endpoint_slice(), ambient],
        options_for_namespace("ferrum-system").with_source_namespaces(vec!["default".to_string()]),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    assert!(mesh.workloads.iter().all(|workload| {
        workload.namespace != "ferrum-system" && workload.node_waypoint.is_none()
    }));
}

#[test]
fn k8s_pod_discovery_does_not_use_waypoint_ip_as_endpoint_fallback() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    waypoint.metadata.uid = "waypoint-pod-uid".to_string();
    let mut slice = endpoint_slice();
    slice.spec["endpoints"][0]["addresses"] = json!(["192.0.2.10"]);
    slice.spec["endpoints"][0]
        .as_object_mut()
        .expect("endpoint object")
        .remove("targetRef");

    let translation = translate_k8s_objects(
        &[node("node-a", "node-uid-a"), service(), slice, waypoint],
        options(),
    )
    .expect("K8s core translation succeeds");

    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    let service = mesh
        .services
        .iter()
        .find(|service| service.name == "reviews")
        .expect("reviews service");
    assert!(service.workloads.is_empty());
    assert!(
        mesh.workloads.is_empty(),
        "waypoint pod must not materialize as an identity-only workload"
    );
}

#[test]
fn k8s_pod_discovery_keeps_istio_root_pods_out_of_pod_sources() {
    let (service, pod, slice) = scoped_prod_service_inputs();
    let mut root_pod = ready_pod();
    root_pod.metadata.namespace = "istio-system".to_string();
    root_pod.metadata.uid = "root-pod-uid".to_string();

    let translation = translate_k8s_objects(
        &[service, pod, slice, root_pod],
        options_for_namespace("istio-system")
            .with_source_namespaces(vec!["prod".to_string(), "istio-system".to_string()])
            .with_pod_source_namespaces(vec!["prod".to_string()]),
    )
    .expect("K8s core translation succeeds");

    assert_eq!(translation.config.known_namespaces, vec!["prod"]);
    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    assert!(
        mesh.workloads
            .iter()
            .all(|workload| workload.namespace == "prod")
    );
}

#[test]
fn k8s_pod_discovery_rejects_noncanonical_node_waypoint_pod_shapes() {
    let mut string_host_network = node_waypoint_pod_with_spiffe(
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint",
    );
    string_host_network.spec["hostNetwork"] = json!("true");

    let mut snake_case_node_name = node_waypoint_pod_with_spiffe(
        "node-a",
        "192.0.2.10",
        true,
        15008,
        "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint",
    );
    let node_name = snake_case_node_name
        .spec
        .as_object_mut()
        .expect("pod spec object")
        .remove("nodeName")
        .expect("canonical nodeName");
    snake_case_node_name
        .spec
        .as_object_mut()
        .expect("pod spec object")
        .insert("node_name".to_string(), node_name);

    for (shape, waypoint) in [
        ("string hostNetwork", string_host_network),
        ("snake-case node_name", snake_case_node_name),
    ] {
        let translation = translate_k8s_objects(
            &[
                node("node-a", "node-uid-a"),
                service(),
                ready_pod(),
                endpoint_slice(),
                waypoint,
            ],
            options(),
        )
        .expect("K8s core translation succeeds");
        let workload = translation
            .config
            .mesh
            .as_ref()
            .expect("mesh config")
            .workloads
            .iter()
            .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
            .expect("reviews workload");
        assert!(
            workload.node_waypoint.is_none(),
            "{shape} must not classify a pod as a trusted NodeWaypoint"
        );
    }
}

#[test]
fn k8s_pod_discovery_rejects_noncanonical_downward_api_field_path() {
    let mut waypoint = node_waypoint_pod("node-a", "192.0.2.10", true, 15008);
    waypoint.spec["containers"][0]["env"]
        .as_array_mut()
        .expect("env array")
        .push(json!({
            "name": "FERRUM_K8S_NODE_NAME",
            "value": "",
            "valueFrom": {
                "fieldRef": {
                    "field_path": "spec.node_name"
                }
            }
        }));
    push_pod_env(
        &mut waypoint,
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID",
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh/node/$(FERRUM_K8S_NODE_NAME)",
    );

    let translation = translate_k8s_objects(
        &[
            node("node-a", "node-uid-a"),
            service(),
            ready_pod(),
            endpoint_slice(),
            waypoint,
        ],
        options(),
    )
    .expect("K8s core translation succeeds");
    let workload = translation
        .config
        .mesh
        .as_ref()
        .expect("mesh config")
        .workloads
        .iter()
        .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
        .expect("reviews workload");
    assert!(
        workload.node_waypoint.is_none(),
        "noncanonical field_path/spec.node_name must not resolve trusted NodeWaypoint identity"
    );
}

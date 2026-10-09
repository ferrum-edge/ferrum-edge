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
            "serviceAccountName": "ferrum-mesh-ambient",
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
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/$(FERRUM_K8S_NODE_NAME)",
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
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/node-a"
    );
    assert_eq!(node_waypoint.node_name.as_deref(), Some("node-a"));
}

#[test]
fn k8s_pod_discovery_attaches_node_waypoint_metadata_to_identity_only_sources() {
    // Live NodeWaypoint same-node Service allow: src-a is a captured client
    // with a ServiceAccount and no Service. Issue #4274's per-assertor grant
    // is derived from Workload.node_waypoint bindings, so identity-only
    // sources must carry the same per-node SVID as service-backed destinations.
    let waypoint_spiffe =
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/node-a";
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
    let waypoint_spiffe =
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/node-a";
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
    let waypoint_spiffe =
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/node-a";
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
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/$(FERRUM_NODE_NAME_ALIAS)",
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
fn k8s_pod_discovery_trusts_only_the_ambient_service_account_for_node_waypoints() {
    let spiffe_id = "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/node-a";
    let node_waypoint_for = |service_account: &str| {
        let mut waypoint =
            node_waypoint_pod_with_spiffe("node-a", "192.0.2.10", true, 15008, spiffe_id);
        waypoint.spec["serviceAccountName"] = json!(service_account);
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
        translation
            .config
            .mesh
            .as_ref()
            .expect("mesh config")
            .workloads
            .iter()
            .find(|workload| workload.namespace == "default" && workload.service_name == "reviews")
            .expect("reviews workload")
            .node_waypoint
            .clone()
    };

    let trusted = node_waypoint_for("ferrum-mesh-ambient").expect("trusted");
    assert_eq!(trusted.address, "192.0.2.10");
    assert_eq!(trusted.spiffe_id.as_str(), spiffe_id);

    // The previous shared chart identity and the control-plane identity both
    // run in the waypoint namespace, but neither runs the NodeWaypoint.
    for service_account in ["ferrum-mesh", "ferrum-mesh-control-plane", "default"] {
        assert!(
            node_waypoint_for(service_account).is_none(),
            "{service_account} must not be trusted as a NodeWaypoint identity"
        );
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
        "spiffe://cluster.local/ns/ferrum-system/sa/ferrum-mesh-ambient/node/$(FERRUM_K8S_NODE_NAME)",
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

/// A ready Pod `namespace/name` running as `service_account` whose own status
/// reports `ip`.
fn ready_pod_in(namespace: &str, name: &str, service_account: &str, ip: &str) -> K8sObject {
    let mut pod = ready_pod();
    pod.metadata.namespace = namespace.to_string();
    pod.metadata.name = name.to_string();
    pod.spec["serviceAccountName"] = json!(service_account);
    pod.status["podIP"] = json!(ip);
    pod
}

/// The `default/reviews` EndpointSlice carrying `endpoints`.
fn reviews_slice_with(endpoints: Value) -> K8sObject {
    let mut slice = endpoint_slice();
    slice.spec["endpoints"] = endpoints;
    slice
}

/// Every address the translation attaches to a `reviews` workload identity.
fn reviews_workload_addresses(translation: &K8sTranslation) -> Vec<&str> {
    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    mesh.workloads
        .iter()
        .filter(|workload| workload.service_name == "reviews")
        .flat_map(|workload| workload.addresses.iter().map(String::as_str))
        .collect()
}

fn reviews_service_workload_count(translation: &K8sTranslation) -> usize {
    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    mesh.services
        .iter()
        .find(|service| service.namespace == "default" && service.name == "reviews")
        .expect("reviews service")
        .workloads
        .len()
}

fn assert_warned(translation: &K8sTranslation, fragment: &str) {
    assert!(
        translation
            .warnings
            .iter()
            .any(|warning| warning.contains(fragment)),
        "expected a warning containing {fragment:?}: {:?}",
        translation.warnings
    );
}

#[test]
fn k8s_pod_discovery_refuses_slice_target_ref_into_another_namespace() {
    // A slice author in `default` names `payments/ledger-0`. Neither an
    // address that Pod does not own nor one it does may lend its identity to
    // the `reviews` Service: the EndpointSlice controller never names another
    // namespace's Pod (issue #6123).
    for address in ["10.1.0.99", "10.9.0.5"] {
        let ledger = ready_pod_in("payments", "ledger-0", "ledger", "10.9.0.5");
        let forged = reviews_slice_with(json!([{
            "addresses": [address],
            "targetRef": {"kind": "Pod", "name": "ledger-0", "namespace": "payments"},
            "conditions": {"ready": true}
        }]));

        let translation = translate_k8s_objects(&[service(), ledger, forged], options())
            .expect("K8s core translation succeeds");

        assert_eq!(reviews_service_workload_count(&translation), 0, "{address}");
        assert!(
            reviews_workload_addresses(&translation).is_empty(),
            "{address}"
        );
        let mesh = translation.config.mesh.as_ref().expect("mesh config");
        assert!(
            mesh.workloads
                .iter()
                .all(|workload| workload.namespace != "payments"),
            "{address}: {:?}",
            mesh.workloads
        );
        assert_warned(&translation, "1 name a Pod outside the Service's namespace");
    }
}

#[test]
fn k8s_pod_discovery_refuses_slice_ip_lookup_into_another_namespace() {
    // Without a `targetRef` the endpoint resolves by IP; an IP owned by
    // another namespace's Pod is refused the same way.
    let ledger = ready_pod_in("payments", "ledger-0", "ledger", "10.9.0.5");
    let forged = reviews_slice_with(json!([{
        "addresses": ["10.9.0.5"],
        "conditions": {"ready": true}
    }]));

    let translation = translate_k8s_objects(&[service(), ledger, forged], options())
        .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());
    assert_warned(&translation, "1 name a Pod outside the Service's namespace");
}

#[test]
fn k8s_pod_discovery_attaches_only_addresses_the_named_pod_reports() {
    let mixed = reviews_slice_with(json!([{
        "addresses": ["10.1.0.10", "10.1.0.99"],
        "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
        "conditions": {"ready": true}
    }]));
    let translation = translate_k8s_objects(&[service(), ready_pod(), mixed], options())
        .expect("K8s core translation succeeds");
    assert_eq!(reviews_service_workload_count(&translation), 1);
    assert_eq!(reviews_workload_addresses(&translation), vec!["10.1.0.10"]);
    assert_warned(
        &translation,
        "1 are not reported by the named Pod's own status",
    );

    // An endpoint left with no address the Pod reports attaches nothing.
    let forged = reviews_slice_with(json!([{
        "addresses": ["10.1.0.99"],
        "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
        "conditions": {"ready": true}
    }]));
    let translation = translate_k8s_objects(&[service(), ready_pod(), forged], options())
        .expect("K8s core translation succeeds");
    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());
    assert_warned(
        &translation,
        "1 are not reported by the named Pod's own status",
    );
}

#[test]
fn k8s_pod_discovery_refuses_an_address_another_namespace_pod_also_reports() {
    // Two namespaces' Pods report the same IP (a reused IP, or a forged Pod
    // status); neither may claim it for its identity.
    let squatter = ready_pod_in("payments", "ledger-0", "ledger", "10.1.0.10");

    let translation = translate_k8s_objects(
        &[service(), ready_pod(), endpoint_slice(), squatter],
        options(),
    )
    .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());
    assert_warned(
        &translation,
        "1 are also reported by another namespace's Pod",
    );
}

#[test]
fn k8s_pod_discovery_refuses_a_never_a_backend_address_even_when_the_pod_reports_it() {
    let mut pod = ready_pod();
    pod.status["podIP"] = json!("169.254.169.254");
    let slice = reviews_slice_with(json!([{
        "addresses": ["169.254.169.254"],
        "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
        "conditions": {"ready": true}
    }]));

    let translation = translate_k8s_objects(&[service(), pod, slice], options())
        .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());
    assert_warned(&translation, "1 can never be a backend");
}

#[test]
fn k8s_pod_discovery_attaches_a_controller_slice_naming_the_services_own_pod() {
    let mut slice = endpoint_slice();
    slice.metadata.labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        "endpointslice-controller.k8s.io".to_string(),
    );

    let translation = translate_k8s_objects(&[service(), ready_pod(), slice], options())
        .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 1);
    assert_eq!(reviews_workload_addresses(&translation), vec!["10.1.0.10"]);
    let mesh = translation.config.mesh.as_ref().expect("mesh config");
    assert_eq!(
        mesh.workloads[0].spiffe_id.as_str(),
        "spiffe://cluster.local/ns/default/sa/reviews"
    );
    assert!(
        translation
            .warnings
            .iter()
            .all(|warning| !warning.contains("mesh workload derivation")),
        "{:?}",
        translation.warnings
    );
}

#[test]
fn k8s_pod_discovery_publishes_the_pods_own_spelling_of_an_ipv4_mapped_address() {
    // A slice may spell the Pod's IPv4 address IPv4-mapped. The workload
    // carries the address the Pod reports, once (issue #6123).
    let mut mapped = reviews_slice_with(json!([{
        "addresses": ["::ffff:10.1.0.10"],
        "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
        "conditions": {"ready": true}
    }]));
    mapped.metadata.name = "reviews-mapped".to_string();

    let translation = translate_k8s_objects(
        &[service(), ready_pod(), endpoint_slice(), mapped],
        options(),
    )
    .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 1);
    assert_eq!(reviews_workload_addresses(&translation), vec!["10.1.0.10"]);
}

/// A ready host-network Pod `namespace/name` reporting its Node's IP.
fn host_network_pod_in(namespace: &str, name: &str, node_ip: &str) -> K8sObject {
    let mut pod = ready_pod_in(namespace, name, name, node_ip);
    pod.spec["hostNetwork"] = json!(true);
    pod
}

#[test]
fn k8s_pod_discovery_attaches_a_host_network_pod_named_by_target_ref() {
    // A host-network DaemonSet Pod reports its Node's IP, as does every other
    // host-network Pod on that Node, in any namespace. The EndpointSlice
    // controller's same-namespace `targetRef` attaches it; the other
    // namespace's host-network Pod must not refuse it.
    let agent = host_network_pod_in("default", "reviews-v1", "192.168.10.5");
    let kube_proxy = host_network_pod_in("kube-system", "kube-proxy-a", "192.168.10.5");
    let slice = reviews_slice_with(json!([{
        "addresses": ["192.168.10.5"],
        "targetRef": {"kind": "Pod", "name": "reviews-v1", "namespace": "default"},
        "conditions": {"ready": true}
    }]));

    let translation = translate_k8s_objects(&[service(), agent, kube_proxy, slice], options())
        .expect("K8s core translation succeeds");

    assert_eq!(reviews_service_workload_count(&translation), 1);
    assert_eq!(
        reviews_workload_addresses(&translation),
        vec!["192.168.10.5"]
    );
    assert!(
        translation
            .warnings
            .iter()
            .all(|warning| !warning.contains("mesh workload derivation")),
        "{:?}",
        translation.warnings
    );
}

#[test]
fn k8s_pod_discovery_ip_lookup_never_resolves_a_node_ip_or_a_shared_ip() {
    // Without a `targetRef` an endpoint resolves its Pod by IP. A Node IP,
    // which every host-network Pod on the Node reports, identifies no Pod;
    // neither does an IP two Pods report.
    let agent = host_network_pod_in("default", "reviews-v1", "192.168.10.5");
    let kube_proxy = host_network_pod_in("kube-system", "kube-proxy-a", "192.168.10.5");
    let node_ip = reviews_slice_with(json!([{
        "addresses": ["192.168.10.5"],
        "conditions": {"ready": true}
    }]));
    let translation = translate_k8s_objects(&[service(), agent, kube_proxy, node_ip], options())
        .expect("K8s core translation succeeds");
    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());

    let twin = ready_pod_in("default", "reviews-v2", "reviews", "10.1.0.10");
    let shared_ip = reviews_slice_with(json!([{
        "addresses": ["10.1.0.10"],
        "conditions": {"ready": true}
    }]));
    let translation = translate_k8s_objects(&[service(), ready_pod(), twin, shared_ip], options())
        .expect("K8s core translation succeeds");
    assert_eq!(reviews_service_workload_count(&translation), 0);
    assert!(reviews_workload_addresses(&translation).is_empty());

    // The same endpoint resolves once only one Pod reports the IP.
    let sole_ip = reviews_slice_with(json!([{
        "addresses": ["10.1.0.10"],
        "conditions": {"ready": true}
    }]));
    let translation = translate_k8s_objects(&[service(), ready_pod(), sole_ip], options())
        .expect("K8s core translation succeeds");
    assert_eq!(reviews_service_workload_count(&translation), 1);
    assert_eq!(reviews_workload_addresses(&translation), vec!["10.1.0.10"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selectorless_numeric_and_named_targets_reach_the_endpoint_slice_backend() {
    use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
    use crate::scaffolding::harness::GatewayHarness;
    use crate::scaffolding::ports::{reserve_port, reserve_refused_tcp_port};
    use std::time::Duration;

    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    // Hold the defaulted Service port closed throughout the test. A gateway
    // using the old numeric-target shortcut cannot accidentally reach a peer.
    let service_port = reserve_refused_tcp_port().expect("reserve Service port");
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET",
            "/slice-port",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn endpoint backend");
    const POD_IP: &str = "10.244.0.250";
    for (case_index, target_port) in [json!(service_port.port), json!("container-http")]
        .into_iter()
        .enumerate()
    {
        let service = object(
            "Service",
            "default",
            "manual",
            json!({
                "clusterIP": "10.96.0.10",
                "ports": [{"name": "http", "port": service_port.port, "targetPort": target_port}]
            }),
        );
        let mut slice = object(
            "EndpointSlice",
            "default",
            "manual-ip4",
            json!({
                "addressType": "IPv4", "ports": [{"name": "http", "port": backend_port}],
                "endpoints": [{"addresses": [POD_IP], "conditions": {"ready": true}}]
            }),
        );
        slice
            .metadata
            .labels
            .insert("kubernetes.io/service-name".into(), "manual".into());
        let mut route = object(
            "HTTPRoute",
            "default",
            "manual",
            json!({
                "rules": [{"matches": [{"path": {"type": "Exact", "value": "/slice-port"}}],
                    "backendRefs": [{"name": "manual", "port": service_port.port}]}]
            }),
        );
        route.api_version = "gateway.networking.k8s.io/v1".into();
        // The backendRef guard admits a Service's endpoints only when they are
        // Pods of its namespace, and never a loopback address (issue #6108).
        // The slice names this Pod's ordinary IP; the served config is then
        // pointed at the loopback address the local backend listens on.
        let mut pod = object("Pod", "default", "manual-0", json!({}));
        pod.status = json!({"phase": "Running", "podIP": POD_IP});
        let mut translated = translate_k8s_objects(
            &[service, slice, route, pod],
            options_for_namespace("default"),
        )
        .expect("translate manual endpoint route");
        assert_eq!(translated.config.proxies.len(), 1);
        assert_eq!(translated.config.proxies[0].backend_host, POD_IP);
        assert_eq!(translated.config.proxies[0].backend_port, backend_port);
        translated.config.proxies[0].listen_port = None;
        translated.config.version = ferrum_edge::config::types::CURRENT_CONFIG_VERSION.to_string();
        let yaml = serde_yaml::to_string(&translated.config)
            .expect("serialize translated config")
            .replace(POD_IP, "127.0.0.1");
        let gateway = GatewayHarness::builder()
            .mode_in_process()
            .file_config(yaml)
            .env("FERRUM_NAMESPACE", "default")
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("start translated gateway");
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client")
            .get(gateway.proxy_url("/slice-port"))
            .send()
            .await
            .expect("translated route response");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "pong");
        backend.assert_no_matcher_mismatches().await;
        assert_eq!(backend.received_requests().await.len(), case_index + 1);
    }
}

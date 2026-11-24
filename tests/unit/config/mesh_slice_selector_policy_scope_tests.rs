//! Selector-scoped AuthorizationPolicies in a mesh slice (issue #7241).
//!
//! A Sidecar slice carries the selector policies that apply to its own
//! workload, not every same-namespace neighbour's. Only the topologies that
//! authorize traffic for other workloads (Ambient / ServiceWaypoint UDP source
//! scoping, NodeWaypoint per-pod scoping) keep the candidate superset.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshPolicy, PolicyScope, Workload, WorkloadPort, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};

const NAMESPACE: &str = "default";

fn spiffe(name: &str) -> String {
    format!("spiffe://cluster.local/ns/{NAMESPACE}/sa/{name}")
}

fn workload(name: &str, app: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(spiffe(name)).expect("spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), app.to_string())]),
            namespace: Some(NAMESPACE.to_string()),
        },
        service_name: name.to_string(),
        service_namespace: None,
        addresses: vec!["10.0.0.10".to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: NAMESPACE.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(name.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

fn selector_policy(name: &str, app: &str) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: NAMESPACE.to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), app.to_string())]),
                namespace: Some(NAMESPACE.to_string()),
            },
        },
        rules: Vec::new(),
    }
}

/// `web` and its unrelated neighbour `api`, each with its own selector policy.
fn config() -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![workload("web", "web"), workload("api", "api")],
            mesh_policies: vec![
                selector_policy("web-only", "web"),
                selector_policy("api-only", "api"),
            ],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    }
}

fn web_request() -> MeshSliceRequest {
    MeshSliceRequest {
        node_id: "web-node".to_string(),
        namespace: NAMESPACE.to_string(),
        workload_spiffe_id: Some(spiffe("web")),
        ..MeshSliceRequest::default()
    }
}

fn policy_names(slice: &MeshSlice) -> Vec<&str> {
    let mut names: Vec<&str> = slice
        .mesh_policies
        .iter()
        .map(|policy| policy.name.as_str())
        .collect();
    names.sort_unstable();
    names
}

#[test]
fn sidecar_slice_omits_a_neighbours_selector_policy() {
    let slice = MeshSlice::from_gateway_config(&config(), web_request());
    assert_eq!(
        policy_names(&slice),
        vec!["web-only"],
        "a Sidecar slice must not carry a selector policy for an unrelated workload"
    );
}

#[test]
fn ambient_udp_slice_keeps_the_destination_candidate_superset() {
    let request = MeshSliceRequest {
        ambient_udp_source_scoping: true,
        ..web_request()
    };
    let slice = MeshSlice::from_gateway_config(&config(), request);
    assert_eq!(
        policy_names(&slice),
        vec!["api-only", "web-only"],
        "Ambient / ServiceWaypoint UDP authorization still needs the policies of the \
         destination-visible workloads"
    );
}

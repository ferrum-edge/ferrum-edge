//! Mesh topology coverage matrix.
//!
//! Confirms all six mesh topologies are recognized by `MeshTopology::parse` and
//! `prepare_gateway_config_for_mesh` produces a usable `GatewayConfig` for each.
//! Topologies: Sidecar, Ambient, NodeWaypoint, ServiceWaypoint, EastWestGateway,
//! EgressGateway (per QW-1).

use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::{MeshConfig, OutboundTrafficPolicy};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

use crate::conformance::registry::Status;

const CATEGORY: &str = "mesh_topology_matrix";

fn runtime_for(topology: MeshTopology) -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "topology-matrix-node".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        topology,
        inbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        outbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        hbone_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        east_west_listen_port: 15443,
        egress_listen_addr: "127.0.0.1:15090".parse::<SocketAddr>().unwrap(),
        workload_spiffe_id: None,
        waypoint_name: match topology {
            // ServiceWaypoint REQUIRES a waypoint name (env validation rejects
            // service_waypoint topology without one).
            MeshTopology::ServiceWaypoint => Some("conformance-waypoint".to_string()),
            _ => None,
        },
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse::<SocketAddr>().unwrap(),
        dns_upstream_addr: "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
    }
}

fn minimal_gateway_config() -> GatewayConfig {
    GatewayConfig {
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    }
}

fn assert_topology_apply_succeeds(topology: MeshTopology) {
    let runtime = runtime_for(topology);
    let result = prepare_gateway_config_for_mesh(minimal_gateway_config(), &runtime);
    assert!(
        result.is_ok(),
        "topology {topology:?} apply must succeed on minimal config: {:?}",
        result.err()
    );
}

#[test]
fn topology_sidecar() {
    register_feature!(
        category = CATEGORY,
        feature = "Sidecar topology",
        status = Status::Supported,
        notes = "Inbound 15006 mTLS + outbound 15001 capture.",
    );
    assert_topology_apply_succeeds(MeshTopology::Sidecar);
}

#[test]
fn topology_ambient() {
    register_feature!(
        category = CATEGORY,
        feature = "Ambient topology",
        status = Status::Supported,
        notes = "HBONE 15008 + outbound 15001 capture.",
    );
    assert_topology_apply_succeeds(MeshTopology::Ambient);
}

#[test]
fn topology_node_waypoint() {
    register_feature!(
        category = CATEGORY,
        feature = "NodeWaypoint topology",
        status = Status::Supported,
        notes = "One HBONE listener serves multiple node-local pods; per-pod policy scoping.",
    );
    assert_topology_apply_succeeds(MeshTopology::NodeWaypoint);
}

#[test]
fn topology_service_waypoint() {
    register_feature!(
        category = CATEGORY,
        feature = "ServiceWaypoint topology",
        status = Status::Supported,
        notes = "GAMMA service-scoped waypoint; requires FERRUM_MESH_WAYPOINT_NAME.",
    );
    assert_topology_apply_succeeds(MeshTopology::ServiceWaypoint);
}

#[test]
fn topology_east_west_gateway() {
    register_feature!(
        category = CATEGORY,
        feature = "EastWestGateway topology",
        status = Status::Supported,
        notes = "SNI-passthrough TCP proxies on 15443 from multi-cluster RemoteCluster entries.",
    );
    assert_topology_apply_succeeds(MeshTopology::EastWestGateway);
}

#[test]
fn topology_egress_gateway() {
    register_feature!(
        category = CATEGORY,
        feature = "EgressGateway topology",
        status = Status::Supported,
        notes = "HTTP-family + stream-family egress proxies from MESH_EXTERNAL ServiceEntries.",
    );
    assert_topology_apply_succeeds(MeshTopology::EgressGateway);
}

/// `MeshTopology::terminates_hbone` invariant: HBONE-terminating topologies
/// (Ambient, NodeWaypoint, ServiceWaypoint) share the waypoint listener.
#[test]
fn topology_terminates_hbone_invariant() {
    register_feature!(
        category = CATEGORY,
        feature = "terminates_hbone classification",
        status = Status::Supported,
        notes =
            "Ambient/NodeWaypoint/ServiceWaypoint terminate HBONE; Sidecar/EastWest/Egress do not.",
    );
    assert!(MeshTopology::Ambient.terminates_hbone());
    assert!(MeshTopology::NodeWaypoint.terminates_hbone());
    assert!(MeshTopology::ServiceWaypoint.terminates_hbone());
    assert!(!MeshTopology::Sidecar.terminates_hbone());
    assert!(!MeshTopology::EastWestGateway.terminates_hbone());
    assert!(!MeshTopology::EgressGateway.terminates_hbone());
}

/// Out-of-scope conformance entry: Wasm and EnvoyFilter are NOT going to be
/// supported. Register them explicitly so operators stop asking.
#[test]
fn out_of_scope_wasm_and_envoyfilter() {
    register_feature!(
        category = CATEGORY,
        feature = "Wasm filters",
        status = Status::OutOfScope,
        notes = "Ferrum Edge runs native Rust plugins; Wasm filters are an explicit non-goal.",
    );
    register_feature!(
        category = CATEGORY,
        feature = "EnvoyFilter",
        status = Status::OutOfScope,
        notes = "Envoy-specific extension API; not part of Ferrum's compatibility surface.",
    );
}

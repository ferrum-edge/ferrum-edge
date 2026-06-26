//! Materialization coverage for SIDECAR cross-cluster east-west egress
//! (PR 1: Sidecar mesh-mTLS).
//!
//! Verifies the load-bearing behavior of the cross-cluster materialization pass
//! (`build_outbound_mesh_targets` → `append_cross_cluster_mesh_targets`): a
//! Sidecar client with a service that has a REMOTE workload on a network with a
//! matching `EastWestGateway` materializes ONE cross-cluster target addressed at
//! the remote gateway, with trust-domain-only verification tags (NO pinned
//! `mesh.spiffe_id`), the destination-FQDN SNI override, the dial port set to
//! the gateway port, and the remote trust domain. The negative case (a remote
//! workload on a network with NO matching gateway) materializes NO cross-cluster
//! target — fail closed, never dial an unresolved address.
//!
//! These are deterministic projection tests: they run the full
//! `prepare_gateway_config_for_mesh` pipeline and inspect the materialized
//! `Upstream.targets`, with no live network.

use ferrum_edge::modes::mesh::config::{
    AppProtocol, EastWestGateway, MeshConfig, MeshService, MultiClusterConfig, ServicePort,
    Workload, WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{MeshTopology, prepare_gateway_config_for_mesh};
use ferrum_edge::proxy::mesh_mtls_pool::{
    MESH_CROSS_CLUSTER_TAG, MESH_EASTWEST_SNI_TAG, MESH_MTLS_PORT_TAG, MESH_MTLS_TARGET_TAG,
};

use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};

use super::mesh_test_support::{
    default_mesh_runtime, gateway_config_with_mesh, mesh_config_with, workload_for,
};

const SVC_B_FQDN: &str = "svc-b.default.svc.cluster.local";
const REMOTE_TRUST_DOMAIN: &str = "cluster-b.local";
const REMOTE_NETWORK: &str = "net-b";
const GATEWAY_HOST: &str = "10.9.9.9";
const GATEWAY_PORT: u16 = 15443;

/// The materialized per-port outbound upstream id for `svc-b` on port 8080.
/// Mirrors `mesh_outbound_upstream_id` (`/`/`.` → `-`).
const SVC_B_OUTBOUND_UPSTREAM_ID: &str = "__mesh-out-upstream-default-svc-b-8080";

fn spiffe(raw: &str) -> SpiffeId {
    SpiffeId::new(raw.to_string()).expect("valid SPIFFE ID")
}

fn td(raw: &str) -> TrustDomain {
    TrustDomain::new(raw).expect("valid trust domain")
}

/// A REMOTE workload of `svc-b` in trust domain B on `network`. `remote_provenance`
/// is the authoritative remote marker (set by the remote-poll ingestion path in
/// production); we set it directly so the materializer's `workload_is_remote`
/// classifies it remote without a live discovery poll.
fn remote_workload(network: Option<&str>) -> Workload {
    Workload {
        spiffe_id: spiffe("spiffe://cluster-b.local/ns/default/sa/svc-b"),
        selector: WorkloadSelector {
            labels: std::collections::HashMap::new(),
            namespace: Some("default".to_string()),
        },
        service_name: "svc-b".to_string(),
        // A remote pod IP — it must NEVER be dialed directly (the cross-cluster
        // target dials the east-west gateway instead).
        addresses: vec!["10.244.5.5".to_string()],
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: td(REMOTE_TRUST_DOMAIN),
        namespace: "default".to_string(),
        network: network.map(str::to_string),
        cluster: Some("cluster-b".to_string()),
        weight: None,
        locality: Some("remote-cluster-b/net-b".to_string()),
        service_account: Some("svc-b".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: true,
    }
}

/// `svc-b` referencing both a local workload and the remote workload.
fn svc_b_service(local: &Workload, remote: &Workload) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: vec![
            WorkloadRef {
                spiffe_id: local.spiffe_id.clone(),
            },
            WorkloadRef {
                spiffe_id: remote.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    }
}

fn multi_cluster_with_gateway(gateway_network: Option<&str>) -> MultiClusterConfig {
    MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-net-b".to_string(),
            namespace: "default".to_string(),
            host: GATEWAY_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec![SVC_B_FQDN.to_string()],
            trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
            network: gateway_network.map(str::to_string),
        }],
    }
}

/// Build a prepared Sidecar mesh config for `svc-b` with a remote workload on
/// `workload_network` and an `EastWestGateway` on `gateway_network`, then return
/// the materialized per-port outbound upstream's targets.
fn materialize_targets(
    workload_network: Option<&str>,
    gateway_network: Option<&str>,
) -> Vec<ferrum_edge::config::types::UpstreamTarget> {
    let mut runtime = default_mesh_runtime();
    runtime.topology = MeshTopology::Sidecar;
    // The client's own identity is a different workload (so `svc-b` is an egress
    // destination, not the local workload).
    runtime.workload_spiffe_id = Some("spiffe://cluster.local/ns/default/sa/client".to_string());

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(workload_network);
    let service = svc_b_service(&local, &remote);

    let mut mesh: MeshConfig = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(gateway_network));

    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    prepared
        .upstreams
        .into_iter()
        .find(|u| u.id == SVC_B_OUTBOUND_UPSTREAM_ID)
        .unwrap_or_else(|| {
            panic!(
                "expected materialized outbound upstream `{SVC_B_OUTBOUND_UPSTREAM_ID}` to exist"
            )
        })
        .targets
}

#[test]
fn cross_cluster_target_is_materialized_for_remote_workload_with_matching_gateway() {
    let targets = materialize_targets(Some(REMOTE_NETWORK), Some(REMOTE_NETWORK));

    // Exactly one cross-cluster target (the gateway is the single ingress; no
    // per-pod fan-out).
    let cross: Vec<_> = targets
        .iter()
        .filter(|t| t.tags.get(MESH_CROSS_CLUSTER_TAG).map(String::as_str) == Some("true"))
        .collect();
    assert_eq!(
        cross.len(),
        1,
        "exactly one cross-cluster target expected, got {:#?}",
        targets
    );
    let xc = cross[0];

    // Dial host = the east-west gateway (NOT the remote pod IP).
    assert_eq!(
        xc.host, GATEWAY_HOST,
        "cross-cluster target must dial the east-west gateway"
    );
    assert_ne!(
        xc.host, "10.244.5.5",
        "cross-cluster target must NOT dial the remote pod IP"
    );

    // Transport tag = mesh.mtls (Sidecar).
    assert_eq!(
        xc.tags.get(MESH_MTLS_TARGET_TAG).map(String::as_str),
        Some("true"),
        "cross-cluster target carries the Sidecar mesh.mtls transport tag"
    );

    // Dial port (mesh.mtls_port) = the gateway port.
    assert_eq!(
        xc.tags.get(MESH_MTLS_PORT_TAG).map(String::as_str),
        Some(GATEWAY_PORT.to_string().as_str()),
        "mesh.mtls_port must be the east-west gateway port"
    );

    // SNI override = the destination service FQDN.
    assert_eq!(
        xc.tags.get(MESH_EASTWEST_SNI_TAG).map(String::as_str),
        Some(SVC_B_FQDN),
        "mesh.eastwest_sni must be the destination service FQDN"
    );

    // NO pinned pod identity (trust-domain-only verification).
    assert!(
        !xc.tags.contains_key("mesh.spiffe_id"),
        "cross-cluster target must NOT carry a pinned mesh.spiffe_id (trust-domain-only)"
    );

    // Trust domain = the remote (B) trust domain.
    assert_eq!(
        xc.tags.get("mesh.trust_domain").map(String::as_str),
        Some(REMOTE_TRUST_DOMAIN),
        "mesh.trust_domain must be the remote (B) trust domain"
    );

    // The request authority/Host port stays the SERVICE port.
    assert_eq!(
        xc.port, 8080,
        "the cross-cluster target's authority/Host port stays the service app port"
    );

    // The local workload still materializes a (first-tier) target dialing the
    // local pod over :15006 — local-first failover preserved.
    let local_targets: Vec<_> = targets
        .iter()
        .filter(|t| {
            t.tags.get(MESH_MTLS_TARGET_TAG).map(String::as_str) == Some("true")
                && !t.tags.contains_key(MESH_CROSS_CLUSTER_TAG)
        })
        .collect();
    assert_eq!(
        local_targets.len(),
        1,
        "the local workload must still materialize one pinned mesh.mtls target"
    );
    assert_eq!(local_targets[0].host, "10.0.0.1");
    assert!(
        local_targets[0].tags.contains_key("mesh.spiffe_id"),
        "the local target stays PINNED (carries mesh.spiffe_id)"
    );
}

#[test]
fn no_cross_cluster_target_when_no_matching_gateway() {
    // Remote workload on `net-b`, but the only gateway fronts `net-other`. No
    // exact match and no catch-all (`network: None`) gateway → fail closed: no
    // cross-cluster target.
    let targets = materialize_targets(Some(REMOTE_NETWORK), Some("net-other"));

    let cross = targets
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        cross, 0,
        "a remote workload on a network with no matching gateway must yield NO cross-cluster target"
    );

    // The local target is unaffected.
    let local_targets = targets
        .iter()
        .filter(|t| t.tags.get(MESH_MTLS_TARGET_TAG).map(String::as_str) == Some("true"))
        .count();
    assert_eq!(
        local_targets, 1,
        "the local workload's pinned mesh.mtls target is unaffected by the missing gateway"
    );
}

#[test]
fn catch_all_gateway_fronts_remote_workload_with_no_network() {
    // A remote workload with NO network + a catch-all (`network: None`) gateway
    // → the catch-all gateway fronts it.
    let targets = materialize_targets(None, None);
    let cross: Vec<_> = targets
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        cross.len(),
        1,
        "the catch-all gateway must front the no-network remote workload"
    );
    assert_eq!(cross[0].host, GATEWAY_HOST);
    assert_eq!(
        cross[0].tags.get(MESH_EASTWEST_SNI_TAG).map(String::as_str),
        Some(SVC_B_FQDN)
    );
}

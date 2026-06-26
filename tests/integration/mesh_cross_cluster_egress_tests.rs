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

    // Remote provenance: the cross-cluster target dials a remote gateway, so it
    // carries the reserved `mesh.remote=true` marker strict local-first locality
    // LB keys remote-vs-local on (without it the gateway target ranks LOCAL and
    // could be picked over healthy local endpoints).
    assert_eq!(
        xc.tags.get("mesh.remote").map(String::as_str),
        Some("true"),
        "cross-cluster target must carry the reserved mesh.remote=true provenance marker"
    );

    // [R2-4] The cross-cluster target's IDENTITY is the gateway DIAL ENDPOINT:
    // `port` == the gateway port (NOT the service port), so the LB/health/CB
    // `(host, port)` key is the actual reachable gateway endpoint. The DR policy
    // key stays the SERVICE port via `service_port_policy_key`. The inner
    // request authority/Host is the service FQDN (route host), unaffected.
    assert_eq!(
        xc.port, GATEWAY_PORT,
        "the cross-cluster target identity port is the gateway dial port, not the service port"
    );
    assert_eq!(
        xc.service_port_policy_key,
        Some(8080),
        "DR policy stays keyed by the declared SERVICE port"
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

// ── Codex round-1 fixes ────────────────────────────────────────────────────

/// Run the full mesh-prepare pipeline for `mesh`/`runtime` and return every
/// materialized upstream's targets keyed by upstream id (HTTP, TCP, and UDP
/// per-port upstreams all surface here).
fn materialize_all_upstream_targets(
    mesh: MeshConfig,
    runtime: &ferrum_edge::modes::mesh::MeshRuntimeConfig,
) -> std::collections::HashMap<String, Vec<ferrum_edge::config::types::UpstreamTarget>> {
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, runtime).expect("mesh-prepared");
    prepared
        .upstreams
        .into_iter()
        .map(|u| (u.id, u.targets))
        .collect()
}

fn sidecar_client_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = default_mesh_runtime();
    runtime.topology = MeshTopology::Sidecar;
    runtime.workload_spiffe_id = Some("spiffe://cluster.local/ns/default/sa/client".to_string());
    runtime
}

/// [1] P1: a TCP (stream-family) service port with a remote workload + a
/// matching east-west gateway must yield NO cross-cluster target. The
/// cross-cluster append is HTTP-family-only; the L4 tunnel paths can't carry the
/// SNI-passthrough semantics, so they must never get a gateway-addressed target.
#[test]
fn no_cross_cluster_target_for_tcp_service_port() {
    let runtime = sidecar_client_runtime();

    // A TCP service port (7070). Local + remote workloads both expose it; the
    // remote workload sits on net-b with a matching gateway, so WITHOUT the
    // HTTP-family gate a cross-cluster target would be appended — proving the
    // gate (not just an absence of remote endpoints).
    let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    local.ports = vec![WorkloadPort {
        port: 7070,
        protocol: AppProtocol::Tcp,
        name: Some("tcp".to_string()),
    }];
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    remote.ports = vec![WorkloadPort {
        port: 7070,
        protocol: AppProtocol::Tcp,
        name: Some("tcp".to_string()),
    }];

    let service = MeshService {
        // Raw-TCP egress maps captured dials by VIP, so cluster_ips is required
        // for the TCP upstream to materialize at all.
        cluster_ips: vec!["10.96.0.50".to_string()],
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 7070,
            protocol: AppProtocol::Tcp,
            name: Some("tcp".to_string()),
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
    };

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    // The TCP upstream exists (proves the port materialized) ...
    let tcp_targets = upstreams
        .get("__mesh-out-tcp-upstream-default-svc-b-7070")
        .expect("raw-TCP per-port upstream must materialize for the TCP service port");
    // ... and carries NO cross-cluster target.
    let cross = tcp_targets
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        cross, 0,
        "a TCP service port must NOT yield a cross-cluster target (HTTP-family only)"
    );
    // No cross-cluster target may appear in ANY materialized upstream either.
    let cross_anywhere = upstreams
        .values()
        .flatten()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        cross_anywhere, 0,
        "no cross-cluster target may be materialized for a TCP-only service"
    );
}

/// [6] P2: a multi-port HTTP service must yield a cross-cluster target only for
/// its FIRST declared port (the east-west gateway routes a service-FQDN SNI to
/// only the first port — single-port-per-SNI).
#[test]
fn cross_cluster_target_only_for_first_service_port() {
    let runtime = sidecar_client_runtime();

    let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    local.ports = vec![
        WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        },
        WorkloadPort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
        },
    ];
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    remote.ports = local.ports.clone();

    // Two HTTP ports; 8080 is the FIRST declared port.
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![
            ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            },
            ServicePort {
                port: 9090,
                protocol: AppProtocol::Http,
                name: Some("http-alt".to_string()),
                target_port: None,
            },
        ],
        workloads: vec![
            WorkloadRef {
                spiffe_id: local.spiffe_id.clone(),
            },
            WorkloadRef {
                spiffe_id: remote.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);

    // First port (8080): exactly one cross-cluster target.
    let first = upstreams
        .get("__mesh-out-upstream-default-svc-b-8080")
        .expect("first-port upstream must materialize");
    let first_cross = first
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        first_cross, 1,
        "the first service port must yield exactly one cross-cluster target"
    );

    // Second port (9090): NO cross-cluster target (it is unreachable across
    // clusters in the single-port-per-SNI east-west model).
    let second = upstreams
        .get("__mesh-out-upstream-default-svc-b-9090")
        .expect("second-port upstream must materialize");
    let second_cross = second
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        second_cross, 0,
        "a non-first service port must NOT yield a cross-cluster target"
    );
}

/// [3] P2: when a network has multiple east-west gateways with different
/// `sni_hosts`, selection must pick the one whose `sni_hosts` claims the
/// destination service FQDN — not merely the first gateway on the network.
#[test]
fn gateway_selection_requires_sni_host_overlap() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK));
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    // Two gateways on the SAME network (net-b). The FIRST claims a DIFFERENT
    // host (svc-other); only the SECOND claims svc-b's FQDN. Selection must pick
    // the second (host-owning) gateway — picking the first would blackhole the
    // request through a gateway that doesn't route svc-b's SNI.
    const OTHER_GATEWAY_HOST: &str = "10.9.9.1";
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            EastWestGateway {
                name: "ew-net-b-other".to_string(),
                namespace: "default".to_string(),
                host: OTHER_GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec!["svc-other.default.svc.cluster.local".to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some(REMOTE_NETWORK.to_string()),
            },
            EastWestGateway {
                name: "ew-net-b-svc-b".to_string(),
                namespace: "default".to_string(),
                host: GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some(REMOTE_NETWORK.to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let targets = upstreams
        .get(SVC_B_OUTBOUND_UPSTREAM_ID)
        .expect("first-port upstream must materialize");
    let cross: Vec<_> = targets
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(cross.len(), 1, "exactly one cross-cluster target expected");
    assert_eq!(
        cross[0].host, GATEWAY_HOST,
        "selection must pick the gateway whose sni_hosts claims svc-b's FQDN, not the first \
         gateway on the network"
    );
    assert_ne!(
        cross[0].host, OTHER_GATEWAY_HOST,
        "the gateway that does not claim svc-b's FQDN must not be selected"
    );
}

/// [3] P2 (negative): if no gateway on the network claims the destination FQDN,
/// no cross-cluster target is materialized (fail closed — the gateway would
/// blackhole an SNI it does not own).
#[test]
fn no_cross_cluster_target_when_no_gateway_claims_host() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK));
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    // The only gateway on net-b claims a different host.
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-net-b-other".to_string(),
            namespace: "default".to_string(),
            host: GATEWAY_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec!["svc-other.default.svc.cluster.local".to_string()],
            trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
            network: Some(REMOTE_NETWORK.to_string()),
        }],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = upstreams
        .values()
        .flatten()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        cross, 0,
        "no gateway claims svc-b's FQDN, so no cross-cluster target may be materialized"
    );
}

// ── Codex round-2 fixes ────────────────────────────────────────────────────

/// Collect every materialized cross-cluster target (across all upstreams).
fn cross_cluster_targets(
    upstreams: &std::collections::HashMap<String, Vec<ferrum_edge::config::types::UpstreamTarget>>,
) -> Vec<&ferrum_edge::config::types::UpstreamTarget> {
    upstreams
        .values()
        .flatten()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect()
}

/// [R2-1] FAIL CLOSED: net-b HAS a gateway, but it does NOT claim svc-b's FQDN;
/// a separate `network: None` catch-all DOES claim the FQDN (matching TD). The
/// catch-all must NOT be used (net-b having any gateway forbids broadening to a
/// different-network catch-all) → NO cross-cluster target.
#[test]
fn catch_all_not_used_when_network_has_a_gateway() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK));
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            // net-b HAS a gateway, but it claims a DIFFERENT host.
            EastWestGateway {
                name: "ew-net-b-other".to_string(),
                namespace: "default".to_string(),
                host: GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec!["svc-other.default.svc.cluster.local".to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some(REMOTE_NETWORK.to_string()),
            },
            // A `network: None` catch-all that DOES claim svc-b's FQDN with a
            // matching TD — it must NOT rescue net-b (fail closed).
            EastWestGateway {
                name: "ew-catch-all".to_string(),
                namespace: "default".to_string(),
                host: "10.9.9.250".to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: None,
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams).len(),
        0,
        "the catch-all must NOT be used when the requested network has a (non-matching) gateway \
         — fail closed, never broaden to a different-network catch-all"
    );
}

/// [R2-1] CONTRAST: net-b has NO gateway at all; only a `network: None` catch-all
/// claims svc-b's FQDN with a matching TD → the catch-all IS used.
#[test]
fn catch_all_used_when_network_has_no_gateway() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Remote workload on net-b, but NO net-b gateway exists.
    let remote = remote_workload(Some(REMOTE_NETWORK));
    let service = svc_b_service(&local, &remote);

    const CATCH_ALL_HOST: &str = "10.9.9.250";
    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-catch-all".to_string(),
            namespace: "default".to_string(),
            host: CATCH_ALL_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec![SVC_B_FQDN.to_string()],
            trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
            network: None,
        }],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        1,
        "with NO net-b gateway, the matching catch-all must front the remote workload"
    );
    assert_eq!(
        cross[0].host, CATCH_ALL_HOST,
        "the catch-all gateway host must be selected"
    );
}

/// [R2-2] REACHABILITY: a remote workload with NO addresses yields no
/// cross-cluster target (the east-west gateway would have no backend to forward
/// the SNI to). A reachable sibling on the same network still produces a target.
#[test]
fn no_cross_cluster_target_for_unreachable_remote_workload() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // An UNREACHABLE remote workload: no addresses (pod IP not yet assigned).
    let mut unreachable = remote_workload(Some(REMOTE_NETWORK));
    unreachable.spiffe_id = spiffe("spiffe://cluster-b.local/ns/default/sa/svc-b-unreachable");
    unreachable.service_account = Some("svc-b-unreachable".to_string());
    unreachable.addresses = Vec::new();

    let service = MeshService {
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
                spiffe_id: unreachable.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    let mut mesh = mesh_config_with(vec![local, unreachable], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams).len(),
        0,
        "an addressless remote workload is unreachable → no cross-cluster target (fail closed)"
    );

    // A reachable sibling on the same network → target IS emitted for the group.
    let local2 = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.2"]);
    let reachable = remote_workload(Some(REMOTE_NETWORK)); // has an address
    let service2 = svc_b_service(&local2, &reachable);
    let mut mesh2 = mesh_config_with(vec![local2, reachable], vec![service2], Vec::new());
    mesh2.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));
    let upstreams2 = materialize_all_upstream_targets(mesh2, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams2).len(),
        1,
        "a reachable remote workload on the network still yields a cross-cluster target"
    );
}

/// [R2-2] REACHABILITY: a remote workload whose first-service-port NAMED
/// targetPort does not resolve against the workload's ports is unreachable →
/// no cross-cluster target (mirrors `build_east_west_service_targets`'s skip).
#[test]
fn no_cross_cluster_target_for_unresolvable_named_target_port() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // The remote workload's ports are named "http" (port 8080), but the service
    // port below declares a NAMED targetPort "grpc" that does NOT exist on the
    // workload → unresolved → unreachable (the gateway side would skip it).
    let remote = remote_workload(Some(REMOTE_NETWORK));

    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: Some(ferrum_edge::modes::mesh::config::ServiceTargetPort::Name(
                "grpc".to_string(),
            )),
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
    };

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams).len(),
        0,
        "an unresolved named first-port targetPort makes the remote workload unreachable → \
         no cross-cluster target"
    );
}

/// [R2-3] TRUST DOMAIN: net-b has two gateways BOTH claiming svc-b's FQDN; the
/// FIRST carries a DIFFERENT trust domain, the SECOND carries the remote
/// workloads' trust domain → the SECOND (TD-matching) gateway is selected.
#[test]
fn gateway_selection_requires_trust_domain_match() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK)); // TD = cluster-b.local
    let service = svc_b_service(&local, &remote);

    const WRONG_TD_GATEWAY_HOST: &str = "10.9.9.2";
    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            // FIRST: claims the FQDN but wrong trust domain — must be REJECTED.
            EastWestGateway {
                name: "ew-net-b-wrong-td".to_string(),
                namespace: "default".to_string(),
                host: WRONG_TD_GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td("other.local")),
                network: Some(REMOTE_NETWORK.to_string()),
            },
            // SECOND: claims the FQDN AND matches the remote TD — must be picked.
            EastWestGateway {
                name: "ew-net-b-right-td".to_string(),
                namespace: "default".to_string(),
                host: GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some(REMOTE_NETWORK.to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(cross.len(), 1, "exactly one cross-cluster target expected");
    assert_eq!(
        cross[0].host, GATEWAY_HOST,
        "selection must pick the gateway whose trust domain matches the remote workloads', not \
         the first (wrong-TD) gateway"
    );
    assert_ne!(
        cross[0].host, WRONG_TD_GATEWAY_HOST,
        "the wrong-trust-domain gateway must not be selected"
    );
}

/// [R2-3] TRUST DOMAIN: a TD-LESS (wildcard) gateway claiming the FQDN matches a
/// remote workload of ANY trust domain.
#[test]
fn td_less_gateway_is_a_trust_domain_wildcard() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK)); // TD = cluster-b.local
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-net-b-td-less".to_string(),
            namespace: "default".to_string(),
            host: GATEWAY_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec![SVC_B_FQDN.to_string()],
            // No trust domain → wildcard, matches any remote TD.
            trust_domain: None,
            network: Some(REMOTE_NETWORK.to_string()),
        }],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        1,
        "a TD-less gateway is a trust-domain wildcard and must front the remote workload"
    );
    assert_eq!(cross[0].host, GATEWAY_HOST);
}

/// [R2-4] IDENTITY: the cross-cluster target's `(host, port)` identity is the
/// gateway DIAL endpoint — `port` == the gateway port (not the service port),
/// `mesh.mtls_port` == the gateway port, `service_port_policy_key` == the
/// declared service port.
#[test]
fn cross_cluster_target_identity_is_the_gateway_dial_endpoint() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK));
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(cross.len(), 1, "exactly one cross-cluster target expected");
    let xc = cross[0];

    assert_eq!(
        xc.host, GATEWAY_HOST,
        "identity host = the gateway dial host"
    );
    assert_eq!(
        xc.port, GATEWAY_PORT,
        "identity port = the gateway dial port, NOT the service port (8080)"
    );
    assert_ne!(xc.port, 8080, "identity port must not be the service port");
    assert_eq!(
        xc.tags.get(MESH_MTLS_PORT_TAG).map(String::as_str),
        Some(GATEWAY_PORT.to_string().as_str()),
        "mesh.mtls_port == the gateway dial port"
    );
    assert_eq!(
        xc.service_port_policy_key,
        Some(8080),
        "DR policy stays keyed by the declared SERVICE port"
    );
}

/// [R2-4] DISTINCT IDENTITIES: two remote networks fronted by gateways on the
/// SAME host but DIFFERENT ports must yield two DISTINCT `(host, port)` targets
/// (not collapsed onto one identity).
#[test]
fn two_networks_on_same_gateway_host_yield_distinct_identities() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote workloads on DIFFERENT networks (net-b, net-c), same TD.
    let remote_b = remote_workload(Some("net-b"));
    let mut remote_c = remote_workload(Some("net-c"));
    remote_c.spiffe_id = spiffe("spiffe://cluster-b.local/ns/default/sa/svc-b-c");
    remote_c.service_account = Some("svc-b-c".to_string());
    remote_c.addresses = vec!["10.244.6.6".to_string()];

    let service = MeshService {
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
                spiffe_id: remote_b.spiffe_id.clone(),
            },
            WorkloadRef {
                spiffe_id: remote_c.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    // Two gateways on the SAME host, DIFFERENT ports — one per network.
    const SHARED_GATEWAY_HOST: &str = "10.9.9.9";
    const NET_B_PORT: u16 = 15443;
    const NET_C_PORT: u16 = 15444;
    let mut mesh = mesh_config_with(vec![local, remote_b, remote_c], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "default".to_string(),
                host: SHARED_GATEWAY_HOST.to_string(),
                port: NET_B_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-b".to_string()),
            },
            EastWestGateway {
                name: "ew-net-c".to_string(),
                namespace: "default".to_string(),
                host: SHARED_GATEWAY_HOST.to_string(),
                port: NET_C_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-c".to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        2,
        "two remote networks must yield two cross-cluster targets (one per gateway)"
    );
    let mut identities: Vec<(String, u16)> =
        cross.iter().map(|t| (t.host.clone(), t.port)).collect();
    identities.sort();
    assert_eq!(
        identities,
        vec![
            (SHARED_GATEWAY_HOST.to_string(), NET_B_PORT),
            (SHARED_GATEWAY_HOST.to_string(), NET_C_PORT),
        ],
        "the two targets must have DISTINCT (host, port) identities (same host, different ports)"
    );
}

// ── Codex round-3 fixes ────────────────────────────────────────────────────

/// [R3-2] SAME-SPIFFE REMOTE NETWORKS: replicas of a service in two remote
/// networks (net-b, net-c) that share ONE service-account SPIFFE id collapse to a
/// SINGLE merged `WorkloadRef` (`merge_remote_endpoints_into_mesh` unions service
/// refs by SPIFFE id), while BOTH networks' `Workload`s survive the merge (keyed
/// by endpoint, incl. network + address). The materializer must surface BOTH
/// networks — one target per network's east-west gateway — not just the first.
#[test]
fn cross_cluster_targets_for_same_spiffe_replicas_across_networks() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote replicas SHARING one service-account SPIFFE id, on different
    // networks with different pod IPs.
    let remote_b = remote_workload(Some("net-b")); // spiffe ...sa/svc-b, 10.244.5.5
    let mut remote_c = remote_workload(Some("net-c"));
    remote_c.addresses = vec!["10.244.6.6".to_string()];
    assert_eq!(
        remote_b.spiffe_id, remote_c.spiffe_id,
        "test premise: the two remote replicas share one SPIFFE id"
    );

    // The merged service carries a SINGLE remote ref for that shared SPIFFE id.
    let service = MeshService {
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
                spiffe_id: remote_b.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    const NET_B_GATEWAY_HOST: &str = "10.9.9.11";
    const NET_C_GATEWAY_HOST: &str = "10.9.9.12";
    let mut mesh = mesh_config_with(vec![local, remote_b, remote_c], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "default".to_string(),
                host: NET_B_GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-b".to_string()),
            },
            EastWestGateway {
                name: "ew-net-c".to_string(),
                namespace: "default".to_string(),
                host: NET_C_GATEWAY_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-c".to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    let mut hosts: Vec<&str> = cross.iter().map(|t| t.host.as_str()).collect();
    hosts.sort();
    assert_eq!(
        hosts,
        vec![NET_B_GATEWAY_HOST, NET_C_GATEWAY_HOST],
        "both remote networks sharing one SPIFFE id must each yield a cross-cluster target, got: \
         {cross:#?}"
    );
}

/// [R3-3] FAIL CLOSED on a shared gateway endpoint: two remote workloads on the
/// SAME network in DIFFERENT trust domains, fronted by a SINGLE trust-domain-less
/// (wildcard-TD) gateway, both resolve to that one gateway `host:port`. Emitting
/// two targets with the same identity would collapse them in LB / passive-health
/// (the key is `host:port`), and the SNI-passthrough gateway can't be steered to
/// a trust domain — so NO cross-cluster target is emitted (the operator must
/// declare a distinct gateway endpoint per trust domain).
#[test]
fn no_cross_cluster_targets_when_two_trust_domains_share_one_gateway_endpoint() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote workloads on the SAME network, DIFFERENT trust domains (distinct
    // SPIFFE ids → distinct refs).
    let remote_td_b = remote_workload(Some(REMOTE_NETWORK)); // TD cluster-b.local
    let mut remote_td_c = remote_workload(Some(REMOTE_NETWORK));
    remote_td_c.spiffe_id = spiffe("spiffe://cluster-c.local/ns/default/sa/svc-b");
    remote_td_c.trust_domain = td("cluster-c.local");
    remote_td_c.cluster = Some("cluster-c".to_string());
    remote_td_c.addresses = vec!["10.244.6.6".to_string()];

    let service = MeshService {
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
                spiffe_id: remote_td_b.spiffe_id.clone(),
            },
            WorkloadRef {
                spiffe_id: remote_td_c.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    let mut mesh = mesh_config_with(
        vec![local, remote_td_b, remote_td_c],
        vec![service],
        Vec::new(),
    );
    // ONE trust-domain-less gateway for net-b — a candidate for BOTH trust
    // domains, so both groups select this single endpoint.
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-net-b-wildcard-td".to_string(),
            namespace: "default".to_string(),
            host: GATEWAY_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec![SVC_B_FQDN.to_string()],
            trust_domain: None,
            network: Some(REMOTE_NETWORK.to_string()),
        }],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams).len(),
        0,
        "two trust domains resolving to one shared gateway endpoint must yield NO cross-cluster \
         target (fail closed)"
    );
}

/// [R5-3] Two remote networks in the SAME trust domain configured to use the
/// SAME east-west gateway `host:port` are NOT ambiguous (same SNI + same
/// trust-domain verification), so they COLLAPSE to a single cross-cluster target
/// rather than being dropped — a remote-only service stays reachable.
#[test]
fn same_trust_domain_networks_sharing_one_gateway_endpoint_collapse_to_one() {
    let runtime = sidecar_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote workloads on DIFFERENT networks but the SAME trust domain.
    let remote_b = remote_workload(Some("net-b"));
    let mut remote_c = remote_workload(Some("net-c"));
    remote_c.spiffe_id = spiffe("spiffe://cluster-b.local/ns/default/sa/svc-b-c");
    remote_c.service_account = Some("svc-b-c".to_string());
    remote_c.addresses = vec!["10.244.6.6".to_string()];

    let service = MeshService {
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
                spiffe_id: remote_b.spiffe_id.clone(),
            },
            WorkloadRef {
                spiffe_id: remote_c.spiffe_id.clone(),
            },
        ],
        protocol_overrides: std::collections::HashMap::new(),
    };

    // Two gateways on the SAME host:port — one per network, SAME trust domain.
    const SHARED_HOST: &str = "10.9.9.7";
    let mut mesh = mesh_config_with(vec![local, remote_b, remote_c], vec![service], Vec::new());
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "default".to_string(),
                host: SHARED_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-b".to_string()),
            },
            EastWestGateway {
                name: "ew-net-c".to_string(),
                namespace: "default".to_string(),
                host: SHARED_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-c".to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        1,
        "two same-trust-domain networks sharing one gateway endpoint must COLLAPSE to one target \
         (not drop), got: {cross:#?}"
    );
    assert_eq!(cross[0].host, SHARED_HOST);
    assert_eq!(cross[0].port, GATEWAY_PORT);
}

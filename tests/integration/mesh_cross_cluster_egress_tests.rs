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

/// Multi-port east-west (issue #2010 phase 3): a multi-port HTTP service now
/// yields a cross-cluster target for EVERY HTTP-family port. The FIRST declared
/// port routes on the base service FQDN; each additional port routes on the
/// deterministic `p<port>.<fqdn>` SNI alias.
#[test]
fn cross_cluster_target_for_each_http_service_port() {
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

    // Multi-port service (codex #2040 Finding A): EVERY HTTP port — including the
    // lowest (8080) — routes on an EXPLICIT per-port SNI alias `p<port>.<fqdn>`.
    // The bare base FQDN routes to NO port, so a client + destination that differ
    // in which ports they declare cannot cross-wire onto the base.
    let first = upstreams
        .get("__mesh-out-upstream-default-svc-b-8080")
        .expect("first-port upstream must materialize");
    let first_cross: Vec<_> = first
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        first_cross.len(),
        1,
        "the lowest service port must yield exactly one cross-cluster target"
    );
    assert_eq!(
        first_cross[0]
            .tags
            .get(MESH_EASTWEST_SNI_TAG)
            .map(String::as_str),
        Some("p8080.svc-b.default.svc.cluster.local"),
        "the lowest port of a MULTI-port service routes on its explicit p<port> alias, not the base FQDN"
    );

    // Second port (9090): one cross-cluster target, routing on the deterministic
    // per-port SNI alias `p9090.<fqdn>`.
    let second = upstreams
        .get("__mesh-out-upstream-default-svc-b-9090")
        .expect("second-port upstream must materialize");
    let second_cross: Vec<_> = second
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        second_cross.len(),
        1,
        "a non-first HTTP service port now yields a cross-cluster target too"
    );
    assert_eq!(
        second_cross[0]
            .tags
            .get(MESH_EASTWEST_SNI_TAG)
            .map(String::as_str),
        Some("p9090.svc-b.default.svc.cluster.local"),
        "the second port routes on the p<port> SNI alias"
    );
    // No port of a multi-port service routes on the bare base FQDN.
    assert!(
        !upstreams
            .values()
            .flatten()
            .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
            .any(|t| t.tags.get(MESH_EASTWEST_SNI_TAG).map(String::as_str) == Some(SVC_B_FQDN)),
        "a multi-port service must NOT route any port on the bare base FQDN (codex #2040 Finding A)"
    );
    // The dial endpoint (identity) is still the east-west gateway for both ports;
    // the per-port SNI alias — not the identity — distinguishes the backend port.
    assert_eq!(
        second_cross[0].tags.get(MESH_MTLS_PORT_TAG),
        first_cross[0].tags.get(MESH_MTLS_PORT_TAG),
        "both ports dial the same east-west gateway endpoint"
    );
}

/// Order-independence + explicit-port channel (issue #2010 phase 3, codex #2040
/// Finding A): for a MULTI-port service EVERY port routes on its own explicit
/// `p<port>.<fqdn>` alias, so two clusters that declare the same service's ports
/// in different orders — or with different port SETS — derive the SAME SNI per
/// numeric port and NO port maps onto the bare base FQDN. Here the ports are
/// declared `[9090, 8080]` (9090 first); both must get their explicit alias
/// regardless of declaration order, and the base FQDN routes to nothing.
#[test]
fn cross_cluster_sni_alias_keys_on_explicit_port_not_declaration_order() {
    let runtime = sidecar_client_runtime();

    let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    local.ports = vec![
        WorkloadPort {
            port: 9090,
            protocol: AppProtocol::Http,
            name: Some("http-alt".to_string()),
        },
        WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        },
    ];
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    remote.ports = local.ports.clone();

    // Ports declared 9090 FIRST, 8080 second — reversed from the natural order.
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![
            ServicePort {
                port: 9090,
                protocol: AppProtocol::Http,
                name: Some("http-alt".to_string()),
                target_port: None,
            },
            ServicePort {
                port: 8080,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
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

    // Every port of a multi-port service routes on its explicit alias — 8080 on
    // p8080 (NOT the base FQDN) even though it is lowest, 9090 on p9090 even
    // though it was declared first. Declaration order and the port set are
    // irrelevant; the numeric port is the channel.
    let sni_for = |port: u16| -> Option<String> {
        upstreams
            .get(&format!("__mesh-out-upstream-default-svc-b-{port}"))
            .and_then(|targets| {
                targets
                    .iter()
                    .find(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
                    .and_then(|t| t.tags.get(MESH_EASTWEST_SNI_TAG).cloned())
            })
    };
    assert_eq!(
        sni_for(8080).as_deref(),
        Some("p8080.svc-b.default.svc.cluster.local"),
        "the lowest port (8080) of a multi-port service routes on its explicit p<port> alias, never the base FQDN"
    );
    assert_eq!(
        sni_for(9090).as_deref(),
        Some("p9090.svc-b.default.svc.cluster.local"),
        "the higher port (9090) routes on the p<port> alias even though it was declared first"
    );
}

/// codex #2040 Finding A (cross-cluster base-port skew fail-closed). Two clusters
/// can declare DIFFERENT HTTP port sets for the same service. The dialed SNI for
/// a given numeric port must depend ONLY on whether the DIALING service is
/// single- or multi-port — never route a multi-port service's port onto the bare
/// base FQDN — so a client and a destination that disagree on port sets can never
/// silently cross-wire through a shared base-FQDN channel; a mismatch fails
/// closed (the missing per-port/base proxy) instead.
///
/// Here the SAME service `svc-b` and SAME numeric port 9090 are materialized
/// under two client shapes: single-port `{9090}` dials the BARE base FQDN, while
/// multi-port `{8080,9090}` dials `p9090`. The two SNIs DIFFER — there is no
/// shared base-FQDN mapping for :9090 that a skewed peer could misroute onto.
#[test]
fn cross_cluster_multiport_port_never_shares_base_fqdn_channel_with_single_port() {
    let runtime = sidecar_client_runtime();

    // Extract the cross-cluster dial SNI a client materializes for :9090 given a
    // service whose HTTP port set is `ports`.
    let dial_sni_for_9090 = |ports: Vec<u16>| -> Option<String> {
        let mk_ports = || -> Vec<WorkloadPort> {
            ports
                .iter()
                .map(|&p| WorkloadPort {
                    port: p,
                    protocol: AppProtocol::Http,
                    name: Some(format!("http-{p}")),
                })
                .collect()
        };
        let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
        local.ports = mk_ports();
        let mut remote = remote_workload(Some(REMOTE_NETWORK));
        remote.ports = mk_ports();
        let service = MeshService {
            cluster_ips: Vec::new(),
            name: "svc-b".to_string(),
            namespace: "default".to_string(),
            ports: ports
                .iter()
                .map(|&p| ServicePort {
                    port: p,
                    protocol: AppProtocol::Http,
                    name: Some(format!("http-{p}")),
                    target_port: None,
                })
                .collect(),
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
        // Gateway claims the base FQDN AND both per-port aliases, so selection
        // never gates this SNI-SHAPE assertion regardless of the port set under
        // test. (`sni_hosts` must be non-empty — validation rejects a cleared
        // list — so we enumerate rather than wildcard.)
        let mut mc = multi_cluster_with_gateway(Some(REMOTE_NETWORK));
        mc.east_west_gateways[0].sni_hosts = vec![
            SVC_B_FQDN.to_string(),
            "p8080.svc-b.default.svc.cluster.local".to_string(),
            "p9090.svc-b.default.svc.cluster.local".to_string(),
        ];
        mesh.multi_cluster = Some(mc);
        materialize_all_upstream_targets(mesh, &runtime)
            .get("__mesh-out-upstream-default-svc-b-9090")
            .and_then(|targets| {
                targets
                    .iter()
                    .find(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
                    .and_then(|t| t.tags.get(MESH_EASTWEST_SNI_TAG).cloned())
            })
    };

    // Single-port client: :9090 is the sole port ⇒ bare base FQDN.
    assert_eq!(
        dial_sni_for_9090(vec![9090]).as_deref(),
        Some(SVC_B_FQDN),
        "a single-port service dials the bare base FQDN for its sole port"
    );
    // Multi-port client: :9090 ⇒ explicit p9090 alias, NOT the base FQDN.
    assert_eq!(
        dial_sni_for_9090(vec![8080, 9090]).as_deref(),
        Some("p9090.svc-b.default.svc.cluster.local"),
        "a multi-port service dials the explicit p<port> alias for :9090, never the base FQDN"
    );
    // The two SNIs differ ⇒ no shared base-FQDN channel for :9090 that a skewed
    // peer (different port set) could silently cross-wire onto — mismatches fail
    // closed on the absent proxy instead.
    assert_ne!(
        dial_sni_for_9090(vec![9090]),
        dial_sni_for_9090(vec![8080, 9090]),
        "port :9090 must not resolve to the SAME SNI under single-port vs multi-port shapes \
         (that shared channel is exactly the codex #2040 Finding A cross-cluster misroute)"
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

/// codex #2040 Finding C: a gateway that lists ONLY the per-port alias SNI
/// (`p9090.<fqdn>`) — not the base FQDN — must still be SELECTED for the :9090
/// port being dialed on that alias. Previously selection tested only the base
/// FQDN, so an alias-only gateway was rejected and the port emitted no
/// cross-cluster target. The multi-port service's :9090 dials `p9090`, and the
/// only gateway on the network claims exactly `p9090` — the target must be
/// emitted, addressed at that gateway.
#[test]
fn gateway_selection_accepts_alias_only_gateway_for_dialed_port() {
    let runtime = sidecar_client_runtime();

    let mk_ports = || -> Vec<WorkloadPort> {
        vec![
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
        ]
    };
    let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    local.ports = mk_ports();
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    remote.ports = mk_ports();
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

    const ALIAS_9090: &str = "p9090.svc-b.default.svc.cluster.local";
    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    // The ONLY gateway on net-b claims JUST the p9090 alias — NOT the base FQDN.
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![EastWestGateway {
            name: "ew-net-b-alias-only".to_string(),
            namespace: "default".to_string(),
            host: GATEWAY_HOST.to_string(),
            port: GATEWAY_PORT,
            sni_hosts: vec![ALIAS_9090.to_string()],
            trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
            network: Some(REMOTE_NETWORK.to_string()),
        }],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);

    // :9090 dials p9090, which the alias-only gateway claims ⇒ target emitted.
    let nine = upstreams
        .get("__mesh-out-upstream-default-svc-b-9090")
        .expect("9090 upstream");
    let nine_cross: Vec<_> = nine
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        nine_cross.len(),
        1,
        "an alias-only gateway must be selectable for the port dialing that alias"
    );
    assert_eq!(
        nine_cross[0].host, GATEWAY_HOST,
        "the alias-only gateway is the selected dial endpoint for :9090"
    );
    assert_eq!(
        nine_cross[0]
            .tags
            .get(MESH_EASTWEST_SNI_TAG)
            .map(String::as_str),
        Some(ALIAS_9090),
    );

    // :8080 dials p8080, which NO gateway claims (and the base FQDN is not claimed
    // either) ⇒ fail closed, no target for :8080.
    let eight_cross = upstreams
        .get("__mesh-out-upstream-default-svc-b-8080")
        .map(|targets| {
            targets
                .iter()
                .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        eight_cross, 0,
        ":8080 dials p8080 which no gateway claims — fail closed (no base-FQDN fallback)"
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

// ── Ambient (HBONE) cross-cluster materialization ───────────────────────────
//
// The HBONE counterpart of the Sidecar cases above. The SHAPE differs: Ambient
// cross-cluster targets are PER-REMOTE-POD with the east-west gateway carried as
// a DIAL OVERRIDE (`mesh.hbone_dial_host` / `mesh.hbone_port`), the destination
// service FQDN as the outer-TLS SNI override (`mesh.eastwest_sni`), and
// trust-domain-only verification (NO `mesh.spiffe_id`). The per-pod IDENTITY
// (`UpstreamTarget.host`) is a SCOPED SYNTHETIC host keyed by `(gateway dial
// endpoint, real pod addr)` (so overlapping-CIDR same-IP pods reached through
// different gateways never collapse to one host:port runtime key); the REAL pod
// addr (the inner HBONE CONNECT `:authority`) rides `mesh.hbone_authority_host`.

use ferrum_edge::proxy::hbone_pool::{
    HBONE_AUTHORITY_HOST_TAG, HBONE_DIAL_HOST_TAG, HBONE_PORT_TAG, HBONE_TARGET_TAG,
};

fn ambient_client_runtime() -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = default_mesh_runtime();
    runtime.topology = MeshTopology::Ambient;
    runtime.workload_spiffe_id = Some("spiffe://cluster.local/ns/default/sa/client".to_string());
    runtime
}

/// Ambient: a remote workload on a network with a matching gateway materializes
/// ONE per-pod HBONE cross-cluster target whose IDENTITY is a scoped synthetic
/// host (NOT the gateway, NOT the bare pod IP), with the real pod addr on
/// `mesh.hbone_authority_host` and the gateway carried as a dial override.
#[test]
fn ambient_cross_cluster_per_pod_hbone_target_has_correct_tags() {
    let runtime = ambient_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK)); // pod IP 10.244.5.5
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        1,
        "exactly one per-pod cross-cluster HBONE target expected, got {cross:#?}"
    );
    let xc = cross[0];

    // IDENTITY = a SCOPED SYNTHETIC host keyed by (gateway endpoint, pod addr) —
    // NOT the gateway and NOT the bare pod IP (so overlapping-CIDR collisions
    // can't collapse two pods onto one host:port runtime key). It must NOT be a
    // dialable address: it carries the gateway endpoint + the pod IP but is not
    // the pod IP alone.
    assert_ne!(
        xc.host, "10.244.5.5",
        "the synthetic identity must NOT be the bare pod IP (overlapping-CIDR collision risk)"
    );
    assert_ne!(
        xc.host, GATEWAY_HOST,
        "the synthetic identity must NOT be the gateway host either"
    );
    assert!(
        xc.host.contains("10.244.5.5") && xc.host.contains(GATEWAY_HOST),
        "the synthetic identity must scope the pod addr by the gateway endpoint, got {:?}",
        xc.host
    );
    // The REAL pod addr (the inner CONNECT authority) rides the dedicated tag.
    assert_eq!(
        xc.tags.get(HBONE_AUTHORITY_HOST_TAG).map(String::as_str),
        Some("10.244.5.5"),
        "mesh.hbone_authority_host must carry the real pod addr (the CONNECT authority)"
    );
    assert_eq!(xc.port, 8080, "the target port is the resolved app port");

    // Ambient HBONE transport tag (NOT mesh.mtls).
    assert_eq!(
        xc.tags.get(HBONE_TARGET_TAG).map(String::as_str),
        Some("true"),
        "cross-cluster Ambient target carries the mesh.hbone transport tag"
    );
    assert!(
        !xc.tags.contains_key("mesh.mtls"),
        "Ambient cross-cluster target must NOT carry the Sidecar mesh.mtls tag"
    );

    // Dial override = the gateway (host:port), DISTINCT from the target identity.
    assert_eq!(
        xc.tags.get(HBONE_DIAL_HOST_TAG).map(String::as_str),
        Some(GATEWAY_HOST),
        "mesh.hbone_dial_host must be the east-west gateway host (≠ the pod IP)"
    );
    assert_eq!(
        xc.tags.get(HBONE_PORT_TAG).map(String::as_str),
        Some(GATEWAY_PORT.to_string().as_str()),
        "mesh.hbone_port must be the east-west gateway port"
    );

    // Outer-TLS SNI override = the destination service FQDN.
    assert_eq!(
        xc.tags.get(MESH_EASTWEST_SNI_TAG).map(String::as_str),
        Some(SVC_B_FQDN),
        "mesh.eastwest_sni must be the destination service FQDN"
    );

    // Cross-cluster + remote markers; trust domain = remote (B); NO pinned id.
    assert_eq!(
        xc.tags.get(MESH_CROSS_CLUSTER_TAG).map(String::as_str),
        Some("true")
    );
    assert_eq!(
        xc.tags.get("mesh.remote").map(String::as_str),
        Some("true"),
        "cross-cluster target must carry the reserved mesh.remote=true provenance marker"
    );
    assert_eq!(
        xc.tags.get("mesh.trust_domain").map(String::as_str),
        Some(REMOTE_TRUST_DOMAIN),
        "mesh.trust_domain must be the remote (B) trust domain"
    );
    assert!(
        !xc.tags.contains_key("mesh.spiffe_id"),
        "Ambient cross-cluster target must NOT carry a pinned mesh.spiffe_id (trust-domain-only)"
    );

    // DR policy stays keyed by the declared SERVICE port.
    assert_eq!(xc.service_port_policy_key, Some(8080));

    // The local workload still materializes a (first-tier) pinned mesh.hbone
    // target dialing the local pod directly — local-first failover preserved.
    let local_targets: Vec<_> = upstreams
        .get(SVC_B_OUTBOUND_UPSTREAM_ID)
        .expect("first-port upstream must materialize")
        .iter()
        .filter(|t| {
            t.tags.get(HBONE_TARGET_TAG).map(String::as_str) == Some("true")
                && !t.tags.contains_key(MESH_CROSS_CLUSTER_TAG)
        })
        .collect();
    assert_eq!(
        local_targets.len(),
        1,
        "the local workload must still materialize one pinned mesh.hbone target"
    );
    assert_eq!(local_targets[0].host, "10.0.0.1");
    assert!(
        local_targets[0].tags.contains_key("mesh.spiffe_id"),
        "the local Ambient target stays PINNED (carries mesh.spiffe_id)"
    );
    // The local target dials the pod directly: no dial-host override, no SNI.
    assert!(
        !local_targets[0].tags.contains_key(HBONE_DIAL_HOST_TAG),
        "the local Ambient target has no dial-host override (dials the pod directly)"
    );
    assert!(!local_targets[0].tags.contains_key(MESH_EASTWEST_SNI_TAG));
}

/// Ties the materialized Ambient cross-cluster target to the RUNTIME guards: the
/// dispatch helpers must read the gateway dial host / SNI / trust domain / real
/// CONNECT authority off it, and `target_hbone_cross_cluster` (the predicate the
/// gRPC fail-closed guard, the capability-collection skip, and the dispatch
/// branch all key on) must return `true`. The LOCAL (in-cluster) target must
/// read its authority back as its own host (no override) and not be classed
/// cross-cluster.
#[test]
fn ambient_cross_cluster_target_drives_runtime_dispatch_helpers() {
    use ferrum_edge::proxy::hbone_pool;

    let runtime = ambient_client_runtime();
    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote = remote_workload(Some(REMOTE_NETWORK)); // pod IP 10.244.5.5
    let service = svc_b_service(&local, &remote);
    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    let xc = cross[0];

    // The predicate the gRPC fail-closed guard, the capability-collection skip,
    // and the dispatch cross-cluster branch all key on.
    assert!(
        hbone_pool::target_hbone_cross_cluster(xc),
        "the materialized target must be recognized as cross-cluster by the runtime predicate"
    );
    // Dispatch reads the gateway as the network DIAL host (not the synthetic id).
    assert_eq!(
        hbone_pool::target_hbone_dial_host(xc).unwrap(),
        GATEWAY_HOST,
        "dispatch dials the east-west gateway"
    );
    assert_eq!(hbone_pool::target_hbone_port(xc), GATEWAY_PORT);
    // Dispatch reads the REAL pod addr (NOT the synthetic host) as the inner
    // CONNECT authority.
    assert_eq!(
        hbone_pool::target_hbone_authority_host(xc).unwrap(),
        "10.244.5.5",
        "dispatch uses the real pod addr as the CONNECT authority, never the synthetic identity"
    );
    assert_ne!(
        hbone_pool::target_hbone_authority_host(xc).unwrap(),
        xc.host.as_str(),
        "the synthetic identity and the CONNECT authority host are distinct for cross-cluster"
    );
    // Required cross-cluster verification inputs are present + usable.
    assert_eq!(
        hbone_pool::target_hbone_eastwest_sni(xc),
        Some(SVC_B_FQDN),
        "the outer-TLS SNI override is the destination service FQDN"
    );
    assert!(
        hbone_pool::target_hbone_cross_cluster_trust_domain(xc).is_some(),
        "the remote trust domain is present + parseable (else dispatch fails closed)"
    );

    // The LOCAL (in-cluster) Ambient target is NOT cross-cluster, and its CONNECT
    // authority reads back as its own host (no override tag).
    let local_target = upstreams
        .get(SVC_B_OUTBOUND_UPSTREAM_ID)
        .expect("first-port upstream")
        .iter()
        .find(|t| {
            t.tags.get(HBONE_TARGET_TAG).map(String::as_str) == Some("true")
                && !t.tags.contains_key(MESH_CROSS_CLUSTER_TAG)
        })
        .expect("a pinned local mesh.hbone target");
    assert!(!hbone_pool::target_hbone_cross_cluster(local_target));
    assert_eq!(
        hbone_pool::target_hbone_authority_host(local_target).unwrap(),
        local_target.host.as_str(),
        "an in-cluster target's CONNECT authority IS its host (no synthetic indirection)"
    );
}

/// Ambient: TWO remote pods on the same network behind one gateway yield TWO
/// per-pod targets (distinct pod-IP identities) — NO same-endpoint collapse
/// (each pod is a distinct pinned CONNECT authority, unlike the Sidecar
/// per-gateway shape).
#[test]
fn ambient_cross_cluster_two_pods_same_gateway_yield_two_per_pod_targets() {
    let runtime = ambient_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote pods sharing one service-account SPIFFE id, same network/TD,
    // DIFFERENT pod IPs (merge keeps both Workloads, one merged ref).
    let remote_a = remote_workload(Some(REMOTE_NETWORK)); // 10.244.5.5
    let mut remote_b = remote_workload(Some(REMOTE_NETWORK));
    remote_b.addresses = vec!["10.244.5.6".to_string()];
    assert_eq!(
        remote_a.spiffe_id, remote_b.spiffe_id,
        "test premise: the two pods share one SPIFFE id"
    );
    let service = svc_b_service(&local, &remote_a);

    let mut mesh = mesh_config_with(vec![local, remote_a, remote_b], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    // Each pod's REAL CONNECT-authority addr (the `mesh.hbone_authority_host`
    // tag) must be its own pod IP — proving the per-pod fan-out (no
    // same-endpoint collapse) routes each by its pinned authority.
    let mut authority_hosts: Vec<&str> = cross
        .iter()
        .map(|t| {
            t.tags
                .get(HBONE_AUTHORITY_HOST_TAG)
                .map(String::as_str)
                .expect("every cross-cluster target carries mesh.hbone_authority_host")
        })
        .collect();
    authority_hosts.sort();
    assert_eq!(
        authority_hosts,
        vec!["10.244.5.5", "10.244.5.6"],
        "two remote pods behind one gateway must each yield a per-pod cross-cluster target \
         (no same-endpoint collapse), got: {cross:#?}"
    );
    // The SYNTHETIC identities (`UpstreamTarget.host`) must also be DISTINCT so
    // the two pods never share a host:port-keyed runtime map entry.
    let mut synthetic_hosts: Vec<&str> = cross.iter().map(|t| t.host.as_str()).collect();
    synthetic_hosts.sort();
    synthetic_hosts.dedup();
    assert_eq!(
        synthetic_hosts.len(),
        2,
        "the two pods' synthetic identities must be distinct, got: {cross:#?}"
    );
    // Both dial the SAME gateway (dial override), with the SAME SNI.
    for t in &cross {
        assert_eq!(
            t.tags.get(HBONE_DIAL_HOST_TAG).map(String::as_str),
            Some(GATEWAY_HOST)
        );
        assert_eq!(
            t.tags.get(MESH_EASTWEST_SNI_TAG).map(String::as_str),
            Some(SVC_B_FQDN)
        );
    }
}

/// Ambient: an UNREACHABLE remote workload (no addresses) yields no
/// cross-cluster target; the local target is unaffected.
#[test]
fn ambient_cross_cluster_skips_unreachable_remote_workload() {
    let runtime = ambient_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    remote.addresses = Vec::new(); // no pod IP → unreachable
    let service = svc_b_service(&local, &remote);

    let mut mesh = mesh_config_with(vec![local, remote], vec![service], Vec::new());
    mesh.multi_cluster = Some(multi_cluster_with_gateway(Some(REMOTE_NETWORK)));

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    assert_eq!(
        cross_cluster_targets(&upstreams).len(),
        0,
        "an unreachable remote workload (no pod IP) must yield NO cross-cluster HBONE target"
    );
}

/// Ambient: a DECLARED named `targetPort` that does NOT resolve on the remote
/// workload yields no cross-cluster target (fail closed; mirrors the
/// reachability filter and `build_east_west_service_targets`'s skip).
#[test]
fn ambient_cross_cluster_skips_unresolvable_named_target_port() {
    let runtime = ambient_client_runtime();

    let mut local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    local.ports = vec![WorkloadPort {
        port: 8080,
        protocol: AppProtocol::Http,
        name: Some("http".to_string()),
    }];
    let mut remote = remote_workload(Some(REMOTE_NETWORK));
    // The workload exposes only a port NAMED differently than the targetPort.
    remote.ports = vec![WorkloadPort {
        port: 8080,
        protocol: AppProtocol::Http,
        name: Some("not-the-name".to_string()),
    }];

    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "svc-b".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            // Named targetPort that the remote workload does NOT expose by name.
            target_port: Some(ferrum_edge::modes::mesh::config::ServiceTargetPort::Name(
                "web".to_string(),
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
        "an unresolvable named targetPort must yield NO Ambient cross-cluster target (fail closed)"
    );
}

/// Ambient multi-port east-west (issue #2010 phase 3; codex #2040 Finding A):
/// EVERY HTTP-family service port of a multi-port service gets per-pod
/// cross-cluster HBONE targets on an EXPLICIT `p<port>.<fqdn>` SNI alias —
/// including the lowest port. No port routes on the bare base FQDN.
#[test]
fn ambient_cross_cluster_for_each_http_service_port() {
    let runtime = ambient_client_runtime();

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
    let first_cross: Vec<_> = upstreams
        .get("__mesh-out-upstream-default-svc-b-8080")
        .expect("first-port upstream")
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        first_cross.len(),
        1,
        "first port yields one per-pod cross-cluster target"
    );
    assert_eq!(
        first_cross[0]
            .tags
            .get(MESH_EASTWEST_SNI_TAG)
            .map(String::as_str),
        Some("p8080.svc-b.default.svc.cluster.local"),
        "the lowest port of a MULTI-port service routes on its explicit p<port> alias, not the base FQDN"
    );
    let second_cross: Vec<_> = upstreams
        .get("__mesh-out-upstream-default-svc-b-9090")
        .expect("second-port upstream")
        .iter()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .collect();
    assert_eq!(
        second_cross.len(),
        1,
        "a non-first HTTP service port now yields a per-pod cross-cluster target too"
    );
    assert_eq!(
        second_cross[0]
            .tags
            .get(MESH_EASTWEST_SNI_TAG)
            .map(String::as_str),
        Some("p9090.svc-b.default.svc.cluster.local"),
        "the second port routes on the p<port> SNI alias"
    );
}

/// Ambient: FAIL CLOSED when two trust domains' pods resolve to the SAME gateway
/// DIAL ENDPOINT (a TD-less wildcard gateway fronting pods that span two trust
/// domains) — the SNI-passthrough gateway terminates one outer-TLS identity, so
/// a shared endpoint cannot pin a trust domain. EVERY pod target on that
/// ambiguous endpoint is dropped.
#[test]
fn ambient_cross_cluster_fails_closed_on_cross_td_shared_dial_endpoint() {
    let runtime = ambient_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    // Two remote pods on the SAME network, DIFFERENT trust domains.
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
    // domains, so both pods' targets resolve to this one DIAL ENDPOINT.
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
        "two trust domains resolving to one shared gateway DIAL ENDPOINT must yield NO Ambient \
         cross-cluster target (fail closed)"
    );
}

/// Ambient: two DISTINCT-TD pods fronted by DISTINCT gateway endpoints (one per
/// TD, distinct host:port) are NOT ambiguous → both per-pod targets are emitted.
#[test]
fn ambient_cross_cluster_distinct_td_distinct_endpoints_both_emitted() {
    let runtime = ambient_client_runtime();

    let local = workload_for("svc-b", "default", [("app", "svc-b")], ["10.0.0.1"]);
    let remote_td_b = remote_workload(Some("net-b")); // TD cluster-b.local
    let mut remote_td_c = remote_workload(Some("net-c"));
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

    const GW_B_HOST: &str = "10.9.9.11";
    const GW_C_HOST: &str = "10.9.9.12";
    let mut mesh = mesh_config_with(
        vec![local, remote_td_b, remote_td_c],
        vec![service],
        Vec::new(),
    );
    mesh.multi_cluster = Some(MultiClusterConfig {
        local_cluster: Some("cluster-a".to_string()),
        federation_endpoint: None,
        remote_clusters: Vec::new(),
        east_west_gateways: vec![
            EastWestGateway {
                name: "ew-net-b".to_string(),
                namespace: "default".to_string(),
                host: GW_B_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td(REMOTE_TRUST_DOMAIN)),
                network: Some("net-b".to_string()),
            },
            EastWestGateway {
                name: "ew-net-c".to_string(),
                namespace: "default".to_string(),
                host: GW_C_HOST.to_string(),
                port: GATEWAY_PORT,
                sni_hosts: vec![SVC_B_FQDN.to_string()],
                trust_domain: Some(td("cluster-c.local")),
                network: Some("net-c".to_string()),
            },
        ],
    });

    let upstreams = materialize_all_upstream_targets(mesh, &runtime);
    let cross = cross_cluster_targets(&upstreams);
    assert_eq!(
        cross.len(),
        2,
        "two distinct-TD pods behind distinct gateway endpoints must both emit a per-pod target, \
         got: {cross:#?}"
    );
    // Each pod's CONNECT-authority addr (`mesh.hbone_authority_host`) is its own
    // pod IP; the dial override + trust domain pair up correctly per TD. The
    // synthetic `target.host` identities must also be distinct.
    let mut by_authority: std::collections::HashMap<&str, (&str, &str)> =
        std::collections::HashMap::new();
    let mut synthetic_hosts: Vec<&str> = Vec::new();
    for t in &cross {
        synthetic_hosts.push(t.host.as_str());
        by_authority.insert(
            t.tags
                .get(HBONE_AUTHORITY_HOST_TAG)
                .map(String::as_str)
                .expect("every cross-cluster target carries mesh.hbone_authority_host"),
            (
                t.tags
                    .get(HBONE_DIAL_HOST_TAG)
                    .map(String::as_str)
                    .unwrap_or(""),
                t.tags
                    .get("mesh.trust_domain")
                    .map(String::as_str)
                    .unwrap_or(""),
            ),
        );
    }
    assert_eq!(
        by_authority.get("10.244.5.5"),
        Some(&(GW_B_HOST, REMOTE_TRUST_DOMAIN))
    );
    assert_eq!(
        by_authority.get("10.244.6.6"),
        Some(&(GW_C_HOST, "cluster-c.local"))
    );
    synthetic_hosts.sort();
    synthetic_hosts.dedup();
    assert_eq!(
        synthetic_hosts.len(),
        2,
        "the two distinct-TD pods' synthetic identities must be distinct"
    );
}

/// Ambient: a TCP (stream-family) service port must yield NO cross-cluster
/// target (HTTP-family only — the L4 tunnel can't carry the SNI-passthrough
/// semantics), proving the HTTP-family gate on the Ambient branch too.
#[test]
fn ambient_no_cross_cluster_target_for_tcp_service_port() {
    let runtime = ambient_client_runtime();

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
    let cross_anywhere = upstreams
        .values()
        .flatten()
        .filter(|t| t.tags.contains_key(MESH_CROSS_CLUSTER_TAG))
        .count();
    assert_eq!(
        cross_anywhere, 0,
        "an Ambient TCP-only service must yield NO cross-cluster target (HTTP-family only)"
    );
}

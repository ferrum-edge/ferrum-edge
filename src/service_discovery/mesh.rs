//! Ferrum mesh service discovery.
//!
//! Resolves CP-delivered [`MeshService`](crate::modes::mesh::config::MeshService)
//! resources into gateway upstream targets. This lets a north-south gateway use
//! the same service names the east-west mesh already understands while keeping
//! the request hot path on the existing load-balancer snapshot.

use crate::config::types::UpstreamTarget;
use crate::modes::mesh::config::{
    AppProtocol, MeshService, ServiceTargetPort, Workload, resolve_target_port,
};
use crate::request_epoch::RequestEpochStore;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;

/// Service discovery provider backed by the current `GatewayConfig.mesh`
/// snapshot delivered to gateway data planes by the control plane.
pub struct MeshServiceDiscoverer {
    request_epoch: Arc<RequestEpochStore>,
    service_name: String,
    namespace: String,
    port: Option<u16>,
    default_weight: u32,
}

impl MeshServiceDiscoverer {
    pub fn new(
        request_epoch: Arc<RequestEpochStore>,
        service_name: String,
        namespace: String,
        port: Option<u16>,
        default_weight: u32,
    ) -> Self {
        Self {
            request_epoch,
            service_name,
            namespace,
            port,
            default_weight,
        }
    }

    fn selected_service_port(&self, service: &MeshService) -> Option<SelectedPort> {
        if let Some(requested) = self.port {
            return if service.ports.is_empty() {
                Some(SelectedPort {
                    port: requested,
                    service_port: Some(requested),
                    name: None,
                    protocol: AppProtocol::Unknown,
                    target_port: None,
                })
            } else {
                service
                    .ports
                    .iter()
                    .find(|port| port.port == requested)
                    .map(|port| SelectedPort {
                        port: port.port,
                        service_port: Some(port.port),
                        name: port.name.clone(),
                        protocol: port.protocol,
                        target_port: port.target_port.clone(),
                    })
            };
        }

        service.ports.first().map(|port| SelectedPort {
            port: port.port,
            service_port: Some(port.port),
            name: port.name.clone(),
            protocol: port.protocol,
            target_port: port.target_port.clone(),
        })
    }

    fn workload_matches_service(
        service: &MeshService,
        workload: &Workload,
        matching_service_spiffe_ids: &HashSet<&str>,
    ) -> bool {
        if workload.namespace != service.namespace {
            return false;
        }

        if service.workloads.is_empty() {
            return workload.service_name == service.name;
        }

        if !service
            .workloads
            .iter()
            .any(|reference| reference.spiffe_id == workload.spiffe_id)
        {
            return false;
        }

        if workload.service_name == service.name {
            return true;
        }

        // Legacy and hand-authored mesh snapshots can carry authoritative
        // MeshService.workloads refs while workload.service_name metadata still
        // points at another logical service. Prefer a matching service_name when
        // duplicate SPIFFE entries exist, but do not blackhole explicit refs when
        // the metadata is stale or absent.
        !matching_service_spiffe_ids.contains(workload.spiffe_id.as_str())
    }

    fn target_port_for_workload(
        selected_service_port: Option<&SelectedPort>,
        workload: &Workload,
    ) -> Option<SelectedPort> {
        if let Some(selected) = selected_service_port {
            // A DECLARED Service `targetPort` is Kubernetes' authoritative
            // service-port→container-port binding, so honor it exclusively: a
            // numeric targetPort needs no matching `containerPort` (so this also
            // covers a workload that declares no `ports[]`), and a named one
            // resolves against the workload's container-port names. FAIL CLOSED —
            // return `None` to drop the target — when a NAMED targetPort does not
            // resolve, rather than fall back to the Service port (a rollout skew
            // or typo like `port: 80, targetPort: "http"` with no matching
            // container port would otherwise silently dial 80). Only an ABSENT
            // targetPort uses the heuristics below.
            if selected.target_port.is_some() {
                return match resolve_target_port(selected.target_port.as_ref(), &workload.ports) {
                    Some(backend) if backend != 0 => Some(SelectedPort {
                        port: backend,
                        service_port: selected.service_port,
                        name: selected.name.clone(),
                        protocol: selected.protocol,
                        target_port: None,
                    }),
                    _ => None,
                };
            }

            if workload.ports.is_empty() {
                return Some(selected.clone());
            }

            if let Some(workload_port) = workload
                .ports
                .iter()
                .find(|port| port.port == selected.port)
            {
                if selected.protocol == AppProtocol::Unknown && selected.name.is_none() {
                    return Some(SelectedPort {
                        port: workload_port.port,
                        service_port: selected.service_port,
                        name: workload_port.name.clone(),
                        protocol: workload_port.protocol,
                        target_port: None,
                    });
                }
                return Some(selected.clone());
            }
            return None;
        }

        workload.ports.first().map(|port| SelectedPort {
            port: port.port,
            service_port: None,
            name: port.name.clone(),
            protocol: port.protocol,
            target_port: None,
        })
    }

    fn tags_for_target(
        service: &MeshService,
        workload: &Workload,
        selected_port: &SelectedPort,
    ) -> HashMap<String, String> {
        mesh_hbone_target_tags(
            service,
            workload,
            selected_port.protocol,
            selected_port.name.as_deref(),
        )
    }
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for MeshServiceDiscoverer {
    async fn discover(&self) -> Result<Vec<UpstreamTarget>, anyhow::Error> {
        let epoch = self.request_epoch.load();
        let Some(mesh) = epoch.config.mesh.as_deref() else {
            return Ok(Vec::new());
        };

        let Some(service) = mesh.services.iter().find(|service| {
            service.name == self.service_name && service.namespace == self.namespace
        }) else {
            return Ok(Vec::new());
        };

        let selected_service_port = self.selected_service_port(service);
        if self.port.is_some() && selected_service_port.is_none() {
            return Ok(Vec::new());
        }

        let mut targets = Vec::new();
        let mut seen = HashSet::new();
        // Multi-cluster config for the cluster-name FALLBACK leg of remote
        // classification. Remote endpoints reach this discoverer via
        // `merge_remote_endpoints_into_mesh` carrying the RESERVED, un-spoofable
        // `Workload::remote_provenance` marker stamped by the DP-side poll loop's
        // `tag_remote_workloads` at ingestion; we copy that into the explicit
        // `mesh.remote=true` target tag so strict local-first LB keys on real
        // cross-cluster PROVENANCE — independent of whatever `cluster` name an
        // Istio WorkloadEntry translation stamped, and NOT a locality-string
        // prefix. This uses the SAME `workload_is_remote` predicate as the egress
        // local-only filter (`matched_local_service_workloads`), so "remote" never
        // means two different things. The provenance marker is authoritative;
        // cluster-name matching (which needs this `multi_cluster`) only ever
        // promotes an unmarked workload to remote (defense in depth), never the
        // reverse.
        let multi_cluster = mesh.multi_cluster.as_ref();
        let matching_service_spiffe_ids: HashSet<&str> = mesh
            .workloads
            .iter()
            .filter(|workload| {
                workload.namespace == service.namespace && workload.service_name == service.name
            })
            .map(|workload| workload.spiffe_id.as_str())
            .collect();
        for workload in mesh.workloads.iter().filter(|workload| {
            Self::workload_matches_service(service, workload, &matching_service_spiffe_ids)
        }) {
            let Some(selected_port) =
                Self::target_port_for_workload(selected_service_port.as_ref(), workload)
            else {
                continue;
            };

            let is_remote =
                crate::modes::mesh::multicluster::workload_is_remote(workload, multi_cluster);

            for address in &workload.addresses {
                if address.is_empty() {
                    continue;
                }
                // Collapse runtime targets on `(address, port, spiffe_id)` ONLY —
                // deliberately NOT on `cluster`/`network` provenance. Two remote
                // entries can advertise the same address on different networks
                // (overlapping CIDR), but the rest of the runtime keys a target by
                // its literal `host:port`: the dial uses `UpstreamTarget.host`, and
                // LoadBalancer/HealthChecker/circuit-breaker keys are `host:port`
                // (or `upstream_id::host:port`). The `mesh.cluster`/`mesh.network`
                // tags are introspection metadata only — nothing downstream reads
                // them to disambiguate dial/health/CB. Emitting two same-`host:port`
                // targets would therefore yield no independently-dial-able failover
                // peer (no network-gateway address rewrite exists yet, issue #1719)
                // while letting a passive/active ejection or opened circuit for one
                // overlapping-CIDR endpoint silently eject the sibling via the
                // shared key. Keep them collapsed until target identity carries
                // provenance. The merge-layer `WorkloadEndpointKey` still retains
                // `cluster`/`network` so the workload REGISTRY keeps both for
                // provenance/metadata; only the emitted RUNTIME target collapses.
                let key = (
                    address.as_str(),
                    selected_port.port,
                    selected_port.service_port,
                    workload.spiffe_id.as_str(),
                );
                if !seen.insert(key) {
                    continue;
                }

                let mut tags = Self::tags_for_target(service, workload, &selected_port);
                if is_remote {
                    tags.insert(
                        crate::modes::mesh::multicluster::MESH_REMOTE_TAG.to_string(),
                        crate::modes::mesh::multicluster::MESH_REMOTE_TAG_VALUE.to_string(),
                    );
                }
                targets.push(UpstreamTarget {
                    host: address.clone(),
                    port: selected_port.port,
                    service_port_policy_key: selected_port.service_port,
                    weight: self.default_weight,
                    tags,
                    locality: workload.locality.clone(),
                    path: None,
                });
            }
        }

        debug!(
            "Mesh discovery: found {} targets for {}/{}",
            targets.len(),
            self.namespace,
            self.service_name,
        );
        Ok(targets)
    }

    fn provider_name(&self) -> &str {
        "mesh"
    }
}

#[derive(Clone)]
struct SelectedPort {
    /// Resolved workload/app port used as the actual dial destination.
    port: u16,
    /// Declared Service port that owns this target and keys DestinationRule
    /// `portLevelSettings`. `None` when discovery fell back to workload ports
    /// because the service declared none.
    service_port: Option<u16>,
    name: Option<String>,
    protocol: AppProtocol,
    /// The Service port's `targetPort`, carried so workload-address targets dial
    /// the container port it declares rather than the Service port.
    target_port: Option<ServiceTargetPort>,
}

fn protocol_tag(protocol: AppProtocol) -> &'static str {
    match protocol {
        AppProtocol::Http => "http",
        AppProtocol::Http2 => "http2",
        AppProtocol::Grpc => "grpc",
        AppProtocol::Tcp => "tcp",
        AppProtocol::Tls => "tls",
        AppProtocol::Udp => "udp",
        AppProtocol::Mongo => "mongo",
        AppProtocol::Redis => "redis",
        AppProtocol::Mysql => "mysql",
        AppProtocol::Postgres => "postgres",
        AppProtocol::Unknown => "unknown",
    }
}

/// Build the `mesh.*` UpstreamTarget tags that mark a target for HBONE dispatch
/// (HTTP/2 CONNECT over auto-originated SVID mTLS) and carry the peer identity
/// the mTLS handshake PINS (`mesh.spiffe_id` / `mesh.trust_domain`).
///
/// Shared by runtime mesh service discovery
/// ([`MeshServiceDiscoverer::tags_for_target`]) and by Ambient outbound route
/// materialization (`modes::mesh::build_outbound_mesh_targets`) so the two paths
/// cannot drift on the tag contract that `proxy::hbone_pool` and
/// `supports_hbone_backend` consume.
pub(crate) fn mesh_hbone_target_tags(
    service: &MeshService,
    workload: &Workload,
    protocol: AppProtocol,
    port_name: Option<&str>,
) -> HashMap<String, String> {
    let mut tags = mesh_target_tags_core(service, workload, protocol, port_name);
    tags.insert(
        crate::proxy::hbone_pool::HBONE_TARGET_TAG.to_string(),
        "true".to_string(),
    );
    tags
}

/// Build the `mesh.*` UpstreamTarget tags for NodeWaypoint captured-Service
/// HTTP dispatch. The in-pod-netns capture listener has already attributed the
/// source pod and runs `mesh_authz`; there is no reachable backing-pod HBONE or
/// sidecar-mTLS listener to tag here, so this intentionally carries destination
/// identity and service metadata without a mesh transport tag.
pub(crate) fn mesh_node_waypoint_plaintext_target_tags(
    service: &MeshService,
    workload: &Workload,
    protocol: AppProtocol,
    port_name: Option<&str>,
) -> HashMap<String, String> {
    mesh_target_tags_core(service, workload, protocol, port_name)
}

/// Build the `mesh.*` UpstreamTarget tags that mark a target for Sidecar
/// SVID-mTLS dispatch (plain HTTP/2 over mutual TLS to the peer sidecar's
/// inbound listener). Same shared identity tags as the HBONE builder, but with
/// `mesh.mtls=true` instead of `mesh.hbone` — the transports are per-topology
/// and a target carries exactly one.
pub(crate) fn mesh_sidecar_mtls_target_tags(
    service: &MeshService,
    workload: &Workload,
    protocol: AppProtocol,
    port_name: Option<&str>,
) -> HashMap<String, String> {
    let mut tags = mesh_target_tags_core(service, workload, protocol, port_name);
    tags.insert(
        crate::proxy::mesh_mtls_pool::MESH_MTLS_TARGET_TAG.to_string(),
        "true".to_string(),
    );
    tags
}

/// Transport-agnostic core of the mesh target tag contract: destination
/// identity (pinned by the outbound mTLS handshake), service metadata, and
/// topology hints. The transport-selecting tag (`mesh.hbone` / `mesh.mtls`) is
/// layered on by the wrappers above.
fn mesh_target_tags_core(
    service: &MeshService,
    workload: &Workload,
    protocol: AppProtocol,
    port_name: Option<&str>,
) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    tags.insert("mesh.namespace".to_string(), workload.namespace.clone());
    tags.insert("mesh.service".to_string(), service.name.clone());
    tags.insert(
        crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG.to_string(),
        workload.spiffe_id.as_str().to_string(),
    );
    tags.insert(
        "mesh.trust_domain".to_string(),
        workload.trust_domain.as_str().to_string(),
    );
    tags.insert(
        "mesh.protocol".to_string(),
        protocol_tag(protocol).to_string(),
    );
    if let Some(port_name) = port_name {
        tags.insert("mesh.port_name".to_string(), port_name.to_string());
    }
    if let Some(network) = &workload.network {
        tags.insert("mesh.network".to_string(), network.clone());
    }
    if let Some(cluster) = &workload.cluster {
        tags.insert("mesh.cluster".to_string(), cluster.clone());
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{GatewayConfig, default_namespace};
    use crate::consumer_index::ConsumerIndex;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::load_balancer::LoadBalancerCache;
    use crate::modes::mesh::config::{
        MeshConfig, ServicePort, WorkloadPort, WorkloadRef, WorkloadSelector,
    };
    use crate::plugin_cache::PluginCache;
    use crate::request_epoch::RequestEpochStore;
    use crate::service_discovery::ServiceDiscoverer;

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw.to_string()).expect("test SPIFFE ID")
    }

    fn workload(id: &str, service_name: &str, addresses: Vec<&str>, ports: Vec<u16>) -> Workload {
        Workload {
            spiffe_id: spiffe(id),
            selector: WorkloadSelector::default(),
            service_name: service_name.to_string(),
            addresses: addresses.into_iter().map(str::to_string).collect(),
            ports: ports
                .into_iter()
                .map(|port| WorkloadPort {
                    port,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                })
                .collect(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: default_namespace(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }
    }

    fn service(name: &str, refs: Vec<&str>, ports: Vec<u16>) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: default_namespace(),
            ports: ports
                .into_iter()
                .map(|port| ServicePort {
                    port,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                    target_port: None,
                })
                .collect(),
            workloads: refs
                .into_iter()
                .map(|id| WorkloadRef {
                    spiffe_id: spiffe(id),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn epoch_store(mesh: Option<MeshConfig>) -> Arc<RequestEpochStore> {
        let config = GatewayConfig {
            version: "1".to_string(),
            mesh: mesh.map(Box::new),
            ..GatewayConfig::default()
        };
        let plugin_cache = PluginCache::new(&config).expect("plugin cache");
        let consumer_index = ConsumerIndex::new(&config.consumers);
        let load_balancer_cache = LoadBalancerCache::new(&config);
        Arc::new(RequestEpochStore::from_runtime_parts(
            config,
            &plugin_cache,
            &consumer_index,
            &load_balancer_cache,
        ))
    }

    #[tokio::test]
    async fn discovers_numeric_target_port_when_workload_omits_ports() {
        // A Kubernetes numeric `targetPort` needs no matching `containerPort`, so
        // a workload with addresses but no `ports[]` must still dial the
        // targetPort (8080), not the Service port (80). Regression: the no-ports
        // fast path used to return the Service port before the targetPort resolve.
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![80]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].port, 8080,
            "dials the numeric targetPort even though the workload declares no ports"
        );
        assert_eq!(
            targets[0].service_port_policy_key,
            Some(80),
            "policy remains keyed by the declared Service port"
        );
    }

    #[tokio::test]
    async fn discovers_named_target_port_with_service_port_policy_key() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![80]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 8080, "dials the named targetPort");
        assert_eq!(
            targets[0].service_port_policy_key,
            Some(80),
            "DestinationRule policy is keyed by the owning declared Service port"
        );
    }

    #[tokio::test]
    async fn service_port_equal_to_workload_port_still_carries_policy_identity() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mesh = MeshConfig {
            services: vec![service("api", vec![api_id], vec![8080])],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 8080);
        assert_eq!(targets[0].service_port_policy_key, Some(8080));
    }

    #[tokio::test]
    async fn same_workload_endpoint_keeps_requested_service_port_identity() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![80, 81]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        svc.ports[1].target_port = Some(ServiceTargetPort::Number(8080));
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080])],
            ..MeshConfig::default()
        };

        let targets_80 = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh.clone())),
            "api".to_string(),
            default_namespace(),
            Some(80),
            1,
        )
        .discover()
        .await
        .expect("discover port 80");
        let targets_81 = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            Some(81),
            1,
        )
        .discover()
        .await
        .expect("discover port 81");

        assert_eq!(targets_80.len(), 1);
        assert_eq!(targets_81.len(), 1);
        assert_eq!(targets_80[0].port, 8080);
        assert_eq!(targets_81[0].port, 8080);
        assert_eq!(targets_80[0].service_port_policy_key, Some(80));
        assert_eq!(targets_81[0].service_port_policy_key, Some(81));
    }

    #[tokio::test]
    async fn same_named_target_port_can_resolve_differently_per_workload() {
        let api_a = "spiffe://cluster.local/ns/ferrum/sa/api-a";
        let api_b = "spiffe://cluster.local/ns/ferrum/sa/api-b";
        let mut svc = service("api", vec![api_a, api_b], vec![80]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![
                workload(api_a, "api", vec!["10.0.0.1"], vec![8080]),
                workload(api_b, "api", vec!["10.0.0.2"], vec![9090]),
            ],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let mut targets = discoverer.discover().await.expect("discover succeeds");
        targets.sort_by(|a, b| a.host.cmp(&b.host));

        assert_eq!(targets.len(), 2);
        assert_eq!(
            (targets[0].host.as_str(), targets[0].port),
            ("10.0.0.1", 8080)
        );
        assert_eq!(
            (targets[1].host.as_str(), targets[1].port),
            ("10.0.0.2", 9090)
        );
        assert!(
            targets
                .iter()
                .all(|target| target.service_port_policy_key == Some(80))
        );
    }

    #[tokio::test]
    async fn changed_target_port_mapping_replaces_discovered_dial_port() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc_v1 = service("api", vec![api_id], vec![80]);
        svc_v1.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let mut svc_v2 = service("api", vec![api_id], vec![80]);
        svc_v2.ports[0].target_port = Some(ServiceTargetPort::Number(9090));

        let discover = |svc| {
            MeshServiceDiscoverer::new(
                epoch_store(Some(MeshConfig {
                    services: vec![svc],
                    workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080, 9090])],
                    ..MeshConfig::default()
                })),
                "api".to_string(),
                default_namespace(),
                None,
                1,
            )
        };

        let targets_v1 = discover(svc_v1).discover().await.expect("discover v1");
        let targets_v2 = discover(svc_v2).discover().await.expect("discover v2");

        assert_eq!(targets_v1[0].port, 8080);
        assert_eq!(targets_v2[0].port, 9090);
        assert_eq!(targets_v2[0].service_port_policy_key, Some(80));
    }

    #[tokio::test]
    async fn discovery_drops_target_when_named_target_port_unresolved() {
        // A NAMED targetPort the workload does not expose must fail closed (drop
        // the target) rather than fall back to the Service port.
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![80]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Name("http".to_string()));
        let mut wl = workload(api_id, "api", vec!["10.0.0.1"], vec![9999]);
        wl.ports[0].name = Some("grpc".to_string()); // no "http" container port
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![wl],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");
        assert!(
            targets.is_empty(),
            "an unresolved named targetPort must drop the target, not dial the Service port"
        );
    }

    #[tokio::test]
    async fn discovers_mesh_service_workload_targets() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mesh = MeshConfig {
            services: vec![service("api", vec![api_id], vec![8080])],
            workloads: vec![
                workload(api_id, "api", vec!["10.0.0.1", "10.0.0.2"], vec![8080]),
                workload(
                    "spiffe://cluster.local/ns/ferrum/sa/other",
                    "other",
                    vec!["10.0.0.3"],
                    vec![8080],
                ),
            ],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            7,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 8080);
        assert_eq!(targets[0].weight, 7);
        assert_eq!(
            targets[0].tags.get("mesh.spiffe_id").map(String::as_str),
            Some(api_id)
        );
        assert_eq!(
            targets[0].tags.get("mesh.hbone").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            targets[0].tags.get("mesh.namespace").map(String::as_str),
            Some("ferrum")
        );
    }

    #[tokio::test]
    async fn honors_service_target_port_for_workload_address() {
        // Service port 80 with targetPort 8080; the pod listens on container
        // port 8080. The discovered target must dial 8080 (the container port),
        // not 80 (the service port).
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![80]);
        svc.ports[0].target_port = Some(ServiceTargetPort::Number(8080));
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(
            targets[0].port, 8080,
            "must dial the container port (targetPort), not the service port"
        );
    }

    #[tokio::test]
    async fn service_without_workload_refs_matches_service_name() {
        let mesh = MeshConfig {
            services: vec![service("api", Vec::new(), vec![8080])],
            workloads: vec![workload(
                "spiffe://cluster.local/ns/ferrum/sa/api",
                "api",
                vec!["10.0.0.1"],
                vec![8080],
            )],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
    }

    #[tokio::test]
    async fn service_workload_refs_do_not_cross_match_same_spiffe_other_services() {
        let shared_id = "spiffe://cluster.local/ns/ferrum/sa/shared";
        let mesh = MeshConfig {
            services: vec![service("api", vec![shared_id], vec![8080])],
            workloads: vec![
                workload(shared_id, "api", vec!["10.0.0.1"], vec![8080]),
                workload(shared_id, "metrics", vec!["10.0.0.2"], vec![8080]),
            ],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
    }

    #[tokio::test]
    async fn service_workload_refs_allow_legacy_mismatched_service_metadata() {
        let shared_id = "spiffe://cluster.local/ns/ferrum/sa/shared";
        let mesh = MeshConfig {
            services: vec![service("api", vec![shared_id], vec![8080])],
            workloads: vec![workload(
                shared_id,
                "legacy-api",
                vec!["10.0.0.1"],
                vec![8080],
            )],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
    }

    #[tokio::test]
    async fn requested_port_filters_service_and_workload_ports() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mut svc = service("api", vec![api_id], vec![8080, 9090]);
        svc.ports[1].name = Some("metrics".to_string());
        let mesh = MeshConfig {
            services: vec![svc],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080, 9090])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            Some(9090),
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 9090);
        assert_eq!(
            targets[0].tags.get("mesh.port_name").map(String::as_str),
            Some("metrics")
        );
    }

    #[tokio::test]
    async fn requested_port_uses_workload_port_metadata_when_service_ports_are_absent() {
        let api_id = "spiffe://cluster.local/ns/ferrum/sa/api";
        let mesh = MeshConfig {
            services: vec![service("api", vec![api_id], Vec::new())],
            workloads: vec![workload(api_id, "api", vec!["10.0.0.1"], vec![8080])],
            ..MeshConfig::default()
        };
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(Some(mesh)),
            "api".to_string(),
            default_namespace(),
            Some(8080),
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].tags.get("mesh.protocol").map(String::as_str),
            Some("http")
        );
        assert_eq!(
            targets[0].tags.get("mesh.port_name").map(String::as_str),
            Some("http")
        );
    }

    #[tokio::test]
    async fn missing_mesh_config_returns_empty_targets() {
        let discoverer = MeshServiceDiscoverer::new(
            epoch_store(None),
            "api".to_string(),
            default_namespace(),
            None,
            1,
        );

        let targets = discoverer.discover().await.expect("discover succeeds");

        assert!(targets.is_empty());
    }
}

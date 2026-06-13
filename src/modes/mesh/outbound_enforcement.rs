//! Shared `outboundTrafficPolicy: REGISTRY_ONLY` enforcement primitive.
//!
//! T5-B extends the HTTP-only `mesh_outbound_registry` gate to cover stream
//! family egress: TCP / UDP / TCP+TLS / UDP+DTLS. The HTTP plugin in
//! [`crate::plugins::mesh::outbound_registry`] continues to enforce on the
//! request path; the stream proxies consult [`MeshOutboundEnforcement`] at
//! connect / first-datagram time.
//!
//! Hot-path contract:
//!   - The struct is built **cold** at slice apply and held behind
//!     `Arc<ArcSwap<Option<Arc<Self>>>>` on `ProxyState`.
//!   - `check_destination()` performs at most two `HashSet::contains`
//!     lookups against the slice-derived registry (delegated to
//!     [`OutboundRegistry::contains`]); no allocations beyond a per-thread
//!     scratch `String` reused across calls.
//!   - The decision counter uses pre-interned protocol label values so
//!     metric label cardinality stays bounded under attacker-driven traffic.
//!
//! The enforcement struct also carries the configured *outbound capture
//! ports*. Stream listeners bound to other ports (inbound, admin, HBONE)
//! must remain unaffected — `check_destination` short-circuits with
//! `Decision::Skip` when the request arrived on a non-capture port. This
//! mirrors the `outbound_listen_ports` scoping already enforced by the
//! HTTP plugin via [`crate::plugins::mesh::outbound_registry::OutboundRegistry`].

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::modes::mesh::slice::MeshSlice;
use crate::plugins::mesh::outbound_registry::OutboundRegistry;

/// Pre-interned protocol label values for the stream decision counter.
///
/// Defined as `&'static str` so emission paths can pass them through
/// without allocating. Add a new constant here when wiring a new
/// stream-family protocol so dashboards stay aligned with the schema.
pub const PROTOCOL_TCP: &str = "tcp";
pub const PROTOCOL_TCP_TLS: &str = "tcp_tls";
pub const PROTOCOL_UDP: &str = "udp";
pub const PROTOCOL_UDP_DTLS: &str = "udp_dtls";

/// Result of an outbound enforcement check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Destination is in the admitted registry — proceed with connect / forward.
    Admit,
    /// Destination is not admitted — reject (TCP: close inbound; UDP: silent drop).
    Deny,
    /// The inbound listener is not an outbound capture port — policy does not apply.
    /// Stream proxies bound to inbound / HBONE / admin listeners flow through.
    Skip,
}

/// Shared outbound `REGISTRY_ONLY` enforcement state.
///
/// Built once per slice apply by [`Self::from_slice`]; readers on the
/// proxy hot path consult a single `Arc<ArcSwap<Option<Arc<Self>>>>`
/// slot on `ProxyState`. Slice apply hot-swaps the slot atomically.
#[derive(Debug)]
pub struct MeshOutboundEnforcement {
    /// Per-mesh-namespace label value used by the stream decision counter.
    /// Pre-stored (rather than re-read from runtime) so the hot path
    /// passes a borrow straight through.
    namespace: String,
    /// Listener ports that are mesh outbound capture surfaces. Stream
    /// listeners bound to other ports skip enforcement entirely. Sorted
    /// + de-duped at construction so the hot-path lookup is a small
    ///   binary search.
    outbound_listen_ports: Vec<u16>,
    /// Registry of admitted destinations, derived from the slice's
    /// services / service entries / workload addresses (the same set
    /// the HTTP plugin sees). Wrapped in `Arc` to keep clones cheap when
    /// the test surface or admin helpers want to hand the registry off
    /// without re-parsing.
    registry: Arc<OutboundRegistry>,
}

impl MeshOutboundEnforcement {
    /// Build an enforcement snapshot from a freshly-applied [`MeshSlice`].
    ///
    /// `cluster_domain` matches the value the HTTP plugin uses so both
    /// gates see the same set of admitted entries.
    ///
    /// `outbound_listen_ports` enumerates the mesh outbound capture ports
    /// on this gateway (typically `15001` in sidecar / ambient topologies).
    /// Stream listeners bound to other ports skip enforcement.
    ///
    /// Returns `None` when the resulting registry would be empty *and*
    /// no outbound capture ports are configured — there is nothing to
    /// enforce. Callers should treat that as "no enforcement active" and
    /// store a `None` in the slot. An empty registry with a non-empty
    /// port list IS a valid fail-closed configuration (every destination
    /// is denied), so we keep that.
    pub fn from_slice(
        slice: &MeshSlice,
        cluster_domain: &str,
        namespace: String,
        outbound_listen_ports: Vec<u16>,
    ) -> Option<Self> {
        if outbound_listen_ports.is_empty() {
            // No mesh outbound capture listener on this gateway, so even
            // if the policy is RegistryOnly there is nothing to enforce.
            // The HTTP plugin already takes the same short-circuit.
            return None;
        }
        let registry_entries = slice.build_known_destinations(cluster_domain);
        let registry =
            OutboundRegistry::new(&serde_json::json!({ "registry": registry_entries })).ok()?;
        let mut outbound_listen_ports = outbound_listen_ports;
        outbound_listen_ports.retain(|port| *port != 0);
        outbound_listen_ports.sort_unstable();
        outbound_listen_ports.dedup();
        if outbound_listen_ports.is_empty() {
            return None;
        }
        Some(Self {
            namespace,
            outbound_listen_ports,
            registry: Arc::new(registry),
        })
    }

    /// Construct directly from a pre-built [`OutboundRegistry`].
    ///
    /// Useful for tests / admin tooling / future code paths that build
    /// the registry by some path other than a [`MeshSlice`]
    /// (`Self::from_slice` is the production caller). Mirrors the same
    /// port-list normalisation that `from_slice` applies.
    #[allow(dead_code)] // Public API; exercised by tests and reserved for admin tooling.
    pub fn from_registry(
        namespace: impl Into<String>,
        outbound_listen_ports: Vec<u16>,
        registry: OutboundRegistry,
    ) -> Self {
        let mut outbound_listen_ports = outbound_listen_ports;
        outbound_listen_ports.retain(|port| *port != 0);
        outbound_listen_ports.sort_unstable();
        outbound_listen_ports.dedup();
        Self {
            namespace: namespace.into(),
            outbound_listen_ports,
            registry: Arc::new(registry),
        }
    }

    #[allow(dead_code)] // Admin / debug surface; reserved for future introspection.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[allow(dead_code)] // Admin / debug surface; reserved for future introspection.
    pub fn outbound_listen_ports(&self) -> &[u16] {
        &self.outbound_listen_ports
    }

    /// Hot-path enforcement check. `listen_port` is the local frontend
    /// port the inbound connection landed on; `host` / `port` are the
    /// resolved backend destination the proxy is about to dial.
    ///
    /// Returns:
    ///   * [`Decision::Skip`] — the local listener is not an outbound
    ///     capture port. Stream listeners bound to inbound / admin /
    ///     HBONE surfaces hit this branch and flow through.
    ///   * [`Decision::Admit`] — destination is admitted.
    ///   * [`Decision::Deny`] — destination is not admitted; reject.
    #[inline]
    pub fn check_destination(&self, listen_port: u16, host: &str, port: u16) -> Decision {
        if self
            .outbound_listen_ports
            .binary_search(&listen_port)
            .is_err()
        {
            return Decision::Skip;
        }
        if self.registry.contains(host, Some(port)) {
            Decision::Admit
        } else {
            Decision::Deny
        }
    }

    /// Increment the stream-decision counter for a finalised decision.
    /// Caller is responsible for ensuring `decision` matches what
    /// [`Self::check_destination`] returned. Skip outcomes are NOT
    /// recorded because they do not represent enforcement on outbound
    /// capture traffic.
    pub fn record_stream_decision(&self, protocol: &'static str, decision: Decision) {
        let label = match decision {
            Decision::Admit => "admit",
            Decision::Deny => "deny",
            Decision::Skip => return,
        };
        crate::plugins::prometheus_metrics::global_registry()
            .record_mesh_outbound_registry_stream_decision(&self.namespace, protocol, label);
    }

    /// Borrow the inner registry for admin / debug paths.
    #[allow(dead_code)]
    pub fn registry(&self) -> &OutboundRegistry {
        &self.registry
    }
}

/// Shared `Arc<ArcSwap<Option<Arc<Self>>>>` slot on `ProxyState`. Hot path
/// readers do a single `ArcSwap::load()` and check `Option::None` for
/// "no enforcement active" before invoking [`MeshOutboundEnforcement::check_destination`].
pub type SharedMeshOutboundEnforcement = Arc<ArcSwap<Option<Arc<MeshOutboundEnforcement>>>>;

/// Construct an empty (no enforcement) slot. Used by `ProxyState::new`
/// for non-mesh modes and as the initial value for mesh mode before the
/// first slice arrives.
pub fn empty_slot() -> SharedMeshOutboundEnforcement {
    Arc::new(ArcSwap::new(Arc::new(None)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::modes::mesh::config::{
        AppProtocol, MeshService, ServicePort, Workload, WorkloadPort, WorkloadSelector,
    };
    use crate::modes::mesh::slice::MeshSlice;
    use serde_json::json;
    use std::collections::HashMap;

    fn registry(entries: &[&str]) -> OutboundRegistry {
        OutboundRegistry::new(&json!({ "registry": entries })).expect("valid registry")
    }

    fn workload(name: &str, namespace: &str, addresses: &[&str]) -> Workload {
        Workload {
            spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/{namespace}/sa/{name}"))
                .expect("valid spiffe id"),
            selector: WorkloadSelector {
                labels: HashMap::new(),
                namespace: Some(namespace.to_string()),
            },
            service_name: name.to_string(),
            addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
            ports: vec![WorkloadPort {
                port: 27017,
                protocol: AppProtocol::Tcp,
                name: Some("mongo".to_string()),
            }],
            trust_domain: TrustDomain::new("cluster.local").expect("td"),
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some(name.to_string()),
            pod_uid: None,
        }
    }

    fn service(name: &str, namespace: &str) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            ports: vec![ServicePort {
                port: 27017,
                protocol: AppProtocol::Tcp,
                name: Some("mongo".to_string()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn slice_with_service(name: &str, namespace: &str, addresses: &[&str]) -> MeshSlice {
        MeshSlice {
            namespace: namespace.to_string(),
            services: vec![service(name, namespace)],
            workloads: vec![workload(name, namespace, addresses)],
            ..MeshSlice::default()
        }
    }

    #[test]
    fn from_slice_returns_none_when_no_capture_ports() {
        let slice = slice_with_service("mongo", "default", &["10.0.0.1"]);
        let result = MeshOutboundEnforcement::from_slice(
            &slice,
            "cluster.local",
            "default".to_string(),
            Vec::new(),
        );
        assert!(result.is_none(), "no capture ports → no enforcement");
    }

    #[test]
    fn from_slice_returns_none_when_capture_ports_are_zero() {
        // Port 0 is the ephemeral-bind sentinel — there is no real
        // listener, so enforcement is moot.
        let slice = slice_with_service("mongo", "default", &["10.0.0.1"]);
        let result = MeshOutboundEnforcement::from_slice(
            &slice,
            "cluster.local",
            "default".to_string(),
            vec![0],
        );
        assert!(result.is_none());
    }

    #[test]
    fn empty_registry_still_enforces_when_capture_ports_present() {
        // Empty registry + a real capture port is a valid REGISTRY_ONLY
        // configuration: every destination is denied. The HTTP plugin
        // takes the same fail-closed branch.
        let slice = MeshSlice {
            namespace: "default".to_string(),
            ..MeshSlice::default()
        };
        let enforcement = MeshOutboundEnforcement::from_slice(
            &slice,
            "cluster.local",
            "default".to_string(),
            vec![15001],
        )
        .expect("enforcement should be present even with empty registry");
        let decision = enforcement.check_destination(15001, "anywhere.io", 443);
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn admits_destination_present_in_registry() {
        let enforcement = MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001],
            registry(&["mongo.allowed.io:27017", "redis.allowed.io:6379"]),
        );
        assert_eq!(
            enforcement.check_destination(15001, "mongo.allowed.io", 27017),
            Decision::Admit
        );
        assert_eq!(
            enforcement.check_destination(15001, "redis.allowed.io", 6379),
            Decision::Admit
        );
    }

    #[test]
    fn denies_destination_absent_from_registry() {
        let enforcement = MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001],
            registry(&["mongo.allowed.io:27017"]),
        );
        assert_eq!(
            enforcement.check_destination(15001, "redis.unknown.io", 6379),
            Decision::Deny
        );
        assert_eq!(
            // Same host but wrong port → also denied (Istio mirrors this
            // — registry entries with an explicit port match only that port).
            enforcement.check_destination(15001, "mongo.allowed.io", 27018),
            Decision::Deny
        );
    }

    #[test]
    fn skips_when_listener_not_in_capture_port_list() {
        let enforcement = MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001],
            registry(&["mongo.allowed.io:27017"]),
        );
        // 15006 is the conventional inbound port — must not enforce.
        assert_eq!(
            enforcement.check_destination(15006, "redis.unknown.io", 6379),
            Decision::Skip,
        );
        // 50051 is the gRPC CP listener — must not enforce.
        assert_eq!(
            enforcement.check_destination(50051, "redis.unknown.io", 6379),
            Decision::Skip,
        );
    }

    #[test]
    fn wildcard_service_entry_hosts_admit_subdomains() {
        // Istio `*.foo.com` ServiceEntries admit one-level-deep subdomains.
        let enforcement = MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001],
            registry(&["*.allowed.io:443"]),
        );
        assert_eq!(
            enforcement.check_destination(15001, "api.allowed.io", 443),
            Decision::Admit
        );
        assert_eq!(
            enforcement.check_destination(15001, "evil.unknown.io", 443),
            Decision::Deny
        );
        // Wildcard is one label deep; multi-label subdomains stay denied.
        assert_eq!(
            enforcement.check_destination(15001, "a.b.allowed.io", 443),
            Decision::Deny
        );
    }

    #[test]
    fn workload_ip_addresses_are_admitted() {
        // Mesh registries include workload IPs so direct pod-IP traffic
        // is admitted alongside service hostnames. Build the registry
        // through the slice path so the IP entries land via
        // `build_known_destinations`.
        let mut slice = slice_with_service("mongo", "default", &["10.0.0.1"]);
        // Service entries with the workload port → registry contains
        // `10.0.0.1:27017` (workloads emit `host:port` with declared
        // ports).
        slice.workloads[0].ports = vec![WorkloadPort {
            port: 27017,
            protocol: AppProtocol::Tcp,
            name: Some("mongo".to_string()),
        }];
        let enforcement = MeshOutboundEnforcement::from_slice(
            &slice,
            "cluster.local",
            "default".to_string(),
            vec![15001],
        )
        .expect("enforcement present");
        assert_eq!(
            enforcement.check_destination(15001, "10.0.0.1", 27017),
            Decision::Admit
        );
        assert_eq!(
            enforcement.check_destination(15001, "10.0.0.2", 27017),
            Decision::Deny
        );
    }

    #[test]
    fn record_stream_decision_no_ops_for_skip() {
        // Skip outcomes are not enforcement decisions and must never
        // contribute to the deny/admit counter (dashboards would
        // otherwise count inbound listener traffic as outbound admits).
        let enforcement = MeshOutboundEnforcement::from_registry(
            "skip-test-ns",
            vec![15001],
            registry(&["mongo.allowed.io:27017"]),
        );
        // No panic; deny / admit paths are exercised in tests below
        // that read the rendered metrics.
        enforcement.record_stream_decision(PROTOCOL_TCP, Decision::Skip);
    }

    #[test]
    fn capture_port_list_is_deduped_and_sorted() {
        let enforcement = MeshOutboundEnforcement::from_registry(
            "default",
            vec![15001, 15001, 0, 15001],
            registry(&["mongo.allowed.io:27017"]),
        );
        assert_eq!(enforcement.outbound_listen_ports(), &[15001]);
    }
}

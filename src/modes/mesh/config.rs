//! Internal mesh data model (Layer 2 of the mesh expansion).
//!
//! These types deliberately mirror Istio CRD vocabulary so the Phase B/C
//! translation layer can be near-1:1. Every type carries `#[serde(default)]`
//! on optional collections and `skip_serializing_if` on `Option`/`Vec` so
//! that a non-mesh `GatewayConfig` round-trips byte-identical (no extra
//! keys appear in the serialised JSON / YAML).
//!
//! All types are namespace-scoped (`namespace: String`) — same convention
//! as `Proxy`, `Consumer`, `Upstream` in [`crate::config::types`]. The
//! mesh subsystem will share the same `FERRUM_NAMESPACE` mechanism so a
//! single gateway instance only loads its own namespace's mesh resources.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use crate::identity::spiffe::{SpiffeId, TrustDomain};
use crate::identity::{JwtAuthority as IdentityJwtAuthority, TrustBundle as IdentityTrustBundle};

/// Application-layer protocol classification for mesh ports.
///
/// Mirrors Istio's `appProtocol` field on `Service` ports + endpoints. Phase
/// A serialises lowercase ("http", "http2", "grpc", "tcp", "tls", "udp",
/// "mongo", "redis", "mysql", "postgres", "unknown").
///
/// `Udp` is a distinct L4 transport: it is NOT HTTP-family (no HTTP route
/// materialization) and NOT part of the raw-TCP stream lane (REDIRECT /
/// `SO_ORIGINAL_DST` capture does not apply to UDP). It partitions out of both
/// the HTTP-family and TCP-stream port predicates so a Service `protocol: UDP`
/// port is never mis-classified as HTTP (its prior fate as `Unknown`). UDP
/// capture/egress arrives in a later F3 §3.3 stage; this variant is inert today.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppProtocol {
    Http,
    Http2,
    Grpc,
    Tcp,
    Tls,
    Udp,
    Mongo,
    Redis,
    Mysql,
    Postgres,
    #[default]
    Unknown,
}

// ── Workload ──────────────────────────────────────────────────────────────

/// A single workload registered with the mesh.
///
/// `Workload` is the unit of identity — every SVID is issued to one workload.
/// The `selector` describes how the workload is matched at attestation time
/// (K8s labels, VM tags, or static), the `service_name` is the logical
/// service it participates in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workload {
    pub spiffe_id: SpiffeId,
    pub selector: WorkloadSelector,
    pub service_name: String,
    /// Namespace of the [`MeshService`] this workload attaches to when it
    /// differs from [`Self::namespace`].
    ///
    /// Same-namespace attachments leave this `None` and resolve through
    /// [`Self::attached_service_namespace`]. Cross-namespace Istio
    /// `WorkloadEntry.service` hosts set this to the authoritative target
    /// Service namespace after ReferenceGrant + Service existence checks so
    /// identity (`namespace` / SPIFFE) stays on the WorkloadEntry while
    /// attachment matching / MeshService linking use the Service namespace.
    /// Carried on native / xDS workloads carriers for CP↔DP parity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_namespace: Option<String>,
    /// Workload IPs or DNS names. Istio `WorkloadEntry.address` maps here;
    /// K8s pod IPs land here once the reconciler wires pod watching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<WorkloadPort>,
    pub trust_domain: TrustDomain,
    pub namespace: String,
    /// Istio network label for multi-network routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Cluster name for CP-to-CP exchange and VM workloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Istio `WorkloadEntry.weight` — load-balancing weight for traffic
    /// splitting between multiple workloads of the same service. Absent
    /// here means "use the default" — equivalent to today's behavior. A
    /// value of `0` is accepted (Istio "no traffic" / drain). Capped at
    /// `MAX_TARGET_WEIGHT` (65_535) at translation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    /// Istio `WorkloadEntry.locality` — slash-delimited
    /// `region/zone/subzone` string consumed by locality-aware routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// Istio `WorkloadEntry.serviceAccount` — kept separately from
    /// `spiffe_id` so introspection and audit don't need to parse the
    /// SPIFFE path. None when the source omits it; the SPIFFE translation
    /// still falls back to `"default"` for SVID issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    /// Kubernetes pod UID (`metadata.uid`) for per-pod K8s workloads; `None`
    /// for WorkloadEntry/VM workloads that have no pod identity. Node-waypoint
    /// per-pod policy scoping keys a pod's scope by this exact UID so pods that
    /// share a service account (and therefore a SPIFFE ID) but carry different
    /// labels are scoped independently instead of collapsed to one merged scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    /// Destination NodeWaypoint endpoint for the node hosting this workload.
    /// NodeWaypoint secured transport dials this endpoint over HBONE and pins
    /// `spiffe_id`, while the CONNECT authority remains the selected workload
    /// address/app port. Missing metadata must fail closed once the secured
    /// NodeWaypoint transport is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_waypoint: Option<NodeWaypointEndpoint>,
    /// Runtime-only RESERVED remote-cluster provenance marker: `true` iff this
    /// workload was ingested from a REMOTE cluster's discovery slice. Set by
    /// [`crate::modes::mesh::multicluster::tag_remote_workloads`] at the DP-side
    /// remote-poll ingestion point (which KNOWS the source is the remote slice),
    /// NOT inferred from `cluster` name equality — an Istio WorkloadEntry
    /// translation can stamp a `cluster` that doesn't equal the configured
    /// `RemoteCluster.name`, which would leave a genuinely-remote endpoint
    /// classified LOCAL. The service discoverer copies this provenance into the
    /// un-spoofable `mesh.remote=true` target tag that strict local-first locality
    /// LB keys on. `#[serde(skip)]` (NOT `serde(default)` with skip-if): it is a
    /// DP-local ingestion artifact and must NEVER ride a wire/file payload — a
    /// remote CP or operator file could otherwise forge it; the marker is only
    /// ever set locally, after `fetch()`, by the remote-poll loop.
    #[serde(skip)]
    pub remote_provenance: bool,
}

impl Workload {
    /// Namespace of the MeshService this workload participates in.
    ///
    /// Cross-namespace WorkloadEntry attachments stamp
    /// [`Self::service_namespace`]; every other path (Pods, same-namespace
    /// WorkloadEntry, native/xDS authors that omit the field) falls back to
    /// [`Self::namespace`].
    pub fn attached_service_namespace(&self) -> &str {
        self.service_namespace
            .as_deref()
            .unwrap_or(self.namespace.as_str())
    }
}

/// Destination NodeWaypoint transport endpoint for a workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeWaypointEndpoint {
    /// IP or DNS name of the destination NodeWaypoint instance that owns the
    /// selected workload's node. This is the outer TCP/TLS dial target.
    pub address: String,
    /// HBONE listener port on `address`. Defaults to Istio's standard 15008
    /// when omitted so older explicit endpoints can stay compact.
    #[serde(
        default = "default_node_waypoint_hbone_port",
        skip_serializing_if = "is_default_node_waypoint_hbone_port"
    )]
    pub hbone_port: u16,
    /// Exact SPIFFE ID expected in the destination NodeWaypoint's server SVID.
    pub spiffe_id: SpiffeId,
    /// Kubernetes node name that owns this NodeWaypoint endpoint, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Kubernetes node UID that owns this NodeWaypoint endpoint, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_uid: Option<String>,
    /// Network/locality identity for multi-network selection, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Cluster identity for multi-cluster routing, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

pub fn default_node_waypoint_hbone_port() -> u16 {
    crate::modes::mesh::hbone::ISTIO_HBONE_PORT
}

fn is_default_node_waypoint_hbone_port(port: &u16) -> bool {
    *port == default_node_waypoint_hbone_port()
}

/// A port advertised by a workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadPort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Selector for workload matching. Empty `labels` matches any workload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSelector {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl WorkloadSelector {
    /// Istio policy scopes only treat a selector with at least one label as
    /// workload-specific. An absent, null, or explicitly empty selector is a
    /// namespace/mesh default for PeerAuthentication precedence.
    #[inline]
    pub fn has_labels(&self) -> bool {
        !self.labels.is_empty()
    }
}

// ── MeshService ───────────────────────────────────────────────────────────

/// A logical service. Workloads are referenced by SPIFFE ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshService {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<WorkloadRef>,
    /// Per-port overrides for service-level protocol classification.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub protocol_overrides: HashMap<u16, AppProtocol>,
    /// The service's virtual IPs (Kubernetes `spec.clusterIPs`, including
    /// dual-stack secondaries; headless services carry none). Raw-TCP egress
    /// maps a captured connection's `SO_ORIGINAL_DST` `(ip, port)` to a
    /// service strictly through these — there is no Host header on a raw
    /// stream, and a port number alone is never enough to pick a service
    /// (two services may share one). Populated by the K8s translator from
    /// the Service spec; file-source operators set it directly. Optional:
    /// HTTP-family routing never consults it, and a TCP-family port on a
    /// VIP-less service simply cannot be egress-routed (warned at
    /// materialization, the captured connection fails as before).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cluster_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServicePort {
    pub port: u16,
    #[serde(default)]
    pub protocol: AppProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Kubernetes `Service.spec.ports[].targetPort` — the container port the
    /// service forwards to, authoritative over the port name/number heuristic
    /// when resolving the inbound backend. `IntOrString`: a numeric container
    /// port or a named container port. Absent defaults to `port` (K8s rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<ServiceTargetPort>,
}

/// Kubernetes `targetPort` is an `IntOrString`: either an explicit container
/// port number, or the name of a container port resolved against the workload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceTargetPort {
    Number(u16),
    Name(String),
}

/// Resolve a Service port's `targetPort` to a backend (container) port when it
/// yields a usable one: a non-zero numeric targetPort, or a named targetPort
/// that matches one of `workload_ports`. Returns `None` when no targetPort is
/// declared, a numeric one is zero, or a named one doesn't resolve — leaving the
/// caller to apply its own fallback (each dialing path differs: skip, the
/// service port, the workload's first port, ...). Shared so every path that
/// dials a workload/endpoint address honors `targetPort` consistently.
pub(crate) fn resolve_target_port(
    target_port: Option<&ServiceTargetPort>,
    workload_ports: &[WorkloadPort],
) -> Option<u16> {
    match target_port {
        Some(ServiceTargetPort::Number(n)) if *n != 0 => Some(*n),
        Some(ServiceTargetPort::Name(name)) => workload_ports
            .iter()
            .find(|wp| wp.name.as_deref() == Some(name.as_str()))
            .map(|wp| wp.port),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadRef {
    pub spiffe_id: SpiffeId,
}

// ── MeshPolicy ────────────────────────────────────────────────────────────

/// Identity-based authorization policy. Mirrors Istio AuthorizationPolicy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshPolicy {
    pub name: String,
    pub namespace: String,
    pub scope: PolicyScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<MeshRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyScope {
    WorkloadSelector {
        selector: WorkloadSelector,
    },
    Namespace {
        namespace: String,
    },
    /// Istio `AuthorizationPolicy.spec.targetRefs` attachment scope.
    ///
    /// A policy matches when **any** attachment applies (OR). Attachments are
    /// resolved at translation time against the resource graph; unsupported
    /// group/kind combinations and selector+targetRefs exclusivity fail closed
    /// before a `MeshPolicy` is emitted. Do not broaden these into namespace
    /// or mesh-wide scope when a target is missing — omit/reject instead.
    ///
    /// **Slice retention is OR over the whole list, so retention alone proves
    /// nothing about which attachment matched.** Every runtime consumer must
    /// re-check the exact attachment against its own authoritative evidence
    /// ([`WaypointAttachment::matches`] for Gateway/GatewayClass,
    /// [`policy_target_attachment_applies_to_service`] for Service). A policy
    /// listing `{Service reviews, Gateway other-waypoint}` is legitimately
    /// retained at `reviews`' waypoint, and the unmatched Gateway arm must
    /// still not apply to any other destination there.
    TargetRefs {
        attachments: Vec<PolicyTargetAttachment>,
    },
    #[default]
    MeshWide,
}

/// Upper bound on `AuthorizationPolicy` / `MeshPolicy` `targetRefs` attachments
/// accepted at the native/file/xDS config boundary (matches the K8s translator).
pub const MAX_POLICY_TARGET_REFS: usize = 16;

/// DNS-1123 subdomain / API-group length bound for TargetRef `group` strings
/// at the native/file and K8s translation boundaries.
pub const MAX_POLICY_TARGET_REF_GROUP_LEN: usize = 253;

/// Kubernetes kind-name length bound for TargetRef `kind` strings.
pub const MAX_POLICY_TARGET_REF_KIND_LEN: usize = 63;

/// TargetRef resource name length bound (DNS-1123 subdomain; same ceiling as
/// the WaypointGatewayClass ECDS carrier).
pub const MAX_POLICY_TARGET_REF_NAME_LEN: usize = 253;

/// TargetRef namespace length bound (reuses the shared Ferrum namespace ceiling).
pub const MAX_POLICY_TARGET_REF_NAMESPACE_LEN: usize = crate::config::types::MAX_NAMESPACE_LENGTH;

/// One resolved `AuthorizationPolicy` / policy `targetRefs[]` attachment.
///
/// Captures the concrete resource the policy attaches to. Attachments carry
/// resource IDENTITY only — never selector labels: membership is always exact
/// namespace/name (or exact waypoint name / gateway class), so two Services
/// that happen to share a pod selector can never inherit each other's policies.
///
/// Istio's supported attachment set (`Gateway`, `GatewayClass`, `Service`,
/// `ServiceEntry`) is deliberately NOT fully modelled here: `ServiceEntry`
/// attachments are refused at translation because Ferrum has no ServiceEntry ↔
/// waypoint association model, and an accepted-but-inert security policy is
/// worse than a rejected one. See `docs/mesh.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyTargetAttachment {
    /// `group: ""` / `core`, `kind: Service` — waypoint destination attachment.
    /// Same namespace as the owning policy (Istio contract).
    Service { namespace: String, name: String },
    /// `group: gateway.networking.k8s.io`, `kind: Gateway` — waypoint Gateway.
    /// Same namespace as the owning policy (Istio contract).
    Gateway { namespace: String, name: String },
    /// `group: gateway.networking.k8s.io`, `kind: GatewayClass` (cluster-scoped;
    /// the owning policy must live in the Istio root namespace).
    GatewayClass { name: String },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<PrincipalMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<RequestMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<ConditionMatch>,
    /// Glob patterns over JWT-derived request principals (`iss/sub`).
    ///
    /// Mirrors Istio AuthorizationPolicy `from[].source.requestPrincipals`.
    /// A request matches when its `request_principal` (set by `jwks_auth`
    /// from the validated JWT's `iss/sub`) matches any pattern in this list.
    /// An empty list means "any request principal" (no filter).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_principals: Vec<String>,
    /// Istio `from[].source.notRequestPrincipals` — conjunctive negative
    /// match over JWT-derived request principals. When any pattern matches
    /// the request's `request_principal`, the rule fails. When no request
    /// principal is present, the negative match succeeds; this is Istio's
    /// canonical way to match anonymous requests with
    /// `notRequestPrincipals: ["*"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_request_principals: Vec<String>,
    /// Conjunctive source-negative / IP-block matchers for this rule's
    /// Istio `from[].source`. ANDed with the ORed positive `from` matches.
    /// Defaults empty so the common case (positive principals only) and old
    /// slices round-trip unchanged.
    #[serde(default, skip_serializing_if = "source_negation_is_empty")]
    pub source_negation: SourceNegationMatch,
    /// Synthetic marker for rules that should affect policy accounting but
    /// never match traffic, e.g. Istio ALLOW-without-rules allow-nothing.
    #[serde(default, skip_serializing_if = "is_false")]
    pub never_matches: bool,
    #[serde(default)]
    pub action: PolicyAction,
}

pub(crate) fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Allow,
    Deny,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PrincipalMatch {
    /// Glob pattern over Istio source principals (`prod/ns/foo/sa/*`).
    /// Full `spiffe://...` patterns are also accepted for direct configs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id_pattern: Option<String>,
    /// Glob pattern over workload namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_pattern: Option<String>,
    /// Restrict matches to a specific trust domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
    /// Glob pattern over source trust domains, for Istio `trustDomains`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain_pattern: Option<String>,
}

/// Conjunctive source-negative / IP-block matchers for one Istio
/// AuthorizationPolicy `from[].source`.
///
/// Istio ANDs every field inside a single `source` together, and a request
/// matches the rule's `from` when **any one** source matches. The positive
/// identity matchers (`principals` / `namespaces`) translate into the ORed
/// [`PrincipalMatch`] list on [`MeshRule::from`]; the negative and IP-block
/// matchers live here on [`MeshRule`] because they must AND with — not OR
/// against — the positive set. Placing them in the ORed `from` vec would let
/// traffic through whenever a single negative-only entry "matched", which is
/// the opposite of Istio's deny-listing intent (fail-open).
///
/// Pre-parsed CIDR block for allocation-free hot-path IP matching.
///
/// Constructed from a CIDR string like `"10.0.0.0/8"` or a bare IP like
/// `"192.168.1.1"` (treated as a host route). IPv4-mapped IPv6 addresses are
/// canonicalized to IPv4 at parse time so `::ffff:10.0.0.0/104` becomes
/// `10.0.0.0/8`. Serializes back to the canonical `network/prefix` form.
///
/// Fields are private so the invariant `prefix <= 32` (IPv4) / `prefix <= 128`
/// (IPv6) cannot be bypassed by a direct struct literal. Use [`ParsedCidr::parse`]
/// to construct values; [`ParsedCidr::contains`] relies on the invariant being
/// upheld to avoid arithmetic overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCidr {
    network: IpAddr,
    prefix: u8,
}

impl ParsedCidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("IP block must not be empty".to_string());
        }
        let (network_str, prefix) = match trimmed.split_once('/') {
            Some((net, plen)) => {
                let prefix = plen
                    .parse::<u8>()
                    .map_err(|_| format!("invalid prefix length in CIDR '{s}'"))?;
                (net, Some(prefix))
            }
            None => (trimmed, None),
        };
        let ip: IpAddr = network_str
            .parse()
            .map_err(|_| format!("invalid IP in CIDR '{s}'"))?;
        let (network, prefix) =
            Self::canonicalize(ip, prefix).map_err(|reason| format!("{reason} in CIDR '{s}'"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix length {prefix} out of range in CIDR '{s}'"));
        }
        Ok(Self { network, prefix })
    }

    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = Self::canonicalize_ip(ip);
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }

    fn canonicalize(ip: IpAddr, prefix: Option<u8>) -> Result<(IpAddr, u8), String> {
        match ip {
            IpAddr::V4(v4) => Ok((IpAddr::V4(v4), prefix.unwrap_or(32))),
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let v4_prefix = match prefix {
                        Some(p) if p >= 96 => p - 96,
                        Some(p) => {
                            return Err(format!(
                                "IPv4-mapped IPv6 CIDR prefix {p} must be at least 96"
                            ));
                        }
                        None => 32,
                    };
                    Ok((IpAddr::V4(v4), v4_prefix))
                } else {
                    Ok((IpAddr::V6(v6), prefix.unwrap_or(128)))
                }
            }
        }
    }

    #[inline]
    fn canonicalize_ip(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other => other,
        }
    }
}

impl std::str::FromStr for ParsedCidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ParsedCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl Serialize for ParsedCidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ParsedCidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// IP fields are **fail-closed** when the corresponding request attribute is
/// absent: a non-empty list with no value to test fails the match rather than
/// admitting traffic the operator meant to gate. Negative identity and
/// namespace fields preserve Istio semantics for anonymous traffic, so
/// `notPrincipals: ["*"]` can be used in a DENY policy to require mTLS.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SourceNegationMatch {
    /// Istio `notPrincipals` — globs over the source principal
    /// (`<trust-domain>/ns/<namespace>/sa/<service-account>`). Full
    /// `spiffe://...` patterns are also accepted for direct configs. When any
    /// matches, the source fails. Non-empty + no peer ⇒ negative match
    /// succeeds, allowing `notPrincipals: ["*"]` to match anonymous traffic.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_spiffe_id_patterns: Vec<String>,
    /// Istio `notNamespaces` — globs over the source workload namespace
    /// (extracted from the SPIFFE ID). When any matches, the source fails.
    /// Non-empty + no namespace ⇒ negative match succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_namespace_patterns: Vec<String>,
    /// Istio `notTrustDomains` — globs over the source trust domain. When any
    /// matches, the source fails. Non-empty + no peer ⇒ negative match
    /// succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_trust_domain_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_blocks: Vec<ParsedCidr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_ip_blocks: Vec<ParsedCidr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_ip_blocks: Vec<ParsedCidr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_remote_ip_blocks: Vec<ParsedCidr>,
}

impl SourceNegationMatch {
    /// True when this matcher carries no constraints (the common case for a
    /// source that only used positive `principals` / `namespaces`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.not_spiffe_id_patterns.is_empty()
            && self.not_namespace_patterns.is_empty()
            && self.not_trust_domain_patterns.is_empty()
            && self.ip_blocks.is_empty()
            && self.not_ip_blocks.is_empty()
            && self.remote_ip_blocks.is_empty()
            && self.not_remote_ip_blocks.is_empty()
    }
}

fn source_negation_is_empty(value: &SourceNegationMatch) -> bool {
    value.is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RequestMatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Glob path patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Glob host patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Header name → glob value pattern.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    /// Glob port patterns, used for Istio string-match ports such as "*".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_patterns: Vec<String>,
    /// Istio `notMethods` — conjunctive negative-match: when any value
    /// matches the request method, the rule fails. Empty means "no
    /// negative filter".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_methods: Vec<String>,
    /// Istio `notPaths` — conjunctive negative-match for the request path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_paths: Vec<String>,
    /// Istio `notHosts` — conjunctive negative-match for the request host.
    /// Normalised at config-load time identical to `hosts` so the hot path
    /// stays allocation-free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_hosts: Vec<String>,
    /// Istio `notPorts` — conjunctive negative-match for the request port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_ports: Vec<u16>,
    /// Glob port patterns for Istio string-match `notPorts` such as `"8*"`.
    /// Compiled/normalized at config load; conjunctive with `not_ports` and
    /// positive fields in the same rule (never split into a separate deny).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_port_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ConditionMatch {
    pub key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_values: Vec<String>,
}

// Istio `AuthorizationPolicy.when` keys. Every key documented at
// https://istio.io/latest/docs/reference/config/security/conditions/ is
// represented here; keys whose authoritative input Ferrum cannot observe are
// still admitted but classified so the evaluator can apply explicit
// fail-closed semantics instead of silently dropping the whole policy.
const CONDITION_SOURCE_PRINCIPAL: &str = "source.principal";
const CONDITION_SOURCE_NAMESPACE: &str = "source.namespace";
const CONDITION_SOURCE_SERVICE_ACCOUNT: &str = "source.serviceAccount";
const CONDITION_SOURCE_TRUST_DOMAIN: &str = "source.trustDomain";
const CONDITION_SOURCE_IP: &str = "source.ip";
const CONDITION_REMOTE_IP: &str = "remote.ip";
const CONDITION_REQUEST_AUTH_PRINCIPAL: &str = "request.auth.principal";
const CONDITION_REQUEST_AUTH_PRESENTER: &str = "request.auth.presenter";
const CONDITION_REQUEST_AUTH_AUDIENCES: &str = "request.auth.audiences";
const CONDITION_DESTINATION_IP: &str = "destination.ip";
const CONDITION_DESTINATION_PORT: &str = "destination.port";
const CONDITION_CONNECTION_SNI: &str = "connection.sni";
const CONDITION_REQUEST_HEADERS_PREFIX: &str = "request.headers[";
const CONDITION_REQUEST_AUTH_CLAIMS_PREFIX: &str = "request.auth.claims[";
/// Istio's experimental Envoy-filter attribute namespace
/// (`experimental.envoy.filters.<filter.name>[<metadata key>]`). Istio compiles
/// these into Envoy dynamic-metadata matchers; Ferrum has no Envoy filter
/// chain, so the attribute is never observable on any path.
const CONDITION_EXPERIMENTAL_ENVOY_FILTER_PREFIX: &str = "experimental.envoy.filters.";

/// Upper bound on an operator-supplied `when[].key`. Istio's own keys are far
/// shorter; the cap keeps a hostile CRD from parking unbounded strings in the
/// per-proxy condition-key index that the request path walks.
pub const MAX_MESH_CONDITION_KEY_LEN: usize = 256;
/// Upper bound on one `when[].values` / `when[].notValues` entry.
pub const MAX_MESH_CONDITION_VALUE_LEN: usize = 512;
/// Upper bound on the number of entries in one `when[].values` or
/// `when[].notValues` list. Each entry is walked linearly per request, so the
/// cap bounds request-path work as well as memory.
pub const MAX_MESH_CONDITION_VALUES: usize = 256;
/// Upper bound on `when[]` entries in a single rule. Conditions are conjunctive
/// and walked in order on every matching request.
pub const MAX_MESH_RULE_CONDITIONS: usize = 64;
/// Istio's own `source.serviceAccount` list bound
/// (`pkg/config/security/security.go::CheckServiceAccount`). Stricter than the
/// common [`MAX_MESH_CONDITION_VALUES`], so it applies on top of it for that one
/// key rather than replacing the shared cap for everything else.
pub const MAX_MESH_SERVICE_ACCOUNT_CONDITION_VALUES: usize = 16;
/// Istio's own `source.serviceAccount` per-value byte bound, from the same
/// `CheckServiceAccount` check. Stricter than [`MAX_MESH_CONDITION_VALUE_LEN`].
pub const MAX_MESH_SERVICE_ACCOUNT_CONDITION_VALUE_LEN: usize = 320;

/// Typed classification of an Istio `AuthorizationPolicy` `when[].key`.
///
/// The evaluator needs three separable facts about a key that a bare string
/// cannot carry: how its values are compared (CIDR containment vs Istio string
/// match), which protocol contexts can source it, and whether Ferrum can source
/// it at all. Keeping the classification typed is what lets a documented key
/// Ferrum cannot observe be *admitted* (so the surrounding policy still
/// installs and still governs traffic) while its condition is evaluated
/// fail-closed, rather than the whole resource being rejected — which drops the
/// policy entirely and is fail-OPEN for a DENY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeshConditionKeyKind {
    /// `source.principal` — peer SPIFFE identity in Istio's scheme-less form.
    SourcePrincipal,
    /// `source.namespace` — namespace segment of the peer SPIFFE identity.
    /// Istio's `srcNamespaceGenerator` rewrites every `*` to `.*`, so this key
    /// takes an arbitrary-position wildcard, NOT the generic string matcher.
    SourceNamespace,
    /// `source.serviceAccount` — `<namespace>/<service-account>` derived from
    /// the peer SPIFFE identity. Matched EXACTLY, with a bare
    /// `<service-account>` resolved against the owning policy's namespace.
    SourceServiceAccount,
    /// `source.trustDomain` — trust domain of the peer SPIFFE identity. Keeps
    /// the presence / prefix / suffix matcher, under Istio's restricted
    /// `CheckTrustDomainValues` grammar enforced at admission.
    SourceTrustDomain,
    /// `source.ip` — immediate downstream socket peer. CIDR-valued.
    SourceIp,
    /// `remote.ip` — forwarded/original client IP. CIDR-valued.
    RemoteIp,
    /// `destination.ip` — authoritative connection destination. CIDR-valued.
    DestinationIp,
    /// `destination.port` — numeric-valued (0..=65535).
    DestinationPort,
    /// `connection.sni` — frontend TLS/QUIC/DTLS SNI.
    ConnectionSni,
    /// `request.auth.principal` — validated-JWT `iss/sub`. HTTP-family only.
    RequestAuthPrincipal,
    /// `request.auth.presenter` — validated-JWT `azp`. HTTP-family only.
    RequestAuthPresenter,
    /// `request.auth.audiences` — validated-JWT `aud`. HTTP-family only.
    RequestAuthAudiences,
    /// `request.auth.claims[<name>]` (and Istio's nested
    /// `request.auth.claims[<name>][<nested>]`). HTTP-family only.
    RequestAuthClaim,
    /// `request.headers[<name>]`. HTTP-family only.
    RequestHeader,
    /// `experimental.envoy.filters.<filter>[<key>]`. Documented by Istio but
    /// backed by Envoy dynamic metadata Ferrum has no equivalent for, so it is
    /// never sourceable on any protocol.
    ExperimentalEnvoyFilter,
}

impl MeshConditionKeyKind {
    /// `true` when `values` / `notValues` for this key are CIDR blocks rather
    /// than Istio string-match patterns.
    #[inline]
    pub const fn is_ip_valued(self) -> bool {
        matches!(self, Self::SourceIp | Self::RemoteIp | Self::DestinationIp)
    }
}

/// Classify an Istio `when[].key`, or `None` when the key is not a documented
/// Istio condition key (or is structurally malformed, e.g. an empty bracketed
/// name). `None` is always a hard config/translation rejection.
pub fn classify_mesh_condition_key(key: &str) -> Option<MeshConditionKeyKind> {
    match key {
        CONDITION_SOURCE_PRINCIPAL => Some(MeshConditionKeyKind::SourcePrincipal),
        CONDITION_SOURCE_NAMESPACE => Some(MeshConditionKeyKind::SourceNamespace),
        CONDITION_SOURCE_SERVICE_ACCOUNT => Some(MeshConditionKeyKind::SourceServiceAccount),
        CONDITION_SOURCE_TRUST_DOMAIN => Some(MeshConditionKeyKind::SourceTrustDomain),
        CONDITION_SOURCE_IP => Some(MeshConditionKeyKind::SourceIp),
        CONDITION_REMOTE_IP => Some(MeshConditionKeyKind::RemoteIp),
        CONDITION_DESTINATION_IP => Some(MeshConditionKeyKind::DestinationIp),
        CONDITION_DESTINATION_PORT => Some(MeshConditionKeyKind::DestinationPort),
        CONDITION_CONNECTION_SNI => Some(MeshConditionKeyKind::ConnectionSni),
        CONDITION_REQUEST_AUTH_PRINCIPAL => Some(MeshConditionKeyKind::RequestAuthPrincipal),
        CONDITION_REQUEST_AUTH_PRESENTER => Some(MeshConditionKeyKind::RequestAuthPresenter),
        CONDITION_REQUEST_AUTH_AUDIENCES => Some(MeshConditionKeyKind::RequestAuthAudiences),
        _ => {
            if bracketed_mesh_header_name(key).is_some() {
                Some(MeshConditionKeyKind::RequestHeader)
            } else if bracketed_mesh_claim_path(key).is_some() {
                Some(MeshConditionKeyKind::RequestAuthClaim)
            } else if experimental_envoy_filter_metadata_key(key).is_some() {
                Some(MeshConditionKeyKind::ExperimentalEnvoyFilter)
            } else {
                None
            }
        }
    }
}

/// Split `experimental.envoy.filters.<filter>[<key>]` into its filter name and
/// metadata key. Returns `None` unless both are present and non-empty — Istio
/// requires the bracketed metadata key, and a bare `experimental.envoy.filters.x`
/// would otherwise be admitted as an attribute nothing can ever populate.
///
/// Match Istio's `validateMapKey` / `envoyFilterGenerator` shape exactly: the
/// first `[` starts the metadata key and the final `]` ends it. Brackets inside
/// the metadata-key string are not structural nesting and remain valid. Being
/// stricter here would reject a policy Istio accepts; for a DENY that drops the
/// policy entirely and is fail-open, whereas admitting the documented key lets
/// Ferrum apply its explicit unsourceable-attribute semantics.
fn experimental_envoy_filter_metadata_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix(CONDITION_EXPERIMENTAL_ENVOY_FILTER_PREFIX)?;
    let (filter, metadata) = rest.split_once('[')?;
    let metadata = metadata.strip_suffix(']')?;
    if filter.is_empty() || metadata.is_empty() {
        return None;
    }
    Some((filter, metadata))
}

pub fn mesh_condition_has_values(condition: &ConditionMatch) -> bool {
    !condition.values.is_empty() || !condition.not_values.is_empty()
}

/// Which sub-field of a `when[]` entry a diagnostic is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshConditionField {
    Key,
    Values,
    NotValues,
}

impl MeshConditionField {
    /// Istio CRD spelling, used verbatim in Kubernetes translation diagnostics.
    pub const fn istio_name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Values => "values",
            Self::NotValues => "notValues",
        }
    }

    /// Ferrum `MeshPolicy` (snake_case) spelling, used in file/native config
    /// validation diagnostics.
    pub const fn mesh_name(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Values => "values",
            Self::NotValues => "not_values",
        }
    }
}

/// One field-specific `when[]` diagnostic. Callers own the path prefix
/// (`rules[].when[i]` vs `MeshPolicy 'x'.rules[i].when[j]`) so the same
/// validation produces the right wording on every configuration surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshConditionIssue {
    pub field: MeshConditionField,
    /// Index within `values` / `notValues` when the issue is value-specific.
    pub index: Option<usize>,
    /// Operator-facing reason. Never echoes an operator-supplied value except
    /// for IP blocks, whose exact text is required to fix the CIDR.
    pub reason: String,
}

impl MeshConditionIssue {
    fn key(reason: impl Into<String>) -> Self {
        Self {
            field: MeshConditionField::Key,
            index: None,
            reason: reason.into(),
        }
    }

    fn value(field: MeshConditionField, index: usize, reason: impl Into<String>) -> Self {
        Self {
            field,
            index: Some(index),
            reason: reason.into(),
        }
    }

    /// `values[3]` / `key` — the sub-path a caller appends to its own prefix.
    pub fn istio_path(&self) -> String {
        match self.index {
            Some(index) => format!("{}[{index}]", self.field.istio_name()),
            None => self.field.istio_name().to_string(),
        }
    }

    /// Same as [`Self::istio_path`] with the Ferrum `MeshPolicy` field spelling.
    pub fn mesh_path(&self) -> String {
        match self.index {
            Some(index) => format!("{}[{index}]", self.field.mesh_name()),
            None => self.field.mesh_name().to_string(),
        }
    }

    /// Reason text with the Ferrum `MeshPolicy` field spelling. Reasons are
    /// authored once in Istio CRD spelling; this is the single normalization
    /// point so the two surfaces cannot drift.
    pub fn mesh_reason(&self) -> std::borrow::Cow<'_, str> {
        if self.reason.contains("notValues") {
            std::borrow::Cow::Owned(self.reason.replace("notValues", "not_values"))
        } else {
            std::borrow::Cow::Borrowed(self.reason.as_str())
        }
    }
}

/// Validate one `when[]` entry: key shape, per-kind value syntax, and the
/// bounds that keep an externally supplied policy from growing unbounded
/// request-path work.
///
/// Returns every issue found (callers surface all of them) plus the classified
/// key on success. A malformed key short-circuits value validation because the
/// value grammar depends on the key kind.
pub fn validate_mesh_condition(
    condition: &ConditionMatch,
) -> Result<MeshConditionKeyKind, Vec<MeshConditionIssue>> {
    let mut issues = Vec::new();

    if condition.key.is_empty() {
        return Err(vec![MeshConditionIssue::key("must not be empty")]);
    }
    if condition.key.len() > MAX_MESH_CONDITION_KEY_LEN {
        return Err(vec![MeshConditionIssue::key(format!(
            "must be at most {MAX_MESH_CONDITION_KEY_LEN} UTF-8 bytes"
        ))]);
    }
    if condition.key.chars().any(char::is_control) {
        return Err(vec![MeshConditionIssue::key(
            "must not contain control characters",
        )]);
    }
    let Some(kind) = classify_mesh_condition_key(&condition.key) else {
        // Safe to echo: the checks above already bounded the key to
        // `MAX_MESH_CONDITION_KEY_LEN` printable UTF-8 bytes, and operators
        // cannot fix the policy without seeing which key failed.
        return Err(vec![MeshConditionIssue::key(format!(
            "'{}' is unsupported (expected one of source.principal, source.namespace, \
             source.serviceAccount, source.trustDomain, source.ip, remote.ip, destination.ip, \
             destination.port, connection.sni, \
             request.auth.principal, request.auth.presenter, request.auth.audiences, \
             request.auth.claims[<name>], request.headers[<name>], or \
             experimental.envoy.filters.<filter>[<key>])",
            condition.key
        ))]);
    };

    if !mesh_condition_has_values(condition) {
        issues.push(MeshConditionIssue::key("must set values or notValues"));
    }

    // Istio bounds `source.serviceAccount` more tightly than the generic
    // string-matcher keys. Both directions (`values` and `notValues`) get the
    // same treatment: a bound that applied to only one of them would leave the
    // other as an unbounded per-request walk.
    let (max_values, max_value_len) = match kind {
        MeshConditionKeyKind::SourceServiceAccount => (
            MAX_MESH_SERVICE_ACCOUNT_CONDITION_VALUES,
            MAX_MESH_SERVICE_ACCOUNT_CONDITION_VALUE_LEN,
        ),
        _ => (MAX_MESH_CONDITION_VALUES, MAX_MESH_CONDITION_VALUE_LEN),
    };

    for (field, values) in [
        (MeshConditionField::Values, &condition.values),
        (MeshConditionField::NotValues, &condition.not_values),
    ] {
        if values.len() > max_values {
            issues.push(MeshConditionIssue {
                field,
                index: None,
                reason: format!("must have at most {max_values} entries"),
            });
        }
        for (index, value) in values.iter().take(max_values).enumerate() {
            if value.is_empty() {
                issues.push(MeshConditionIssue::value(field, index, "must not be empty"));
                continue;
            }
            if value.len() > max_value_len {
                issues.push(MeshConditionIssue::value(
                    field,
                    index,
                    format!("must be at most {max_value_len} UTF-8 bytes"),
                ));
                continue;
            }
            if value.chars().any(char::is_control) {
                issues.push(MeshConditionIssue::value(
                    field,
                    index,
                    "must not contain control characters",
                ));
                continue;
            }
            match kind {
                MeshConditionKeyKind::SourceIp
                | MeshConditionKeyKind::RemoteIp
                | MeshConditionKeyKind::DestinationIp => {
                    if let Err(reason) = validate_mesh_condition_ip_block(value) {
                        issues.push(MeshConditionIssue::value(field, index, reason));
                    }
                }
                // Istio validates port conditions with a strict numeric
                // parse; a wildcard or non-numeric value can never match a
                // port, which is fail-open for a DENY.
                MeshConditionKeyKind::DestinationPort if value.parse::<u16>().is_err() => {
                    issues.push(MeshConditionIssue::value(
                        field,
                        index,
                        "must be a numeric port in 0..=65535",
                    ));
                }
                // Istio gives `source.serviceAccount` and `source.trustDomain`
                // their own value grammars instead of the generic string
                // matcher. Enforcing them here is what lets the evaluator use
                // an exact matcher for the first and keep the presence /
                // leading / trailing matcher for the second.
                MeshConditionKeyKind::SourceServiceAccount => {
                    if let Err(reason) = validate_mesh_condition_service_account(value) {
                        issues.push(MeshConditionIssue::value(field, index, reason));
                    }
                }
                MeshConditionKeyKind::SourceTrustDomain => {
                    if let Err(reason) = validate_mesh_condition_trust_domain(value) {
                        issues.push(MeshConditionIssue::value(field, index, reason));
                    }
                }
                _ => {
                    // The remaining string-match keys follow Istio's
                    // `matcher.StringMatcherWithPrefix` grammar: exact / `*`
                    // (presence) / `<prefix>*` / `*<suffix>`; anything else —
                    // including a mid-string `*` — is an exact match on the
                    // literal text. `source.namespace` is deliberately in this
                    // arm as well: Istio's `srcNamespaceGenerator` accepts a
                    // `*` at ANY position (each one becomes an arbitrary
                    // substring), so there is nothing to reject there either.
                    // The evaluator implements both grammars verbatim.
                }
            }
        }
    }

    if issues.is_empty() {
        Ok(kind)
    } else {
        Err(issues)
    }
}

/// Istio's `source.serviceAccount` value grammar
/// (`pkg/config/security/security.go::CheckServiceAccount`): either an explicit
/// `<namespace>/<service-account>` or a bare `<service-account>` that is
/// resolved against the namespace of the `AuthorizationPolicy` that declared it.
///
/// Wildcards are rejected outright. Istio compiles this key to an EXACT matcher
/// (`serviceAccountRegex` in `pilot/pkg/security/authz/model/generator.go`), so
/// admitting a `*` would install a condition that can never match — silently
/// fail-OPEN for a DENY. Diagnostics never echo the operator-supplied value.
fn validate_mesh_condition_service_account(value: &str) -> Result<(), &'static str> {
    if value.contains('*') {
        return Err(
            "must not contain '*' (source.serviceAccount is matched exactly; use \
             '<namespace>/<service-account>' or a bare '<service-account>' relative to \
             the policy namespace)",
        );
    }
    let mut segments = value.split('/');
    let namespace = segments.next().unwrap_or_default();
    let Some(service_account) = segments.next() else {
        // Bare `<service-account>`, resolved against the policy namespace.
        return if namespace.is_empty() {
            Err("must not be empty")
        } else {
            Ok(())
        };
    };
    if segments.next().is_some() {
        return Err(
            "must be '<namespace>/<service-account>' or a bare '<service-account>' \
             (at most one '/')",
        );
    }
    if namespace.is_empty() || service_account.is_empty() {
        return Err(
            "must be '<namespace>/<service-account>' with a non-empty namespace and \
             service account",
        );
    }
    Ok(())
}

/// Istio's `source.trustDomain` value grammar
/// (`pkg/config/security/security.go::CheckTrustDomainValues`): an exact trust
/// domain, the presence wildcard `*`, one LEADING wildcard, or one TRAILING
/// wildcard. Multiple or mid-string wildcards, and any `/`, are rejected.
///
/// Guaranteeing this shape at admission is what lets the evaluator keep the
/// presence / prefix / suffix matcher for this key: a mid-string `*` would
/// otherwise degrade to a literal exact match that can never fire, which is
/// fail-OPEN for a DENY. Diagnostics never echo the operator-supplied value.
fn validate_mesh_condition_trust_domain(value: &str) -> Result<(), &'static str> {
    if value.contains('/') {
        return Err("must not contain '/' (a trust domain is a single segment)");
    }
    match value.matches('*').count() {
        0 => Ok(()),
        1 if value.starts_with('*') || value.ends_with('*') => Ok(()),
        1 => Err("supports '*' only as a leading or trailing wildcard"),
        _ => Err("supports at most one '*', as a leading or trailing wildcard"),
    }
}

/// Validate the CIDR/bare-IP syntax used by `source.ip` / `remote.ip` /
/// `destination.ip` condition values. Malformed entries would never match at
/// runtime, which is fail-open for DENY policies.
pub fn validate_mesh_condition_ip_block(cidr: &str) -> Result<(), String> {
    let trimmed = cidr.trim();
    if trimmed.is_empty() {
        return Err("IP block must not be empty".to_string());
    }
    match trimmed.split_once('/') {
        Some((net, prefix_str)) => {
            let ip = net
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid IP in CIDR '{cidr}'"))?;
            let prefix = prefix_str
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix length in CIDR '{cidr}'"))?;
            let max = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(v6) => {
                    if v6.to_ipv4_mapped().is_some() && prefix < 96 {
                        return Err(format!(
                            "IPv4-mapped IPv6 CIDR prefix {prefix} must be at least 96 in CIDR '{cidr}'"
                        ));
                    }
                    128
                }
            };
            if prefix > max {
                return Err(format!(
                    "prefix length {prefix} out of range in CIDR '{cidr}'"
                ));
            }
            Ok(())
        }
        None => trimmed
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("invalid IP address '{cidr}'")),
    }
}

fn bracketed_mesh_header_name(key: &str) -> Option<&str> {
    let name = key
        .strip_prefix(CONDITION_REQUEST_HEADERS_PREFIX)?
        .strip_suffix(']')?;
    // Match Istio's validateMapKey shape exactly: the fixed first `[` and the
    // final `]` delimit one non-empty map key. Istio deliberately does not
    // validate the interior as an HTTP HeaderName here. Rejecting a shape it
    // admits drops the entire AuthorizationPolicy, including unrelated DENY
    // rules. Known pseudo-headers are sourced from typed request facts at
    // runtime; other names that HTTP cannot carry simply remain absent.
    (!name.is_empty()).then_some(name)
}

fn bracketed_mesh_claim_path(key: &str) -> Option<&str> {
    let path = key
        .strip_prefix(CONDITION_REQUEST_AUTH_CLAIMS_PREFIX)?
        .strip_suffix(']')?;
    // Istio applies the same loose map-key framing here. Well-formed nested
    // paths use `a][b` and match the flattened validated-claim store; unusual
    // admitted interiors that no validated claim can materialize stay absent
    // without causing the whole policy to be discarded.
    (!path.is_empty()).then_some(path)
}

/// Abstraction over per-workload label maps.
///
/// `mesh_authz` carries labels in a `BTreeMap<String, String>` (the
/// canonical [`crate::modes::mesh::slice::MeshSlice`] form), the Kubernetes injector
/// keeps them in a `HashMap`, and tests freely build either. This trait lets
/// the scope-matching helpers below accept any of those without copying.
pub trait WorkloadLabels {
    fn lookup(&self, key: &str) -> Option<&str>;
}

impl<S: ::std::hash::BuildHasher> WorkloadLabels for HashMap<String, String, S> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl WorkloadLabels for ::std::collections::BTreeMap<String, String> {
    #[inline]
    fn lookup(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Returns `true` when `policy.scope` applies to a workload whose namespace is
/// `proxy_namespace` and whose labels are `proxy_labels`.
///
/// This is the **single canonical scope-matching helper** used by both the
/// xDS / native MeshSubscribe slice builder ([`crate::modes::mesh::slice::MeshSlice::from_gateway_config`])
/// and the `mesh_authz` plugin's per-policy filter so that scope semantics
/// stay byte-identical across the two surfaces.
///
/// Semantics:
/// - [`PolicyScope::MeshWide`] — applies to every workload.
/// - [`PolicyScope::Namespace`] — applies iff `proxy_namespace == policy.scope.namespace`.
/// - [`PolicyScope::WorkloadSelector`] — applies iff (a) the selector's
///   namespace is unset or equal to `proxy_namespace` AND (b) every
///   `(key, value)` in `selector.labels` is present in `proxy_labels` with the
///   same value (subset match — empty selector labels means "any workload in
///   the optional namespace").
/// - [`PolicyScope::TargetRefs`] — never matches via bare namespace/labels alone.
///   Waypoint Gateway / GatewayClass attachments require
///   [`policy_scope_applies_with_waypoint`]; Service attachments match
///   destination identity through exact service namespace/name membership
///   ([`policy_target_attachment_applies_to_service`],
///   [`crate::modes::mesh::runtime::PolicyScopeCache::policy_applies_for_destination`],
///   ServiceWaypoint narrowing). Targeted policies never broaden onto Sidecar
///   workloads or sibling Services that share selector labels.
pub fn policy_scope_applies_to_workload<L: WorkloadLabels + ?Sized>(
    policy: &MeshPolicy,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    scope_applies_to_workload(&policy.scope, proxy_namespace, proxy_labels)
}

/// Returns `true` when a [`PolicyScope`] applies to a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`.
///
/// Same semantics as [`policy_scope_applies_to_workload`] but accepts a
/// bare `PolicyScope` instead of a full `MeshPolicy`, making it reusable
/// for `MeshRequestAuthentication` scope filtering.
pub fn scope_applies_to_workload<L: WorkloadLabels + ?Sized>(
    scope: &PolicyScope,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    match scope {
        PolicyScope::MeshWide => true,
        PolicyScope::Namespace {
            namespace: policy_namespace,
        } => policy_namespace == proxy_namespace,
        PolicyScope::WorkloadSelector { selector } => {
            workload_selector_matches(selector, proxy_namespace, proxy_labels)
        }
        // AuthorizationPolicy targetRefs are waypoint/attachment scoped; bare
        // label matching would broaden them onto Sidecar workloads.
        PolicyScope::TargetRefs { .. } => false,
    }
}

/// The exact waypoint identity a targeted policy attachment is evaluated
/// against.
///
/// This is the ONE place Gateway / GatewayClass `targetRefs` matching is
/// decided, shared by slice narrowing, the `mesh_authz` cold-path retain, and
/// the request-path destination check. Retention uses OR semantics over the
/// whole attachment list and never prunes the non-matching arms, so a runtime
/// consumer that assumed "the policy is here, therefore its Gateway arm
/// matched" would let a policy targeting `{Service reviews, Gateway wp-b}`
/// apply to EVERY destination at `wp-a`. Carrying the exact context and
/// re-checking is what keeps true OR semantics without that broadening.
///
/// All fields are borrowed and `Copy`; constructing one per request allocates
/// nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct WaypointAttachment<'a> {
    /// Namespace of the waypoint proxy serving this slice.
    pub namespace: &'a str,
    /// `Gateway.metadata.name` of the waypoint, when this IS a waypoint slice.
    /// `None` means "not a waypoint" and makes every attachment fail closed:
    /// Istio only applies `targetRefs` policies at waypoint proxies.
    pub name: Option<&'a str>,
    /// Authoritative `Gateway.spec.gatewayClassName` for [`Self::name`].
    /// `None` (unknown class) fails GatewayClass attachments closed.
    pub gateway_class: Option<&'a str>,
}

impl WaypointAttachment<'_> {
    /// Whether this exact waypoint is the resource `attachment` names.
    ///
    /// `Service` attachments are destination-resource identity and are never
    /// decided here — see [`policy_target_attachment_applies_to_service`].
    #[inline]
    pub fn matches(&self, attachment: &PolicyTargetAttachment) -> bool {
        let Some(waypoint_name) = self.name else {
            return false;
        };
        match attachment {
            PolicyTargetAttachment::Gateway { namespace, name } => {
                waypoint_name == name.as_str() && namespace == self.namespace
            }
            PolicyTargetAttachment::GatewayClass { name } => self
                .gateway_class
                .is_some_and(|class| class == name.as_str()),
            PolicyTargetAttachment::Service { .. } => false,
        }
    }
}

/// Waypoint-aware policy scope predicate.
///
/// Extends [`policy_scope_applies_to_workload`] so Gateway / GatewayClass
/// `targetRefs` attachments apply inside the matching ServiceWaypoint slice
/// without broadening onto Sidecar / Ambient workloads.
///
/// `waypoint_gateway_class` must be the authoritative
/// `Gateway.spec.gatewayClassName` for this waypoint (from
/// [`MeshWaypointBinding::gateway_class_name`]). A `GatewayClass` attachment
/// matches only that exact class — `istio-waypoint` never attaches to a
/// `ferrum-waypoint` Gateway (and vice versa). Missing class evidence, and a
/// non-waypoint proxy, both fail closed.
pub fn policy_scope_applies_with_waypoint<L: WorkloadLabels + ?Sized>(
    policy: &MeshPolicy,
    proxy_namespace: &str,
    proxy_labels: &L,
    waypoint_name: Option<&str>,
    waypoint_gateway_class: Option<&str>,
) -> bool {
    match &policy.scope {
        PolicyScope::TargetRefs { attachments } => {
            let waypoint = WaypointAttachment {
                namespace: proxy_namespace,
                name: waypoint_name,
                gateway_class: waypoint_gateway_class,
            };
            attachments
                .iter()
                .any(|attachment| waypoint.matches(attachment))
        }
        _ => policy_scope_applies_to_workload(policy, proxy_namespace, proxy_labels),
    }
}

/// Returns `true` when a Service-targeted attachment names this exact service.
///
/// Used by ServiceWaypoint narrowing so a policy attached to Service `reviews`
/// is kept when that service is bound to the waypoint, even though the waypoint
/// pod's own labels have nothing to do with the Service's pod selector.
/// Membership is exact `(namespace, name)` — never a label overlap.
pub fn policy_target_attachment_applies_to_service(
    attachment: &PolicyTargetAttachment,
    service_namespace: &str,
    service_name: &str,
) -> bool {
    match attachment {
        PolicyTargetAttachment::Service { namespace, name } => {
            namespace == service_namespace && name == service_name
        }
        PolicyTargetAttachment::Gateway { .. } | PolicyTargetAttachment::GatewayClass { .. } => {
            false
        }
    }
}

/// Supported waypoint `GatewayClass` names (`istio-waypoint` / `ferrum-waypoint`).
#[inline]
pub fn is_supported_waypoint_gateway_class_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("istio-waypoint") || name.eq_ignore_ascii_case("ferrum-waypoint")
}

/// Returns `true` when a [`WorkloadSelector`] matches a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`. Same
/// shape as [`policy_scope_applies_to_workload`]; lifted so PeerAuthentication
/// selector matching shares the same predicate.
pub fn workload_selector_matches<L: WorkloadLabels + ?Sized>(
    selector: &WorkloadSelector,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    if let Some(selector_namespace) = selector.namespace.as_ref()
        && selector_namespace != proxy_namespace
    {
        return false;
    }
    labels_match_subset(&selector.labels, proxy_labels)
}

// ── RequestAuthentication ─────────────────────────────────────────────────

/// Represents an Istio `RequestAuthentication` resource translated into
/// Ferrum's model. Declares which JWTs are accepted for a workload.
///
/// Semantics mirror Istio: RequestAuthentication is **permissive** by
/// default — it only declares which JWTs are *valid*, not which are
/// *required*. A request with no JWT passes through. An invalid JWT is
/// rejected. A valid JWT has its claims extracted and identity propagated.
/// Enforcement (requiring a JWT) comes from `AuthorizationPolicy`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshRequestAuthentication {
    pub name: String,
    pub namespace: String,
    pub scope: PolicyScope,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_rules: Vec<MeshJwtRule>,
}

/// A single JWT validation rule within a [`MeshRequestAuthentication`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshJwtRule {
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Inline JWKS JSON (alternative to `jwks_uri`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_headers: Vec<JwtHeader>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from_params: Vec<String>,
    #[serde(default)]
    pub forward_original_token: bool,
}

/// A header location from which to extract a JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JwtHeader {
    pub name: String,
    /// Prefix stripped before validation (e.g., `"Bearer "`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

// ── Telemetry ─────────────────────────────────────────────────────────────

/// Raw Telemetry resource from Istio CRD translation (before workload merge).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshTelemetryResource {
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub scope: PolicyScope,
    pub config: MeshTelemetryConfig,
}

/// Merged telemetry configuration for a workload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MeshTelemetryConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracing: Option<MeshTracingConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MeshMetricsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_logging: Option<MeshAccessLoggingConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshTracingConfig {
    /// Istio tracing mode selector — `Server`, `Client`, or `ClientAndServer`.
    /// `None` defers to the default (Istio treats unset as SERVER for sidecar
    /// inbound and CLIENT for sidecar outbound). The mesh plugin injection
    /// path turns this into a `direction_emit` field on the `workload_metrics`
    /// plugin instance so a single plugin handles both sides of a hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<TelemetryTracingMode>,
    /// Sampling percentage 0.0–100.0. `None` inherits from less-specific Telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling_percentage: Option<f64>,
    /// Istio `disableSpanReporting`.
    #[serde(
        default,
        alias = "disableSpanReporting",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_span_reporting: Option<bool>,
    /// Literal custom tags and environment-tag `defaultValue` fallbacks injected
    /// into every span / transaction metadata. Live environment values are never
    /// resolved from this map on the controller; see [`Self::custom_env_tags`].
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_tags: HashMap<String, String>,
    /// Custom tags resolved from request headers at runtime.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_header_tags: HashMap<String, String>,
    /// Istio `customTags.<tag>.environment` references carried as
    /// `tag_name -> env_var_name`. The Kubernetes translator never reads the
    /// controller-host environment: the mesh data plane resolves these at
    /// `workload_metrics` construction/reload. A present value overrides any
    /// matching [`Self::custom_tags`] default; a missing variable without a
    /// default omits the tag (Istio/Envoy semantics).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub custom_env_tags: HashMap<String, String>,
    /// Provider-specific tracing backends (Zipkin / Datadog / Lightstep / OpenTelemetry).
    ///
    /// The legacy singular `provider` spelling deserializes into this vector
    /// for back-compat, but new slices serialize only `providers`.
    #[serde(
        default,
        alias = "provider",
        deserialize_with = "deserialize_tracing_providers",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub providers: Vec<TracingProvider>,
}

impl MeshTracingConfig {
    /// Merge custom-tag definitions while preserving the oneof semantics of
    /// Istio's literal/header/environment tag sources.
    ///
    /// `custom_tags` may accompany a header or environment source as its
    /// `defaultValue`, so every key named by `next` replaces that key across
    /// all three maps before the new source and optional fallback are copied.
    /// Without the cross-map removal, a more-specific source can leave an
    /// inherited environment/header lookup or literal fallback active.
    pub fn merge_custom_tag_sources(
        &mut self,
        custom_tags: &HashMap<String, String>,
        custom_header_tags: &HashMap<String, String>,
        custom_env_tags: &HashMap<String, String>,
    ) {
        let keys: HashSet<&str> = custom_tags
            .keys()
            .chain(custom_header_tags.keys())
            .chain(custom_env_tags.keys())
            .map(String::as_str)
            .collect();

        for key in keys {
            self.custom_tags.remove(key);
            self.custom_header_tags.remove(key);
            self.custom_env_tags.remove(key);

            if let Some(value) = custom_tags.get(key) {
                self.custom_tags.insert(key.to_string(), value.clone());
            }
            if let Some(header) = custom_header_tags.get(key) {
                self.custom_header_tags
                    .insert(key.to_string(), header.clone());
            }
            if let Some(env_var) = custom_env_tags.get(key) {
                self.custom_env_tags
                    .insert(key.to_string(), env_var.clone());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryTracingMode {
    Client,
    Server,
    ClientAndServer,
}

impl TelemetryTracingMode {
    /// Whether this mode covers server-side (inbound) span emission.
    pub fn emits_server(self) -> bool {
        matches!(self, Self::Server | Self::ClientAndServer)
    }

    /// Whether this mode covers client-side (outbound) span emission.
    pub fn emits_client(self) -> bool {
        matches!(self, Self::Client | Self::ClientAndServer)
    }
}

/// Tracing backend selection for a `MeshTracingConfig`.
///
/// Mirrors Istio's `Tracing.providers[]` provider definitions for the four
/// most common backends. Serialised with `kind` discriminator + `config`
/// payload so a future variant can be appended without an `unknown`-handling
/// shim on older DPs (serde will simply fail to deserialise an unknown
/// variant and the slice update is rejected at slice-apply time, consistent
/// with the rest of the mesh slice contract).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "config")]
pub enum TracingProvider {
    Zipkin {
        url: String,
    },
    Datadog {
        agent_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
    },
    Lightstep {
        collector_url: String,
        #[serde(alias = "accessTokenEnv")]
        access_token_env: String,
    },
    #[serde(rename = "opentelemetry")]
    OpenTelemetry {
        endpoint: String,
    },
}

impl fmt::Debug for TracingProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zipkin { url } => f.debug_struct("Zipkin").field("url", url).finish(),
            Self::Datadog { agent_url, service } => f
                .debug_struct("Datadog")
                .field("agent_url", agent_url)
                .field("service", service)
                .finish(),
            Self::Lightstep {
                collector_url,
                access_token_env,
            } => f
                .debug_struct("Lightstep")
                .field("collector_url", collector_url)
                .field("access_token_env", access_token_env)
                .finish(),
            Self::OpenTelemetry { endpoint } => f
                .debug_struct("OpenTelemetry")
                .field("endpoint", endpoint)
                .finish(),
        }
    }
}

fn deserialize_tracing_providers<'de, D>(deserializer: D) -> Result<Vec<TracingProvider>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(Vec::new());
    }
    if value.is_array() {
        serde_json::from_value(value).map_err(serde::de::Error::custom)
    } else {
        serde_json::from_value(value)
            .map(|provider| vec![provider])
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshMetricsConfig {
    /// Tag overrides: rename, remove, or set custom values for metric tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_overrides: Vec<MetricTagOverride>,
    /// Specific metric names to disable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_metrics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricTagOverride {
    /// Metric family this override targets. `None` applies to every supported
    /// mesh metric for direct/native configurations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<String>,
    pub name: String,
    pub operation: TagOverrideOperation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum TagOverrideOperation {
    Remove,
    Rename {
        new_name: String,
    },
    /// Static UPSERT value (decoded Telemetry string literal or direct plugin config).
    Set {
        value: String,
    },
    /// Compiled Telemetry UPSERT CEL expression evaluated at metric emission.
    SetExpr {
        expression: super::metric_tag_cel::MetricTagCelExpr,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshAccessLoggingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<AccessLogFilter>,
}

fn default_true() -> bool {
    true
}

/// Simple access log filter operating on transaction summary fields.
///
/// Pure conjunctions of supported predicates are stored in the flat fields.
/// Expressions containing `||` compile to the optional [`AccessLogFilterExpr`]
/// tree instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogFilter {
    /// Only log responses with status code >= this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code_min: Option<u16>,
    /// Only log responses with status code <= this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code_max: Option<u16>,
    /// Only log requests with latency above this threshold (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_latency_ms: Option<u64>,
    /// Only log requests that resulted in an error.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub errors_only: bool,
    /// Boolean expression compiled from an Istio Telemetry `filter.expression`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<super::access_log_filter::AccessLogFilterExpr>,
}

// ── ProxyConfig ───────────────────────────────────────────────────────────

/// Represents an Istio `ProxyConfig` (`networking.istio.io/v1beta1`) resource
/// translated into Ferrum's model.
///
/// ProxyConfig carries config-time, read-only settings for a workload's
/// data plane: `concurrency`, `image`, `environmentVariables`, and tracing
/// `sampling`. It has **no data-plane request-path impact** — values are
/// applied at slice-apply time (cold path) and surfaced to operator
/// tooling. Tracing `sampling` flows into the injected `workload_metrics`
/// plugin's `sampling_percentage` field.
///
/// Scope resolution mirrors the canonical [`PolicyScope`] used by
/// `PeerAuthentication`, `RequestAuthentication`, and `Telemetry`: a
/// resource in the Istio root namespace with no selector is `MeshWide`; a
/// resource in any other namespace with no selector is `Namespace`-scoped;
/// any resource with a selector is `WorkloadSelector`-scoped (with the
/// `namespace` set when not in the root namespace, mirroring the Istio
/// "root-namespace selectors apply mesh-wide" rule used by Telemetry / RA).
/// Most-specific match wins per workload (WorkloadSelector > Namespace >
/// MeshWide); same-specificity ties are broken by ASCII-ordered name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshProxyConfig {
    pub name: String,
    pub namespace: String,
    /// Resolved [`PolicyScope`] capturing Istio's root-namespace +
    /// selector semantics. See struct docs for the full table.
    #[serde(default)]
    pub scope: PolicyScope,
    /// `spec.concurrency` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<u32>,
    /// `spec.image.imageType` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// `spec.environmentVariables` — informational; surfaced to operator tooling.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment: HashMap<String, String>,
    /// `spec.tracing.sampling` — percentage 0-100; merged into
    /// `workload_metrics.sampling_percentage` at slice-apply time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracing_sampling: Option<f64>,
}

/// Returns `true` when a [`MeshProxyConfig`] applies to a workload whose
/// namespace is `proxy_namespace` and whose labels are `proxy_labels`.
///
/// Delegates to the canonical [`scope_applies_to_workload`] helper so
/// ProxyConfig honors the same root-namespace + selector semantics as
/// every other Istio mesh resource (PeerAuthentication, Telemetry,
/// RequestAuthentication, AuthorizationPolicy).
pub fn proxy_config_applies_to_workload<L: WorkloadLabels + ?Sized>(
    config: &MeshProxyConfig,
    proxy_namespace: &str,
    proxy_labels: &L,
) -> bool {
    scope_applies_to_workload(&config.scope, proxy_namespace, proxy_labels)
}

/// Returns `true` when every `(key, value)` in `selector_labels` is present
/// in `proxy_labels` with the same value. Empty `selector_labels` always
/// matches (subset semantics). Shared by [`workload_selector_matches`].
#[inline]
fn labels_match_subset<L: WorkloadLabels + ?Sized>(
    selector_labels: &HashMap<String, String>,
    proxy_labels: &L,
) -> bool {
    selector_labels
        .iter()
        .all(|(key, value)| proxy_labels.lookup(key) == Some(value.as_str()))
}

/// Returns true when a ServiceEntry is visible to a workload namespace under
/// Ferrum's egress materialization rules. Empty `export_to` is intentionally
/// namespace-local to avoid cross-tenant exposure by omission. Istio
/// `workloadSelector` describes backing workloads/endpoints, not which clients
/// may consume the service, so it is deliberately not part of this visibility
/// check.
pub fn service_entry_exported_to_namespace(entry: &ServiceEntry, workload_namespace: &str) -> bool {
    export_visibility_admits(&entry.export_to, &entry.namespace, workload_namespace)
}

/// The ONE `exportTo` visibility evaluator, shared by ServiceEntry,
/// DestinationRule, and VirtualService-derived CORS policy so the three can
/// never drift apart.
///
/// `.` expands against `declaring_namespace` — which is why every carrier of
/// an `exportTo` list must also carry its declaring namespace. An EMPTY list
/// is namespace-local: Ferrum's fail-closed-by-omission convention on the
/// native/file/carrier sources (Kubernetes translation materializes Istio's
/// public default as an explicit `["*"]` instead of leaving the list empty).
///
/// Every source canonicalizes entries before this evaluator runs. Deliberately
/// do not reinterpret padded or otherwise unnormalized input here: an invalid
/// value must match nothing until boundary normalization and validation have
/// accepted it, never accidentally widen visibility.
pub(crate) fn export_visibility_admits(
    export_to: &[String],
    declaring_namespace: &str,
    workload_namespace: &str,
) -> bool {
    let declaring_namespace = declaring_namespace.trim();
    let workload_namespace = workload_namespace.trim();
    if export_to.is_empty() {
        return declaring_namespace == workload_namespace;
    }

    export_to.iter().any(|target| {
        target == "*"
            || target == workload_namespace
            || (target == "." && declaring_namespace == workload_namespace)
    })
}

/// THE `exportTo` entry canonicalizer, and the other half of
/// [`export_visibility_admits`]'s contract.
///
/// The evaluator deliberately refuses to reinterpret padded input, which only
/// holds as a safety property if EVERY source canonicalizes first — otherwise
/// a boundary that validates a trimmed copy (`validate_mesh_export_to` trims
/// per entry) accepts `" beta "` while the stored entry goes on to match
/// nothing, i.e. accepted-then-silently-inert. Config-source normalization
/// (`MeshConfig::normalize`), the Kubernetes translator, and the xDS carrier
/// decode paths all funnel through this ONE function so they cannot drift.
///
/// Trimming is the whole transformation: an entry that is still invalid after
/// trimming stays invalid and is rejected by [`validate_mesh_export_to`].
pub fn normalize_mesh_export_to(export_to: &mut [String]) {
    for entry in export_to {
        let trimmed = entry.trim();
        if trimmed.len() != entry.len() {
            *entry = trimmed.to_string();
        }
    }
}

/// True when this DestinationRule is exported to `workload_namespace`
/// (issue #2465).
///
/// This is the visibility half of DestinationRule selection and runs BEFORE
/// [`destination_rule_lookup_tier`]: a rule the subscriber cannot see is never
/// eligible for any tier, so root-namespace fallback can never resurrect a
/// namespace-local rule.
pub fn destination_rule_exported_to_namespace(
    rule: &MeshDestinationRule,
    workload_namespace: &str,
) -> bool {
    export_visibility_admits(&rule.export_to, &rule.namespace, workload_namespace)
}

/// Istio's DestinationRule lookup path, most specific first (issue #2469).
///
/// Istio resolves the DestinationRule for a destination host by searching the
/// client's own namespace, then the target service's namespace, then
/// `meshConfig.rootNamespace` — the FIRST tier that yields a visible rule
/// wins outright. Derived `Ord` follows the declaration order, so
/// `Client < Service < Root < Unscoped` and "smallest tier wins" is the
/// selection rule.
///
/// [`Unscoped`](Self::Unscoped) is the lowest-priority bucket for a rule whose
/// namespace is none of the three: slice narrowing refuses those outright, so
/// it only ever appears on the data-plane materialization pass, where it keeps
/// an unexpected rule from outranking a properly scoped one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DestinationRuleLookupTier {
    /// Declared in the client workload's own namespace.
    Client,
    /// Declared in the target service's namespace.
    Service,
    /// Declared in the configured `istio_root_namespace`.
    Root,
    /// Declared somewhere else entirely.
    Unscoped,
}

impl DestinationRuleLookupTier {
    /// True when this tier is part of Istio's lookup path at all.
    #[inline]
    pub fn is_in_lookup_path(self) -> bool {
        self != DestinationRuleLookupTier::Unscoped
    }
}

/// Classify a DestinationRule's declaring namespace into its Istio lookup tier.
///
/// Ties resolve to the most specific tier (a rule in a namespace that is both
/// the client's and the service's is `Client`), so tier assignment never
/// depends on how `(namespace, name)` happens to sort.
///
/// `service_namespace` is `None` when the caller could not establish, from
/// evidence, which namespace owns the target service — an ambiguously owned
/// external host, or a two-label short host with no matching entry in the
/// service inventory. That DISABLES the service tier rather than guessing a
/// namespace: guessing lets a rule from an unrelated namespace nominate itself
/// as the owner of a host it does not own (issue #2469).
///
/// EVERY tier comparison is guarded against an empty namespace on the
/// authoritative side. An empty `client_namespace`, `service_namespace`, or
/// `root_namespace` disables that tier rather than matching every rule whose
/// own namespace also trims to empty.
pub fn destination_rule_lookup_tier(
    rule_namespace: &str,
    client_namespace: &str,
    service_namespace: Option<&str>,
    root_namespace: &str,
) -> DestinationRuleLookupTier {
    let rule_namespace = rule_namespace.trim();
    let client_namespace = client_namespace.trim();
    let service_namespace = service_namespace.map(str::trim).filter(|ns| !ns.is_empty());
    let root_namespace = root_namespace.trim();
    if !client_namespace.is_empty() && rule_namespace == client_namespace {
        DestinationRuleLookupTier::Client
    } else if service_namespace == Some(rule_namespace) {
        DestinationRuleLookupTier::Service
    } else if !root_namespace.is_empty() && rule_namespace == root_namespace {
        DestinationRuleLookupTier::Root
    } else {
        DestinationRuleLookupTier::Unscoped
    }
}

pub fn service_entry_applies_to_workload<L: WorkloadLabels + ?Sized>(
    entry: &ServiceEntry,
    workload_namespace: &str,
    _workload_labels: &L,
) -> bool {
    service_entry_exported_to_namespace(entry, workload_namespace)
}

// ── PeerAuthentication ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerAuthentication {
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PolicyScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<WorkloadSelector>,
    #[serde(default)]
    pub mtls_mode: MtlsMode,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_overrides: HashMap<u16, MtlsMode>,
}

impl PeerAuthentication {
    /// Whether this policy has a non-empty workload selector. This is the
    /// canonical predicate for PeerAuthentication scope classification and
    /// `portLevelMtls` applicability across translated and native slices.
    pub fn has_workload_selector(&self) -> bool {
        match self.scope.as_ref() {
            Some(PolicyScope::WorkloadSelector { selector }) => selector.has_labels(),
            Some(
                PolicyScope::MeshWide
                | PolicyScope::Namespace { .. }
                | PolicyScope::TargetRefs { .. },
            ) => false,
            None => self
                .selector
                .as_ref()
                .is_some_and(WorkloadSelector::has_labels),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtlsMode {
    // ── PeerAuthentication server-side modes ──
    Strict,
    #[default]
    Permissive,
    Disable,
    // ── DestinationRule client-side modes (Istio `ClientTLSSettings.mode`) ──
    /// SIMPLE: originate TLS to the backend, verify the server certificate.
    Simple,
    /// MUTUAL: originate mTLS with operator-provided client cert/key.
    Mutual,
    /// ISTIO_MUTUAL: originate mTLS using the workload's SPIFFE identity
    /// material (no explicit cert/key in the DR).
    IstioMutual,
}

impl MtlsMode {
    #[inline]
    pub fn is_peer_auth_mode(self) -> bool {
        matches!(self, Self::Strict | Self::Permissive | Self::Disable)
    }
}

// ── ServiceEntry ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    pub namespace: String,
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<MeshEndpoint>,
    #[serde(default)]
    pub resolution: Resolution,
    #[serde(default)]
    pub location: ServiceEntryLocation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
    /// Optional Istio-style visibility list. Empty means namespace-local for
    /// Ferrum's materialization path; `*` exports mesh-wide, `.` exports to
    /// this entry's namespace, and a namespace value exports there explicitly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_selector: Option<WorkloadSelector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Dns,
    Static,
    #[default]
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEntryLocation {
    #[default]
    MeshExternal,
    MeshInternal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEndpoint {
    pub address: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub ports: HashMap<String, u16>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── Trust bundles ─────────────────────────────────────────────────────────

/// Full trust-bundle set carried in `GatewayConfig`. Mirrors
/// [`crate::identity::TrustBundleSet`] in shape, but uses serialisable
/// representations so the config can be persisted to file/DB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundleSet {
    pub local: TrustBundle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federated: Vec<TrustBundle>,
}

/// Persistable trust bundle. `x509_authorities` is a list of base64-encoded
/// DER blobs; `jwt_authorities` is a flat list. Both are intentionally
/// serialisation-friendly (no `Vec<u8>` raw bytes) so YAML/JSON output
/// stays human-readable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustBundle {
    pub trust_domain: TrustDomain,
    /// Base64-encoded DER certificates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub x509_authorities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jwt_authorities: Vec<JwtAuthority>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hint_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtAuthority {
    pub key_id: String,
    pub public_key_pem: String,
}

impl TrustBundle {
    /// Decode the base64 authorities into raw DER, suitable for handing to
    /// the runtime [`crate::identity::TrustBundle`]. Returns the list of
    /// bytes or an error on the first malformed entry.
    pub fn decode_x509_authorities(&self) -> Result<Vec<Vec<u8>>, String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        self.x509_authorities
            .iter()
            .enumerate()
            .map(|(i, s)| {
                engine
                    .decode(s.as_bytes())
                    .map_err(|e| format!("x509_authorities[{}]: invalid base64: {}", i, e))
            })
            .collect()
    }

    /// Convert this serialisable bundle into a runtime
    /// [`crate::identity::TrustBundle`] (DER-decoded).
    pub fn to_runtime(&self) -> Result<IdentityTrustBundle, String> {
        Ok(IdentityTrustBundle {
            trust_domain: self.trust_domain.clone(),
            x509_authorities: self.decode_x509_authorities()?,
            jwt_authorities: self
                .jwt_authorities
                .iter()
                .map(|a| IdentityJwtAuthority {
                    key_id: a.key_id.clone(),
                    public_key_pem: a.public_key_pem.clone(),
                })
                .collect(),
            refresh_hint_seconds: self.refresh_hint_seconds,
        })
    }
}

impl TrustBundleSet {
    /// Convenience: build a runtime [`crate::identity::TrustBundleSet`].
    pub fn to_runtime(&self) -> Result<crate::identity::TrustBundleSet, String> {
        let local = self.local.to_runtime()?;
        let mut federated = std::collections::HashMap::new();
        for tb in &self.federated {
            let runtime = tb.to_runtime()?;
            federated.insert(runtime.trust_domain.clone(), runtime);
        }
        Ok(crate::identity::TrustBundleSet { local, federated })
    }
}

// ── Sidecar (Istio egress scoping) ───────────────────────────────────────

/// Istio `Sidecar` resource. Narrows which services / service-entries /
/// destination-rules a workload may reach via egress and can replace its
/// default inbound surface with declared `ingress[]` HTTP or stream listeners.
/// Mirror of the modeled `networking.istio.io/v1.Sidecar` fields.
///
/// Resolution order at slice build time (most specific wins):
/// 1. Workload-scoped (non-empty `workload_selector` whose labels match)
/// 2. Namespace-default (empty / `None` `workload_selector`)
///
/// Behavior is gated by `FERRUM_MESH_SIDECAR_ENFORCED` (default `false`).
/// When the flag is unset, sidecars are accepted and persisted in
/// `MeshConfig` but slice narrowing is not applied (existing behavior).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSidecar {
    pub name: String,
    pub namespace: String,
    /// Empty / `None` = namespace-default; non-empty = workload-scoped via labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_selector: Option<WorkloadSelector>,
    /// `true` when Kubernetes `spec.egress` was omitted and the Sidecar should
    /// inherit the namespace default outbound scope instead of treating the
    /// empty `egress` vector as an explicit block-all policy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub egress_inherits_defaults: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<MeshSidecarEgress>,
    /// `true` when Kubernetes `spec.ingress` was PRESENT — including an explicit
    /// empty `ingress: []` — as opposed to omitted. Istio distinguishes the two:
    /// an OMITTED `ingress` block lets the workload keep the automatic
    /// per-service-port inbound defaults, while a DECLARED `ingress` (even empty)
    /// configures the workload's inbound listeners explicitly and REPLACES those
    /// defaults. So an explicit `ingress: []` must suppress the default inbound
    /// routes (the operator declared "no custom inbound listeners"), not fall
    /// back to exposing the service-port defaults. The slice builder folds this
    /// with `!ingress.is_empty()` into the fail-closed `sidecar_ingress_declared`
    /// marker (a non-empty `ingress` always declares; this bool adds the
    /// explicit-empty case for both the K8s and native paths).
    #[serde(default, skip_serializing_if = "is_false")]
    pub ingress_declared: bool,
    /// Istio `spec.ingress[]` — custom inbound listeners the workload declares
    /// (a listener port + optional bind address + a `defaultEndpoint` to
    /// forward inbound traffic to). Per Istio semantics, when `ingress` is
    /// present it **replaces** the default per-service-port inbound listeners
    /// for the workload (Ferrum mirrors that: the sidecar inbound materializer
    /// emits routes from these entries instead of the service-port defaults —
    /// see `materialize_sidecar_inbound_proxies`). Empty / absent keeps the
    /// default inbound behavior unchanged unless `ingress_declared` is set (an
    /// explicit empty `ingress: []`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<MeshSidecarIngress>,
    /// Istio `spec.outboundTrafficPolicy.mode` — the workload-scoped override of
    /// the mesh-wide [`MeshConfig::outbound_traffic_policy`] (issue #3262).
    ///
    /// `None` = the Sidecar OMITTED `outboundTrafficPolicy`, so the workload
    /// inherits the mesh-wide policy (slice `outbound_traffic_policy`, else
    /// `FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY`). `Some(_)` REPLACES it for every
    /// workload this Sidecar applies to — Istio resolves exactly ONE Sidecar per
    /// workload, so there is no inheritance chain here (unlike `egress`, whose
    /// omitted-means-inherit walk is a separate, egress-only concern).
    ///
    /// On the K8s path, a present object with omitted/null `mode` uses Istio's
    /// documented `ALLOW_ANY` default. A PRESENT `outboundTrafficPolicy` block
    /// Ferrum cannot represent exactly — an unrecognized/non-string `mode`, a
    /// non-object block, or an `egressProxy` Ferrum cannot route through —
    /// resolves fail-closed to [`OutboundTrafficPolicy::RegistryOnly`] and is
    /// surfaced in the resource's `deferred_fields` status. The Sidecar itself
    /// is never REJECTED over this field: dropping it would also drop its egress
    /// narrowing and thereby WIDEN both the slice's service view and the derived
    /// outbound registry.
    ///
    /// Applied only under `FERRUM_MESH_SIDECAR_ENFORCED && !…_DRY_RUN` (the same
    /// effective gate as `ingress[]` materialization) — see
    /// `MeshSlice::sidecar_outbound_traffic_policy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<OutboundTrafficPolicy>,
}

/// A single ingress listener entry under a [`MeshSidecar`] (`spec.ingress[]`).
///
/// Mirrors Istio's `IstioIngressListener`: inbound traffic arriving on `port`
/// is forwarded to `default_endpoint`. In Ferrum's sidecar capture model all
/// inbound is iptables-REDIRECTed to the shared `:15006` listener, so `port`
/// is the port the client originally dialed (recovered from the captured
/// original destination, or a peer sidecar's request authority) and selects
/// which ingress route serves the request — exactly the per-port sibling
/// disambiguation the default inbound materializer uses, but keyed by the
/// declared listener port instead of the resolved container port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSidecarIngress {
    /// The listener port the workload declares. Inbound traffic addressed to
    /// this port (captured original destination, or a peer's request
    /// authority) is forwarded to `default_endpoint`.
    pub port: u16,
    /// Application-layer protocol of the listener.
    ///
    /// Recognized HTTP-family listeners (`http`/`http2`/`grpc`/`https`)
    /// materialize an HTTP inbound route. Recognized stream-family listeners
    /// (`tcp`/`tls`/database protocols) materialize a raw-TCP inbound relay
    /// keyed by the declared listener port (issue #3260). `Udp` and
    /// `Unknown` (native omitted / K8s unrecognized typo) stay deferred —
    /// never guessed onto either lane.
    ///
    /// Fail-closed across sources: on the K8s path the translator's
    /// `sidecar_ingress_app_protocol` maps recognized HTTP and stream tokens
    /// explicitly, defaults a MISSING protocol to `Tcp` (Istio's unset-port
    /// default), and maps an UNRECOGNIZED string to `Unknown` so typos cannot
    /// become live TCP listeners. On the native/file/xDS path this field
    /// deserializes directly, so an OMITTED `protocol` falls back to
    /// `AppProtocol::default()` (`Unknown`) and defers at `resolve()` rather
    /// than being guessed onto the HTTP request path.
    #[serde(default)]
    pub protocol: AppProtocol,
    /// Istio `port.name` — informational; preserved for observability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Istio `bind` — the address the listener binds. Ferrum's capture model
    /// funnels all inbound through the shared `:15006` listener, so a custom
    /// `bind` does not create a separate OS listener; it is preserved for
    /// observability and surfaced as a documented limitation when non-default.
    /// Unix sockets are not valid here (Istio rejects them too).
    ///
    /// **Scope boundary (issue #3266):** arbitrary Sidecar ingress `bind`
    /// socket materialization is intentionally out of scope for stream-ingress
    /// modeling (#3260). Supported non-HTTP ingress still requires the shared
    /// capture-listener contract (orig-dst / authority selects the declared
    /// listener port). Do not treat a non-default `bind` as opening a dedicated
    /// socket here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<String>,
    /// Istio `defaultEndpoint` — where inbound traffic is forwarded. Supported
    /// forms (per Istio): `127.0.0.1:PORT`, `[::1]:PORT` (loopback),
    /// `0.0.0.0:PORT` / `[::]:PORT` (the instance IP, modeled as loopback in
    /// Ferrum's co-located-app deployment), and `unix:///absolute/path.sock`
    /// (a co-located Unix-domain stream socket, dialed by the Unix backend
    /// dispatch path). A `unix://` path that fails the admission rules in
    /// [`crate::util::unix_socket::validate_unix_socket_path`] — relative,
    /// traversal-like, over-long, control characters — fails closed (the entry
    /// is skipped at materialization and kept in the `deferred_fields` report)
    /// rather than being dialed.
    ///
    /// **Optional** in Istio (an entry may omit it — Istio then defers the
    /// listener). The native/file/xDS mesh model must mirror that: an omitted
    /// `defaultEndpoint` deserializes to the empty string and is deferred at
    /// `resolve()` (the empty value fails the `host:port` parse →
    /// `UnparseableEndpoint`), exactly like the K8s translation path which fills
    /// an empty string for an omitted field. Without `#[serde(default)]` an
    /// omitted field would fail DESERIALIZATION before validation could defer
    /// the listener — a native-path-only break the K8s path never hit.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_endpoint: String,
}

/// A resolved, routable form of one [`MeshSidecarIngress`] entry, computed at
/// slice-build time and carried on the slice so the DP materializer never
/// re-resolves the applicable Sidecar (raw `MeshSidecar` records do not ride
/// the slice — only the resolved local-inbound views do, mirroring
/// `local_inbound_services`).
///
/// Forward-derived (the listener port + the parsed `defaultEndpoint` +
/// protocol), never reconstructed by parsing materialized proxy ids.
/// Unsupported shapes (non-loopback, non-instance-IP `defaultEndpoint`; an
/// inadmissible `unix://` path; `Unknown`/`Udp` protocol) are dropped before
/// this is built and reported as deferred. HTTP-family entries materialize
/// inbound HTTP routes (including supported Unix backends); stream-family
/// entries materialize raw-TCP inbound relays (issue #3260).
///
/// The backend is one of TWO shapes and never both (see
/// [`ResolvedIngressListener::backend`]):
///   * **loopback TCP** — `endpoint_host` + `endpoint_port` set,
///     `endpoint_unix_path` absent;
///   * **Unix stream** — `endpoint_unix_path` set, `endpoint_host` empty and
///     `endpoint_port` zero.
///
/// The mutual exclusion is enforced by [`Self::endpoint_is_valid`] rather than
/// by the type, because this struct is decoded straight from untrusted carrier
/// JSON: a hostile carrier that set BOTH could otherwise smuggle a TCP fallback
/// alongside a socket path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedIngressListener {
    /// The declared listener port (the dialed/authority port used for
    /// per-port disambiguation on the shared inbound listener).
    pub port: u16,
    /// Backend host the route forwards to — always loopback (`127.0.0.1` or
    /// `::1`) in Ferrum's co-located-app sidecar model. EMPTY for a Unix-stream
    /// backend (see `endpoint_unix_path`).
    pub endpoint_host: String,
    /// Backend port parsed from `defaultEndpoint`. ZERO for a Unix-stream
    /// backend (see `endpoint_unix_path`).
    pub endpoint_port: u16,
    /// Application protocol that resolved.
    ///
    /// **No compatibility default.** The ECDS / native carrier is an untrusted
    /// decode boundary, so an OMITTED `protocol` deserializes to
    /// `AppProtocol::default()` (`Unknown`) — NOT to a live HTTP listener.
    /// `Unknown` fails [`Self::endpoint_is_valid`], so the back-projection
    /// chokepoint and the materializer both drop the entry before it can
    /// become a route or a relay. Same treatment as an explicitly hostile
    /// `Udp`/`unknown` protocol on the wire: a carrier that cannot say what a
    /// listener speaks never gets one.
    #[serde(default)]
    pub protocol: AppProtocol,
    /// Absolute filesystem path of the co-located Unix-domain STREAM socket
    /// this listener forwards to, parsed from a `unix:///path` `defaultEndpoint`
    /// and admitted by [`crate::util::unix_socket::validate_unix_socket_path`].
    ///
    /// Mutually exclusive with `endpoint_host`/`endpoint_port` (see the struct
    /// docs). `skip_serializing_if` keeps the wire shape byte-identical for the
    /// far more common loopback-TCP listener, so an older peer that never sees
    /// the field is unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_unix_path: Option<String>,
    /// Whether the Unix-stream backend speaks **h2c prior-knowledge** HTTP/2
    /// rather than HTTP/1.1, derived from the declared `port.protocol`:
    /// `http` → HTTP/1.1 (`false`); `http2`, `https` (which the Istio
    /// translator maps to `Http2`), and `grpc` → h2c (`true`).
    ///
    /// This is the ONLY thing that decides which client handshake the dispatch
    /// path performs on the socket, so it must never be guessed: an unmapped
    /// protocol is refused at [`MeshSidecarIngress::resolve`] before a listener
    /// exists. Meaningless — and never set — for a loopback-TCP listener, whose
    /// protocol negotiation is the ordinary backend-capability machinery.
    ///
    /// `skip_serializing_if` keeps the wire shape byte-identical for the far
    /// more common HTTP/1.1 listener.
    #[serde(default, skip_serializing_if = "is_false")]
    pub endpoint_unix_h2c: bool,
    /// Namespace of the local service whose host identity anchors the listener
    /// route. Carried so the materializer and the router/validator derive the
    /// SAME materialized proxy id forward (`mesh_ingress_proxy_id`) without
    /// re-running local-workload resolution.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_namespace: String,
    /// Name of the local service anchoring the listener route (see
    /// `owner_namespace`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_service: String,
}

/// The typed, routable backend one [`ResolvedIngressListener`] forwards to.
///
/// Constructed only by [`MeshSidecarIngress::resolve`] and
/// [`ResolvedIngressListener::backend`]. The former applies the shape and
/// syntax rules available to a control plane; the latter additionally applies
/// the data plane's configured containment roots. Callers at a materialization
/// or dial boundary must use `backend(allowed_roots)`, not treat a carried enum
/// or listener as evidence of local containment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshIngressBackend {
    /// A co-located loopback TCP backend (`127.0.0.1`/`::1` + nonzero port).
    Loopback { host: String, port: u16 },
    /// A co-located Unix-domain STREAM socket at a syntactically admitted
    /// absolute path. Values returned by `backend(allowed_roots)` are also
    /// contained by the supplied data-plane roots; CP-side `resolve()` cannot
    /// make that filesystem-local decision. `h2c` selects the client handshake:
    /// prior-knowledge HTTP/2 when true, HTTP/1.1 when false.
    Unix { path: String, h2c: bool },
}

impl ResolvedIngressListener {
    /// Re-validate a CARRIED resolved listener's backend endpoint against the
    /// same allowlists [`MeshSidecarIngress::resolve`] applies at resolution.
    ///
    /// A `ResolvedIngressListener` can arrive already resolved over the xDS /
    /// native slice carrier (`LocalIngressListeners`), where the
    /// `endpoint_host`/`endpoint_port`/`protocol`/`endpoint_unix_path` are decoded straight
    /// from untrusted wire JSON. A malformed or hostile carrier could therefore
    /// point a listener at an off-box host, a `:0` backend, or a traversal-like
    /// socket path that the raw `Sidecar` path would have deferred fail-closed.
    /// The inbound materializer re-checks this before dialing so the carrier
    /// path enforces the SAME invariants as resolution:
    ///   * nonzero LISTENER port on both shapes;
    ///   * loopback host (`127.0.0.1`/`::1`, the only forms `resolve()` ever
    ///     emits after collapsing the instance-IP wildcards) + nonzero backend
    ///     port for the TCP shape;
    ///   * an admitted, CONTAINED absolute socket path AND a vacant
    ///     `endpoint_host` / `endpoint_port` for the Unix shape, so a
    ///     both-shapes carrier cannot smuggle a TCP fallback past the Unix
    ///     dispatch gate.
    ///
    /// `allowed_roots` is the data plane's configured Unix-socket containment
    /// allowlist (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS`). It is a DATA-PLANE
    /// policy — a control plane does not share the workload's filesystem — so
    /// containment is enforced here, at materialization, and again at dial,
    /// rather than at CP-side `resolve()`. An EMPTY allowlist refuses every
    /// Unix listener; loopback-TCP listeners are unaffected by it.
    ///
    /// `pub` (like `MeshSidecarIngress::resolve`) so it is testable from the
    /// external mesh-validation test crate; it is a pure, side-effect-free
    /// validator over already-public fields.
    pub fn endpoint_is_valid(&self, allowed_roots: &[String]) -> bool {
        self.backend(allowed_roots).is_some()
    }

    /// The listener's backend SHAPE check, WITHOUT Unix-socket containment.
    ///
    /// Used only by the PeerAuthentication port-domain helpers, which care
    /// solely about the backend app PORT (a Unix listener has none and is
    /// filtered out by their own `endpoint_port != 0` rule). Never use it to
    /// decide whether a listener may be materialized or dialed — that is
    /// [`Self::endpoint_is_valid`]'s job, and only it applies containment.
    pub fn endpoint_shape_is_valid(&self) -> bool {
        self.backend_shape().is_some()
    }

    /// The typed backend this listener dials, or `None` when the carried fields
    /// fail the fail-closed admission rules described on
    /// [`Self::endpoint_is_valid`] — INCLUDING containment inside
    /// `allowed_roots` for the Unix shape.
    pub fn backend(&self, allowed_roots: &[String]) -> Option<MeshIngressBackend> {
        let backend = self.backend_shape()?;
        if let MeshIngressBackend::Unix { path, .. } = &backend {
            crate::util::unix_socket::admit_configured_path(path, allowed_roots).ok()?;
        }
        Some(backend)
    }

    /// Shape-only backend resolution: mutual exclusion, nonzero ports, loopback
    /// host, and the SYNTACTIC socket-path rules. Deliberately does NOT apply
    /// containment, so every containment decision has exactly one home
    /// ([`Self::backend`]).
    fn backend_shape(&self) -> Option<MeshIngressBackend> {
        if self.port == 0 || !is_modeled_ingress_app_protocol(self.protocol) {
            return None;
        }
        if let Some(path) = self.endpoint_unix_path.as_deref() {
            if !self.endpoint_host.is_empty() || self.endpoint_port != 0 {
                return None;
            }
            crate::util::unix_socket::validate_unix_socket_path(path).ok()?;
            let h2c = unix_backend_wire_protocol(self.protocol)?;
            if h2c != self.endpoint_unix_h2c {
                return None;
            }
            return Some(MeshIngressBackend::Unix {
                path: path.to_string(),
                h2c,
            });
        }
        // A loopback-TCP listener must not carry the Unix-only protocol marker:
        // a carrier that sets it is internally inconsistent, and admitting it
        // would let a future reader treat a TCP listener as an h2c socket one.
        if self.endpoint_unix_h2c {
            return None;
        }
        if self.endpoint_port == 0 {
            return None;
        }
        match self.endpoint_host.parse::<std::net::IpAddr>() {
            Ok(ip) if ip.is_loopback() => Some(MeshIngressBackend::Loopback {
                host: self.endpoint_host.clone(),
                port: self.endpoint_port,
            }),
            _ => None,
        }
    }

    /// Whether this resolved listener materializes on the HTTP inbound route
    /// lane (vs. the raw-TCP inbound relay lane).
    pub fn is_http_family(&self) -> bool {
        is_http_family_app_protocol(self.protocol)
    }

    /// Whether this resolved listener materializes as a raw-TCP inbound relay
    /// keyed by the declared listener port (issue #3260).
    pub fn is_stream_family(&self) -> bool {
        is_stream_family_app_protocol(self.protocol)
    }

    /// The admitted, CONTAINED Unix-socket path this listener dials, or `None`
    /// when it is a loopback-TCP listener (or fails admission).
    pub fn unix_socket_path(&self, allowed_roots: &[String]) -> Option<&str> {
        if !self.endpoint_is_valid(allowed_roots) {
            return None;
        }
        self.endpoint_unix_path.as_deref()
    }
}

/// Why a [`MeshSidecarIngress`] entry could not be modeled as a routable
/// inbound listener. Surfaced so the K8s status writer can keep the entry in
/// the Sidecar `deferred_fields` report rather than silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressListenerUnsupported {
    /// `defaultEndpoint` named a `unix://` socket whose PATH failed admission
    /// (relative, traversal-like, over-long, control characters, …). The
    /// wrapped rejection keeps the diagnostic field-specific instead of
    /// collapsing every bad socket path into one opaque reason.
    ///
    /// A well-formed `unix://` path is NOT reported here — it resolves into a
    /// routable Unix-stream backend.
    InvalidUnixSocketPath(crate::util::unix_socket::UnixSocketPathRejection),
    /// `defaultEndpoint` did not parse as a supported `host:port` (missing
    /// port, malformed, or an arbitrary non-loopback / non-instance IP).
    UnparseableEndpoint,
    /// `port` or the parsed endpoint port was `0`.
    ZeroPort,
    /// The listener protocol is not a modeled HTTP-family or stream-family
    /// token (`Unknown` typo / native omitted, or `Udp`). Historical name
    /// retained for status/test stability; stream protocols are modeled.
    NonHttpProtocol,
    /// The listener protocol is HTTP-family but Ferrum cannot speak it over a
    /// Unix stream, so a `unix://` `defaultEndpoint` for it is refused with a
    /// field-specific reason rather than materialized into a listener that
    /// would refuse every request at runtime (issue #3261).
    UnixProtocolUnsupported,
}

/// Which HTTP wire protocol Ferrum speaks to a Unix-stream backend for a given
/// declared listener protocol, or `None` when that protocol has no Unix-stream
/// dispatch at all.
///
/// `Some(false)` = HTTP/1.1, `Some(true)` = h2c prior-knowledge HTTP/2 (which
/// is what carries gRPC's request/response streaming, deadlines, cancellation,
/// and trailers). The `Http2` arm also covers Istio's `https`, which the K8s
/// ingress translator maps to `Http2`: a `defaultEndpoint` is a plaintext hop
/// to a co-located app, so TLS is not re-originated onto the socket.
///
/// Kept as an explicit total match over the HTTP-family set — adding an
/// `AppProtocol` variant must be a deliberate decision here, not a silent
/// inherit of HTTP/1.1.
pub(crate) fn unix_backend_wire_protocol(protocol: AppProtocol) -> Option<bool> {
    match protocol {
        AppProtocol::Http => Some(false),
        AppProtocol::Http2 | AppProtocol::Grpc => Some(true),
        _ => None,
    }
}

impl MeshSidecarIngress {
    /// Resolve this ingress entry into a routable [`ResolvedIngressListener`],
    /// or the reason it cannot be modeled. Fail-closed: anything that does not
    /// map cleanly onto a loopback host:port HTTP route or a syntactically
    /// admitted Unix-stream HTTP socket, or a loopback raw-TCP relay is
    /// rejected, never guessed. Unix containment is deliberately enforced
    /// later by the data plane.
    pub fn resolve(&self) -> Result<ResolvedIngressListener, IngressListenerUnsupported> {
        if !is_modeled_ingress_app_protocol(self.protocol) {
            return Err(IngressListenerUnsupported::NonHttpProtocol);
        }
        if self.port == 0 {
            return Err(IngressListenerUnsupported::ZeroPort);
        }
        let (endpoint_host, endpoint_port, endpoint_unix_path, endpoint_unix_h2c) =
            match parse_ingress_default_endpoint(&self.default_endpoint)? {
                MeshIngressBackend::Loopback { host, port } => (host, port, None, false),
                // The host:port pair is left VACANT for a Unix backend so the
                // carrier re-validation (`endpoint_is_valid`) can reject a
                // both-shapes carrier outright.
                MeshIngressBackend::Unix { path, .. } => {
                    // The wire protocol spoken on the socket is decided HERE,
                    // from the declared `port.protocol`, and never guessed at
                    // dispatch. `unix_backend_wire_protocol` returns `None` for
                    // any HTTP-family protocol Ferrum cannot actually speak over
                    // a Unix stream, which fails the entry closed with a
                    // field-specific reason instead of materializing a listener
                    // that would refuse every request at runtime.
                    let Some(h2c) = unix_backend_wire_protocol(self.protocol) else {
                        return Err(IngressListenerUnsupported::UnixProtocolUnsupported);
                    };
                    (String::new(), 0, Some(path), h2c)
                }
            };
        Ok(ResolvedIngressListener {
            port: self.port,
            endpoint_host,
            endpoint_port,
            protocol: self.protocol,
            endpoint_unix_path,
            endpoint_unix_h2c,
            // Stamped by the slice builder once the local service is known.
            owner_namespace: String::new(),
            owner_service: String::new(),
        })
    }

    /// Whether this entry counts toward the workload's DECLARED HTTP-family
    /// ingress listener port set — i.e. it names an HTTP-family protocol on a
    /// usable (nonzero) listener port, so it WOULD materialize an inbound route
    /// were its `defaultEndpoint` routable. This is the port-ambiguity predicate
    /// (a superset of [`resolve`](Self::resolve) success): it deliberately
    /// returns `true` for an HTTP-family entry whose endpoint is omitted /
    /// an inadmissible `unix://` / off-box (a `resolve()` failure), because such an entry STILL
    /// declared a distinct inbound listener port — so a partially materialized
    /// group must stay ambiguous to an orig-dst-less request rather than letting
    /// a surviving sibling absorb the skipped port's traffic (F6 §6.2). It
    /// excludes stream-family listeners (they use the raw-TCP inbound table,
    /// not HTTP sibling disambiguation), unrecognized/`Udp` protocols, and
    /// zero-port entries. The slice resolver dedups by port, so the DECLARED
    /// COUNT is over distinct HTTP-family ports, mirroring the resolved-set
    /// dedup.
    pub(crate) fn is_declared_http_family_listener(&self) -> bool {
        self.port != 0 && is_http_family_app_protocol(self.protocol)
    }
}

/// HTTP-family classification for Sidecar `ingress[]` listeners, shared by
/// ingress-listener resolution ([`MeshSidecarIngress::resolve`]) and the K8s
/// status writer's shared modeled-listener predicate,
/// kept here so the config model can resolve ingress entries without importing
/// the mode module and so the two callers can never disagree on whether a
/// listener is modeled as HTTP.
///
/// **Fail-closed on `Unknown`** (unlike the service-port default path's separate
/// `is_http_family_mesh_protocol`, which keeps the `unknown → HTTP` convention).
/// On the K8s path the raw `port.protocol` string is pre-classified by
/// `sidecar_ingress_app_protocol`, which maps `https` → `Http2` (routed),
/// recognized stream tokens to their `AppProtocol`, a missing protocol → `Tcp`
/// (stream-modeled), and an unrecognized typo → `Unknown` (deferred). The
/// native/file/xDS source stores `MeshSidecarIngress.protocol` directly via
/// serde, where an OMITTED `protocol` falls back to `AppProtocol::default()`
/// (`Unknown`) and an explicit `"unknown"` deserializes to `Unknown`. Treating
/// `Unknown` as HTTP-family there would materialize a custom inbound listener
/// the K8s translator (and the documented fail-closed rule) would have deferred.
pub fn is_http_family_app_protocol(protocol: AppProtocol) -> bool {
    matches!(
        protocol,
        AppProtocol::Http | AppProtocol::Http2 | AppProtocol::Grpc
    )
}

/// Stream-family classification for Sidecar `ingress[]` listeners (issue #3260):
/// raw TCP, opaque TLS, and the database protocols Ferrum already relays on the
/// service-port default inbound path. Shared by resolution and the K8s status
/// writer so a modeled stream listener is never falsely reported as deferred.
///
/// Excludes `Unknown` (typo / native omitted) and `Udp` (not REDIRECT-captured
/// TCP). Partitions with [`is_http_family_app_protocol`].
pub fn is_stream_family_app_protocol(protocol: AppProtocol) -> bool {
    matches!(
        protocol,
        AppProtocol::Tcp
            | AppProtocol::Tls
            | AppProtocol::Mongo
            | AppProtocol::Redis
            | AppProtocol::Mysql
            | AppProtocol::Postgres
    )
}

/// Whether a Sidecar `ingress[]` protocol is modeled on either inbound lane.
pub fn is_modeled_ingress_app_protocol(protocol: AppProtocol) -> bool {
    is_http_family_app_protocol(protocol) || is_stream_family_app_protocol(protocol)
}

/// Parse an Istio `defaultEndpoint` into the typed backend it names.
///
/// Supported (per Istio's "Arbitrary IPs are not supported" rule): loopback
/// (`127.0.0.1` / `::1`), the instance-IP wildcards (`0.0.0.0` / `::`) — which
/// in Ferrum's co-located-app sidecar model both resolve to loopback (the app
/// shares the pod network namespace) — and `unix:///absolute/path.sock`, whose
/// path must pass [`crate::util::unix_socket::validate_unix_socket_path`].
/// Arbitrary IPs and inadmissible socket paths are rejected fail-closed with a
/// field-specific reason.
fn parse_ingress_default_endpoint(
    endpoint: &str,
) -> Result<MeshIngressBackend, IngressListenerUnsupported> {
    if let Some(path) = endpoint.strip_prefix("unix://") {
        // Istio writes `unix://` + an ABSOLUTE path, so the canonical form is
        // the triple-slash `unix:///var/run/app.sock`. The leading `/` is part
        // of the path, and a value that lost it (`unix://var/run/app.sock`)
        // fails admission as `NotAbsolute` rather than being repaired.
        return match crate::util::unix_socket::validate_unix_socket_path(path) {
            Ok(()) => Ok(MeshIngressBackend::Unix {
                path: path.to_string(),
                // The wire protocol is not a property of the ENDPOINT string;
                // `resolve` fills it in from the declared `port.protocol`.
                h2c: false,
            }),
            Err(rejection) => Err(IngressListenerUnsupported::InvalidUnixSocketPath(rejection)),
        };
    }
    // `host:port` where host is an IP literal (IPv4 dotted, or bracketed IPv6).
    let socket: std::net::SocketAddr = endpoint
        .parse()
        .map_err(|_| IngressListenerUnsupported::UnparseableEndpoint)?;
    if socket.port() == 0 {
        return Err(IngressListenerUnsupported::ZeroPort);
    }
    let ip = socket.ip();
    let host = if ip.is_loopback() || ip.is_unspecified() {
        // `127.0.0.1`/`::1` (loopback) and `0.0.0.0`/`::` (instance IP) both
        // map to loopback for a co-located sidecar app. Preserve the address
        // family so an IPv6 endpoint dials `::1`.
        if ip.is_ipv6() { "::1" } else { "127.0.0.1" }
    } else {
        // Arbitrary IP — Istio forbids these and Ferrum's loopback-only model
        // can't honor them; fail closed rather than dial an off-box address.
        return Err(IngressListenerUnsupported::UnparseableEndpoint);
    };
    Ok(MeshIngressBackend::Loopback {
        host: host.to_string(),
        port: socket.port(),
    })
}

/// A single egress listener entry under a [`MeshSidecar`]. Carries the
/// Istio scope-host syntax (`namespace/host`) plus an optional port narrowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSidecarEgress {
    /// Egress hosts in Istio scope-host syntax:
    ///   - `*/*`           — allow everything (effectively no narrowing)
    ///   - `*/host`        — `host` in any namespace
    ///   - `./host`        — `host` in the Sidecar's own namespace
    ///   - `namespace/host` — `host` in the specified namespace
    ///   - `namespace/*`   — anything in the specified namespace
    pub hosts: Vec<String>,
    /// Optional Istio Port object; when set, narrows MeshService and
    /// ServiceEntry port lists during Sidecar egress slice projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Parsed Istio scope-host pattern (`<namespace_part>/<host_part>`).
///
/// Returned by [`MeshSidecarEgress::parse_host_pattern`]; centralises the
/// pattern-form for downstream matchers in [`crate::modes::mesh::slice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarHostPattern<'a> {
    /// `*/*` — allow everything.
    AllowAll,
    /// `*/host` — `host` in any namespace.
    AnyNamespaceHost { host: &'a str },
    /// `./host` — `host` in the Sidecar's own namespace.
    SameNamespaceHost { host: &'a str },
    /// `namespace/*` — anything in the specified namespace.
    NamespaceWildcard { namespace: &'a str },
    /// `namespace/host` — exact namespace + host.
    NamespaceHost { namespace: &'a str, host: &'a str },
    /// Bare `host` (no `/`): treated as same-namespace, matching the
    /// Istio convention when the namespace prefix is omitted.
    SameNamespaceHostBare { host: &'a str },
}

impl MeshSidecarEgress {
    /// Parse one `egress.hosts` entry into a [`SidecarHostPattern`].
    pub fn parse_host_pattern(host: &str) -> SidecarHostPattern<'_> {
        let trimmed = host.trim().trim_end_matches('.');
        match trimmed.split_once('/') {
            Some(("*", "*")) => SidecarHostPattern::AllowAll,
            Some(("*", host)) if !host.is_empty() && !host.contains('/') => {
                SidecarHostPattern::AnyNamespaceHost { host }
            }
            Some((".", host)) if !host.is_empty() && !host.contains('/') => {
                SidecarHostPattern::SameNamespaceHost { host }
            }
            Some((namespace, "*")) if !namespace.is_empty() => {
                SidecarHostPattern::NamespaceWildcard { namespace }
            }
            Some((namespace, host))
                if !namespace.is_empty() && !host.is_empty() && !host.contains('/') =>
            {
                SidecarHostPattern::NamespaceHost { namespace, host }
            }
            // Fallback: bare host — treat as same-namespace host.
            _ => SidecarHostPattern::SameNamespaceHostBare { host: trimmed },
        }
    }
}

// ── Multi-cluster ────────────────────────────────────────────────────────

/// Maximum number of remote clusters accepted in one mesh slice. Each remote
/// cluster may spawn federation and/or endpoint-discovery work, so keep the
/// fan-out explicitly bounded even though the source is a trusted CP/config.
pub const MAX_MESH_REMOTE_CLUSTERS: usize = 256;

/// Layer-10 multi-cluster mesh settings.
///
/// This is intentionally control-plane neutral. Istio CRDs, Gateway API,
/// native ConfigSync, xDS, file mode, and future CP-to-CP exchange all carry
/// the same canonical shape instead of talking past Layer 2.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MultiClusterConfig {
    /// Operator-facing name for the local cluster. When set, must be a
    /// canonical identifier with no leading/trailing whitespace (same identity
    /// domain as `RemoteCluster.name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_cluster: Option<String>,
    /// SPIFFE federation endpoint served by this control plane, when Ferrum
    /// is publishing bundles to remote clusters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
    /// Remote clusters whose services/workloads/bundles may be exchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_clusters: Vec<RemoteCluster>,
    /// SNI-routed east-west gateway backends. Mesh mode materializes these as
    /// passthrough TCP proxies only when topology is `east_west_gateway`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub east_west_gateways: Vec<EastWestGateway>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCluster {
    /// Canonical peer-cluster identity. Doubles as the remote-discovery JWT
    /// audience suffix (`ferrum-mesh-discovery:<name>`). Must not carry
    /// leading/trailing whitespace; uniqueness is enforced in that same
    /// identity domain so aliases cannot collapse onto one audience.
    pub name: String,
    pub trust_domain: TrustDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_plane_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_endpoint: Option<String>,
    /// Optional reference naming the per-remote discovery credential the data
    /// plane uses to authenticate to THIS remote cluster's control plane. The
    /// reference is resolved data-plane-side against
    /// `FERRUM_MESH_REMOTE_DISCOVERY_CREDENTIALS` (a JSON map of ref -> secret,
    /// itself resolvable through the external-secret backends). The raw secret
    /// is NEVER serialized into the slice/config — only this reference. When
    /// unset, discovery falls back to the shared CP-DP JWT secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_credential_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EastWestGateway {
    pub name: String,
    pub namespace: String,
    /// Backend host to which the east-west gateway forwards matched SNI.
    pub host: String,
    /// Backend port on `host`.
    pub port: u16,
    /// TLS SNI hosts routed through this gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sni_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomain>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

// ── DestinationRule ──────────────────────────────────────────────────────

/// Istio DestinationRule traffic policy mapped onto Ferrum primitives.
///
/// Each DestinationRule targets a service host and carries connection pool
/// settings, outlier detection, load balancer config, and optional subsets.
/// The mesh runtime applies these onto matching `Upstream` entries during
/// `prepare_gateway_config_for_mesh()`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshDestinationRule {
    pub name: String,
    pub namespace: String,
    /// Target service host (e.g., `reviews.default.svc.cluster.local`).
    pub host: String,
    /// Top-level traffic policy applied to all targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<MeshTrafficPolicy>,
    /// Per-destination-port traffic policy overrides. Keyed by destination
    /// port number; values override the corresponding fields of
    /// `traffic_policy` for traffic landing on that port. Mirrors Istio's
    /// `trafficPolicy.portLevelSettings[]`.
    ///
    /// Default empty → old DPs reading new slices ignore the field; new DPs
    /// reading old slices see an empty map (same behaviour as today).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_level_settings: HashMap<u16, MeshTrafficPolicy>,
    /// Named subsets with per-subset label selectors and optional policy
    /// overrides. Proxies reference these via `upstream_subset`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subsets: Vec<MeshSubset>,
    /// Export visibility from Istio `spec.exportTo` (issue #2465).
    ///
    /// Supported values are `*` (visible mesh-wide), `.` (visible only in this
    /// rule's own [`namespace`](Self::namespace)), and explicit namespace
    /// names. `~` and every other token is unsupported and rejected — see
    /// [`validate_mesh_export_to`].
    ///
    /// Omitted-versus-explicitly-empty is DEFINED, not guessed, and the two
    /// sources differ deliberately:
    ///
    /// * **Kubernetes**: an omitted (or explicitly empty) `spec.exportTo` is
    ///   translated into an explicit `["*"]`, preserving Istio's public
    ///   default.
    /// * **Native / file / xDS carrier**: an EMPTY list is namespace-local,
    ///   the same fail-closed-by-omission convention
    ///   [`ServiceEntry::export_to`] and
    ///   [`MeshVirtualServiceCorsPolicy::export_to`] already use. Write
    ///   `["*"]` to publish a rule mesh-wide on those sources.
    ///
    /// Visibility is evaluated by [`destination_rule_exported_to_namespace`]
    /// BEFORE lookup-tier selection and before a per-node slice is serialized,
    /// so a namespace-local rule never reaches a subscriber outside its
    /// declared visibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_to: Vec<String>,
}

/// Traffic policy controlling connection pool, outlier detection, and LB.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshTrafficPolicy {
    /// Backend connect timeout in milliseconds
    /// (from `connectionPool.tcp.connectTimeout`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Outlier detection (maps to Ferrum PassiveHealthCheck).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outlier_detection: Option<MeshOutlierDetection>,
    /// Load balancer configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer: Option<MeshLoadBalancer>,
    /// Optional backend TLS override from `DestinationRule.trafficPolicy.tls`.
    ///
    /// When `None` (default) the workload's `PeerAuthentication`-derived
    /// mTLS posture continues to apply. When `Some(...)` the DR settings
    /// win at cold-path apply time: `apply_traffic_policy_to_upstream`
    /// projects them onto the matching `Upstream`'s `backend_tls_*` fields.
    /// Old DPs reading new slices see this as a no-op (serde defaults to
    /// `None`); new DPs reading old slices behave identically to today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<MeshTrafficPolicyTls>,
    /// Optional `DestinationRule.trafficPolicy.localityLbSetting`. When
    /// present, the mesh apply layer projects this onto the resolved
    /// `Upstream.locality_lb_setting`; the load balancer then honours
    /// mutually exclusive `distribute` weights, `failover` region overrides,
    /// or ordered `failover_priority` label tiers. Failover-priority tiers
    /// replace the existing exact/zone/region preference only when applicable
    /// active/passive health enables failover; otherwise they remain inert.
    /// Old DPs reading new slices see this as a no-op via the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality_lb_setting: Option<MeshLocalityLbSetting>,
    /// Cap on concurrent OPEN backend connections per destination, mapped from
    /// Istio `connectionPool.tcp.maxConnections`. Enforced by every transport
    /// whose physical connection lifecycle Ferrum owns: stream-family (TCP /
    /// TCP+TLS), HTTP-family WebSocket, the pooled multiplexed transports
    /// (direct H2, gRPC, native H3, HBONE, mesh-mTLS), and known-HTTP/1.1
    /// reqwest dispatch. `Some(0)` is rejected by validation on both the K8s
    /// and native/file paths because it would refuse every connection.
    /// Old DPs reading new slices see this as a no-op via the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// TCP keepalive overrides mapped from Istio
    /// `connectionPool.tcp.tcpKeepalive`. Each subfield is independently
    /// optional. Currently applied only by stream-family backend dispatch on
    /// the newly connected backend socket (HTTP-family dispatch is a
    /// follow-on PR). Old DPs reading new slices see this as a no-op via
    /// the serde default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keepalive: Option<crate::config::types::TcpKeepaliveCfg>,
    /// Optional `DestinationRule.trafficPolicy.connectionPool.http` block.
    /// When present, the K8s translator has parsed at least one supported HTTP
    /// connection-pool knob (`idleTimeout`, `http2MaxRequests`,
    /// `h2UpgradePolicy`, `maxRetries`, `http1MaxPendingRequests`); the mesh
    /// apply layer accumulates top-level values on the upstream's inherited
    /// fallback and stores explicit `portLevelSettings` values separately in
    /// `port_overrides[port]`; dispatch merges them field-by-field with the
    /// per-port tier first. Old DPs reading new slices see this as a no-op via
    /// the serde default.
    ///
    /// `maxRequestsPerConnection` may still deserialize for carrier/backward
    /// compatibility, but new K8s translation warns, reports it as deferred, and
    /// does not populate this overlay field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_pool_http: Option<MeshConnectionPoolHttp>,
}

/// Subset of Istio `ConnectionPoolSettings.HTTPSettings` parsed and
/// projected by the gateway. Each field is independently optional so the
/// translator can express "operator set N of M fields"; the apply pass
/// only overlays fields that are `Some`. See
/// [`crate::config::types::UpstreamPortOverride`] for the corresponding
/// resolved slots and dispatch wiring.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshConnectionPoolHttp {
    /// Deprecated carrier for `maxRequestsPerConnection`. New K8s translation
    /// validates and warns on the field, reports it as deferred, and does not
    /// populate this slot because Ferrum has no backend close-after-N-requests
    /// behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_requests_per_connection: Option<u32>,
    /// Mapped from `idleTimeout` (parsed as an Istio duration, persisted
    /// as milliseconds). Translator rejects sub-second durations because
    /// the proxy-level `pool_idle_timeout_seconds` field is whole-second
    /// granular and silently rounding `500ms` would not match the
    /// operator's intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
    /// Mapped from `http2MaxRequests`. Projects to
    /// `Proxy.pool_http2_max_concurrent_streams` per port via
    /// `resolve_effective_proxy_for_target` and threads into the H2/gRPC
    /// builder knobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2_max_requests: Option<u32>,
    /// Mapped from `h2UpgradePolicy`. Controls whether plain-HTTP backend
    /// dispatch upgrades to HTTP/2. Projects onto
    /// `Proxy.h2_upgrade_policy` per port and is consulted at the
    /// plain-HTTPS H2-vs-H1 dispatch fork in `proxy_to_backend`. Does NOT
    /// affect gRPC (always H2) or HBONE/mesh-mTLS transport selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_upgrade_policy: Option<crate::config::types::H2UpgradePolicy>,
    /// Mapped from `maxRetries`. Interpreted as a per-request retry-count
    /// CAP (an upper bound on `Proxy.retry.max_retries`), NOT Envoy's
    /// cluster-wide outstanding-retry concurrency budget — see the honest
    /// semantics note in `docs/mesh.md` and `route_retry_ceiling` /
    /// `retry_attempt_allowed_for_target` in `src/proxy/mod.rs`. When a proxy
    /// already carries a retry policy the effective budget for a target is
    /// `min(original_route_ceiling, this)`; when no policy exists this field
    /// does NOT synthesize one (an Istio `maxRetries` is a budget, not a
    /// retry-policy enabler). Zero explicitly disables an existing retry
    /// policy for the selected destination. The original route ceiling stays
    /// available across rotation; retry loops re-resolve the candidate's cap
    /// before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    /// Mapped from `http1MaxPendingRequests`. Honestly reinterpreted as the
    /// maximum concurrent in-flight requests for a backend destination on the
    /// HTTP/1.1 dispatch path. Projects onto the inherited/per-port dispatch
    /// policy and is enforced per `(host, policy port, selected subset)`: when
    /// full a new H1 request is shed with a 503 ("upstream overflow" in Envoy
    /// terms).
    /// HTTP/1.1-scoped: it does NOT gate
    /// direct-H2 / gRPC / HTTP/3 / HBONE / mesh-mTLS dispatch (those use
    /// `http2MaxRequests` → `h2_max_concurrent_streams` for concurrency).
    /// Always positive when set (zero/negative rejected at translate time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http1_max_pending_requests: Option<u32>,
}

/// `DestinationRule.trafficPolicy.tls` settings mapped from Istio's
/// `ClientTLSSettings` (`networking.istio.io/v1beta1`).
///
/// Carries the originating-client TLS mode plus optional SNI, CA, client
/// cert/key, SAN verification list, and an `insecureSkipVerify` escape
/// hatch. The cold-path apply at `apply_traffic_policy_to_upstream`
/// projects these onto the `Upstream` `backend_tls_*` fields when set.
///
/// `Default::default()` returns a `Simple`-mode block (matches Istio's
/// `ClientTLSSettings.mode` default and avoids the `MtlsMode::Permissive`
/// server-side default that the derived `Default` would otherwise produce —
/// a `MeshTrafficPolicyTls` with a server-side mode is treated as a
/// programming error by the cold-path apply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshTrafficPolicyTls {
    /// DR client-side TLS mode: `Disable` / `Simple` / `Mutual` / `IstioMutual`.
    ///
    /// Defaults to `Simple` when omitted, matching Istio's `ClientTLSSettings.mode`
    /// default and the `translate_client_tls_settings` translator behavior. Without
    /// this default, a hand-authored or partially-updated slice such as
    /// `{ "tls": { "sni": "..." } }` would fail to deserialize even though Istio
    /// defaulting semantics treat it as `SIMPLE`.
    #[serde(default = "default_client_tls_mode")]
    pub mode: MtlsMode,
    /// Optional Server Name Indication value for backend TLS origination.
    /// Cold-path DestinationRule application projects this onto
    /// `Upstream.backend_tls_sni` and then into `Proxy.resolved_tls` so the
    /// backend handshake layer can consume the cached value when wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Optional path to a PEM CA bundle for verifying the backend server's
    /// certificate (Istio `caCertificates`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificates: Option<String>,
    /// Optional path to a PEM client certificate for mTLS with the backend
    /// (Istio `clientCertificate`). Required when `mode == Mutual`; must be
    /// absent when `mode == IstioMutual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate: Option<String>,
    /// Optional path to a PEM private key for mTLS with the backend
    /// (Istio `privateKey`). Required when `mode == Mutual`; must be
    /// absent when `mode == IstioMutual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Optional list of acceptable Subject Alternative Names for the
    /// backend's server certificate (Istio `subjectAltNames`). Cold-path
    /// DestinationRule application projects this onto
    /// `Upstream.backend_tls_san_allow_list` and then into
    /// `Proxy.resolved_tls` so certificate-verifier enforcement can consume
    /// the cached value when wired.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_alt_names: Vec<String>,
    /// When true, suppress server-cert verification on the backend handshake
    /// (Istio `insecureSkipVerify`). Maps to
    /// `Upstream.backend_tls_verify_server_cert = false`.
    #[serde(default = "default_insecure_skip_verify")]
    pub insecure_skip_verify: bool,
}

fn default_insecure_skip_verify() -> bool {
    false
}

fn default_client_tls_mode() -> MtlsMode {
    MtlsMode::Simple
}

impl Default for MeshTrafficPolicyTls {
    fn default() -> Self {
        // Use a client-side default (`Simple`) instead of the derived
        // `MtlsMode::default() == Permissive` so that `..Default::default()`
        // in callers / tests always produces a value that the cold-path
        // apply treats as a valid DR.tls mode. `Simple` also matches Istio's
        // own `ClientTLSSettings.mode` default when the block is present but
        // `mode` is omitted. Shares the `default_client_tls_mode` helper with
        // the serde field default so the two cannot drift.
        Self {
            mode: default_client_tls_mode(),
            sni: None,
            ca_certificates: None,
            client_certificate: None,
            private_key: None,
            subject_alt_names: Vec::new(),
            insecure_skip_verify: default_insecure_skip_verify(),
        }
    }
}

/// Outlier detection settings from Istio DestinationRule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshOutlierDetection {
    /// Number of consecutive errors before ejecting a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consecutive_errors: Option<u32>,
    /// Detection interval in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u64>,
    /// Base ejection duration in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_ejection_seconds: Option<u64>,
    /// Maximum percentage of hosts that can be ejected (0-100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ejection_percent: Option<u8>,
}

/// Load balancer configuration from Istio DestinationRule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshLoadBalancer {
    /// Simple algorithm selection.
    Simple(MeshSimpleLb),
    /// Consistent hash configuration.
    ConsistentHash(MeshConsistentHash),
}

/// Simple LB algorithm names matching Istio's enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeshSimpleLb {
    RoundRobin,
    LeastRequest,
    Random,
    Passthrough,
}

/// Consistent hash key source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshConsistentHash {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_cookie_name: Option<String>,
    #[serde(default)]
    pub use_source_ip: bool,
}

/// Istio `DestinationRule.trafficPolicy.localityLbSetting` mapped onto
/// Ferrum primitives.
///
/// `enabled` defaults to `true` when the block is present (matches Istio
/// semantics — an explicit `enabled: false` disables locality-aware LB
/// entirely, including the priority-tier preference projected by
/// `Upstream.source_locality`). Exactly one of `distribute`, `failover`,
/// or `failover_priority` may be set (Istio mutual exclusivity). When a
/// `distribute` entry matches the source locality the load balancer uses
/// per-locality weights and ignores the priority-tier preference;
/// otherwise `failover` (when configured) adds a fourth tier consulted
/// after `region` and before the unfiltered fallback set. When
/// `failover_priority` is set and applicable active/passive health enables
/// failover, it replaces the default region/zone/subzone tiers with ordered
/// workload-label priority tiers. Without that signal it is inert.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshLocalityLbSetting {
    /// When `false`, disables all locality preference (priority tier,
    /// distribute weighting, failover override, and failover-priority
    /// tiers). Defaults to `true`.
    #[serde(default = "default_true_bool")]
    pub enabled: bool,
    /// Per-source-locality weighted distribution to target localities.
    /// Each entry's `to` map values are integer weights (Istio specifies
    /// 0-100 as a percentage). Targets in localities not named by any
    /// matching `to` map are excluded from selection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribute: Vec<MeshLocalityDistribute>,
    /// Per-source-region failover targets. Consulted when no healthy
    /// target exists in the source's exact/zone/region tiers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failover: Vec<MeshLocalityFailover>,
    /// Ordered Istio `failoverPriority` label keys (`key`) or key/value
    /// overrides containing exactly one equals sign (`key=value`). Mutually
    /// exclusive with `distribute` and `failover`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failover_priority: Vec<String>,
}

fn default_true_bool() -> bool {
    true
}

impl Default for MeshLocalityLbSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            distribute: Vec::new(),
            failover: Vec::new(),
            failover_priority: Vec::new(),
        }
    }
}

/// One `localityLbSetting.distribute[]` entry.
///
/// `from` is an Istio-style `region/zone/subzone` locality string. `to`
/// maps target localities (same syntax) to integer weights. Istio's API
/// treats the values as percentages summing to 100; we propagate the
/// integers verbatim and use them as ratios so non-summing operator
/// configurations still produce a deterministic ratio split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLocalityDistribute {
    pub from: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub to: std::collections::BTreeMap<String, u32>,
}

/// One `localityLbSetting.failover[]` entry. `from` and `to` are Istio
/// region names (the first `region/zone/subzone` segment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshLocalityFailover {
    pub from: String,
    pub to: String,
}

/// Named subset of targets with label selectors and optional policy override.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshSubset {
    pub name: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<MeshTrafficPolicy>,
}

// ── VirtualService-derived CORS policies (issue #1973) ─────────────────────

/// A host-level CORS policy derived from Istio VirtualService
/// `http[].corsPolicy`, carried on the mesh slice so a sidecar DP can
/// synthesize a `cors` plugin instance onto its materialized OUTBOUND routes
/// (Istio applies VirtualService policy on the client sidecar).
///
/// This is the narrow route-policy slice carriage that unblocks live VS CORS
/// on mesh sidecars: the VS-derived `cors` plugin itself lands on HTTP-family
/// `GatewayConfig` proxies, which do not ride the slice (the dedicated
/// `MeshSlice::virtual_service_l4_proxies` field carries only L4 routes).
/// Application is
/// HOST-LEVEL — match-scoped per-route CORS from multiple `http[]` entries is
/// intentionally out of scope for mesh routes (materialized routes are
/// host-routed `/`; the K8s translator carries the first corsPolicy-bearing
/// `http[]` entry per host).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshVirtualServiceCorsPolicy {
    /// Source resource name (diagnostics only).
    pub name: String,
    /// Source resource namespace; also the namespace `host` short names
    /// resolve against, exactly like `MeshDestinationRule.namespace`.
    pub namespace: String,
    /// Target service host (bare name, `name.namespace`, or FQDN) — matched
    /// against materialized outbound services with DestinationRule host
    /// semantics.
    pub host: String,
    /// VirtualService `exportTo` visibility, honored by slice narrowing with
    /// the SAME semantics as [`ServiceEntry.export_to`]: `*` = every
    /// namespace, `.` = the policy's own namespace, otherwise an explicit
    /// namespace list. EMPTY is namespace-local (Ferrum's conservative
    /// convention for hand-written sources — no cross-tenant exposure by
    /// omission); the K8s translator writes `["*"]` for an omitted
    /// `spec.exportTo` so Istio's public default is preserved explicitly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub export_to: Vec<String>,
    pub cors: MeshCorsPolicy,
}

/// Returns true when a VirtualService-derived CORS policy is visible to a
/// workload namespace — the [`service_entry_exported_to_namespace`] rules
/// applied to the carried `export_to` field.
///
/// Routes through the ONE shared evaluator `export_visibility_admits`, so
/// ServiceEntry, DestinationRule, and VirtualService-derived CORS can never
/// drift apart on what `.`, `*`, an explicit namespace, or an EMPTY list
/// means. `validate_virtual_service_cors_policies` runs the same
/// [`validate_mesh_export_to`] fail-closed boundary check DestinationRules
/// get, while config-source normalization canonicalizes accepted entries
/// before this evaluator sees them. The evaluator itself never reinterprets
/// unnormalized input.
pub fn virtual_service_cors_policy_exported_to_namespace(
    policy: &MeshVirtualServiceCorsPolicy,
    workload_namespace: &str,
) -> bool {
    export_visibility_admits(&policy.export_to, &policy.namespace, workload_namespace)
}

/// The Istio `corsPolicy` fields Ferrum projects onto the `cors` plugin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshCorsPolicy {
    /// Origin matchers (Istio `allowOrigins[]` StringMatch). At least one is
    /// required — a CORS policy that can never match an origin is a config
    /// error, not a silent no-op.
    pub allowed_origins: Vec<MeshCorsOriginMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exposed_headers: Vec<String>,
    /// Preflight cache lifetime (Istio `maxAge`, seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
    /// Credentialed CORS is unrepresentable with an exact `*` origin because
    /// the native plugin's wildcard response cannot safely retain credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<bool>,
    /// Preserve the Istio source field's presence and value. Omission and
    /// explicit `FORWARD` are behaviorally identical but remain distinct on
    /// the mesh wire; both synthesize the plugin's explicit forward mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmatched_preflights: Option<MeshCorsUnmatchedPreflights>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshCorsUnmatchedPreflights {
    Forward,
    Ignore,
}

/// One Istio `StringMatch` origin matcher. Hand-written serde keeps the wire
/// shape a SINGLE-KEY MAP (`{exact: ...}` / `{prefix: ...}` / `{regex: ...}`)
/// in BOTH YAML and JSON — a derived externally-tagged enum would demand
/// `!exact` YAML tags on the file source — and enforces the Istio
/// `StringMatch` contract fail-closed: exactly one recognized key, a string
/// value, nothing else (`{exact: "a", regex: "b"}` is rejected, never
/// approximated by dropping a key).
#[derive(Debug, Clone, PartialEq)]
pub enum MeshCorsOriginMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
}

impl Serialize for MeshCorsOriginMatch {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let (key, value) = match self {
            MeshCorsOriginMatch::Exact(value) => ("exact", value),
            MeshCorsOriginMatch::Prefix(value) => ("prefix", value),
            MeshCorsOriginMatch::Regex(value) => ("regex", value),
        };
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(key, value)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for MeshCorsOriginMatch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let entries = std::collections::BTreeMap::<String, String>::deserialize(deserializer)?;
        if entries.len() != 1 {
            return Err(D::Error::custom(
                "CORS origin matcher must carry exactly one of `exact`, `prefix`, or `regex`",
            ));
        }
        let Some((key, value)) = entries.into_iter().next() else {
            // Unreachable after the len==1 check; keep the parse fail-closed
            // rather than panicking on a config path.
            return Err(D::Error::custom(
                "CORS origin matcher must carry exactly one of `exact`, `prefix`, or `regex`",
            ));
        };
        match key.as_str() {
            "exact" => Ok(MeshCorsOriginMatch::Exact(value)),
            "prefix" => Ok(MeshCorsOriginMatch::Prefix(value)),
            "regex" => Ok(MeshCorsOriginMatch::Regex(value)),
            other => Err(D::Error::custom(format!(
                "unknown CORS origin matcher `{other}` (expected `exact`, `prefix`, or `regex`)"
            ))),
        }
    }
}

/// Project the typed policy onto the `cors` plugin's config schema
/// (`src/plugins/cors.rs`): every matcher is a single-key object, including
/// `exact`, which selects the plugin's LITERAL matcher (issue #3254). Emitting
/// an exact as a plain string would select the plugin's NATIVE syntax instead,
/// canonicalizing the value and reading a leading `*` as wildcard-subdomain
/// syntax — silently widening a carried `*.example.com` to every subdomain.
/// The emitted shape is byte-for-byte the shape the K8s translator's
/// gateway-side `route_cors_plugin` emits, pinned by a unit test so the two
/// projections can never drift. The synthesized config always carries
/// `unmatched_preflights`, which selects Istio semantics without changing the
/// defaults of operator-authored direct plugin configurations.
pub fn cors_plugin_config_from_mesh_policy(policy: &MeshCorsPolicy) -> serde_json::Value {
    let origins: Vec<serde_json::Value> = policy
        .allowed_origins
        .iter()
        .map(|origin| match origin {
            MeshCorsOriginMatch::Exact(value) => serde_json::json!({ "exact": value }),
            MeshCorsOriginMatch::Prefix(value) => serde_json::json!({ "prefix": value }),
            MeshCorsOriginMatch::Regex(value) => serde_json::json!({ "regex": value }),
        })
        .collect();
    let mut config = serde_json::Map::new();
    config.insert(
        "allowed_origins".to_string(),
        serde_json::Value::from(origins),
    );
    config.insert(
        "allowed_methods".to_string(),
        serde_json::json!(policy.allowed_methods),
    );
    config.insert(
        "allowed_headers".to_string(),
        serde_json::json!(policy.allowed_headers),
    );
    config.insert(
        "exposed_headers".to_string(),
        serde_json::json!(policy.exposed_headers),
    );
    if let Some(max_age) = policy.max_age_seconds {
        config.insert("max_age".to_string(), serde_json::json!(max_age));
    }
    if let Some(allow_credentials) = policy.allow_credentials {
        config.insert(
            "allow_credentials".to_string(),
            serde_json::Value::Bool(allow_credentials),
        );
    }
    config.insert(
        "unmatched_preflights".to_string(),
        serde_json::Value::String(
            match policy
                .unmatched_preflights
                .unwrap_or(MeshCorsUnmatchedPreflights::Forward)
            {
                MeshCorsUnmatchedPreflights::Forward => "forward",
                MeshCorsUnmatchedPreflights::Ignore => "ignore",
            }
            .to_string(),
        ),
    );
    serde_json::Value::Object(config)
}

// ── Top-level mesh config container ───────────────────────────────────────

/// All mesh-specific configuration, kept in a single container so the
/// core `GatewayConfig` struct stays lean for non-mesh deployments.
/// Stored as `Option<Box<MeshConfig>>` on `GatewayConfig` — `None` when
/// the operator has no mesh resources, zero cost in that case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Istio root namespace used for mesh-wide policy resources and
    /// cluster-wide Sidecar defaults. Native mesh YAML can override it;
    /// Kubernetes translation fills it from `K8sTranslationOptions`.
    #[serde(
        default = "default_istio_root_namespace",
        skip_serializing_if = "is_default_istio_root_namespace"
    )]
    pub istio_root_namespace: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<Workload>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshService>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_policies: Vec<MeshPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_authentications: Vec<PeerAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_entries: Vec<ServiceEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_authentications: Vec<MeshRequestAuthentication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub telemetry_resources: Vec<MeshTelemetryResource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_rules: Vec<MeshDestinationRule>,
    /// VirtualService-derived host-level CORS policies (issue #1973). The
    /// sidecar DP synthesizes per-route `cors` plugin instances onto its
    /// materialized outbound routes from these. Populated by the K8s
    /// translator from `http[].corsPolicy` and directly expressible on the
    /// file source; rides its own xDS ECDS carrier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_service_cors_policies: Vec<MeshVirtualServiceCorsPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_configs: Vec<MeshProxyConfig>,
    /// Istio `Sidecar` egress-scoping resources. Used by the slice builder
    /// to narrow which services / service-entries / destination-rules a
    /// workload sees. Narrowing is gated by `FERRUM_MESH_SIDECAR_ENFORCED`
    /// (default `false`) — when disabled the field is parsed and persisted
    /// but slice narrowing is skipped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<MeshSidecar>,
    /// GAMMA Waypoint bindings: a list mapping waypoint names to the set
    /// of services routed through that waypoint. Populated by the K8s
    /// translator from `Gateway` resources whose `gatewayClassName` is
    /// `istio-waypoint` / `ferrum-waypoint` plus `Service` objects
    /// annotated with `istio.io/use-waypoint`. The slice builder consumes
    /// this map when `MeshSliceRequest.waypoint_name == Some(name)` to
    /// narrow `services` / `service_entries` / `destination_rules` /
    /// `workloads` to entries bound to the named waypoint. Empty default
    /// keeps non-mesh and non-waypoint deployments at zero overhead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waypoint_bindings: Vec<MeshWaypointBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<TrustBundleSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_cluster: Option<MultiClusterConfig>,
    /// Mirrors Istio `MeshConfig.outboundTrafficPolicy.mode`. `None` keeps
    /// the legacy `AllowAny` behavior (no gate). When set to `RegistryOnly`,
    /// the mesh outbound dispatcher rejects requests whose destination does
    /// not appear in the slice-derived known-destinations registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_traffic_policy: Option<OutboundTrafficPolicy>,
    /// Operator-defined ECDS resources served by the ADS translator as
    /// `envoy.config.core.v3.TypedExtensionConfig` payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extension_configs: Vec<crate::modes::mesh::slice::MeshExtensionConfig>,
    /// Runtime-only CP-derived NodeWaypoint assertor inventory. The CP fills
    /// this before request-specific workload narrowing so destination slices can
    /// still trust legitimate source node-waypoint identities. `serde(skip)`:
    /// never operator-settable, never serialized on raw `GatewayConfig`; the
    /// narrowed `MeshSlice.node_waypoint_assertors` field carries it over the
    /// mesh subscription transports.
    #[serde(skip)]
    pub node_waypoint_assertors: Vec<SpiffeId>,
    /// Runtime-only NodeWaypoint transparent-inbound-capture destination
    /// inventory (issue #3287). CP-side this is resolved BEFORE the
    /// request-namespace retains, with CP scope and bearer-namespace
    /// authorization applied, so a NodeWaypoint can resolve an enrolled pod in
    /// another authorized namespace. DP-side it is back-projected from
    /// `MeshSlice.node_waypoint_capture_destinations`.
    ///
    /// `serde(skip)`: never operator-settable and never on the `config_json`
    /// wire — the narrowed slice field is the only transport. Consumed ONLY by
    /// `crate::proxy::resolve_node_waypoint_capture_destination`; it must never
    /// be folded into `workloads` (that would widen routing / known-destination
    /// visibility across namespaces).
    #[serde(skip)]
    pub node_waypoint_capture_destinations: Vec<Workload>,
    /// Runtime-only PeerAuthentication candidates applicable to
    /// [`Self::node_waypoint_capture_destinations`] (issue #3287). Resolved
    /// alongside that inventory and, like it, never folded into
    /// `peer_authentications` (which stays the subscription-namespace view that
    /// governs this proxy's OWN inbound posture). `serde(skip)` for the same
    /// reason.
    #[serde(skip)]
    pub node_waypoint_capture_peer_authentications: Vec<PeerAuthentication>,
    /// Runtime-only back-projection of the slice's narrowed **local-inbound**
    /// service view (`MeshSlice.local_inbound_services`), set by mesh
    /// preparation. `Some` exactly when Sidecar narrowing resolved the local
    /// view (mirroring `MeshSlice.local_inbound_workloads` semantics — an
    /// empty `Some` means the local identity was ambiguous and nothing
    /// materialized); `None` means no narrowing applied and consumers fall
    /// back to `services`. The router's INBOUND per-port sibling grouping and
    /// the listen-path uniqueness exemption read this so they see the same
    /// service view `materialize_sidecar_inbound_proxies` consumed — `services`
    /// is the EGRESS-narrowed view and can lack the local service entirely.
    /// `serde(skip)`: never operator-settable, never serialized, and — per the
    /// egress-scope security rule — never folded into `services` (the
    /// outbound registry / egress scope must not widen to the local service).
    #[serde(skip)]
    pub local_inbound_services: Option<Vec<MeshService>>,
    /// Runtime-only back-projection of the slice's resolved Sidecar `ingress[]`
    /// custom inbound listeners (`MeshSlice.local_ingress_listeners`), set by
    /// mesh preparation. The router's INBOUND per-port sibling grouping and the
    /// listen-path uniqueness exemption read this (via
    /// `mesh_ingress_listener_groups`) so they see the same listeners
    /// `materialize_sidecar_inbound_proxies` materialized. `serde(skip)`: never
    /// operator-settable, never serialized.
    #[serde(skip)]
    pub local_ingress_listeners: Vec<ResolvedIngressListener>,
    /// Runtime-only back-projection of `MeshSlice.sidecar_ingress_declared`.
    /// This is deliberately separate from `local_ingress_listeners`: an
    /// explicit empty block, an all-unsupported block, or a carrier whose
    /// entries all fail re-validation still replaces the ordinary Sidecar
    /// inbound surface. The authenticated CONNECT boundary reads this marker
    /// so those cases deny rather than falling through to the transparent
    /// relay and dialing a port the operator removed. `serde(skip)`: never
    /// operator-settable, never serialized.
    ///
    /// Back-projected under `MeshTopology::Sidecar` ONLY, matching the inbound
    /// materializer this marker gates. `FERRUM_MESH_SIDECAR_ENFORCED` is
    /// topology-independent, so an Ambient/Waypoint proxy can be handed a slice
    /// whose applicable Sidecar declares `ingress[]` — and those topologies
    /// materialize no inbound routes at all, so honoring the marker there would
    /// deny every transparent-relay CONNECT instead of replacing a surface.
    #[serde(skip)]
    pub sidecar_ingress_declared: bool,
    /// Runtime-only back-projection of `MeshSlice.declared_ingress_http_ports`
    /// (F6 §6.2), set by mesh preparation. The count of DISTINCT HTTP-family
    /// `ingress[]` listener ports the workload DECLARED — which can EXCEED
    /// `local_ingress_listeners.len()` when an HTTP-family entry's
    /// `defaultEndpoint` is unroutable. `mesh_ingress_listener_groups` uses it as
    /// the ingress group's `declared_http_ports` so a partially materialized
    /// group stays AMBIGUOUS to an orig-dst-less request (fail closed) instead of
    /// the surviving sibling absorbing the skipped port's traffic. `serde(skip)`:
    /// never operator-settable, never serialized.
    #[serde(skip)]
    pub declared_ingress_http_ports: usize,
    /// Runtime-only back-projection of local Sidecar stream-family inbound
    /// routes. The accept loop indexes these by captured original-destination
    /// app port before handing plaintext inbound streams to Hyper, so raw TCP
    /// protocols never need HTTP route parsing. `serde(skip)`: never
    /// operator-settable, never serialized.
    #[serde(skip)]
    pub local_inbound_tcp_routes: Vec<MeshInboundTcpRoute>,
    /// Runtime-only back-projection of the unambiguously resolved local
    /// service workload set's addresses, taken
    /// from `MeshSlice.local_inbound_workloads` (the un-narrowed local-inbound
    /// view) and canonicalized for comparison (IPv4-mapped IPv6 folded).
    ///
    /// Deliberately NOT `workloads`: that is the subscription-NAMESPACE view
    /// and contains unrelated pods. This set can include sibling replicas of
    /// the one resolved service, so the authenticated CONNECT boundary also
    /// requires the authority host to equal the accepted socket's actual local
    /// IP. Together those checks prove the peer reached the pod it named before
    /// the dial may be remapped onto a local `ingress[]` `defaultEndpoint`
    /// (issue #3260). Empty ⇒ no local identity resolved, and the remap is
    /// refused. `serde(skip)`: never operator-settable, never serialized.
    #[serde(skip)]
    pub local_workload_addresses: Vec<std::net::IpAddr>,
    /// Runtime-only allowlist of external UDP destinations this **EgressGateway**
    /// may relay datagram-over-mesh traffic to (issue #3263). Materialized by
    /// `materialize_egress_gateway_proxies` from `MESH_EXTERNAL` `ServiceEntry`
    /// ports whose protocol is `UDP`. Admission at CONNECT-authority time uses
    /// `crate::proxy::mesh_egress_udp_destination_dial_endpoint` (route-miss
    /// synthesis); `handle_hbone_udp_request` then re-checks the **effective**
    /// post-route-override destination via
    /// `crate::proxy::mesh_egress_udp_destination_allowed` before opening any
    /// socket — that guard matches **precomputed dial endpoints only**, so a
    /// route-override plugin cannot land on a STATIC hostname authority and
    /// DNS-bypass the operator-declared `endpoints[]` after the build-time
    /// lookup ran. The vector is bounded by
    /// [`crate::modes::mesh::MAX_EGRESS_UDP_DESTINATIONS`].
    ///
    /// **Fail closed by construction.** The vector is assigned UNCONDITIONALLY on
    /// every mesh apply — empty for every non-`EgressGateway` topology, when
    /// stream-family egress is disabled, and when the slice carries no admissible
    /// UDP ServiceEntry port — so an empty list denies every external UDP relay
    /// and a removed/edited ServiceEntry cannot leave a stale admission behind.
    ///
    /// `serde(skip)`: never operator-settable and never on the `config_json`
    /// wire. Widening this by hand would turn the gateway's authenticated mesh
    /// CONNECT terminator into an open UDP relay.
    #[serde(skip)]
    pub egress_udp_destinations: Vec<MeshEgressUdpDestination>,
    /// Runtime-only SOURCE-side routes that steer captured external UDP at a
    /// `Sidecar`/`Ambient` workload to the configured **EgressGateway** (issue
    /// #3263). Materialized by `materialize_mesh_external_udp_egress_upstreams`
    /// from `MESH_EXTERNAL` `ServiceEntry` UDP ports with `STATIC` endpoint IPs,
    /// and consumed by `RouterCache::build_route_table`, which folds each route
    /// into the same `mesh_udp_egress` `(destination IP, port)` index the
    /// in-mesh UDP datapath uses — so `mesh_udp_capture` needs no external
    /// special case.
    ///
    /// **Fail closed by construction**, exactly like
    /// [`Self::egress_udp_destinations`]: assigned UNCONDITIONALLY on every mesh
    /// apply and empty whenever the topology has no source-side UDP producer,
    /// `FERRUM_MESH_EGRESS_STREAM_ENABLED` / stream-family egress is disabled
    /// (the same all-or-nothing opt-in the gateway allowlist uses), the
    /// EgressGateway endpoint/identity is unset, or the entry declares no
    /// admissible `STATIC` endpoint. A withdrawn ServiceEntry therefore
    /// withdraws the route, and an empty list routes nothing.
    ///
    /// `serde(skip)`: never operator-settable and never on the `config_json`
    /// wire — an operator-supplied route here would name a dial destination the
    /// captured datapath trusts.
    #[serde(skip)]
    pub external_udp_egress_routes: Vec<MeshExternalUdpEgressRoute>,
}

/// Canonical comparison form for a mesh host: IP literals fold IPv4-mapped
/// IPv6 to their IPv4 form, everything else is ASCII-lowercased. Used for
/// validated loopback endpoint comparisons.
pub fn canonical_mesh_host(host: &str) -> String {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_canonical().to_string(),
        Err(_) => host.to_ascii_lowercase(),
    }
}

/// Outcome of resolving an authenticated inbound CONNECT `:authority` against
/// this workload's declared Sidecar `ingress[]` listeners (issue #3260).
///
/// The identity-protected Sidecar inbound path is a fresh mesh-mTLS HTTP/2
/// CONNECT to `:15006`, NOT a REDIRECT-captured plaintext stream, so it never
/// reaches `local_inbound_tcp_routes`. Without this resolution an authenticated
/// CONNECT for a declared ingress listener (`pod-ip:16379`) would be relayed
/// straight back to `pod-ip:16379` — the declared listener port — instead of the
/// `defaultEndpoint` the operator pointed it at (`127.0.0.1:6379`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarIngressConnectRelay {
    /// This workload has no declared Sidecar ingress block. The ordinary
    /// transparent-relay open-relay guard decides this CONNECT unchanged; this
    /// resolution must never widen ordinary HBONE/Ambient relay destinations.
    NotDeclared,
    /// A Sidecar ingress block is declared, but the authority does not resolve
    /// to exactly one valid, owner-stamped, stream-family loopback mapping for
    /// this accepted local address. Fail closed: the caller must refuse the
    /// CONNECT rather than fall back to dialing the authority, including for a
    /// port absent from an explicit-empty/all-invalid replacement surface.
    Deny,
    /// Relay to the listener's validated loopback `defaultEndpoint`, while
    /// AuthorizationPolicy evaluation stays keyed to `listener_port`.
    Relay {
        /// The DECLARED listener port the peer addressed. Authorization
        /// (`mesh_authz` `destination.port`) is evaluated on this, never on
        /// `endpoint_port` — a listener-scoped DENY must still fire.
        listener_port: u16,
        /// Validated loopback backend host.
        endpoint_host: String,
        /// Validated `defaultEndpoint` backend port.
        endpoint_port: u16,
    },
}

impl MeshConfig {
    /// Whether `host` belongs to the unambiguously resolved local service's
    /// workload set (see [`Self::local_workload_addresses`]). This membership
    /// check is not pod-unique; callers that need the exact replica must also
    /// compare the accepted socket's local IP. Empty inventory ⇒ `false`.
    pub fn host_is_local_service_workload_address(&self, host: &str) -> bool {
        if self.local_workload_addresses.is_empty() || host.is_empty() {
            return false;
        }
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| self.local_workload_addresses.contains(&ip.to_canonical()))
    }

    /// Resolve an authenticated inbound CONNECT `host:port` against this
    /// workload's declared Sidecar `ingress[]` stream listeners (issue #3260).
    ///
    /// `host` must already be unbracketed (the CONNECT boundary normalizes an
    /// `[::1]`-style authority before calling). Fail-closed rules, in order:
    ///
    /// 1. No Sidecar `ingress` block declared ⇒
    ///    [`SidecarIngressConnectRelay::NotDeclared`] (ordinary relay guard
    ///    decides; behavior unchanged). Once an ingress block is declared,
    ///    any port without one valid modeled listener is denied: explicit
    ///    empty/all-invalid declarations replace the ordinary inbound surface.
    /// 2. MORE than one declared listener on `port` ⇒ `Deny`. A hostile or
    ///    duplicated carrier must not pick a mapping by iteration order.
    /// 3. `host` is not in the resolved local-service workload set, does not
    ///    equal the accepted connection's actual local IP, or the local IP is
    ///    unavailable ⇒ `Deny`. Sharing a port number with a local listener
    ///    is not permission to remap a sibling replica's (or a bare loopback)
    ///    destination onto our application.
    /// 4. Malformed endpoint / unmodeled protocol / zero port, or a missing
    ///    owner stamp ⇒ `Deny` (same pair of guards the back-projection
    ///    chokepoint and the materializer apply).
    /// 5. Not stream-family ⇒ `Deny`. An HTTP-family listener is served by its
    ///    materialized `__mesh-ingress-*` HTTP route; a bare byte-stream CONNECT
    ///    naming it is outside the declared contract and is refused rather than
    ///    relayed to the listener port the operator replaced.
    pub fn resolve_sidecar_ingress_connect_relay(
        &self,
        host: &str,
        port: u16,
        accepted_local_ip: Option<std::net::IpAddr>,
    ) -> SidecarIngressConnectRelay {
        if !self.sidecar_ingress_declared {
            return SidecarIngressConnectRelay::NotDeclared;
        }
        if port == 0 {
            return SidecarIngressConnectRelay::Deny;
        }
        let mut rest = self.local_ingress_listeners.iter();
        let Some(listener) = rest.find(|entry| entry.port == port) else {
            return SidecarIngressConnectRelay::Deny;
        };
        if rest.any(|entry| entry.port == port) {
            return SidecarIngressConnectRelay::Deny;
        }
        let Ok(authority_ip) = host.parse::<std::net::IpAddr>() else {
            return SidecarIngressConnectRelay::Deny;
        };
        let authority_ip = authority_ip.to_canonical();
        if accepted_local_ip.map(|ip| ip.to_canonical()) != Some(authority_ip)
            || !self.local_workload_addresses.contains(&authority_ip)
        {
            return SidecarIngressConnectRelay::Deny;
        }
        if !listener.endpoint_shape_is_valid()
            || listener.owner_namespace.is_empty()
            || listener.owner_service.is_empty()
            || !listener.is_stream_family()
        {
            return SidecarIngressConnectRelay::Deny;
        }
        SidecarIngressConnectRelay::Relay {
            listener_port: listener.port,
            endpoint_host: listener.endpoint_host.clone(),
            endpoint_port: listener.endpoint_port,
        }
    }

    /// Whether `host:port` is EXACTLY the loopback `defaultEndpoint` that
    /// `listener_port` resolves to right now — the post-plugin re-check for a
    /// Sidecar ingress CONNECT relay.
    ///
    /// The synthesized relay proxy passes through the ordinary `before_proxy`
    /// chain, so a `mesh_route_dispatch` route override (or an upstream
    /// selection) can replace the destination between synthesis and dial. Only
    /// the one mapping this listener declares survives; anything else — a
    /// different backend, a widened port, a withdrawn listener — fails closed
    /// before the dial.
    pub fn sidecar_ingress_connect_relay_endpoint_matches(
        &self,
        listener_port: u16,
        host: &str,
        port: u16,
    ) -> bool {
        if !self.sidecar_ingress_declared {
            return false;
        }
        let mut rest = self.local_ingress_listeners.iter();
        let Some(listener) = rest.find(|entry| entry.port == listener_port) else {
            return false;
        };
        if rest.any(|entry| entry.port == listener_port) {
            return false;
        }
        listener.endpoint_shape_is_valid()
            && listener.is_stream_family()
            && !listener.owner_namespace.is_empty()
            && !listener.owner_service.is_empty()
            && listener.endpoint_port == port
            && canonical_mesh_host(&listener.endpoint_host) == canonical_mesh_host(host)
    }
}

/// One admitted external UDP egress destination materialized from a
/// `MESH_EXTERNAL` `ServiceEntry` UDP port under `EgressGateway` topology
/// (issue #3263).
///
/// The gateway terminates the sidecar's authenticated mesh transport on its
/// `:15090` SVID-mTLS egress listener (not Sidecar `:15006` / Ambient `:15008`),
/// unframes the `udp`-marked CONNECT body with the shared datagram codec
/// (`crate::proxy::mesh_udp_frame`), and relays each datagram over a
/// `connect()`ed local `UdpSocket` — so the reply peer is pinned by the kernel
/// to the exact destination that was admitted here. There is no plaintext UDP
/// listener and no DTLS material to seed.
///
/// **Authority and dial destination are represented separately.** `host` is the
/// exact authority host an admitted CONNECT may name (a declared ServiceEntry
/// host, or — only when derived from that very endpoint — a `STATIC`
/// `endpoints[].address` IP literal); [`Self::dial_endpoints`] is the
/// precomputed set the gateway's socket may actually dial. Under `STATIC`
/// resolution the dial set is the operator-declared endpoints, so the gateway
/// NEVER DNS-resolves the ServiceEntry host — collapsing the two would silently
/// bypass STATIC endpoint semantics. Under `DNS`/`NONE` resolution the entry
/// declares no dialable endpoint set, so the single dial endpoint is the
/// authority host itself (resolved at dial time, which is what those modes mean).
/// The post-route-override guard admits only dial endpoints, so an override that
/// lands on a STATIC hostname authority cannot DNS-bypass `endpoints[]`.
///
/// Matching is exact and ASCII-case-insensitive — wildcard ServiceEntry hosts
/// (`*.example.com`) are refused at materialization so no admission is ever
/// decided by a prefix/subnet guess. The allowlist as a whole is bounded by
/// [`MAX_EGRESS_UDP_DESTINATIONS`](crate::modes::mesh::MAX_EGRESS_UDP_DESTINATIONS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MeshEgressUdpDestination {
    /// Exact authority host admitted for a `udp` CONNECT (lowercased).
    pub host: String,
    /// Service port the CONNECT `:authority` carries.
    pub port: u16,
    /// The destinations the gateway's local `UdpSocket` may dial for this
    /// authority. Precomputed at materialization and NON-EMPTY by construction
    /// (a destination that resolves no dial endpoint is refused rather than
    /// admitted), bounded by
    /// [`MAX_EGRESS_UDP_DIAL_ENDPOINTS`](crate::modes::mesh::MAX_EGRESS_UDP_DIAL_ENDPOINTS).
    pub dial_endpoints: Vec<MeshEgressUdpDialEndpoint>,
    /// Owning ServiceEntry name, for diagnostics only.
    pub service_entry: String,
    /// Owning ServiceEntry namespace, for diagnostics only.
    pub namespace: String,
}

/// One dialable destination behind an admitted [`MeshEgressUdpDestination`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MeshEgressUdpDialEndpoint {
    /// Host the gateway's `UdpSocket` dials. An IP literal for every `STATIC`
    /// destination; the authority host itself for `DNS`/`NONE` resolution.
    pub host: String,
    /// Port the gateway's `UdpSocket` dials — the ServiceEntry's numeric
    /// `targetPort` (or the endpoint's named port) when declared, otherwise the
    /// service port.
    pub port: u16,
}

/// One SOURCE-side captured-datagram route to the configured EgressGateway
/// (issue #3263), forward-derived from a `MESH_EXTERNAL` `ServiceEntry` UDP port
/// with `STATIC` endpoints.
///
/// A UDP datagram carries no Host, so the ONLY thing a source can key on is the
/// original destination address the workload dialed — which, for an external
/// ServiceEntry, is the endpoint IP the mesh DNS proxy answered with. The route
/// therefore pairs that exact `(dest_ip, port)` with the upstream whose single
/// identity-pinned target is the EgressGateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MeshExternalUdpEgressRoute {
    /// Owning ServiceEntry namespace.
    pub namespace: String,
    /// Owning ServiceEntry name.
    pub service_entry: String,
    /// Declared ServiceEntry service port. This is BOTH the captured
    /// original-destination port and the port of the CONNECT `:authority` the
    /// gateway admits.
    pub port: u16,
    /// Captured original-destination IP: a `STATIC` `endpoints[].address` IP
    /// literal, canonicalized by the router before indexing.
    pub dest_ip: String,
    /// Upstream whose single target is the EgressGateway dial endpoint.
    pub upstream_id: String,
    /// Diagnostics / observability label for the session (the ServiceEntry host
    /// this endpoint backs).
    pub service_fqdn: String,
}

pub fn default_istio_root_namespace() -> String {
    "istio-system".to_string()
}

fn is_default_istio_root_namespace(value: &str) -> bool {
    value == default_istio_root_namespace()
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            istio_root_namespace: default_istio_root_namespace(),
            workloads: Vec::new(),
            services: Vec::new(),
            mesh_policies: Vec::new(),
            peer_authentications: Vec::new(),
            service_entries: Vec::new(),
            request_authentications: Vec::new(),
            telemetry_resources: Vec::new(),
            destination_rules: Vec::new(),
            virtual_service_cors_policies: Vec::new(),
            proxy_configs: Vec::new(),
            sidecars: Vec::new(),
            waypoint_bindings: Vec::new(),
            trust_bundles: None,
            multi_cluster: None,
            outbound_traffic_policy: None,
            extension_configs: Vec::new(),
            node_waypoint_assertors: Vec::new(),
            node_waypoint_capture_destinations: Vec::new(),
            node_waypoint_capture_peer_authentications: Vec::new(),
            local_inbound_services: None,
            local_ingress_listeners: Vec::new(),
            sidecar_ingress_declared: false,
            declared_ingress_http_ports: 0,
            local_inbound_tcp_routes: Vec::new(),
            local_workload_addresses: Vec::new(),
            egress_udp_destinations: Vec::new(),
            external_udp_egress_routes: Vec::new(),
        }
    }
}

/// One GAMMA Waypoint → services binding. Produced by the K8s translator
/// from Gateway resources with `gatewayClassName: istio-waypoint` /
/// `ferrum-waypoint` plus `Service` annotations
/// (`istio.io/use-waypoint: <name>`). `waypoint_for` mirrors Istio's
/// `istio.io/waypoint-for` annotation: `service` (default) means the
/// waypoint terminates traffic targeted at the listed services;
/// `workload` means it terminates traffic addressed directly to the
/// workload IPs; `all` means both. `none` opts out and yields no binding.
///
/// `services` is the list of `MeshService` references (namespace + name)
/// the operator has bound to this waypoint. The slice builder uses the
/// list as the authoritative narrowing key when
/// `MeshSliceRequest.waypoint_name == Some(name)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshWaypointBinding {
    /// Waypoint name. Matches the `metadata.name` of the Gateway resource
    /// in the K8s flow, and the `istio.io/use-waypoint` annotation value
    /// on bound Services.
    pub name: String,
    /// Namespace the waypoint is scoped to (the Gateway resource's
    /// namespace). Bound services normally live in the same namespace;
    /// `istio.io/use-waypoint-namespace` can override, in which case the
    /// translator emits the cross-namespace ref directly.
    pub namespace: String,
    /// `service` (default), `workload`, `all`, or `none`. Persisted as a
    /// string to keep the schema forward-compatible with future Istio
    /// enum values without requiring a Ferrum-side migration.
    #[serde(default = "default_waypoint_for")]
    pub waypoint_for: String,
    /// Gateway API `spec.gatewayClassName` when this binding came from a
    /// waypoint `Gateway`. Used to resolve AuthorizationPolicy
    /// `targetRefs` to `GatewayClass`. Absent for Service-only binding
    /// shells created before the Gateway is observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_class_name: Option<String>,
    /// Bound services. Empty when the Gateway resource exists but no
    /// `Service` annotation references it; the slice builder treats an
    /// empty binding as "no services pass through this waypoint" and
    /// fails closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<MeshWaypointServiceRef>,
}

/// Runtime-only local Sidecar raw-TCP inbound route, prepared from the same
/// local workload/service view as HTTP-family inbound materialization — and,
/// when Sidecar `ingress[]` declares stream-family listeners (issue #3260),
/// from those resolved listeners as well.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshInboundTcpRoute {
    /// Captured original-destination port that selects this route.
    ///
    /// For service-port default inbound this is the local app/container port.
    /// For Sidecar `ingress[]` stream listeners it is the **declared listener
    /// port** (the dialed port recovered from orig-dst), while
    /// [`Self::backend_addr`] may target a different `defaultEndpoint` port.
    pub match_port: u16,
    /// Loopback target for the co-located application.
    pub backend_addr: std::net::SocketAddr,
    /// Local service namespace, used for synthesized proxy identity/logging.
    pub namespace: String,
    /// Local service name, used for synthesized proxy identity/logging.
    pub service_name: String,
    /// Fully qualified service host, used in logs.
    pub service_fqdn: String,
    /// `true` only for opaque-TLS app ports (`AppProtocol::Tls`), where the
    /// captured plaintext bytes are a real TLS ClientHello so the inbound relay
    /// peeks the SNI before the stream plugin chain (a `when: connection.sni`
    /// `AuthorizationPolicy` needs it).
    pub tls_inspect: bool,
    /// `true` only when the mesh classifier has an explicit client-first signal
    /// for safe pre-dial peeking. `false` for ambiguous/server-first raw-TCP
    /// protocols (Tcp/Mongo/MySQL/Postgres/Redis), where clients may send
    /// nothing until the backend greeting.
    pub first_bytes_inspect: bool,
}

fn default_waypoint_for() -> String {
    "service".to_string()
}

/// A `(namespace, service)` reference inside a `MeshWaypointBinding`.
/// Kept as plain strings rather than a `WorkloadRef`-style typed handle
/// so the binding survives slice round-trips through CP→DP gRPC and
/// xDS ECDS without needing a separate per-service lookup table at apply
/// time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeshWaypointServiceRef {
    pub namespace: String,
    pub name: String,
}

/// Istio outbound traffic policy. Mirrors the upstream `OutboundTrafficPolicy`
/// message, which Istio uses at TWO scopes: mesh-wide
/// (`MeshConfig.outboundTrafficPolicy.mode`, carried on
/// [`MeshConfig::outbound_traffic_policy`]) and workload-scoped
/// (`Sidecar.outboundTrafficPolicy.mode`, carried on
/// [`MeshSidecar::outbound_traffic_policy`]). The workload-scoped value wins for
/// the workloads its Sidecar selects; the effective value is resolved once per
/// slice apply by `MeshSlice::effective_outbound_traffic_policy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundTrafficPolicy {
    /// Sidecar accepts traffic to any destination (no gate). Existing default.
    #[default]
    AllowAny,
    /// Sidecar only accepts traffic to destinations resolved in the mesh
    /// registry (services, service entries, workload addresses) plus their
    /// declared ports. Unknown destinations are rejected at the proxy entry
    /// point with a configurable 4xx/5xx status (default 502).
    ///
    /// HTTP-family traffic is gated by the auto-injected
    /// `mesh_outbound_registry` plugin. Stream-family traffic on mesh
    /// outbound capture listener ports is gated by the stream dispatch
    /// enforcement slot. Both paths read the same registry built from the
    /// already-projected mesh slice, so future slice-filtering refinements
    /// naturally narrow the allowed destination set.
    RegistryOnly,
}

impl MeshConfig {
    pub fn validate(&self) -> Vec<String> {
        // `normalize()` folds a blank root namespace back to the default;
        // validation may run before it, so resolve the same effective value
        // here rather than skipping the GatewayClass ownership rule.
        let root_namespace = match self.istio_root_namespace.trim() {
            "" => default_istio_root_namespace(),
            trimmed => trimmed.to_string(),
        };
        let mut errors = validate_mesh_config_internal(
            &self.workloads,
            &self.services,
            &self.mesh_policies,
            &self.peer_authentications,
            &self.service_entries,
            &self.request_authentications,
            &self.telemetry_resources,
            &self.destination_rules,
            &self.proxy_configs,
            &self.sidecars,
            &self.waypoint_bindings,
            &root_namespace,
            self.trust_bundles.as_ref(),
            self.multi_cluster.as_ref(),
        );
        validate_mesh_root_namespace(
            "MeshConfig.istio_root_namespace",
            &self.istio_root_namespace,
            &mut errors,
        );
        validate_virtual_service_cors_policies(&self.virtual_service_cors_policies, &mut errors);
        errors
    }

    pub fn normalize(&mut self) {
        let trimmed_root_namespace = self.istio_root_namespace.trim();
        if trimmed_root_namespace.is_empty() {
            self.istio_root_namespace = default_istio_root_namespace();
        } else if trimmed_root_namespace.len() != self.istio_root_namespace.len() {
            self.istio_root_namespace = trimmed_root_namespace.to_string();
        }
        normalize_mesh_fields_internal(
            &mut self.service_entries,
            &mut self.workloads,
            &mut self.mesh_policies,
            &mut self.destination_rules,
            &mut self.sidecars,
            &mut self.virtual_service_cors_policies,
            self.multi_cluster.as_mut(),
        );
    }

    /// Every namespace that owns at least one namespaced mesh object here.
    ///
    /// Diagnostics and tests only. Kubernetes overlay ownership is keyed by
    /// object identity, NOT by namespace (issue #2452) — a namespace can hold
    /// objects from several sources at once, so withdrawing a namespace would
    /// erase mesh state Kubernetes never owned. See
    /// [`Self::overlay_objects_from`].
    ///
    /// The `serde(skip)` runtime-only back-projections
    /// (`node_waypoint_capture_*`, `local_*`) are deliberately excluded: they
    /// are per-slice derivations, never source-owned configuration, and are
    /// always default on a control-plane snapshot.
    pub fn object_namespaces(&self) -> BTreeSet<String> {
        let mut namespaces = BTreeSet::new();
        collect_ns(&self.workloads, &mut namespaces);
        collect_ns(&self.services, &mut namespaces);
        collect_ns(&self.mesh_policies, &mut namespaces);
        collect_ns(&self.peer_authentications, &mut namespaces);
        collect_ns(&self.service_entries, &mut namespaces);
        collect_ns(&self.request_authentications, &mut namespaces);
        collect_ns(&self.telemetry_resources, &mut namespaces);
        collect_ns(&self.destination_rules, &mut namespaces);
        collect_ns(&self.virtual_service_cors_policies, &mut namespaces);
        collect_ns(&self.proxy_configs, &mut namespaces);
        collect_ns(&self.sidecars, &mut namespaces);
        collect_ns(&self.waypoint_bindings, &mut namespaces);
        namespaces
    }

    /// Every namespaced mesh object's full identity, as
    /// `(collection, namespace, key)`.
    ///
    /// Only used by ownership tests; the merge itself works per collection.
    /// Exposed so the exhaustive-coverage guard can assert that a value placed
    /// in ANY namespaced collection is actually visible to the ownership
    /// accounting rather than silently skipped.
    pub fn object_identities(&self) -> BTreeSet<(&'static str, String, String)> {
        let mut out = BTreeSet::new();
        collect_ids("workloads", &self.workloads, &mut out);
        collect_ids("services", &self.services, &mut out);
        collect_ids("mesh_policies", &self.mesh_policies, &mut out);
        collect_ids("peer_authentications", &self.peer_authentications, &mut out);
        collect_ids("service_entries", &self.service_entries, &mut out);
        collect_ids(
            "request_authentications",
            &self.request_authentications,
            &mut out,
        );
        collect_ids("telemetry_resources", &self.telemetry_resources, &mut out);
        collect_ids("destination_rules", &self.destination_rules, &mut out);
        collect_ids(
            "virtual_service_cors_policies",
            &self.virtual_service_cors_policies,
            &mut out,
        );
        collect_ids("proxy_configs", &self.proxy_configs, &mut out);
        collect_ids("sidecars", &self.sidecars, &mut out);
        collect_ids("waypoint_bindings", &self.waypoint_bindings, &mut out);
        out
    }

    /// Layer `overlay`'s namespaced mesh objects ON TOP of this config's.
    ///
    /// This is the whole of Kubernetes overlay ownership (issue #2452), and it
    /// is deliberately keyed by OBJECT IDENTITY rather than by namespace:
    ///
    /// * every object in `overlay` is added, and
    /// * a base object whose `(namespace, key)` collides with an overlay
    ///   object of the SAME collection is dropped first, so the overlay wins
    ///   deterministically instead of leaving two ambiguous duplicates.
    ///
    /// Nothing else in `self` is touched. A base object that the overlay does
    /// not name survives even when it sits in the same namespace — or is of
    /// the same kind — as an overlay object, which is what keeps
    /// native/file/xDS-authored mesh state alive through a Kubernetes
    /// publish. Withdrawal is not modeled here at all: the caller recomposes
    /// from the retained base layer, so an empty overlay simply yields the
    /// base again and the shadowed base object is restored.
    ///
    /// Mesh-global blocks (`trust_bundles`, `multi_cluster`,
    /// `outbound_traffic_policy`, `extension_configs`, `istio_root_namespace`)
    /// are NOT namespaced objects and are never layered here — the Kubernetes
    /// translator does not produce them, so it cannot own them.
    ///
    /// Ordering inside each collection is base-then-overlay, so a source that
    /// emits its objects deterministically keeps that order in the composed
    /// view.
    pub fn overlay_objects_from(&mut self, overlay: &MeshConfig) {
        overlay_ns(&mut self.workloads, &overlay.workloads);
        overlay_ns(&mut self.services, &overlay.services);
        overlay_ns(&mut self.mesh_policies, &overlay.mesh_policies);
        overlay_ns(
            &mut self.peer_authentications,
            &overlay.peer_authentications,
        );
        overlay_ns(&mut self.service_entries, &overlay.service_entries);
        overlay_ns(
            &mut self.request_authentications,
            &overlay.request_authentications,
        );
        overlay_ns(&mut self.telemetry_resources, &overlay.telemetry_resources);
        overlay_ns(&mut self.destination_rules, &overlay.destination_rules);
        overlay_ns(
            &mut self.virtual_service_cors_policies,
            &overlay.virtual_service_cors_policies,
        );
        overlay_ns(&mut self.proxy_configs, &overlay.proxy_configs);
        overlay_ns(&mut self.sidecars, &overlay.sidecars);
        overlay_ns(&mut self.waypoint_bindings, &overlay.waypoint_bindings);
    }

    /// `true` when this config carries nothing beyond its root namespace.
    ///
    /// Structural equality against a default config with the same
    /// `istio_root_namespace`, so a field added to [`MeshConfig`] later is
    /// covered without touching this predicate. `GatewayConfig.mesh` is
    /// normalized back to `None` when this holds, which keeps `mesh.is_some()`
    /// meaning "this deployment has mesh state" everywhere it is read.
    pub fn is_empty_overlay(&self) -> bool {
        let empty = MeshConfig {
            istio_root_namespace: self.istio_root_namespace.clone(),
            ..MeshConfig::default()
        };
        *self == empty
    }
}

/// One namespaced mesh object.
///
/// Implemented by every [`MeshConfig`] collection element a config source can
/// own, so Kubernetes overlay ownership accounting
/// ([`MeshConfig::object_namespaces`], [`MeshConfig::object_identities`],
/// [`MeshConfig::overlay_objects_from`]) cannot silently miss a collection
/// (issue #2452).
pub trait MeshNamespacedObject {
    /// The namespace that owns this object.
    fn object_namespace(&self) -> &str;

    /// This object's identity WITHIN its namespace and collection.
    ///
    /// Two objects of the same collection sharing `(namespace, object_key)`
    /// are the same logical resource authored twice, so the overlay layer's
    /// copy deterministically replaces the base layer's. The key must
    /// therefore include every field a source uses to distinguish two
    /// coexisting objects of that kind, and nothing else — an over-specific
    /// key leaves duplicates, an under-specific one hides a distinct object.
    fn object_key(&self) -> Cow<'_, str>;
}

fn collect_ns<T: MeshNamespacedObject>(items: &[T], out: &mut BTreeSet<String>) {
    for item in items {
        out.insert(item.object_namespace().to_string());
    }
}

fn collect_ids<T: MeshNamespacedObject>(
    collection: &'static str,
    items: &[T],
    out: &mut BTreeSet<(&'static str, String, String)>,
) {
    for item in items {
        out.insert((
            collection,
            item.object_namespace().to_string(),
            item.object_key().into_owned(),
        ));
    }
}

/// Layer one collection: drop base entries the overlay re-authors, then append
/// the overlay's. See [`MeshConfig::overlay_objects_from`].
fn overlay_ns<T: MeshNamespacedObject + Clone>(base: &mut Vec<T>, overlay: &[T]) {
    if overlay.is_empty() {
        return;
    }
    let shadowed: HashSet<(String, String)> = overlay.iter().map(owned_identity).collect();
    base.retain(|item| !shadowed.contains(&owned_identity(item)));
    base.extend(overlay.iter().cloned());
}

fn owned_identity<T: MeshNamespacedObject>(item: &T) -> (String, String) {
    (
        item.object_namespace().to_string(),
        item.object_key().into_owned(),
    )
}

impl MeshNamespacedObject for Workload {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    /// A workload has no `metadata.name` in the mesh model, so its identity is
    /// TIERED.
    ///
    /// * **Pod-backed** (`pod_uid` present and non-empty): the pod UID ALONE.
    ///   A Kubernetes Pod UID is the stable identity of that logical workload —
    ///   its addresses, SPIFFE id, service account, locality and node-waypoint
    ///   metadata all legitimately change while the same Pod object is
    ///   reconciled. Folding any of those mutable fields into the key would stop
    ///   the Kubernetes overlay from shadowing the base snapshot's copy of the
    ///   same pod and leave two logical copies of it in the composed mesh.
    /// * **Everything else** (WorkloadEntry / VM / native / xDS workloads, which
    ///   carry no pod identity): the SPIFFE id plus addresses. `Workload` has no
    ///   stable resource name to key on, so this composite is what keeps two
    ///   distinct workloads sharing a service account — and therefore a SPIFFE
    ///   id — from collapsing into one.
    ///
    /// An explicitly EMPTY `pod_uid` is treated as absent, not as a real pod
    /// identity. The Kubernetes translator only ever stamps a non-empty UID,
    /// but `pod_uid` is a plain deserialized field on the native / file / xDS
    /// sources, so `Some("")` is reachable — and normalizing it into the pod
    /// tier would collapse every such workload in a namespace onto one key.
    ///
    /// The two tiers live in disjoint key spaces (`uid|…` vs `id|…`) so no
    /// `pod_uid` value, however malformed, can be made to collide with a
    /// fallback key.
    fn object_key(&self) -> Cow<'_, str> {
        match self.pod_uid.as_deref() {
            Some(uid) if !uid.is_empty() => Cow::Owned(format!("uid|{uid}")),
            _ => Cow::Owned(format!(
                "id|{}|{}",
                self.spiffe_id,
                self.addresses.join(",")
            )),
        }
    }
}

impl MeshNamespacedObject for MeshService {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshPolicy {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for PeerAuthentication {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for ServiceEntry {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshRequestAuthentication {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshTelemetryResource {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshDestinationRule {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    /// One source resource can yield several rules distinguished by `host`.
    fn object_key(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{}|{}", self.name, self.host))
    }
}

impl MeshNamespacedObject for MeshVirtualServiceCorsPolicy {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    /// One VirtualService carries at most one policy PER HOST, so the host is
    /// part of the identity.
    fn object_key(&self) -> Cow<'_, str> {
        Cow::Owned(format!("{}|{}", self.name, self.host))
    }
}

impl MeshNamespacedObject for MeshProxyConfig {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshSidecar {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

impl MeshNamespacedObject for MeshWaypointBinding {
    fn object_namespace(&self) -> &str {
        &self.namespace
    }

    fn object_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

// ── Validation ────────────────────────────────────────────────────────────

/// Validate the mesh portion of a [`crate::config::types::GatewayConfig`].
///
/// Errors are returned as a flat `Vec<String>` so the file/DB/DP modes can
/// dispatch them per their own error-handling policy (file = fatal, DB =
/// warn, DP = reject update).
pub fn validate_mesh_config(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    request_authentications: &[MeshRequestAuthentication],
    trust_bundles: Option<&TrustBundleSet>,
) -> Vec<String> {
    validate_mesh_config_internal(
        workloads,
        services,
        policies,
        peer_auths,
        service_entries,
        request_authentications,
        &[],
        &[],
        &[],
        &[],
        &[],
        // Trust-bundle-only entrypoint: no root-namespace concept is available
        // here, so GatewayClass ownership is not evaluated (see
        // `validate_mesh_policy_target_refs_scope`).
        "",
        trust_bundles,
        None,
    )
}

/// Validate VirtualService-derived CORS policies at the config boundary:
/// unusable policies (no origins, empty host, empty/over-budget matcher, a
/// regex that does not compile within the shared byte/complexity bounds, or too
/// many matchers) reject the slice fail-closed with a field-specific diagnostic
/// instead of surfacing later as a plugin-construction failure on the data
/// plane. Every origin predicate is the SHARED `plugins::cors` admission gate —
/// do not fork it.
fn validate_virtual_service_cors_policies(
    policies: &[MeshVirtualServiceCorsPolicy],
    errors: &mut Vec<String>,
) {
    for policy in policies {
        let context = format!(
            "MeshVirtualServiceCorsPolicy '{}/{}'",
            policy.namespace, policy.name
        );
        validate_non_empty_string(format!("{context}.name"), &policy.name, errors);
        validate_non_empty_string(format!("{context}.namespace"), &policy.namespace, errors);
        validate_non_empty_string(format!("{context}.host"), &policy.host, errors);
        // Same fail-closed export boundary DestinationRules get: this list is
        // the ONLY thing standing between a namespace-local CORS policy and
        // another tenant's outbound routes, and
        // `virtual_service_cors_policy_exported_to_namespace` interprets it
        // through the shared evaluator rather than re-validating it.
        validate_mesh_export_to(&context, &policy.export_to, errors);
        if policy.cors.allowed_origins.is_empty() {
            errors.push(format!(
                "{context}: cors.allowed_origins must declare at least one origin matcher"
            ));
        }
        if let Err(err) =
            crate::plugins::cors::validate_origin_matcher_count(policy.cors.allowed_origins.len())
        {
            errors.push(format!("{context}: {err}"));
        }
        if policy.cors.allow_credentials == Some(true)
            && policy
                .cors
                .allowed_origins
                .iter()
                .any(|origin| matches!(origin, MeshCorsOriginMatch::Exact(value) if value == "*"))
        {
            errors.push(format!(
                "{context}: cors.allow_credentials must not be true with an exact `*` origin because credentialed wildcard CORS cannot be represented safely"
            ));
        }
        for (index, origin) in policy.cors.allowed_origins.iter().enumerate() {
            match origin {
                MeshCorsOriginMatch::Exact(value) => {
                    // Synthesis projects exacts onto the cors plugin's LITERAL
                    // `{"exact": ...}` matcher (issue #3254), so a
                    // wildcard-shaped (`*.example.com`) or non-canonical
                    // (`https://Example.com:443`) value is carried faithfully
                    // rather than rejected or reinterpreted as native
                    // wildcard-subdomain syntax. Only values the plugin itself
                    // refuses are errors here — Istio's allow-all `*` is
                    // exempt because the plugin maps that one value to its
                    // wildcard policy.
                    if value != "*"
                        && let Err(err) = crate::plugins::cors::validate_literal_exact_origin(value)
                    {
                        errors.push(format!("{context}: cors.allowed_origins[{index}] {err}"));
                    }
                }
                MeshCorsOriginMatch::Prefix(value) => {
                    if let Err(err) = crate::plugins::cors::validate_origin_prefix(value) {
                        errors.push(format!("{context}: cors.allowed_origins[{index}] {err}"));
                    }
                }
                MeshCorsOriginMatch::Regex(pattern) => {
                    // Compile under the plugin's explicit byte/complexity
                    // bounds (issue #3253) — the shared gate, not a fork, so a
                    // pattern that passes here can never fail plugin
                    // construction on the data plane.
                    if let Err(err) = crate::plugins::cors::compile_origin_regex(pattern) {
                        errors.push(format!("{context}: cors.allowed_origins[{index}] {err}"));
                    }
                }
            }
        }
        // Method/header lists are copied verbatim into the synthesized `cors`
        // plugin config, whose construction rejects padded/empty values,
        // invalid HTTP methods, and invalid header
        // names — run the plugin's own admission (shared
        // `plugins::cors::{validate_method,validate_header_name}`, not a
        // fork) here so a bad token rejects the slice at the config boundary
        // instead of failing plugin-cache construction on the data plane.
        type TokenValidator = fn(&str, &str) -> Result<(), String>;
        let string_lists: [(&str, &[String], TokenValidator); 3] = [
            (
                "allowed_methods",
                &policy.cors.allowed_methods,
                crate::plugins::cors::validate_method,
            ),
            (
                "allowed_headers",
                &policy.cors.allowed_headers,
                crate::plugins::cors::validate_header_name,
            ),
            (
                "exposed_headers",
                &policy.cors.exposed_headers,
                crate::plugins::cors::validate_header_name,
            ),
        ];
        for (field, values, validate) in string_lists {
            for (index, value) in values.iter().enumerate() {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    errors.push(format!(
                        "{context}: cors.{field}[{index}] must not be empty"
                    ));
                } else if trimmed.len() != value.len() {
                    errors.push(format!(
                        "{context}: cors.{field}[{index}] must not have leading/trailing whitespace"
                    ));
                } else if let Err(err) = validate(field, value) {
                    errors.push(format!("{context}: {err}"));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_mesh_config_internal(
    workloads: &[Workload],
    services: &[MeshService],
    policies: &[MeshPolicy],
    peer_auths: &[PeerAuthentication],
    service_entries: &[ServiceEntry],
    request_authentications: &[MeshRequestAuthentication],
    telemetry_resources: &[MeshTelemetryResource],
    destination_rules: &[MeshDestinationRule],
    proxy_configs: &[MeshProxyConfig],
    sidecars: &[MeshSidecar],
    waypoint_bindings: &[MeshWaypointBinding],
    istio_root_namespace: &str,
    trust_bundles: Option<&TrustBundleSet>,
    multi_cluster: Option<&MultiClusterConfig>,
) -> Vec<String> {
    let mut errors = Vec::new();

    // Workloads
    for wl in workloads {
        if wl.spiffe_id.trust_domain() != &wl.trust_domain {
            errors.push(format!(
                "Workload '{}': spiffe_id trust domain '{}' does not match \
                 workload's trust_domain '{}'",
                wl.spiffe_id,
                wl.spiffe_id.trust_domain(),
                wl.trust_domain
            ));
        }
        validate_non_empty_string(
            format!("Workload '{}'.namespace", wl.spiffe_id),
            &wl.namespace,
            &mut errors,
        );
        validate_non_empty_string(
            format!("Workload '{}'.service_name", wl.spiffe_id),
            &wl.service_name,
            &mut errors,
        );
        if let Some(service_namespace) = wl.service_namespace.as_deref() {
            if service_namespace.trim().is_empty() {
                errors.push(format!(
                    "Workload '{}'.service_namespace: must not be empty when set",
                    wl.spiffe_id
                ));
            } else if service_namespace != wl.namespace {
                // Cross-namespace attachment is only valid when an authoritative
                // MeshService in the target namespace names this workload. A bare
                // service_namespace stamp without membership is fail-closed so
                // native/xDS/file authors cannot spoof attachment via the field
                // alone (K8s stamping already requires ReferenceGrant + Service).
                let authorized = services.iter().any(|svc| {
                    svc.namespace == service_namespace
                        && svc.name == wl.service_name
                        && svc
                            .workloads
                            .iter()
                            .any(|reference| reference.spiffe_id == wl.spiffe_id)
                });
                if !authorized {
                    errors.push(format!(
                        "Workload '{}'.service_namespace: cross-namespace attachment to \
                         '{}/{}' requires that MeshService to list this workload's SPIFFE id",
                        wl.spiffe_id, service_namespace, wl.service_name
                    ));
                }
            }
        }
        for (i, address) in wl.addresses.iter().enumerate() {
            if address.trim().is_empty() {
                errors.push(format!(
                    "Workload '{}'.addresses[{}]: address must not be empty",
                    wl.spiffe_id, i
                ));
            }
        }
        for (i, port) in wl.ports.iter().enumerate() {
            validate_non_zero_port(
                format!("Workload '{}'.ports[{}].port", wl.spiffe_id, i),
                port.port,
                &mut errors,
            );
        }
        if wl
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': network must not be empty when set",
                wl.spiffe_id
            ));
        }
        if wl
            .cluster
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "Workload '{}': cluster must not be empty when set",
                wl.spiffe_id
            ));
        }
        if let Some(endpoint) = &wl.node_waypoint {
            validate_non_empty_string(
                format!("Workload '{}'.node_waypoint.address", wl.spiffe_id),
                &endpoint.address,
                &mut errors,
            );
            validate_non_zero_port(
                format!("Workload '{}'.node_waypoint.hbone_port", wl.spiffe_id),
                endpoint.hbone_port,
                &mut errors,
            );
            if endpoint
                .node_name
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "Workload '{}'.node_waypoint.node_name: must not be empty when set",
                    wl.spiffe_id
                ));
            }
            if endpoint
                .node_uid
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "Workload '{}'.node_waypoint.node_uid: must not be empty when set",
                    wl.spiffe_id
                ));
            }
            if endpoint
                .network
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "Workload '{}'.node_waypoint.network: must not be empty when set",
                    wl.spiffe_id
                ));
            }
            if endpoint
                .cluster
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                errors.push(format!(
                    "Workload '{}'.node_waypoint.cluster: must not be empty when set",
                    wl.spiffe_id
                ));
            }
        }
    }

    // Services
    for svc in services {
        validate_non_empty_string("MeshService.name".to_string(), &svc.name, &mut errors);
        validate_non_empty_string(
            format!("MeshService '{}'.namespace", svc.name),
            &svc.namespace,
            &mut errors,
        );
        for (i, port) in svc.ports.iter().enumerate() {
            validate_non_zero_port(
                format!("MeshService '{}'.ports[{}].port", svc.name, i),
                port.port,
                &mut errors,
            );
            match &port.target_port {
                Some(ServiceTargetPort::Number(0)) => errors.push(format!(
                    "MeshService '{}'.ports[{}].target_port: numeric targetPort must be greater than 0",
                    svc.name, i
                )),
                Some(ServiceTargetPort::Name(name)) if name.trim().is_empty() => errors.push(format!(
                    "MeshService '{}'.ports[{}].target_port: named targetPort must not be empty",
                    svc.name, i
                )),
                _ => {}
            }
        }
        for port in svc.protocol_overrides.keys() {
            validate_non_zero_port(
                format!("MeshService '{}'.protocol_overrides[{}]", svc.name, port),
                *port,
                &mut errors,
            );
        }
        for (i, vip) in svc.cluster_ips.iter().enumerate() {
            if vip.parse::<std::net::IpAddr>().is_err() {
                errors.push(format!(
                    "MeshService '{}'.cluster_ips[{}]: '{}' is not a valid IP address \
                     (headless services should omit cluster_ips, not carry 'None')",
                    svc.name, i, vip
                ));
            }
        }
    }

    // Policies
    for policy in policies {
        validate_non_empty_string("MeshPolicy.name".to_string(), &policy.name, &mut errors);
        validate_non_empty_string(
            format!("MeshPolicy '{}'.namespace", policy.name),
            &policy.namespace,
            &mut errors,
        );
        validate_mesh_policy_target_refs_scope(
            &MeshPolicyTargetRefsIdentity {
                resource_kind: "MeshPolicy",
                resource_name: &policy.name,
                policy_namespace: &policy.namespace,
            },
            &policy.scope,
            services,
            waypoint_bindings,
            istio_root_namespace,
            &mut errors,
        );
        for (i, rule) in policy.rules.iter().enumerate() {
            for (j, principal) in rule.from.iter().enumerate() {
                if principal.spiffe_id_pattern.is_none()
                    && principal.namespace_pattern.is_none()
                    && principal.trust_domain.is_none()
                    && principal.trust_domain_pattern.is_none()
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}]: at least one \
                         of spiffe_id_pattern/namespace_pattern/trust_domain/\
                         trust_domain_pattern must be set",
                        policy.name, i, j
                    ));
                }
                if let Some(pat) = principal.spiffe_id_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].spiffe_id_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
                if let Some(pat) = principal.namespace_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].namespace_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
                if let Some(pat) = principal.trust_domain_pattern.as_ref()
                    && let Err(e) = glob::Pattern::new(pat)
                {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].from[{}].trust_domain_pattern \
                         '{}' is not a valid glob: {}",
                        policy.name, i, j, pat, e
                    ));
                }
            }
            for (j, request) in rule.to.iter().enumerate() {
                let any_method = !request.methods.is_empty();
                let any_path = !request.paths.is_empty();
                let any_host = !request.hosts.is_empty();
                let any_header = !request.headers.is_empty();
                let any_port = !request.ports.is_empty() || !request.port_patterns.is_empty();
                let any_not = !request.not_methods.is_empty()
                    || !request.not_paths.is_empty()
                    || !request.not_hosts.is_empty()
                    || !request.not_ports.is_empty()
                    || !request.not_port_patterns.is_empty();
                if !(any_method || any_path || any_host || any_header || any_port || any_not) {
                    errors.push(format!(
                        "MeshPolicy '{}'.rules[{}].to[{}]: at least one of \
                         methods/paths/hosts/headers/ports or their negated \
                         counterparts must be non-empty",
                        policy.name, i, j
                    ));
                }
                for (k, host) in request.hosts.iter().enumerate() {
                    if !is_valid_request_match_host_pattern(host) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].hosts[{}] \
                             '{}' is not a valid host pattern \
                             (expected hostname, [ipv6], or host:port/host:* \
                             with u16 numeric or '*' port)",
                            policy.name, i, j, k, host
                        ));
                    }
                }
                for (k, host) in request.not_hosts.iter().enumerate() {
                    if !is_valid_request_match_host_pattern(host) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].not_hosts[{}] \
                             '{}' is not a valid host pattern \
                             (expected hostname, [ipv6], or host:port/host:* \
                             with u16 numeric or '*' port)",
                            policy.name, i, j, k, host
                        ));
                    }
                }
                for (k, pattern) in request.port_patterns.iter().enumerate() {
                    if !is_valid_request_match_port_pattern(pattern) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].port_patterns[{}] \
                             is not an admissible port pattern \
                             (expected '*', '<digits>*', or '*<digits>' that can \
                             match a destination/listener port in 1..=65535)",
                            policy.name, i, j, k
                        ));
                    }
                }
                for (k, pattern) in request.not_port_patterns.iter().enumerate() {
                    if !is_valid_request_match_port_pattern(pattern) {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].to[{}].not_port_patterns[{}] \
                             is not an admissible port pattern \
                             (expected '*', '<digits>*', or '*<digits>' that can \
                             match a destination/listener port in 1..=65535)",
                            policy.name, i, j, k
                        ));
                    }
                }
            }
            if rule.when.len() > MAX_MESH_RULE_CONDITIONS {
                errors.push(format!(
                    "MeshPolicy '{}'.rules[{}].when must have at most \
                     {MAX_MESH_RULE_CONDITIONS} entries",
                    policy.name, i
                ));
            }
            for (j, condition) in rule.when.iter().take(MAX_MESH_RULE_CONDITIONS).enumerate() {
                if let Err(issues) = validate_mesh_condition(condition) {
                    for issue in issues {
                        errors.push(format!(
                            "MeshPolicy '{}'.rules[{}].when[{}].{} {}",
                            policy.name,
                            i,
                            j,
                            issue.mesh_path(),
                            issue.mesh_reason()
                        ));
                    }
                }
            }
        }
    }

    // PeerAuthentications
    for pa in peer_auths {
        validate_non_empty_string("PeerAuthentication.name".to_string(), &pa.name, &mut errors);
        validate_non_empty_string(
            format!("PeerAuthentication '{}'.namespace", pa.name),
            &pa.namespace,
            &mut errors,
        );
        if let Some(scope) = pa.scope.as_ref() {
            reject_unsupported_target_refs_scope(
                "PeerAuthentication",
                &pa.name,
                scope,
                &mut errors,
            );
        }
        for port in pa.port_overrides.keys() {
            validate_non_zero_port(
                format!("PeerAuthentication '{}'.port_overrides[{}]", pa.name, port),
                *port,
                &mut errors,
            );
        }
        if !pa.mtls_mode.is_peer_auth_mode() {
            errors.push(format!(
                "PeerAuthentication '{}': mtls_mode '{:?}' is invalid for server-side policy",
                pa.name, pa.mtls_mode
            ));
        }
        for (port, mode) in &pa.port_overrides {
            if !mode.is_peer_auth_mode() {
                errors.push(format!(
                    "PeerAuthentication '{}': port_overrides[{port}] mode '{mode:?}' is invalid for server-side policy",
                    pa.name
                ));
            }
        }
    }

    // RequestAuthentications
    for ra in request_authentications {
        validate_non_empty_string(
            "MeshRequestAuthentication.name".to_string(),
            &ra.name,
            &mut errors,
        );
        validate_non_empty_string(
            format!("MeshRequestAuthentication '{}'.namespace", ra.name),
            &ra.namespace,
            &mut errors,
        );
        reject_unsupported_target_refs_scope(
            "MeshRequestAuthentication",
            &ra.name,
            &ra.scope,
            &mut errors,
        );
        for (i, rule) in ra.jwt_rules.iter().enumerate() {
            if rule.issuer.trim().is_empty() {
                errors.push(format!(
                    "MeshRequestAuthentication '{}' jwt_rules[{}]: issuer must not be empty",
                    ra.name, i
                ));
            }
            if rule.jwks_uri.is_none() && rule.jwks.is_none() {
                errors.push(format!(
                    "MeshRequestAuthentication '{}' jwt_rules[{}]: one of jwks_uri or jwks is required",
                    ra.name, i
                ));
            }
        }
    }

    // ServiceEntries
    for se in service_entries {
        validate_non_empty_string("ServiceEntry.name".to_string(), &se.name, &mut errors);
        if se.hosts.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': hosts must not be empty",
                se.name
            ));
        }
        for (i, port) in se.ports.iter().enumerate() {
            validate_non_zero_port(
                format!("ServiceEntry '{}'.ports[{}].port", se.name, i),
                port.port,
                &mut errors,
            );
        }
        for (i, endpoint) in se.endpoints.iter().enumerate() {
            validate_non_empty_string(
                format!("ServiceEntry '{}'.endpoints[{}].address", se.name, i),
                &endpoint.address,
                &mut errors,
            );
            for (name, port) in &endpoint.ports {
                validate_non_zero_port(
                    format!(
                        "ServiceEntry '{}'.endpoints[{}].ports['{}']",
                        se.name, i, name
                    ),
                    *port,
                    &mut errors,
                );
            }
        }
        if se.resolution != Resolution::Static && !se.endpoints.is_empty() {
            errors.push(format!(
                "ServiceEntry '{}': endpoints are only valid when resolution=static",
                se.name
            ));
        }
    }

    // Telemetry
    for telemetry in telemetry_resources {
        validate_non_empty_string(
            "MeshTelemetryResource.name".to_string(),
            &telemetry.name,
            &mut errors,
        );
        validate_non_empty_string(
            format!("MeshTelemetryResource '{}'.namespace", telemetry.name),
            &telemetry.namespace,
            &mut errors,
        );
        reject_unsupported_target_refs_scope(
            "MeshTelemetryResource",
            &telemetry.name,
            &telemetry.scope,
            &mut errors,
        );
        if let Some(tracing) = telemetry.config.tracing.as_ref() {
            validate_percentage(
                format!(
                    "MeshTelemetryResource '{}'.config.tracing.sampling_percentage",
                    telemetry.name
                ),
                tracing.sampling_percentage,
                &mut errors,
            );
        }
    }

    // DestinationRules
    for dr in destination_rules {
        validate_non_empty_string(
            "MeshDestinationRule.name".to_string(),
            &dr.name,
            &mut errors,
        );
        validate_non_empty_string(
            format!("MeshDestinationRule '{}'.namespace", dr.name),
            &dr.namespace,
            &mut errors,
        );
        validate_non_empty_string(
            format!("MeshDestinationRule '{}'.host", dr.name),
            &dr.host,
            &mut errors,
        );
        // Export visibility is security-relevant (issue #2465): an
        // unsupported or self-conflicting list must reject the config rather
        // than be interpreted, so a typo can never widen a namespace-local
        // rule into a mesh-wide one.
        validate_mesh_export_to(
            &format!("MeshDestinationRule '{}'", dr.name),
            &dr.export_to,
            &mut errors,
        );
        // Validate top-level trafficPolicy boundary fields (outlier-detection
        // ranges, client-TLS mode/cert consistency) that the K8s translator
        // enforces but the native/file/xDS slice path otherwise skips.
        if let Some(policy) = dr.traffic_policy.as_ref() {
            validate_mesh_traffic_policy(
                format!("MeshDestinationRule '{}'.traffic_policy", dr.name),
                policy,
                &mut errors,
            );
        }
        // `http1MaxPendingRequests` is honestly reinterpreted by the limiter as
        // a per-`(host, policy port, selected subset)` concurrent in-flight H1
        // gate, where `Some(0)` would shed every request.
        // Native/file/xDS slices bypass K8s translation, so apply the same
        // field-specific validation here. (`maxRetries: 0` is valid and
        // disables an existing retry policy for the destination.)
        // Walk every place a `connectionPool.http` block can ride a DR:
        // top-level `trafficPolicy`, per-port `portLevelSettings`, and each
        // `subsets[].trafficPolicy`.
        validate_dr_connection_pool(
            &format!("MeshDestinationRule '{}'.trafficPolicy", dr.name),
            dr.traffic_policy.as_ref(),
            &mut errors,
        );
        for (port, policy) in &dr.port_level_settings {
            validate_non_zero_port(
                format!(
                    "MeshDestinationRule '{}'.port_level_settings[{}]",
                    dr.name, port
                ),
                *port,
                &mut errors,
            );
            validate_mesh_traffic_policy(
                format!(
                    "MeshDestinationRule '{}'.port_level_settings[{}]",
                    dr.name, port
                ),
                policy,
                &mut errors,
            );
            validate_dr_connection_pool(
                &format!(
                    "MeshDestinationRule '{}'.port_level_settings[{}].trafficPolicy",
                    dr.name, port
                ),
                Some(policy),
                &mut errors,
            );
        }
        for (i, subset) in dr.subsets.iter().enumerate() {
            validate_non_empty_string(
                format!("MeshDestinationRule '{}'.subsets[{}].name", dr.name, i),
                &subset.name,
                &mut errors,
            );
            if let Some(policy) = subset.traffic_policy.as_ref() {
                validate_mesh_traffic_policy(
                    format!(
                        "MeshDestinationRule '{}'.subsets[{}].traffic_policy",
                        dr.name, i
                    ),
                    policy,
                    &mut errors,
                );
            }
            validate_dr_connection_pool(
                &format!(
                    "MeshDestinationRule '{}'.subsets[{}].trafficPolicy",
                    dr.name, i
                ),
                subset.traffic_policy.as_ref(),
                &mut errors,
            );
        }
    }

    // ProxyConfigs
    for proxy_config in proxy_configs {
        validate_non_empty_string(
            "MeshProxyConfig.name".to_string(),
            &proxy_config.name,
            &mut errors,
        );
        validate_non_empty_string(
            format!("MeshProxyConfig '{}'.namespace", proxy_config.name),
            &proxy_config.namespace,
            &mut errors,
        );
        reject_unsupported_target_refs_scope(
            "MeshProxyConfig",
            &proxy_config.name,
            &proxy_config.scope,
            &mut errors,
        );
        validate_percentage(
            format!("MeshProxyConfig '{}'.tracing_sampling", proxy_config.name),
            proxy_config.tracing_sampling,
            &mut errors,
        );
    }

    // Sidecars
    for sidecar in sidecars {
        validate_non_empty_string("MeshSidecar.name".to_string(), &sidecar.name, &mut errors);
        validate_non_empty_string(
            format!("MeshSidecar '{}'.namespace", sidecar.name),
            &sidecar.namespace,
            &mut errors,
        );
        for (i, egress) in sidecar.egress.iter().enumerate() {
            if egress.hosts.is_empty() {
                errors.push(format!(
                    "MeshSidecar '{}'.egress[{}].hosts must not be empty",
                    sidecar.name, i
                ));
            }
            for (j, host) in egress.hosts.iter().enumerate() {
                if !is_valid_sidecar_host_pattern(host) {
                    errors.push(format!(
                        "MeshSidecar '{}'.egress[{}].hosts[{}] '{}' is not a valid Sidecar host pattern",
                        sidecar.name, i, j, host
                    ));
                }
            }
            if let Some(port) = egress.port {
                validate_non_zero_port(
                    format!("MeshSidecar '{}'.egress[{}].port", sidecar.name, i),
                    port,
                    &mut errors,
                );
            }
        }
        // Ingress listeners: the listener port is a mandatory structural field.
        // The `defaultEndpoint` routability decision — empty, Unix sockets,
        // unrecognized/`Udp` protocols, arbitrary IPs — is NOT a validation error
        // (Istio allows omitting `defaultEndpoint`): those entries are accepted,
        // reported as deferred by the status writer, and skipped fail-closed at
        // materialization. Recognized HTTP and stream protocols are modeled.
        for (i, ingress) in sidecar.ingress.iter().enumerate() {
            validate_non_zero_port(
                format!("MeshSidecar '{}'.ingress[{}].port", sidecar.name, i),
                ingress.port,
                &mut errors,
            );
        }
    }

    // Trust bundles
    if let Some(tb_set) = trust_bundles {
        if tb_set.local.x509_authorities.is_empty() && tb_set.local.jwt_authorities.is_empty() {
            errors.push(format!(
                "TrustBundleSet.local for trust domain '{}' has no authorities",
                tb_set.local.trust_domain
            ));
        }
        if let Err(e) = tb_set.local.decode_x509_authorities() {
            errors.push(format!("TrustBundleSet.local: {e}"));
        }
        let mut seen_trust_domains = HashSet::from([tb_set.local.trust_domain.clone()]);
        for fed in &tb_set.federated {
            if !seen_trust_domains.insert(fed.trust_domain.clone()) {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: duplicate trust domain",
                    fed.trust_domain
                ));
            }
            if fed.x509_authorities.is_empty() && fed.jwt_authorities.is_empty() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: no authorities",
                    fed.trust_domain
                ));
            }
            if let Err(e) = fed.decode_x509_authorities() {
                errors.push(format!(
                    "TrustBundleSet.federated[{}]: {e}",
                    fed.trust_domain
                ));
            }
        }
    }

    if let Some(multi_cluster) = multi_cluster {
        validate_multi_cluster(multi_cluster, trust_bundles, &mut errors);
    }

    errors
}

/// Reject `PolicyScope::TargetRefs` on shared-scope consumers that do not yet
/// implement end-to-end targetRefs attachment (PeerAuthentication,
/// RequestAuthentication, Telemetry, ProxyConfig). AuthorizationPolicy /
/// MeshPolicy validate attachments separately.
fn reject_unsupported_target_refs_scope(
    resource_kind: &str,
    resource_name: &str,
    scope: &PolicyScope,
    errors: &mut Vec<String>,
) {
    if matches!(scope, PolicyScope::TargetRefs { .. }) {
        errors.push(format!(
            "{resource_kind} '{resource_name}': PolicyScope::target_refs is not supported; \
             only AuthorizationPolicy/MeshPolicy implement targetRefs attachment"
        ));
    }
}

/// Immutable resource/policy identity used by targetRefs scope diagnostics.
struct MeshPolicyTargetRefsIdentity<'a> {
    resource_kind: &'a str,
    resource_name: &'a str,
    policy_namespace: &'a str,
}

/// Fail-closed validation for AuthorizationPolicy / MeshPolicy `targetRefs`.
///
/// Mirrors the Istio AuthorizationPolicy support contract at the native/file
/// boundary so a hand-authored `MeshConfig` cannot express something the K8s
/// translator refuses:
///
/// * `Service` and `Gateway` attachments are **same namespace as the owning
///   policy**. Istio lists both as same-namespace only, and Ferrum's CP
///   namespace filter (`resource_owner_can_apply_to_namespace`) would drop a
///   cross-namespace attachment before it ever reached the target DP slice —
///   an accepted-but-inert security policy.
/// * `GatewayClass` is cluster-scoped and only the Istio **root namespace** may
///   own such a policy. This is an **ownership** rule, so it hard-fails even
///   alongside a valid sibling attachment (see below).
/// * A missing / inapplicable sibling attachment must **not** invalidate the
///   whole policy when another attachment is still valid and applicable —
///   retention is OR and runtime matching stays exact, so an unmatched arm
///   never becomes a wildcard. A policy whose *every* attachment is
///   unresolved still fails closed rather than silently broadening.
///   Deferral covers **inventory** misses only (an absent Service / Gateway
///   named by exact `(namespace, name)`, which nothing can match). Structural
///   and ownership refusals — malformed fields, cross-namespace
///   Service/Gateway, unsupported class names, and non-root `GatewayClass`
///   ownership — are always hard errors, because those arms stay live and
///   matchable in the retained scope.
/// * Gateway presence is checked only when `waypoint_bindings` is a real
///   inventory. DP slices reconstruct `MeshConfig` without bindings (matching
///   uses the live `waypoint_name` / class stamp), so an empty bindings list
///   cannot prove a Gateway target is missing.
fn validate_mesh_policy_target_refs_scope(
    identity: &MeshPolicyTargetRefsIdentity<'_>,
    scope: &PolicyScope,
    services: &[MeshService],
    waypoint_bindings: &[MeshWaypointBinding],
    istio_root_namespace: &str,
    errors: &mut Vec<String>,
) {
    let PolicyScope::TargetRefs { attachments } = scope else {
        return;
    };
    let context = format!(
        "{} '{}'.scope.target_refs",
        identity.resource_kind, identity.resource_name
    );
    let policy_namespace = identity.policy_namespace;
    if attachments.is_empty() {
        errors.push(format!(
            "{context}: attachments must not be empty (targeted policies fail closed)"
        ));
        return;
    }
    if attachments.len() > MAX_POLICY_TARGET_REFS {
        errors.push(format!(
            "{context}: supports at most {MAX_POLICY_TARGET_REFS} attachments"
        ));
    }

    // Inventory-miss failures are deferred: one unresolved arm must not reject
    // a mixed policy that still has a valid applicable target. Emit them only
    // when *no* attachment remains valid, so an all-invalid policy cannot
    // silently broaden. Structural and ownership refusals are NOT deferred —
    // those arms remain live and matchable in the retained scope.
    let mut valid_attachments = 0usize;
    let mut unresolved: Vec<String> = Vec::new();

    for (index, attachment) in attachments.iter().enumerate() {
        let path = format!("{context}[{index}]");
        match attachment {
            PolicyTargetAttachment::Service { namespace, name }
            | PolicyTargetAttachment::Gateway { namespace, name } => {
                let kind = match attachment {
                    PolicyTargetAttachment::Service { .. } => "Service",
                    _ => "Gateway",
                };
                let errors_before = errors.len();
                validate_non_empty_string(format!("{path}.namespace"), namespace, errors);
                validate_bounded_string(
                    format!("{path}.namespace"),
                    namespace,
                    MAX_POLICY_TARGET_REF_NAMESPACE_LEN,
                    errors,
                );
                validate_non_empty_string(format!("{path}.name"), name, errors);
                validate_bounded_string(
                    format!("{path}.name"),
                    name,
                    MAX_POLICY_TARGET_REF_NAME_LEN,
                    errors,
                );
                if errors.len() > errors_before {
                    continue;
                }
                if namespace != policy_namespace {
                    errors.push(format!(
                        "{path}: {kind} '{namespace}/{name}' is in another namespace; \
                         Istio AuthorizationPolicy targetRefs to {kind} are same-namespace only \
                         (policy namespace '{policy_namespace}')"
                    ));
                    continue;
                }
                let is_service = matches!(attachment, PolicyTargetAttachment::Service { .. });
                if is_service {
                    let present = services
                        .iter()
                        .any(|service| service.namespace == *namespace && service.name == *name);
                    if present {
                        valid_attachments += 1;
                    } else {
                        unresolved.push(format!(
                            "{path}: Service '{namespace}/{name}' was not found in services; \
                             targeted policies fail closed when the target is missing"
                        ));
                    }
                } else if waypoint_bindings.is_empty() {
                    // No bindings inventory on this validation path (typical DP
                    // slice reconstruction). Presence cannot be proven or
                    // disproven; runtime attachment matching remains exact and
                    // fail-closed.
                    valid_attachments += 1;
                } else if waypoint_bindings
                    .iter()
                    .any(|binding| binding.namespace == *namespace && binding.name == *name)
                {
                    valid_attachments += 1;
                } else {
                    unresolved.push(format!(
                        "{path}: Gateway '{namespace}/{name}' was not found in \
                         waypoint_bindings; targeted policies fail closed when the \
                         target is missing"
                    ));
                }
            }
            PolicyTargetAttachment::GatewayClass { name } => {
                let errors_before = errors.len();
                validate_non_empty_string(format!("{path}.name"), name, errors);
                validate_bounded_string(
                    format!("{path}.name"),
                    name,
                    MAX_POLICY_TARGET_REF_NAME_LEN,
                    errors,
                );
                if errors.len() > errors_before {
                    continue;
                }
                // GatewayClass is cluster-scoped: only the root namespace may
                // own a class-wide policy. An empty configured root namespace
                // means the caller has no root-namespace concept (the
                // trust-bundle-only `validate_mesh_config` entrypoint), so the
                // ownership rule is not evaluated there.
                //
                // This is an ownership refusal, NOT an inventory miss, so it is
                // never deferred: the class exists and is supported, and
                // `WaypointAttachment::matches` compares the class name ALONE
                // (no namespace, no Gateway name). A retained non-root arm is
                // therefore a live cluster-wide wildcard over every waypoint of
                // that class, not an arm that simply fails to resolve. Deferring
                // it would let any namespace buy class-wide reach by pairing it
                // with one valid same-namespace Service arm — exactly what the
                // K8s translator rejects unconditionally (`istio.rs`).
                if !istio_root_namespace.is_empty() && policy_namespace != istio_root_namespace {
                    errors.push(format!(
                        "{path}: GatewayClass attachments must be owned by a policy in the Istio \
                         root namespace ('{istio_root_namespace}'), not '{policy_namespace}'"
                    ));
                    continue;
                }
                if !is_supported_waypoint_gateway_class_name(name) {
                    let known_on_binding = waypoint_bindings.iter().any(|binding| {
                        binding
                            .gateway_class_name
                            .as_deref()
                            .is_some_and(|class| class == name.as_str())
                    });
                    if !known_on_binding {
                        // Unsupported class name is a structural refusal, not an
                        // inventory miss — always hard-fail.
                        errors.push(format!(
                            "{path}: GatewayClass '{name}' is unsupported; \
                             Ferrum accepts istio-waypoint/ferrum-waypoint class attachments"
                        ));
                        continue;
                    }
                }
                valid_attachments += 1;
            }
        }
    }

    if valid_attachments == 0 {
        errors.extend(unresolved);
    }
}

fn validate_non_empty_string(context: String, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{context}: must not be empty"));
    }
}

fn validate_bounded_string(context: String, value: &str, max_len: usize, errors: &mut Vec<String>) {
    if !value.trim().is_empty() && value.len() > max_len {
        errors.push(format!(
            "{context}: must be at most {max_len} characters (got {})",
            value.len()
        ));
    }
}

pub const MESH_EXPORT_TO_MAX_ENTRIES: usize = 64;

/// Validate an `exportTo` visibility list (issue #2465).
///
/// Fail-closed and shared by every source that carries one: an unsupported,
/// malformed, or self-conflicting list is a config REJECTION, never a silent
/// downgrade to "visible everywhere". Rejecting before publication leaves the
/// previously accepted slice live.
///
/// Diagnostics name the field and the offending INDEX plus a fixed
/// classification — the raw value is never echoed, because it is
/// operator-supplied and can be arbitrarily long or hostile.
pub fn validate_mesh_export_to(context: &str, export_to: &[String], errors: &mut Vec<String>) {
    if export_to.len() > MESH_EXPORT_TO_MAX_ENTRIES {
        errors.push(format!(
            "{context}.exportTo: must not exceed {MESH_EXPORT_TO_MAX_ENTRIES} entries (got {})",
            export_to.len()
        ));
        return;
    }
    let mut has_wildcard = false;
    for (index, raw) in export_to.iter().enumerate() {
        let entry = raw.trim();
        if entry == "*" {
            has_wildcard = true;
            continue;
        }
        if entry == "." {
            continue;
        }
        if entry.is_empty() {
            errors.push(format!(
                "{context}.exportTo[{index}]: must not be empty; use '.', '*', or a namespace name"
            ));
            continue;
        }
        if entry == "~" {
            errors.push(format!(
                "{context}.exportTo[{index}]: '~' is not a supported exportTo value; use '.', '*', or a namespace name"
            ));
            continue;
        }
        if !is_dns1123_namespace_label(entry) {
            errors.push(format!(
                "{context}.exportTo[{index}]: must be '.', '*', or a lowercase RFC 1123 namespace name of at most 63 characters"
            ));
        }
    }
    if has_wildcard && export_to.len() > 1 {
        errors.push(format!(
            "{context}.exportTo: '*' is mesh-wide and conflicts with the other {} entries; declare either '*' alone or an explicit namespace list",
            export_to.len() - 1
        ));
    }
}

/// Validate the policy-authority namespace carried by a mesh config or xDS
/// slice (issue #2469).
///
/// The root namespace decides which tenant may supply mesh-wide policy, so a
/// non-empty but malformed value must be rejected at the source boundary. The
/// diagnostic intentionally withholds the operator/CP-supplied value.
pub fn validate_mesh_root_namespace(context: &str, namespace: &str, errors: &mut Vec<String>) {
    if !is_dns1123_namespace_label(namespace.trim()) {
        errors.push(format!(
            "{context}: must be a lowercase RFC 1123 namespace name of at most 63 characters"
        ));
    }
}

/// RFC 1123 label check used for namespace names inside `exportTo`.
fn is_dns1123_namespace_label(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return false;
    }
    matches!(bytes.first(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
        && matches!(bytes.last(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn validate_non_zero_port(context: String, port: u16, errors: &mut Vec<String>) {
    if port == 0 {
        errors.push(format!("{context}: port must be greater than 0"));
    }
}

fn validate_percentage(context: String, value: Option<f64>, errors: &mut Vec<String>) {
    if let Some(value) = value
        && (!value.is_finite() || !(0.0..=100.0).contains(&value))
    {
        errors.push(format!(
            "{context}: must be a finite percentage from 0 to 100"
        ));
    }
}

fn validate_mesh_traffic_policy(
    context: String,
    policy: &MeshTrafficPolicy,
    errors: &mut Vec<String>,
) {
    if let Some(outlier) = policy.outlier_detection.as_ref() {
        validate_mesh_outlier_detection(format!("{context}.outlier_detection"), outlier, errors);
    }
    if let Some(tls) = policy.tls.as_ref() {
        validate_mesh_traffic_policy_tls(format!("{context}.tls"), tls, errors);
    }
    if let Some(locality) = policy.locality_lb_setting.as_ref() {
        validate_mesh_locality_lb_setting(
            format!("{context}.locality_lb_setting"),
            locality,
            errors,
        );
    }
}

fn validate_mesh_locality_lb_setting(
    context: String,
    locality: &MeshLocalityLbSetting,
    errors: &mut Vec<String>,
) {
    let has_distribute = !locality.distribute.is_empty();
    let has_failover = !locality.failover.is_empty();
    let has_failover_priority = !locality.failover_priority.is_empty();
    let mode_count = has_distribute as u8 + has_failover as u8 + has_failover_priority as u8;
    if mode_count > 1 {
        errors.push(format!(
            "{context}: must set only one of distribute, failover, or failover_priority"
        ));
    }

    for (idx, entry) in locality.distribute.iter().enumerate() {
        if entry.from.trim().is_empty() {
            errors.push(format!(
                "{context}.distribute[{idx}].from: must not be empty"
            ));
        }
        if entry.to.is_empty() {
            errors.push(format!("{context}.distribute[{idx}].to: must not be empty"));
        }
    }

    for (idx, entry) in locality.failover.iter().enumerate() {
        if entry.from.trim().is_empty() {
            errors.push(format!("{context}.failover[{idx}].from: must not be empty"));
        }
        if entry.to.trim().is_empty() {
            errors.push(format!("{context}.failover[{idx}].to: must not be empty"));
        }
        if !entry.from.is_empty() && entry.from == entry.to {
            errors.push(format!(
                "{context}.failover[{idx}]: cannot fail over a region to itself"
            ));
        }
    }

    for (idx, raw) in locality.failover_priority.iter().enumerate() {
        let Some((key, _override)) = crate::config::types::parse_failover_priority_entry(raw)
        else {
            errors.push(format!(
                "{context}.failover_priority[{idx}]: must be a non-empty label key or key=value \
                 entry with exactly one '=' and without leading/trailing whitespace"
            ));
            continue;
        };
        if key.chars().any(|c| c.is_whitespace()) {
            errors.push(format!(
                "{context}.failover_priority[{idx}]: key must not contain whitespace"
            ));
        }
    }
}

fn validate_mesh_outlier_detection(
    context: String,
    outlier: &MeshOutlierDetection,
    errors: &mut Vec<String>,
) {
    // Istio treats `consecutive5xxErrors: 0` as *disabling* 5xx ejection rather
    // than as an out-of-range value, and the K8s translator preserves the
    // `Some(0)` verbatim. Rejecting it here would make a valid Istio config fail
    // mesh startup/reload, so only reject negatives-via-overflow ranges and the
    // degenerate zero-interval / zero-base-ejection cases that disable recovery.
    if matches!(outlier.interval_seconds, Some(0)) {
        errors.push(format!(
            "{context}.interval_seconds: must be greater than 0"
        ));
    }
    // Istio requires `baseEjectionTime` to be at least 1ms; a `Some(0)` projects
    // onto `PassiveHealthCheck.healthy_after_seconds = 0`, which disables
    // automatic readmission (ejected hosts are never recovered). The native/file
    // path deserializes seconds as an integer, so reject the zero case at the
    // boundary instead of producing never-readmitted passive ejections.
    if matches!(outlier.base_ejection_seconds, Some(0)) {
        errors.push(format!(
            "{context}.base_ejection_seconds: must be greater than 0"
        ));
    }
    if let Some(max_ejection_percent) = outlier.max_ejection_percent
        && max_ejection_percent > 100
    {
        errors.push(format!(
            "{context}.max_ejection_percent: must be from 0 to 100"
        ));
    }
}

fn validate_mesh_traffic_policy_tls(
    context: String,
    tls: &MeshTrafficPolicyTls,
    errors: &mut Vec<String>,
) {
    if let Some(ca_certificates) = tls.ca_certificates.as_deref()
        && let Err(error) = crate::config::types::validate_tls_material_source_field(
            &format!("{context}.ca_certificates"),
            ca_certificates,
            crate::tls::source::MaterialKind::CaBundle,
        )
    {
        errors.push(error);
    }
    if let Some(error) = crate::config::types::validate_system_trust_roots_skip_verify_pairing(
        &format!("{context}.ca_certificates"),
        &format!("{context}.insecure_skip_verify"),
        tls.ca_certificates.as_deref(),
        tls.insecure_skip_verify,
    ) {
        errors.push(error);
    }

    match tls.mode {
        MtlsMode::Strict | MtlsMode::Permissive => errors.push(format!(
            "{context}.mode: {mode:?} is invalid for DestinationRule client TLS",
            mode = tls.mode
        )),
        MtlsMode::Mutual => {
            validate_required_tls_path(
                format!("{context}.client_certificate"),
                tls.client_certificate.as_deref(),
                errors,
            );
            validate_required_tls_path(
                format!("{context}.private_key"),
                tls.private_key.as_deref(),
                errors,
            );
        }
        MtlsMode::IstioMutual => {
            // Istio requires every ClientTLSSettings field to be empty for
            // ISTIO_MUTUAL: the workload SVID and its trust bundle are used and
            // any caller-supplied cert/key/CA is silently ignored at TLS apply.
            // Reject stray fields at the boundary instead of letting the slice
            // silently change the trust configuration.
            if tls.client_certificate.is_some() {
                errors.push(format!(
                    "{context}.client_certificate: must be absent when mode is IstioMutual"
                ));
            }
            if tls.private_key.is_some() {
                errors.push(format!(
                    "{context}.private_key: must be absent when mode is IstioMutual"
                ));
            }
            if tls.ca_certificates.is_some() {
                errors.push(format!(
                    "{context}.ca_certificates: must be absent when mode is IstioMutual"
                ));
            }
        }
        MtlsMode::Disable | MtlsMode::Simple => {}
    }
}

fn validate_required_tls_path(context: String, value: Option<&str>, errors: &mut Vec<String>) {
    if value.is_none_or(|value| value.trim().is_empty()) {
        errors.push(format!("{context}: must be set and non-empty"));
    }
}

/// Validate a DestinationRule `connectionPool` block from the native/file mesh
/// slice path, matching the lower-bound checks the K8s translator
/// (`translate_http_uint32`, `translate_tcp_max_connections`) enforces at parse
/// time.
///
/// Two fields are load-bearing because `Some(0)` is a hard-deny at runtime
/// rather than "unlimited", so an accidental `0` on a hand-authored native/file
/// DR would silently blackhole traffic to the matched destination:
///
/// * `http1MaxPendingRequests` — the
///   [`crate::backend_pending_limit::BackendPendingLimiter`] sheds every
///   HTTP/1.1 request at `0`.
/// * `tcp.maxConnections` — the
///   [`crate::backend_conn_limit::BackendConnectionLimiter`] refuses every
///   backend connection at `0`, on every transport (stream, WebSocket, and the
///   pooled multiplexed pools), so the destination becomes unreachable.
///
/// The K8s translator rejects 0/negative for both; this keeps the native/file
/// path equivalent. `maxRetries: 0` is valid and explicitly disables an existing
/// retry policy for the selected destination; negatives are already impossible
/// because these fields deserialize as `u32`.
fn validate_dr_connection_pool(
    context: &str,
    policy: Option<&MeshTrafficPolicy>,
    errors: &mut Vec<String>,
) {
    let Some(policy) = policy else {
        return;
    };
    if policy.max_connections == Some(0) {
        errors.push(format!(
            "{context}.connectionPool.tcp.maxConnections must be positive (0 would refuse every backend connection)"
        ));
    }
    let Some(http) = policy.connection_pool_http.as_ref() else {
        return;
    };
    if http.http1_max_pending_requests == Some(0) {
        errors.push(format!(
            "{context}.connectionPool.http.http1MaxPendingRequests must be positive (0 would shed every HTTP/1.1 request)"
        ));
    }
}

fn is_valid_sidecar_host_pattern(pattern: &str) -> bool {
    let trimmed = pattern.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    match trimmed.split_once('/') {
        Some(("*", "*")) => true,
        Some(("*", host)) | Some((".", host)) => !host.is_empty() && !host.contains('/'),
        Some((namespace, "*")) => !namespace.is_empty(),
        Some((namespace, host)) => !namespace.is_empty() && !host.is_empty() && !host.contains('/'),
        None => true,
    }
}

fn validate_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundles: Option<&TrustBundleSet>,
    errors: &mut Vec<String>,
) {
    // `local_cluster` participates in the same operator-visible cluster-identity
    // domain as `RemoteCluster.name` (workload.cluster comparisons, remote
    // provenance). Reject surrounding whitespace rather than silently rewriting
    // so config identity stays byte-stable and cannot alias a trimmed peer.
    if let Some(local_cluster) = multi_cluster.local_cluster.as_deref() {
        let canonical = local_cluster.trim();
        if canonical.is_empty() {
            errors.push("MultiClusterConfig.local_cluster must not be empty when set".to_string());
        } else if local_cluster != canonical {
            errors.push(
                "MultiClusterConfig.local_cluster must not have leading/trailing whitespace"
                    .to_string(),
            );
        }
    }
    if multi_cluster
        .federation_endpoint
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        errors
            .push("MultiClusterConfig.federation_endpoint must not be empty when set".to_string());
    }
    if multi_cluster.remote_clusters.len() > MAX_MESH_REMOTE_CLUSTERS {
        errors.push(format!(
            "MultiClusterConfig.remote_clusters has {} entries; max is {}",
            multi_cluster.remote_clusters.len(),
            MAX_MESH_REMOTE_CLUSTERS
        ));
    }

    // Uniqueness is keyed on the SAME canonical identity `remote_discovery_audience`
    // uses (trimmed `RemoteCluster.name` → JWT `aud`). Surrounding-whitespace
    // aliases are rejected outright — never rewritten — because the raw name
    // also keys remote discovery state and operator-visible config. Validation
    // runs before any remote poller is spawned, so a colliding audience cannot
    // reach minting.
    let mut seen_cluster_names = HashSet::new();
    for remote in &multi_cluster.remote_clusters {
        let canonical_name = remote.name.trim();
        if canonical_name.is_empty() {
            errors.push("RemoteCluster: name must not be empty".to_string());
        } else {
            if remote.name.as_str() != canonical_name {
                errors.push(format!(
                    "RemoteCluster '{}': name must not have leading/trailing whitespace",
                    remote.name
                ));
            }
            if !seen_cluster_names.insert(canonical_name) {
                errors.push(format!("RemoteCluster '{}': duplicate name", remote.name));
            }
        }
        if remote
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': network must not be empty when set",
                remote.name
            ));
        }
        if remote
            .control_plane_url
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': control_plane_url must not be empty when set",
                remote.name
            ));
        }
        if remote
            .federation_endpoint
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': federation_endpoint must not be empty when set",
                remote.name
            ));
        }
        if remote
            .discovery_credential_ref
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "RemoteCluster '{}': discovery_credential_ref must not be empty when set",
                remote.name
            ));
        }

        if let Some(tb_set) = trust_bundles
            && remote.trust_domain != tb_set.local.trust_domain
            && !tb_set
                .federated
                .iter()
                .any(|bundle| bundle.trust_domain == remote.trust_domain)
        {
            errors.push(format!(
                "RemoteCluster '{}': trust domain '{}' has no matching federated trust bundle",
                remote.name, remote.trust_domain
            ));
        }
    }

    // Per-gateway field validation. Cross-gateway SNI-overlap ambiguity is
    // checked in a SEPARATE pairwise pass below — it needs the SAME wildcard-
    // aware `hosts_overlap` semantics `select_east_west_gateway_for_network` uses
    // to resolve a destination FQDN, which a literal per-SNI-string key cannot
    // express.
    for gateway in &multi_cluster.east_west_gateways {
        if gateway.name.trim().is_empty() {
            errors.push("EastWestGateway: name must not be empty".to_string());
        }
        if gateway.namespace.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': namespace must not be empty",
                gateway.name
            ));
        }
        if gateway.host.trim().is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': host must not be empty",
                gateway.name
            ));
        }
        if gateway.port == 0 {
            errors.push(format!(
                "EastWestGateway '{}': port must be between 1 and 65535",
                gateway.name
            ));
        }
        if gateway.sni_hosts.is_empty() {
            errors.push(format!(
                "EastWestGateway '{}': sni_hosts must not be empty",
                gateway.name
            ));
        }
        if gateway
            .network
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            errors.push(format!(
                "EastWestGateway '{}': network must not be empty when set",
                gateway.name
            ));
        }
        for sni in &gateway.sni_hosts {
            if sni.trim().is_empty() {
                errors.push(format!(
                    "EastWestGateway '{}': sni_hosts must not contain empty entries",
                    gateway.name
                ));
            }
        }
    }

    // [R4-1] Reject AMBIGUOUS east-west gateway claims using the SAME wildcard-
    // aware host-overlap semantics the selector uses. Two gateways on the SAME
    // network whose trust domains OVERLAP (a TD-less gateway is a wildcard that
    // overlaps every trust domain; two specific TDs overlap only when EQUAL) AND
    // whose `sni_hosts` OVERLAP under east-west alias-aware host semantics (so
    // `*.default.svc.cluster.local` vs `reviews.default.svc.cluster.local`, and
    // `reviews.default.svc.cluster.local` vs `p9090.reviews.default.svc.cluster.local`,
    // are caught, not only literal string equality) can BOTH route the same
    // destination FQDN, and `select_east_west_gateway_for_network` would silently
    // pick whichever is first. On a CLIENT data plane these are remote gateways
    // across networks, so a DIFFERENT network is never a collision; on an
    // EastWestGateway data plane same-host passthrough-proxy collisions remain
    // caught downstream by `validate_stream_proxies`. (Gateways with an empty
    // `sni_hosts` are already rejected above, so they are skipped here rather
    // than reported a second time as catch-all overlaps.)
    let gateways = &multi_cluster.east_west_gateways;
    for (earlier_idx, earlier) in gateways.iter().enumerate() {
        if earlier.sni_hosts.is_empty() {
            continue;
        }
        for later in gateways.iter().skip(earlier_idx + 1) {
            if later.sni_hosts.is_empty() {
                continue;
            }
            let same_network = earlier.network.as_deref().map(str::to_ascii_lowercase)
                == later.network.as_deref().map(str::to_ascii_lowercase);
            if !same_network {
                continue;
            }
            let trust_domains_overlap = match (&earlier.trust_domain, &later.trust_domain) {
                (None, _) | (_, None) => true,
                (Some(a), Some(b)) => a == b,
            };
            if !trust_domains_overlap {
                continue;
            }
            // Lowercase both SNI lists so the overlap is case-insensitive even on
            // un-normalized input (`validate` can run before `normalize_mesh_fields`),
            // matching how the selector compares against a lowercased FQDN.
            let earlier_snis: Vec<String> = earlier
                .sni_hosts
                .iter()
                .map(|sni| sni.to_ascii_lowercase())
                .collect();
            let later_snis: Vec<String> = later
                .sni_hosts
                .iter()
                .map(|sni| sni.to_ascii_lowercase())
                .collect();
            if east_west_sni_hosts_overlap(&earlier_snis, &later_snis) {
                errors.push(format!(
                    "EastWestGateway '{}': sni_hosts overlap EastWestGateway '{}' on the same \
                     network for an overlapping trust domain (both can route the same destination \
                     FQDN or per-port SNI alias; selection would silently pick one — disambiguate \
                     by sni_hosts, network, or trust_domain)",
                    later.name, earlier.name
                ));
            }
        }
    }
}

/// East-west gateway selection treats a service base FQDN as also owning its
/// generated `p<port>.<base-fqdn>` aliases. Validation must therefore reject not
/// only raw host/wildcard overlaps, but also a configured base FQDN on one
/// gateway and a configured per-port alias of that base FQDN on another gateway.
fn east_west_sni_hosts_overlap(a: &[String], b: &[String]) -> bool {
    if crate::config::types::hosts_overlap(a, b) {
        return true;
    }

    let a_bases: Vec<String> = a
        .iter()
        .filter_map(|host| east_west_alias_claim_base(host))
        .collect();
    if !a_bases.is_empty() && crate::config::types::hosts_overlap(&a_bases, b) {
        return true;
    }

    let b_bases: Vec<String> = b
        .iter()
        .filter_map(|host| east_west_alias_claim_base(host))
        .collect();
    !b_bases.is_empty() && crate::config::types::hosts_overlap(a, &b_bases)
}

/// Return the base service FQDN claimed by a generated exact alias
/// (`p<port>.<base>`) or by a wildcard alias owner (`*.<base>`).
///
/// The suffix must have Ferrum's `<service>.<namespace>.svc.<cluster-domain>`
/// shape. This keeps unrelated explicit hosts such as `p9090.example.com`
/// literal: runtime cross-cluster service routing never derives them as aliases.
fn east_west_alias_claim_base(host: &str) -> Option<String> {
    let (alias_label, base) = host.split_once('.')?;
    if !mesh_service_fqdn_like(base) {
        return None;
    }
    if alias_label == "*" {
        return Some(base.to_string());
    }

    let port = alias_label.strip_prefix('p')?;
    // `cross_cluster_service_sni` renders a non-zero u16 without leading
    // zeroes. Recognize only that canonical generated namespace so an ordinary
    // hostname such as `p65536.example` is not reinterpreted as an alias.
    let Ok(port_number) = port.parse::<u16>() else {
        return None;
    };
    if base.is_empty() || port.starts_with('0') || port_number == 0 {
        return None;
    }
    Some(base.to_string())
}

fn mesh_service_fqdn_like(host: &str) -> bool {
    let mut labels = host.split('.');
    labels.next().is_some_and(|label| !label.is_empty())
        && labels.next().is_some_and(|label| !label.is_empty())
        && labels.next() == Some("svc")
        && labels.next().is_some_and(|label| !label.is_empty())
        && labels.all(|label| !label.is_empty())
}

/// Lower-case in-place hostname normalisation for mesh entries — matches
/// the existing `normalize_fields()` pattern used elsewhere in
/// [`crate::config::types`]. Idempotent.
pub fn normalize_mesh_fields(service_entries: &mut [ServiceEntry], workloads: &mut [Workload]) {
    normalize_mesh_fields_internal(
        service_entries,
        workloads,
        &mut [],
        &mut [],
        &mut [],
        &mut [],
        None,
    );
}

fn normalize_mesh_fields_internal(
    service_entries: &mut [ServiceEntry],
    workloads: &mut [Workload],
    policies: &mut [MeshPolicy],
    destination_rules: &mut [MeshDestinationRule],
    sidecars: &mut [MeshSidecar],
    virtual_service_cors_policies: &mut [MeshVirtualServiceCorsPolicy],
    multi_cluster: Option<&mut MultiClusterConfig>,
) {
    for se in service_entries {
        for host in &mut se.hosts {
            *host = normalize_mesh_hostname_like(host);
        }
        normalize_mesh_export_to(&mut se.export_to);
        for ep in &mut se.endpoints {
            ep.address.make_ascii_lowercase();
        }
    }
    for workload in workloads {
        for address in &mut workload.addresses {
            address.make_ascii_lowercase();
        }
    }
    normalize_mesh_policy_fields(policies);
    for dr in destination_rules {
        dr.host = normalize_mesh_hostname_like(&dr.host);
        // `exportTo` is semantic identity carried through native, file, and
        // xDS JSON. Canonicalize the same whitespace the evaluator and
        // validator recognize so equivalent visibility does not produce
        // different carrier bytes or defeat slice dedupe.
        normalize_mesh_export_to(&mut dr.export_to);
    }
    // Same treatment as DestinationRule hosts: synthesis matches
    // `policy.host` against service FQDNs via `destination_rule_host_matches`
    // (no trimming/lowercasing there), so an un-normalized native/file host
    // like `" Svc.Default "` would silently attach no CORS plugin.
    for policy in virtual_service_cors_policies {
        policy.host = normalize_mesh_hostname_like(&policy.host);
        normalize_mesh_export_to(&mut policy.export_to);
    }
    for sidecar in sidecars {
        for egress in &mut sidecar.egress {
            for host in &mut egress.hosts {
                *host = normalize_mesh_hostname_like(host);
            }
        }
    }
    if let Some(multi_cluster) = multi_cluster {
        for gateway in &mut multi_cluster.east_west_gateways {
            gateway.host.make_ascii_lowercase();
            for sni in &mut gateway.sni_hosts {
                sni.make_ascii_lowercase();
            }
        }
    }
}

/// `pub(crate)` because the CORS synthesis path (`modes::mesh::mod`) also
/// normalizes carried policy hosts with it when matching against service
/// FQDNs — a slice arriving over the native/xDS carriers never passes
/// `MeshConfig::normalize()`, so the consumer must normalize its own key.
pub(crate) fn normalize_mesh_hostname_like(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_mesh_policy_fields(policies: &mut [MeshPolicy]) {
    for policy in policies {
        for rule in &mut policy.rules {
            for request in &mut rule.to {
                for host in &mut request.hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for host in &mut request.not_hosts {
                    *host = normalize_request_match_host_pattern(host);
                }
                for pattern in &mut request.port_patterns {
                    let trimmed = pattern.trim();
                    if trimmed.len() != pattern.len() {
                        *pattern = trimmed.to_string();
                    }
                }
                for pattern in &mut request.not_port_patterns {
                    let trimmed = pattern.trim();
                    if trimmed.len() != pattern.len() {
                        *pattern = trimmed.to_string();
                    }
                }
                normalize_mesh_policy_header_map(&mut request.headers);
            }
        }
    }
}

/// Normalise a `RequestMatch.hosts` glob pattern at config-load time so the
/// authorization hot path never re-normalises on every request.
///
/// Mirrors `normalize_match_host` for inbound request authorities so a pattern
/// `Example.COM:8443` and a request `example.com:8443` produce equal strings.
/// Lower-cases ASCII, strips a trailing dot from the host portion, and
/// preserves any explicit `:port` (or `:*`) suffix.
pub(crate) fn normalize_request_match_host_pattern(pattern: &str) -> String {
    let pattern = pattern.trim().to_ascii_lowercase();
    if pattern.starts_with('[') {
        return pattern;
    }
    if let Some((name, port)) = pattern.rsplit_once(':')
        && !name.contains(':')
    {
        let name = name.strip_suffix('.').unwrap_or(name);
        return format!("{name}:{port}");
    }
    pattern
        .strip_suffix('.')
        .map(ToOwned::to_owned)
        .unwrap_or(pattern)
}

/// Cold-path admission outcome for Istio/Ferrum port wildcard patterns.
///
/// Shared by the Istio AuthorizationPolicy translator (`ports` / `notPorts`)
/// and native MeshPolicy validation (`port_patterns` / `not_port_patterns`) so
/// grammar and semantic checks cannot drift across surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortPatternAdmission {
    /// Pattern is one of `*` / `<digits>*` / `*<digits>` and matches at least
    /// one ordinary decimal port in `1..=65535`.
    Admissible,
    /// Pattern has the wildcard grammar above but cannot match any port in
    /// `1..=65535` (for example `70000*` or `0*`).
    Inadmissible,
    /// Not a port wildcard pattern; callers may attempt literal `u16` parse.
    NotAPattern,
}

/// Canonical bounded port-pattern admissibility helper.
///
/// Accepts only `*`, `<digits>*`, or `*<digits>`, and only when the pattern can
/// match at least one ordinary decimal port in `1..=65535` (no leading zeroes
/// in port representations). Mid-string stars, named ports, empty values, and
/// semantically impossible digit wildcards are not admissible. Cold-path only.
pub(crate) fn admit_request_match_port_pattern(pattern: &str) -> PortPatternAdmission {
    if pattern == "*" {
        return PortPatternAdmission::Admissible;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        // Reject mid-string stars such as `8*9` (prefix still contains `*`).
        if prefix.is_empty() || prefix.contains('*') {
            return PortPatternAdmission::NotAPattern;
        }
        if !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return PortPatternAdmission::NotAPattern;
        }
        return if port_prefix_pattern_is_admissible(prefix) {
            PortPatternAdmission::Admissible
        } else {
            PortPatternAdmission::Inadmissible
        };
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        if suffix.is_empty() || suffix.contains('*') {
            return PortPatternAdmission::NotAPattern;
        }
        if !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
            return PortPatternAdmission::NotAPattern;
        }
        return if port_suffix_pattern_is_admissible(suffix) {
            PortPatternAdmission::Admissible
        } else {
            PortPatternAdmission::Inadmissible
        };
    }
    PortPatternAdmission::NotAPattern
}

/// True when `pattern` is an admissible Istio/Ferrum port wildcard.
pub(crate) fn is_valid_request_match_port_pattern(pattern: &str) -> bool {
    admit_request_match_port_pattern(pattern) == PortPatternAdmission::Admissible
}

/// Prefix form `<digits>*`: ordinary decimal ports never use leading zeroes, so
/// a zero-prefixed digit string can never match `1..=65535`. A non-zero prefix
/// is admissible iff it is itself the decimal form of some port in range
/// (longer ports that share the prefix are then also covered).
fn port_prefix_pattern_is_admissible(prefix: &str) -> bool {
    if prefix.as_bytes().first().copied() == Some(b'0') {
        return false;
    }
    match prefix.parse::<u32>() {
        Ok(value) => (1..=65535).contains(&value),
        Err(_) => false,
    }
}

/// Suffix form `*<digits>`: admissible when some port in `1..=65535` has a
/// decimal representation ending with `suffix` (leading zeroes in the suffix
/// are meaningful, e.g. `*0001` is witnessed by `10001`).
fn port_suffix_pattern_is_admissible(suffix: &str) -> bool {
    let len = suffix.len();
    if len > 5 {
        return false;
    }
    let modulus = 10u32.pow(len as u32);
    let Ok(target) = suffix.parse::<u32>() else {
        return false;
    };
    // Smallest port whose decimal form has at least `len` digits.
    let min_with_len = if len == 1 {
        1u32
    } else {
        10u32.pow((len - 1) as u32)
    };
    let rem = min_with_len % modulus;
    let first = if rem <= target {
        min_with_len + (target - rem)
    } else {
        min_with_len + (modulus - rem) + target
    };
    let mut candidate = first;
    while candidate <= 65535 {
        if candidate >= 1 {
            return true;
        }
        match candidate.checked_add(modulus) {
            Some(next) => candidate = next,
            None => break,
        }
    }
    false
}

/// True when `pattern` is a syntactically valid `RequestMatch.hosts` entry.
///
/// Accepts:
///   - bare hostname / glob (any chars except `:`, `@`)
///   - bracketed IPv6 literal `[...]`, optionally followed by `:port` or `:*`
///   - `host:port` or `host:*` where `host` has no other `:`
///
/// Rejects:
///   - empty / `@`-bearing values
///   - `host:abc` / `host:` (port is neither digits nor `*`)
///   - multiple `:` outside an IPv6 bracket
fn is_valid_request_match_host_pattern(pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.contains('@') {
        return false;
    }
    if let Some(rest) = pattern.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return false;
        };
        if close == 0 {
            return false;
        }
        let suffix = &rest[close + 1..];
        return suffix.is_empty()
            || suffix
                .strip_prefix(':')
                .is_some_and(is_request_match_host_port_token);
    }
    match pattern.rsplit_once(':') {
        Some((name, port)) => {
            !name.is_empty() && !name.contains(':') && is_request_match_host_port_token(port)
        }
        None => true,
    }
}

fn is_request_match_host_port_token(token: &str) -> bool {
    if token == "*" {
        return true;
    }
    token.parse::<u16>().is_ok()
}

pub(crate) fn normalize_mesh_policy_header_map(headers: &mut HashMap<String, String>) {
    if headers
        .keys()
        .all(|key| key.bytes().all(|byte| !byte.is_ascii_uppercase()))
    {
        return;
    }

    let mut entries = headers.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(key, _)| *key);

    let mut normalized = HashMap::with_capacity(headers.len());
    for (key, value) in entries {
        let lower = key.to_ascii_lowercase();
        let prefer_value =
            key == &lower || !headers.contains_key(&lower) || !normalized.contains_key(&lower);
        if prefer_value {
            normalized.insert(lower, value.clone());
        }
    }

    *headers = normalized;
}

// ── MeshRuntimeOverlay (GAP-3E) ───────────────────────────────────────────

/// Mesh runtime knobs sourced from xDS RTDS (`envoy.service.runtime.v3.Runtime`)
/// layers.
///
/// The overlay is carried verbatim on
/// [`crate::modes::mesh::slice::MeshSlice`]; operators inspect it via
/// `GET /mesh/runtime-overlay`. Fault-injection percentages are captured in
/// the same plugin cache / request epoch as the config they modify
/// ([`crate::plugins::fault_injection::runtime_overlay`]). Accepted slices also
/// fan the remaining process-wide knobs out through
/// [`crate::modes::mesh::runtime_overlay_consumers::apply_overlay`]:
/// request/response transformer gates
/// ([`crate::plugins::request_transformer::runtime_overlay`],
/// [`crate::plugins::response_transformer::runtime_overlay`]), and the
/// gateway-wide tracing filter ([`crate::logging::runtime_overlay`]).
///
/// Wire compatibility: the type is an optional field on `MeshSlice` with
/// `#[serde(default, skip_serializing_if = "MeshRuntimeOverlay::is_empty")]`,
/// so non-RTDS deployments round-trip byte-identical.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MeshRuntimeOverlay {
    /// Top-level keys flattened from the RTDS layer's `google.protobuf.Struct`
    /// payload. Keys are runtime feature names
    /// (e.g. `envoy.reloadable_features.allow_multiplexed_response`); values
    /// preserve the typed shape from the wire.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub fields: HashMap<String, RuntimeValue>,
}

impl MeshRuntimeOverlay {
    /// Cheap emptiness check used by both `skip_serializing_if` and runtime
    /// callers that want to elide overlay handling when no layer has shipped
    /// any fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Typed runtime value mapped from an RTDS layer field.
///
/// Mirrors the subset of `google.protobuf.Value` kinds that RTDS layers ship
/// in practice. `null` and list values are intentionally absent — Envoy / Istio
/// CPs do not emit them as runtime knob values today, and inventing a
/// placeholder semantics here would be a footgun once consumers land.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RuntimeValue {
    Number(f64),
    String(String),
    Bool(bool),
    FractionalPercent(RuntimeFractionalPercent),
}

/// Envoy `type.v3.FractionalPercent`-shaped runtime value. RTDS layers
/// encode it on the wire as a `google.protobuf.Struct` with two fields,
/// `numerator: number` and `denominator: string`, where the string is one of
/// the three named denominators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFractionalPercent {
    pub numerator: u32,
    pub denominator: FractionalPercentDenominator,
}

impl RuntimeFractionalPercent {
    /// Convert to a 0.0–100.0 percentage. Saturates at 100.0 if the operator
    /// supplied a numerator larger than the denominator. Used by RTDS
    /// consumers that work in `f64` percent space (e.g. fault injection).
    pub fn as_percent(&self) -> f64 {
        let denom = self.denominator.units_per_full();
        if denom == 0 {
            return 0.0;
        }
        let pct = (self.numerator as f64 / denom as f64) * 100.0;
        pct.clamp(0.0, 100.0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FractionalPercentDenominator {
    #[default]
    Hundred,
    TenThousand,
    Million,
}

impl FractionalPercentDenominator {
    /// The number of units the `numerator` is expressed against. `Hundred`
    /// → 100, `TenThousand` → 10_000, `Million` → 1_000_000.
    pub fn units_per_full(&self) -> u64 {
        match self {
            FractionalPercentDenominator::Hundred => 100,
            FractionalPercentDenominator::TenThousand => 10_000,
            FractionalPercentDenominator::Million => 1_000_000,
        }
    }
}

/// Extract a `0.0..=100.0` percentage from a [`RuntimeValue`] for consumers
/// that work in percent space. Accepts:
///
///   - `RuntimeValue::Number(n)` where `0.0 <= n <= 100.0`
///   - `RuntimeValue::FractionalPercent(fp)` (via `as_percent`)
///
/// Returns `None` for any other shape so RTDS consumers can fall back to
/// their static config without aborting the slice install.
pub fn runtime_value_as_percent(value: &RuntimeValue) -> Option<f64> {
    match value {
        RuntimeValue::Number(n) if n.is_finite() && (0.0..=100.0).contains(n) => Some(*n),
        RuntimeValue::FractionalPercent(fp) => Some(fp.as_percent()),
        _ => None,
    }
}

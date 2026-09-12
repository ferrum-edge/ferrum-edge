//! NodeWaypoint per-datagram UDP/DTLS source-workload identity (issue #3286).
//!
//! # The gap this closes
//!
//! NodeWaypoint scopes a TCP stream's source pod through the socket-cookie
//! bridge (`resolve_node_waypoint_stream_scope` in `super::tcp_proxy`), so
//! namespace/selector-scoped `AuthorizationPolicy` enforces per source workload.
//! UDP/DTLS had no equivalent: eBPF capture is `connect()`-hooked and TCP-only,
//! and one UDP listener demuxes every client off a single shared frontend
//! socket, so there is no per-source-pod socket cookie to resolve. The slice
//! preparation step therefore DISABLED every NodeWaypoint UDP/DTLS service port
//! and proxy as soon as one enforcing scoped policy existed — fail-closed, but
//! an outage for the workloads it protected.
//!
//! # The channel
//!
//! A NodeWaypoint proxy runs `hostNetwork: true`, so a local pod's datagram
//! enters the host namespace on THAT pod's host-side interface and nothing else
//! does. That is the same exact (not heuristic) discriminator
//! [`super::host_udp_capture`] established for Ambient host-network capture, and
//! this module deliberately reuses its planner
//! ([`super::host_udp_capture::plan_host_udp_bindings`]) so the two cannot
//! diverge on what counts as an attributable pod.
//!
//! Every admitted datagram is attributed from two independent KERNEL-provided
//! facts, never from its payload and never from operator input:
//!
//! * `IP_PKTINFO` / `IPV6_PKTINFO` — the ingress interface index.
//! * the datagram's source address, which must be one the interface's pod is
//!   registered (by the node-agent) to source from.
//!
//! Forging a source address does not change which interface a packet entered
//! on, and an interface belongs to exactly one enrolled pod, so a workload
//! cannot assert a neighbour's identity. An interface claimed by more than one
//! enrolled pod is refused for BOTH claimants rather than guessed.
//!
//! # Fail-closed, never mesh-wide-fallback
//!
//! Resolution yields `(pod identity, PolicyScopeCache)` or nothing. Nothing
//! leaves `StreamConnectionContext::node_waypoint_policy_scope` absent, and
//! `mesh_authz`'s stream path then rejects the session (403) whenever any
//! namespace/selector-scoped policy exists — exactly the gate the TCP path
//! applies. There is no plaintext lane and no mesh-wide fallback while scoped
//! enforcement applies.
//!
//! The scope comes from the SAME live-slice read that vouches the pod
//! ([`crate::modes::mesh::node_waypoint::NodeWaypointIdentityResolver::policy_scope_for_pod`]),
//! so a workload that left the slice resolves to no scope and fails closed
//! rather than borrowing a stale one.
//!
//! # Sessions, churn, and ABA
//!
//! An admitted session pins the exact [`NodeWaypointUdpSourceBinding`] that
//! authorized its first datagram. Every subsequent datagram of that session is
//! re-authorized against the CURRENT published generation and must still resolve
//! to an attribution-identical binding
//! ([`NodeWaypointUdpSourceBinding::attribution_eq`]). That is what makes pod
//! churn safe: a veth index recycled onto a different pod, a pod restarted under
//! a new UID at the same address, or a workload removed from the registry all
//! change the attribution, so the in-flight session stops being served instead
//! of continuing under evidence this generation no longer vouches for. Sessions
//! also pin the coherent accepted mesh-slice generation that supplied their
//! plugin chain and policy scope; every later accepted slice retires the old
//! authorization lifetime, including for a session admitted unattributable under
//! mesh-wide-only policy. An unchanged registry republish compares equal and
//! disturbs nothing.
//!
//! # Bounds
//!
//! * Published bindings are bounded by
//!   `crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES` (the planner enforces it
//!   and reports the overflow as a refusal, never a silent truncation).
//! * Refusal counters are a fixed array over a CLOSED enum, so no
//!   registry-supplied or peer-supplied value ever becomes a metric label or a
//!   map key.
//! * Warn logging is rate-limited per refusal kind with a suppressed count.
//!
//! The reconcile logic is platform-independent and unit-tested with a mock
//! interface resolver; the procfs/sysfs resolution is Linux-only.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::host_udp_capture::{
    HostUdpDesiredState, HostUdpPodBinding, ResolvedInterface, plan_host_udp_bindings,
};
use super::netns_capture::{PodCaptureSource, PodCaptureTarget};
use crate::identity::SpiffeId;
use crate::modes::mesh::node_waypoint::{NodeWaypointIdentityResolver, parse_pod_uid};
use crate::modes::mesh::runtime::PolicyScopeCache;

/// Plan which enrolled pods are attributable for NodeWaypoint UDP/DTLS.
///
/// A thin, deliberately non-forking alias of
/// [`super::host_udp_capture::plan_host_udp_bindings`]: the fail-closed rules —
/// an attested identity is mandatory, a published pod address is mandatory, the
/// interface must resolve to a dedicated host-side peer, an interface (by name
/// OR index) claimed by more than one enrolled pod refuses BOTH claimants, and
/// the published set is bounded by
/// `crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES` with the overflow reported
/// as a refusal rather than silently truncated — are exactly the ones this path
/// needs, and having one implementation is what keeps Ambient host capture and
/// NodeWaypoint attribution from disagreeing about which pod owns an interface.
pub fn plan_node_waypoint_udp_bindings(
    targets: &[PodCaptureTarget],
    resolved: &HashMap<String, ResolvedInterface>,
) -> HostUdpDesiredState {
    plan_host_udp_bindings(targets, resolved)
}

/// Rate-limit window for per-refusal-kind warn logging.
const REFUSAL_WARN_WINDOW_MS: u64 = 60_000;

const REFUSAL_WARN_UNSET_MS: u64 = u64::MAX;

/// One enrolled pod's UDP source attribution: the interface its datagrams enter
/// the host namespace on, the addresses it may source from, and the attested
/// workload identity every datagram it sends is authorized under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWaypointUdpSourceBinding {
    /// Parsed pod UID — the same `[u8; 16]` key the slice's per-pod policy-scope
    /// index uses, so scope resolution needs no re-parse on the hot path.
    pub pod_uid: [u8; 16],
    /// Registry-published pod UID text, retained for diagnostics only.
    #[allow(dead_code)] // Diagnostics + external test assertions; unread by the binary target.
    pub pod_uid_text: String,
    /// Attested workload SPIFFE identity for this pod.
    pub principal: SpiffeId,
    pub iface: String,
    pub ifindex: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    /// Index generation this binding was published in. Diagnostics only — never
    /// part of [`Self::attribution_eq`], because an unchanged republish must not
    /// invalidate live sessions.
    #[allow(dead_code)] // Diagnostics + external test assertions; unread by the binary target.
    pub generation: u64,
}

impl NodeWaypointUdpSourceBinding {
    /// Whether `addr` is an address this pod is registered to source from.
    /// IPv4-mapped IPv6 senders are canonicalized by the caller, so a plain
    /// family comparison is exact here.
    fn owns_source(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.ipv4 == Some(v4),
            IpAddr::V6(v6) => self.ipv6 == Some(v6),
        }
    }

    /// Whether two bindings attribute traffic to the SAME workload on the SAME
    /// interface with the SAME permitted sources. `generation` is deliberately
    /// excluded: a republish that changed nothing must leave live sessions
    /// alone, while any real attribution change must end them.
    pub fn attribution_eq(&self, other: &Self) -> bool {
        self.pod_uid == other.pod_uid
            && self.principal == other.principal
            && self.ifindex == other.ifindex
            && self.iface == other.iface
            && self.ipv4 == other.ipv4
            && self.ipv6 == other.ipv6
    }
}

/// Why a datagram could not be attributed to an enrolled source workload.
/// Closed set: safe to log and count without echoing untrusted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointUdpSourceRefusal {
    /// No generation has been published yet (the reconcile loop has not run, or
    /// it published an empty set). Fails closed rather than admitting unscoped
    /// traffic.
    IndexUnavailable,
    /// The kernel reported no ingress interface for the datagram (no
    /// `IP_PKTINFO`/`IPV6_PKTINFO` cmsg, or index 0). Without it the datagram
    /// cannot be attributed, so it is never relayed unattributed.
    NoIngressInterface,
    /// The ingress interface belongs to no currently enrolled pod — including
    /// off-node traffic arriving on the uplink.
    UnenrolledInterface,
    /// The source address is not one the pod owning that interface is
    /// registered to use: a spoofed or stale source.
    SourceAddressMismatch,
    /// The pod is attributable but its workload is not in the live mesh slice,
    /// so no per-pod policy scope exists for it.
    PodNotInSlice,
    /// A live session's attribution changed under it (pod churn, interface
    /// reuse, or registry removal).
    AttributionChanged,
    /// The accepted mesh-slice generation changed after this session's stream
    /// admission. The old plugin chain and per-pod scope are no longer a valid
    /// authorization lifetime, even when the workload's registry attribution
    /// itself is unchanged.
    PolicyGenerationChanged,
}

impl NodeWaypointUdpSourceRefusal {
    pub const COUNT: usize = 7;

    pub fn as_str(self) -> &'static str {
        match self {
            Self::IndexUnavailable => "index_unavailable",
            Self::NoIngressInterface => "no_ingress_interface",
            Self::UnenrolledInterface => "unenrolled_interface",
            Self::SourceAddressMismatch => "source_address_mismatch",
            Self::PodNotInSlice => "pod_not_in_slice",
            Self::AttributionChanged => "attribution_changed",
            Self::PolicyGenerationChanged => "policy_generation_changed",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::IndexUnavailable => 0,
            Self::NoIngressInterface => 1,
            Self::UnenrolledInterface => 2,
            Self::SourceAddressMismatch => 3,
            Self::PodNotInSlice => 4,
            Self::AttributionChanged => 5,
            Self::PolicyGenerationChanged => 6,
        }
    }

    #[allow(dead_code)] // Feeds `refusal_counts`, a diagnostics/test seam.
    fn all() -> [Self; Self::COUNT] {
        [
            Self::IndexUnavailable,
            Self::NoIngressInterface,
            Self::UnenrolledInterface,
            Self::SourceAddressMismatch,
            Self::PodNotInSlice,
            Self::AttributionChanged,
            Self::PolicyGenerationChanged,
        ]
    }
}

/// One published attribution generation. Replaced wholesale so a reader sees the
/// previous mapping or the next one, never a half-applied mix.
#[derive(Debug, Default)]
struct SourceGeneration {
    generation: u64,
    /// Part of the same `ArcSwap` snapshot as the bindings. This makes shutdown
    /// retraction atomic with map replacement: readers see either the prior
    /// published generation or the new retracted generation, never a stale
    /// binding paired with a separately loaded publication flag.
    published: bool,
    by_ifindex: HashMap<u32, Arc<NodeWaypointUdpSourceBinding>>,
}

/// The result of one [`NodeWaypointUdpSourceIndex::publish`] call: the
/// generation number and the interfaces that actually survived publication.
///
/// `ifaces` is the AUTHORITATIVE "which interfaces are attributable this
/// generation" answer — sorted and deduplicated, and empty whenever the
/// generation published nothing (including the over-bound collapse). A
/// contested interface appears in NEITHER claimant's entry, a malformed or
/// UID-mismatched binding contributes nothing, and duplicates collapse.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishedSourceGeneration {
    pub generation: u64,
    pub ifaces: Vec<String>,
}

/// Lock-free ingress-interface-keyed source-evidence index consulted on every
/// captured datagram.
#[derive(Debug)]
pub struct NodeWaypointUdpSourceIndex {
    current: ArcSwap<SourceGeneration>,
    next_generation: AtomicU64,
    refusals: [AtomicU64; NodeWaypointUdpSourceRefusal::COUNT],
    warn_last_ms: [AtomicU64; NodeWaypointUdpSourceRefusal::COUNT],
    warn_suppressed: [AtomicU64; NodeWaypointUdpSourceRefusal::COUNT],
}

impl Default for NodeWaypointUdpSourceIndex {
    fn default() -> Self {
        Self {
            current: ArcSwap::from_pointee(SourceGeneration::default()),
            next_generation: AtomicU64::new(1),
            refusals: std::array::from_fn(|_| AtomicU64::new(0)),
            warn_last_ms: std::array::from_fn(|_| AtomicU64::new(REFUSAL_WARN_UNSET_MS)),
            warn_suppressed: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl NodeWaypointUdpSourceIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a complete new generation. Returns the generation number **and
    /// the exact interface set that survived publication**.
    ///
    /// Returning the surviving set is not a convenience: publication is where
    /// the fail-closed rules below actually take effect, so the caller's
    /// pre-publication wish list is NOT the set of interfaces whose datagrams
    /// can be attributed. Anything that consumes "which interfaces are
    /// attributable" — notably the Service-path steering — must consume this
    /// value, or it would act on interfaces this generation refused.
    ///
    /// Publication is the FINAL authorization boundary for UDP/DTLS source
    /// attribution — everything downstream reads only this index — so it applies
    /// its own fail-closed rules rather than trusting the planner to have
    /// applied them:
    ///
    /// * Bindings whose registry pod UID does not parse are dropped: the parsed
    ///   `[u8; 16]` is the scope-index key, and an unparseable UID could not be
    ///   scoped anyway, so admitting it would only produce an unscoped session.
    /// * A binding whose registry pod UID disagrees with the UID the attested
    ///   identity was issued for is dropped.
    /// * An **ingress interface claimed by more than one binding refuses every
    ///   claimant**, unless the records are attribution-identical
    ///   ([`NodeWaypointUdpSourceBinding::attribution_eq`]: UID, principal,
    ///   ifindex, interface name, IPv4, IPv6). The ingress interface is the
    ///   whole source-evidence channel: conflicting evidence — including the
    ///   same UID/principal with a different interface name or permitted source
    ///   set — means the kernel fact no longer identifies one pod, so admitting
    ///   either would run datagrams under an unvouched name or source set.
    ///   Insertion order is never authoritative, and a later third record cannot
    ///   re-add an already-contested ifindex. `plan_host_udp_bindings` normally
    ///   rejects the conflict first, but a last-writer-wins insert here would
    ///   silently pick a winner if it ever did not.
    /// * The published cardinality stays bounded by
    ///   [`crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES`]. An input that
    ///   exceeds it publishes an EMPTY generation (every datagram then refuses
    ///   `unenrolled_interface`) rather than an arbitrary truncation of which
    ///   pods keep their identity.
    ///
    /// Diagnostics are counts only — no interface name, pod UID, or principal is
    /// logged, so nothing registry-supplied is echoed.
    pub fn publish(&self, bindings: &[HostUdpPodBinding]) -> PublishedSourceGeneration {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut by_ifindex: HashMap<u32, Arc<NodeWaypointUdpSourceBinding>> = HashMap::new();
        // Interfaces withdrawn because two bindings claimed them. Kept so a
        // third claimant cannot re-add an interface a conflict already retired.
        let mut contested_ifindexes: HashSet<u32> = HashSet::new();
        let mut malformed = 0usize;
        for binding in bindings {
            // `pod_uid` is the registry/interface owner while
            // `identity.pod_uid` is the UID bound to the attested principal.
            // They are constructed together on the production registry path,
            // but publication is the final attribution boundary: a mismatched
            // pair must never let pod A's interface/address run under pod B's
            // policy scope or asserted identity.
            if binding.pod_uid != binding.identity.pod_uid {
                malformed += 1;
                continue;
            }
            let Ok(pod_uid) = parse_pod_uid(&binding.pod_uid) else {
                malformed += 1;
                continue;
            };
            if contested_ifindexes.contains(&binding.ifindex) {
                continue;
            }
            let candidate = NodeWaypointUdpSourceBinding {
                pod_uid,
                pod_uid_text: binding.pod_uid.clone(),
                principal: binding.identity.principal.clone(),
                iface: binding.iface.clone(),
                ifindex: binding.ifindex,
                ipv4: binding.ipv4,
                ipv6: binding.ipv6,
                generation,
            };
            if let Some(existing) = by_ifindex.get(&binding.ifindex) {
                // Conflicting evidence for one ingress ifindex refuses every
                // claimant. Only an attribution-identical duplicate may
                // collapse; insertion order is never a winner.
                if !existing.attribution_eq(&candidate) {
                    by_ifindex.remove(&binding.ifindex);
                    contested_ifindexes.insert(binding.ifindex);
                }
                continue;
            }
            by_ifindex.insert(binding.ifindex, Arc::new(candidate));
        }

        if by_ifindex.len() > crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES {
            warn!(
                generation,
                attributable = by_ifindex.len(),
                bound = crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES,
                "NodeWaypoint UDP source attribution exceeds the supported interface bound; \
                 publishing an empty generation so no datagram is attributed under a truncated \
                 index"
            );
            by_ifindex.clear();
        }
        if !contested_ifindexes.is_empty() || malformed > 0 {
            warn!(
                generation,
                contested_interfaces = contested_ifindexes.len(),
                malformed_bindings = malformed,
                published = by_ifindex.len(),
                "NodeWaypoint UDP source attribution refused bindings at publication; a contested \
                 ingress interface refuses every claimant because the kernel fact no longer names \
                 one pod"
            );
        }

        // Derived from the SAME map that is about to become the published
        // generation, after every refusal above, so the two cannot disagree.
        // Sorted and deduplicated so an unchanged registry yields a byte-equal
        // steering plan and the reconcile runs no command.
        let mut ifaces: Vec<String> = by_ifindex
            .values()
            .map(|binding| binding.iface.clone())
            .collect();
        ifaces.sort_unstable();
        ifaces.dedup();

        self.current.store(Arc::new(SourceGeneration {
            generation,
            published: true,
            by_ifindex,
        }));
        PublishedSourceGeneration { generation, ifaces }
    }

    /// Retract every binding and mark the index unpublished, so a socket still
    /// draining cannot attribute a late datagram to a pod that is no longer
    /// covered.
    pub fn clear(&self) {
        self.current.store(Arc::new(SourceGeneration {
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed),
            published: false,
            by_ifindex: HashMap::new(),
        }));
    }

    #[allow(dead_code)] // Diagnostics/test seam; the datapath compares bindings, not generations.
    pub fn generation(&self) -> u64 {
        self.current.load().generation
    }

    #[allow(dead_code)] // Diagnostics/test seam.
    pub fn len(&self) -> usize {
        self.current.load().by_ifindex.len()
    }

    #[allow(dead_code)] // Diagnostics/test seam.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Interfaces that survived the current published attribution generation.
    ///
    /// Empty when the index is unpublished or published nothing. This is the
    /// same set [`Self::publish`] returns; Service-path steering must consume
    /// it rather than the planner's pre-publication list.
    pub fn published_ifaces(&self) -> Vec<String> {
        let snapshot = self.current.load();
        if !snapshot.published {
            return Vec::new();
        }
        let mut ifaces: Vec<String> = snapshot
            .by_ifindex
            .values()
            .map(|binding| binding.iface.clone())
            .collect();
        ifaces.sort_unstable();
        ifaces.dedup();
        ifaces
    }

    /// Per-datagram admission: one lock-free snapshot load, one hash lookup, one
    /// address comparison, one `Arc` retain.
    pub fn authorize(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<Arc<NodeWaypointUdpSourceBinding>, NodeWaypointUdpSourceRefusal> {
        let snapshot = self.current.load();
        if !snapshot.published {
            return Err(self.record(NodeWaypointUdpSourceRefusal::IndexUnavailable));
        }
        let Some(ifindex) = ingress_ifindex.filter(|index| *index != 0) else {
            return Err(self.record(NodeWaypointUdpSourceRefusal::NoIngressInterface));
        };
        let Some(binding) = snapshot.by_ifindex.get(&ifindex) else {
            return Err(self.record(NodeWaypointUdpSourceRefusal::UnenrolledInterface));
        };
        if !binding.owns_source(source.to_canonical()) {
            return Err(self.record(NodeWaypointUdpSourceRefusal::SourceAddressMismatch));
        }
        Ok(binding.clone())
    }

    /// Re-authorize an already-admitted session's datagram against the CURRENT
    /// generation. The stamped binding must still be attribution-identical.
    pub fn revalidate(
        &self,
        pinned: &NodeWaypointUdpSourceBinding,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpSourceRefusal> {
        let current = self.authorize(ingress_ifindex, source)?;
        if current.attribution_eq(pinned) {
            Ok(())
        } else {
            Err(self.record(NodeWaypointUdpSourceRefusal::AttributionChanged))
        }
    }

    fn record(&self, refusal: NodeWaypointUdpSourceRefusal) -> NodeWaypointUdpSourceRefusal {
        self.refusals[refusal.index()].fetch_add(1, Ordering::Relaxed);
        refusal
    }

    /// Monotonic per-reason refusal counts, in [`NodeWaypointUdpSourceRefusal`]
    /// order. Closed-set labels only.
    #[allow(dead_code)] // Diagnostics/test seam.
    pub fn refusal_counts(&self) -> [(&'static str, u64); NodeWaypointUdpSourceRefusal::COUNT] {
        NodeWaypointUdpSourceRefusal::all().map(|refusal| {
            (
                refusal.as_str(),
                self.refusals[refusal.index()].load(Ordering::Relaxed),
            )
        })
    }

    /// Rate-limited warn for a refusal, with the suppressed count folded into
    /// the emitted record. Never echoes a peer- or registry-supplied value
    /// beyond the client IP the proxy already logs elsewhere.
    pub fn warn_refusal(
        &self,
        proxy_id: &str,
        client_ip: &str,
        refusal: NodeWaypointUdpSourceRefusal,
    ) {
        let slot = refusal.index();
        let now_ms = crate::socket_opts::monotonic_now_ms();
        let last_ms = self.warn_last_ms[slot].load(Ordering::Relaxed);
        if last_ms != REFUSAL_WARN_UNSET_MS
            && now_ms.saturating_sub(last_ms) < REFUSAL_WARN_WINDOW_MS
        {
            self.warn_suppressed[slot].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.warn_last_ms[slot]
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            self.warn_suppressed[slot].fetch_add(1, Ordering::Relaxed);
            return;
        }
        let suppressed = self.warn_suppressed[slot].swap(0, Ordering::Relaxed);
        warn!(
            proxy_id = %proxy_id,
            client = %client_ip,
            refusal = refusal.as_str(),
            policy_scope = "missing",
            mesh_authz_scope_missing = true,
            suppressed,
            "NodeWaypoint UDP/DTLS datagram has no attributable source workload; the session \
             carries no per-pod authorization scope and is denied while namespace/selector-scoped \
             AuthorizationPolicies exist"
        );
    }

    /// Warns suppressed by the rate limiter since the last emitted record, for
    /// the given refusal kind. Test seam for the external unit suite.
    #[doc(hidden)]
    #[allow(dead_code)] // External unit-test seam.
    pub fn suppressed_warn_count(&self, refusal: NodeWaypointUdpSourceRefusal) -> u64 {
        self.warn_suppressed[refusal.index()].load(Ordering::Relaxed)
    }
}

/// Everything a UDP/DTLS listener needs to scope a session's source workload:
/// the published attribution index plus the resolver that owns the live slice's
/// per-pod policy scopes.
#[derive(Clone)]
pub struct NodeWaypointUdpSourceScoping {
    pub index: Arc<NodeWaypointUdpSourceIndex>,
    pub resolver: Arc<NodeWaypointIdentityResolver>,
}

/// A fully resolved UDP/DTLS source workload: attributable AND present in the
/// live slice with a per-pod scope.
pub struct ResolvedUdpSource {
    pub binding: Arc<NodeWaypointUdpSourceBinding>,
    pub scope: Arc<PolicyScopeCache>,
    /// Coherent accepted mesh-slice generation that supplied `scope`. Sessions
    /// pin this alongside the binding and close when it changes, so policy-only
    /// updates cannot leave an established datagram flow on an old plugin/scope
    /// generation.
    pub policy_generation: u64,
}

/// How an admitted session must react to one of its datagrams failing
/// re-authorization.
///
/// A UDP session is keyed by the datagram's source address and port, and both
/// are forgeable by anything that can put a packet on the wire — a neighbouring
/// pod with `CAP_NET_RAW`, or an off-node sender. So "this datagram does not
/// attribute to this session's workload" and "this session's own evidence is no
/// longer vouched for" are DIFFERENT facts with different correct reactions,
/// and collapsing them lets a third party end a session it has no relationship
/// to. Neither verdict ever forwards the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeWaypointUdpDatagramVerdict {
    /// This datagram entered the host namespace on an interface other than the
    /// one the session pinned, while the pinned binding still resolves. It
    /// belongs to some other sender, so it is DROPPED and the session is left
    /// alone.
    DropDatagram(NodeWaypointUdpSourceRefusal),
    /// The session's own pinned evidence no longer resolves under the current
    /// generation — veth reuse, a same-address restart under a new UID, a
    /// re-attested identity, or a registry removal. The session must END.
    CloseSession(NodeWaypointUdpSourceRefusal),
}

impl NodeWaypointUdpDatagramVerdict {
    /// The closed-set refusal reason behind this verdict, for logging and
    /// counting.
    pub fn refusal(self) -> NodeWaypointUdpSourceRefusal {
        match self {
            Self::DropDatagram(refusal) | Self::CloseSession(refusal) => refusal,
        }
    }

    /// Whether the session must be terminated.
    pub fn closes_session(self) -> bool {
        matches!(self, Self::CloseSession(_))
    }
}

impl NodeWaypointUdpSourceScoping {
    /// Resolve while also returning the coherent policy generation observed on
    /// a miss. The plain `resolve` API remains for callers that only need an
    /// admission verdict; UDP/DTLS session creation uses this richer form so an
    /// unattributable-but-mesh-wide-only admission is still fenced by later
    /// policy updates.
    pub fn resolve_observed(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> (u64, Result<ResolvedUdpSource, NodeWaypointUdpSourceRefusal>) {
        let binding = match self.index.authorize(ingress_ifindex, source) {
            Ok(binding) => binding,
            Err(refusal) => {
                return (self.resolver.policy_scope_generation(), Err(refusal));
            }
        };
        let (policy_generation, scope) = self
            .resolver
            .policy_scope_observation_for_pod_identity(&binding.pod_uid, &binding.principal);
        let Some(scope) = scope else {
            return (
                policy_generation,
                Err(self
                    .index
                    .record(NodeWaypointUdpSourceRefusal::PodNotInSlice)),
            );
        };
        (
            policy_generation,
            Ok(ResolvedUdpSource {
                binding,
                scope,
                policy_generation,
            }),
        )
    }

    /// Attribute a datagram and resolve its per-pod policy scope from the same
    /// live-slice read that vouches the pod.
    #[allow(dead_code)] // Exercised through the external integration-test API.
    pub fn resolve(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<ResolvedUdpSource, NodeWaypointUdpSourceRefusal> {
        self.resolve_observed(ingress_ifindex, source).1
    }

    /// Re-authorize ONE datagram of an admitted session and classify what its
    /// refusal actually proves.
    ///
    /// `pinned_ingress_ifindex` is the interface the session was admitted on;
    /// `ingress_ifindex` is the interface THIS datagram arrived on. When the
    /// two agree, the only inputs left are the pinned binding and the current
    /// generation, so a refusal is a property of the session and ends it. When
    /// they differ and the pinned evidence still resolves, the refusal is a
    /// property of the datagram — a forged source tuple cannot change which
    /// interface a packet entered on, but it CAN name an established session —
    /// so the datagram is dropped and the session continues under its own,
    /// still-vouched-for evidence. The datagram is never forwarded either way.
    #[allow(dead_code)] // Exercised through the external integration-test API.
    pub fn revalidate_datagram(
        &self,
        pinned: &NodeWaypointUdpSourceBinding,
        pinned_ingress_ifindex: Option<u32>,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpDatagramVerdict> {
        let Err(refusal) = self.revalidate(pinned, ingress_ifindex, source) else {
            return Ok(());
        };
        if ingress_ifindex == pinned_ingress_ifindex {
            // Same evidence the session pinned: nothing datagram-specific was
            // consulted, so this is the session's own attribution changing.
            // Short-circuited so the refusal is counted exactly once.
            return Err(NodeWaypointUdpDatagramVerdict::CloseSession(refusal));
        }
        match self.revalidate(pinned, pinned_ingress_ifindex, source) {
            Ok(()) => Err(NodeWaypointUdpDatagramVerdict::DropDatagram(refusal)),
            Err(_) => Err(NodeWaypointUdpDatagramVerdict::CloseSession(refusal)),
        }
    }

    /// Generation-fenced form of [`Self::revalidate_datagram`] used by live
    /// UDP/DTLS sessions. A policy-generation change is always a session
    /// property and therefore closes the session, even when the triggering
    /// datagram arrived on a different interface.
    pub fn revalidate_datagram_at_policy_generation(
        &self,
        pinned: &NodeWaypointUdpSourceBinding,
        pinned_policy_generation: u64,
        pinned_ingress_ifindex: Option<u32>,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpDatagramVerdict> {
        let Err(refusal) = self.revalidate_at_policy_generation(
            pinned,
            pinned_policy_generation,
            ingress_ifindex,
            source,
        ) else {
            return Ok(());
        };
        if refusal == NodeWaypointUdpSourceRefusal::PolicyGenerationChanged
            || ingress_ifindex == pinned_ingress_ifindex
        {
            return Err(NodeWaypointUdpDatagramVerdict::CloseSession(refusal));
        }
        match self.revalidate_at_policy_generation(
            pinned,
            pinned_policy_generation,
            pinned_ingress_ifindex,
            source,
        ) {
            Ok(()) => Err(NodeWaypointUdpDatagramVerdict::DropDatagram(refusal)),
            Err(pinned_refusal) => {
                Err(NodeWaypointUdpDatagramVerdict::CloseSession(pinned_refusal))
            }
        }
    }

    /// Re-authorize a live session against both current attribution evidence
    /// and the current slice's coherent pod-identity/scope generation.
    #[allow(dead_code)] // Exercised through the external integration-test API.
    pub fn revalidate(
        &self,
        pinned: &NodeWaypointUdpSourceBinding,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpSourceRefusal> {
        self.index.revalidate(pinned, ingress_ifindex, source)?;
        if self
            .resolver
            .policy_scope_for_pod_identity(&pinned.pod_uid, &pinned.principal)
            .is_none()
        {
            return Err(self
                .index
                .record(NodeWaypointUdpSourceRefusal::PodNotInSlice));
        }
        Ok(())
    }

    /// Re-authorize an attributed session and require the exact accepted mesh
    /// policy generation that ran its stream-admission plugin chain. A later
    /// generation may change policy without changing workload identity or
    /// labels, so presence of a current scope alone is insufficient.
    pub fn revalidate_at_policy_generation(
        &self,
        pinned: &NodeWaypointUdpSourceBinding,
        pinned_policy_generation: u64,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpSourceRefusal> {
        self.index.revalidate(pinned, ingress_ifindex, source)?;
        let (current_generation, scope) = self
            .resolver
            .policy_scope_observation_for_pod_identity(&pinned.pod_uid, &pinned.principal);
        if current_generation != pinned_policy_generation {
            return Err(self
                .index
                .record(NodeWaypointUdpSourceRefusal::PolicyGenerationChanged));
        }
        if scope.is_none() {
            return Err(self
                .index
                .record(NodeWaypointUdpSourceRefusal::PodNotInSlice));
        }
        Ok(())
    }

    /// Revalidate a session that was deliberately admitted without an
    /// attributable pod while the then-current mesh policy generation had no
    /// enforcing scoped policy. The same miss must still be observed in the
    /// same generation; any accepted slice update or newly attributable source
    /// ends the old authorization lifetime.
    pub fn revalidate_unattributed(
        &self,
        pinned_policy_generation: u64,
        pinned_refusal: NodeWaypointUdpSourceRefusal,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), NodeWaypointUdpSourceRefusal> {
        let (current_generation, current) = self.resolve_observed(ingress_ifindex, source);
        if current_generation != pinned_policy_generation {
            return Err(self
                .index
                .record(NodeWaypointUdpSourceRefusal::PolicyGenerationChanged));
        }
        match current {
            Err(refusal) if refusal == pinned_refusal => Ok(()),
            _ => Err(self
                .index
                .record(NodeWaypointUdpSourceRefusal::AttributionChanged)),
        }
    }

    /// Record the closed-set refusal used when a datagram arrives on an
    /// interface other than the one an unattributable session pinned.
    pub(crate) fn record_attribution_changed(&self) -> NodeWaypointUdpSourceRefusal {
        self.index
            .record(NodeWaypointUdpSourceRefusal::AttributionChanged)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Reconcile loop
// ───────────────────────────────────────────────────────────────────────────

/// Resolves one enrolled pod's host-side interface. A trait so the reconcile
/// logic is unit-testable without root, procfs, or a live node.
pub trait NodeWaypointUdpInterfaceResolver: Send + Sync + 'static {
    /// `Err` means "unresolved" and is treated as a refusal for that pod, never
    /// as "attribute everything".
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String>;
}

/// Production resolver: the pod's own netns view (`iflink` → host peer index)
/// first, then the host route table keyed on the registry-published pod IP for
/// both families. Identical to the Ambient host-capture resolution, so the two
/// paths agree on which interface belongs to a pod.
pub struct VethInterfaceResolver {
    /// Only the Linux `resolve_interface` reads this; the non-Linux impl
    /// refuses outright. The field is still initialized on every host so the
    /// resolver keeps one shape, so the non-Linux build allows it explicitly
    /// rather than dropping it from the struct.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    sysfs_net: std::path::PathBuf,
}

impl Default for VethInterfaceResolver {
    fn default() -> Self {
        Self {
            sysfs_net: std::path::PathBuf::from("/sys/class/net"),
        }
    }
}

impl VethInterfaceResolver {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(target_os = "linux")]
impl NodeWaypointUdpInterfaceResolver for VethInterfaceResolver {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        let name = crate::ebpf::veth::discover_veth_for_pod(None, Some(&target.cgroup_path))
            .or_else(|| {
                target
                    .source_ips
                    .ipv4
                    .and_then(crate::ebpf::veth::discover_dedicated_veth_for_pod_ip)
            })
            .or_else(|| {
                target
                    .source_ips
                    .ipv6
                    .and_then(crate::ebpf::veth::discover_dedicated_veth_for_pod_ip6)
            })
            .ok_or_else(|| "no host-side interface resolved for this pod".to_string())?;
        let ifindex = super::host_udp_capture::dedicated_host_ifindex(&self.sysfs_net, &name)?;
        Ok(ResolvedInterface { name, ifindex })
    }
}

#[cfg(not(target_os = "linux"))]
impl NodeWaypointUdpInterfaceResolver for VethInterfaceResolver {
    fn resolve_interface(&self, _target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        Err("NodeWaypoint UDP source attribution is Linux-only".to_string())
    }
}

/// Polls the node-agent-published enrolled-pod registry and republishes the
/// attribution index.
pub struct NodeWaypointUdpSourceIndexManager<R: NodeWaypointUdpInterfaceResolver> {
    source: Arc<dyn PodCaptureSource>,
    resolver: R,
    index: Arc<NodeWaypointUdpSourceIndex>,
    poll_interval: Duration,
    /// Service-path steering (issue #3286), reconciled from the SAME pass that
    /// publishes attribution so the two can never disagree about which pods
    /// exist: a pod whose interface is not attributable this pass is also not an
    /// interface whose traffic is steered. `None` disables steering entirely
    /// (non-Linux, or an operator who has not enabled the listeners), which
    /// leaves the Service path unsteered and therefore fail-closed.
    steering: Option<Arc<super::node_waypoint_udp_steering::NodeWaypointUdpSteering>>,
}

/// Retract attribution evidence AND the steering plan whenever the manager
/// future leaves scope — not only on an orderly shutdown signal. Tokio task
/// abort and panic both drop the future; `StreamListenerManager` retains its own
/// `Arc` to steering, so relying on `NodeWaypointUdpSteering::drop` would leave
/// rules and reply-source authorization live after attribution disappeared.
struct SourceIndexRetractionGuard {
    index: Arc<NodeWaypointUdpSourceIndex>,
    steering: Option<Arc<super::node_waypoint_udp_steering::NodeWaypointUdpSteering>>,
}

impl Drop for SourceIndexRetractionGuard {
    fn drop(&mut self) {
        self.index.clear();
        if let Some(steering) = self.steering.as_ref() {
            steering.shutdown();
        }
    }
}

impl<R: NodeWaypointUdpInterfaceResolver> NodeWaypointUdpSourceIndexManager<R> {
    pub fn new(
        source: Arc<dyn PodCaptureSource>,
        resolver: R,
        index: Arc<NodeWaypointUdpSourceIndex>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            source,
            resolver,
            index,
            poll_interval,
            steering: None,
        }
    }

    /// Attach the Service-path steering datapath to this reconcile loop.
    pub fn with_steering(
        mut self,
        steering: Arc<super::node_waypoint_udp_steering::NodeWaypointUdpSteering>,
    ) -> Self {
        self.steering = Some(steering);
        self
    }

    /// One reconcile pass. Returns the published bindings so tests can assert
    /// the fail-closed refusals without touching the datapath.
    #[allow(dead_code)] // Also an external test seam for one deterministic pass.
    pub fn reconcile_once(&self) -> Vec<HostUdpPodBinding> {
        let targets = self.source.list_targets();
        let mut resolved: HashMap<String, ResolvedInterface> = HashMap::new();
        for target in &targets {
            match self.resolver.resolve_interface(target) {
                Ok(interface) => {
                    resolved.insert(target.pod_uid.clone(), interface);
                }
                Err(error) => {
                    debug!(
                        error = %error,
                        "NodeWaypoint UDP source attribution: pod interface unresolved this pass"
                    );
                }
            }
        }
        let desired = plan_node_waypoint_udp_bindings(&targets, &resolved);
        if !desired.refused.is_empty() {
            // Closed-set reasons only; pod UIDs stay out of the aggregate line.
            let mut by_reason: HashMap<&'static str, usize> = HashMap::new();
            for (_, refusal) in &desired.refused {
                *by_reason.entry(refusal.as_str()).or_insert(0) += 1;
            }
            let mut rendered: Vec<String> = by_reason
                .into_iter()
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect();
            rendered.sort();
            debug!(
                refusals = %rendered.join(","),
                "NodeWaypoint UDP source attribution: enrolled pods without an attributable \
                 interface; their UDP/DTLS sessions fail closed under scoped policy"
            );
        }
        let published = self.index.publish(&desired.bindings);
        // Steering follows publication of attribution AND of a bound serving
        // listener: a datagram may only be diverted to the waypoint once the
        // interface it arrives on can be attributed AND the destination's
        // UDP/DTLS listener is actually bound on the accepted generation.
        //
        // The interface set is taken from `published`, NOT from
        // `desired.bindings`. Publication is the final authorization boundary
        // and applies its own refusals — a contested ingress interface refuses
        // BOTH claimants, a malformed or UID-mismatched binding is dropped, and
        // an input above the interface bound collapses the whole generation to
        // empty. Steering a pre-publication interface would therefore divert a
        // pod's Service datagrams to a listener that could only deny them:
        // strictly worse than the unsteered path, which fails closed at the
        // pod-veth guard with no listener state involved. A pod that lost
        // attribution this pass loses steering in the same pass.
        if let Some(steering) = self.steering.as_ref() {
            steering.reconcile(&published.ifaces);
        }
        desired.bindings
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let retraction = SourceIndexRetractionGuard {
            index: self.index.clone(),
            steering: self.steering.clone(),
        };
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            "NodeWaypoint UDP/DTLS source-identity index started; scoped AuthorizationPolicy is \
             enforced per source pod for captured UDP/DTLS instead of disabling the ports"
        );
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.reconcile_once();
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        // Drop the guard explicitly so retraction precedes the diagnostic. The
        // same Drop path also runs if this task is aborted or unwinds.
        drop(retraction);
        debug!("NodeWaypoint UDP/DTLS source-identity index retracted at shutdown");
    }
}

/// Whether NodeWaypoint UDP/DTLS scoped authorization can be served at all on
/// this build/platform. When this is false the slice-preparation step keeps the
/// pre-existing fail-closed suppression of UDP/DTLS service ports and proxies:
/// attribution needs `IP_PKTINFO` and sysfs interface resolution, so no
/// non-Linux host can attribute a datagram, and admitting one unattributed
/// would be exactly the cross-tenant confusion this path exists to prevent.
pub const fn source_identity_supported() -> bool {
    cfg!(target_os = "linux")
}

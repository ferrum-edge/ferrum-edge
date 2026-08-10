//! Host-network UDP capture for the Ambient mesh proxy (issue #3288).
//!
//! # Why this exists
//!
//! Ambient's proxy runs `hostNetwork: true`, OUTSIDE the workload pods' network
//! namespaces. Until now the only UDP capture producer was
//! [`super::netns_udp_capture`], which `setns(CLONE_NEWNET)`s into each enrolled
//! pod to install rules and bind a socket there. That needs `hostPID`,
//! `SYS_ADMIN`, and `SYS_PTRACE` — privileges some clusters will not grant — and
//! the host-namespace alternative did not exist: the pod-netns rule generator
//! splits inbound from outbound with `-m addrtype --dst-type LOCAL`, which is
//! meaningless in the host namespace (pod IPs are forwarded there, not local), so
//! it deliberately emitted NOTHING for `host_netns`.
//!
//! # The safe host-namespace discriminator
//!
//! This module captures from the host namespace using the INGRESS INTERFACE as
//! the direction discriminator, which is exact rather than heuristic:
//!
//! * A pod's egress is the only traffic that enters the host namespace on THAT
//!   pod's host-side interface. `-i <iface>` in `mangle PREROUTING` selects it
//!   and nothing else.
//! * Traffic destined FOR a pod arrives on the node uplink and is forwarded out
//!   the pod interface; it never matches an `-i <pod iface>` rule.
//! * The node's own traffic (kubelet, CNI, DNS, the mesh proxy's own relay
//!   egress, every `hostNetwork` pod) is locally generated and traverses
//!   `OUTPUT`. This path installs no `mangle OUTPUT` chain at all, so host
//!   traffic is structurally incapable of being captured.
//!
//! # Per-datagram identity
//!
//! One transparent socket serves every enrolled pod on the node, so evidence
//! cannot be fixed per producer the way the pod-netns path fixes it per netns.
//! Each datagram carries two independent kernel-provided facts:
//!
//! * `IP_RECVORIGDSTADDR` — the original destination, un-rewritten by TPROXY.
//! * `IP_PKTINFO` / `IPV6_PKTINFO` — the ingress interface index.
//!
//! [`HostUdpIdentityIndex`] maps the ingress interface index to exactly one
//! enrolled pod and then requires the datagram's SOURCE address to be one of that
//! pod's registry-published addresses. Both facts come from the kernel, never
//! from the datagram payload, so a workload cannot assert another tenant's
//! identity: forging a source IP does not change which interface the packet
//! entered on, and an interface belongs to one pod. Anything that fails either
//! check is dropped — the path never falls back to an unattested or mesh-wide
//! identity, which on a shared socket would be exactly the cross-tenant
//! confusion this design exists to prevent.
//!
//! An interface that more than one enrolled pod claims makes attribution
//! ambiguous, so BOTH pods are refused (never captured under a guessed
//! identity). In practice that is the "shared bridge CNI" case: such a
//! deployment must use the per-pod-netns producer instead.
//!
//! # Lifecycle
//!
//! The manager polls the same node-agent-published registry the pod-netns
//! producer uses, and holds the datapath at one of three postures, never between
//! them:
//!
//! 1. **Guarded** — a scope-exact DROP guard is jumped from `PREROUTING`. Used
//!    while rules are rebuilt and whenever setup fails. Enrolled UDP egress is
//!    dropped, never leaked as plaintext.
//! 2. **Live** — guard released, capture chain populated, socket bound.
//! 3. **Absent** — every Ferrum-owned host object removed by exact name.
//!
//! Two lifecycle rules keep a POD LEAVING capture from becoming a plaintext
//! window:
//!
//! * The guard's scope is the UNION of the interfaces the new generation
//!   captures and the interfaces of pods that still owe a transition, and a
//!   removed pod's capture rule is not rebuilt away until the node-agent
//!   acknowledges (over the durable `.udp-ack-required` → `.udp-not-ready`
//!   handshake) that it closed that pod's BPF gate. Removing a readiness marker
//!   does not close that gate synchronously.
//! * A removal, refusal, or attribution change stops the shared capture loop
//!   before the next evidence generation goes live, because an already-admitted
//!   session keeps its own [`UdpSourceIdentity`] and its transparent reply
//!   socket. A pure addition disturbs nothing and does not restart it.
//!
//! The capture loop is supervised: every reconcile checks whether it exited on
//! its own and, if it did, guards the datapath and restarts it rather than
//! leaving a published-ready node black-holing captured traffic.
//!
//! # Crossing a process boundary
//!
//! Readiness is DURABLE and shared with the node-agent, so a generation that
//! dies leaves behind both its `mangle` state and open BPF UDP gates for every
//! pod it readied. Removing the former while the latter are open is precisely a
//! plaintext window, and the stale interface set does not even bound the damage:
//! a pod that restarted onto a new veth has no stale rule at all and an open gate
//! regardless. So the first thing a new generation does is NOT a teardown — it is
//! [`HostUdpStaleGenerationRecovery`], which puts every pod the durable state
//! names back through the close handshake and waits for the node-agent's
//! acknowledgement. Nothing is applied and nothing is removed until it settles;
//! the predecessor's objects are retained meanwhile, and a capture path whose
//! socket died with its process drops rather than leaks. The same recovery runs
//! on a node that switched AWAY from this placement
//! ([`recover_and_reap_stale_host_udp_state`]), where no manager exists to do it.
//!
//! Linux-only. The reconcile/attribution logic is platform-independent and unit
//! tested with a mock backend; the socket/iptables datapath is exercised on a
//! live node.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::netns_capture::{PodCaptureSource, PodCaptureTarget};
use crate::capture::IptablesPlan;
use crate::modes::mesh::hbone::UdpSourceIdentity;

/// How long shutdown waits for the node-agent to acknowledge that its BPF UDP
/// gate closed before giving up and leaving the datapath fail-closed. Mirrors the
/// pod-netns producer's bounded handshake window.
const GATE_CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for the gate-close acknowledgement.
const GATE_CLOSE_ACK_POLL: Duration = Duration::from_millis(100);

/// How long ONE reconcile pass waits for a departing pod's gate-close
/// acknowledgement before leaving the protective guard up and retrying on the
/// next poll. Deliberately shorter than the shutdown budget: the reconcile loop
/// retries anyway, so a stalled node-agent must not stall reconciliation for
/// every other pod on the node. Waiting longer would not change the posture —
/// the departing pod's rules and guard are retained either way.
const RECONCILE_GATE_CLOSE_ACK_WAIT: Duration = Duration::from_secs(1);

/// One enrolled pod's host-side capture binding: the interface its egress enters
/// the host namespace on, the addresses it is allowed to source from, and the
/// attested identity every datagram it sends is relayed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUdpPodBinding {
    pub pod_uid: String,
    pub iface: String,
    pub ifindex: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub identity: UdpSourceIdentity,
}

impl HostUdpPodBinding {
    /// Whether `addr` is an address this pod is registered to source from.
    /// IPv4-mapped IPv6 senders are canonicalized by the caller, so a plain
    /// family comparison is exact here.
    fn owns_source(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.ipv4 == Some(v4),
            IpAddr::V6(v6) => self.ipv6 == Some(v6),
        }
    }
}

/// Why one enrolled pod is not covered by host UDP capture. Every variant is a
/// FAIL-CLOSED outcome: the pod's UDP egress is not captured, and (because the
/// node-agent's readiness marker is withheld) its tc guard keeps that egress
/// closed rather than letting it out in plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUdpRefusal {
    /// The registry entry carried no attested SPIFFE identity. On a shared
    /// capture socket an unattested datagram would be relayed with no source
    /// principal beside a sibling pod's attested one.
    MissingIdentity,
    /// The registry entry published no pod address for any family, so a
    /// datagram's source could not be bound to this pod.
    MissingPodAddress,
    /// The pod's host-side interface could not be resolved.
    UnresolvedInterface,
    /// The resolved interface name is not a name this path will place in an
    /// `iptables -i` argument (see `capture::validate_host_capture_interface`).
    InvalidInterface,
    /// More than one enrolled pod resolved to this interface, so a datagram
    /// arriving on it cannot be attributed to a single workload.
    AmbiguousInterface,
    /// The node has more enrolled pods than the supported host capture interface
    /// bound.
    InterfaceCapacity,
}

impl HostUdpRefusal {
    /// Stable, closed-set reason label. Safe for logs and metrics: it is a
    /// `&'static str` from this enum, never operator- or registry-supplied text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingIdentity => "missing_identity",
            Self::MissingPodAddress => "missing_pod_address",
            Self::UnresolvedInterface => "unresolved_interface",
            Self::InvalidInterface => "invalid_interface",
            Self::AmbiguousInterface => "ambiguous_interface",
            Self::InterfaceCapacity => "interface_capacity",
        }
    }
}

/// A resolved host-side interface for one pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInterface {
    pub name: String,
    pub ifindex: u32,
}

/// The reconciled host capture state for one poll: which pods are captured, on
/// which interfaces, and which are refused and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostUdpDesiredState {
    /// Captured pods, ordered by interface name so the rendered ruleset is
    /// deterministic across polls (an unordered set would rewrite the chain on
    /// every reconcile even when nothing changed).
    pub bindings: Vec<HostUdpPodBinding>,
    /// Refused pods, ordered by pod UID.
    pub refused: Vec<(String, HostUdpRefusal)>,
}

impl HostUdpDesiredState {
    /// Interface names in rule order.
    pub fn ifaces(&self) -> Vec<String> {
        self.bindings.iter().map(|b| b.iface.clone()).collect()
    }

    /// Pod UIDs whose capture is live.
    pub fn bound_uids(&self) -> HashSet<String> {
        self.bindings.iter().map(|b| b.pod_uid.clone()).collect()
    }

    /// Whether the RULESET this state renders differs from `other`'s. Only the
    /// interface set feeds the ruleset, so an identity-only change is NOT a rule
    /// change (it is handled by [`Self::requires_listener_restart_from`], which
    /// is the stronger, listener-restarting condition).
    pub fn rules_differ_from(&self, other: &Self) -> bool {
        self.ifaces() != other.ifaces()
    }

    /// Whether the running capture loop must be stopped before this state
    /// becomes live. Two cases, and both leave an already-admitted session
    /// relaying under evidence this generation no longer vouches for:
    ///
    /// * An interface's ATTRIBUTION changed — a different pod, identity, or
    ///   source-address set behind the same interface.
    /// * A binding was REMOVED: the pod left the registry, became refused, or
    ///   moved to another interface. Per-datagram authorization stops new and
    ///   refreshed traffic the moment the next index generation is published,
    ///   but a session admitted earlier keeps its old [`UdpSourceIdentity`] and
    ///   its transparent reply socket, so a one-way return stream could keep
    ///   sending to a removed — or recycled — pod address until it idles out.
    ///
    /// A pure ADDITION is not a restart: no existing session's evidence changes,
    /// so the live sessions of the pods that stayed are left undisturbed.
    pub fn requires_listener_restart_from(&self, other: &Self) -> bool {
        let current: HashMap<&str, &HostUdpPodBinding> = self
            .bindings
            .iter()
            .map(|b| (b.iface.as_str(), b))
            .collect();
        other.bindings.iter().any(|prior| {
            current
                .get(prior.iface.as_str())
                .is_none_or(|binding| *binding != prior)
        })
    }

    /// Captured pod UID to the interface its capture rule is scoped to.
    fn bound_ifaces(&self) -> HashMap<String, String> {
        self.bindings
            .iter()
            .map(|binding| (binding.pod_uid.clone(), binding.iface.clone()))
            .collect()
    }
}

/// Build the desired host capture state from the enrolled-pod registry and the
/// per-pod interface resolution.
///
/// Pure and platform-independent: every effect (procfs reads, `iptables`,
/// sockets) is the caller's. `resolved` maps pod UID to its host-side interface;
/// a missing entry means resolution failed for that pod.
pub fn plan_host_udp_bindings(
    targets: &[PodCaptureTarget],
    resolved: &HashMap<String, ResolvedInterface>,
) -> HostUdpDesiredState {
    let mut refused: Vec<(String, HostUdpRefusal)> = Vec::new();
    let mut candidates: Vec<HostUdpPodBinding> = Vec::new();

    for target in targets {
        // Attested identity is mandatory on the shared host socket. The
        // pod-netns producer tolerates its absence because its socket is already
        // scoped to one pod; here absence would mean relaying one tenant's
        // datagrams with no principal alongside another's attested ones.
        let Some(identity) = target.source_identity.clone() else {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::MissingIdentity));
            continue;
        };
        if target.source_ips.ipv4.is_none() && target.source_ips.ipv6.is_none() {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::MissingPodAddress));
            continue;
        }
        let Some(interface) = resolved.get(&target.pod_uid) else {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::UnresolvedInterface));
            continue;
        };
        if crate::capture::validate_host_capture_interface(&interface.name).is_err()
            || interface.ifindex == 0
        {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::InvalidInterface));
            continue;
        }
        candidates.push(HostUdpPodBinding {
            pod_uid: target.pod_uid.clone(),
            iface: interface.name.clone(),
            ifindex: interface.ifindex,
            ipv4: target.source_ips.ipv4,
            ipv6: target.source_ips.ipv6,
            identity,
        });
    }

    // Ambiguity is fail-closed for EVERY claimant, not first-wins: a shared
    // interface (a bridge CNI, or a stale registry entry pointing at a recycled
    // veth) makes per-datagram attribution impossible, and capturing under a
    // guessed identity is precisely the cross-tenant confusion this path must
    // not have. Interface index and name are both checked so a rename between
    // resolutions cannot smuggle two pods onto one index.
    let mut iface_claims: HashMap<String, usize> = HashMap::new();
    let mut index_claims: HashMap<u32, usize> = HashMap::new();
    for binding in &candidates {
        *iface_claims.entry(binding.iface.clone()).or_insert(0) += 1;
        *index_claims.entry(binding.ifindex).or_insert(0) += 1;
    }

    let mut bindings: Vec<HostUdpPodBinding> = Vec::new();
    for binding in candidates {
        let shared = iface_claims
            .get(binding.iface.as_str())
            .is_some_and(|count| *count > 1)
            || index_claims
                .get(&binding.ifindex)
                .is_some_and(|count| *count > 1);
        if shared {
            refused.push((binding.pod_uid.clone(), HostUdpRefusal::AmbiguousInterface));
            continue;
        }
        bindings.push(binding);
    }

    // Deterministic rule order, and a deterministic overflow decision when a node
    // somehow exceeds the interface bound.
    bindings.sort_by(|left, right| left.iface.cmp(&right.iface));
    if bindings.len() > crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES {
        for binding in bindings.split_off(crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES) {
            refused.push((binding.pod_uid, HostUdpRefusal::InterfaceCapacity));
        }
    }
    refused.sort_by(|left, right| left.0.cmp(&right.0));

    HostUdpDesiredState { bindings, refused }
}

/// Ingress-interface keyed source-evidence index consulted on every captured
/// datagram.
///
/// A whole generation is published at once through [`ArcSwap`]: the reconcile
/// loop is the only writer and always replaces the complete mapping, so a reader
/// observes either the previous generation or the next one, never a half-applied
/// mix in which one pod's interface already points at its successor while another
/// still points at its predecessor. Its cardinality is bounded by
/// `capture::MAX_HOST_UDP_CAPTURE_INTERFACES`.
#[derive(Debug)]
pub struct HostUdpIdentityIndex {
    by_ifindex: ArcSwap<HashMap<u32, Arc<HostUdpPodBinding>>>,
}

impl Default for HostUdpIdentityIndex {
    fn default() -> Self {
        Self {
            by_ifindex: ArcSwap::from_pointee(HashMap::new()),
        }
    }
}

/// Why a captured datagram was refused by [`HostUdpIdentityIndex::authorize`].
/// Closed set, so it is safe to log and count without echoing untrusted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUdpDatagramRefusal {
    /// The kernel reported no ingress interface for the datagram (no
    /// `IP_PKTINFO`/`IPV6_PKTINFO` cmsg, or index 0). Without it the datagram
    /// cannot be attributed, so it is dropped rather than relayed unattributed.
    NoIngressInterface,
    /// The ingress interface belongs to no currently enrolled pod.
    UnenrolledInterface,
    /// The source address is not one the pod owning that interface is registered
    /// to use — a spoofed or stale source.
    SourceAddressMismatch,
}

impl HostUdpDatagramRefusal {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoIngressInterface => "no_ingress_interface",
            Self::UnenrolledInterface => "unenrolled_interface",
            Self::SourceAddressMismatch => "source_address_mismatch",
        }
    }
}

impl HostUdpIdentityIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a complete new generation of bindings.
    pub fn publish(&self, bindings: &[HostUdpPodBinding]) {
        let map: HashMap<u32, Arc<HostUdpPodBinding>> = bindings
            .iter()
            .map(|binding| (binding.ifindex, Arc::new(binding.clone())))
            .collect();
        self.by_ifindex.store(Arc::new(map));
    }

    /// Drop every binding (used when capture stops, so a socket still draining
    /// cannot attribute a late datagram to a pod that is no longer captured).
    pub fn clear(&self) {
        self.by_ifindex.store(Arc::new(HashMap::new()));
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_ifindex.load().len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Per-datagram admission check: one lock-free snapshot load, one hash lookup,
    /// one address comparison, and one `Arc` retain for the authorized binding.
    #[allow(dead_code)] // Library test seam; the binary uses `authorized_binding` directly.
    pub fn authorize(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), HostUdpDatagramRefusal> {
        self.authorized_binding(ingress_ifindex, source).map(|_| ())
    }

    /// Return the exact binding generation that authorized this datagram.
    ///
    /// The capture loop retains this `Arc` until it knows whether the flow is a
    /// refresh or a new admission. That makes authorization and session identity
    /// one atomic-snapshot decision: a concurrent generation swap can never turn
    /// an authorized host datagram into an identity-less session.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn authorized_binding(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<Arc<HostUdpPodBinding>, HostUdpDatagramRefusal> {
        let Some(ifindex) = ingress_ifindex.filter(|index| *index != 0) else {
            return Err(HostUdpDatagramRefusal::NoIngressInterface);
        };
        let snapshot = self.by_ifindex.load();
        let Some(binding) = snapshot.get(&ifindex) else {
            return Err(HostUdpDatagramRefusal::UnenrolledInterface);
        };
        if !binding.owns_source(source) {
            return Err(HostUdpDatagramRefusal::SourceAddressMismatch);
        }
        Ok(binding.clone())
    }

    /// Resolve attested evidence from one authorization snapshot.
    #[allow(dead_code)] // Library test seam; the binary retains the authorized binding instead.
    pub fn identity_for(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Option<Arc<UdpSourceIdentity>> {
        let binding = self.authorized_binding(ingress_ifindex, source).ok()?;
        Some(Arc::new(binding.identity.clone()))
    }
}

/// Effects the host capture manager performs, behind a trait so the reconcile
/// logic is testable without root, iptables, or a live node.
pub trait HostUdpCaptureBackend: Send + Sync + 'static {
    /// Resolve one pod's host-side interface. `Err` means "unresolved" and is
    /// treated as a refusal, never as "capture everything".
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String>;

    /// Install/refresh the scope-exact fail-closed DROP guard for `ifaces`.
    fn install_guard(&self, ifaces: &[String]) -> Result<(), String>;

    /// Rebuild the capture chain + transparent routing for `ifaces`.
    fn install_capture(&self, ifaces: &[String]) -> Result<(), String>;

    /// Remove the capture chain + routing, leaving any active guard in place.
    fn teardown_capture_rules(&self) -> Result<(), String>;

    /// Strictly release the fail-closed guard once capture is live.
    fn release_guard(&self) -> Result<(), String>;

    /// Remove every Ferrum-owned host UDP object (capture path and guards).
    fn teardown_all(&self) -> Result<(), String>;

    /// Bind the transparent capture socket and run the capture loop until the
    /// returned handle is stopped.
    fn start_listener(
        &self,
        index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String>;
}

/// Handle to a running host capture listener.
pub struct HostUdpListenerHandle {
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HostUdpListenerHandle {
    pub fn new(stop: watch::Sender<bool>, task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            stop,
            task: Some(task),
        }
    }

    /// A handle with no task, for backends (and tests) that do not spawn one.
    #[allow(dead_code)]
    pub fn detached(stop: watch::Sender<bool>) -> Self {
        Self { stop, task: None }
    }

    /// Whether the capture loop this handle owns has already returned. The
    /// manager polls it every reconcile: a loop that exits on its own is
    /// otherwise invisible (the handle stays `Some`), and the datapath would keep
    /// steering enrolled egress into a socket nobody reads. A handle carrying no
    /// task cannot exit on its own, so it is never reported as finished.
    fn is_finished(&self) -> bool {
        self.task.as_ref().is_some_and(|task| task.is_finished())
    }

    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Stale-generation recovery
// ───────────────────────────────────────────────────────────────────────────

/// Upper bound on the directory ENTRIES one recovery pass will examine in one
/// durable handshake directory — not just the ones that turn out to be valid
/// markers, because the directory is written by another process and the work it
/// can demand has to be bounded by what is present.
///
/// Hitting the bound is not silently ignored: the pass reports itself unsettled
/// and rescans, so nothing stale is removed until the directory reads in full.
/// A node has one entry per pod, so this is an order of magnitude above any real
/// backlog and reaching it means something is wrong — for which never reaping is
/// the correct posture.
const MAX_STALE_RECOVERY_MARKERS: usize = 4096;

/// How long ONE recovery pass waits for the node-agent's acknowledgements before
/// returning unsettled and letting the caller retry. Deliberately short: the
/// caller retries on its ordinary poll cadence, and the datapath stays
/// fail-closed for the whole wait either way, so a long single wait would only
/// delay the first useful log line.
const STALE_RECOVERY_ACK_WAIT: Duration = Duration::from_secs(1);

/// How long between repeat warnings while a recovery cannot settle. A stalled
/// node-agent must stay visible without warning on every poll.
const STALE_RECOVERY_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Fail-closed recovery of the durable UDP readiness handshake a PREVIOUS
/// generation of the host capture producer left behind.
///
/// # Why removing stale host state has to be a handshake
///
/// `.udp-ready` / `.udp-ack-required` live in a durable directory shared with
/// the node-agent and survive this process. When a generation dies — a crash, a
/// restart, a rollout that switches placement or turns UDP capture off — its
/// sockets die with it but three things do not: its `mangle` chains, its
/// published readiness markers, and (because readiness is what opens it) the
/// node-agent's BPF UDP gate for every pod it readied.
///
/// A socketless capture path still DROPS, so leaving it is safe. Removing it
/// while those gates are open is not: the pod's UDP egress is then neither
/// captured nor gated and leaves the node in plaintext. The interface set is not
/// a safe proxy for that either — a pod that restarted onto a new veth is not
/// covered by the stale rules at all, yet its gate is still open.
///
/// So before ANY stale host object is removed, this recovers every pod the
/// durable state names and puts it back through the ordinary close handshake:
/// [`request_udp_gate_close`](super::netns_udp_capture::request_udp_gate_close)
/// persists a fresh `.udp-ack-required`, deletes any `.udp-not-ready` (so a
/// stale acknowledgement can never authorize this new handoff), and only then
/// retracts `.udp-ready`. The pod is settled when the node-agent republishes
/// `.udp-not-ready`, which is the proof its gate is shut.
///
/// # The one other way a pod settles
///
/// A pod also settles when READINESS reappears for it. That is not a shortcut:
/// a pod only reaches the awaiting set once its own `request_udp_gate_close`
/// reported success, which includes having removed the readiness marker, so a
/// marker that exists again was published by a DIFFERENT producer — on this node
/// that is the per-pod-netns producer starting under the new placement, which
/// publishes readiness only once it is capturing that pod INSIDE its namespace.
/// Its egress therefore never reaches the host namespace, and removing the host
/// rules cannot leak it. Without this the two halves of a placement switch would
/// deadlock: the incoming producer opens the gate the outgoing recovery is
/// waiting to see closed.
pub struct HostUdpStaleGenerationRecovery {
    /// `<registry>/.udp-ready`. `None` means nothing gated any pod on a
    /// readiness marker, so there is no durable obligation to recover.
    ready_dir: Option<PathBuf>,
    /// Discovered pods whose durable close request has not been persisted yet.
    /// Retried every pass: an obligation must never be dropped because one
    /// filesystem write failed, or the recovery would settle and reap while that
    /// pod's gate is still open.
    pending_request: BTreeSet<String>,
    /// Pods whose close this recovery persisted and whose settlement has not
    /// arrived. Membership is also what stops a pod being re-requested: a repeat
    /// `request_udp_gate_close` would delete the very acknowledgement being
    /// awaited.
    awaiting: BTreeSet<String>,
    /// Discovery is ONE-SHOT once both directories have been read in full. The
    /// previous generation's obligations are exactly what was on disk when this
    /// process started; re-scanning later would retract readiness the INCOMING
    /// producer has since published for a newly enrolled pod, which is the one
    /// way this recovery could fight the producer it runs ahead of.
    discovery_complete: bool,
    /// A marker directory this pass could not read in full.
    scan_truncated: bool,
    announced: bool,
    last_warned: Option<Instant>,
    last_reap_warned: Option<Instant>,
}

impl HostUdpStaleGenerationRecovery {
    pub fn new(ready_dir: Option<PathBuf>) -> Self {
        Self {
            ready_dir,
            pending_request: BTreeSet::new(),
            awaiting: BTreeSet::new(),
            discovery_complete: false,
            scan_truncated: false,
            announced: false,
            last_warned: None,
            last_reap_warned: None,
        }
    }

    /// Pods whose gate is not yet provably closed.
    pub fn outstanding(&self) -> usize {
        self.pending_request.len() + self.awaiting.len()
    }

    /// Whether the previous generation's marker set was read completely and
    /// every discovered close request was durably persisted and retracted.
    ///
    /// Once this is true an incoming producer may start: recovery no longer
    /// scans `.udp-ready`, so it cannot mistake that producer's newly published
    /// markers for predecessor state. Acknowledgements and stale-rule teardown
    /// may still be pending and can continue in the background.
    pub fn retraction_complete(&self) -> bool {
        self.ready_dir.is_none() || (self.discovery_complete && self.pending_request.is_empty())
    }

    /// Run one bounded pass. `true` means every durable obligation the previous
    /// generation left is discharged and its host objects may now be removed;
    /// `false` means the caller must retain them and retry.
    pub async fn poll_once(&mut self, ack_wait: Duration) -> bool {
        let Some(ready_dir) = self.ready_dir.clone() else {
            return true;
        };
        // A per-pass verdict: a directory that reads cleanly this time must not
        // stay poisoned by an earlier failure.
        self.scan_truncated = false;
        if !self.discovery_complete {
            self.discover(&ready_dir);
        }
        self.request_pending(&ready_dir);
        self.await_acknowledgements(&ready_dir, ack_wait).await;

        let settled =
            self.pending_request.is_empty() && self.awaiting.is_empty() && !self.scan_truncated;
        self.report(settled);
        settled
    }

    /// Collect the durable obligations: every pod with published readiness (its
    /// gate may be open) and every pod with an outstanding close request (a
    /// previous generation started the handshake and died before it completed).
    fn discover(&mut self, ready_dir: &Path) {
        let mut pods: BTreeSet<String> = BTreeSet::new();
        let mut dirs = vec![ready_dir.to_path_buf()];
        if let Some(request_dir) = super::netns_udp_capture::udp_ack_required_dir(ready_dir) {
            dirs.push(request_dir);
        }
        for dir in dirs {
            match read_handshake_marker_uids(&dir) {
                Ok((uids, truncated)) => {
                    if truncated {
                        warn!(
                            path = %dir.display(),
                            limit = MAX_STALE_RECOVERY_MARKERS,
                            "Host UDP capture: too many entries in the durable UDP handshake \
                             directory to recover in one pass; retaining the previous \
                             generation's host state and rescanning"
                        );
                        self.scan_truncated = true;
                    }
                    pods.extend(uids);
                }
                Err(error) => {
                    warn!(
                        path = %dir.display(),
                        %error,
                        "Host UDP capture: could not scan the durable UDP handshake directory; \
                         retaining the previous generation's host state and retrying"
                    );
                    self.scan_truncated = true;
                }
            }
        }
        // Only a complete scan retires discovery. An incomplete one rescans, and
        // is anomalous enough (thousands of entries, or an unreadable directory)
        // that never reaping is the right posture until it clears.
        self.discovery_complete = !self.scan_truncated;
        for pod_uid in pods {
            if self.awaiting.contains(&pod_uid) {
                continue;
            }
            self.pending_request.insert(pod_uid);
        }
    }

    /// Persist (or re-persist) the close request for every discovered pod.
    fn request_pending(&mut self, ready_dir: &Path) {
        if self.pending_request.is_empty() {
            return;
        }
        if !self.announced {
            self.announced = true;
            info!(
                pods = self.pending_request.len(),
                "Host UDP capture: a previous generation left durable UDP readiness state; \
                 retracting it and requiring the node-agent to acknowledge closing those gates \
                 before any stale host state is removed"
            );
        }
        for pod_uid in std::mem::take(&mut self.pending_request) {
            let one: HashSet<String> = std::iter::once(pod_uid.clone()).collect();
            if super::netns_udp_capture::request_udp_gate_close(ready_dir, &one) {
                self.awaiting.insert(pod_uid);
            } else {
                // Retried on the next pass, never dropped: forgetting it would
                // let the recovery settle and reap while this pod's gate is open.
                debug!(
                    pod_uid = %pod_uid,
                    "Host UDP capture: could not persist the recovery gate-close handshake"
                );
                self.pending_request.insert(pod_uid);
            }
        }
    }

    async fn await_acknowledgements(&mut self, ready_dir: &Path, budget: Duration) {
        if self.awaiting.is_empty() {
            return;
        }
        let deadline = Instant::now() + budget;
        loop {
            self.reap_settled(ready_dir);
            if self.awaiting.is_empty() || Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(GATE_CLOSE_ACK_POLL).await;
        }
    }

    fn reap_settled(&mut self, ready_dir: &Path) {
        let settled: Vec<String> = self
            .awaiting
            .iter()
            .filter(|pod_uid| {
                let pod_uid = pod_uid.as_str();
                super::netns_udp_capture::udp_gate_close_acknowledged(ready_dir, pod_uid)
                    || readiness_republished(ready_dir, pod_uid)
            })
            .cloned()
            .collect();
        for pod_uid in settled {
            let one: HashSet<String> = std::iter::once(pod_uid.clone()).collect();
            super::netns_udp_capture::clear_udp_ack_requirement(ready_dir, &one);
            self.awaiting.remove(&pod_uid);
        }
    }

    fn report(&mut self, settled: bool) {
        if settled {
            if self.announced {
                self.announced = false;
                self.last_warned = None;
                info!(
                    "Host UDP capture: every UDP gate a previous generation left open is \
                     acknowledged closed; the stale host state may now be removed"
                );
            }
            return;
        }
        let now = Instant::now();
        if self
            .last_warned
            .is_some_and(|last| now.duration_since(last) < STALE_RECOVERY_WARN_INTERVAL)
        {
            return;
        }
        self.last_warned = Some(now);
        warn!(
            awaiting_acknowledgement = self.awaiting.len(),
            unpersisted_requests = self.pending_request.len(),
            scan_incomplete = self.scan_truncated,
            "Host UDP capture: the UDP gates a previous generation left open are not yet provably \
             closed; its host state is retained (a capture path with no socket drops, it does not \
             leak) and recovery is retried"
        );
    }

    fn should_warn_reap_failure(&mut self) -> bool {
        let now = Instant::now();
        if self
            .last_reap_warned
            .is_some_and(|last| now.duration_since(last) < STALE_RECOVERY_WARN_INTERVAL)
        {
            return false;
        }
        self.last_reap_warned = Some(now);
        true
    }
}

/// Whether a producer OTHER than this recovery has published readiness for the
/// pod since the retraction — see the type-level note on why that settles it.
fn readiness_republished(ready_dir: &Path, pod_uid: &str) -> bool {
    super::netns_udp_capture::udp_ready_marker_path(ready_dir, pod_uid)
        .is_some_and(|marker| marker.is_file())
}

/// Names in one Ferrum-owned handshake directory, bounded and exact-name scoped.
///
/// Only plain files whose name is one this path would itself have written are
/// returned, so nothing outside Ferrum's own marker convention is ever acted on.
/// Returns whether the scan hit [`MAX_STALE_RECOVERY_MARKERS`]; an absent
/// directory is an empty, complete scan.
fn read_handshake_marker_uids(dir: &Path) -> Result<(Vec<String>, bool), std::io::Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), false));
        }
        Err(error) => return Err(error),
    };
    let mut uids: Vec<String> = Vec::new();
    let mut truncated = false;
    let mut scanned = 0usize;
    for entry in entries {
        // A per-entry read error may conceal a Ferrum marker. Ignoring it would
        // let the scan declare itself complete and authorize stale-rule removal
        // while the corresponding BPF gate may still be open.
        let entry = entry?;
        // EVERY entry counts, not just the accepted ones: the directory is
        // written by another process, so the work a scan can be made to do has
        // to be bounded by what is present, not by what turns out to be valid.
        scanned += 1;
        if scanned > MAX_STALE_RECOVERY_MARKERS {
            truncated = true;
            break;
        }
        let Ok(pod_uid) = entry.file_name().into_string() else {
            continue;
        };
        if super::netns_udp_capture::udp_ready_marker_path(dir, &pod_uid).is_none() {
            continue;
        }
        // The same fail-closed rule applies to the type lookup: a stat failure
        // cannot be treated as proof that the entry is not a marker.
        if !entry.file_type()?.is_file() {
            continue;
        }
        uids.push(pod_uid);
    }
    Ok((uids, truncated))
}

/// Reconciles host-network UDP capture against the enrolled-pod registry.
pub struct HostUdpCaptureManager<B: HostUdpCaptureBackend> {
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    index: Arc<HostUdpIdentityIndex>,
    /// Producer-to-node-agent readiness handshake directory
    /// (`<registry>/.udp-ready`). The node-agent keeps each pod's BPF UDP gate
    /// closed until the marker exists, so publishing it is what admits a pod's
    /// UDP egress — and withholding it is what keeps a refused pod closed.
    ready_dir: Option<PathBuf>,
    /// The state whose ruleset is currently installed. `None` until the first
    /// successful apply, which is also the "nothing installed yet" posture.
    applied: Option<HostUdpDesiredState>,
    /// What the most recent poll DECIDED, whether or not it was installed. This
    /// is what `reconcile_once` reports, so refusals stay visible even on a poll
    /// that installed nothing (a node whose every enrolled pod is refused would
    /// otherwise look indistinguishable from a node with no enrolled pods).
    last_desired: HostUdpDesiredState,
    listener: Option<HostUdpListenerHandle>,
    /// How long shutdown waits for the node-agent's gate-close acknowledgement.
    gate_close_timeout: Duration,
    /// `true` when the fail-closed guard is installed and has not been released.
    /// A retained guard survives across polls so a failing node stays closed.
    guard_active: bool,
    /// The interface set the last guard/capture install was scoped to. Tracked
    /// SEPARATELY from `applied`, which a failed apply clears: shutdown still has
    /// to be able to (re)install a scope-exact guard for the pods whose readiness
    /// it published, and it cannot derive that scope from a cleared `applied`.
    guard_scope: Vec<String>,
    /// Pods whose readiness marker this process published and has not retracted,
    /// mapped to the interface their capture rule is scoped to.
    ///
    /// This — NOT `applied` — is what shutdown and retraction key on. A failed
    /// apply clears `applied` while the node-agent's UDP gate is still open for
    /// those pods (their egress is held by the retained DROP guard), so keying
    /// teardown on `applied` would let shutdown conclude "nothing was ready",
    /// remove the guard, and release their egress in plaintext. The interface is
    /// carried alongside the UID because it is what a protective guard has to be
    /// scoped to once the pod is gone from the desired state.
    published_ready: HashMap<String, String>,
    /// Pods whose durable `.udp-ack-required` gate-close handshake this process
    /// has issued and whose `.udp-not-ready` acknowledgement has not arrived,
    /// mapped to the interface that must stay guarded until it does.
    ///
    /// Removing a readiness marker does NOT synchronously close the node-agent's
    /// BPF UDP gate, so a removed pod's capture rule may not disappear until the
    /// close is acknowledged — otherwise its egress leaves the node in plaintext
    /// for as long as the node-agent takes to notice. Reconcile keeps these pods
    /// inside the DROP guard's scope and refuses to rebuild the chain until the
    /// set drains.
    awaiting_gate_close: HashMap<String, String>,
    /// Refusal reasons already logged, so a persistently unresolvable pod does
    /// not warn on every poll.
    logged_refusals: HashMap<String, HostUdpRefusal>,
    /// The durable handshake a previous generation of this process left behind.
    recovery: HostUdpStaleGenerationRecovery,
    /// Armed by [`Self::run`], the entry point that owns a whole process
    /// lifetime and is therefore the one that can have a predecessor. While it
    /// is set, nothing is applied and nothing is torn down: either would race
    /// the node-agent's still-open UDP gates. A caller driving the reconcile
    /// steps itself is responsible for having recovered first.
    startup_recovery_pending: bool,
}

impl<B: HostUdpCaptureBackend> HostUdpCaptureManager<B> {
    pub fn new(source: Arc<dyn PodCaptureSource>, backend: B, poll_interval: Duration) -> Self {
        Self {
            source,
            backend,
            poll_interval,
            index: Arc::new(HostUdpIdentityIndex::new()),
            ready_dir: None,
            applied: None,
            last_desired: HostUdpDesiredState::default(),
            listener: None,
            gate_close_timeout: GATE_CLOSE_ACK_TIMEOUT,
            guard_active: false,
            guard_scope: Vec::new(),
            published_ready: HashMap::new(),
            awaiting_gate_close: HashMap::new(),
            logged_refusals: HashMap::new(),
            recovery: HostUdpStaleGenerationRecovery::new(None),
            startup_recovery_pending: false,
        }
    }

    pub fn with_ready_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.recovery = HostUdpStaleGenerationRecovery::new(dir.clone());
        self.ready_dir = dir;
        self
    }

    /// Override the bounded wait for the node-agent's gate-close acknowledgement
    /// (tests use a short window; production uses [`GATE_CLOSE_ACK_TIMEOUT`]).
    #[allow(dead_code)]
    pub fn with_gate_close_timeout(mut self, timeout: Duration) -> Self {
        self.gate_close_timeout = timeout;
        self
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        // This is the entry point that owns a whole process lifetime, so it is
        // the one that can have a predecessor whose durable state must be
        // recovered before anything else happens.
        self.startup_recovery_pending = true;
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    // Startup recovery gates the FIRST apply, not just the reap:
                    // applying would publish readiness for this generation while
                    // the previous generation's gates are still open and its
                    // rules still installed, which is the same mixed state the
                    // recovery exists to resolve. Failing closed and retrying is
                    // the correct posture — enrolled UDP egress stays dropped by
                    // the retained state rather than escaping in plaintext.
                    if self.startup_recovery_pending
                        && !self.recover_stale_generation_once().await
                    {
                        continue;
                    }
                    self.reconcile_once().await;
                }
            }
        }
        self.shutdown().await;
    }

    /// One bounded startup-recovery pass: discharge the durable handshake a
    /// previous generation left, then reap its host objects.
    ///
    /// `true` means the datapath is now genuinely empty of predecessor state and
    /// the first apply may run. `false` means everything the predecessor
    /// installed is retained — a capture path whose socket died with its process
    /// drops, so retaining it is the fail-closed posture, and a reap that failed
    /// is retried rather than logged once and forgotten.
    pub async fn recover_stale_generation_once(&mut self) -> bool {
        // Same shape as the reconcile-time budget: bounded by the configured
        // handshake window so a shortened test window shortens this too, and by
        // the per-pass ceiling so a stalled node-agent still yields a log line
        // and a retry instead of one long silent wait.
        let budget = self.gate_close_timeout.min(STALE_RECOVERY_ACK_WAIT);
        if !self.recovery.poll_once(budget).await {
            return false;
        }
        if let Err(error) = self.backend.teardown_all() {
            if self.recovery.should_warn_reap_failure() {
                warn!(
                    %error,
                    "Host UDP capture: could not reap the previous generation's host capture \
                     state; retaining it and retrying before anything is applied"
                );
            }
            return false;
        }
        self.startup_recovery_pending = false;
        true
    }

    /// One reconcile pass. Never panics and never leaves the datapath in a state
    /// that leaks plaintext: every failure path either keeps the previous live
    /// ruleset or retains the DROP guard.
    ///
    /// Assumes [`Self::recover_stale_generation_once`] has already succeeded —
    /// [`Self::run`] guarantees that. A caller that drives this directly owns
    /// that precondition: applying over a predecessor's un-acknowledged state
    /// would publish this generation's readiness while the node-agent still has
    /// the previous generation's gates open.
    pub async fn reconcile_once(&mut self) -> &HostUdpDesiredState {
        self.supervise_listener().await;
        let targets = self.source.list_targets();
        let mut resolved: HashMap<String, ResolvedInterface> = HashMap::new();
        for target in &targets {
            match self.backend.resolve_interface(target) {
                Ok(interface) => {
                    resolved.insert(target.pod_uid.clone(), interface);
                }
                Err(error) => {
                    debug!(
                        pod_uid = %target.pod_uid,
                        %error,
                        "Host UDP capture: could not resolve host-side interface for pod"
                    );
                }
            }
        }
        let desired = plan_host_udp_bindings(&targets, &resolved);
        self.log_refusals(&desired);
        self.last_desired = desired.clone();

        let rules_changed = self
            .applied
            .as_ref()
            .is_none_or(|applied| desired.rules_differ_from(applied));
        let restart_required = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.requires_listener_restart_from(applied));
        let listener_needed = !desired.bindings.is_empty();
        let listener_missing = listener_needed && self.listener.is_none();
        // A pod whose gate close is not yet acknowledged still owes this manager
        // a transition, so its poll can never be a no-op no matter how stable the
        // desired state looks.
        let gate_close_pending = !self.awaiting_gate_close.is_empty();

        // Nothing enrolled and nothing installed: install no chain, no jump, and
        // no routing. A node with no mesh-enrolled pods keeps a completely
        // untouched datapath.
        if desired.bindings.is_empty()
            && self.applied.is_none()
            && self.listener.is_none()
            && !self.guard_active
            && !gate_close_pending
            && self.published_ready.is_empty()
        {
            return &self.last_desired;
        }
        if !rules_changed
            && !restart_required
            && !listener_missing
            && !self.guard_active
            && !gate_close_pending
        {
            // Readiness publication is a durable, fallible filesystem effect.
            // Retry missing markers on every otherwise-idle poll without
            // rebuilding a healthy rules/listener generation.
            self.publish_readiness_markers(&desired);
            return &self.last_desired;
        }

        self.apply(desired).await;
        &self.last_desired
    }

    /// Detect a capture loop that returned on its own — a socket error, a bind
    /// that died under it, a panicked task.
    ///
    /// Nothing else notices: the handle stays `Some`, so no poll sees a missing
    /// listener, the ruleset keeps steering every enrolled pod's egress into a
    /// socket nobody reads, and readiness stays published. Clearing `applied`
    /// forces the next apply, which reinstalls the guard, rebuilds the chain, and
    /// restarts the loop through the ordinary guarded path. An operator-requested
    /// stop consumes the handle (both [`Self::shutdown`] and [`Self::apply`]
    /// `take()` it before stopping), so this can only ever observe an UNEXPECTED
    /// exit — a requested shutdown is never turned into a restart.
    async fn supervise_listener(&mut self) {
        if !self
            .listener
            .as_ref()
            .is_some_and(HostUdpListenerHandle::is_finished)
        {
            return;
        }
        warn!(
            "Host UDP capture: the transparent capture loop exited unexpectedly; guarding the \
             datapath and restarting it"
        );
        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
        // Stale evidence and the claim to a live ruleset both go: a late datagram
        // must not be attributed by a socket that is gone, and the next apply has
        // to rebuild from the guarded posture rather than short-circuit.
        self.index.clear();
        self.applied = None;
    }

    async fn apply(&mut self, desired: HostUdpDesiredState) {
        let ifaces = desired.ifaces();
        let now_bound = desired.bound_uids();

        // 1. Guard first, scoped to the UNION of what this generation captures
        //    and what still owes a transition (pods whose readiness this process
        //    published, pods awaiting a gate-close acknowledgement, and the scope
        //    the last guard was installed with). A desired-only guard would leave
        //    a removed pod's interface unprotected exactly while its capture rule
        //    is being rebuilt away. Enrolled egress is dropped for the duration of
        //    the rebuild rather than briefly escaping capture. A guard failure
        //    keeps the previous live ruleset (still correct for the pods it
        //    covers) and retries next poll; it must NOT proceed to flush the
        //    capture chain, because that would open the very window the guard
        //    exists to close.
        let guard_ifaces = self.guard_scope_for(&ifaces);
        if !guard_ifaces.is_empty() {
            if let Err(error) = self.backend.install_guard(&guard_ifaces) {
                warn!(
                    %error,
                    interfaces = guard_ifaces.len(),
                    "Host UDP capture: fail-closed guard install failed; keeping the previous \
                     ruleset and retrying"
                );
                return;
            }
            self.guard_active = true;
            self.guard_scope = guard_ifaces;
        }

        // 2. A restart-requiring change cannot be absorbed by a running loop: its
        //    admitted sessions still carry the previous evidence, and a removed
        //    pod's session still holds a transparent reply socket. Stop the loop
        //    (which drains and cancels its sessions) before republishing.
        let restart_required = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.requires_listener_restart_from(applied));
        if restart_required && let Some(listener) = self.listener.take() {
            info!(
                "Host UDP capture: a captured pod's attribution changed or was withdrawn; \
                 restarting the capture listener so no session keeps relaying under the previous \
                 evidence"
            );
            listener.stop().await;
            self.index.clear();
        }

        // 3. Retire the pods this generation drops through the DURABLE node-agent
        //    handshake before any rule of theirs can disappear. Removing a
        //    readiness marker does not synchronously close the node-agent's BPF
        //    gate, so an unacknowledged close plus a rebuilt chain is exactly the
        //    window in which a removed pod's UDP egress leaves the node in
        //    plaintext. Their interfaces stay inside the guard installed above
        //    until the acknowledgement lands, so waiting costs availability for
        //    the pods being retired, never confidentiality.
        self.cancel_gate_close_for_returning(&now_bound);
        let leaving: Vec<(String, String)> = self
            .published_ready
            .iter()
            .filter(|(uid, _)| !now_bound.contains(*uid))
            .map(|(uid, iface)| (uid.clone(), iface.clone()))
            .collect();
        let requested = self.begin_gate_close(&leaving);
        let budget = self.gate_close_timeout.min(RECONCILE_GATE_CLOSE_ACK_WAIT);
        let acknowledged = self.await_gate_close(budget).await;
        if !requested || !acknowledged {
            // Fail closed and retry: the guard installed above stays up, the live
            // ruleset is left alone, and nothing this pass would have removed is
            // removed.
            return;
        }

        // 4. Rebuild the capture chain. An empty interface set renders no rules
        //    at all (the generator refuses to emit an empty ruleset), so the
        //    chain contents are removed instead; the `PREROUTING` jump and the
        //    guard both stay until step 8.
        let rebuilt = if ifaces.is_empty() {
            self.backend.teardown_capture_rules()
        } else {
            self.backend.install_capture(&ifaces)
        };
        if let Err(error) = rebuilt {
            warn!(
                %error,
                interfaces = ifaces.len(),
                "Host UDP capture: capture rule install failed; removing partial capture state \
                 and retaining the fail-closed guard"
            );
            if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                warn!(
                    error = %cleanup_error,
                    "Host UDP capture: partial capture cleanup failed; guard retained"
                );
            }
            // The previously applied ruleset is gone, so do not keep claiming it
            // or leave sessions from that now-untracked generation alive. If the
            // listener survived while `applied` became `None`, a later removal
            // could not detect that it must restart the listener, and an admitted
            // session could keep its stale identity / transparent reply socket.
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
            self.applied = None;
            self.index.clear();
            return;
        }

        // 5. Publish evidence BEFORE the guard is released, so the very first
        //    datagram the socket can receive is already attributable.
        self.index.publish(&desired.bindings);

        // 6. Start the listener if capture is wanted and none is running. A bind
        //    failure keeps the guard: rules without a socket are a black hole,
        //    and a black hole plus a released guard would look like capture while
        //    silently discarding traffic.
        if !desired.bindings.is_empty() && self.listener.is_none() {
            match self.backend.start_listener(self.index.clone()) {
                Ok(handle) => self.listener = Some(handle),
                Err(error) => {
                    warn!(
                        %error,
                        "Host UDP capture: transparent socket bind failed; retaining the \
                         fail-closed guard and retrying"
                    );
                    if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                        warn!(
                            error = %cleanup_error,
                            "Host UDP capture: capture cleanup after bind failure did not complete"
                        );
                    }
                    self.index.clear();
                    self.applied = None;
                    return;
                }
            }
        }

        // 7. Stop a listener nobody needs (every pod unenrolled or refused).
        if desired.bindings.is_empty()
            && let Some(listener) = self.listener.take()
        {
            listener.stop().await;
            self.index.clear();
        }

        // 8. Guarded → live. A release failure keeps the guard AND removes the
        //    capture rules: dropping is a correct posture, capturing behind a
        //    DROP is not.
        // Released unconditionally, not only when THIS pass installed a guard: a
        // previous pass may have retained one (its release failed, or the pod set
        // has since emptied), and that retained DROP must not outlive the rebuild
        // that fixed it. The release script tolerates absent chains and stays
        // strict about resource errors.
        if let Err(error) = self.backend.release_guard() {
            warn!(
                %error,
                "Host UDP capture: could not release the fail-closed guard; removing capture \
                 rules and retrying with enrolled egress still closed"
            );
            if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                warn!(
                    error = %cleanup_error,
                    "Host UDP capture: capture cleanup after guard-release failure did not complete"
                );
            }
            // Keep the listener generation and `applied` generation coupled on
            // every failure path. The guard remains fail-closed and the capture
            // rules are gone, so preserving live sessions provides no availability
            // benefit and would make their evidence impossible to compare during
            // the next withdrawal.
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
            self.index.clear();
            self.applied = None;
            self.guard_active = true;
            return;
        }
        self.guard_active = false;

        // 9. Only now is each captured pod's egress genuinely going through the
        //    mesh, so publish its readiness marker and open the BPF gate.
        self.publish_readiness_markers(&desired);
        // Every retirement this pass owed is acknowledged (step 3 returned
        // otherwise), so the protective scope narrows back to what is captured.
        self.guard_scope = ifaces;

        info!(
            captured_pods = desired.bindings.len(),
            refused_pods = desired.refused.len(),
            "Host UDP capture reconciled"
        );
        self.applied = Some(desired);
    }

    /// Publish readiness only for pods whose marker write actually succeeded.
    /// Failed writes remain absent from `published_ready`, so the idle reconcile
    /// path retries them instead of permanently leaving the node-agent's BPF UDP
    /// gate closed. An already-published entry is retained if its marker later
    /// disappears: the node-agent may already have opened that gate, so shutdown
    /// and withdrawal must still discharge the close handshake.
    fn publish_readiness_markers(&mut self, desired: &HostUdpDesiredState) {
        let Some(ready_dir) = self.ready_dir.clone() else {
            self.published_ready.extend(desired.bound_ifaces());
            return;
        };
        for binding in &desired.bindings {
            if let Some(iface) = self.published_ready.get_mut(&binding.pod_uid) {
                // The marker already opened this pod's gate, but its dedicated
                // veth may have been recreated. Keep the guard/withdrawal scope
                // aligned with the current evidence generation.
                iface.clone_from(&binding.iface);
                continue;
            }
            if super::netns_udp_capture::write_udp_ready_marker(&ready_dir, &binding.pod_uid) {
                self.published_ready
                    .insert(binding.pod_uid.clone(), binding.iface.clone());
            }
        }
    }

    /// The interface set the fail-closed guard must cover for one transition:
    /// what the new generation captures, plus every interface still carrying an
    /// obligation — a pod whose readiness this process published (the node-agent
    /// may still have its BPF gate open) or one awaiting a gate-close
    /// acknowledgement — plus whatever the last guard was scoped to (a failed
    /// apply clears `applied`, so it is the only remaining record of what an
    /// earlier pass protected).
    fn guard_scope_for(&self, desired: &[String]) -> Vec<String> {
        let mut scope: Vec<String> = desired.to_vec();
        for iface in self
            .published_ready
            .values()
            .chain(self.awaiting_gate_close.values())
            .chain(self.guard_scope.iter())
        {
            if !scope.contains(iface) {
                scope.push(iface.clone());
            }
        }
        // The generator refuses duplicates and the rendered ruleset should not
        // depend on map iteration order.
        scope.sort();
        scope.dedup();
        scope
    }

    /// A pod that re-entered capture is owned by the ordinary apply path again:
    /// this pass republishes its readiness once capture is live, so its pending
    /// handshake is cancelled rather than awaited. Awaiting it would stall every
    /// reconcile on an acknowledgement the node-agent has no reason to send.
    fn cancel_gate_close_for_returning(&mut self, bound: &HashSet<String>) {
        let returning: Vec<String> = self
            .awaiting_gate_close
            .keys()
            .filter(|uid| bound.contains(*uid))
            .cloned()
            .collect();
        for pod_uid in returning {
            self.clear_gate_close_requirement(&pod_uid);
            self.awaiting_gate_close.remove(&pod_uid);
            // The close request retracted this marker even though the durable
            // published record stays until an acknowledgement. Drop that stale
            // record now so step 9 must write readiness again after the returning
            // pod's capture path is live.
            self.published_ready.remove(&pod_uid);
        }
    }

    /// Start (or continue) the durable gate-close handshake for pods leaving
    /// capture. `false` means at least one requirement could not be persisted, so
    /// the caller must stay fail-closed: that pod keeps its published readiness,
    /// its interface stays in the guard scope, and no rule of its is removed.
    ///
    /// A pod already awaiting an acknowledgement is deliberately NOT re-requested.
    /// [`request_udp_gate_close`](super::netns_udp_capture::request_udp_gate_close)
    /// deletes any `.udp-not-ready` ack before retracting readiness — so a stale
    /// ack can never authorize a new handoff — and reissuing it every poll would
    /// delete the very acknowledgement this manager is waiting for.
    fn begin_gate_close(&mut self, leaving: &[(String, String)]) -> bool {
        let mut requested = true;
        for (pod_uid, iface) in leaving {
            if self.awaiting_gate_close.contains_key(pod_uid) {
                continue;
            }
            let Some(ready_dir) = self.ready_dir.clone() else {
                // No handshake directory: nothing gates this pod's UDP egress on
                // our readiness marker, so there is no acknowledgement to await.
                self.published_ready.remove(pod_uid);
                continue;
            };
            let one: HashSet<String> = std::iter::once(pod_uid.clone()).collect();
            if super::netns_udp_capture::request_udp_gate_close(&ready_dir, &one) {
                self.awaiting_gate_close
                    .insert(pod_uid.clone(), iface.clone());
            } else {
                warn!(
                    pod_uid = %pod_uid,
                    "Host UDP capture: could not persist the UDP gate-close handshake for a pod \
                     leaving capture; its fail-closed guard and capture rule are retained until \
                     it succeeds"
                );
                requested = false;
            }
        }
        requested
    }

    /// Wait (bounded by `budget`) for the node-agent to acknowledge every
    /// outstanding gate close. Each pod is retired individually the moment its
    /// `.udp-not-ready` marker appears — that marker is the proof its BPF gate is
    /// shut, and it is the only thing that makes clearing the durable requirement
    /// safe.
    async fn await_gate_close(&mut self, budget: Duration) -> bool {
        if self.awaiting_gate_close.is_empty() {
            return true;
        }
        let deadline = Instant::now() + budget;
        loop {
            self.reap_acknowledged_gate_closes();
            if self.awaiting_gate_close.is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                warn!(
                    pods = self.awaiting_gate_close.len(),
                    "Host UDP capture: the node-agent did not acknowledge closing its UDP gate \
                     for pods leaving capture; retaining their fail-closed guard and their \
                     capture rules, and retrying"
                );
                return false;
            }
            tokio::time::sleep(GATE_CLOSE_ACK_POLL).await;
        }
    }

    fn reap_acknowledged_gate_closes(&mut self) {
        let acknowledged: Vec<String> = self
            .awaiting_gate_close
            .keys()
            .filter(|pod_uid| self.gate_close_acknowledged(pod_uid.as_str()))
            .cloned()
            .collect();
        for pod_uid in acknowledged {
            self.clear_gate_close_requirement(&pod_uid);
            self.awaiting_gate_close.remove(&pod_uid);
            self.published_ready.remove(&pod_uid);
        }
    }

    fn clear_gate_close_requirement(&self, pod_uid: &str) {
        if let Some(ready_dir) = &self.ready_dir {
            let one: HashSet<String> = std::iter::once(pod_uid.to_string()).collect();
            super::netns_udp_capture::clear_udp_ack_requirement(ready_dir, &one);
        }
    }

    /// Graceful shutdown: retract readiness, wait (bounded) for the node-agent to
    /// confirm the BPF gates are closed, then remove Ferrum-owned host state.
    ///
    /// If the acknowledgement does not arrive, the fail-closed guard is installed
    /// and only the capture rules are removed. If the guard itself cannot be
    /// installed, the existing capture/routing objects are retained after the
    /// listener stops; a socketless TPROXY path drops traffic, while removing the
    /// path could release it as plaintext while the node-agent still believes
    /// capture is live.
    pub async fn shutdown(&mut self) {
        // A shutdown that races an unfinished startup recovery must remove
        // NOTHING. This process published no readiness of its own and installed
        // no rules of its own, so it owns no teardown here; every host object
        // present belongs to the previous generation and is the only thing
        // holding its still-un-acknowledged pods closed. The ordinary path below
        // would see an empty `published_ready`, conclude nothing was ready, and
        // reap exactly that state.
        if self.startup_recovery_pending {
            warn!(
                pods = self.recovery.outstanding(),
                "Host UDP capture: shutting down before startup recovery completed; retaining \
                 every host object so the UDP gates a previous generation left open stay closed \
                 by its rules"
            );
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
            self.index.clear();
            return;
        }

        // Every pod this process ever published readiness for, INCLUDING the ones
        // a reconcile already moved onto the handshake but could not retire: both
        // still owe an acknowledgement, and both still need guard coverage.
        let leaving: Vec<(String, String)> = self
            .published_ready
            .iter()
            .map(|(uid, iface)| (uid.clone(), iface.clone()))
            .collect();
        let ifaces = self.guard_scope_for(&[]);
        // A pod awaiting an acknowledgement is still published, so this is the
        // whole set, not a subset of it.
        let pods = leaving.len();

        let budget = self.gate_close_timeout;
        let requested = self.begin_gate_close(&leaving);
        let acknowledged = requested && self.await_gate_close(budget).await;

        if acknowledged {
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
            self.index.clear();
            if let Err(error) = self.backend.teardown_all() {
                warn!(%error, "Host UDP capture: shutdown teardown did not complete");
            }
            self.published_ready.clear();
        } else {
            warn!(
                pods,
                "Host UDP capture: node-agent did not acknowledge closing its UDP gates; \
                 preserving a fail-closed shutdown posture"
            );
            let guard_installed = if ifaces.is_empty() {
                true
            } else {
                match self.backend.install_guard(&ifaces) {
                    Ok(()) => true,
                    Err(error) => {
                        warn!(
                            %error,
                            "Host UDP capture: could not install the shutdown fail-closed guard; \
                             retaining the existing capture and routing objects so egress cannot \
                             escape in plaintext"
                        );
                        false
                    }
                }
            };
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
            self.index.clear();
            if guard_installed && let Err(error) = self.backend.teardown_capture_rules() {
                warn!(%error, "Host UDP capture: shutdown capture cleanup did not complete");
            }
        }
        self.applied = None;
        self.guard_active = false;
        self.guard_scope.clear();
    }

    /// Whether the node-agent published the durable `.udp-not-ready` marker that
    /// proves this pod's BPF UDP gate is shut. Without a handshake directory
    /// nothing gated the pod on our readiness marker in the first place.
    fn gate_close_acknowledged(&self, pod_uid: &str) -> bool {
        let Some(ready_dir) = &self.ready_dir else {
            return true;
        };
        super::netns_udp_capture::udp_gate_close_acknowledged(ready_dir, pod_uid)
    }

    fn log_refusals(&mut self, desired: &HostUdpDesiredState) {
        for (pod_uid, reason) in &desired.refused {
            if self.logged_refusals.get(pod_uid) == Some(reason) {
                continue;
            }
            warn!(
                pod_uid = %pod_uid,
                reason = reason.as_str(),
                "Host UDP capture refused a pod; its UDP egress stays closed (the readiness \
                 marker is withheld) rather than bypassing the mesh"
            );
            self.logged_refusals.insert(pod_uid.clone(), *reason);
        }
        let still_refused: HashSet<&String> = desired.refused.iter().map(|(uid, _)| uid).collect();
        self.logged_refusals
            .retain(|uid, _| still_refused.contains(uid));
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Production backend
// ───────────────────────────────────────────────────────────────────────────

/// The production host capture backend: renders the plans from
/// `crate::capture`, runs them through `sh -c` in the process's OWN (host)
/// network namespace — no `setns` anywhere — and binds the transparent socket
/// here too.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ProxyHostUdpBackend {
    state: Arc<super::ProxyState>,
    capture_config: crate::capture::CaptureConfig,
    capture_port: u16,
    max_sessions: usize,
    cleanup_interval_seconds: u64,
    recvmmsg_batch_size: usize,
    session_shard_amount: usize,
    sysfs_net: PathBuf,
}

impl ProxyHostUdpBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: Arc<super::ProxyState>,
        capture_config: crate::capture::CaptureConfig,
        capture_port: u16,
        max_sessions: usize,
        cleanup_interval_seconds: u64,
        recvmmsg_batch_size: usize,
        session_shard_amount: usize,
    ) -> Self {
        Self {
            state,
            capture_config,
            capture_port,
            max_sessions,
            cleanup_interval_seconds,
            recvmmsg_batch_size,
            session_shard_amount,
            sysfs_net: PathBuf::from("/sys/class/net"),
        }
    }

    /// Override the sysfs root used for interface-index lookups (tests).
    #[allow(dead_code)]
    pub fn with_sysfs_net(mut self, path: PathBuf) -> Self {
        self.sysfs_net = path;
        self
    }

    /// Read an interface's kernel index. The index is what every captured
    /// datagram is attributed by, so it is read from sysfs (authoritative) rather
    /// than derived from the name.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn ifindex_for(&self, name: &str) -> Result<u32, String> {
        dedicated_host_ifindex(&self.sysfs_net, name)
    }
}

/// Validate that a resolved device is a dedicated host-side peer and return its
/// kernel interface index.
///
/// `iptables -i` is safe only at a per-pod boundary, not on a shared bridge or
/// uplink. Route discovery already requires an exact host route, but that alone
/// does not prove interface shape. A host-side veth has a distinct peer
/// `iflink`; a bridge or ordinary physical interface links to itself. Refuse
/// uncertainty rather than widening one enrolled pod's capture rule to unrelated
/// neighbours.
pub(crate) fn dedicated_host_ifindex(sysfs_net: &Path, name: &str) -> Result<u32, String> {
    crate::capture::validate_host_capture_interface(name)?;
    let iface_path = sysfs_net.join(name);
    let index_path = iface_path.join("ifindex");
    let raw = std::fs::read_to_string(&index_path)
        .map_err(|error| format!("could not read {}: {error}", index_path.display()))?;
    let index = raw.trim().parse::<u32>().map_err(|_| {
        format!(
            "{} does not contain an interface index",
            index_path.display()
        )
    })?;
    if index == 0 {
        return Err("interface index 0 is not a usable capture attribution key".to_string());
    }

    let link_path = iface_path.join("iflink");
    let link_raw = std::fs::read_to_string(&link_path)
        .map_err(|error| format!("could not read {}: {error}", link_path.display()))?;
    let link = link_raw.trim().parse::<u32>().map_err(|_| {
        format!(
            "{} does not contain an interface link index",
            link_path.display()
        )
    })?;
    if link == 0 || link == index || iface_path.join("bridge").exists() {
        return Err(
            "resolved interface is not a dedicated host-side peer; refusing shared capture"
                .to_string(),
        );
    }
    Ok(index)
}

#[cfg(target_os = "linux")]
impl HostUdpCaptureBackend for ProxyHostUdpBackend {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        // Prefer the pod's own netns view (`iflink` → host peer index), which
        // identifies the veth peer directly. Fall back to the host route table
        // keyed on the registry-published pod IP, which needs neither `hostPID`
        // nor `setns` — that fallback is what lets this path run without the
        // per-pod-netns producer's elevated privileges.
        //
        // BOTH families are tried, and that is load-bearing rather than tidiness:
        // on the intended deployment (no `hostPID`, so the cgroup/`/proc` view is
        // unavailable) the route table is the ONLY resolver, so a v4-only
        // fallback would refuse every IPv6-only enrolled pod while this path
        // claims dual-stack support. v4 is tried first so a dual-stack pod keeps
        // resolving exactly as before.
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
        let ifindex = self.ifindex_for(&name)?;
        Ok(ResolvedInterface { name, ifindex })
    }

    fn install_guard(&self, ifaces: &[String]) -> Result<(), String> {
        let script = IptablesPlan::host_udp_guard_script(&self.capture_config, ifaces)?;
        if script.is_empty() {
            return Ok(());
        }
        run_host_script(&script)
    }

    fn install_capture(&self, ifaces: &[String]) -> Result<(), String> {
        let script = IptablesPlan::host_udp_setup_script(&self.capture_config, ifaces)?;
        run_host_script(&script)
    }

    fn teardown_capture_rules(&self) -> Result<(), String> {
        let script = IptablesPlan::host_udp_capture_rules_teardown_script();
        run_host_script(&script)
    }

    fn release_guard(&self) -> Result<(), String> {
        run_host_script(&IptablesPlan::host_udp_guard_release_script())
    }

    fn teardown_all(&self) -> Result<(), String> {
        let script = IptablesPlan::host_udp_teardown_script();
        run_host_script(&script)
    }

    fn start_listener(
        &self,
        index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String> {
        let wildcard = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let bind_addr = std::net::SocketAddr::new(wildcard, self.capture_port);
        // `true` requests the ingress-interface cmsg: on this shared socket the
        // interface index IS the identity key, so a bind that cannot report it
        // fails rather than serving unattributable datagrams.
        let (std_socket, bound_addr, v4_origdst, v6_origdst) =
            super::mesh_udp_capture::bind_mesh_udp_capture_socket_with_pktinfo(bind_addr, true)
                .map_err(|error| error.to_string())?;
        let frontend_socket =
            tokio::net::UdpSocket::from_std(std_socket).map_err(|error| error.to_string())?;
        let runtime = super::mesh_udp_capture::MeshUdpCaptureRuntime {
            state: self.state.clone(),
            cleanup_interval_seconds: self.cleanup_interval_seconds,
            recvmmsg_batch_size: self.recvmmsg_batch_size,
            session_shard_amount: self.session_shard_amount,
            session_limiter: Arc::new(super::mesh_udp_capture::MeshUdpSessionLimiter::new(
                self.max_sessions,
            )),
            source_identity: super::mesh_udp_capture::CapturedSourceEvidence::HostIngress(index),
            // The capture socket and its reply sockets must share a namespace.
            // Both live in the proxy's own (host) namespace here; a reply is
            // sourced from the captured VIP:port and reaches the pod over the
            // ordinary host route out its interface.
            reply_socket_factory: Arc::new(super::mesh_udp_capture::CurrentNetnsReplySocketFactory),
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        info!(
            bound = %bound_addr,
            v4_origdst,
            v6_origdst,
            "Host UDP capture: transparent host-namespace capture socket bound"
        );
        let task = tokio::spawn(async move {
            let _ = super::mesh_udp_capture::run_mesh_udp_capture_on_socket(
                frontend_socket,
                bound_addr,
                v4_origdst,
                v6_origdst,
                runtime,
                stop_rx,
                None,
                None,
            )
            .await;
        });
        Ok(HostUdpListenerHandle::new(stop_tx, task))
    }
}

#[cfg(not(target_os = "linux"))]
impl HostUdpCaptureBackend for ProxyHostUdpBackend {
    fn resolve_interface(&self, _target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn install_guard(&self, _ifaces: &[String]) -> Result<(), String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn install_capture(&self, _ifaces: &[String]) -> Result<(), String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn teardown_capture_rules(&self) -> Result<(), String> {
        Ok(())
    }

    fn release_guard(&self) -> Result<(), String> {
        Ok(())
    }

    fn teardown_all(&self) -> Result<(), String> {
        Ok(())
    }

    fn start_listener(
        &self,
        _index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }
}

/// Removal of every Ferrum-owned host-netns UDP object, for the deployments that
/// are NOT running the host capture path.
///
/// A node that once ran host capture and now runs the pod-netns producer (or has
/// UDP capture switched off entirely) would otherwise keep a `PREROUTING` jump
/// into a chain whose socket nobody binds — captured egress diverted into a black
/// hole, with nothing left to reap it, because both the shutdown teardown and the
/// setup path are owned by a code path that no longer runs. This is the same
/// pre-setup reap the node-agent performs for the pod-netns UDP objects, applied
/// to the host-netns ones.
///
/// Every command targets an exact Ferrum-owned object, so it is a no-op when no
/// host state exists. NOT public on its own: removing these objects is only safe
/// once the durable readiness handshake they back has been discharged, which is
/// what [`recover_and_reap_stale_host_udp_state`] sequences.
fn reap_stale_host_udp_state() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    run_host_script(&IptablesPlan::host_udp_teardown_script())
}

/// Discharge the durable UDP readiness handshake a previous HOST-capture
/// generation left, then reap its host objects — for a node whose placement is
/// now the per-pod-netns producer, or which has UDP capture switched off.
///
/// This is the disabled/switched half of the same fail-closed recovery
/// [`HostUdpCaptureManager::recover_stale_generation_once`] runs: the node-agent
/// keeps a pod's BPF UDP gate open on a `.udp-ready` marker no live producer
/// owns any more, so reaping the host rules first would leave that pod's egress
/// neither captured nor gated.
///
/// Ordering matters and is the caller's responsibility: do not start the
/// incoming producer until the returned retraction boundary is open. The first
/// pass is awaited and bounded; if retraction cannot finish in that pass, the
/// returned barrier keeps the producer out while retries continue in the
/// background. Once the boundary opens, discovery is frozen and recovery can no
/// longer retract a per-pod-netns producer's newly published readiness. A pod
/// that producer republishes then settles the pending acknowledgement (see
/// [`HostUdpStaleGenerationRecovery`]), so the two halves of a placement switch
/// cannot deadlock.
///
/// Outcome of one bounded stale-host-state startup pass.
pub struct HostUdpStaleRecovery {
    /// Resolves when an incoming UDP producer can publish readiness without the
    /// recovery retracting it. `None` means that boundary is already safe.
    pub retraction_ready: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Retries unfinished retraction and stale-state reaping until success or
    /// shutdown. `None` means the first pass completed everything.
    pub retry_task: Option<tokio::task::JoinHandle<()>>,
}

/// Returns a bounded startup outcome. If marker discovery or close-request
/// persistence cannot complete, the caller may continue bringing up unrelated
/// mesh listeners while delaying only the incoming UDP producer on
/// `retraction_ready`. Until that barrier resolves, predecessor objects stay
/// installed and enrolled UDP remains fail-closed.
pub async fn recover_and_reap_stale_host_udp_state(
    ready_dir: Option<PathBuf>,
    retry_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> HostUdpStaleRecovery {
    let mut recovery = HostUdpStaleGenerationRecovery::new(ready_dir);
    // Exactly one bounded pass belongs to synchronous startup. Repeating this
    // loop here could wedge every mesh/admin listener forever on an unreadable or
    // oversized marker directory even when UDP capture is disabled.
    if recover_and_reap_once(&mut recovery).await {
        return HostUdpStaleRecovery {
            retraction_ready: None,
            retry_task: None,
        };
    }

    let (retraction_tx, retraction_ready) = if recovery.retraction_complete() {
        (None, None)
    } else {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (Some(tx), Some(rx))
    };
    let retry_task = tokio::spawn(async move {
        let mut retraction_tx = retraction_tx;
        let mut ticker = tokio::time::interval(retry_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The immediate first tick is the attempt the caller already awaited.
        ticker.tick().await;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = ticker.tick() => {
                    let reaped = recover_and_reap_once(&mut recovery).await;
                    if recovery.retraction_complete()
                        && let Some(tx) = retraction_tx.take()
                    {
                        let _ = tx.send(());
                    }
                    if reaped {
                        return;
                    }
                }
            }
        }
    });
    HostUdpStaleRecovery {
        retraction_ready,
        retry_task: Some(retry_task),
    }
}

pub(crate) async fn recover_and_reap_once(recovery: &mut HostUdpStaleGenerationRecovery) -> bool {
    if !recovery.poll_once(STALE_RECOVERY_ACK_WAIT).await {
        return false;
    }
    match reap_stale_host_udp_state() {
        Ok(()) => true,
        Err(error) => {
            // A reap that cannot complete is retried, not logged once: leaving a
            // `PREROUTING` jump into a socketless chain black-holes every
            // enrolled pod's UDP on this node until something removes it, and
            // after this point nothing else would.
            if recovery.should_warn_reap_failure() {
                warn!(
                    %error,
                    "Host UDP capture: stale host-namespace UDP state reap did not complete; \
                     retrying"
                );
            }
            false
        }
    }
}

/// Run one capture script in the process's own network namespace.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_host_script(script: &str) -> Result<(), String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|error| format!("could not run the host capture script: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    // Only the script's own diagnostics are surfaced, bounded in length. The
    // script text itself is not echoed: it embeds the node's capture scope and
    // would be noisy without adding diagnostic value.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail: String = stderr.trim().chars().take(512).collect();
    Err(format!(
        "host capture script failed with status {}: {detail}",
        output.status
    ))
}

//! NodeWaypoint UDP/DTLS **Service-path steering** (issue #3286).
//!
//! # The gap this closes
//!
//! Issue #3286's listeners are host-netns wildcard UDP/DTLS sockets, one per
//! in-mesh Service port. Materializing them makes the authorization *mechanism*
//! reachable, but nothing makes ORDINARY traffic reach it. Trace what a workload
//! actually does:
//!
//! 1. It resolves `svc.ns.svc.cluster.local` and sends a datagram to
//!    `<ClusterIP>:<port>`.
//! 2. The datagram leaves the pod netns and enters the host namespace on that
//!    pod's host-side veth. `cgroup/connect4`/`connect6` do NOT touch it — the
//!    outbound capture listener is TCP-only, so those hooks deliberately skip
//!    `SOCK_DGRAM` and the destination stays the ClusterIP.
//! 3. tc ingress on that veth sees a destination that is not an enrolled pod IP
//!    and passes it on.
//! 4. `nat PREROUTING` / kube-proxy DNATs the ClusterIP to a backing
//!    `podIP:targetPort` and the datagram is FORWARDED to that pod's veth.
//! 5. tc egress on the destination pod's veth finds an enrolled destination and
//!    an unmarked, non-DNS datagram — and DROPS it.
//!
//! So the Service path is not merely a bypass of the waypoint; with the relay
//! auth mark configured it is a black hole. Only a direct dial to a *node*
//! address ever reached the materialized listener.
//!
//! # The steering, in one sentence
//!
//! On each enrolled pod's host-side interface, exempt that pod's datagrams to a
//! materialized Service `(ClusterIP, port)` from conntrack, mark them, and route
//! marked datagrams to a `local` table — so the datagram is delivered to the
//! waypoint's own socket **with its original destination still in the IP
//! header**, before kube-proxy can DNAT it.
//!
//! See `crate::capture::node_waypoint_udp_steer_setup_script` for the exact rule
//! shape and why each element is required. The properties that matter here:
//!
//! * **Evidence is preserved, not synthesized.** Nothing is rewritten, so the
//!   source address is still the pod's, the ingress interface is still the pod's
//!   veth, and `IP_PKTINFO`/`IPV6_PKTINFO` reports the ClusterIP as the local
//!   address. That is precisely the evidence
//!   [`crate::proxy::node_waypoint_udp_identity`] already attributes from, and
//!   the reply source the UDP session pins.
//! * **Service identity is part of the match.** Rules are scoped
//!   `-d <ClusterIP> --dport <port>`, never by port alone: a workload's datagram
//!   to an unrelated off-cluster host that happens to share a port number is not
//!   steered. Compatible same-port UDP Services share one listener and are
//!   demultiplexed by this exact ClusterIP destination; ambiguous exact-address
//!   claimants and incompatible DTLS/mixed frontend postures are refused.
//! * **No recursion.** The match is `-i <pod veth>` in `PREROUTING`. The
//!   waypoint's own relay dials and replies are locally generated and traverse
//!   `OUTPUT`, which is never hooked, so they are structurally incapable of
//!   being steered back into the waypoint.
//! * **No plaintext lane.** When steering is absent (never published, refused,
//!   or successfully torn down) the datagram takes the pre-existing path and is
//!   dropped by the pod-veth guard. Losing steering loses the service, it does
//!   not open an unauthorized one.
//! * **The direct-pod guard is untouched.** No rule here admits anything to a
//!   pod; steering only diverts traffic to a local socket.
//!
//! # Ownership and lifecycle
//!
//! Mesh config preparation may *derive* the desired destination set and carry
//! it as candidate metadata. It must not publish the live datapath: preparation
//! is not commit, and read-only callers reach the same materializer. The
//! serving [`NodeWaypointUdpSteering`] instance owns the bound destination set
//! and is updated only from the accepted serving generation, and only for
//! destinations whose UDP/DTLS listeners are actually bound
//! (`StreamListenerManager`). The interface set is the EXACT set of interfaces
//! the source-attribution index successfully published this pass
//! (`NodeWaypointUdpSourceIndex::publish` → `PublishedSourceGeneration::ifaces`),
//! not the planner's pre-publication wish list: publication is where a
//! contested interface refuses every claimant, a malformed or UID-mismatched
//! binding is dropped, and an over-bound input collapses to an empty
//! generation. Steering an interface publication refused would divert its
//! datagrams to a listener that could only deny them.
//!
//! The same serving generation also drives the **reply-source authorization**
//! this steering makes necessary (see
//! [`crate::proxy::node_waypoint_udp_reply_source`]). Steering preserves the
//! ClusterIP as the datagram's local address, so the listener's reply is pinned
//! to it — and a ClusterIP is not a configured node IP, so `tc_inbound` would
//! drop that reply without an exact `(address, port)` authorization. The two
//! halves move together inside one critical section: on apply the sources are
//! authorized BEFORE the rules exist, and on teardown they are withdrawn only
//! AFTER the rules are proven gone. A failure prevents a replacement or
//! withdrawal from settling; a teardown error leaves predecessor state
//! explicitly unproven and retryable.
//!
//! # Publishing is not applying: the acknowledgement gate
//!
//! The proxy does not write BPF maps — the node-agent does, on its own poll. So
//! "the claim is published" is not evidence that "the map holds it", and the
//! interval between the two is precisely the steered-but-unanswerable window
//! that the Service-path black hole is made of. A node-agent that is wedged,
//! restarting, missing a map, or refusing the set would leave a new generation's
//! rules installed indefinitely against a guard that drops every reply.
//!
//! So a reconcile installs setup rules only after the node-agent has
//! acknowledged THAT EXACT generation
//! ([`crate::proxy::node_waypoint_udp_reply_source::ReplySourceGeneration`]).
//! Until then the outcome is [`SteerReconcileOutcome::PendingAck`], the rules
//! stay (or are put back) absent, and the pass returns immediately — the retry
//! is the next ordinary reconcile tick, never a sleep, a spin, or a blocked
//! runtime worker. The teardown side is symmetric: a withdrawal is not
//! [`SteerReconcileOutcome::Removed`] until the node-agent acknowledges the
//! INACTIVE generation, and until then every pass re-publishes and re-checks. An
//! acknowledgement naming a different owner (a crashed predecessor) or a
//! different sequence (an earlier set, or a differently ordered rendering of
//! one) satisfies nothing.
//!
//! [`NodeWaypointUdpSteering::reconcile`] applies the pair only when it CHANGED
//! and ALWAYS runs one strict exact-name teardown before this process trusts the
//! datapath (so objects a crashed prior process left installed are reaped on the
//! first pass rather than surviving until this process exits). Losing the last
//! serving listener, shutdown, and every owner exit invoke the same inactive
//! teardown, including task abort and panic. An empty destination set while a
//! listener is still bound publishes ACTIVE instead of withdrawing. Only
//! success records proof, while an error remains unproven and retryable.
//!
//! Destination and interface updates share one cold-path mutex: each event
//! mutates only its component, then the backend reconcile derives from the
//! latest combined desired state inside that same critical section. A stale
//! cloned plan must never install after a newer event has already published.
//! The datagram hot path does not take this lock.
//!
//! Linux-only. Everywhere else [`NodeWaypointUdpSteering`] is inert and
//! `steering_supported()` is false, which is also why the mesh startup path
//! keeps its fail-closed UDP/DTLS suppression off Linux.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use tracing::{debug, info, warn};

use crate::capture::NodeWaypointUdpSteerDestination;
use crate::proxy::node_waypoint_udp_reply_source::{
    NodeWaypointUdpReplySourcePublisher, ReplySourceGeneration,
};

/// Whether the steering datapath can exist on this platform at all.
pub const fn steering_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Upper bound on the failed-script diagnostic carried into a `warn!`.
const STEER_ERROR_DETAIL_MAX_CHARS: usize = 512;

/// Withhold every interface name this generation named from a tool diagnostic.
///
/// `iptables` can echo the `-i <iface>` argument it rejected, and an enrolled
/// pod's host-side interface name is discovered per pod rather than being ours
/// to disclose. The failure CLASS is what an operator needs; the device name is
/// not. The placeholder cannot contain an interface name (the shared
/// `validate_host_capture_interfaces` charset admits no `<` or `>`), so this is
/// a single non-amplifying pass, and the result is re-bounded afterwards.
fn redact_steer_error_detail(detail: &str, ifaces: &[String]) -> String {
    let mut out = detail.to_string();
    for iface in ifaces {
        if !iface.is_empty() {
            out = out.replace(iface.as_str(), "<iface>");
        }
    }
    out.chars().take(STEER_ERROR_DETAIL_MAX_CHARS).collect()
}

/// Effects the steering reconcile performs, behind a trait so the reconcile
/// logic is testable without root, `iptables`, or a live node.
pub trait NodeWaypointUdpSteerBackend: Send + Sync + 'static {
    /// Run one rendered `sh -c` script in the process's OWN (host) network
    /// namespace.
    fn run_script(&self, script: &str) -> Result<(), String>;
}

/// Production backend: runs the rendered script in the process's own namespace.
/// No `setns` anywhere — a NodeWaypoint proxy is `hostNetwork: true`, which is
/// exactly why the interface is a valid direction discriminator.
pub struct HostNamespaceSteerBackend;

impl NodeWaypointUdpSteerBackend for HostNamespaceSteerBackend {
    #[cfg(target_os = "linux")]
    fn run_script(&self, script: &str) -> Result<(), String> {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .map_err(|error| format!("failed to run the steering script: {error}"))?;
        if output.status.success() {
            // A successful script installed every published family completely:
            // the setup script is `set -e` and each family opens with its own
            // `command -v` guard, so there is no "succeeded but skipped a
            // family" outcome whose stderr would need reporting. Anything the
            // tools wrote to stderr on success is therefore non-actionable
            // noise and is deliberately not surfaced.
            return Ok(());
        }
        // stderr can only contain iptables/ip diagnostics about Ferrum-owned
        // objects; no secret, peer, or registry value reaches this script.
        // Bounded so a pathological tool cannot turn one failed reconcile into
        // an unbounded log record.
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        let truncated: String = detail.chars().take(STEER_ERROR_DETAIL_MAX_CHARS).collect();
        let ellipsis = if truncated.chars().count() < detail.chars().count() {
            "…"
        } else {
            ""
        };
        Err(format!(
            "steering script exited with {}: {truncated}{ellipsis}",
            output.status
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn run_script(&self, _script: &str) -> Result<(), String> {
        Err("NodeWaypoint UDP Service steering is Linux-only".to_string())
    }
}

/// What one reconcile pass decided, for diagnostics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteerReconcileOutcome {
    /// The desired state equals the applied state AND the node-agent has
    /// acknowledged exactly that generation; nothing was run.
    Unchanged,
    /// Steering rules were installed or rebuilt, against an acknowledged
    /// reply-source generation.
    Applied,
    /// The datapath was torn down and the INACTIVE generation is acknowledged, so
    /// the withdrawal is PROVEN, not merely requested.
    Removed,
    /// The desired generation is published but the node-agent has not
    /// acknowledged it (or has acknowledged a different one). No steering rule
    /// is installed and any previously installed one has been removed, so the
    /// Service path stays on its pre-existing fail-closed posture. The next
    /// reconcile retries; nothing waits.
    PendingAck,
    /// The plan could not be rendered, published, applied, or strictly torn
    /// down. No replacement/withdrawal is settled; a teardown failure may
    /// leave predecessor rules in place and is retried without claiming proof.
    Failed,
}

/// The applied generation, so a reconcile that changes nothing runs no command.
#[derive(Debug, Default, PartialEq, Eq)]
struct AppliedSteering {
    ifaces: Vec<String>,
    destinations: Vec<NodeWaypointUdpSteerDestination>,
}

/// What this PROCESS knows about the node's steering objects.
#[derive(Debug, Default)]
struct SteeringState {
    /// Whether this process has completed one successful exact-name teardown,
    /// i.e. whether "nothing is applied" is a PROVEN statement about the node
    /// rather than merely about this process's memory.
    ///
    /// It starts `false` on purpose. Ferrum-owned chains, rules, and routes
    /// survive the process that installed them, so a crashed or `SIGKILL`ed
    /// predecessor leaves destinations marked and locally delivered to a socket
    /// that no longer exists. Without this flag the first reconcile of an empty
    /// plan short-circuits on `applied == None` and those objects stay installed
    /// for the whole life of the new process.
    reaped: bool,
    /// The generation this process installed, or `None` when nothing is (or is
    /// known to be) installed.
    applied: Option<AppliedSteering>,
    /// Latest bound destination set. Source of truth for reconcile; the
    /// lock-free [`NodeWaypointUdpSteering::bound_destinations`] snapshot is
    /// only a diagnostic copy written while this mutex is held.
    desired_destinations: Vec<NodeWaypointUdpSteerDestination>,
    /// Whether at least one owned UDP/DTLS listener is actually bound, started,
    /// and not finished. Distinct from [`Self::desired_destinations`]: a
    /// headless/VIP-less listener is serving with an empty destination set,
    /// and adding/removing ClusterIP tuples while this stays true must not
    /// withdraw the relay-cgroup sender proof.
    desired_serving: bool,
    /// Latest published attribution interfaces. Paired with
    /// [`Self::desired_destinations`] inside the same critical section.
    desired_ifaces: Vec<String>,
    /// The reply-source set this process has PUBLISHED on the channel, with the
    /// generation naming it. `Some((_, vec![]))` is an empty source set — ACTIVE
    /// when a bound listener is still serving (headless/VIP-less), INACTIVE when
    /// it is a true withdrawal. `None` means the channel's content is unknown,
    /// so the next pass must republish rather than settle.
    ///
    /// Kept separate from [`Self::applied`] because the two datapath halves
    /// fail independently: a successful `iptables` apply whose authorization
    /// write failed would steer datagrams at a listener whose replies the
    /// pod-veth guard drops, and a successful withdrawal of the rules whose
    /// authorization withdrawal failed would leave a ClusterIP admissible with
    /// no serving socket. Neither may be recorded as settled by the other.
    published_reply_sources: Option<(ReplySourceGeneration, Vec<NodeWaypointUdpSteerDestination>)>,
    /// The generation the node-agent was last OBSERVED to acknowledge, i.e. to
    /// have made complete in BOTH BPF map families and opened through their
    /// shared gate. Publishing is a request; only this is evidence, and only
    /// when it equals the generation in
    /// [`Self::published_reply_sources`].
    acknowledged_reply_sources: Option<ReplySourceGeneration>,
}

/// Reconciles the NodeWaypoint Service-steering datapath.
pub struct NodeWaypointUdpSteering {
    backend: Arc<dyn NodeWaypointUdpSteerBackend>,
    /// Publishes the exact reply-source authorizations for the serving
    /// generation (issue #3286). `None` where the datapath cannot exist (no
    /// registry directory, non-Linux), in which case authorization is
    /// unnecessary because no listener is materialized either.
    reply_sources: Option<Arc<dyn NodeWaypointUdpReplySourcePublisher>>,
    /// Guarded by a plain `Mutex` because it is touched once per registry poll
    /// (seconds), never on a datagram path. Desired destinations, desired
    /// interfaces, and the applied generation all live here so a stale cloned
    /// plan cannot install after a newer event has already published.
    state: Mutex<SteeringState>,
    /// Lock-free diagnostic snapshot of the desired destination set. Written
    /// only while `state` is held; never the reconcile source of truth.
    bound_destinations: ArcSwap<Vec<NodeWaypointUdpSteerDestination>>,
    /// Lock-free diagnostic snapshot of [`SteeringState::desired_serving`].
    serving: AtomicBool,
}

impl NodeWaypointUdpSteering {
    pub fn new(backend: Arc<dyn NodeWaypointUdpSteerBackend>) -> Self {
        Self {
            backend,
            reply_sources: None,
            state: Mutex::new(SteeringState::default()),
            bound_destinations: ArcSwap::from_pointee(Vec::new()),
            serving: AtomicBool::new(false),
        }
    }

    /// Attach the reply-source authorization publisher.
    ///
    /// Consumed at construction rather than installed later on purpose: the
    /// publisher and the rule backend must move through every reconcile as one
    /// unit, so there is no window in which rules are installed for a
    /// generation whose reply sources were never authorized.
    pub fn with_reply_source_publisher(
        mut self,
        publisher: Arc<dyn NodeWaypointUdpReplySourcePublisher>,
    ) -> Self {
        self.reply_sources = Some(publisher);
        self
    }

    /// Destinations currently owned by this serving instance.
    pub fn bound_destinations(&self) -> Vec<NodeWaypointUdpSteerDestination> {
        self.bound_destinations.load_full().as_ref().clone()
    }

    /// Whether this serving instance currently has at least one actually bound
    /// NodeWaypoint UDP/DTLS listener. Distinct from
    /// [`Self::bound_destinations`]: a headless listener is serving with none.
    pub fn serving(&self) -> bool {
        self.serving.load(Ordering::Acquire)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, SteeringState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // A poisoned lock is treated as "nothing is KNOWN about the
                // node": forget the applied generation AND drop the reaped
                // proof, so the pass below runs a teardown rather than
                // short-circuiting on this process's own stale memory.
                let mut guard = poisoned.into_inner();
                *guard = SteeringState::default();
                self.bound_destinations.store(Arc::new(Vec::new()));
                self.serving.store(false, Ordering::Release);
                guard
            }
        }
    }

    fn publish_desired_snapshot(&self, state: &SteeringState) {
        self.bound_destinations
            .store(Arc::new(state.desired_destinations.clone()));
        self.serving.store(state.desired_serving, Ordering::Release);
    }

    /// Replace the bound destination set and serving bit, then apply immediately
    /// against the last published attribution interfaces (or `ifaces` when
    /// supplied).
    ///
    /// Whole-plan replacement: a generation is applied or it is not. `serving`
    /// is whether at least one owned UDP/DTLS listener is actually bound,
    /// started, and not finished — not whether ClusterIP destinations exist.
    /// `serving == false` requests strict teardown and settles only after the
    /// INACTIVE generation is proven. `serving == true` with an empty
    /// destination set (or empty attribution interfaces) keeps the relay
    /// sender proof live and leaves steering rules absent.
    ///
    /// Callers must pass only destinations whose listeners are actually bound
    /// on the accepted serving generation, and must pass `serving` from that
    /// same bound inventory.
    ///
    /// The destination (and optional interface) update and the backend
    /// reconcile share one critical section so a concurrent later event cannot
    /// be overwritten by this call's stale clone.
    pub fn set_bound_destinations(
        &self,
        destinations: Vec<NodeWaypointUdpSteerDestination>,
        ifaces: Option<&[String]>,
        serving: bool,
    ) -> SteerReconcileOutcome {
        let mut destinations = destinations;
        destinations.sort_unstable();
        destinations.dedup();
        if !serving {
            destinations.clear();
        }
        let mut state = self.lock_state();
        state.desired_destinations = destinations;
        state.desired_serving = serving;
        if let Some(ifaces) = ifaces {
            state.desired_ifaces = ifaces.to_vec();
        }
        self.publish_desired_snapshot(&state);
        self.reconcile_locked(&mut state)
    }

    /// Drop every destination served on `port` and apply immediately.
    ///
    /// External tests use this seam to exercise serialized per-port retraction.
    /// Production listener exits instead use the generation-fenced
    /// `retract_owned_node_waypoint_udp_listener` path in `stream_listener`.
    ///
    /// Filters the latest desired set while holding the same mutex the full
    /// plan update uses, so a concurrent `set_bound_destinations` cannot be
    /// lost to a stale load/filter/store.
    pub fn retract_port(&self, port: u16) -> SteerReconcileOutcome {
        let mut state = self.lock_state();
        state
            .desired_destinations
            .retain(|destination| destination.port != port);
        self.publish_desired_snapshot(&state);
        self.reconcile_locked(&mut state)
    }

    /// Reconcile the datapath against `ifaces` — the interfaces the source
    /// attribution index actually PUBLISHED this pass, never the planner's
    /// pre-publication list — and this instance's bound destination set.
    ///
    /// A poisoned lock is treated as "nothing known about the node": both the
    /// applied generation and the teardown proof are dropped, so the pass runs
    /// a teardown rather than trusting stale in-process memory. Guessing that
    /// the previous generation is still installed is the one answer that could
    /// leave marked-but-unserved destinations behind.
    pub fn reconcile(&self, ifaces: &[String]) -> SteerReconcileOutcome {
        let mut state = self.lock_state();
        state.desired_ifaces = ifaces.to_vec();
        self.reconcile_locked(&mut state)
    }

    /// [`Self::reconcile`] against an explicit destination set. Tests drive this
    /// form so they do not depend on another task mutating this instance.
    pub fn reconcile_with(
        &self,
        ifaces: &[String],
        destinations: &[NodeWaypointUdpSteerDestination],
        serving: bool,
    ) -> SteerReconcileOutcome {
        let mut destinations = destinations.to_vec();
        destinations.sort_unstable();
        destinations.dedup();
        if !serving {
            destinations.clear();
        }
        let mut state = self.lock_state();
        state.desired_ifaces = ifaces.to_vec();
        state.desired_destinations = destinations;
        state.desired_serving = serving;
        self.publish_desired_snapshot(&state);
        self.reconcile_locked(&mut state)
    }

    /// Apply the latest combined desired state. Must be called while `state` is
    /// held so the backend never installs a plan that a later event has already
    /// superseded.
    fn reconcile_locked(&self, state: &mut SteeringState) -> SteerReconcileOutcome {
        let desired = AppliedSteering {
            ifaces: state.desired_ifaces.clone(),
            destinations: state.desired_destinations.clone(),
        };

        // Re-observe the node-agent's proof on EVERY pass, BEFORE the settled
        // short-circuits. It is one bounded read of a small file and never a
        // command, so a quiet poll stays silent — but an applied generation
        // whose acknowledgement has since been retracted (a later node-agent
        // refusal, a lost map, an agent restart) must revert its steering
        // rather than stay installed on this process's stale belief.
        if let Err(error) = self.observe_acknowledgement(state) {
            warn!(
                %error,
                "NodeWaypoint UDP/DTLS reply-source acknowledgement could not be read; the \
                 Service path stays unsteered rather than steering at a generation whose \
                 authorization cannot be proven"
            );
            self.tear_down(state);
            return SteerReconcileOutcome::Failed;
        }

        if !state.desired_serving {
            // Nothing is serving. Run the exact-name teardown unless this
            // process has already PROVEN the node holds no Ferrum-owned
            // steering objects AND the node-agent has acknowledged the
            // INACTIVE generation — which is exactly what makes the first
            // pass reap a crashed predecessor's rules and authorizations
            // while every later quiet poll runs no command at all.
            if state.reaped && state.applied.is_none() && Self::generation_proven(state, &[], false)
            {
                return SteerReconcileOutcome::Unchanged;
            }
            return self.converge_inactive(state);
        }

        if desired.ifaces.is_empty() || desired.destinations.is_empty() {
            // A bound listener is serving, but there is nothing to steer
            // (headless/VIP-less, or no attribution interfaces). Keep the
            // relay sender proof live; leave steering rules absent.
            if state.reaped
                && state.applied.is_none()
                && Self::generation_proven(state, &desired.destinations, true)
            {
                return SteerReconcileOutcome::Unchanged;
            }
            return self.converge_serving_unsteered(state);
        }

        if state.reaped
            && state.applied.as_ref() == Some(&desired)
            && Self::generation_proven(state, &desired.destinations, true)
        {
            return SteerReconcileOutcome::Unchanged;
        }

        let script = match crate::capture::node_waypoint_udp_steer_setup_script(
            &desired.ifaces,
            &desired.destinations,
        ) {
            Ok(Some(script)) => script,
            Ok(None) => return self.converge_serving_unsteered(state),
            Err(error) => {
                warn!(
                    interfaces = desired.ifaces.len(),
                    destinations = desired.destinations.len(),
                    error = %error,
                    "NodeWaypoint UDP Service steering plan refused; the Service path stays \
                     unsteered (and therefore fails closed at the pod-veth guard) rather than \
                     installing a partial ruleset"
                );
                self.tear_down(state);
                return SteerReconcileOutcome::Failed;
            }
        };

        // Remove whatever rules may already be installed before authorizing the
        // new generation: the previous generation this process applied, or — on
        // the first pass — a crashed predecessor's objects, which may name an
        // address family or a destination this generation does not. This is
        // also what REVERTS a previously applied generation whose
        // acknowledgement has since gone stale or missing: falling through to
        // the pending arm below with its rules still installed would be the
        // steered-but-unanswerable state itself.
        if (!state.reaped || state.applied.is_some()) && !self.remove_rules(state) {
            // Do not publish a replacement generation while the outgoing
            // rules are still unproven. The next reconcile retries the
            // exact-name teardown first.
            return SteerReconcileOutcome::Failed;
        }

        // Authorize the exact reply sources BEFORE installing the rules that
        // steer datagrams at them. Ordered this way there is never a window in
        // which a workload's datagram reaches the listener but the listener's
        // source-pinned reply is dropped by this node's own pod-veth guard; the
        // reverse order would make every new generation start with one.
        let generation = match self.publish_reply_sources(state, &desired.destinations, true) {
            Ok(generation) => generation,
            Err(error) => {
                warn!(
                    destinations = desired.destinations.len(),
                    %error,
                    "NodeWaypoint UDP/DTLS reply sources could not be authorized; leaving the \
                     Service path unsteered (and therefore fail-closed at the pod-veth guard) \
                     rather than steering datagrams at a listener whose replies would be dropped"
                );
                self.tear_down(state);
                return SteerReconcileOutcome::Failed;
            }
        };

        // Publishing is a request, not proof. The node-agent owns every BPF map
        // write, so until it has acknowledged THIS generation the shared gate
        // may be closed or map storage may be stale/partial — and steering into
        // that is the Service-path black hole. No rule is installed until the
        // acknowledgement is exact.
        match self.observe_acknowledgement(state) {
            Ok(Some(acknowledged)) if acknowledged == generation => {}
            Ok(_) => {
                debug!(
                    destinations = desired.destinations.len(),
                    "NodeWaypoint UDP/DTLS reply-source generation published but not yet \
                     acknowledged by the node-agent; leaving the Service path unsteered and \
                     retrying on the next reconcile"
                );
                return SteerReconcileOutcome::PendingAck;
            }
            Err(error) => {
                warn!(
                    %error,
                    "NodeWaypoint UDP/DTLS reply-source acknowledgement could not be read; the \
                     Service path stays unsteered rather than steering at a generation whose \
                     authorization cannot be proven"
                );
                self.tear_down(state);
                return SteerReconcileOutcome::Failed;
            }
        }

        match self.backend.run_script(&script) {
            Ok(()) => {
                info!(
                    interfaces = desired.ifaces.len(),
                    destinations = desired.destinations.len(),
                    "NodeWaypoint UDP/DTLS Service steering installed; enrolled workloads reach \
                     their Service ClusterIP through the materialized listener with the original \
                     destination, source address, and ingress interface intact"
                );
                // `reaped` is deliberately NOT set here — only a SUCCESSFUL
                // teardown sets it. If the reap above failed we have proven
                // nothing about a predecessor's objects, so the next reconcile
                // must re-enter and retry it rather than settling on Unchanged.
                state.applied = Some(desired);
                SteerReconcileOutcome::Applied
            }
            Err(error) => {
                warn!(
                    error = %redact_steer_error_detail(&error, &desired.ifaces),
                    "NodeWaypoint UDP Service steering could not be installed; removing every \
                     Ferrum-owned steering object so no destination is marked without a serving \
                     socket, and retrying the whole plan on the next reconcile"
                );
                self.tear_down(state);
                SteerReconcileOutcome::Failed
            }
        }
    }

    /// Whether the node-agent has proven that EXACTLY `desired` is live in both
    /// BPF map families right now.
    ///
    /// Two independent conditions, and both are required: the set this process
    /// published must be the set it currently wants, and the acknowledgement
    /// must name that publication's own generation. An acknowledgement from a
    /// crashed predecessor carries a different owner, and one from an earlier
    /// set — or from a differently ordered rendering of a set, which the
    /// manifest parser refuses outright — carries a different sequence. Neither
    /// can be mistaken for proof about this generation.
    fn generation_proven(
        state: &SteeringState,
        desired: &[NodeWaypointUdpSteerDestination],
        active: bool,
    ) -> bool {
        match (
            state.published_reply_sources.as_ref(),
            state.acknowledged_reply_sources.as_ref(),
        ) {
            (Some((generation, published)), Some(acknowledged)) => {
                published.as_slice() == desired
                    && generation.active() == active
                    && acknowledged == generation
            }
            _ => false,
        }
    }

    /// Converge on "nothing steered, nothing authorized".
    ///
    /// Rules first, then the INACTIVE generation, then the proof: a withdrawal
    /// is only [`SteerReconcileOutcome::Removed`] once the node-agent has
    /// acknowledged the inactive generation. Until then the pass reports
    /// [`SteerReconcileOutcome::PendingAck`] and the next reconcile re-checks,
    /// so one lost acknowledgement cannot leave a revoked ClusterIP recorded as
    /// withdrawn.
    fn converge_inactive(&self, state: &mut SteeringState) -> SteerReconcileOutcome {
        let rules_removed = if !state.reaped || state.applied.is_some() {
            self.remove_rules(state)
        } else {
            true
        };

        // Withdraw the authorizations only AFTER the rules are PROVEN gone, so
        // nothing is steered at an address whose authorization has already
        // disappeared. A failed teardown retains the outgoing generation and
        // retries rules-first on the next pass.
        if !rules_removed {
            return SteerReconcileOutcome::Failed;
        }

        match self.publish_reply_sources(state, &[], false) {
            Ok(generation) => match self.observe_acknowledgement(state) {
                Ok(Some(acknowledged)) if acknowledged == generation => {
                    SteerReconcileOutcome::Removed
                }
                Ok(_) => SteerReconcileOutcome::PendingAck,
                Err(error) => {
                    warn!(
                        %error,
                        "NodeWaypoint UDP/DTLS reply-source withdrawal could not be proven; the \
                         acknowledgement is unreadable, so the withdrawal stays unproven and is \
                         retried on the next reconcile"
                    );
                    SteerReconcileOutcome::Failed
                }
            },
            Err(error) => {
                warn!(
                    %error,
                    "NodeWaypoint UDP/DTLS reply-source withdrawal reported an error; the \
                     authorizations stay recorded as unproven and are retried on the next reconcile"
                );
                SteerReconcileOutcome::Failed
            }
        }
    }

    /// A bound listener is serving but steering rules must stay absent (no
    /// ClusterIP destinations, or no attribution interfaces). Publish ACTIVE
    /// — including the active-empty headless shape — so the relay-cgroup
    /// sender proof stays live for the direct-node lane.
    fn converge_serving_unsteered(&self, state: &mut SteeringState) -> SteerReconcileOutcome {
        let rules_removed = if !state.reaped || state.applied.is_some() {
            self.remove_rules(state)
        } else {
            true
        };
        if !rules_removed {
            return SteerReconcileOutcome::Failed;
        }

        let sources = state.desired_destinations.clone();
        match self.publish_reply_sources(state, &sources, true) {
            Ok(generation) => match self.observe_acknowledgement(state) {
                Ok(Some(acknowledged)) if acknowledged == generation => {
                    SteerReconcileOutcome::Applied
                }
                Ok(_) => SteerReconcileOutcome::PendingAck,
                Err(error) => {
                    warn!(
                        %error,
                        "NodeWaypoint UDP/DTLS active-empty reply-source generation could not be \
                         proven; the sender proof stays unproven and is retried on the next \
                         reconcile rather than withdrawing a bound listener"
                    );
                    SteerReconcileOutcome::Failed
                }
            },
            Err(error) => {
                warn!(
                    %error,
                    "NodeWaypoint UDP/DTLS active generation could not be published; a bound \
                     listener stays unproven rather than being recorded as withdrawn"
                );
                SteerReconcileOutcome::Failed
            }
        }
    }

    /// Remove every Ferrum-owned steering object and forget the applied
    /// generation, leaving the published authorizations alone. The teardown
    /// script proves exact absence, so genuinely missing objects are an
    /// idempotent success while inspection and deletion failures remain errors.
    ///
    /// `reaped` is set ONLY when the script succeeded: a failed teardown has not
    /// proven anything about the node, so the next reconcile must try again
    /// rather than treat "nothing applied" as settled. Returns whether the node
    /// is now proven free of Ferrum-owned steering objects.
    fn remove_rules(&self, state: &mut SteeringState) -> bool {
        state.applied = None;
        // A prior successful reap does not prove this later teardown succeeded.
        // Clear the proof before the command so a failure cannot short-circuit
        // a retry or allow a replacement generation to install.
        state.reaped = false;
        if let Err(error) = self
            .backend
            .run_script(&crate::capture::node_waypoint_udp_steer_teardown_script())
        {
            warn!(
                error = %error,
                "NodeWaypoint UDP Service steering teardown reported an error; it will be retried \
                 on the next reconcile"
            );
            return false;
        }
        state.reaped = true;
        debug!("NodeWaypoint UDP Service steering datapath removed");
        true
    }

    /// Rules first, then the INACTIVE generation. The recovery path for every hard
    /// failure, and the shutdown path.
    fn tear_down(&self, state: &mut SteeringState) {
        if !self.remove_rules(state) {
            return;
        }
        if let Err(error) = self.publish_reply_sources(state, &[], false) {
            warn!(
                %error,
                "NodeWaypoint UDP/DTLS reply-source withdrawal reported an error; the \
                 authorizations stay recorded as unproven and are retried on the next reconcile"
            );
            return;
        }
        // Refresh the observed acknowledgement so the next pass can tell a
        // proven withdrawal from a pending one without a spurious republish.
        let _ = self.observe_acknowledgement(state);
    }

    /// Publish the reply-source set, recording the generation so a later pass
    /// can tell "published" from "unknown" — and, with
    /// [`Self::observe_acknowledgement`], "published" from "applied".
    ///
    /// A publisher-less instance (no registry directory, or a platform with no
    /// steering datapath) records the set as published AND acknowledged: there
    /// is no node-agent to ask and no listener to authorize, so the pair is
    /// trivially coherent and the quiet-poll `Unchanged` short-circuit stays
    /// intact without asserting anything about a node.
    fn publish_reply_sources(
        &self,
        state: &mut SteeringState,
        sources: &[NodeWaypointUdpSteerDestination],
        active: bool,
    ) -> Result<ReplySourceGeneration, String> {
        let Some(publisher) = self.reply_sources.as_ref() else {
            let generation = ReplySourceGeneration::inert_with_active(active);
            state.published_reply_sources = Some((generation.clone(), sources.to_vec()));
            state.acknowledged_reply_sources = Some(generation.clone());
            return Ok(generation);
        };
        match publisher.publish(sources, active) {
            Ok(generation) => {
                state.published_reply_sources = Some((generation.clone(), sources.to_vec()));
                Ok(generation)
            }
            Err(error) => {
                // What the channel now holds is unknown. Fail closed by
                // forgetting BOTH halves, so the next pass republishes from
                // scratch and cannot read a stale acknowledgement as proof.
                state.published_reply_sources = None;
                state.acknowledged_reply_sources = None;
                Err(error)
            }
        }
    }

    /// Refresh the observed acknowledgement. Never blocks and never waits: it is
    /// one bounded read of a small file, and a pending answer is retried by the
    /// next ordinary reconcile tick.
    fn observe_acknowledgement(
        &self,
        state: &mut SteeringState,
    ) -> Result<Option<ReplySourceGeneration>, String> {
        let Some(publisher) = self.reply_sources.as_ref() else {
            // Nothing to apply, so the published generation is its own proof.
            state.acknowledged_reply_sources = state
                .published_reply_sources
                .as_ref()
                .map(|(generation, _)| generation.clone());
            return Ok(state.acknowledged_reply_sources.clone());
        };
        match publisher.acknowledged() {
            Ok(acknowledged) => {
                state.acknowledged_reply_sources = acknowledged.clone();
                Ok(acknowledged)
            }
            Err(error) => {
                state.acknowledged_reply_sources = None;
                Err(error)
            }
        }
    }

    /// Unconditional teardown, for shutdown and for the retraction guard.
    ///
    /// Always runs the script, even when this process installed nothing: a
    /// previous process generation's objects survive this process, and they are
    /// exactly the marked-without-a-serving-socket state that must not outlive
    /// it. Also forgets the bound destination set so a later reconcile cannot
    /// reinstall destinations whose listeners are already gone.
    pub fn shutdown(&self) {
        let mut state = self.lock_state();
        state.desired_destinations.clear();
        state.desired_serving = false;
        self.publish_desired_snapshot(&state);
        self.tear_down(&mut state);
    }
}

impl Drop for NodeWaypointUdpSteering {
    fn drop(&mut self) {
        // Task abort and panic both drop the owner, so this is the last line of
        // defence against leaving destinations steered at a socket that no
        // longer exists.
        self.shutdown();
    }
}

// Contract coverage for this module lives in
// `tests/unit/gateway_core/node_waypoint_udp_steering_tests.rs` (first-pass
// reaping, later-empty idempotence, command order, failure cleanup, and
// serialized latest-state B/C and retract-vs-full-plan ordering).

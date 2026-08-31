//! Node-local enrolled-pod destination inventory for the authenticated inbound
//! HBONE relay guard (issue #4249).
//!
//! # The gap this closes
//!
//! Issue #4150 bounded the inbound CONNECT relay to the destinations a proxy
//! actually terminates for. For `Sidecar` / `Ambient` the slice-derived half of
//! that set was the workload record(s) carrying this proxy's own SPIFFE
//! identity, later narrowed to the shared `slice::workload_is_local` predicate
//! (SPIFFE + cluster + configured labels).
//!
//! None of those three facts is node-local. Two replicas of ONE Deployment
//! share a service-account SPIFFE id, a cluster, and their pod-template labels
//! while running on different nodes, so identity/label filtering admits a
//! sibling this terminator cannot legitimately terminate for: relaying to it
//! dials that pod in plaintext from this node, skipping the destination's own
//! `AuthorizationPolicy` set and arriving as a trusted-looking unauthenticated
//! source under a PERMISSIVE posture.
//!
//! The authoritative "which pods does this node terminate for" answer already
//! exists — it is the node-agent's per-pod registry directory, the same
//! enrollment lifecycle `crate::proxy::netns_capture` and the Ambient UDP
//! producer consume. This module turns it into a lock-free index the guard can
//! read on the CONNECT path.
//!
//! # Why an index and not a slice-apply-time snapshot
//!
//! Two shapes were rejected in issue #4249 and must not be reintroduced:
//!
//! * A filesystem scan per CONNECT (what
//!   `hbone_proxy::registered_pod_target_for_udp_destination` does on the DIAL
//!   path) is not acceptable on the guard's hot path.
//! * Folding the registry into `MeshConfig` once per mesh apply goes STALE
//!   against pod churn, which is strictly worse than the identity bound: a
//!   withdrawn pod would stay admitted until the next slice arrives.
//!
//! So the registry is polled on the existing 2s node-agent reconcile cadence
//! and republished wholesale into an [`arc_swap::ArcSwap`]; the guard performs
//! one `load()` and one hash lookup, with no allocation, no lock, and no I/O.
//! A pod the node-agent withdraws leaves the admitted set within one poll
//! interval.
//!
//! # Fail closed
//!
//! * An index that has never published admits NOTHING. Startup, a missing
//!   registry directory, and a retracted (shutdown) index are all
//!   indistinguishable from "this node enrolls no pods", which is the correct
//!   refusal, not a reason to fall back to the identity view.
//! * The poller consumes a **strict, bounded, all-or-nothing** registry
//!   snapshot ([`PodCaptureSource::list_complete_targets`]), never the
//!   best-effort [`PodCaptureSource::list_targets`] scan. Any missing
//!   directory, enumeration/read/metadata/ownership/parse error, unsafe name,
//!   symlink, oversized or non-regular file, too many entries, present-but-
//!   malformed optional field, duplicate recognized key, or unknown content
//!   retracts the index immediately: last-good is not retained and a partial
//!   snapshot is never published. A later complete snapshot may republish.
//!   The one enumerated leaf that is SKIPPED instead is one that has already
//!   been unlinked when the reader opens it — the ordinary pod-teardown race
//!   against every scan. An absent entry only ever REMOVES an admission, so
//!   skipping it is exactly as fail-closed as retracting, and retracting there
//!   would instead take every authenticated inbound relay on this node out for
//!   a poll interval on each pod deletion.
//! * An address claimed by two DIFFERENT pod UIDs is ambiguous and refused for
//!   BOTH claimants, mirroring the contested-interface rule
//!   `plan_host_udp_bindings` already applies to ingress interfaces.
//! * Independently, mesh apply marks an inventory IP contested when several
//!   raw workload records declare it without one identical non-empty pod UID.
//!   While this index is authoritative the guard refuses every such claimant,
//!   so a UID-less same-identity record cannot borrow an enrolled pod's address
//!   and widen its ports. A lone UID-less record remains admissible.
//! * A registry entry with an unsafe/absent pod UID, or with no published pod
//!   address, contributes nothing.
//! * Identity-based fallback exists ONLY when no registry source is configured
//!   at all (see [`NodeLocalEnrolledDestinationsHandle`]), never per missing
//!   entry and never per destination SHAPE. In particular a destination this
//!   terminator can only NAME is not admitted while the registry is
//!   authoritative: the guard never resolves a name, and the address the dial
//!   eventually selects for it is chosen AFTER the decision, so no evidence
//!   gathered here could still be binding at the socket.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::proxy::netns_capture::{PodCaptureSource, PodCaptureTarget};

/// One enrolled pod as the relay guard needs it: the node-agent's pod UID, the
/// workload SPIFFE identity it attested for that pod (when it published one),
/// and the pod addresses it published.
///
/// Deliberately NOT `PodCaptureTarget`: the guard needs no cgroup path and no
/// netns handle, and keeping the guard's input a plain owned record lets the
/// index be published from a test without constructing capture machinery.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnrolledPodEntry {
    /// Registry-published pod UID (`metadata.uid`), the node-agent's key.
    pub pod_uid: String,
    /// Workload SPIFFE identity the node-agent attested for this pod. `None`
    /// when the node-agent published no `spiffe_id=` line — an older agent, or
    /// a pod whose service account it could not resolve. Absent attestation is
    /// NOT a refusal: the published pod ADDRESS is itself the node-local proof
    /// this guard needs, and requiring an identity line the production
    /// publisher marks optional would refuse every legitimately enrolled pod on
    /// such a node.
    pub identity: Option<String>,
    /// Pod addresses the node-agent published, canonicalized.
    pub addresses: Vec<IpAddr>,
}

impl EnrolledPodEntry {
    /// Project a node-agent registry record into the guard's view.
    ///
    /// Returns `None` for a record that carries no usable node-local evidence:
    /// an unsafe/empty pod UID, or no published pod address at all. Both are
    /// refusals, not defaults — an entry with no address can never prove that
    /// this node terminates for any particular destination.
    pub fn from_capture_target(target: &PodCaptureTarget) -> Option<Self> {
        if pod_uid_is_unsafe(&target.pod_uid) {
            return None;
        }
        let mut addresses: Vec<IpAddr> = Vec::new();
        if let Some(ipv4) = target.source_ips.ipv4 {
            addresses.push(IpAddr::V4(ipv4).to_canonical());
        }
        if let Some(ipv6) = target.source_ips.ipv6 {
            addresses.push(IpAddr::V6(ipv6).to_canonical());
        }
        if addresses.is_empty() {
            return None;
        }
        Some(Self {
            pod_uid: target.pod_uid.clone(),
            identity: target
                .source_identity
                .as_ref()
                .map(|identity| identity.principal.as_str().to_string()),
            addresses,
        })
    }
}

/// Same canonical leaf-name rule the node-agent publisher applies before writing
/// an entry (`publish_pod_registry` / `is_safe_pod_registry_uid`), re-checked
/// on the consuming side so a directory this process did not write cannot
/// smuggle a traversal-shaped, whitespace, or control-character key into the
/// index or a diagnostic.
fn pod_uid_is_unsafe(pod_uid: &str) -> bool {
    !crate::modes::mesh::node_waypoint::is_safe_pod_registry_uid(pod_uid)
}

/// What one enrolled address resolves to. Shared behind an `Arc` so a pod with
/// both families contributes one allocation, not two.
#[derive(Debug, PartialEq, Eq)]
struct EnrolledAddressOwner {
    pod_uid: String,
    identity: Option<String>,
}

/// One published generation of the node-local enrolled-pod set. Replaced
/// wholesale so a reader sees the previous set or the next one, never a
/// half-applied mix.
#[derive(Debug, Default)]
struct EnrolledGeneration {
    /// Part of the same snapshot as the map, so retraction is atomic with
    /// replacement: a reader can never pair a stale entry with a separately
    /// loaded publication flag. `false` ⇒ this index vouches for NOTHING.
    published: bool,
    by_address: HashMap<IpAddr, Arc<EnrolledAddressOwner>>,
}

/// One preloaded enrolled-destination generation for a complete relay-guard
/// decision. Holding the `ArcSwap` guard pins one coherent generation while
/// every matching inventory entry is compared.
pub(crate) struct NodeLocalEnrolledDestinationsSnapshot {
    current: arc_swap::Guard<Arc<EnrolledGeneration>>,
}

impl NodeLocalEnrolledDestinationsSnapshot {
    /// Resolve one canonical destination address from this generation. The
    /// caller performs this once before walking matching inventory entries.
    pub(crate) fn owner_for(
        &self,
        address: IpAddr,
    ) -> Option<NodeLocalEnrolledDestinationOwner<'_>> {
        if !self.current.published {
            return None;
        }
        self.current
            .by_address
            .get(&address.to_canonical())
            .map(|owner| NodeLocalEnrolledDestinationOwner {
                owner: owner.as_ref(),
            })
    }
}

/// Borrowed enrollment evidence for one address from a pinned generation.
/// Copying this view performs no allocation or lookup.
#[derive(Clone, Copy)]
pub(crate) struct NodeLocalEnrolledDestinationOwner<'a> {
    owner: &'a EnrolledAddressOwner,
}

impl NodeLocalEnrolledDestinationOwner<'_> {
    /// Whether this enrolled owner satisfies the slice record's evidence.
    pub(crate) fn terminates_for(self, identity: Option<&str>, pod_uid: Option<&str>) -> bool {
        if let Some(pod_uid) = pod_uid
            && self.owner.pod_uid != pod_uid
        {
            return false;
        }
        if let (Some(required), Some(attested)) = (identity, self.owner.identity.as_deref())
            && required != attested
        {
            return false;
        }
        true
    }
}

/// Lock-free, poller-published index of the pods enrolled on THIS node.
///
/// Read once per authenticated inbound CONNECT (and per UDP CONNECT) through
/// [`Self::terminates_for`]: one `ArcSwap::load()` plus at most one hash lookup
/// per candidate address, no allocation and no filesystem access.
#[derive(Debug)]
pub struct NodeLocalEnrolledDestinations {
    current: ArcSwap<EnrolledGeneration>,
    next_generation: AtomicU64,
}

impl Default for NodeLocalEnrolledDestinations {
    fn default() -> Self {
        Self {
            current: ArcSwap::from_pointee(EnrolledGeneration::default()),
            next_generation: AtomicU64::new(1),
        }
    }
}

impl NodeLocalEnrolledDestinations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load one coherent generation for one complete guard decision.
    fn snapshot(&self) -> NodeLocalEnrolledDestinationsSnapshot {
        NodeLocalEnrolledDestinationsSnapshot {
            current: self.current.load(),
        }
    }

    /// Publish a complete new generation, returning its number.
    ///
    /// An address claimed by more than one DISTINCT pod UID is dropped for
    /// every claimant: the registry cannot tell the guard which pod owns it,
    /// and guessing would let one pod be relayed to under another's
    /// enrollment. Two records repeating one pod UID (the same pod re-listed)
    /// collapse rather than contest.
    pub fn publish(&self, entries: &[EnrolledPodEntry]) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut by_address: HashMap<IpAddr, Arc<EnrolledAddressOwner>> = HashMap::new();
        let mut contested: Vec<IpAddr> = Vec::new();
        for entry in entries {
            if pod_uid_is_unsafe(&entry.pod_uid) {
                continue;
            }
            let owner = Arc::new(EnrolledAddressOwner {
                pod_uid: entry.pod_uid.clone(),
                identity: entry.identity.clone(),
            });
            for address in &entry.addresses {
                let address = address.to_canonical();
                match by_address.get(&address) {
                    Some(existing) if existing.pod_uid == owner.pod_uid => {}
                    Some(_) => contested.push(address),
                    None => {
                        by_address.insert(address, owner.clone());
                    }
                }
            }
        }
        for address in contested {
            by_address.remove(&address);
        }
        if !by_address.is_empty() {
            debug!(
                generation,
                enrolled_addresses = by_address.len(),
                "Node-local enrolled destination index published"
            );
        }
        self.current.store(Arc::new(EnrolledGeneration {
            published: true,
            by_address,
        }));
        generation
    }

    /// Retract every entry. The index then vouches for nothing, so every
    /// registry-bounded relay destination is refused until a later publish.
    pub fn clear(&self) {
        self.current.store(Arc::new(EnrolledGeneration {
            published: false,
            by_address: HashMap::new(),
        }));
    }

    /// Whether this node currently enrolls the destination pod at `address`
    /// (issue #4249). HOT PATH: one snapshot load, one hash lookup, no
    /// allocation and no I/O.
    ///
    /// `address` is the EFFECTIVE DIAL DESTINATION, not a hint: the guard only
    /// reaches this for an inventory entry matched by IP LITERAL, and an IP
    /// authority is relayed to verbatim, so admitting the address here admits
    /// exactly the socket the relay opens. A destination the terminator can
    /// only NAME never gets here — the caller refuses it outright while this
    /// index is authoritative, because a name is resolved AFTER the decision
    /// and could select an off-node sibling or any other address DNS returns.
    /// See `MeshConfig::destination_is_node_local_enrolled`.
    ///
    /// `identity` and `pod_uid` bind the admission to the actual enrolled pod
    /// when both sides carry the evidence: a mismatch is a refusal. The
    /// node-agent publishes `spiffe_id=` optionally and the slice publishes
    /// `pod_uid` only for per-pod Kubernetes workloads, so an ABSENT value on
    /// either side leaves that particular comparison unmade instead of refusing
    /// an enrollment the address already proves.
    pub fn terminates_for(
        &self,
        address: IpAddr,
        identity: Option<&str>,
        pod_uid: Option<&str>,
    ) -> bool {
        let snapshot = self.snapshot();
        let Some(owner) = snapshot.owner_for(address) else {
            return false;
        };
        owner.terminates_for(identity, pod_uid)
    }
}

/// The relay guard's binding to a node-local registry, carried on
/// `MeshConfig` (issue #4249).
///
/// `Some` is AUTHORITATIVE: `inbound_relay_destinations` is bounded by what the
/// node-agent currently enrolls, there is NO per-entry fallback to slice
/// identity matching, and a declared-NAME entry — which has no address this
/// index could ever vouch for — is refused rather than admitted on identity.
/// `None` means no registry source is configured for this topology at all,
/// which is the one case #4249's acceptance contract leaves on the
/// identity/locality bound.
///
/// Compared by pointer identity: this is a shared live handle, not config
/// content, so two applies of the same serving cycle must not look different
/// to `MeshConfig`'s change detection merely because the index republished.
#[derive(Debug, Clone, Default)]
pub struct NodeLocalEnrolledDestinationsHandle(Option<Arc<NodeLocalEnrolledDestinations>>);

impl NodeLocalEnrolledDestinationsHandle {
    #[allow(dead_code)] // Serving runtimes install through the global slot; also an external test seam.
    pub fn new(index: Arc<NodeLocalEnrolledDestinations>) -> Self {
        Self(Some(index))
    }

    /// The index, when a node-local registry is authoritative for this proxy.
    pub fn index(&self) -> Option<&NodeLocalEnrolledDestinations> {
        self.0.as_deref()
    }

    /// Load the authoritative registry generation once for a complete guard
    /// decision. `None` means this proxy has no registry source configured.
    pub(crate) fn snapshot(&self) -> Option<NodeLocalEnrolledDestinationsSnapshot> {
        self.0
            .as_deref()
            .map(NodeLocalEnrolledDestinations::snapshot)
    }

    /// Whether a node-local registry bounds this proxy's relay inventory.
    #[allow(dead_code)] // Diagnostics + external test assertions; unread by the binary target.
    pub fn is_authoritative(&self) -> bool {
        self.0.is_some()
    }
}

impl PartialEq for NodeLocalEnrolledDestinationsHandle {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for NodeLocalEnrolledDestinationsHandle {}

/// One serving-cycle installation of the process-wide enrolled index slot.
///
/// Each install allocates a fresh `Arc` token even when it wraps the same
/// [`NodeLocalEnrolledDestinations`] pointer as a prior cycle. Retraction
/// compare-and-swaps this exact token to `None`, so a stale guard cannot clear
/// a newer cycle's slot after that cycle has installed a different token.
#[derive(Debug)]
struct InstalledEnrolledDestinationsToken {
    index: Arc<NodeLocalEnrolledDestinations>,
}

/// Process-wide installed index for the current mesh serving cycle.
///
/// A process runs at most one mesh runtime against at most one node-agent
/// registry directory, and `prepare_normalized_gateway_config_for_mesh` — which
/// stamps the handle onto every applied `MeshConfig` — is reached from the
/// initial bootstrap config, every slice apply, and `validate`, none of which
/// thread a runtime handle. Installing once per serving cycle keeps the handle
/// coherent across all of them without widening `MeshRuntimeConfig`.
///
/// Unset outside a serving mesh runtime (including `validate`), so the guard's
/// default is the identity bound. The installation-ownership tests below are
/// the only tests that exercise this slot and serialize their own mutations.
/// Tests that build a `MeshConfig` assign
/// `MeshConfig::inbound_relay_node_local_registry` on the built config (or
/// explicitly clear it after mesh apply) so a parallel slot test cannot change
/// their expected registry posture.
static INSTALLED_ENROLLED_DESTINATIONS: std::sync::LazyLock<
    ArcSwapOption<InstalledEnrolledDestinationsToken>,
> = std::sync::LazyLock::new(ArcSwapOption::empty);

/// Install `index` as this serving cycle's authoritative node-local registry.
fn install_node_local_enrolled_destinations(
    index: Arc<NodeLocalEnrolledDestinations>,
) -> Arc<InstalledEnrolledDestinationsToken> {
    let token = Arc::new(InstalledEnrolledDestinationsToken { index });
    INSTALLED_ENROLLED_DESTINATIONS.store(Some(Arc::clone(&token)));
    token
}

/// Retract `token` if it is still the installed one.
///
/// Compare-and-swap rather than load-then-store: retraction runs from a `Drop`,
/// and a newer serving cycle may install a different token between an observed
/// load and an unconditional `store(None)`. Clearing that newer token would
/// leave the live cycle's applies falling back to the identity bound — a
/// FAIL-OPEN direction, and precisely the "retire what you do not own" the guard
/// exists to prevent. A fresh token per install also covers the case where two
/// cycles wrap the same underlying [`NodeLocalEnrolledDestinations`] `Arc`.
fn retract_installed_index_if_ours(token: &Arc<InstalledEnrolledDestinationsToken>) {
    let _previous = INSTALLED_ENROLLED_DESTINATIONS.compare_and_swap(token, None);
}

/// The installed index itself, for the serving runtime that owns its poller.
pub fn installed_index() -> Option<Arc<NodeLocalEnrolledDestinations>> {
    INSTALLED_ENROLLED_DESTINATIONS
        .load_full()
        .map(|token| Arc::clone(&token.index))
}

/// The handle to stamp onto a `MeshConfig` being prepared.
pub fn installed_node_local_enrolled_destinations() -> NodeLocalEnrolledDestinationsHandle {
    match INSTALLED_ENROLLED_DESTINATIONS.load_full() {
        Some(token) => NodeLocalEnrolledDestinationsHandle::new(Arc::clone(&token.index)),
        None => NodeLocalEnrolledDestinationsHandle::default(),
    }
}

/// Retracts the installed index when the mesh serving cycle unwinds, so an
/// aborted or panicking runtime cannot leave a stale registry bound to a later
/// cycle's config.
pub struct InstalledEnrolledDestinationsGuard {
    /// The installation token this guard published. Retraction CASes this exact
    /// `Arc` to `None`, so a newer cycle's token survives a stale guard drop.
    token: Arc<InstalledEnrolledDestinationsToken>,
}

impl InstalledEnrolledDestinationsGuard {
    pub fn install(index: Arc<NodeLocalEnrolledDestinations>) -> Self {
        let token = install_node_local_enrolled_destinations(index);
        Self { token }
    }
}

impl Drop for InstalledEnrolledDestinationsGuard {
    fn drop(&mut self) {
        // The index's own contents are retracted by the poller's
        // `EnrolledRetractionGuard`; this only gives up the shared installation,
        // and only while this guard's token is still the installed one.
        retract_installed_index_if_ours(&self.token);
    }
}

/// Polls the node-agent-published enrolled-pod registry and republishes
/// [`NodeLocalEnrolledDestinations`].
///
/// Deliberately its own manager rather than a hook on the capture/steering
/// reconcilers: those start only when their datapath feature is enabled, while
/// the relay guard's bound must hold for every Ambient proxy. It shares their
/// `PodCaptureSource` abstraction and their 2s cadence, so the enrolled set the
/// guard admits and the set the capture managers act on cannot drift by more
/// than one poll — but it reads [`PodCaptureSource::list_complete_targets`],
/// not the best-effort [`PodCaptureSource::list_targets`] scan those reconcilers
/// use. The relay index is an authoritative security attestation; a partial
/// or unsafe snapshot must not publish.
pub struct NodeLocalEnrolledDestinationsManager {
    source: Arc<dyn PodCaptureSource>,
    index: Arc<NodeLocalEnrolledDestinations>,
    poll_interval: Duration,
    snapshot_unhealthy: AtomicBool,
}

/// Retract the enrolled set whenever the manager future leaves scope — not only
/// on an orderly shutdown signal. Task abort and unwind both drop the future,
/// and a retained set with no poller behind it would keep admitting a pod the
/// node-agent may already have withdrawn.
struct EnrolledRetractionGuard {
    index: Arc<NodeLocalEnrolledDestinations>,
}

impl Drop for EnrolledRetractionGuard {
    fn drop(&mut self) {
        self.index.clear();
    }
}

impl NodeLocalEnrolledDestinationsManager {
    pub fn new(
        source: Arc<dyn PodCaptureSource>,
        index: Arc<NodeLocalEnrolledDestinations>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            source,
            index,
            poll_interval,
            snapshot_unhealthy: AtomicBool::new(false),
        }
    }

    /// One reconcile pass. A complete snapshot is published wholesale; any
    /// incomplete, unsafe, or malformed registry snapshot retracts the index
    /// immediately so the guard admits nothing. Last-good is never retained
    /// and a partial snapshot is never published. That includes a present
    /// malformed `spiffe_id=` / `ipv4=` / `ipv6=` (which must not become missing
    /// evidence), a duplicate recognized key, unknown content, and an unsafe
    /// pod-UID leaf name. A leaf already unlinked when the reader opens it is a
    /// withdrawn pod, not an incomplete snapshot, and is skipped — see the
    /// module docs.
    ///
    /// Returns the entries that were published (empty after a retraction).
    /// Diagnostics are fixed-shape transition lines; the error payload is
    /// discarded so registry contents, identities, pod UIDs, and attacker-
    /// controlled names never reach a log. The first retraction warns, repeated
    /// failures are debug-only, and recovery warns once.
    pub fn reconcile_once(&self) -> Vec<EnrolledPodEntry> {
        match self.source.list_complete_targets() {
            Ok(targets) => {
                let entries: Vec<EnrolledPodEntry> = targets
                    .iter()
                    .filter_map(EnrolledPodEntry::from_capture_target)
                    .collect();
                self.index.publish(&entries);
                if self.snapshot_unhealthy.swap(false, Ordering::Relaxed) {
                    warn!(
                        "Node-local enrolled destination registry recovered; complete snapshots \
                         are publishing again"
                    );
                }
                entries
            }
            Err(_) => {
                self.index.clear();
                if !self.snapshot_unhealthy.swap(true, Ordering::Relaxed) {
                    warn!(
                        "Node-local enrolled destination registry is unavailable; the \
                         authenticated inbound HBONE relay inventory is retracted"
                    );
                } else {
                    debug!(
                        "Node-local enrolled destination index remains retracted; \
                         registry snapshot was not complete"
                    );
                }
                Vec::new()
            }
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let retraction = EnrolledRetractionGuard {
            index: self.index.clone(),
        };
        info!(
            poll_interval_ms = self.poll_interval.as_millis() as u64,
            "Node-local enrolled destination index started; the authenticated inbound HBONE relay \
             admits only pods this node's agent currently enrolls"
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
        drop(retraction);
        debug!("Node-local enrolled destination index retracted at shutdown");
    }
}

#[cfg(test)]
mod installation_ownership_tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_lock() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn clear_installed_for_test() {
        INSTALLED_ENROLLED_DESTINATIONS.store(None);
    }

    fn installed_token_ptr() -> Option<*const InstalledEnrolledDestinationsToken> {
        INSTALLED_ENROLLED_DESTINATIONS
            .load_full()
            .map(|token| Arc::as_ptr(&token))
    }

    #[test]
    fn sequential_replacement_survives_stale_guard_drop() {
        let _lock = test_lock();
        clear_installed_for_test();

        let index_a = Arc::new(NodeLocalEnrolledDestinations::new());
        let index_b = Arc::new(NodeLocalEnrolledDestinations::new());
        let guard_a = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_a));
        let token_a = Arc::as_ptr(&guard_a.token);
        assert!(Arc::ptr_eq(
            &installed_index().expect("first install publishes"),
            &index_a
        ));

        let guard_b = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_b));
        let token_b = Arc::as_ptr(&guard_b.token);
        assert_ne!(token_a, token_b, "each install must allocate a fresh token");
        assert!(Arc::ptr_eq(
            &installed_index().expect("second install replaces"),
            &index_b
        ));

        drop(guard_a);
        assert_eq!(
            installed_token_ptr(),
            Some(token_b),
            "stale guard drop must not clear the newer installation token"
        );
        assert!(Arc::ptr_eq(
            &installed_index().expect("newer cycle still installed"),
            &index_b
        ));

        drop(guard_b);
        assert!(installed_index().is_none());
        clear_installed_for_test();
    }

    #[test]
    fn same_index_reinstallation_survives_stale_guard_drop() {
        let _lock = test_lock();
        clear_installed_for_test();

        let shared_index = Arc::new(NodeLocalEnrolledDestinations::new());
        let guard_a = InstalledEnrolledDestinationsGuard::install(Arc::clone(&shared_index));
        let token_a = Arc::as_ptr(&guard_a.token);

        let guard_b = InstalledEnrolledDestinationsGuard::install(Arc::clone(&shared_index));
        let token_b = Arc::as_ptr(&guard_b.token);
        assert_ne!(
            token_a, token_b,
            "reinstalling the same index Arc must still mint a new token"
        );
        assert!(Arc::ptr_eq(
            &installed_index().expect("reinstall keeps the shared index"),
            &shared_index
        ));

        drop(guard_a);
        assert_eq!(
            installed_token_ptr(),
            Some(token_b),
            "dropping the older token must not clear the newer reinstall"
        );
        assert!(Arc::ptr_eq(
            &installed_index().expect("newer reinstall still authoritative"),
            &shared_index
        ));

        drop(guard_b);
        assert!(installed_index().is_none());
        clear_installed_for_test();
    }

    #[test]
    fn cas_survives_new_install_before_stale_retract() {
        let _lock = test_lock();
        clear_installed_for_test();

        let index_a = Arc::new(NodeLocalEnrolledDestinations::new());
        let index_b = Arc::new(NodeLocalEnrolledDestinations::new());
        let guard_a = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_a));
        let stale_token = Arc::clone(&guard_a.token);

        let guard_b = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_b));
        let live_token = Arc::as_ptr(&guard_b.token);

        retract_installed_index_if_ours(&stale_token);
        assert_eq!(
            installed_token_ptr(),
            Some(live_token),
            "late retract of the superseded token must be a no-op"
        );
        assert!(Arc::ptr_eq(
            &installed_index().expect("live install survives stale CAS"),
            &index_b
        ));

        drop(guard_a);
        assert_eq!(
            installed_token_ptr(),
            Some(live_token),
            "stale guard drop after the late retract must still be a no-op"
        );

        drop(guard_b);
        assert!(installed_index().is_none());
        clear_installed_for_test();
    }

    #[test]
    fn cas_allows_clean_handoff_when_retract_precedes_reinstall() {
        let _lock = test_lock();
        clear_installed_for_test();

        let index_a = Arc::new(NodeLocalEnrolledDestinations::new());
        let index_b = Arc::new(NodeLocalEnrolledDestinations::new());
        let guard_a = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_a));
        let token_a = Arc::clone(&guard_a.token);

        drop(guard_a);
        assert!(installed_index().is_none());

        let guard_b = InstalledEnrolledDestinationsGuard::install(Arc::clone(&index_b));
        retract_installed_index_if_ours(&token_a);
        assert!(Arc::ptr_eq(
            &installed_index().expect("prior retract must not touch the new token"),
            &index_b
        ));

        drop(guard_b);
        assert!(installed_index().is_none());
        clear_installed_for_test();
    }
}

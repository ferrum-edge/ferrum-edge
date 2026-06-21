//! Node-waypoint identity resolution.
//!
//! In node-waypoint topology one proxy listener accepts traffic for many pods.
//! The node-agent/eBPF side records the socket cookie, original destination,
//! and source pod identity. The proxy resolves that cookie at accept time and
//! rejects unknown cookies before the request enters the plugin chain.
//!
//! ## Hot-path contract
//!
//! The resolver is consulted once per inbound TCP accept on a node-waypoint
//! listener (see `run_accept_loop` in `src/proxy/mod.rs`). The cost budget per
//! accept is:
//!
//! 1. One `getsockopt(SO_COOKIE)` (~50 ns) via [`socket_cookie`].
//! 2. One `DashMap::get` against the unified cookie record map (returns
//!    `(pod_uid, workload_spiffe_hash)`).
//! 3. One `DashMap::get` against the identity map (returns `Arc<NodeWaypointIdentity>`).
//! 4. One `ArcSwap::load` of the current slice generation + `HashMap` lookups
//!    against its `identities_by_hash` gate, re-validating that the control
//!    plane still vouches for the resolved workload (fail closed if it was
//!    removed) and, from the SAME load, deriving the per-pod policy scope by
//!    pod UID (`scopes_by_pod_uid`, with a SPIFFE-keyed fallback for uid-less
//!    VM workloads). No allocation; the same loaded generation serves the
//!    cached and lazy-enrollment branches AND the returned scope, so a reader
//!    can never pair a new gate with an old/missing scope.
//! 5. One `Arc::clone` (~5 ns) to hand the identity to the connection task.
//!
//! Both hot-path DashMaps are sized via `crate::util::sharding::pool_shard_amount`
//! so contention scales with `num_cpus`. New accept-path atomics (per-reason
//! `node_waypoint_*_drops` counters in `OverloadState`) are `CachePadded` —
//! see `src/overload.rs`.
//!
//! Per-pod policy scope is part of the SAME slice generation as the identity
//! gate: the accept path receives `(identity, scope)` from one `resolve_*`
//! call (one slice load). The HTTP/HBONE request path re-derives scope per
//! request via [`NodeWaypointIdentityResolver::policy_scope_for_pod`] — one
//! `ArcSwap::load` then a `scopes_by_pod_uid` lookup (SPIFFE fallback for
//! uid-less workloads) — so a workload whose SPIFFE hash is unchanged but whose
//! scope changed is served the scope from the very generation that re-vouched
//! for it. Keying scope by pod UID (not SPIFFE) means pods that share a service
//! account but carry different labels are scoped independently.
//! The slice is published as one atomic `ArcSwap` store on slice apply; nothing
//! is rebuilt in the accept loop.
//!
//! Linux socket cookies are unique across the IPv4/IPv6 protocol families, so
//! both address families share a single cookie record map; this avoids the
//! wasted IPv4 lookup that a dual-map design imposed on every IPv6 accept.
//! The eBPF original-destination address and port are surfaced by
//! [`resolve_stream`] for NodeWaypoint capture: `connect4` rewrites do not
//! create conntrack state, so `SO_ORIGINAL_DST` may be unavailable on the
//! accept side. Production callers use this value as the direct-pod / service
//! port routing signal while still resolving identity from the same cookie
//! record.
//!
//! [`socket_cookie`]: crate::socket_opts::socket_cookie
//!
//! ## Cgroup-inode lifecycle binding (GAP-2M.5)
//!
//! Pods get evicted, restarted, or rescheduled all the time. The kubelet
//! creates a fresh cgroup directory for every pod instance, so a pod restart
//! is observable as a cgroup-inode change at the same path. The resolver
//! optionally binds each enrolled identity to a cgroup v2 path captured at
//! enrollment time (`upsert_identity_with_cgroup`). Enrollment stores the
//! inode plus a small metadata fingerprint so inode reuse does not mask pod
//! restarts. A periodic sweep task (driven by
//! `FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS`) re-stats those
//! paths and evicts identities whose fingerprint no longer matches (pod
//! restarted under the same UID) or whose path is gone (pod removed), so a
//! fresh enrollment from the control plane / eBPF side is required before
//! traffic for the new pod instance is honoured. Identities enrolled without
//! a cgroup path are reclaimed by an independent idle-identity GC task driven
//! by `FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS`; disabling cgroup
//! stats does not disable lazy-enrollment churn cleanup. Both passes are
//! best-effort garbage collection, not security invariants. The fail-closed
//! invariant on the accept path is unchanged: an unknown cookie or pod is
//! still rejected before traffic enters the plugin chain.
#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use dashmap::DashMap;
use ferrum_ebpf_common::{OrigDst4, OrigDst6};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::identity::SpiffeId;
use crate::modes::mesh::config::Workload;
use crate::modes::mesh::runtime::PolicyScopeCache;

/// Address family stamp on a cookie record.
///
/// Tracked only so the cold-path identities snapshot (admin endpoint) can
/// break cookie counts down by family the way the dual-map design did.
/// Resolved identity is family-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieFamily {
    V4,
    V6,
}

/// Identity-affecting fields of an eBPF original-destination record.
///
/// The full BPF records ([`OrigDst4`] / [`OrigDst6`]) also carry the original
/// destination address and port. Those bytes are used by the node-agent for
/// telemetry but are never read by the proxy's identity resolver, so we
/// project them out of the userspace cookie map to keep memory tight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CookieRecord {
    pod_uid: [u8; 16],
    workload_spiffe_hash: u64,
    family: CookieFamily,
    orig_dst: SocketAddr,
}

impl From<&OrigDst4> for CookieRecord {
    fn from(record: &OrigDst4) -> Self {
        Self {
            pod_uid: record.pod_uid,
            workload_spiffe_hash: record.workload_spiffe_hash,
            family: CookieFamily::V4,
            orig_dst: orig_dst4_socket_addr(record),
        }
    }
}

impl From<&OrigDst6> for CookieRecord {
    fn from(record: &OrigDst6) -> Self {
        Self {
            pod_uid: record.pod_uid,
            workload_spiffe_hash: record.workload_spiffe_hash,
            family: CookieFamily::V6,
            orig_dst: orig_dst6_socket_addr(record),
        }
    }
}

fn orig_dst4_socket_addr(record: &OrigDst4) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(record.addr.to_ne_bytes())),
        record.port as u16,
    )
}

fn orig_dst6_socket_addr(record: &OrigDst6) -> SocketAddr {
    let mut octets = [0u8; 16];
    for (idx, word) in record.addr.iter().enumerate() {
        octets[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), record.port as u16)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWaypointIdentity {
    pub pod_uid: [u8; 16],
    pub spiffe_id: SpiffeId,
    pub workload_spiffe_hash: u64,
    /// Filesystem path to the pod's cgroup v2 directory captured at
    /// enrollment. `None` when the enrollment source didn't supply a cgroup
    /// path — sweep treats such identities as opt-out and never evicts them.
    pub cgroup_path: Option<PathBuf>,
    /// Inode of `cgroup_path` at enrollment time. Pod restart yields a new
    /// inode at the same path; the sweep task evicts the identity when the
    /// current inode no longer matches this value. `None` when
    /// `cgroup_path` is `None`, or on platforms / filesystems where the
    /// inode cannot be read (`stat` returned an error at enrollment) —
    /// see `upsert_identity_with_cgroup`'s caller for the warning path.
    pub cgroup_inode: Option<u64>,
    /// Full Unix metadata fingerprint captured with the inode. Some
    /// filesystems can reuse inode numbers after a directory is deleted, so
    /// sweep compares this fingerprint when available and falls back to
    /// inode-only matching for identities built through `with_cgroup`.
    pub cgroup_fingerprint: Option<CgroupFingerprint>,
}

/// `ctime` (inode-metadata change time) is used rather than `mtime` because
/// kubelet writes to files *inside* the cgroup directory (`cgroup.procs`,
/// thresholds, etc.) update the directory's `mtime` without indicating a
/// new pod incarnation. `ctime` only advances when the directory's own
/// metadata changes — which for a kubelet-managed cgroup means
/// creation/replacement, exactly the signal the sweep needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupFingerprint {
    pub device: u64,
    pub inode: u64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
}

impl NodeWaypointIdentity {
    pub fn new(pod_uid: [u8; 16], spiffe_id: SpiffeId) -> Self {
        let workload_spiffe_hash = workload_spiffe_hash(&spiffe_id);
        Self {
            pod_uid,
            spiffe_id,
            workload_spiffe_hash,
            cgroup_path: None,
            cgroup_inode: None,
            cgroup_fingerprint: None,
        }
    }

    pub fn with_cgroup(mut self, path: PathBuf, inode: u64) -> Self {
        self.cgroup_path = Some(path);
        self.cgroup_inode = Some(inode);
        self.cgroup_fingerprint = None;
        self
    }

    pub fn with_cgroup_fingerprint(
        mut self,
        path: PathBuf,
        fingerprint: CgroupFingerprint,
    ) -> Self {
        self.cgroup_path = Some(path);
        self.cgroup_inode = Some(fingerprint.inode);
        self.cgroup_fingerprint = Some(fingerprint);
        self
    }
}

/// One atomically-published node-waypoint slice generation: the fail-closed
/// identity gate (`workload_spiffe_hash` -> SPIFFE, covering ALL workloads) and
/// the per-pod-UID policy-scope index (pod UID -> scope) in a single `ArcSwap`
/// payload, so a lock-free reader sees a consistent (gate, scope) view — never
/// a mix of a new gate with an old/missing scope.
#[derive(Default)]
struct NodeWaypointSlice {
    identities_by_hash: std::collections::HashMap<u64, NodeWaypointIdentityGateEntry>,
    /// Per-pod policy scope keyed by the exact `[u8; 16]` pod UID the eBPF
    /// capture stamps (parsed from each per-pod workload's `metadata.uid`).
    /// Pods that share a SPIFFE but differ in labels get distinct entries, so
    /// selector-scoped policy is evaluated against the source pod's own labels
    /// — never a cross-pod label merge.
    scopes_by_pod_uid: std::collections::HashMap<[u8; 16], std::sync::Arc<PolicyScopeCache>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeWaypointIdentityGateEntry {
    Single(SpiffeId),
    Collision,
}

fn insert_identity_gate_entry(
    identities_by_hash: &mut HashMap<u64, NodeWaypointIdentityGateEntry>,
    workload_spiffe_hash: u64,
    spiffe_id: &SpiffeId,
) {
    use std::collections::hash_map::Entry;

    match identities_by_hash.entry(workload_spiffe_hash) {
        Entry::Vacant(entry) => {
            entry.insert(NodeWaypointIdentityGateEntry::Single(spiffe_id.clone()));
        }
        Entry::Occupied(mut entry) => match entry.get() {
            NodeWaypointIdentityGateEntry::Single(existing) if existing == spiffe_id => {}
            NodeWaypointIdentityGateEntry::Single(existing) => {
                warn!(
                    workload_spiffe_hash,
                    first_spiffe_id = %existing,
                    collided_spiffe_id = %spiffe_id,
                    "Disabling collided node-waypoint workload SPIFFE hash gate entry"
                );
                entry.insert(NodeWaypointIdentityGateEntry::Collision);
            }
            NodeWaypointIdentityGateEntry::Collision => {}
        },
    }
}

impl NodeWaypointSlice {
    fn spiffe_for_hash(&self, workload_spiffe_hash: u64) -> Option<&SpiffeId> {
        match self.identities_by_hash.get(&workload_spiffe_hash)? {
            NodeWaypointIdentityGateEntry::Single(spiffe_id) => Some(spiffe_id),
            NodeWaypointIdentityGateEntry::Collision => None,
        }
    }

    /// Resolve a captured pod's policy scope from this one generation, keyed by
    /// the exact `[u8; 16]` the eBPF stamps. `None` means the pod's workload is
    /// not in the live slice generation — the caller (`mesh_authz`) then fails
    /// closed when scoped policies exist, else evaluates mesh-wide-only.
    ///
    /// A captured pod is NEVER resolved through the SPIFFE-keyed index: that
    /// index is for uid-less (VM/WorkloadEntry) workloads, and a same-SPIFFE
    /// uid-less workload's labels are not this pod's — collapsing onto them would
    /// evaluate scoped policy against the wrong labels (and let a selector-scoped
    /// DENY be evaded). A captured pod whose UID is absent fails closed instead.
    fn scope_for(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.scopes_by_pod_uid.get(pod_uid).map(Arc::clone)
    }
}

pub struct NodeWaypointPolicyScopeSnapshot {
    slice: NodeWaypointSlice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeWaypointIdentityError {
    SocketCookieUnavailable(String),
    UnknownCookie(u64),
    MissingPodUid(u64),
    MissingWorkloadHash {
        cookie: u64,
        pod_uid: [u8; 16],
    },
    UnknownPod([u8; 16]),
    WorkloadHashMismatch {
        pod_uid: [u8; 16],
        expected: u64,
        actual: u64,
    },
    PodUidMismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },
}

impl fmt::Display for NodeWaypointIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketCookieUnavailable(error) => {
                write!(f, "socket cookie unavailable: {error}")
            }
            Self::UnknownCookie(cookie) => write!(f, "no node-waypoint record for cookie {cookie}"),
            Self::MissingPodUid(cookie) => {
                write!(f, "node-waypoint record for cookie {cookie} has no pod UID")
            }
            Self::MissingWorkloadHash { cookie, pod_uid } => write!(
                f,
                "node-waypoint record for cookie {cookie} and pod {} has no workload SPIFFE hash",
                pod_uid_label(pod_uid)
            ),
            Self::UnknownPod(pod_uid) => {
                write!(
                    f,
                    "no node-waypoint identity for pod {}",
                    pod_uid_label(pod_uid)
                )
            }
            Self::WorkloadHashMismatch {
                pod_uid,
                expected,
                actual,
            } => write!(
                f,
                "node-waypoint SPIFFE hash mismatch for pod {}: expected {expected}, got {actual}",
                pod_uid_label(pod_uid)
            ),
            Self::PodUidMismatch { expected, actual } => write!(
                f,
                "node-waypoint pod UID mismatch: listener expected pod {}, eBPF record resolved pod {}",
                pod_uid_label(expected),
                pod_uid_label(actual)
            ),
        }
    }
}

impl std::error::Error for NodeWaypointIdentityError {}

/// Synchronous accept-path cookie lookup, returning `(pod_uid, workload SPIFFE
/// hash, original destination)` for a socket cookie. Boxed because
/// `ArcSwapOption` needs a `Sized` payload. Injected by the eBPF orig-dst
/// bridge so the resolver itself stays aya-free; see
/// [`NodeWaypointIdentityResolver::set_cookie_fallback`].
pub type CookieLookupFallback =
    Box<dyn Fn(u64) -> Option<([u8; 16], u64, SocketAddr)> + Send + Sync>;

pub struct NodeWaypointResolvedConnection {
    pub identity: Arc<NodeWaypointIdentity>,
    pub policy_scope: Option<Arc<PolicyScopeCache>>,
    pub orig_dst: SocketAddr,
}

pub struct NodeWaypointIdentityResolver {
    /// Unified cookie → identity-key map. Linux socket cookies are globally
    /// unique across IPv4/IPv6, so the resolver doesn't need separate maps;
    /// keeping them merged saves one wasted lookup on every IPv6 accept
    /// (previously the IPv4 map was always probed first) and halves the
    /// DashMap shard-array overhead.
    cookie_records: DashMap<u64, CookieRecord>,
    /// Optional synchronous fallback consulted by [`Self::resolve_cookie`] when
    /// `cookie_records` misses. The orig-dst bridge mirrors the pinned BPF maps
    /// into `cookie_records` only every `ORIG_DST_BRIDGE_POLL_INTERVAL_MS`, so a
    /// connection accepted right after its accept-side cookie was stamped would
    /// otherwise be dropped (UnknownCookie) until the next poll. This fallback
    /// reads the pinned map directly so the first resolve succeeds. `None` on
    /// non-eBPF builds / before the bridge installs it. Lock-free swap so the
    /// hot accept path never blocks.
    cookie_fallback: ArcSwapOption<CookieLookupFallback>,
    identities_by_pod_uid: DashMap<[u8; 16], Arc<NodeWaypointIdentity>>,
    /// The current node-waypoint slice generation, published atomically as one
    /// `ArcSwap` payload: the fail-closed identity gate
    /// (`workload_spiffe_hash` → SPIFFE for every workload) and the per-pod-UID
    /// policy-scope index (pod UID → scope). `resolve_record` loads this once
    /// and derives BOTH the identity (joining the eBPF-stamped
    /// `(pod_uid, workload_spiffe_hash)` against `identities_by_hash` to lazily
    /// enroll `pod_uid` → identity) and the per-pod scope (`scopes_by_pod_uid`)
    /// from the SAME load, so a reader can never see a new gate with an
    /// old/missing scope (the "never partial" reload invariant).
    slice: ArcSwap<NodeWaypointSlice>,
    // Sweep counters below are intentionally NOT `CachePadded` (unlike the
    // accept-path `node_waypoint_*_drops` atomics in `OverloadState`). They
    // are written at most once per sweep tick (default 30s) on a single
    // background task and read only via cold-path admin endpoints, so no
    // hot writer/reader pair can land on the same cache line.
    /// Monotonic count of identities evicted because their cgroup path was
    /// gone at sweep time. Operator/admin endpoints can read this to
    /// surface pod-churn signal.
    cgroup_sweep_path_missing: AtomicU64,
    /// Monotonic count of identities evicted because the cgroup inode at
    /// the same path no longer matches the enrolled value (pod restarted
    /// under the same UID).
    cgroup_sweep_inode_changed: AtomicU64,
    /// Sweep-pass counter — increments once per sweep tick regardless of
    /// whether anything was evicted. Useful for "is the sweep task alive"
    /// liveness diagnostics.
    cgroup_sweep_passes: AtomicU64,
    /// Monotonic count of lazily-enrolled (non-cgroup-bound) identities
    /// reclaimed by the sweep because no live cookie record still referenced
    /// the pod — the churn-reclamation path for the production enrollment
    /// model, which binds no cgroup. Operators can watch this to see pod
    /// turnover.
    idle_unreferenced_evicted: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CgroupSweepReport {
    pub evicted_inode_changed: usize,
    pub evicted_path_missing: usize,
    /// Lazily-enrolled (non-cgroup-bound) identities reclaimed because no live
    /// cookie record still referenced the pod (pod churn).
    pub evicted_idle_unreferenced: usize,
}

impl CgroupSweepReport {
    pub fn total_evicted(&self) -> usize {
        self.evicted_inode_changed + self.evicted_path_missing + self.evicted_idle_unreferenced
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupSweepSnapshot {
    pub passes: u64,
    pub inode_changed_total: u64,
    pub path_missing_total: u64,
    pub idle_unreferenced_total: u64,
}

impl NodeWaypointIdentityResolver {
    pub fn new(pool_shard_override: usize) -> Self {
        let shards = crate::util::sharding::pool_shard_amount(pool_shard_override);
        Self {
            cookie_records: DashMap::with_shard_amount(shards),
            cookie_fallback: ArcSwapOption::empty(),
            identities_by_pod_uid: DashMap::with_shard_amount(shards),
            slice: ArcSwap::from_pointee(NodeWaypointSlice::default()),
            cgroup_sweep_path_missing: AtomicU64::new(0),
            cgroup_sweep_inode_changed: AtomicU64::new(0),
            cgroup_sweep_passes: AtomicU64::new(0),
            idle_unreferenced_evicted: AtomicU64::new(0),
        }
    }

    /// Install the synchronous accept-path cookie fallback (the eBPF orig-dst
    /// bridge supplies one backed by the pinned `FERRUM_ORIG_DST4/6` maps).
    /// Lock-free swap; safe to call from the bridge while the accept path reads.
    pub fn set_cookie_fallback(&self, fallback: CookieLookupFallback) {
        self.cookie_fallback.store(Some(Arc::new(fallback)));
    }

    /// Drop the synchronous fallback (e.g. on bridge shutdown) so the resolver
    /// no longer references closed BPF maps.
    pub fn clear_cookie_fallback(&self) {
        self.cookie_fallback.store(None);
    }

    pub fn record_orig_dst4(&self, cookie: u64, record: OrigDst4) {
        self.cookie_records.insert(cookie, (&record).into());
    }

    pub fn record_orig_dst6(&self, cookie: u64, record: OrigDst6) {
        self.cookie_records.insert(cookie, (&record).into());
    }

    /// Drop every cookie record. Used by the orig-dst bridge (GAP-1b) when the
    /// node-agent restarts and re-pins fresh BPF maps: the old cookie records
    /// reference an evicted map generation and must not resolve to stale pods.
    pub fn clear_cookie_records(&self) {
        self.cookie_records.clear();
    }

    /// Retain only the cookies present in `live`, dropping the rest. The
    /// orig-dst bridge calls this each poll so the resolver's cookie map ages
    /// out cookies the kernel evicted from its LRU `FERRUM_ORIG_DST*` maps,
    /// keeping the two maps in step instead of letting the resolver grow
    /// unbounded relative to the BPF map.
    pub fn retain_cookie_records(&self, live: &std::collections::HashSet<u64>) {
        self.cookie_records
            .retain(|cookie, _| live.contains(cookie));
    }

    /// Number of cookie records currently tracked. Cold-path test/diagnostic
    /// helper; the accept path never calls this.
    pub fn cookie_record_count(&self) -> usize {
        self.cookie_records.len()
    }

    pub fn upsert_identity(&self, identity: NodeWaypointIdentity) -> Arc<NodeWaypointIdentity> {
        let identity = Arc::new(identity);
        self.identities_by_pod_uid
            .insert(identity.pod_uid, identity.clone());
        identity
    }

    /// Enroll an identity that is lifecycle-bound to a cgroup v2 directory.
    /// Reads the inode and metadata fingerprint of `cgroup_path` once and
    /// stores them on the identity. A subsequent sweep evicts the identity
    /// if the path is gone or the fingerprint changed (pod restart yields a
    /// fresh cgroup at the same path, even when the inode number is reused).
    ///
    /// On stat error the identity is still inserted but without inode
    /// binding — sweep treats it like a non-cgroup enrollment (kept until
    /// explicit removal). The recorded `cgroup_path` in that case is
    /// informational only: with `cgroup_inode == None` and
    /// `cgroup_fingerprint == None` the sweep's candidate filter rejects
    /// the entry and never re-stats the path. The caller decides whether
    /// to warn; a control plane that requires lifecycle binding can check
    /// the returned identity's `cgroup_inode` and reject when `None`.
    pub fn upsert_identity_with_cgroup(
        &self,
        mut identity: NodeWaypointIdentity,
        cgroup_path: PathBuf,
    ) -> Arc<NodeWaypointIdentity> {
        match read_cgroup_fingerprint(&cgroup_path) {
            Ok(fingerprint) => {
                identity.cgroup_path = Some(cgroup_path);
                identity.cgroup_inode = Some(fingerprint.inode);
                identity.cgroup_fingerprint = Some(fingerprint);
            }
            Err(error) => {
                warn!(
                    pod_uid = %pod_uid_label(&identity.pod_uid),
                    cgroup_path = %cgroup_path.display(),
                    %error,
                    "Enrolling node-waypoint identity without cgroup-inode lifecycle binding (stat failed)"
                );
                identity.cgroup_path = Some(cgroup_path);
                identity.cgroup_inode = None;
                identity.cgroup_fingerprint = None;
            }
        }
        self.upsert_identity(identity)
    }

    pub fn remove_identity(&self, pod_uid: &[u8; 16]) {
        self.identities_by_pod_uid.remove(pod_uid);
    }

    /// Run both identity lifecycle passes once and return a combined report.
    /// Production starts cgroup-bound and idle-unreferenced reclamation from
    /// separate tasks so operators can disable cgroup stat sweeps without also
    /// disabling lazy-enrollment garbage collection.
    pub fn sweep_cgroup_stale_identities(&self) -> CgroupSweepReport {
        let mut report = self.sweep_cgroup_bound_stale_identities();
        report.evicted_idle_unreferenced = self.sweep_idle_unreferenced_identities();
        report
    }

    /// Evict cgroup-bound identities when their enrolled cgroup path is gone
    /// or its inode/fingerprint no longer matches the enrolled value.
    fn sweep_cgroup_bound_stale_identities(&self) -> CgroupSweepReport {
        #[derive(Clone, Copy)]
        enum CgroupExpectation {
            Fingerprint(CgroupFingerprint),
            Inode(u64),
        }

        impl CgroupExpectation {
            fn inode(self) -> u64 {
                match self {
                    Self::Fingerprint(fingerprint) => fingerprint.inode,
                    Self::Inode(inode) => inode,
                }
            }

            fn matches(self, current: CgroupFingerprint) -> bool {
                match self {
                    Self::Fingerprint(fingerprint) => fingerprint == current,
                    Self::Inode(inode) => inode == current.inode,
                }
            }

            fn still_attached_to(self, identity: &NodeWaypointIdentity) -> bool {
                match self {
                    Self::Fingerprint(fingerprint) => {
                        identity.cgroup_fingerprint == Some(fingerprint)
                    }
                    Self::Inode(inode) => {
                        identity.cgroup_inode == Some(inode)
                            && identity.cgroup_fingerprint.is_none()
                    }
                }
            }
        }

        enum EvictionReason {
            BindingChanged { current_inode: u64 },
            PathMissing { error: String },
        }

        let mut report = CgroupSweepReport::default();

        // Snapshot cgroup bindings first so filesystem metadata calls don't
        // hold DashMap shard locks used by accept-time identity resolution.
        let candidates: Vec<([u8; 16], PathBuf, CgroupExpectation)> = self
            .identities_by_pod_uid
            .iter()
            .filter_map(|entry| {
                let identity = entry.value();
                let expectation = identity
                    .cgroup_fingerprint
                    .map(CgroupExpectation::Fingerprint)
                    .or_else(|| identity.cgroup_inode.map(CgroupExpectation::Inode))?;
                Some((
                    *entry.key(),
                    identity.cgroup_path.as_ref()?.clone(),
                    expectation,
                ))
            })
            .collect();

        for (pod_uid, path, expectation) in candidates {
            let Some(reason) = (match read_cgroup_fingerprint(&path) {
                Ok(current) if expectation.matches(current) => None,
                Ok(current) => Some(EvictionReason::BindingChanged {
                    current_inode: current.inode,
                }),
                Err(error) => Some(EvictionReason::PathMissing {
                    error: error.to_string(),
                }),
            }) else {
                continue;
            };

            let removed = self
                .identities_by_pod_uid
                .remove_if(&pod_uid, |_, identity| {
                    expectation.still_attached_to(identity)
                        && identity.cgroup_path.as_deref() == Some(path.as_path())
                });
            if removed.is_none() {
                continue;
            }

            match reason {
                EvictionReason::BindingChanged { current_inode } => {
                    info!(
                        pod_uid = %pod_uid_label(&pod_uid),
                        expected_inode = expectation.inode(),
                        current_inode,
                        cgroup_path = %path.display(),
                        "Evicting node-waypoint identity (cgroup binding changed)"
                    );
                    report.evicted_inode_changed += 1;
                }
                EvictionReason::PathMissing { error } => {
                    debug!(
                        pod_uid = %pod_uid_label(&pod_uid),
                        cgroup_path = %path.display(),
                        %error,
                        "Evicting node-waypoint identity (cgroup path missing)"
                    );
                    report.evicted_path_missing += 1;
                }
            }
        }

        self.cgroup_sweep_passes.fetch_add(1, Ordering::Relaxed);
        if report.evicted_inode_changed > 0 {
            self.cgroup_sweep_inode_changed
                .fetch_add(report.evicted_inode_changed as u64, Ordering::Relaxed);
        }
        if report.evicted_path_missing > 0 {
            self.cgroup_sweep_path_missing
                .fetch_add(report.evicted_path_missing as u64, Ordering::Relaxed);
        }
        report
    }

    /// Evict identities without a cgroup binding when no live cookie record and
    /// no open HTTP/HBONE connection still references the pod. This is the
    /// churn-reclamation path for lazy hash-join enrollment, which binds no
    /// cgroup and has no explicit removal API in production.
    ///
    /// Per-pod policy scope is slice-driven (`policy_scope_for_pod`), not stored
    /// on the identity, so evicting an identity from `identities_by_pod_uid` is
    /// sufficient. A stale PolicyScopeCache from a previous incarnation can
    /// never apply to a newly enrolled pod with the same UID.
    fn sweep_idle_unreferenced_identities(&self) -> usize {
        // Idle-unreferenced pass (see method docs): reclaim non-cgroup-bound
        // (lazily-enrolled) identities whose pod is no longer referenced by any
        // live cookie record. Snapshot candidates first so filesystem-free
        // bookkeeping doesn't hold shard locks. Only when at least one unbound
        // identity exists do we walk cookie records, and the referenced UIDs
        // stay in a sorted Vec instead of rebuilding a HashSet every tick.
        let idle_candidates: Vec<[u8; 16]> = self
            .identities_by_pod_uid
            .iter()
            .filter(|entry| {
                let identity = entry.value();
                identity.cgroup_path.is_none() || identity.cgroup_inode.is_none()
            })
            .map(|entry| *entry.key())
            .collect();
        let referenced: Vec<[u8; 16]> = if idle_candidates.is_empty() {
            Vec::new()
        } else {
            let mut referenced: Vec<[u8; 16]> = self
                .cookie_records
                .iter()
                .map(|entry| entry.value().pod_uid)
                .collect();
            referenced.sort_unstable();
            referenced.dedup();
            referenced
        };
        let mut evicted = 0;
        for pod_uid in idle_candidates {
            if referenced.binary_search(&pod_uid).is_ok() {
                continue;
            }
            let removed = self
                .identities_by_pod_uid
                .remove_if(&pod_uid, |_, identity| {
                    // Re-check "still unbound" under the shard lock so a
                    // concurrent cgroup enrollment is never reclaimed here.
                    if identity.cgroup_path.is_some() && identity.cgroup_inode.is_some() {
                        return false;
                    }
                    // Skip if an open connection still holds this identity Arc.
                    // The HTTP/HBONE accept path stores the resolved
                    // `Arc<NodeWaypointIdentity>` on the connection for its whole
                    // lifetime and re-queries the per-pod scope on every request
                    // (`proxy/mod.rs`), so the BPF LRU evicting this pod's cookie
                    // mid-connection must NOT let the sweep drop its scope — that
                    // would downgrade later streams to mesh-wide. `strong_count
                    // == 1` means only this map entry references the identity, so
                    // no connection holds it; `> 1` means at least one open
                    // connection does, so keep it. (The cookie-reference check
                    // above already covers TCP, whose scope is resolved once at
                    // accept and never re-queried.)
                    Arc::strong_count(identity) == 1
                });
            if removed.is_some() {
                evicted += 1;
            }
        }

        if evicted > 0 {
            self.idle_unreferenced_evicted
                .fetch_add(evicted as u64, Ordering::Relaxed);
        }
        evicted
    }

    pub fn cgroup_sweep_snapshot(&self) -> CgroupSweepSnapshot {
        CgroupSweepSnapshot {
            passes: self.cgroup_sweep_passes.load(Ordering::Relaxed),
            inode_changed_total: self.cgroup_sweep_inode_changed.load(Ordering::Relaxed),
            path_missing_total: self.cgroup_sweep_path_missing.load(Ordering::Relaxed),
            idle_unreferenced_total: self.idle_unreferenced_evicted.load(Ordering::Relaxed),
        }
    }

    /// Per-pod policy scope from the current slice, keyed by the same `[u8; 16]`
    /// the eBPF stamps. One consistent `ArcSwap::load`, paid once per HTTP/HBONE
    /// request on the node-waypoint admit path. Returns `None` when the pod's
    /// workload is not in the live slice generation; the caller (`mesh_authz`)
    /// then fails closed when scoped policies exist, else evaluates
    /// mesh-wide-only.
    ///
    /// Scope is slice-driven (keyed by the workload's `metadata.uid`), not
    /// derived from the enrolled identity — so it is reclaimed by slice updates,
    /// not by identity removal/sweep, and a removed/re-keyed workload fails
    /// closed instead of borrowing a same-SPIFFE workload's labels. Captured
    /// pods never fall back to the SPIFFE-keyed index (that is for uid-less
    /// workloads).
    pub fn policy_scope_for_pod(&self, pod_uid: &[u8; 16]) -> Option<Arc<PolicyScopeCache>> {
        self.slice
            .load()
            .scopes_by_pod_uid
            .get(pod_uid)
            .map(Arc::clone)
    }

    /// Install a node-waypoint slice generation derived from a slice's workload
    /// set.
    ///
    /// Used by tests and direct resolver callers. Mesh slice apply should
    /// prefer [`build_policy_scope_snapshot_from_workloads`] and
    /// [`install_policy_scope_snapshot`] so it can stage the slice before config
    /// validation while publishing it only after the proxy config is accepted.
    pub fn install_policy_scopes_from_workloads<'a, I>(&self, workloads: I)
    where
        I: IntoIterator<Item = &'a Workload>,
    {
        let snapshot = self.build_policy_scope_snapshot_from_workloads(workloads);
        self.install_policy_scope_snapshot(snapshot);
    }

    pub fn build_policy_scope_snapshot_from_workloads<'a, I>(
        &self,
        workloads: I,
    ) -> NodeWaypointPolicyScopeSnapshot
    where
        I: IntoIterator<Item = &'a Workload>,
    {
        let workloads: Vec<&Workload> = workloads.into_iter().collect();
        // Per-pod scope: each workload carrying a pod UID gets its OWN scope
        // keyed by the exact `[u8; 16]` the eBPF stamps (parsed from
        // `metadata.uid`). No cross-pod merge, so pods sharing a SPIFFE but
        // differing in labels are scoped against their own labels. A malformed
        // UID is skipped (the SPIFFE gate still vouches the identity; scope then
        // falls through to `None` → fail closed when scoped policies exist).
        let mut scopes_by_pod_uid: HashMap<[u8; 16], Arc<PolicyScopeCache>> = HashMap::new();
        for workload in &workloads {
            let Some(raw_uid) = workload.pod_uid.as_deref() else {
                continue;
            };
            match parse_pod_uid(raw_uid) {
                Ok(uid) => {
                    scopes_by_pod_uid
                        .insert(uid, Arc::new(PolicyScopeCache::from_workload(workload)));
                }
                Err(error) => {
                    warn!(
                        pod_uid = %raw_uid,
                        %error,
                        "Skipping node-waypoint per-pod scope for workload with invalid pod UID"
                    );
                }
            }
        }
        // The identity gate covers ALL workloads (every pod needs an identity
        // for authz, not only those carrying scoped policies).
        let mut identities_by_hash: HashMap<u64, NodeWaypointIdentityGateEntry> = HashMap::new();
        for workload in &workloads {
            insert_identity_gate_entry(
                &mut identities_by_hash,
                workload_spiffe_hash(&workload.spiffe_id),
                &workload.spiffe_id,
            );
        }
        NodeWaypointPolicyScopeSnapshot {
            slice: NodeWaypointSlice {
                identities_by_hash,
                scopes_by_pod_uid,
            },
        }
    }

    /// Publish the whole slice atomically as one generation: a single
    /// `ArcSwap` store of the `(identity gate, scope index)` payload. Because
    /// the gate and the scopes ride one `ArcSwap`, a lock-free reader
    /// (`resolve_record` / `policy_scope_for_pod`) sees a coherent generation —
    /// it can never observe a new gate paired with an old/missing scope, which
    /// is the "never partial" reload invariant this resolver must hold.
    pub fn install_policy_scope_snapshot(&self, snapshot: NodeWaypointPolicyScopeSnapshot) {
        self.slice.store(std::sync::Arc::new(snapshot.slice));
    }

    /// Build an operator-facing snapshot of the currently enrolled identities.
    ///
    /// Returned entries are sorted by pod UID so admin polling produces a
    /// deterministic order across calls. The shape carries:
    ///   - canonical hyphenated UUID for the pod UID
    ///   - the workload's SPIFFE ID string
    ///   - the workload SPIFFE hash (matches the value the eBPF map stores;
    ///     useful when correlating with node-agent telemetry)
    ///   - the cookie counts (IPv4 + IPv6) currently mapped to that pod via
    ///     `OrigDst{4,6}` records, so operators can see "is this identity
    ///     actually receiving traffic right now?" without joining datasets.
    ///   - whether a per-pod `PolicyScopeCache` is installed.
    ///
    /// This is a cold-path snapshot — it iterates every entry of each
    /// hot-path `DashMap` once and reads the policy-scope `ArcSwap`. Not safe
    /// to call on a hot accept path.
    pub fn identities_snapshot(&self) -> Vec<NodeWaypointIdentitySummary> {
        self.identities_snapshot_with_cookie_totals().0
    }

    /// Cold-path snapshot that returns both the per-identity summary list and
    /// the grand totals of `(orig_dst4, orig_dst6)` cookie records in a single
    /// pass over the `cookie_records` map. The admin endpoint uses this to
    /// honor the documented "single cookie-record pass" contract. Invoking
    /// [`identities_snapshot`] and [`cookie_count`]
    /// separately would walk `cookie_records` twice.
    ///
    /// The totals include cookies whose `pod_uid` has no enrolled identity
    /// (eBPF saw the connection but the node-agent has not yet registered the
    /// pod) so the admin "cookies" summary reflects the full eBPF state, not
    /// just the slice that maps to known identities.
    pub fn identities_snapshot_with_cookie_totals(
        &self,
    ) -> (Vec<NodeWaypointIdentitySummary>, (usize, usize)) {
        let mut cookie_counts: HashMap<[u8; 16], (usize, usize)> = HashMap::new();
        let mut totals = (0usize, 0usize);
        for entry in self.cookie_records.iter() {
            let counters = cookie_counts.entry(entry.value().pod_uid).or_insert((0, 0));
            match entry.value().family {
                CookieFamily::V4 => {
                    counters.0 += 1;
                    totals.0 += 1;
                }
                CookieFamily::V6 => {
                    counters.1 += 1;
                    totals.1 += 1;
                }
            }
        }

        let slice = self.slice.load();
        let mut out: Vec<NodeWaypointIdentitySummary> =
            Vec::with_capacity(self.identities_by_pod_uid.len());
        out.extend(self.identities_by_pod_uid.iter().map(|entry| {
            let identity = entry.value();
            let (orig_dst4_cookies, orig_dst6_cookies) = cookie_counts
                .get(&identity.pod_uid)
                .copied()
                .unwrap_or((0, 0));
            NodeWaypointIdentitySummary {
                pod_uid: identity.pod_uid,
                spiffe_id: identity.spiffe_id.as_str().to_string(),
                workload_spiffe_hash: identity.workload_spiffe_hash,
                orig_dst4_cookies,
                orig_dst6_cookies,
                // Mirrors `policy_scope_for_pod`: a captured pod has a scope iff
                // the slice carries its exact pod UID. Node-waypoint resolves
                // only eBPF-captured, uid-bearing pods; there is no SPIFFE
                // fallback, so an absent UID is a fail-closed miss here too.
                has_policy_scope: slice.scopes_by_pod_uid.contains_key(&identity.pod_uid),
            }
        }));
        out.sort_by_key(|summary| summary.pod_uid);
        (out, totals)
    }

    /// Number of currently enrolled identities. Cheap-ish; uses DashMap's
    /// `len()` which iterates per-shard counters.
    pub fn identity_count(&self) -> usize {
        self.identities_by_pod_uid.len()
    }

    /// Total cookie records (IPv4 + IPv6) currently tracked. Useful for
    /// standalone diagnostics; the admin endpoint instead calls
    /// [`identities_snapshot_with_cookie_totals`] so it walks `cookie_records`
    /// once rather than twice.
    pub fn cookie_count(&self) -> (usize, usize) {
        let mut v4 = 0usize;
        let mut v6 = 0usize;
        for entry in self.cookie_records.iter() {
            match entry.value().family {
                CookieFamily::V4 => v4 += 1,
                CookieFamily::V6 => v6 += 1,
            }
        }
        (v4, v6)
    }

    pub fn resolve_stream(
        &self,
        stream: &TcpStream,
    ) -> Result<NodeWaypointResolvedConnection, NodeWaypointIdentityError> {
        let cookie = crate::socket_opts::socket_cookie(stream).map_err(|error| {
            NodeWaypointIdentityError::SocketCookieUnavailable(error.to_string())
        })?;
        self.resolve_cookie_metadata(cookie)
    }

    /// Resolve an accepted stream and require the eBPF record's pod UID to
    /// match the pod-specific in-netns listener that accepted it. This is a
    /// defense-in-depth guard for the sock-ops bridge's `netns_cookie = 0`
    /// compatibility key: the bridge may recover an accept-side cookie when the
    /// passive callback reports the proxy task's netns, but userspace still
    /// refuses to admit a connection whose source pod does not match the
    /// listener it arrived on.
    pub fn resolve_stream_for_expected_pod(
        &self,
        stream: &TcpStream,
        expected_pod_uid: [u8; 16],
    ) -> Result<NodeWaypointResolvedConnection, NodeWaypointIdentityError> {
        let cookie = crate::socket_opts::socket_cookie(stream).map_err(|error| {
            NodeWaypointIdentityError::SocketCookieUnavailable(error.to_string())
        })?;
        self.resolve_cookie_metadata_for_expected_pod(cookie, expected_pod_uid)
    }

    /// Resolve a socket cookie to its `(identity, scope)` pair, both derived
    /// from the SAME slice load (see [`Self::resolve_record`]). Both branches —
    /// the warm `cookie_records` hit and the between-tick synchronous fallback —
    /// fail closed with `UnknownCookie` on a miss.
    pub fn resolve_cookie(
        &self,
        cookie: u64,
    ) -> Result<(Arc<NodeWaypointIdentity>, Option<Arc<PolicyScopeCache>>), NodeWaypointIdentityError>
    {
        self.resolve_cookie_metadata(cookie)
            .map(|resolved| (resolved.identity, resolved.policy_scope))
    }

    /// Resolve a socket cookie to identity, policy scope, and the eBPF-captured
    /// original destination. Production accept paths use this richer form
    /// because cgroup/connect eBPF rewrites do not populate conntrack state for
    /// `SO_ORIGINAL_DST`.
    fn resolve_cookie_metadata(
        &self,
        cookie: u64,
    ) -> Result<NodeWaypointResolvedConnection, NodeWaypointIdentityError> {
        if let Some(record) = self.cookie_records.get(&cookie) {
            return self.resolve_record(
                cookie,
                record.pod_uid,
                record.workload_spiffe_hash,
                record.orig_dst,
            );
        }
        // Between-tick fallback (GAP-2M): the orig-dst bridge mirrors the pinned
        // BPF maps into `cookie_records` only on its poll interval, so a cookie
        // stamped on the accept side moments ago may not be mirrored yet. Read
        // the pinned map synchronously so a freshly accepted connection resolves
        // on the first try instead of being dropped until the next poll. No
        // fallback (non-eBPF / pre-install) or a miss → UnknownCookie
        // (fail-closed, unchanged).
        if let Some(fallback) = self.cookie_fallback.load_full()
            && let Some((pod_uid, workload_spiffe_hash, orig_dst)) = fallback(cookie)
        {
            return self.resolve_record(cookie, pod_uid, workload_spiffe_hash, orig_dst);
        }
        Err(NodeWaypointIdentityError::UnknownCookie(cookie))
    }

    fn resolve_cookie_metadata_for_expected_pod(
        &self,
        cookie: u64,
        expected_pod_uid: [u8; 16],
    ) -> Result<NodeWaypointResolvedConnection, NodeWaypointIdentityError> {
        let resolved = self.resolve_cookie_metadata(cookie)?;
        if resolved.identity.pod_uid != expected_pod_uid {
            return Err(NodeWaypointIdentityError::PodUidMismatch {
                expected: expected_pod_uid,
                actual: resolved.identity.pod_uid,
            });
        }
        Ok(resolved)
    }

    /// Resolve an eBPF-stamped `(pod_uid, workload_spiffe_hash)` record to its
    /// identity AND per-pod policy scope from a single, consistent slice load.
    ///
    /// The fail-closed identity gate (`identities_by_hash`) and the per-pod-UID
    /// scope index (`scopes_by_pod_uid`) ride one `ArcSwap` generation, so a
    /// reader can never pair a new gate with an old/missing scope: a workload
    /// whose SPIFFE
    /// hash is unchanged but whose scope changed is admitted with the matching
    /// scope from the very generation that vouched for it, satisfying the "never
    /// partial" reload invariant. The scope is returned to the caller (the TCP
    /// accept path captures it once at accept; the HTTP path re-queries per
    /// request via [`Self::policy_scope_for_pod`], itself a single slice load).
    fn resolve_record(
        &self,
        cookie: u64,
        pod_uid: [u8; 16],
        expected_hash: u64,
        orig_dst: SocketAddr,
    ) -> Result<NodeWaypointResolvedConnection, NodeWaypointIdentityError> {
        if pod_uid == [0; 16] {
            return Err(NodeWaypointIdentityError::MissingPodUid(cookie));
        }
        if expected_hash == 0 {
            return Err(NodeWaypointIdentityError::MissingWorkloadHash { cookie, pod_uid });
        }

        // The current slice generation: the authoritative `workload_spiffe_hash`
        // gate AND the SPIFFE → scope index. Loaded ONCE so the gate decision and
        // the derived scope come from the same coherent generation, and so the
        // cached and lazy-enrollment paths fail closed identically when the
        // control plane removes a workload.
        let slice = self.slice.load();

        if let Some(identity) = self.identities_by_pod_uid.get(&pod_uid) {
            let identity = identity.clone();
            if identity.workload_spiffe_hash != expected_hash {
                return Err(NodeWaypointIdentityError::WorkloadHashMismatch {
                    pod_uid,
                    expected: expected_hash,
                    actual: identity.workload_spiffe_hash,
                });
            }
            // Re-validate the cached identity against the *current* slice
            // (finding-#18). Enrollment (below) only happens when the hash is
            // present in the slice gate, but later slice updates replace that
            // generation without touching `identities_by_pod_uid`. If the control
            // plane has since removed this workload (its hash left the gate), or
            // re-keyed the truncated 64-bit hash to a *different* SPIFFE, while
            // the pod keeps stamping the old `(pod_uid, hash)`, fail closed
            // instead of serving the now-orphaned identity — matching the lazy
            // branch's no-matching-slice behavior. In production every enrolled
            // identity's hash was in the gate at enroll time, so this rejects only
            // genuinely removed/re-keyed workloads, never a still-valid one. The
            // stale cache entry is left in place: it never resolves while its hash
            // is absent, is re-validated for free if the workload returns, and is
            // reclaimed by the cgroup-inode / idle sweep when the pod exits.
            //
            // Compare the slice's CURRENT SPIFFE for the hash against the cached
            // `spiffe_id` rather than merely checking presence: a later slice that
            // dropped workload A but introduced a distinct workload B colliding on
            // the same truncated hash maps the hash to B alone (a single entry, no
            // in-slice `Collision`), so a bare presence check would keep resolving
            // the stale A identity and defeat the cross-reload collision guard.
            // `Collision` entries already yield `None` here and fail closed.
            match slice.spiffe_for_hash(expected_hash) {
                Some(current_spiffe) if *current_spiffe == identity.spiffe_id => {}
                _ => return Err(NodeWaypointIdentityError::UnknownPod(pod_uid)),
            }
            // Scope from the SAME generation that just vouched for the identity:
            // captured pods resolve strictly per-UID (None on miss → fail closed).
            let scope = slice.scope_for(&pod_uid);
            return Ok(NodeWaypointResolvedConnection {
                identity,
                policy_scope: scope,
                orig_dst,
            });
        }

        // Lazy enrollment (hash-join). The eBPF side stamps the record with
        // `(pod_uid, workload_spiffe_hash)`; the slice supplies the SPIFFE keyed
        // by that hash (installed at slice apply via the policy-scope snapshot).
        // Join on the hash to enroll `pod_uid` → identity on first sight. No
        // matching slice workload → `UnknownPod` (fail-closed, unchanged). The
        // enrolled identity's hash equals `expected_hash` by construction, so no
        // re-check is needed. Identity AND scope both come from this single
        // `slice` load.
        if let Some(spiffe_id) = slice.spiffe_for_hash(expected_hash).cloned() {
            let scope = slice.scope_for(&pod_uid);
            let identity = self.upsert_identity(NodeWaypointIdentity::new(pod_uid, spiffe_id));
            return Ok(NodeWaypointResolvedConnection {
                identity,
                policy_scope: scope,
                orig_dst,
            });
        }

        Err(NodeWaypointIdentityError::UnknownPod(pod_uid))
    }
}

impl Default for NodeWaypointIdentityResolver {
    fn default() -> Self {
        Self::new(0)
    }
}

/// One enrolled identity as exposed via `GET /node-waypoint/identities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWaypointIdentitySummary {
    pub pod_uid: [u8; 16],
    pub spiffe_id: String,
    pub workload_spiffe_hash: u64,
    pub orig_dst4_cookies: usize,
    pub orig_dst6_cookies: usize,
    pub has_policy_scope: bool,
}

impl NodeWaypointIdentitySummary {
    /// Hyphenated lowercase UUID rendering of the pod UID. Matches the
    /// Kubernetes `metadata.uid` format operators see in `kubectl` output.
    pub fn pod_uid_string(&self) -> String {
        pod_uid_label(&self.pod_uid)
    }
}

pub fn parse_pod_uid(raw: &str) -> Result<[u8; 16], String> {
    let uuid = uuid::Uuid::parse_str(raw)
        .map_err(|error| format!("invalid Kubernetes pod UID '{raw}': {error}"))?;
    Ok(*uuid.as_bytes())
}

pub fn pod_uid_label(pod_uid: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*pod_uid).hyphenated().to_string()
}

pub fn workload_spiffe_hash(spiffe_id: &SpiffeId) -> u64 {
    let digest = Sha256::digest(spiffe_id.as_str().as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

#[cfg(unix)]
fn read_cgroup_fingerprint(path: &Path) -> std::io::Result<CgroupFingerprint> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok(CgroupFingerprint {
        device: meta.dev(),
        inode: meta.ino(),
        ctime_seconds: meta.ctime(),
        ctime_nanoseconds: meta.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn read_cgroup_fingerprint(_path: &Path) -> std::io::Result<CgroupFingerprint> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "cgroup-inode lifecycle binding is Linux/Unix-only",
    ))
}

/// Spawn a periodic sweep task that re-stats every enrolled cgroup path and
/// evicts stale cgroup-bound identities. `interval_secs == 0` disables only
/// this cgroup sweep and returns `None` so callers don't need to track an
/// unused task handle. The task exits when `shutdown` is notified.
pub fn spawn_cgroup_sweep_task(
    resolver: Arc<NodeWaypointIdentityResolver>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if interval_secs == 0 {
        info!(
            "Node-waypoint cgroup sweep disabled (FERRUM_MESH_NODE_WAYPOINT_CGROUP_SWEEP_INTERVAL_SECS=0)"
        );
        return None;
    }
    let period = Duration::from_secs(interval_secs);
    let handle = tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(interval_secs, "Node-waypoint cgroup sweep task started");
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let report = resolver.sweep_cgroup_bound_stale_identities();
                    if report.evicted_inode_changed > 0 || report.evicted_path_missing > 0 {
                        info!(
                            evicted_inode_changed = report.evicted_inode_changed,
                            evicted_path_missing = report.evicted_path_missing,
                            "Node-waypoint cgroup sweep evicted stale identities"
                        );
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("Node-waypoint cgroup sweep task shutting down");
                        return;
                    }
                }
            }
        }
    });
    Some(handle)
}

/// Spawn a periodic GC task for lazily-enrolled identities that have no cgroup
/// binding. This is intentionally independent from the cgroup-inode sweep: an
/// operator may disable cgroup stat sweeps while still needing bounded memory
/// under ordinary pod churn.
pub fn spawn_idle_identity_gc_task(
    resolver: Arc<NodeWaypointIdentityResolver>,
    interval_secs: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if interval_secs == 0 {
        info!(
            "Node-waypoint idle identity GC disabled (FERRUM_MESH_NODE_WAYPOINT_IDLE_GC_INTERVAL_SECS=0)"
        );
        return None;
    }
    let period = Duration::from_secs(interval_secs);
    let handle = tokio::spawn(async move {
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(interval_secs, "Node-waypoint idle identity GC task started");
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let evicted_idle_unreferenced = resolver.sweep_idle_unreferenced_identities();
                    if evicted_idle_unreferenced > 0 {
                        info!(
                            evicted_idle_unreferenced,
                            "Node-waypoint idle identity GC evicted stale identities"
                        );
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("Node-waypoint idle identity GC task shutting down");
                        return;
                    }
                }
            }
        }
    });
    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TrustDomain;
    use crate::modes::mesh::config::{
        MeshPolicy, PolicyScope, Workload, WorkloadSelector, policy_scope_applies_to_workload,
    };

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw).expect("test SPIFFE ID is valid")
    }

    fn orig_dst4(pod_uid: [u8; 16], workload_spiffe_hash: u64) -> OrigDst4 {
        OrigDst4 {
            addr: u32::from_ne_bytes([10, 0, 0, 1]),
            port: 8080,
            pod_uid,
            workload_spiffe_hash,
        }
    }

    fn orig_dst6(pod_uid: [u8; 16], workload_spiffe_hash: u64) -> OrigDst6 {
        OrigDst6 {
            addr: [0, 0, 0, u32::from_ne_bytes([0, 0, 0, 1])],
            port: 8080,
            _pad: 0,
            pod_uid,
            workload_spiffe_hash,
        }
    }

    fn workload(
        spiffe_id: &str,
        namespace: &str,
        service_name: &str,
        labels: HashMap<String, String>,
    ) -> Workload {
        Workload {
            spiffe_id: spiffe(spiffe_id),
            selector: WorkloadSelector {
                labels,
                namespace: Some(namespace.to_string()),
            },
            service_name: service_name.to_string(),
            addresses: Vec::new(),
            ports: Vec::new(),
            trust_domain: TrustDomain::new("td").expect("td"),
            namespace: namespace.to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            remote_provenance: false,
        }
    }

    /// Make the resolver's slice gate vouch for `spiffe_ids` so
    /// `resolve_record`'s current-slice re-validation passes. Production enrolls
    /// identities only through the slice (lazy hash-join), so a still-valid
    /// identity's hash is always present in the slice's `identities_by_hash`
    /// gate. These older unit tests pre-seed `identities_by_pod_uid` directly via
    /// `upsert_identity` for brevity, so they must also seed the slice the
    /// resolver now revalidates against.
    fn vouch_for_workloads(resolver: &NodeWaypointIdentityResolver, spiffe_ids: &[&str]) {
        let workloads: Vec<Workload> = spiffe_ids
            .iter()
            .map(|spiffe_id| workload(spiffe_id, "default", "app", HashMap::new()))
            .collect();
        resolver.install_policy_scopes_from_workloads(&workloads);
    }

    #[test]
    fn resolve_cookie_returns_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        // A uid-bearing workload supplies BOTH the slice gate (identities_by_hash)
        // and the per-pod scope (scopes_by_pod_uid) for this captured pod's UID.
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::new(),
            "11111111-1111-1111-1111-111111111111",
        )]);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        let (resolved, scope) = resolver.resolve_cookie(7).expect("identity resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id.as_str(), "spiffe://td/ns/default/sa/api");
        // The vouching workload carries a scope (namespace "default"), so the
        // returned scope comes from the same generation that vouched.
        assert!(
            scope.is_some(),
            "a vouched workload's resolve must return its scope from the same slice"
        );
    }

    #[test]
    fn resolve_cookie_lazily_enrolls_identity_from_slice_hash_index() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("33333333-3333-3333-3333-333333333333").unwrap();
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/web");
        let hash = workload_spiffe_hash(&spiffe_id);

        // Slice apply installs the hash → SPIFFE index from the workloads;
        // production never pre-enrolls via upsert_identity.
        let workloads = vec![workload_with_uid(
            "spiffe://td/ns/default/sa/web",
            "default",
            "web",
            HashMap::new(),
            "33333333-3333-3333-3333-333333333333",
        )];
        let snapshot = resolver.build_policy_scope_snapshot_from_workloads(&workloads);
        resolver.install_policy_scope_snapshot(snapshot);

        // The eBPF side mirrors a cookie record carrying (pod_uid, hash); no
        // identity exists in identities_by_pod_uid yet.
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        // Resolution enrolls the identity by hash-join on first sight, and the
        // scope is returned from the same slice generation.
        let (resolved, scope) = resolver
            .resolve_cookie(7)
            .expect("lazy enrollment resolves the cookie");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id.as_str(), "spiffe://td/ns/default/sa/web");
        assert!(
            scope.is_some(),
            "lazy enrollment must return the workload's scope from the same slice load"
        );

        // A cookie whose hash matches no slice workload still fails closed.
        let other_pod = parse_pod_uid("44444444-4444-4444-4444-444444444444").unwrap();
        resolver.record_orig_dst4(8, orig_dst4(other_pod, 0xdead_beef));
        assert_eq!(
            resolver
                .resolve_cookie(8)
                .expect_err("unknown hash fails closed"),
            NodeWaypointIdentityError::UnknownPod(other_pod)
        );
    }

    #[test]
    fn cached_identity_fails_closed_after_slice_drops_its_workload() {
        // GAP-2M fail-closed regression: once a pod is lazily enrolled it is
        // cached in `identities_by_pod_uid`. A later slice that removes its
        // workload publishes a new generation whose `identities_by_hash` gate no
        // longer carries the hash, but does not touch the cache, so the
        // cached-identity branch must re-validate against the current slice and
        // fail closed — otherwise a decommissioned workload keeps resolving as
        // long as the pod stamps the old (pod_uid, hash).
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("55555555-5555-5555-5555-555555555555").unwrap();
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/web");
        let hash = workload_spiffe_hash(&spiffe_id);

        // Slice vouches for the workload; the pod enrolls lazily on first resolve.
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/web"]);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));
        let (resolved, _scope) = resolver
            .resolve_cookie(7)
            .expect("resolves while the workload is in the slice");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert!(
            resolver.identities_by_pod_uid.contains_key(&pod_uid),
            "first resolve must cache the enrolled identity"
        );

        // The control plane removes that workload (the slice now carries a
        // different one), so its hash leaves the index.
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/other"]);

        // The pod keeps stamping the old (pod_uid, hash). The cached-identity
        // branch must fail closed rather than serve the orphaned identity.
        assert_eq!(
            resolver
                .resolve_cookie(7)
                .expect_err("a removed workload must fail closed even when cached"),
            NodeWaypointIdentityError::UnknownPod(pod_uid)
        );

        // If the workload returns, the cached identity is re-validated for free
        // (no eviction, no re-enrollment): resolution succeeds again.
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/web"]);
        let (reresolved, _scope) = resolver
            .resolve_cookie(7)
            .expect("a returning workload re-validates the cached identity");
        assert_eq!(reresolved.spiffe_id, spiffe_id);
    }

    #[test]
    fn resolve_cookie_fails_closed_for_unknown_cookie() {
        let resolver = NodeWaypointIdentityResolver::new(0);

        let error = resolver
            .resolve_cookie(7)
            .expect_err("unknown cookie must fail closed");
        assert_eq!(error, NodeWaypointIdentityError::UnknownCookie(7));
    }

    #[test]
    fn resolve_cookie_uses_synchronous_fallback_on_miss() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        let identity =
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/reviews"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/reviews"]);

        // `cookie_records` is empty — simulates the 200ms orig-dst poll not
        // having mirrored the just-stamped accept cookie yet. The injected
        // synchronous fallback resolves cookie 42.
        resolver.set_cookie_fallback(Box::new(move |cookie| {
            (cookie == 42).then_some((pod_uid, hash, "10.0.0.42:8080".parse().unwrap()))
        }));

        let (resolved, _scope) = resolver
            .resolve_cookie(42)
            .expect("synchronous fallback resolves the fresh cookie");
        assert_eq!(resolved.pod_uid, pod_uid);

        // A fallback miss still fails closed.
        assert_eq!(
            resolver
                .resolve_cookie(99)
                .expect_err("fallback miss fails closed"),
            NodeWaypointIdentityError::UnknownCookie(99)
        );

        // Clearing the fallback reverts to pure in-memory resolution.
        resolver.clear_cookie_fallback();
        assert_eq!(
            resolver
                .resolve_cookie(42)
                .expect_err("no fallback after clear fails closed"),
            NodeWaypointIdentityError::UnknownCookie(42)
        );
    }

    #[test]
    fn resolve_cookie_returns_ipv6_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/api"]);
        resolver.record_orig_dst6(7, orig_dst6(pod_uid, hash));

        let (resolved, _scope) = resolver.resolve_cookie(7).expect("IPv6 identity resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id.as_str(), "spiffe://td/ns/default/sa/api");
    }

    #[test]
    fn resolve_cookie_metadata_preserves_original_destination() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("12121212-1212-1212-1212-121212121212").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/api"]);

        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));
        let resolved = resolver
            .resolve_cookie_metadata(7)
            .expect("IPv4 original destination is preserved");
        assert_eq!(resolved.orig_dst, "10.0.0.1:8080".parse().unwrap());

        resolver.record_orig_dst6(8, orig_dst6(pod_uid, hash));
        let resolved = resolver
            .resolve_cookie_metadata(8)
            .expect("IPv6 original destination is preserved");
        assert_eq!(resolved.orig_dst, "[::1]:8080".parse().unwrap());
    }

    #[test]
    fn resolve_cookie_metadata_for_expected_pod_rejects_wrong_listener_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let actual_pod = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let expected_pod = parse_pod_uid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let identity =
            NodeWaypointIdentity::new(actual_pod, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::new(),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )]);
        resolver.record_orig_dst4(7, orig_dst4(actual_pod, hash));

        let error = match resolver.resolve_cookie_metadata_for_expected_pod(7, expected_pod) {
            Ok(_) => panic!("listener pod UID mismatch must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            NodeWaypointIdentityError::PodUidMismatch {
                expected: expected_pod,
                actual: actual_pod,
            }
        );
    }

    #[test]
    fn resolve_cookie_fails_closed_for_missing_pod_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        resolver.record_orig_dst4(7, orig_dst4([0; 16], 0));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("zero pod UID must fail closed");
        assert_eq!(error, NodeWaypointIdentityError::MissingPodUid(7));
    }

    #[test]
    fn resolve_cookie_fails_closed_for_missing_workload_hash() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, 0));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("zero workload hash must fail closed");
        assert_eq!(
            error,
            NodeWaypointIdentityError::MissingWorkloadHash { cookie: 7, pod_uid }
        );
    }

    #[test]
    fn resolve_cookie_fails_closed_for_hash_mismatch() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, 42));

        let error = resolver
            .resolve_cookie(7)
            .expect_err("mismatched SPIFFE hash must fail closed");
        assert!(matches!(
            error,
            NodeWaypointIdentityError::WorkloadHashMismatch { .. }
        ));
    }

    #[test]
    fn policy_scope_cache_uses_canonical_policy_helper() {
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "reviews".to_string());
        let resolver = NodeWaypointIdentityResolver::new(0);
        // Install the scope via the slice keyed by this pod's UID; the enrolled
        // identity below is incidental now that scope is resolved per-UID, not
        // derived from the identity's SPIFFE.
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/reviews",
            "default",
            "reviews",
            labels.clone(),
            "11111111-1111-1111-1111-111111111111",
        )]);
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/reviews"),
        ));

        let policy = MeshPolicy {
            name: "reviews-only".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels,
                    namespace: Some("default".to_string()),
                },
            },
            rules: Vec::new(),
        };
        let from_cache = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("policy scope should be installed");

        assert!(from_cache.policy_applies(&policy));
        assert_eq!(
            from_cache.policy_applies(&policy),
            policy_scope_applies_to_workload(&policy, "default", &from_cache.labels)
        );
    }

    #[cfg(unix)]
    #[test]
    fn upsert_with_cgroup_captures_inode_and_sweep_keeps_identity_when_inode_unchanged() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let arc = resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            cgroup_path.clone(),
        );
        assert!(
            arc.cgroup_inode.is_some(),
            "successful enrollment must record inode"
        );
        assert!(
            arc.cgroup_fingerprint.is_some(),
            "successful enrollment must record full cgroup fingerprint"
        );

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.total_evicted(), 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.passes, 1);
        assert_eq!(snapshot.inode_changed_total, 0);
        assert_eq!(snapshot.path_missing_total, 0);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_path_disappears() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            cgroup_path.clone(),
        );
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));

        // Simulate pod removal: delete the cgroup dir.
        std::fs::remove_dir_all(&cgroup_path).expect("remove cgroup dir");

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_path_missing, 1);
        assert_eq!(report.evicted_inode_changed, 0);
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
        // Per-pod scope is slice-driven and decoupled from identity eviction
        // (reclaimed by slice updates, not by this sweep) — see
        // `later_slice_dropping_workload_reclaims_pod_scope`.
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.path_missing_total, 1);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_inode_changes() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");
        let current_fingerprint =
            read_cgroup_fingerprint(&cgroup_path).expect("read cgroup fingerprint");
        let stale_inode = current_fingerprint.inode.wrapping_add(1);

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"))
                .with_cgroup(cgroup_path.clone(), stale_inode),
        );

        // Simulate a restart with a stale enrolled inode. Recreate-based tests
        // are flaky because filesystems may reuse the removed directory's inode.
        assert_ne!(stale_inode, current_fingerprint.inode);

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_inode_changed, 1);
        assert_eq!(report.evicted_path_missing, 0);
        assert!(
            !resolver.identities_by_pod_uid.contains_key(&pod_uid),
            "stale identity for pod-restart UID must be evicted"
        );
        let snapshot = resolver.cgroup_sweep_snapshot();
        assert_eq!(snapshot.inode_changed_total, 1);
    }

    #[cfg(unix)]
    #[test]
    fn sweep_evicts_identity_when_cgroup_fingerprint_changes_even_if_inode_matches() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod.scope");
        std::fs::create_dir(&cgroup_path).expect("create cgroup dir");
        let current_fingerprint =
            read_cgroup_fingerprint(&cgroup_path).expect("read cgroup fingerprint");
        let stale_fingerprint = CgroupFingerprint {
            ctime_nanoseconds: current_fingerprint.ctime_nanoseconds.wrapping_add(1),
            ..current_fingerprint
        };

        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"))
                .with_cgroup_fingerprint(cgroup_path.clone(), stale_fingerprint),
        );

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_inode_changed, 1);
        assert_eq!(report.evicted_path_missing, 0);
        assert!(
            !resolver.identities_by_pod_uid.contains_key(&pod_uid),
            "stale identity must be evicted even if the inode number was reused"
        );
    }

    /// Scope is keyed by the slice's per-pod-UID index, NOT by the enrolled
    /// identity, so `remove_identity` (cgroup/idle reclamation) leaves the pod's
    /// scope intact — it is reclaimed by slice updates, not identity lifecycle.
    /// The previous model cleared scope on identity removal; that coupling is
    /// what let a captured pod fall back to a same-SPIFFE workload's scope when
    /// its own identity churned, which H1 removes.
    #[test]
    fn remove_identity_does_not_affect_slice_driven_scope() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::new(),
            "11111111-1111-1111-1111-111111111111",
        )]);
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        assert!(resolver.policy_scope_for_pod(&pod_uid).is_some());

        resolver.remove_identity(&pod_uid);

        // Identity is gone, but the slice still carries the pod's UID → scope
        // stays available (decoupled from identity lifecycle).
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_some(),
            "scope is slice-driven and must survive identity removal"
        );
    }

    #[test]
    fn remove_identity_is_a_noop_when_identity_already_missing() {
        // Scope is slice-driven (keyed by pod UID), so a pod whose UID is not in
        // the slice's per-UID index has no scope regardless of identity state,
        // and removing a never-enrolled identity is a harmless no-op. The
        // installed workload below is uid-less, so it contributes no per-UID
        // scope for this pod (it only populates the SPIFFE-keyed VM index).
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.install_policy_scopes_from_workloads(&[workload(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::new(),
        )]);

        // No per-UID scope for this pod, and no identity was ever enrolled.
        assert!(resolver.policy_scope_for_pod(&pod_uid).is_none());
        resolver.remove_identity(&pod_uid);
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "a pod whose UID is absent from the slice has no scope"
        );
    }

    #[test]
    fn sweep_keeps_referenced_unbound_identity() {
        // An unbound (lazily-enrolled, no cgroup) identity that is still
        // referenced by a live cookie record must be kept: the idle pass only
        // reclaims pods that no longer have any live cookie, and the cgroup pass
        // ignores unbound entries entirely.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        let identity =
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/legacy"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        // A live cookie record keeps the pod referenced.
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.total_evicted(), 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[test]
    fn sweep_evicts_unreferenced_lazy_identity() {
        // GAP-2M lifecycle (P2): the production lazy hash-join enrollment binds
        // no cgroup, so the cgroup pass never reclaims it and nothing calls
        // remove_identity. When the pod churns away its cookies age out of
        // cookie_records; the idle pass must then reclaim the orphaned identity
        // so it does not grow without bound. (Per-pod scope is slice-driven and
        // reclaimed by slice updates, not by this sweep — see
        // `later_slice_dropping_workload_reclaims_pod_scope`.)
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("66666666-6666-6666-6666-666666666666").unwrap();
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/web");
        let hash = workload_spiffe_hash(&spiffe_id);

        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/web"]);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));
        resolver
            .resolve_cookie(7)
            .expect("lazy enrollment resolves while the pod is live");
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));

        // While the cookie is live the idle pass keeps it.
        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_idle_unreferenced, 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));

        // Pod dies → its accept-side cookies age out of the mirrored map.
        resolver.retain_cookie_records(&std::collections::HashSet::new());

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_idle_unreferenced, 1);
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[test]
    fn cgroup_bound_sweep_does_not_reclaim_unbound_idle_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("99999999-9999-9999-9999-999999999999").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/web"),
        ));

        let report = resolver.sweep_cgroup_bound_stale_identities();
        assert_eq!(report.total_evicted(), 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));

        let evicted = resolver.sweep_idle_unreferenced_identities();
        assert_eq!(evicted, 1);
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[tokio::test]
    async fn cgroup_sweep_disabled_does_not_disable_idle_identity_gc_task() {
        let resolver = Arc::new(NodeWaypointIdentityResolver::new(0));
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        assert!(spawn_cgroup_sweep_task(resolver.clone(), 0, shutdown_rx.clone()).is_none());

        let handle = spawn_idle_identity_gc_task(resolver, 30, shutdown_rx)
            .expect("idle identity GC should be independently spawnable");
        handle.abort();
        let _ = handle.await;
    }

    #[test]
    fn sweep_keeps_unbound_identity_held_by_open_connection() {
        // Finding-2 regression: HTTP/HBONE connections hold the resolved
        // identity Arc for their lifetime and re-query the per-pod scope on
        // every request. If the BPF LRU evicts a live connection's cookie, the
        // cookie-reference signal goes stale — but the sweep must NOT evict the
        // pod (else later streams on that connection lose per-pod scoping). An
        // outstanding Arc ref (strong_count > 1) keeps it un-evictable.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("88888888-8888-8888-8888-888888888888").unwrap();
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/web");
        let hash = workload_spiffe_hash(&spiffe_id);

        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/web",
            "default",
            "web",
            HashMap::new(),
            "88888888-8888-8888-8888-888888888888",
        )]);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));
        // Simulate an open connection: resolve and HOLD the returned Arc, the
        // way the accept path stores it on the connection for its lifetime.
        let (conn_identity, _scope) = resolver.resolve_cookie(7).expect("resolves and enrolls");

        // The connection's cookie ages out of the mirror (BPF LRU eviction)
        // while the connection is still open.
        resolver.retain_cookie_records(&std::collections::HashSet::new());

        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(
            report.evicted_idle_unreferenced, 0,
            "a pod whose identity an open connection still holds must not be evicted"
        );
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
        assert!(resolver.policy_scope_for_pod(&pod_uid).is_some());

        // Once the connection closes (Arc dropped), the next sweep reclaims it.
        drop(conn_identity);
        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_idle_unreferenced, 1);
        assert!(!resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[cfg(unix)]
    #[test]
    fn sweep_keeps_cgroup_bound_identity_when_unreferenced() {
        // cgroup-bound identities are the cgroup pass's domain; the idle pass
        // must never reclaim them even with no live cookie reference, or it
        // would race the cgroup lifecycle.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("77777777-7777-7777-7777-777777777777").unwrap();
        let tmp = tempfile::tempdir().expect("temp dir");
        let cgroup_path = tmp.path().join("pod");
        std::fs::create_dir_all(&cgroup_path).expect("create cgroup dir");

        let identity = resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/web")),
            cgroup_path,
        );
        assert!(identity.cgroup_inode.is_some(), "binding must be recorded");

        // No cookie record references the pod, but it is cgroup-bound.
        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(report.evicted_idle_unreferenced, 0);
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[cfg(unix)]
    #[test]
    fn upsert_with_cgroup_records_none_inode_on_stat_failure() {
        // Missing path: enrollment still inserts the identity (so a control
        // plane that doesn't yet provide a cgroup path is not blocked), but
        // marks `cgroup_inode = None` and the sweep ignores it.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("33333333-3333-3333-3333-333333333333").unwrap();
        let missing = PathBuf::from("/this/path/does/not/exist/ferrum-test");

        let identity = resolver.upsert_identity_with_cgroup(
            NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api")),
            missing,
        );
        assert!(
            identity.cgroup_inode.is_none(),
            "stat failure must leave cgroup_inode unset"
        );
        // A live cookie keeps the pod referenced so the idle pass leaves it
        // alone; the point under test is that the *cgroup* pass ignores an
        // entry with no recorded inode (it never tries to stat the missing path).
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, identity.workload_spiffe_hash));
        let report = resolver.sweep_cgroup_stale_identities();
        assert_eq!(
            report.total_evicted(),
            0,
            "cgroup pass ignores identities without a recorded inode"
        );
        assert!(resolver.identities_by_pod_uid.contains_key(&pod_uid));
    }

    #[test]
    fn per_pod_scope_keyed_by_pod_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);

        let pod_a = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let pod_b = parse_pod_uid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let pod_orphan = parse_pod_uid("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();

        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_a,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_b,
            spiffe("spiffe://td/ns/default/sa/billing"),
        ));
        // pod_orphan has no Workload entry, so it must not appear in the map.
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_orphan,
            spiffe("spiffe://td/ns/default/sa/orphan"),
        ));

        let workloads = vec![
            workload_with_uid(
                "spiffe://td/ns/default/sa/api",
                "default",
                "api",
                HashMap::from([("app".to_string(), "api".to_string())]),
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ),
            workload_with_uid(
                "spiffe://td/ns/default/sa/billing",
                "default",
                "billing",
                HashMap::from([("app".to_string(), "billing".to_string())]),
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ),
        ];

        // Installing the slice publishes the per-pod-UID scope index, keyed by
        // each workload's `metadata.uid`. `policy_scope_for_pod` looks the pod up
        // by the exact UID the eBPF stamps — no enrolled identity required.
        resolver.install_policy_scopes_from_workloads(&workloads);

        let scope_a = resolver
            .policy_scope_for_pod(&pod_a)
            .expect("api workload scope");
        assert_eq!(scope_a.namespace, "default");
        assert_eq!(scope_a.labels.get("app").map(String::as_str), Some("api"));
        let scope_b = resolver
            .policy_scope_for_pod(&pod_b)
            .expect("billing workload scope");
        assert_eq!(
            scope_b.labels.get("app").map(String::as_str),
            Some("billing")
        );
        assert!(
            resolver.policy_scope_for_pod(&pod_orphan).is_none(),
            "pod with no Workload entry must derive no scope"
        );
    }

    fn workload_with_uid(
        spiffe_id: &str,
        namespace: &str,
        service_name: &str,
        labels: HashMap<String, String>,
        pod_uid: &str,
    ) -> Workload {
        Workload {
            pod_uid: Some(pod_uid.to_string()),
            ..workload(spiffe_id, namespace, service_name, labels)
        }
    }

    /// Two pods that share a service account — and therefore one SPIFFE ID —
    /// but carry different labels (a canary `version` split, or two ReplicaSets
    /// mid-rollout) must each resolve their OWN scope. Keying scope by SPIFFE
    /// alone collapsed them to the label *intersection*, silently dropping
    /// selector-scoped policy for the diverging label; keying by pod UID keeps
    /// them distinct. Covers both the per-request (`policy_scope_for_pod`) and
    /// the accept (`resolve_cookie`) lookups.
    #[test]
    fn per_pod_uid_scope_distinguishes_pods_sharing_a_spiffe() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let uid_v1 = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let uid_v2 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        let pod_v1 = parse_pod_uid(uid_v1).unwrap();
        let pod_v2 = parse_pod_uid(uid_v2).unwrap();
        let shared_spiffe = "spiffe://td/ns/default/sa/web";

        let workloads = vec![
            workload_with_uid(
                shared_spiffe,
                "default",
                "web",
                HashMap::from([
                    ("app".to_string(), "web".to_string()),
                    ("version".to_string(), "v1".to_string()),
                ]),
                uid_v1,
            ),
            workload_with_uid(
                shared_spiffe,
                "default",
                "web",
                HashMap::from([
                    ("app".to_string(), "web".to_string()),
                    ("version".to_string(), "v2".to_string()),
                ]),
                uid_v2,
            ),
        ];
        resolver.install_policy_scopes_from_workloads(&workloads);

        // Per-request path: keyed by the exact pod UID the eBPF stamps — no
        // enrolled identity required, and no cross-pod label merge.
        let scope_v1 = resolver
            .policy_scope_for_pod(&pod_v1)
            .expect("v1 pod scope");
        let scope_v2 = resolver
            .policy_scope_for_pod(&pod_v2)
            .expect("v2 pod scope");
        assert_eq!(
            scope_v1.labels.get("version").map(String::as_str),
            Some("v1"),
            "v1 pod must keep its own labels, not the intersection"
        );
        assert_eq!(
            scope_v2.labels.get("version").map(String::as_str),
            Some("v2"),
            "v2 pod must keep its own labels, not the intersection"
        );

        // Accept path: resolve_cookie returns the SAME per-pod scope (both pods
        // stamp the shared SPIFFE hash, but the pod UID disambiguates the scope).
        let hash = workload_spiffe_hash(&spiffe(shared_spiffe));
        resolver.record_orig_dst4(51, orig_dst4(pod_v2, hash));
        let (resolved, scope) = resolver.resolve_cookie(51).expect("v2 cookie resolves");
        assert_eq!(resolved.pod_uid, pod_v2);
        assert_eq!(
            scope
                .expect("v2 accept scope")
                .labels
                .get("version")
                .map(String::as_str),
            Some("v2"),
        );
    }

    /// H1 fail-closed: a captured pod (the eBPF stamps its pod UID) whose only
    /// matching workload in the slice is uid-less (a VM/WorkloadEntry sharing the
    /// SPIFFE) must NOT borrow that workload's scope. Resolving the pod through
    /// the SPIFFE-keyed index would evaluate scoped policy against the wrong
    /// labels and could let a selector-scoped DENY be evaded; the pod fails
    /// closed (no per-UID scope) until its own uid-bearing workload is in the
    /// slice. The SPIFFE-keyed index stays for genuine uid-less workloads, but
    /// `policy_scope_for_pod` (captured pods) never consults it.
    #[test]
    fn captured_pod_does_not_borrow_uidless_spiffe_scope() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/vm"),
        ));
        // pod_uid: None → contributes only to the SPIFFE-keyed index, never to
        // the per-UID index a captured pod resolves through.
        resolver.install_policy_scopes_from_workloads(&[workload(
            "spiffe://td/ns/default/sa/vm",
            "default",
            "vm",
            HashMap::from([("app".to_string(), "vm".to_string())]),
        )]);
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "a captured pod must not borrow a same-SPIFFE uid-less workload's scope (fail closed)"
        );
    }

    #[test]
    fn identities_snapshot_lists_enrolled_pods_sorted_by_uid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let pod_b = parse_pod_uid("22222222-2222-2222-2222-222222222222").unwrap();
        let identity_b =
            NodeWaypointIdentity::new(pod_b, spiffe("spiffe://td/ns/default/sa/billing"));
        let identity_a = NodeWaypointIdentity::new(pod_a, spiffe("spiffe://td/ns/default/sa/api"));
        let hash_a = identity_a.workload_spiffe_hash;
        let hash_b = identity_b.workload_spiffe_hash;

        // Insert b first so the snapshot has to sort.
        resolver.upsert_identity(identity_b);
        resolver.upsert_identity(identity_a);
        // Two cookies for pod_a, one for pod_b.
        resolver.record_orig_dst4(11, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst4(12, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst6(21, orig_dst6(pod_b, hash_b));

        let snapshot = resolver.identities_snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].pod_uid, pod_a);
        assert_eq!(snapshot[1].pod_uid, pod_b);
        assert_eq!(snapshot[0].spiffe_id, "spiffe://td/ns/default/sa/api");
        assert_eq!(snapshot[0].orig_dst4_cookies, 2);
        assert_eq!(snapshot[0].orig_dst6_cookies, 0);
        assert!(!snapshot[0].has_policy_scope);
        assert_eq!(snapshot[1].orig_dst4_cookies, 0);
        assert_eq!(snapshot[1].orig_dst6_cookies, 1);
        assert_eq!(resolver.identity_count(), 2);
        assert_eq!(resolver.cookie_count(), (2, 1));
    }

    #[test]
    fn identities_snapshot_reports_policy_scope_presence() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        resolver.upsert_identity(identity);

        let snapshot_pre = resolver.identities_snapshot();
        assert!(!snapshot_pre[0].has_policy_scope);

        // `has_policy_scope` reflects whether the current slice carries a per-pod
        // scope for this pod's exact UID (mirroring what authz resolves).
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::new(),
            "11111111-1111-1111-1111-111111111111",
        )]);

        let snapshot_post = resolver.identities_snapshot();
        assert!(snapshot_post[0].has_policy_scope);
    }

    #[test]
    fn identities_snapshot_with_cookie_totals_counts_orphans_in_totals_only() {
        // Regression guard for the cold-path "single pass" contract used by
        // GET /node-waypoint/identities: the returned totals include cookies
        // whose pod_uid has no enrolled identity (so the admin "cookies"
        // summary reflects full eBPF state), but the per-identity summaries
        // omit those orphans.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let pod_orphan = parse_pod_uid("33333333-3333-3333-3333-333333333333").unwrap();
        let identity_a = NodeWaypointIdentity::new(pod_a, spiffe("spiffe://td/ns/default/sa/api"));
        let hash_a = identity_a.workload_spiffe_hash;
        resolver.upsert_identity(identity_a);
        // Enrolled pod gets one v4 + one v6 cookie. Orphan pod (not enrolled)
        // gets one v6 cookie, representing eBPF capture racing identity
        // registration.
        resolver.record_orig_dst4(11, orig_dst4(pod_a, hash_a));
        resolver.record_orig_dst6(12, orig_dst6(pod_a, hash_a));
        resolver.record_orig_dst6(99, orig_dst6(pod_orphan, 0xdead_beef));

        let (snapshot, totals) = resolver.identities_snapshot_with_cookie_totals();
        // Snapshot contains only the enrolled pod.
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].pod_uid, pod_a);
        assert_eq!(snapshot[0].orig_dst4_cookies, 1);
        assert_eq!(snapshot[0].orig_dst6_cookies, 1);
        // Totals include the orphan v6 cookie.
        assert_eq!(totals, (1, 2));
        // And matches cookie_count() (which iterates separately).
        assert_eq!(resolver.cookie_count(), totals);
    }

    #[test]
    fn identities_snapshot_summary_renders_canonical_uuid() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let snapshot = resolver.identities_snapshot();
        assert_eq!(
            snapshot[0].pod_uid_string(),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    /// Inverse of the pre-H1 behavior: when two pods share a SPIFFE but carry
    /// divergent labels, keying scope by pod UID gives each pod ALL of its own
    /// labels. The old SPIFFE-keyed model intersected them, silently dropping
    /// the divergent label (here `app`) from every pod's scope — and with it any
    /// selector-scoped policy that matched on that label.
    #[test]
    fn per_pod_scope_keeps_all_own_labels_not_intersection() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_api = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let pod_billing = parse_pod_uid("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();

        let workloads = vec![
            workload_with_uid(
                "spiffe://td/ns/default/sa/shared",
                "default",
                "api",
                HashMap::from([
                    ("app".to_string(), "api".to_string()),
                    ("version".to_string(), "v1".to_string()),
                ]),
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ),
            workload_with_uid(
                "spiffe://td/ns/default/sa/shared",
                "default",
                "billing",
                HashMap::from([
                    ("app".to_string(), "billing".to_string()),
                    ("version".to_string(), "v1".to_string()),
                ]),
                "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            ),
        ];
        resolver.install_policy_scopes_from_workloads(&workloads);

        // Each pod keeps its OWN app label (no intersection), plus the shared one.
        let api = resolver
            .policy_scope_for_pod(&pod_api)
            .expect("api pod scope");
        assert_eq!(api.namespace, "default");
        assert_eq!(api.labels.get("app").map(String::as_str), Some("api"));
        assert_eq!(api.labels.get("version").map(String::as_str), Some("v1"));

        let billing = resolver
            .policy_scope_for_pod(&pod_billing)
            .expect("billing pod scope");
        assert_eq!(
            billing.labels.get("app").map(String::as_str),
            Some("billing")
        );
        assert_eq!(
            billing.labels.get("version").map(String::as_str),
            Some("v1")
        );
    }

    #[test]
    fn install_policy_scopes_from_workloads_updates_late_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let workloads = vec![workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )];
        resolver.install_policy_scopes_from_workloads(&workloads);

        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let scope = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("late identity should pick up current workload scope");
        assert_eq!(scope.labels.get("app").map(String::as_str), Some("api"));
    }

    #[test]
    fn staged_policy_scope_snapshot_does_not_publish_until_installed() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        let workloads = vec![workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )];
        let snapshot = resolver.build_policy_scope_snapshot_from_workloads(&workloads);

        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "staging scopes for a candidate slice must not mutate live authz state"
        );

        resolver.install_policy_scope_snapshot(snapshot);

        let scope = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("accepted slice should publish staged scope");
        assert_eq!(scope.labels.get("app").map(String::as_str), Some("api"));
    }

    /// Scope publication needs no enrolled identity: building a staged snapshot
    /// from a uid-bearing workload and installing it publishes the per-UID scope
    /// even though no identity is ever enrolled for the pod. Scope is keyed by
    /// the slice's `metadata.uid`, decoupled from identity enrollment order. The
    /// staged snapshot must still not leak into live authz before install.
    #[test]
    fn slice_install_publishes_scope_without_enrolled_identity() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();

        let workloads = vec![workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )];
        let snapshot = resolver.build_policy_scope_snapshot_from_workloads(&workloads);

        // No identity enrolled, and the candidate snapshot is not yet installed.
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "staged scopes must not leak into live authz before install"
        );

        resolver.install_policy_scope_snapshot(snapshot);

        let scope = resolver
            .policy_scope_for_pod(&pod_uid)
            .expect("install publishes the per-UID scope with no identity required");
        assert_eq!(scope.labels.get("app").map(String::as_str), Some("api"));
    }

    /// Per-pod scope is reclaimed by SLICE updates, not identity lifecycle: a
    /// later slice that no longer carries the pod's workload (its UID leaves the
    /// per-UID index) makes the pod fail closed, even while its identity is still
    /// enrolled. This is the bound that keeps `scopes_by_pod_uid` from growing —
    /// install rebuilds it wholesale from the new workload set.
    #[test]
    fn later_slice_dropping_workload_reclaims_pod_scope() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_uid,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));
        resolver.install_policy_scopes_from_workloads(&[workload_with_uid(
            "spiffe://td/ns/default/sa/api",
            "default",
            "api",
            HashMap::from([("app".to_string(), "api".to_string())]),
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )]);
        assert!(resolver.policy_scope_for_pod(&pod_uid).is_some());

        // A later slice drops the workload (e.g. the pod was deleted). The
        // identity may still be enrolled, but the pod's UID is no longer in the
        // per-UID index → it fails closed.
        resolver.install_policy_scopes_from_workloads(std::iter::empty());
        assert!(
            resolver.policy_scope_for_pod(&pod_uid).is_none(),
            "a workload absent from the new slice must reclaim the pod's scope"
        );
    }

    #[test]
    fn empty_slice_derives_no_per_pod_scope() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_a = parse_pod_uid("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        resolver.upsert_identity(NodeWaypointIdentity::new(
            pod_a,
            spiffe("spiffe://td/ns/default/sa/api"),
        ));

        // Installing an empty workload set leaves the slice's per-UID scope index
        // empty, so the pod's UID is absent and it resolves no per-pod scope.
        resolver.install_policy_scopes_from_workloads(std::iter::empty());
        assert!(resolver.policy_scope_for_pod(&pod_a).is_none());
    }

    #[test]
    fn resolve_cookie_path_is_two_dashmap_gets_in_warm_case() {
        // Regression guard for the documented hot-path contract:
        // - 1x cookie_records.get
        // - 1x identities_by_pod_uid.get
        // - 1x slice.load + HashMap lookups (gate re-validation + per-UID scope
        //   lookup; one ArcSwap load serves both, no allocation)
        // - 0 allocations on success
        //
        // We assert the structural shape (two DashMaps, one ArcSwap load, one
        // Arc clone) by making the same call twice and confirming both arms hit
        // warm entries without re-inserting anything. If a future refactor adds
        // a third DashMap probe or an alloc, this test still passes, but the
        // module-level rustdoc is the source of truth and any change here that
        // adds work must update that contract.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        let stored = resolver.upsert_identity(identity);
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/api"]);
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, hash));

        let (first, _scope) = resolver.resolve_cookie(7).expect("warm v4 cookie");
        let (second, _scope) = resolver.resolve_cookie(7).expect("repeat warm v4 cookie");
        // Same Arc reused, no rebuild.
        assert!(Arc::ptr_eq(&first, &stored));
        assert!(Arc::ptr_eq(&second, &stored));
    }

    #[test]
    fn resolve_cookie_v6_path_does_not_probe_a_dead_v4_map() {
        // Pre-unification the resolver probed orig_dst4 first then fell
        // through to orig_dst6 on miss, so every IPv6 connection paid a
        // wasted v4 lookup. Now the families share `cookie_records`. This
        // test asserts: a v6-only registration is found by resolve_cookie
        // without any v4 record being present.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("11111111-1111-1111-1111-111111111111").unwrap();
        let identity = NodeWaypointIdentity::new(pod_uid, spiffe("spiffe://td/ns/default/sa/api"));
        let hash = identity.workload_spiffe_hash;
        resolver.upsert_identity(identity);
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/api"]);
        resolver.record_orig_dst6(42, orig_dst6(pod_uid, hash));

        let (resolved, _scope) = resolver
            .resolve_cookie(42)
            .expect("v6-only cookie resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        // The v4/v6 family stamp is what the admin endpoint reports, so verify
        // we attributed the cookie to v6 not v4 and the snapshot stays honest.
        let snap = resolver.identities_snapshot();
        assert_eq!(snap[0].orig_dst4_cookies, 0);
        assert_eq!(snap[0].orig_dst6_cookies, 1);
        assert_eq!(resolver.cookie_count(), (0, 1));
    }

    #[test]
    fn workload_spiffe_hash_is_stable_first_sha256_u64() {
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/api");
        let digest = Sha256::digest(spiffe_id.as_str().as_bytes());
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&digest[..8]);

        assert_eq!(
            workload_spiffe_hash(&spiffe_id),
            u64::from_be_bytes(expected)
        );
    }

    #[test]
    fn collided_workload_spiffe_hash_fails_closed() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("99999999-9999-9999-9999-999999999999").unwrap();
        let collision_hash = 0xfeed_face_cafe_beefu64;
        let spiffe_a = spiffe("spiffe://td/ns/default/sa/a");
        let spiffe_b = spiffe("spiffe://td/ns/default/sa/b");
        let mut identities_by_hash = HashMap::new();
        insert_identity_gate_entry(&mut identities_by_hash, collision_hash, &spiffe_a);
        insert_identity_gate_entry(&mut identities_by_hash, collision_hash, &spiffe_b);
        resolver.install_policy_scope_snapshot(NodeWaypointPolicyScopeSnapshot {
            slice: NodeWaypointSlice {
                identities_by_hash,
                scopes_by_pod_uid: HashMap::new(),
            },
        });
        resolver.record_orig_dst4(7, orig_dst4(pod_uid, collision_hash));

        assert_eq!(
            resolver
                .resolve_cookie(7)
                .expect_err("hash collision must fail closed before lazy enrollment"),
            NodeWaypointIdentityError::UnknownPod(pod_uid)
        );

        resolver.upsert_identity(NodeWaypointIdentity {
            pod_uid,
            spiffe_id: spiffe_a,
            workload_spiffe_hash: collision_hash,
            cgroup_path: None,
            cgroup_inode: None,
            cgroup_fingerprint: None,
        });

        assert_eq!(
            resolver
                .resolve_cookie(7)
                .expect_err("cached identity with collided hash must fail closed"),
            NodeWaypointIdentityError::UnknownPod(pod_uid)
        );
    }

    #[test]
    fn cross_reload_hash_collision_invalidates_cached_identity() {
        // A pod is enrolled as workload A under truncated hash H. A later slice
        // drops A and introduces a DISTINCT workload B that collides on the same
        // truncated 64-bit hash (a single, non-`Collision` gate entry). The
        // cached A identity must stop resolving — a bare presence check on H
        // would keep serving the orphaned A. (Real SHA-256 collisions can't be
        // produced by hand, so — like `collided_workload_spiffe_hash_fails_closed`
        // — the cached identity is constructed with the chosen hash directly.)
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod_uid = parse_pod_uid("88888888-8888-8888-8888-888888888888").unwrap();
        let hash = 0x0102_0304_0506_0708u64;
        let spiffe_a = spiffe("spiffe://td/ns/default/sa/a");
        let spiffe_b = spiffe("spiffe://td/ns/default/sa/b");

        resolver.upsert_identity(NodeWaypointIdentity {
            pod_uid,
            spiffe_id: spiffe_a.clone(),
            workload_spiffe_hash: hash,
            cgroup_path: None,
            cgroup_inode: None,
            cgroup_fingerprint: None,
        });
        resolver.record_orig_dst4(11, orig_dst4(pod_uid, hash));

        // Slice still maps H → A: the cached identity resolves (sanity).
        let mut gate_a = HashMap::new();
        insert_identity_gate_entry(&mut gate_a, hash, &spiffe_a);
        resolver.install_policy_scope_snapshot(NodeWaypointPolicyScopeSnapshot {
            slice: NodeWaypointSlice {
                identities_by_hash: gate_a,
                scopes_by_pod_uid: HashMap::new(),
            },
        });
        let (identity, _) = resolver
            .resolve_cookie(11)
            .expect("cached A resolves while the slice still maps H → A");
        assert_eq!(identity.spiffe_id, spiffe_a);

        // Slice re-keys H → B only (A removed, B collides on the truncated hash).
        let mut gate_b = HashMap::new();
        insert_identity_gate_entry(&mut gate_b, hash, &spiffe_b);
        resolver.install_policy_scope_snapshot(NodeWaypointPolicyScopeSnapshot {
            slice: NodeWaypointSlice {
                identities_by_hash: gate_b,
                scopes_by_pod_uid: HashMap::new(),
            },
        });
        assert_eq!(
            resolver
                .resolve_cookie(11)
                .expect_err("cached A must fail closed once the hash re-keys to B"),
            NodeWaypointIdentityError::UnknownPod(pod_uid)
        );
    }

    // ── GAP-1b: orig-dst bridge support ──

    #[test]
    fn retain_cookie_records_ages_out_evicted_cookies() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod = [3u8; 16];
        resolver.record_orig_dst4(1, orig_dst4(pod, 10));
        resolver.record_orig_dst4(2, orig_dst4(pod, 10));
        resolver.record_orig_dst6(3, orig_dst6(pod, 10));
        assert_eq!(resolver.cookie_record_count(), 3);

        // Simulate a bridge poll where only cookies 1 and 3 are still live in
        // the BPF LRU map; cookie 2 was evicted by the kernel.
        let live: std::collections::HashSet<u64> = [1u64, 3u64].into_iter().collect();
        resolver.retain_cookie_records(&live);

        assert_eq!(resolver.cookie_record_count(), 2);
    }

    #[test]
    fn clear_cookie_records_drops_all_on_node_agent_restart() {
        let resolver = NodeWaypointIdentityResolver::new(0);
        let pod = [4u8; 16];
        resolver.record_orig_dst4(1, orig_dst4(pod, 10));
        resolver.record_orig_dst6(2, orig_dst6(pod, 10));
        assert_eq!(resolver.cookie_record_count(), 2);

        // Node-agent restart re-pins fresh maps; the bridge clears stale
        // cookie records so an evicted-pod cookie can't resolve.
        resolver.clear_cookie_records();
        assert_eq!(resolver.cookie_record_count(), 0);
    }

    #[test]
    fn bridge_recorded_cookie_resolves_to_identity() {
        // Exercises the resolver's cookie→identity lookup mechanics IN
        // ISOLATION: a record (as record_orig_dst4 would mirror it) plus a
        // pre-enrolled identity under the same cookie resolves. Production now
        // resolves the *accept-side* socket cookie bridged by the GAP-2M
        // sock_ops program and enrolls identities through the lazy hash-join at
        // resolve time; here we seed both sides by hand (the slice index via
        // `vouch_for_workloads`, the identity via `upsert_identity`) and a single
        // cookie record, so this pins the resolver logic rather than proving the
        // live end-to-end datapath.
        let resolver = NodeWaypointIdentityResolver::new(0);
        let spiffe_id = spiffe("spiffe://td/ns/default/sa/api");
        let pod_uid = [9u8; 16];
        let hash = workload_spiffe_hash(&spiffe_id);

        resolver.upsert_identity(NodeWaypointIdentity::new(pod_uid, spiffe_id.clone()));
        vouch_for_workloads(&resolver, &["spiffe://td/ns/default/sa/api"]);
        // The bridge mirrors the BPF record (stamped with pod_uid + hash by
        // the connect hook) into the resolver.
        resolver.record_orig_dst4(77, orig_dst4(pod_uid, hash));

        let (resolved, _scope) = resolver.resolve_cookie(77).expect("cookie resolves");
        assert_eq!(resolved.pod_uid, pod_uid);
        assert_eq!(resolved.spiffe_id, spiffe_id);
    }
}

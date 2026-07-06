//! In-pod-network-namespace outbound capture listeners (node-waypoint).
//!
//! # Why this exists
//!
//! In node-waypoint topology the eBPF `connect4`/`connect6` hooks rewrite a
//! captured pod's outbound `connect()` to `127.0.0.1:15001` or `[::1]:15001`
//! (the outbound capture port). Those destinations are **pod loopback** — they
//! never leave the pod's network namespace — so the connection can only be
//! accepted by sockets that live *inside that pod's netns*. Host/proxy-netns
//! loopback listeners can therefore never receive captured traffic from any pod:
//! there is nothing listening on the pod's own loopback.
//!
//! The listener itself is scoped to exactly one pod netns, so the accept path
//! passes the listener's expected pod UID as the primary source-identity gate:
//! the current mesh slice must still contain that pod UID before traffic is
//! admitted. The GAP-2M `sock_ops` cookie bridge remains the source of
//! original-destination metadata when available; it re-keys the orig-dst record
//! by `(netns cookie, 4-tuple)` at active-established and recovers it at
//! passive-established using the accept-side callback's netns cookie. Live
//! kernels may report the proxy accepting task's netns for that passive callback
//! even though the listener was bound in the workload netns. The eBPF bridge
//! therefore has a best-effort any-netns fallback, and the accept path still
//! validates any resolved cookie record against the listener pod UID before
//! using its original destination.
//!
//! # What this does
//!
//! For each pod the node-agent has enrolled for capture, the mesh proxy opens
//! `127.0.0.1:15001` and `[::1]:15001` listeners **inside that pod's network
//! namespace** (entering via `setns(CLONE_NEWNET)` on a dedicated OS thread —
//! the same pattern as [`crate::ebpf::veth`]) and runs the normal proxy accept
//! loop on the returned sockets. Each listening socket's fd is process-global
//! once created, so the accept loop runs on the shared tokio runtime in the host
//! netns; only the `bind()` happens in the pod netns. The accepted connection
//! then resolves its source pod identity from the listener pod UID and uses
//! cookie metadata, when present, only after validating it against that UID.
//!
//! The node-agent (which watches pods and holds their cgroup paths) publishes
//! the enrolled-pod set to a pinned registry directory; this manager polls it
//! and reconciles **one listener per address family per pod netns** (deduplicated
//! by netns inode, since a pod's sandbox + containers share one netns). Pods that
//! come and go drive listener open/close.
//!
//! # Verification
//!
//! Linux-only (`setns`, `/proc/<pid>/ns/net`); non-Linux targets compile to a
//! stub that reports unsupported. The reconcile bookkeeping and the registry
//! parser are unit-tested with a mock backend; the `setns`/`bind` path and the
//! full pod-loopback datapath are **not** unit- or CI-testable (they need a live
//! multi-pod node) and are exercised only in a real cluster. Always on for
//! NodeWaypoint topology; the registry directory path is configurable via
//! `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::modes::mesh::node_waypoint::parse_pod_uid;

use super::{ListenerTlsSource, ProxyState, SourceIpOverride, run_accept_loop};

/// A pod the node-agent has enrolled for node-waypoint capture. `cgroup_path`
/// is the pod cgroup directory the node-agent resolved; the manager walks it to
/// find a live PID and, through `/proc/<pid>/ns/net`, the pod's network
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCaptureTarget {
    pub pod_uid: String,
    pub cgroup_path: String,
    /// Source pod IPs, if the node-agent published them. Used to override the
    /// loopback peer of accepted in-netns capture connections so client-IP
    /// authz conditions, logs, and IP-keyed plugins see the real same-family pod
    /// IP rather than `127.0.0.1` / `::1`.
    pub source_ips: PodCaptureSourceIps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PodCaptureSourceIps {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl PodCaptureSourceIps {
    fn source_for_family(self, family: CaptureFamily) -> Option<IpAddr> {
        match family {
            CaptureFamily::Ipv4 => self.ipv4.map(IpAddr::V4),
            CaptureFamily::Ipv6 => self.ipv6.map(IpAddr::V6),
        }
    }

    fn source_for_addr(self, addr: SocketAddr) -> Option<IpAddr> {
        match addr {
            SocketAddr::V4(_) => self.source_for_family(CaptureFamily::Ipv4),
            SocketAddr::V6(_) => self.source_for_family(CaptureFamily::Ipv6),
        }
    }
}

/// Source of the current enrolled-pod set. Production reads a directory the
/// node-agent publishes; tests inject a fake.
pub trait PodCaptureSource: Send + Sync {
    fn list_targets(&self) -> Vec<PodCaptureTarget>;
}

/// Filesystem registry source: the node-agent writes one file per enrolled pod,
/// named `<pod_uid>`, whose first line is the pod cgroup path and whose
/// optional keyed lines carry same-family source IP overrides (`ipv4=<addr>`,
/// `ipv6=<addr>`). Removing the file (on pod teardown) drops the pod from the
/// set. This mirrors the existing "pinned path is the entire node-agent ↔
/// mesh-proxy IPC surface" contract.
pub struct DirectoryCaptureSource {
    dir: PathBuf,
}

impl DirectoryCaptureSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl PodCaptureSource for DirectoryCaptureSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            // Registry dir absent (node-agent not up yet, or no enrolled pods):
            // an empty set is the correct steady state, not an error.
            return Vec::new();
        };
        let mut targets = Vec::new();
        for entry in entries.flatten() {
            let pod_uid = entry.file_name().to_string_lossy().to_string();
            if pod_uid.is_empty() || pod_uid.starts_with('.') {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            // Line 1: pod cgroup path (required). Subsequent optional lines are
            // family-specific source IPs (`ipv4=<addr>`, `ipv6=<addr>`).
            let mut lines = contents.lines();
            let cgroup_path = lines.next().unwrap_or("").trim().to_string();
            if cgroup_path.is_empty() {
                continue;
            }
            let mut source_ips = PodCaptureSourceIps::default();
            for line in lines {
                let line = line.trim();
                if let Some(value) = line.strip_prefix("ipv4=") {
                    source_ips.ipv4 = value.trim().parse::<Ipv4Addr>().ok();
                } else if let Some(value) = line.strip_prefix("ipv6=") {
                    source_ips.ipv6 = value.trim().parse::<Ipv6Addr>().ok();
                }
            }
            targets.push(PodCaptureTarget {
                pod_uid,
                cgroup_path,
                source_ips,
            });
        }
        targets
    }
}

/// Opens/closes the actual in-netns listeners. Abstracted so the manager's
/// reconcile diff is unit-testable with a mock; production uses
/// [`ProxyNetnsBackend`].
pub trait NetnsBackend: Send + Sync + 'static {
    /// Stable per-netns key for the pod (the netns inode). An error means no
    /// live PID can be found in the cgroup (pod terminating, race), the proxy
    /// cannot inspect the host cgroup/proc view it needs, or the platform can't
    /// resolve it. The pod is skipped this round and retried next poll.
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String>;

    /// Open a `capture_addr` listener inside the pod's netns and spawn its
    /// accept loop. Returns a stop handle (setting it `true` shuts the loop
    /// down) or `None` if the listener could not be created.
    fn open_listener(
        &self,
        target: &PodCaptureTarget,
        capture_addr: SocketAddr,
    ) -> Option<OpenedNetnsListener>;
}

pub struct OpenedNetnsListener {
    stop: watch::Sender<bool>,
    source_ip: Option<watch::Sender<Option<IpAddr>>>,
}

impl OpenedNetnsListener {
    fn new(stop: watch::Sender<bool>, source_ip: Option<watch::Sender<Option<IpAddr>>>) -> Self {
        Self { stop, source_ip }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CaptureFamily {
    Ipv4,
    Ipv6,
}

impl CaptureFamily {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CaptureEndpoint {
    family: CaptureFamily,
    addr: SocketAddr,
}

fn capture_endpoints_from_port(port: u16) -> [CaptureEndpoint; 2] {
    [
        CaptureEndpoint {
            family: CaptureFamily::Ipv4,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        },
        CaptureEndpoint {
            family: CaptureFamily::Ipv6,
            addr: SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        },
    ]
}

struct ActiveFamilyListener {
    stop: watch::Sender<bool>,
    source_ip_tx: Option<watch::Sender<Option<IpAddr>>>,
}

impl ActiveFamilyListener {
    fn close(&self) {
        let _ = self.stop.send(true);
    }
}

/// Open in-netns listeners for one network namespace, keyed in the manager by
/// netns inode.
struct ActiveListener {
    listeners: HashMap<CaptureFamily, ActiveFamilyListener>,
    /// Pods sharing this netns (normally exactly one; a pod's sandbox and
    /// containers share its netns). Kept for observability and so a netns stays
    /// open while any of its pods is still enrolled.
    pod_uids: HashSet<String>,
    /// The source pod IPs this listener's accept loops are currently overriding
    /// with. Tracked so later status changes can update running accept loops
    /// without rebinding pod-loopback sockets.
    source_ips: PodCaptureSourceIps,
}

impl ActiveListener {
    fn close(&self) {
        for listener in self.listeners.values() {
            listener.close();
        }
    }

    fn has_family(&self, family: CaptureFamily) -> bool {
        self.listeners.contains_key(&family)
    }
}

/// Resolve the readiness-marker path `<dir>/<pod_uid>`, rejecting a `pod_uid`
/// that is empty or could escape `dir` (path separators / `.` / `..`). The pod
/// UIDs come from registry filenames the node-agent already guards, but the
/// marker path is built independently here, so guard it again (defense in
/// depth — the manager writes into a directory shared with the node-agent).
fn ready_marker_path(dir: &Path, pod_uid: &str) -> Option<PathBuf> {
    if pod_uid.is_empty()
        || pod_uid == "."
        || pod_uid == ".."
        || pod_uid.contains('/')
        || pod_uid.contains('\\')
    {
        return None;
    }
    Some(dir.join(pod_uid))
}

fn ready_family_dir(legacy_ready_dir: &Path, family: CaptureFamily) -> PathBuf {
    let family_dir = match family {
        CaptureFamily::Ipv4 => ".ready4",
        CaptureFamily::Ipv6 => ".ready6",
    };
    legacy_ready_dir
        .parent()
        .map(|parent| parent.join(family_dir))
        .unwrap_or_else(|| legacy_ready_dir.join(family_dir))
}

fn ready_marker_dirs_for_family(dir: &Path, family: CaptureFamily) -> Vec<PathBuf> {
    match family {
        CaptureFamily::Ipv4 => vec![dir.to_path_buf(), ready_family_dir(dir, family)],
        CaptureFamily::Ipv6 => vec![ready_family_dir(dir, family)],
    }
}

fn write_marker_file(dir: &Path, pod_uid: &str, family: CaptureFamily) {
    let Some(path) = ready_marker_path(dir, pod_uid) else {
        return;
    };
    if let Err(error) = std::fs::create_dir_all(dir) {
        warn!(pod_uid, dir = %dir.display(), family = family.as_str(), %error, "Failed to create in-netns readiness marker dir");
        return;
    }
    if let Err(error) = std::fs::write(&path, b"") {
        warn!(pod_uid, path = %path.display(), family = family.as_str(), %error, "Failed to write in-netns readiness marker");
    }
}

/// Publish a listener-readiness marker for `pod_uid` and `family`. Best-effort:
/// a failure to create the directory or write the file is logged and swallowed;
/// the affected family remains visibly unready and captured connects continue to
/// fail closed until a listener exists.
fn write_ready_marker(dir: &Path, pod_uid: &str, family: CaptureFamily) {
    for marker_dir in ready_marker_dirs_for_family(dir, family) {
        write_marker_file(&marker_dir, pod_uid, family);
    }
}

fn remove_marker_file(dir: &Path, pod_uid: &str, family: CaptureFamily) {
    let Some(path) = ready_marker_path(dir, pod_uid) else {
        return;
    };
    if let Err(error) = std::fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(pod_uid, path = %path.display(), family = family.as_str(), %error, "Failed to remove in-netns readiness marker");
    }
}

/// Remove listener-readiness markers for `pod_uid`. Missing files are success.
fn remove_ready_marker(dir: &Path, pod_uid: &str, family: CaptureFamily) {
    for marker_dir in ready_marker_dirs_for_family(dir, family) {
        remove_marker_file(&marker_dir, pod_uid, family);
    }
}

fn remove_all_ready_markers(dir: &Path, pod_uid: &str) {
    for family in [CaptureFamily::Ipv4, CaptureFamily::Ipv6] {
        remove_ready_marker(dir, pod_uid, family);
    }
}

fn open_missing_family_listeners<B: NetnsBackend>(
    backend: &B,
    listener: &mut ActiveListener,
    target: &PodCaptureTarget,
    endpoints: [CaptureEndpoint; 2],
    ready_dir: Option<&Path>,
    netns: u64,
) {
    for endpoint in endpoints {
        if listener.has_family(endpoint.family) {
            continue;
        }
        match backend.open_listener(target, endpoint.addr) {
            Some(opened) => {
                info!(
                    netns_inode = netns,
                    pod_uid = %target.pod_uid,
                    source_ips = ?listener.source_ips,
                    capture_addr = %endpoint.addr,
                    family = endpoint.family.as_str(),
                    "Opened node-waypoint in-netns capture listener"
                );
                if let Some(dir) = ready_dir {
                    for uid in &listener.pod_uids {
                        write_ready_marker(dir, uid, endpoint.family);
                    }
                }
                listener.listeners.insert(
                    endpoint.family,
                    ActiveFamilyListener {
                        stop: opened.stop,
                        source_ip_tx: opened.source_ip,
                    },
                );
            }
            None => {
                warn!(
                    netns_inode = netns,
                    pod_uid = %target.pod_uid,
                    capture_addr = %endpoint.addr,
                    family = endpoint.family.as_str(),
                    "Failed to open node-waypoint in-netns capture listener for address family; will retry"
                );
            }
        }
    }
}

/// Reconciles in-netns capture listeners against the enrolled-pod set.
pub struct NetnsCaptureManager<B: NetnsBackend> {
    capture_endpoints: [CaptureEndpoint; 2],
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    /// netns inode → its open listener.
    active: HashMap<u64, ActiveListener>,
    /// When set, per-pod readiness markers are written when that pod's listeners
    /// open and removed when they close. Redirect hooks attach at enrollment and
    /// fail closed until a listener exists; these markers expose family readiness
    /// to the live gate and keep stale-listener cleanup observable. `None`
    /// disables marker publishing (unit tests).
    ready_dir: Option<PathBuf>,
    /// Last registry UID set logged, so startup/churn diagnostics show whether
    /// the ambient proxy can see the node-agent's hostPath registry without
    /// emitting the same line every poll.
    last_registry_uids: HashSet<String>,
    /// Last unresolved-netns reason per pod UID, so persistent cgroup/proc
    /// visibility failures remain clear without warning every poll.
    unresolved_reasons: HashMap<String, String>,
}

impl<B: NetnsBackend> NetnsCaptureManager<B> {
    pub fn new(
        capture_addr: SocketAddr,
        source: Arc<dyn PodCaptureSource>,
        backend: B,
        poll_interval: Duration,
    ) -> Self {
        Self {
            capture_endpoints: capture_endpoints_from_port(capture_addr.port()),
            source,
            backend,
            poll_interval,
            active: HashMap::new(),
            ready_dir: None,
            last_registry_uids: HashSet::new(),
            unresolved_reasons: HashMap::new(),
        }
    }

    /// Set the legacy readiness marker directory (`<registry>/.ready`). The
    /// manager writes the historical IPv4 marker there, plus sibling `.ready4`
    /// and `.ready6` directories for family-level evidence. `None` (the default)
    /// disables marker publishing — used by unit tests.
    pub fn with_ready_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.ready_dir = dir;
        self
    }

    /// Poll-and-reconcile until `shutdown` flips to `true`, then close every
    /// listener.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            capture_addrs = ?self.capture_endpoints.iter().map(|endpoint| endpoint.addr).collect::<Vec<_>>(),
            poll_secs = self.poll_interval.as_secs_f64(),
            "Node-waypoint in-netns capture manager started"
        );
        loop {
            self.reconcile_once();
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        self.shutdown_all();
    }

    /// One reconcile pass: open listeners for newly enrolled pod netns, close
    /// listeners whose pods are all gone. Returns the count of currently active
    /// listeners (used by tests).
    fn reconcile_once(&mut self) -> usize {
        let targets = self.source.list_targets();

        // Resolve every enrolled pod's current netns once. Three buckets matter
        // for reconcile:
        //   * `desired`           netns inode → pods that resolve to it now
        //   * `resolved_uid_netns` pod UID → the netns it resolves to now
        //   * `unresolved_uids`    pods present in the registry but whose netns
        //                          can't be resolved this round (terminating /
        //                          PID race) — the transient-grace set
        // and `registry_uids` is every pod the registry currently lists.
        let mut desired: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut resolved_uid_netns: HashMap<String, u64> = HashMap::new();
        let mut unresolved_uids: HashSet<String> = HashSet::new();
        let registry_uids: HashSet<String> = targets.iter().map(|t| t.pod_uid.clone()).collect();
        if registry_uids != self.last_registry_uids {
            info!(
                target_count = registry_uids.len(),
                pod_uids = ?registry_uids,
                "Node-waypoint capture registry changed"
            );
            self.last_registry_uids = registry_uids.clone();
        }
        for target in &targets {
            match self.backend.netns_key(target) {
                Ok(netns) => {
                    if self.unresolved_reasons.remove(&target.pod_uid).is_some() {
                        info!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            netns_inode = netns,
                            "Node-waypoint capture: pod netns resolved after retry"
                        );
                    }
                    desired
                        .entry(netns)
                        .or_default()
                        .insert(target.pod_uid.clone());
                    resolved_uid_netns.insert(target.pod_uid.clone(), netns);
                }
                Err(error) => {
                    unresolved_uids.insert(target.pod_uid.clone());
                    let previous = self
                        .unresolved_reasons
                        .insert(target.pod_uid.clone(), error.clone());
                    if previous.as_deref() == Some(error.as_str()) {
                        debug!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            %error,
                            "Node-waypoint capture: pod netns still not resolvable; will retry"
                        );
                    } else {
                        warn!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            %error,
                            "Node-waypoint capture: pod netns not resolvable; will retry"
                        );
                    }
                }
            }
        }
        self.unresolved_reasons
            .retain(|uid, _| unresolved_uids.contains(uid));

        // Close a listener when none of its pods still justify it. A pod on the
        // listener for netns N justifies keeping N open when it is still in the
        // registry AND either (a) still resolves to N, or (b) is unresolvable
        // this round — the transient PID/netns-miss grace case (container
        // restarting while its registry file persists), which must not flap the
        // listener. A pod that has left the registry, OR that now resolves to a
        // DIFFERENT netns (sandbox/netns restart, or an in-place registry
        // rewrite between polls), no longer justifies N: leaving N open would
        // leak the old socket and pin the dead netns alive. The pod's new netns
        // gets its own listener in the open pass below.
        let gone: Vec<u64> = self
            .active
            .iter()
            .filter(|(netns, listener)| {
                !listener.pod_uids.iter().any(|uid| {
                    registry_uids.contains(uid)
                        && match resolved_uid_netns.get(uid) {
                            Some(resolved) => *resolved == **netns,
                            None => unresolved_uids.contains(uid),
                        }
                })
            })
            .map(|(netns, _)| *netns)
            .collect();
        for netns in gone {
            if let Some(listener) = self.active.remove(&netns) {
                listener.close();
                if let Some(dir) = &self.ready_dir {
                    for uid in &listener.pod_uids {
                        remove_all_ready_markers(dir, uid);
                    }
                }
                info!(
                    netns_inode = netns,
                    "Closed node-waypoint in-netns capture listener"
                );
            }
        }

        // Open listeners for newly-seen netns; for an existing netns, refresh
        // pod membership and update the source-IP overrides when pod IPs change.
        // The accept loops read the overrides from watch channels, so a pod that
        // was enrolled before `status.podIPs` existed (override `None`), or
        // whose IPs later changed, does not need socket rebinds just to report
        // current pod IPs to authz, logs, and IP-keyed plugins.
        for (netns, pod_uids) in desired {
            // The source IPs this netns's listeners should report: take them
            // from the same target that would open them. Stable while one pod
            // owns the netns (the normal case — a pod's sandbox and containers
            // share it).
            let desired_target = targets.iter().find(|t| pod_uids.contains(&t.pod_uid));
            let desired_source_ips = desired_target.map(|t| t.source_ips).unwrap_or_default();

            if let Some(listener) = self.active.get_mut(&netns) {
                let existing_source_ips = listener.source_ips;
                let previous_pod_uids = listener.pod_uids.clone();
                // Source pod IPs changed. Keep existing listeners and push the
                // new same-family overrides into their accept loops. Rebinding a
                // pod-loopback socket would either require SO_REUSEPORT (unsafe
                // inside a workload netns) or create a no-listener window for
                // redirected egress.
                listener.pod_uids = pod_uids.clone();
                if existing_source_ips != desired_source_ips {
                    listener.source_ips = desired_source_ips;
                    for (family, family_listener) in &listener.listeners {
                        if let Some(source_ip_tx) = &family_listener.source_ip_tx {
                            let _ =
                                source_ip_tx.send(desired_source_ips.source_for_family(*family));
                        }
                    }
                    debug!(
                        netns_inode = netns,
                        old_ips = ?existing_source_ips,
                        new_ips = ?desired_source_ips,
                        "Node-waypoint capture: source pod IPs changed; updated in-netns listener overrides"
                    );
                }
                if let Some(dir) = &self.ready_dir {
                    for uid in previous_pod_uids.difference(&listener.pod_uids) {
                        remove_all_ready_markers(dir, uid);
                    }
                    for uid in listener.pod_uids.difference(&previous_pod_uids) {
                        for family in listener.listeners.keys().copied() {
                            write_ready_marker(dir, uid, family);
                        }
                    }
                }
                let endpoints = self.capture_endpoints;
                let ready_dir = self.ready_dir.clone();
                if let Some(target) = desired_target {
                    open_missing_family_listeners(
                        &self.backend,
                        listener,
                        target,
                        endpoints,
                        ready_dir.as_deref(),
                        netns,
                    );
                }
                continue;
            }

            // New netns: open listeners. Any target in this netns can open them —
            // they share the namespace. IPv4 and IPv6 are independent so a pod can
            // keep the working family serving while the other fails closed and
            // retries on the next poll.
            let Some(target) = desired_target else {
                continue;
            };
            let mut listener = ActiveListener {
                listeners: HashMap::new(),
                pod_uids,
                source_ips: desired_source_ips,
            };
            open_missing_family_listeners(
                &self.backend,
                &mut listener,
                target,
                self.capture_endpoints,
                self.ready_dir.as_deref(),
                netns,
            );
            if listener.listeners.is_empty() {
                warn!(
                    netns_inode = netns,
                    pod_uid = %target.pod_uid,
                    "Failed to open any node-waypoint in-netns capture listener; will retry"
                );
            } else {
                self.active.insert(netns, listener);
            }
        }

        self.active.len()
    }

    fn shutdown_all(&mut self) {
        let ready_dir = self.ready_dir.clone();
        for (_, listener) in self.active.drain() {
            listener.close();
            if let Some(dir) = &ready_dir {
                for uid in &listener.pod_uids {
                    remove_all_ready_markers(dir, uid);
                }
            }
        }
    }
}

/// Production backend: resolves pod netns from its cgroup and opens a real
/// capture listener inside it, feeding accepted connections into the shared
/// proxy accept loop.
pub struct ProxyNetnsBackend {
    state: ProxyState,
    conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    global_shutdown: watch::Receiver<bool>,
}

impl ProxyNetnsBackend {
    pub fn new(
        state: ProxyState,
        conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
        mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
        global_shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            conn_semaphore,
            mesh_direction,
            global_shutdown,
        }
    }
}

impl NetnsBackend for ProxyNetnsBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        imp::netns_inode_for_cgroup(&target.cgroup_path).map_err(|error| error.to_string())
    }

    fn open_listener(
        &self,
        target: &PodCaptureTarget,
        capture_addr: SocketAddr,
    ) -> Option<OpenedNetnsListener> {
        let expected_pod_uid = match parse_pod_uid(&target.pod_uid) {
            Ok(pod_uid) => pod_uid,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    %error,
                    "Node-waypoint in-netns listener rejected invalid pod UID"
                );
                return None;
            }
        };
        let std_listener =
            match imp::bind_capture_listener_in_pod_netns(&target.cgroup_path, capture_addr) {
                Ok(listener) => listener,
                Err(error) => {
                    warn!(
                        pod_uid = %target.pod_uid,
                        cgroup = %target.cgroup_path,
                        %error,
                        "Node-waypoint in-netns bind failed"
                    );
                    return None;
                }
            };
        let listener = match tokio::net::TcpListener::from_std(std_listener) {
            Ok(listener) => listener,
            Err(error) => {
                warn!(pod_uid = %target.pod_uid, %error, "Adopting in-netns listener fd failed");
                return None;
            }
        };

        // Per-listener stop signal. A forwarder flips it when the global
        // shutdown fires so the accept loop stops on either signal; the
        // forwarder ALSO exits when the listener is closed directly (via
        // `ActiveListener::close`, e.g. on pod removal), so a churned listener
        // never leaves an idle task lingering until process shutdown.
        let (stop_tx, stop_rx) = watch::channel(false);
        let (source_ip_tx, source_ip_rx) =
            watch::channel(target.source_ips.source_for_addr(capture_addr));
        let forwarder_stop = stop_tx.clone();
        let mut closed = stop_tx.subscribe();
        let mut global = self.global_shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = global.changed() => {
                        if changed.is_err() || *global.borrow() {
                            let _ = forwarder_stop.send(true);
                            break;
                        }
                    }
                    changed = closed.changed() => {
                        // Listener closed directly (pod removed) — nothing to
                        // forward; just stop this task.
                        if changed.is_err() || *closed.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        let state = self.state.clone();
        let conn_semaphore = self.conn_semaphore.clone();
        let mesh_direction = self.mesh_direction;
        tokio::spawn(async move {
            run_accept_loop(
                listener,
                Arc::new(state),
                ListenerTlsSource::Static {
                    tls_config: None,
                    record_mesh_mtls_metric: false,
                },
                conn_semaphore,
                stop_rx,
                mesh_direction,
                0,
                SourceIpOverride::Dynamic(source_ip_rx),
                Some(expected_pod_uid),
            )
            .await;
        });

        Some(OpenedNetnsListener::new(stop_tx, Some(source_ip_tx)))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::io;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    /// Resolve the pod's netns identity (the `net` namespace inode) from a live
    /// PID in its cgroup. The inode is stable for the life of the netns and is a
    /// good dedup key across the pod sandbox + container cgroups.
    pub(crate) fn netns_inode_for_cgroup(cgroup_path: &str) -> io::Result<u64> {
        let pid = first_pid_in_cgroup(cgroup_path)?;
        let path = format!("/proc/{pid}/ns/net");
        let meta = std::fs::metadata(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to stat pod netns {path}: {error}"),
            )
        })?;
        Ok(meta.ino())
    }

    /// The inode of the CALLING process's own (host/proxy) network namespace.
    /// The Ambient UDP producer runs in the host netns, so this is the identity
    /// of the node namespace. It is compared against a resolved pod netns inode
    /// to refuse installing pod TPROXY/OUTPUT rules in the NODE namespace when a
    /// registry entry resolves to the host netns (a `hostNetwork` workload, or a
    /// stale/manual entry pointing at a host-netns cgroup). Fails closed: any
    /// error means the caller cannot prove the target is NOT the host netns.
    pub(crate) fn host_netns_inode() -> io::Result<u64> {
        let meta = std::fs::metadata("/proc/self/ns/net").map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to stat host netns /proc/self/ns/net: {error}"),
            )
        })?;
        Ok(meta.ino())
    }

    /// Open a STABLE handle to a pod's network namespace (`/proc/<pid>/ns/net`)
    /// resolved from its cgroup. The returned `File` keeps the netns alive even
    /// if the resolving PID later exits, so the Ambient UDP producer can `setns`
    /// to it for the whole capture lifetime (the capture socket AND every
    /// per-session reply socket) without re-resolving a live PID each time. Used
    /// by `netns_udp_capture`.
    pub(crate) fn open_pod_netns_handle(cgroup_path: &str) -> io::Result<File> {
        let pid = first_pid_in_cgroup(cgroup_path)?;
        let path = format!("/proc/{pid}/ns/net");
        File::open(&path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to open pod netns {path}: {error}"),
            )
        })
    }

    /// Run `f` inside the network namespace `netns` on a DEDICATED OS thread,
    /// restoring the thread's original netns before it exits. `setns(CLONE_NEWNET)`
    /// mutates the CALLING thread's netns, so it must never run on a tokio worker
    /// (it would corrupt unrelated tasks); a scoped thread confines the switch and
    /// any fd/socket `f` returns is process-global and outlives the thread. Used by
    /// the Ambient UDP producer to bind capture/reply sockets and run the in-netns
    /// iptables setup/teardown inside a pod netns. Shares the exact `setns` recipe
    /// with `bind_capture_listener_in_pod_netns`.
    pub(crate) fn run_in_netns<T, F>(netns: &File, f: F) -> io::Result<T>
    where
        T: Send,
        F: FnOnce() -> io::Result<T> + Send,
    {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = NetnsGuard::enter_fd(netns.as_raw_fd())?;
                    f()
                    // `_guard` drops here, on this thread, restoring the original
                    // netns before the scoped thread joins.
                })
                .join()
                .map_err(|_| io::Error::other("in-netns worker thread panicked"))?
        })
    }

    /// Bind `addr` (the capture loopback endpoint) inside the pod's network
    /// namespace and return the listening socket.
    ///
    /// `setns(CLONE_NEWNET)` changes the **calling thread's** netns, so it must
    /// NOT run on a tokio worker (it would corrupt unrelated tasks). We run it
    /// on a dedicated OS thread that restores its netns before exiting; the
    /// returned socket fd is process-global and outlives the thread.
    pub(super) fn bind_capture_listener_in_pod_netns(
        cgroup_path: &str,
        addr: SocketAddr,
    ) -> std::io::Result<std::net::TcpListener> {
        let pid = first_pid_in_cgroup(cgroup_path)?;
        std::thread::spawn(move || -> std::io::Result<std::net::TcpListener> {
            let _guard = NetnsGuard::enter(pid)?;
            let domain = match addr {
                SocketAddr::V4(_) => socket2::Domain::IPV4,
                SocketAddr::V6(_) => socket2::Domain::IPV6,
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            if addr.is_ipv6() {
                socket.set_only_v6(true)?;
            }
            socket.set_reuse_address(true)?;
            // Do not enable SO_REUSEPORT here. The socket is bound inside the
            // workload pod's network namespace, so pod processes with the same
            // effective UID could otherwise join the reuseport group on this
            // loopback tuple and intercept captured egress before Ferrum's
            // accept path performs identity resolution and policy checks.
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            socket.listen(1024)?;
            Ok(socket.into())
            // `_guard` drops here, on this thread, restoring the original netns
            // before the thread exits.
        })
        .join()
        .map_err(|_| std::io::Error::other("in-netns bind thread panicked"))?
    }

    /// Breadth-first walk of the pod cgroup subtree, returning the first PID
    /// from any `cgroup.procs`. Mirrors the discovery used by
    /// `crate::ebpf::veth`. Bounded to avoid runaway traversal.
    fn first_pid_in_cgroup(cgroup_path: &str) -> io::Result<u32> {
        let root = PathBuf::from(cgroup_path);
        let metadata = std::fs::metadata(&root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("failed to stat pod cgroup {}: {error}", root.display()),
            )
        })?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pod cgroup path is not a directory: {}", root.display()),
            ));
        }
        let mut dirs = vec![PathBuf::from(cgroup_path)];
        let mut scanned = 0usize;
        let mut first_read_error: Option<String> = None;
        while let Some(dir) = dirs.pop() {
            scanned += 1;
            if scanned > 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("pod cgroup walk exceeded 1024 directories under {cgroup_path}"),
                ));
            }
            let procs_path = dir.join("cgroup.procs");
            match std::fs::read_to_string(&procs_path) {
                Ok(procs) => {
                    if let Some(pid) = procs.split_whitespace().find_map(|raw| raw.parse().ok()) {
                        return Ok(pid);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    first_read_error.get_or_insert_with(|| {
                        format!("failed to read {}: {error}", procs_path.display())
                    });
                }
            }
            match std::fs::read_dir(&dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                            dirs.push(entry.path());
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    first_read_error.get_or_insert_with(|| {
                        format!("failed to read cgroup directory {}: {error}", dir.display())
                    });
                }
            }
        }
        let detail = first_read_error
            .map(|error| format!("; first read error: {error}"))
            .unwrap_or_default();
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no live PID found in pod cgroup subtree {cgroup_path}{detail}"),
        ))
    }

    /// RAII netns switch: enters the target PID's net namespace on construction
    /// and restores the caller's on drop. Must live only on a dedicated thread.
    struct NetnsGuard {
        original: File,
    }

    impl NetnsGuard {
        fn enter(pid: u32) -> std::io::Result<Self> {
            let original = File::open("/proc/self/ns/net")?;
            let target = File::open(format!("/proc/{pid}/ns/net"))?;
            setns_net(target.as_raw_fd())?;
            Ok(Self { original })
        }

        /// Enter a netns given an already-open handle fd (from
        /// [`open_pod_netns_handle`]) instead of a live PID, so the switch works
        /// even after the resolving PID has exited. Saves and restores the
        /// caller's netns exactly like [`Self::enter`].
        fn enter_fd(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
            let original = File::open("/proc/self/ns/net")?;
            setns_net(fd)?;
            Ok(Self { original })
        }
    }

    impl Drop for NetnsGuard {
        fn drop(&mut self) {
            let _ = setns_net(self.original.as_raw_fd());
        }
    }

    fn setns_net(fd: std::os::fd::RawFd) -> std::io::Result<()> {
        // Safety: `fd` is an open `/proc/.../ns/net` handle owned by the caller
        // for the duration of the call; `setns` only reads it.
        if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::net::SocketAddr;

    pub(crate) fn netns_inode_for_cgroup(_cgroup_path: &str) -> std::io::Result<u64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns capture listeners are Linux-only",
        ))
    }

    pub(super) fn bind_capture_listener_in_pod_netns(
        _cgroup_path: &str,
        _addr: SocketAddr,
    ) -> std::io::Result<std::net::TcpListener> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns capture listeners are Linux-only",
        ))
    }

    pub(crate) fn host_netns_inode() -> std::io::Result<u64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns UDP capture is Linux-only",
        ))
    }

    pub(crate) fn open_pod_netns_handle(_cgroup_path: &str) -> std::io::Result<std::fs::File> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns UDP capture is Linux-only",
        ))
    }

    pub(crate) fn run_in_netns<T, F>(_netns: &std::fs::File, _f: F) -> std::io::Result<T>
    where
        T: Send,
        F: FnOnce() -> std::io::Result<T> + Send,
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns UDP capture is Linux-only",
        ))
    }
}

/// Shared low-level netns primitives, re-exported for the Ambient per-pod-netns
/// UDP producer (`netns_udp_capture`) so it reuses the SAME `setns`/cgroup
/// resolution recipe as the TCP node-waypoint capture path.
pub(crate) use imp::{
    host_netns_inode, netns_inode_for_cgroup, open_pod_netns_handle, run_in_netns,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock backend: maps each pod's cgroup path to a caller-provided netns
    /// inode and records every open/close so the reconcile diff can be asserted
    /// without a real netns.
    struct MockBackend {
        // cgroup_path → netns inode (None = unresolvable this round)
        netns_by_cgroup: Mutex<HashMap<String, Option<u64>>>,
        opened: Mutex<Vec<(u64, SocketAddr, Option<IpAddr>)>>,
    }

    impl MockBackend {
        fn new(mapping: &[(&str, Option<u64>)]) -> Self {
            Self {
                netns_by_cgroup: Mutex::new(
                    mapping.iter().map(|(c, n)| (c.to_string(), *n)).collect(),
                ),
                opened: Mutex::new(Vec::new()),
            }
        }
    }

    impl NetnsBackend for MockBackend {
        fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
            self.netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
                .copied()
                .flatten()
                .ok_or_else(|| "mock netns unresolved".to_string())
        }

        fn open_listener(
            &self,
            target: &PodCaptureTarget,
            addr: SocketAddr,
        ) -> Option<OpenedNetnsListener> {
            let netns = self.netns_key(target).ok()?;
            self.opened.lock().unwrap().push((
                netns,
                addr,
                target.source_ips.source_for_addr(addr),
            ));
            // The manager records closes by dropping the listener from `active`;
            // tests assert on `mgr.active` membership, so the mock just hands
            // back a live stop handle.
            let (tx, _rx) = watch::channel(false);
            Some(OpenedNetnsListener::new(tx, None))
        }
    }

    fn target(uid: &str, cgroup: &str) -> PodCaptureTarget {
        PodCaptureTarget {
            pod_uid: uid.to_string(),
            cgroup_path: cgroup.to_string(),
            source_ips: PodCaptureSourceIps::default(),
        }
    }

    struct StaticSource(Vec<PodCaptureTarget>);
    impl PodCaptureSource for StaticSource {
        fn list_targets(&self) -> Vec<PodCaptureTarget> {
            self.0.clone()
        }
    }

    #[test]
    fn directory_source_parses_pod_uid_and_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pod-a"),
            "/sys/fs/cgroup/kubepods/pod-a\nipv4=10.0.0.5\nipv6=fd00::5\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pod-b"),
            "  /sys/fs/cgroup/kubepods/pod-b  ",
        )
        .unwrap();
        std::fs::write(dir.path().join(".hidden"), "ignored").unwrap();
        std::fs::write(dir.path().join("empty"), "   ").unwrap();

        let source = DirectoryCaptureSource::new(dir.path());
        let mut targets = source.list_targets();
        targets.sort_by(|a, b| a.pod_uid.cmp(&b.pod_uid));

        assert_eq!(targets.len(), 2, "hidden + empty-cgroup files are skipped");
        assert_eq!(targets[0].pod_uid, "pod-a");
        assert_eq!(targets[0].cgroup_path, "/sys/fs/cgroup/kubepods/pod-a");
        assert_eq!(
            targets[0].source_ips.ipv4,
            Some("10.0.0.5".parse().unwrap())
        );
        assert_eq!(targets[0].source_ips.ipv6, Some("fd00::5".parse().unwrap()));
        assert_eq!(targets[1].pod_uid, "pod-b");
        assert_eq!(targets[1].cgroup_path, "/sys/fs/cgroup/kubepods/pod-b");
        assert_eq!(targets[1].source_ips, PodCaptureSourceIps::default());
    }

    #[test]
    fn directory_source_absent_dir_is_empty_not_error() {
        let source = DirectoryCaptureSource::new("/definitely/not/a/dir");
        assert!(source.list_targets().is_empty());
    }

    #[tokio::test]
    async fn reconcile_opens_one_listener_per_netns_and_dedupes_shared_netns() {
        // pod-a and pod-b share netns 100 (e.g. sandbox + container); pod-c is
        // its own netns 200.
        let source = Arc::new(StaticSource(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
            target("pod-c", "/cg/c"),
        ]));
        let backend = MockBackend::new(&[
            ("/cg/a", Some(100)),
            ("/cg/b", Some(100)),
            ("/cg/c", Some(200)),
        ]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );
        let active = mgr.reconcile_once();
        assert_eq!(active, 2, "two distinct netns → two listeners, not three");
        let opened = mgr.backend.opened.lock().unwrap().clone();
        assert_eq!(
            opened.len(),
            4,
            "each distinct netns gets IPv4 and IPv6 listeners"
        );
        assert!(
            opened
                .iter()
                .any(|(netns, addr, _)| *netns == 100 && addr.is_ipv4())
                && opened
                    .iter()
                    .any(|(netns, addr, _)| *netns == 100 && addr.is_ipv6())
                && opened
                    .iter()
                    .any(|(netns, addr, _)| *netns == 200 && addr.is_ipv4())
                && opened
                    .iter()
                    .any(|(netns, addr, _)| *netns == 200 && addr.is_ipv6())
        );
    }

    #[tokio::test]
    async fn reconcile_is_idempotent_and_closes_removed_pods() {
        let targets = Arc::new(Mutex::new(vec![
            target("pod-a", "/cg/a"),
            target("pod-c", "/cg/c"),
        ]));

        struct DynSource(Arc<Mutex<Vec<PodCaptureTarget>>>);
        impl PodCaptureSource for DynSource {
            fn list_targets(&self) -> Vec<PodCaptureTarget> {
                self.0.lock().unwrap().clone()
            }
        }

        let backend = MockBackend::new(&[("/cg/a", Some(100)), ("/cg/c", Some(200))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            Arc::new(DynSource(targets.clone())),
            backend,
            Duration::from_secs(1),
        );

        assert_eq!(mgr.reconcile_once(), 2);
        // Second pass with the SAME set opens nothing new.
        assert_eq!(mgr.reconcile_once(), 2);
        assert_eq!(mgr.backend.opened.lock().unwrap().len(), 4, "no re-open");

        // pod-c goes away → its netns listener closes.
        targets.lock().unwrap().retain(|t| t.pod_uid != "pod-c");
        assert_eq!(mgr.reconcile_once(), 1);
        assert!(!mgr.active.contains_key(&200));
        assert!(mgr.active.contains_key(&100));
    }

    #[tokio::test]
    async fn reconcile_skips_unresolvable_netns_without_tearing_down() {
        // pod-a resolves; pod-b's netns is unresolvable this round (terminating
        // / race). The unresolvable pod is skipped, never affecting pod-a.
        let source = Arc::new(StaticSource(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
        ]));
        let backend = MockBackend::new(&[("/cg/a", Some(100)), ("/cg/b", None)]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );
        assert_eq!(mgr.reconcile_once(), 1, "only the resolvable pod opens");
        assert!(mgr.active.contains_key(&100));
    }

    #[tokio::test]
    async fn reconcile_opens_family_listeners_with_matching_source_ips() {
        let source_ips = PodCaptureSourceIps {
            ipv4: Some("10.1.2.3".parse().unwrap()),
            ipv6: Some("fd00::3".parse().unwrap()),
        };
        let source = Arc::new(StaticSource(vec![PodCaptureTarget {
            pod_uid: "pod-a".to_string(),
            cgroup_path: "/cg/a".to_string(),
            source_ips,
        }]));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );

        assert_eq!(mgr.reconcile_once(), 1);
        let opened = mgr.backend.opened.lock().unwrap().clone();
        assert!(
            opened.iter().any(|(netns, addr, source_ip)| {
                *netns == 100 && addr.is_ipv4() && *source_ip == source_ips.ipv4.map(IpAddr::V4)
            }),
            "IPv4 listener must use the IPv4 pod source IP: {opened:?}"
        );
        assert!(
            opened.iter().any(|(netns, addr, source_ip)| {
                *netns == 100 && addr.is_ipv6() && *source_ip == source_ips.ipv6.map(IpAddr::V6)
            }),
            "IPv6 listener must use the IPv6 pod source IP: {opened:?}"
        );
    }

    #[tokio::test]
    async fn reconcile_updates_listener_source_ips_when_pod_ips_change() {
        // pod-a is enrolled before `status.podIPs` exists (override `None`),
        // then gets family-specific IPs, then they change. Each transition must
        // update listener source overrides without rebinding pod-loopback
        // sockets.
        let targets = Arc::new(Mutex::new(vec![PodCaptureTarget {
            pod_uid: "pod-a".to_string(),
            cgroup_path: "/cg/a".to_string(),
            source_ips: PodCaptureSourceIps::default(),
        }]));

        struct DynSource(Arc<Mutex<Vec<PodCaptureTarget>>>);
        impl PodCaptureSource for DynSource {
            fn list_targets(&self) -> Vec<PodCaptureTarget> {
                self.0.lock().unwrap().clone()
            }
        }

        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            Arc::new(DynSource(targets.clone())),
            backend,
            Duration::from_secs(1),
        );

        // Initial open carries no source IPs.
        assert_eq!(mgr.reconcile_once(), 1);
        let opened = mgr.backend.opened.lock().unwrap().clone();
        assert_eq!(opened.len(), 2);
        assert!(
            opened.iter().all(|(_, _, source_ip)| source_ip.is_none()),
            "initial listener opens should not override loopback: {opened:?}"
        );
        assert_eq!(
            mgr.active.get(&100).unwrap().source_ips,
            PodCaptureSourceIps::default()
        );

        // Unchanged IPs (still None) → membership refresh only, no reopen.
        assert_eq!(mgr.reconcile_once(), 1);
        assert_eq!(
            mgr.backend.opened.lock().unwrap().len(),
            2,
            "no reopen when source IPs are unchanged"
        );

        // status.podIPs assigned → update the overrides without reopening.
        let ips1 = PodCaptureSourceIps {
            ipv4: Some("10.1.2.3".parse().unwrap()),
            ipv6: Some("fd00::3".parse().unwrap()),
        };
        targets.lock().unwrap()[0].source_ips = ips1;
        assert_eq!(mgr.reconcile_once(), 1);
        assert_eq!(
            mgr.backend.opened.lock().unwrap().len(),
            2,
            "pod IP assignment must not reopen listeners"
        );
        assert_eq!(mgr.active.get(&100).unwrap().source_ips, ips1);

        // IPs change again → update again without reopening.
        let ips2 = PodCaptureSourceIps {
            ipv4: Some("10.1.2.9".parse().unwrap()),
            ipv6: Some("fd00::9".parse().unwrap()),
        };
        targets.lock().unwrap()[0].source_ips = ips2;
        assert_eq!(mgr.reconcile_once(), 1);
        assert_eq!(
            mgr.backend.opened.lock().unwrap().len(),
            2,
            "pod IP changes must not reopen listeners"
        );
        assert_eq!(mgr.active.get(&100).unwrap().source_ips, ips2);
    }

    #[tokio::test]
    async fn reconcile_closes_listener_when_pod_uid_moves_netns() {
        // pod-a is enrolled in netns 100, then its sandbox/netns restarts and the
        // SAME pod UID now resolves to netns 200 (in-place registry rewrite or
        // remove+publish between polls). The stale listener for 100 must close
        // (no leaked socket / pinned dead netns) and a fresh one open for 200.
        let source = Arc::new(StaticSource(vec![target("pod-a", "/cg/a")]));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );
        assert_eq!(mgr.reconcile_once(), 1);
        assert!(mgr.active.contains_key(&100));

        // Same UID, new netns.
        mgr.backend
            .netns_by_cgroup
            .lock()
            .unwrap()
            .insert("/cg/a".to_string(), Some(200));

        assert_eq!(
            mgr.reconcile_once(),
            1,
            "exactly one listener, now on the new netns"
        );
        assert!(
            !mgr.active.contains_key(&100),
            "stale netns listener must be closed when the pod UID moves netns"
        );
        assert!(
            mgr.active.contains_key(&200),
            "a listener must open for the pod's new netns"
        );
    }

    #[tokio::test]
    async fn reconcile_writes_and_removes_readiness_markers() {
        // With a ready dir configured, opening a pod's listener writes the
        // legacy IPv4 marker plus address-family markers; closing it removes
        // them.
        let registry = tempfile::tempdir().unwrap();
        let ready_dir = registry.path().join(".ready");
        let ready4_dir = registry.path().join(".ready4");
        let ready6_dir = registry.path().join(".ready6");
        let targets = Arc::new(Mutex::new(vec![target("pod-a", "/cg/a")]));
        struct DynSource(Arc<Mutex<Vec<PodCaptureTarget>>>);
        impl PodCaptureSource for DynSource {
            fn list_targets(&self) -> Vec<PodCaptureTarget> {
                self.0.lock().unwrap().clone()
            }
        }
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            Arc::new(DynSource(targets.clone())),
            backend,
            Duration::from_secs(1),
        )
        .with_ready_dir(Some(ready_dir.clone()));

        assert_eq!(mgr.reconcile_once(), 1);
        assert!(
            ready_dir.join("pod-a").exists(),
            "the legacy IPv4 readiness marker must be written when the IPv4 listener opens"
        );
        assert!(
            ready4_dir.join("pod-a").exists(),
            "the IPv4 family readiness marker must be written when the IPv4 listener opens"
        );
        assert!(
            ready6_dir.join("pod-a").exists(),
            "the IPv6 family readiness marker must be written when the IPv6 listener opens"
        );

        // Pod leaves the registry → listener closes → marker removed.
        targets.lock().unwrap().clear();
        assert_eq!(mgr.reconcile_once(), 0);
        assert!(
            !ready_dir.join("pod-a").exists(),
            "the legacy readiness marker must be removed when the listener closes"
        );
        assert!(
            !ready4_dir.join("pod-a").exists(),
            "the IPv4 readiness marker must be removed when the listener closes"
        );
        assert!(
            !ready6_dir.join("pod-a").exists(),
            "the IPv6 readiness marker must be removed when the listener closes"
        );
    }

    #[tokio::test]
    async fn pod_ip_change_keeps_listener_and_marker_without_reopen() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Backend that opens the initial dual-family listeners and would fail
        // any later open. A pod IP update must not call it again: closing the
        // active listener would leave already-promoted redirects pointing at an
        // empty port.
        struct FailReopenBackend {
            opens: AtomicUsize,
        }
        impl NetnsBackend for FailReopenBackend {
            fn netns_key(&self, _target: &PodCaptureTarget) -> Result<u64, String> {
                Ok(100)
            }
            fn open_listener(
                &self,
                _target: &PodCaptureTarget,
                _addr: SocketAddr,
            ) -> Option<OpenedNetnsListener> {
                if self.opens.fetch_add(1, Ordering::SeqCst) < 2 {
                    let (tx, _rx) = watch::channel(false);
                    Some(OpenedNetnsListener::new(tx, None))
                } else {
                    None
                }
            }
        }

        let registry = tempfile::tempdir().unwrap();
        let ready_dir = registry.path().join(".ready");
        let ready6_dir = registry.path().join(".ready6");
        let targets = Arc::new(Mutex::new(vec![PodCaptureTarget {
            pod_uid: "pod-a".to_string(),
            cgroup_path: "/cg/a".to_string(),
            source_ips: PodCaptureSourceIps::default(),
        }]));
        struct DynSource(Arc<Mutex<Vec<PodCaptureTarget>>>);
        impl PodCaptureSource for DynSource {
            fn list_targets(&self) -> Vec<PodCaptureTarget> {
                self.0.lock().unwrap().clone()
            }
        }
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            Arc::new(DynSource(targets.clone())),
            FailReopenBackend {
                opens: AtomicUsize::new(0),
            },
            Duration::from_secs(1),
        )
        .with_ready_dir(Some(ready_dir.clone()));

        // First open succeeds → marker present.
        assert_eq!(mgr.reconcile_once(), 1);
        assert!(ready_dir.join("pod-a").exists());
        assert!(
            ready6_dir.join("pod-a").exists(),
            "the IPv6 readiness marker is present after the v6 listener opens"
        );

        // Pod IPs change → update metadata only. The existing listeners and
        // ready markers must stay in place even though any reopen would fail.
        targets.lock().unwrap()[0].source_ips = PodCaptureSourceIps {
            ipv4: Some("10.0.0.7".parse().unwrap()),
            ipv6: Some("fd00::7".parse().unwrap()),
        };
        assert_eq!(
            mgr.reconcile_once(),
            1,
            "a pod IP update keeps the existing listener active"
        );
        assert!(
            ready_dir.join("pod-a").exists(),
            "the readiness marker stays while the listener still serves the pod"
        );
        assert_eq!(
            mgr.backend.opens.load(Ordering::SeqCst),
            2,
            "pod IP changes must not attempt a replacement bind"
        );
    }

    #[test]
    fn ready_marker_path_rejects_unsafe_pod_uids() {
        let dir = Path::new("/run/ferrum/node-waypoint-pods/.ready");
        for unsafe_uid in ["", ".", "..", "a/b", "a\\b", "../escape"] {
            assert!(
                ready_marker_path(dir, unsafe_uid).is_none(),
                "unsafe pod UID {unsafe_uid:?} must be rejected"
            );
        }
        assert_eq!(
            ready_marker_path(dir, "pod-uid-1"),
            Some(dir.join("pod-uid-1"))
        );
    }
}

/// Privileged functional tests for the in-netns capture primitive
/// ([`imp::bind_capture_listener_in_pod_netns`]). They create and enter network
/// namespaces, which needs `CAP_SYS_ADMIN`/root, so they are `#[ignore]`d and
/// run only by the dedicated `netns-capture-live` CI job. CI sets
/// `FERRUM_LIVE_TESTS_REQUIRED=1`, so missing prerequisites fail there instead
/// of passing as skips; local ad-hoc runs still self-skip when root or
/// `unshare` is unavailable.
///
/// No eBPF here: this layer proves the OS mechanism the whole design rests on —
/// `127.0.0.1:15001` and `[::1]:15001` listeners bound *inside* a pod's netns
/// are reachable from a client in that netns and **unreachable from the host
/// netns** (the per-pod loopback isolation that makes a single host-netns
/// listener insufficient).
#[cfg(all(test, target_os = "linux"))]
mod live_netns_tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    const CAPTURE_PORT: u16 = 15001;

    fn is_root() -> bool {
        // Safety: `geteuid` is always sound and never fails.
        unsafe { libc::geteuid() == 0 }
    }

    fn live_tests_required() -> bool {
        std::env::var("FERRUM_LIVE_TESTS_REQUIRED")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn skip_or_fail(reason: &str) {
        if live_tests_required() {
            panic!(
                "netns capture live test prerequisite missing under FERRUM_LIVE_TESTS_REQUIRED: {reason}"
            );
        }
        eprintln!("SKIP: {reason}");
    }

    /// Spawn a child living in a fresh network namespace (loopback brought up),
    /// then sleeping. `/proc/<pid>/ns/net` is the synthetic "pod" netns.
    /// `None` if `unshare` is unavailable. `unshare --net` does not fork, so the
    /// spawned PID is the process living in the new netns.
    fn spawn_pod_netns_child() -> Option<Child> {
        Command::new("unshare")
            .args([
                "--net",
                "sh",
                "-c",
                "ip link set lo up 2>/dev/null || true; exec sleep 30",
            ])
            .spawn()
            .ok()
    }

    /// Reaps the child netns process on drop so the test never leaks it.
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Connect to `addr` from inside `pid`'s network namespace, on a throwaway
    /// thread (setns mutates only the calling thread, and the thread exits
    /// immediately so no restore is needed). Returns whether it connected.
    fn connect_inside_netns(pid: u32, addr: SocketAddr) -> bool {
        std::thread::spawn(move || -> bool {
            let Ok(target) = std::fs::File::open(format!("/proc/{pid}/ns/net")) else {
                return false;
            };
            // Safety: `target` is an open netns handle owned for the call.
            if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return false;
            }
            match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                Ok(mut stream) => {
                    let _ = stream.write_all(b"ping");
                    true
                }
                Err(_) => false,
            }
        })
        .join()
        .unwrap_or(false)
    }

    fn assert_accepts_loopback(listener: &TcpListener, label: &str) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut accepted = false;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok(_) => {
                    accepted = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("in-netns listener accept failed for {label}: {e}"),
            }
        }
        assert!(
            accepted,
            "the in-netns listener must accept the pod's loopback connection for {label}"
        );
    }

    #[test]
    #[ignore = "requires root + CAP_SYS_ADMIN to create/enter network namespaces"]
    fn in_netns_dual_family_listeners_reachable_inside_pod_and_isolated_from_host() {
        if !is_root() {
            skip_or_fail("not root; cannot create network namespaces");
            return;
        }
        let Some(child) = spawn_pod_netns_child() else {
            skip_or_fail("`unshare --net` unavailable");
            return;
        };
        let pid = child.id();
        let _child = ChildGuard(child);
        // Let the child unshare its netns and bring loopback up.
        std::thread::sleep(Duration::from_millis(400));

        // Synthetic pod cgroup: `first_pid_in_cgroup` only reads `cgroup.procs`,
        // so a tempdir holding the child PID is enough — no real cgroupfs.
        let cgdir = tempfile::tempdir().unwrap();
        std::fs::write(cgdir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        let cgroup_path = cgdir.path().to_string_lossy().to_string();

        let listener = super::imp::bind_capture_listener_in_pod_netns(
            &cgroup_path,
            SocketAddr::from((Ipv4Addr::LOCALHOST, CAPTURE_PORT)),
        )
        .expect("bind IPv4 capture listener inside the pod netns");
        listener
            .set_nonblocking(true)
            .expect("IPv4 listener set_nonblocking");
        let listener6 = super::imp::bind_capture_listener_in_pod_netns(
            &cgroup_path,
            SocketAddr::from((Ipv6Addr::LOCALHOST, CAPTURE_PORT)),
        )
        .expect("bind IPv6 capture listener inside the pod netns");
        listener6
            .set_nonblocking(true)
            .expect("IPv6 listener set_nonblocking");

        // (1) A client INSIDE the pod netns must reach the in-netns listener.
        assert!(
            connect_inside_netns(pid, SocketAddr::from((Ipv4Addr::LOCALHOST, CAPTURE_PORT))),
            "a client inside the pod netns must reach the IPv4 in-netns capture listener"
        );
        assert!(
            connect_inside_netns(pid, SocketAddr::from((Ipv6Addr::LOCALHOST, CAPTURE_PORT))),
            "a client inside the pod netns must reach the IPv6 in-netns capture listener"
        );
        assert_accepts_loopback(&listener, "ipv4");
        assert_accepts_loopback(&listener6, "ipv6");

        // (2) The HOST netns must NOT reach 127.0.0.1:15001 — the listener lives
        // or [::1]:15001 — the listeners live only in the pod netns. This loopback
        // isolation is exactly why a single host-netns listener can never serve
        // captured pods.
        let host_reach = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, CAPTURE_PORT)),
            Duration::from_millis(500),
        );
        assert!(
            host_reach.is_err(),
            "host netns must not reach a pod-netns-only IPv4 loopback listener (got {host_reach:?})"
        );
        let host_reach6 = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv6Addr::LOCALHOST, CAPTURE_PORT)),
            Duration::from_millis(500),
        );
        assert!(
            host_reach6.is_err(),
            "host netns must not reach a pod-netns-only IPv6 loopback listener (got {host_reach6:?})"
        );
    }
}

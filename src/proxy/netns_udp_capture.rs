//! Ambient per-pod-netns UDP capture producer (F3 §3.3, #2013).
//!
//! Ambient's proxy runs OUTSIDE the workload pods' network namespaces (unlike a
//! Sidecar, which shares the pod netns), and the host-netns iptables fallback
//! emits NO UDP TPROXY rules (there is no host-netns-safe direction
//! discriminator — see `capture::udp_tproxy_commands_for_family`). So an Ambient
//! deployment had NO UDP capture producer: captured-and-relayed UDP existed only
//! on the destination (relay) half. This module is the missing source-capture
//! producer.
//!
//! It rides the same per-enrolled-pod registry the NodeWaypoint TCP in-netns
//! capture path uses ([`super::netns_capture::DirectoryCaptureSource`] over the
//! node-agent-published registry dir): a [`NetnsUdpCaptureManager`] polls the
//! enrolled-pod set and, for each pod netns, opens a UDP capture "producer" that
//!   1. installs a scope-exact fail-closed OUTPUT guard INSIDE the pod netns,
//!   2. binds a transparent UDP capture socket and installs the UDP TPROXY rules
//!      while that guard remains active,
//!   3. removes the guard only after the socket/rules are ready, then runs the
//!      shared capture/session/egress loop
//!      ([`super::mesh_udp_capture::run_mesh_udp_capture_on_socket`]) with a
//!      pod-netns reply-socket factory (so return-path replies are spoofed from
//!      the captured VIP:port INSIDE the pod netns), and
//!   4. on pod removal / config change / shutdown / error, stops the loop and
//!      tears down ONLY its own UDP rules from that netns.
//!
//! The destination relay, framing, session DoS bounds, and fail-closed contract
//! are entirely reused from [`super::mesh_udp_capture`]; this module only adds
//! the per-pod-netns producer plumbing. TCP capture for Ambient rides
//! eBPF/HBONE, so this producer installs UDP-only rules (never the TCP nat
//! chains).
//!
//! Linux-only (`setns`, `IP_TRANSPARENT`, in-netns iptables). Non-Linux is an
//! unsupported stub. The reconcile logic is platform-independent and unit-tested
//! with a mock backend; the `setns`/socket/iptables datapath is verified on a
//! live multi-pod node (the `netns-capture-live` follow-up).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::netns_capture::{PodCaptureSource, PodCaptureTarget};

/// Handle to one pod netns's active UDP capture (its rules + socket + loop).
/// Closing it signals the capture loop to stop; the production backend's loop
/// task then tears down that netns's UDP TPROXY rules once the loop exits.
pub struct OpenedUdpCapture {
    stop: watch::Sender<bool>,
    /// Test-only close hook so a mock backend can record teardown. Production
    /// leaves this `None` — real teardown runs in the supervising task after `stop`.
    on_close: Option<Box<dyn FnOnce() + Send>>,
    /// The production backend's supervising task (capture loop → in-netns rule
    /// teardown). On graceful shutdown the manager awaits it (bounded) so the
    /// TPROXY/routing rules are actually removed from the pod netns before the
    /// process exits, instead of leaking them (codex). `None` for the test mock.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OpenedUdpCapture {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn new(stop: watch::Sender<bool>, task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            stop,
            on_close: None,
            task: Some(task),
        }
    }

    #[cfg(test)]
    fn with_on_close(stop: watch::Sender<bool>, on_close: Box<dyn FnOnce() + Send>) -> Self {
        Self {
            stop,
            on_close: Some(on_close),
            task: None,
        }
    }

    /// Signal the capture loop to stop and return the supervising task handle (if
    /// any) so the caller can await its in-netns teardown. `on_close` is a test
    /// hook only. Dropping the returned handle does NOT abort the task — teardown
    /// still runs in the background (used on pod removal); the shutdown path awaits
    /// it instead.
    fn close(mut self) -> Option<tokio::task::JoinHandle<()>> {
        let _ = self.stop.send(true);
        if let Some(cb) = self.on_close.take() {
            cb();
        }
        self.task.take()
    }
}

/// Opens/closes per-pod-netns UDP capture. A trait so the manager's reconcile
/// logic is unit-testable with a mock (no real netns, `setns`, or iptables).
pub trait NetnsUdpBackend: Send + Sync + 'static {
    /// Stable netns identity for dedup (the pod's `net` namespace inode), so many
    /// pods sharing a netns open ONE producer. `Err` when the pod netns can't be
    /// resolved this round (terminating / PID race) — the transient-grace case.
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String>;

    /// Install UDP TPROXY rules + bind the capture socket + start the capture
    /// loop INSIDE the target pod's netns. `expected_netns` is the inode resolved
    /// during this reconcile pass; the backend must fail closed if the reopened
    /// netns handle no longer matches it. `None` on failure (retried next
    /// reconcile); the backend must leave no partial capture rules behind on
    /// failure. It may intentionally retain a dedicated fail-closed guard until a
    /// later retry succeeds.
    fn open_udp_capture(
        &self,
        target: &PodCaptureTarget,
        expected_netns: u64,
    ) -> Option<OpenedUdpCapture>;
}

/// Best-effort cleanup backend used when Ambient UDP capture is disabled. It
/// removes stale Ferrum UDP TPROXY state from pod netns without opening sockets or
/// installing rules.
pub trait NetnsUdpCleanupBackend: Send + Sync + 'static {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String>;

    fn cleanup_udp_capture(&self, target: &PodCaptureTarget, expected_netns: u64) -> bool;
}

/// One active pod-netns UDP producer, keyed in the manager by netns inode.
struct ActiveUdpCapture {
    handle: OpenedUdpCapture,
    /// Pod UIDs currently justifying this netns's producer. A netns is closed
    /// only when NONE of its pods still justify it.
    pod_uids: HashSet<String>,
}

/// Reconciles per-pod-netns UDP capture producers against the enrolled-pod set.
pub struct NetnsUdpCaptureManager<B: NetnsUdpBackend> {
    /// The UDP capture port bound (dual-stack `[::]`) inside each pod netns.
    /// Stored for the startup/diagnostic log only; the backend owns the bind.
    capture_port: u16,
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    /// netns inode → its active producer.
    active: HashMap<u64, ActiveUdpCapture>,
    /// netns inode → the still-running teardown of a producer we just closed
    /// (pod removal / netns move / registry flap). The reopen path AWAITS the
    /// entry for a netns before opening a new producer for that same netns, so a
    /// lagging old teardown can never delete the fresh producer's
    /// `FERRUM_MESH_UDP_*` chains/routing after they were installed (codex
    /// fail-open race). Empty for the test mock, whose `close()` carries no task.
    pending_teardowns: HashMap<u64, tokio::task::JoinHandle<()>>,
    /// Last registry UID set logged, so churn diagnostics don't repeat per poll.
    last_registry_uids: HashSet<String>,
    /// Last unresolved-netns reason per pod UID, so persistent cgroup/proc
    /// visibility failures stay clear without warning every poll.
    unresolved_reasons: HashMap<String, String>,
}

impl<B: NetnsUdpBackend> NetnsUdpCaptureManager<B> {
    pub fn new(
        capture_port: u16,
        source: Arc<dyn PodCaptureSource>,
        backend: B,
        poll_interval: Duration,
    ) -> Self {
        Self {
            capture_port,
            source,
            backend,
            poll_interval,
            active: HashMap::new(),
            pending_teardowns: HashMap::new(),
            last_registry_uids: HashSet::new(),
            unresolved_reasons: HashMap::new(),
        }
    }

    /// Poll-and-reconcile until `shutdown` flips to `true`, then close every
    /// producer (which tears down its in-netns UDP rules).
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            capture_port = self.capture_port,
            poll_secs = self.poll_interval.as_secs_f64(),
            "Ambient per-pod-netns UDP capture manager started"
        );
        loop {
            self.reconcile_once().await;
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        self.shutdown_all().await;
    }

    /// One reconcile pass: open producers for newly enrolled pod netns, close
    /// producers whose pods are all gone. Returns the count of active producers
    /// (used by tests).
    ///
    /// Async because reopening a netns that we just closed must AWAIT the old
    /// producer's in-netns teardown to completion before the new producer
    /// installs its rules — otherwise a lagging teardown could delete the fresh
    /// `FERRUM_MESH_UDP_*` chains after install and silently drop the pod out of
    /// mesh capture (codex fail-open race).
    async fn reconcile_once(&mut self) -> usize {
        let targets = self.source.list_targets();

        // Resolve every enrolled pod's current netns once, into three buckets:
        //   * `desired`            netns inode → pods resolving to it now
        //   * `resolved_uid_netns` pod UID → the netns it resolves to now
        //   * `unresolved_uids`    pods present in the registry but whose netns
        //                          can't resolve this round (terminating / PID
        //                          race) — the transient-grace set.
        let mut desired: HashMap<u64, HashSet<String>> = HashMap::new();
        let mut resolved_uid_netns: HashMap<String, u64> = HashMap::new();
        let mut unresolved_uids: HashSet<String> = HashSet::new();
        let registry_uids: HashSet<String> = targets.iter().map(|t| t.pod_uid.clone()).collect();
        if registry_uids != self.last_registry_uids {
            info!(
                target_count = registry_uids.len(),
                pod_uids = ?registry_uids,
                "Ambient UDP capture registry changed"
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
                            "Ambient UDP capture: pod netns resolved after retry"
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
                            "Ambient UDP capture: pod netns still not resolvable; will retry"
                        );
                    } else {
                        warn!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            %error,
                            "Ambient UDP capture: pod netns not resolvable; will retry"
                        );
                    }
                }
            }
        }
        self.unresolved_reasons
            .retain(|uid, _| unresolved_uids.contains(uid));

        // Close a producer when none of its pods still justify it. A pod on the
        // producer for netns N justifies keeping N open when it is still in the
        // registry AND either (a) still resolves to N, or (b) is unresolvable
        // this round (the transient PID/netns-miss grace — a container restarting
        // while its registry file persists must not flap the producer). A pod
        // that left the registry, OR now resolves to a DIFFERENT netns
        // (sandbox/netns restart), no longer justifies N: leaving N open would
        // leak the socket + rules and pin the dead netns. The pod's new netns
        // gets its own producer in the open pass below.
        let gone: Vec<u64> = self
            .active
            .iter()
            .filter(|(netns, active)| {
                !active.pod_uids.iter().any(|uid| {
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
            if let Some(active) = self.active.remove(&netns) {
                // Close the producer (signal its loop to stop). Rather than drop
                // the supervising task's handle fire-and-forget, RETAIN it keyed
                // by netns so the open pass can await this teardown to completion
                // before installing a new producer's rules in the same netns — a
                // registry flap (file disappears then reappears for the same pod
                // netns) must not let this old teardown fire AFTER the new install
                // and delete the fresh chains (codex fail-open race). The handle
                // is `None` for the test mock (no supervising task).
                if let Some(task) = active.handle.close() {
                    // Defensive: an unlikely pre-existing pending teardown for the
                    // same netns is awaited first, so handles cannot accumulate.
                    if let Some(prior) = self.pending_teardowns.remove(&netns) {
                        let _ = prior.await;
                    }
                    self.pending_teardowns.insert(netns, task);
                }
                info!(
                    netns_inode = netns,
                    "Closed Ambient per-pod-netns UDP capture producer"
                );
            }
        }

        // Open producers for newly-seen netns; for an existing netns, refresh pod
        // membership (a shared netns may gain/lose pods without a socket rebind).
        for (netns, pod_uids) in desired {
            if let Some(active) = self.active.get_mut(&netns) {
                active.pod_uids = pod_uids;
                continue;
            }
            // New netns: open one producer. Any target in this netns can open it —
            // they share the namespace.
            let Some(target) = targets.iter().find(|t| pod_uids.contains(&t.pod_uid)) else {
                continue;
            };
            // Before installing fresh rules in this netns, await a prior
            // producer's teardown (registry flap: closed then reopened for the
            // same pod netns). Take the handle OUT of the map first, then await
            // with no map borrow held, so the awaited teardown's chain deletion
            // is guaranteed to run BEFORE `open_udp_capture` reinstalls — a
            // lagging old teardown can never delete the new chains (codex). A
            // cancelled/panicked teardown is logged and we proceed to reinstall
            // (the new producer's own pre-teardown reaps any stale rules).
            if let Some(prior) = self.pending_teardowns.remove(&netns)
                && let Err(error) = prior.await
            {
                warn!(
                    netns_inode = netns,
                    %error,
                    "Ambient UDP producer: prior teardown task did not complete cleanly \
                     before reopen; proceeding to reinstall rules"
                );
            }
            match self.backend.open_udp_capture(target, netns) {
                Some(handle) => {
                    info!(
                        netns_inode = netns,
                        pod_uid = %target.pod_uid,
                        capture_port = self.capture_port,
                        "Opened Ambient per-pod-netns UDP capture producer"
                    );
                    self.active
                        .insert(netns, ActiveUdpCapture { handle, pod_uids });
                }
                None => {
                    warn!(
                        netns_inode = netns,
                        pod_uid = %target.pod_uid,
                        "Failed to open Ambient per-pod-netns UDP capture producer; will retry"
                    );
                }
            }
        }

        // Reap teardowns that have already finished for netns not reopened this
        // pass, so completed handles for permanently-gone pods don't accumulate.
        // Non-blocking: unfinished teardowns stay retained and are still awaited
        // on a future reopen of that netns (or on shutdown).
        self.pending_teardowns.retain(|_, task| !task.is_finished());

        self.active.len()
    }

    /// Close every producer on graceful shutdown and AWAIT their in-netns rule
    /// teardown (bounded), so the process does not exit while pod netns still hold
    /// this producer's TPROXY/routing rules (codex). The wait is bounded so a pod
    /// netns that has already disappeared (its teardown blocking on `setns`) can't
    /// hang shutdown.
    async fn shutdown_all(&mut self) {
        let mut tasks = tokio::task::JoinSet::new();
        for (_, active) in self.active.drain() {
            if let Some(handle) = active.handle.close() {
                tasks.spawn(async move {
                    let _ = handle.await;
                });
            }
        }
        // Also await teardowns already in flight for producers closed but not
        // reopened (registry flap / pod removal between polls), so shutdown does
        // not race ahead of their in-netns rule deletion.
        for (_, task) in self.pending_teardowns.drain() {
            tasks.spawn(async move {
                let _ = task.await;
            });
        }
        if tasks.is_empty() {
            return;
        }
        let drained = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            warn!(
                "Ambient UDP capture: timed out awaiting per-pod-netns rule teardown on shutdown; \
                 some rules may remain until the pod netns is removed"
            );
        }
    }
}

/// Reconciles enrolled pod netns and runs the UDP teardown exactly once per live
/// netns. This is used when Ambient UDP capture is disabled so a pod that was
/// left with stale `FERRUM_MESH_UDP_*` rules by a prior crashed/killed enabled
/// proxy is cleaned without requiring UDP capture to be re-enabled.
pub struct NetnsUdpCleanupManager<B: NetnsUdpCleanupBackend> {
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    cleaned_netns: HashSet<u64>,
    last_registry_uids: HashSet<String>,
    unresolved_reasons: HashMap<String, String>,
}

impl<B: NetnsUdpCleanupBackend> NetnsUdpCleanupManager<B> {
    pub fn new(source: Arc<dyn PodCaptureSource>, backend: B, poll_interval: Duration) -> Self {
        Self {
            source,
            backend,
            poll_interval,
            cleaned_netns: HashSet::new(),
            last_registry_uids: HashSet::new(),
            unresolved_reasons: HashMap::new(),
        }
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            poll_secs = self.poll_interval.as_secs_f64(),
            "Ambient UDP disabled stale-rule cleanup manager started"
        );
        loop {
            self.cleanup_once();
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    fn cleanup_once(&mut self) -> usize {
        let targets = self.source.list_targets();
        let registry_uids: HashSet<String> = targets.iter().map(|t| t.pod_uid.clone()).collect();
        if registry_uids != self.last_registry_uids {
            info!(
                target_count = registry_uids.len(),
                pod_uids = ?registry_uids,
                "Ambient UDP disabled cleanup registry changed"
            );
            self.last_registry_uids = registry_uids;
        }

        let mut desired: HashMap<u64, &PodCaptureTarget> = HashMap::new();
        let mut unresolved_uids = HashSet::new();
        for target in &targets {
            match self.backend.netns_key(target) {
                Ok(netns) => {
                    if self.unresolved_reasons.remove(&target.pod_uid).is_some() {
                        info!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            netns_inode = netns,
                            "Ambient UDP disabled cleanup: pod netns resolved after retry"
                        );
                    }
                    desired.entry(netns).or_insert(target);
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
                            "Ambient UDP disabled cleanup: pod netns still not resolvable; will retry"
                        );
                    } else {
                        warn!(
                            pod_uid = %target.pod_uid,
                            cgroup = %target.cgroup_path,
                            %error,
                            "Ambient UDP disabled cleanup: pod netns not resolvable; will retry"
                        );
                    }
                }
            }
        }
        self.unresolved_reasons
            .retain(|uid, _| unresolved_uids.contains(uid));

        let desired_netns: HashSet<u64> = desired.keys().copied().collect();
        self.cleaned_netns
            .retain(|netns| desired_netns.contains(netns));

        let mut cleaned = 0;
        for (netns, target) in desired {
            if self.cleaned_netns.contains(&netns) {
                continue;
            }
            if self.backend.cleanup_udp_capture(target, netns) {
                self.cleaned_netns.insert(netns);
                cleaned += 1;
                info!(
                    netns_inode = netns,
                    pod_uid = %target.pod_uid,
                    "Ambient UDP disabled cleanup: stale pod-netns UDP rules removed"
                );
            } else {
                warn!(
                    netns_inode = netns,
                    pod_uid = %target.pod_uid,
                    "Ambient UDP disabled cleanup failed; will retry"
                );
            }
        }
        cleaned
    }
}

/// Preflight the external tools the Ambient UDP producer needs — a shell plus
/// `ip` + `iptables` (and `ip6tables` when IPv6 UDP capture is REQUIRED) — before
/// starting the manager. The producer runs `sh -c` scripts that call
/// `ip`/`iptables`/`ip6tables` inside each pod netns; a distroless runtime image
/// ships none of them, so without this check every pod's `open_udp_capture` would
/// fail `NotFound`, return `None`, and the manager would retry forever with
/// nothing captured (codex). Fail startup with a clear, actionable message
/// instead. `require_ip6tables` mirrors the per-pod script's FATAL `ip6tables`
/// preflight (`CaptureConfig::udp_ipv6_capture_required`): with
/// `FERRUM_MESH_IP6TABLES_ENABLED=required` + IPv6 UDP CIDRs, an image missing
/// `ip6tables` would otherwise pass startup and then fail every per-pod setup
/// forever — the exact failure mode this check exists to prevent (codex).
/// Non-`cfg`-gated so the `cfg!(target_os = "linux")` runtime gate at the call
/// site compiles on every platform; it only runs on Linux.
pub(crate) fn preflight_capture_tools(require_ip6tables: bool) -> Result<(), String> {
    let probe = preflight_capture_tools_probe(require_ip6tables);
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&probe)
        .output()
        .map_err(|e| {
            format!(
                "Ambient UDP capture is enabled but `sh` is not available in the runtime image \
                 (the producer runs in-netns `sh -c` scripts that call `ip`/`iptables`): {e}. Use a \
                 runtime image that ships a shell + iproute2 + iptables, or unset \
                 FERRUM_MESH_CAPTURE_UDP_ENABLED."
            )
        })?;
    if !output.status.success() {
        let tools = if require_ip6tables {
            "`ip`, `iptables` with the mangle table, and `ip6tables` with the mangle table \
             (IPv6 UDP capture is set to `required`)"
        } else {
            "`ip` and/or `iptables` with the mangle table"
        };
        return Err(format!(
            "Ambient UDP capture is enabled but {tools} are not available in the runtime image; \
             the per-pod-netns producer needs them to install UDP TPROXY rules. Use a runtime \
             image that ships iproute2 + iptables (the distroless default lacks them), or unset \
             FERRUM_MESH_CAPTURE_UDP_ENABLED."
        ));
    }
    Ok(())
}

fn preflight_capture_tools_probe(require_ip6tables: bool) -> String {
    let wait = crate::capture::XTABLES_LOCK_WAIT_SECONDS;
    let mut probe = format!(
        "command -v ip >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1 && \
         iptables -t mangle -w {wait} -L >/dev/null 2>&1"
    );
    if require_ip6tables {
        probe.push_str(&format!(
            " && command -v ip6tables >/dev/null 2>&1 && \
             ip6tables -t mangle -w {wait} -L >/dev/null 2>&1"
        ));
    }
    probe
}

/// Production backend: resolves each pod's netns from its cgroup, installs the
/// UDP TPROXY rules + binds the transparent capture socket INSIDE that netns, and
/// runs the shared capture loop with a pod-netns reply-socket factory.
pub struct ProxyNetnsUdpBackend {
    state: Arc<super::ProxyState>,
    capture_config: crate::capture::CaptureConfig,
    capture_port: u16,
    session_limiter: Arc<super::mesh_udp_capture::MeshUdpSessionLimiter>,
    cleanup_interval_seconds: u64,
    recvmmsg_batch_size: usize,
    session_shard_amount: usize,
    global_shutdown: watch::Receiver<bool>,
}

impl ProxyNetnsUdpBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: Arc<super::ProxyState>,
        capture_config: crate::capture::CaptureConfig,
        capture_port: u16,
        max_sessions: usize,
        cleanup_interval_seconds: u64,
        recvmmsg_batch_size: usize,
        session_shard_amount: usize,
        global_shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            capture_config,
            capture_port,
            session_limiter: Arc::new(super::mesh_udp_capture::MeshUdpSessionLimiter::new(
                max_sessions,
            )),
            cleanup_interval_seconds,
            recvmmsg_batch_size,
            session_shard_amount,
            global_shutdown,
        }
    }
}

/// Production disabled-mode cleanup backend: resolve each enrolled pod netns and
/// run the exact Ferrum UDP teardown there. No sockets are opened and no setup
/// rules are installed.
pub struct ProxyNetnsUdpCleanupBackend {
    include_v6: bool,
}

impl ProxyNetnsUdpCleanupBackend {
    pub fn new(include_v6: bool) -> Self {
        Self { include_v6 }
    }
}

#[cfg(target_os = "linux")]
impl NetnsUdpCleanupBackend for ProxyNetnsUdpCleanupBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        super::netns_capture::netns_inode_for_cgroup(&target.cgroup_path).map_err(|e| e.to_string())
    }

    fn cleanup_udp_capture(&self, target: &PodCaptureTarget, expected_netns: u64) -> bool {
        let netns = match super::netns_capture::open_pod_netns_handle(&target.cgroup_path) {
            Ok(file) => file,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP disabled cleanup: could not open pod netns handle"
                );
                return false;
            }
        };
        let opened_netns = match netns
            .metadata()
            .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
        {
            Ok(inode) => inode,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP disabled cleanup: could not read opened pod netns identity"
                );
                return false;
            }
        };
        if opened_netns != expected_netns {
            warn!(
                pod_uid = %target.pod_uid,
                cgroup = %target.cgroup_path,
                reconciled_netns_inode = expected_netns,
                opened_netns_inode = opened_netns,
                "Ambient UDP disabled cleanup: pod netns changed between reconcile and cleanup"
            );
            return false;
        }
        match super::netns_capture::host_netns_inode() {
            Ok(host_ino) if opened_netns == host_ino => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    netns_inode = opened_netns,
                    "Ambient UDP disabled cleanup: target resolves to the host/proxy netns; \
                     refusing to run pod UDP teardown in the node namespace"
                );
                return false;
            }
            Ok(_) => {}
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP disabled cleanup: could not compare pod vs host netns identity"
                );
                return false;
            }
        }

        let teardown_script = crate::capture::IptablesPlan::udp_teardown_script(self.include_v6);
        match super::netns_capture::run_in_netns(&netns, move || run_shell_script(&teardown_script))
        {
            Ok(()) => true,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    netns_inode = opened_netns,
                    %error,
                    "Ambient UDP disabled cleanup: pod-netns UDP teardown failed"
                );
                false
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl NetnsUdpCleanupBackend for ProxyNetnsUdpCleanupBackend {
    fn netns_key(&self, _target: &PodCaptureTarget) -> Result<u64, String> {
        let _ = self.include_v6;
        Err("Ambient UDP disabled cleanup is Linux-only".to_string())
    }

    fn cleanup_udp_capture(&self, _target: &PodCaptureTarget, _expected_netns: u64) -> bool {
        let _ = self.include_v6;
        false
    }
}

#[cfg(target_os = "linux")]
impl NetnsUdpBackend for ProxyNetnsUdpBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        super::netns_capture::netns_inode_for_cgroup(&target.cgroup_path).map_err(|e| e.to_string())
    }

    fn open_udp_capture(
        &self,
        target: &PodCaptureTarget,
        expected_netns: u64,
    ) -> Option<OpenedUdpCapture> {
        use crate::capture::{Ip6TablesMode, IptablesPlan};

        // The UDP-only setup + teardown scripts for THIS pod netns. `host_netns`
        // is never set here (the producer runs against the pod netns), but the
        // scripts still fail closed if UDP capture is somehow disabled.
        let setup_script = IptablesPlan::udp_setup_script(&self.capture_config);
        if setup_script.is_empty() {
            warn!(
                pod_uid = %target.pod_uid,
                "Ambient UDP producer: empty UDP setup script (capture disabled?); not opening"
            );
            return None;
        }
        let include_v6 = self.capture_config.ip6tables_mode != Ip6TablesMode::Disabled;
        let teardown_script = IptablesPlan::udp_teardown_script(include_v6);
        let capture_teardown_script = IptablesPlan::udp_capture_rules_teardown_script(include_v6);
        let fail_closed_script = IptablesPlan::udp_fail_closed_script(&self.capture_config);
        let fail_closed_teardown_script = IptablesPlan::udp_fail_closed_teardown_script(include_v6);

        // Stable netns handle for the whole capture lifetime (survives PID exit).
        let netns = match super::netns_capture::open_pod_netns_handle(&target.cgroup_path) {
            Ok(file) => Arc::new(file),
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP producer: could not open pod netns handle"
                );
                return None;
            }
        };

        let opened_netns = match netns
            .metadata()
            .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
        {
            Ok(inode) => inode,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP producer: could not read opened pod netns identity; \
                     refusing to install pod UDP rules (fail closed)"
                );
                return None;
            }
        };
        if opened_netns != expected_netns {
            warn!(
                pod_uid = %target.pod_uid,
                cgroup = %target.cgroup_path,
                reconciled_netns_inode = expected_netns,
                opened_netns_inode = opened_netns,
                "Ambient UDP producer: pod netns changed between reconcile and open; \
                 refusing to install rules under a stale key"
            );
            return None;
        }

        // Refuse to run pod UDP setup INSIDE the host/proxy network namespace.
        // A registry entry can resolve to the host netns for a mesh-labeled
        // `hostNetwork` workload, or a stale/manual entry whose cgroup points at
        // a host-netns process. Running the setup there would install the
        // TPROXY/OUTPUT rules in the NODE namespace and divert host UDP into a
        // pod capture socket. Compare the identity of the netns we are about to
        // `setns` into (the inode of the opened `/proc/<pid>/ns/net` handle)
        // against our own (host) netns inode; skip when they match. Fail closed:
        // if either inode cannot be read we cannot prove the target is not the
        // host netns, so we do NOT install rules.
        match super::netns_capture::host_netns_inode() {
            Ok(host_ino) => {
                if opened_netns == host_ino {
                    warn!(
                        pod_uid = %target.pod_uid,
                        cgroup = %target.cgroup_path,
                        netns_inode = opened_netns,
                        "Ambient UDP producer: target resolves to the host/proxy netns \
                         (hostNetwork or stale entry); refusing to install pod UDP rules \
                         in the node namespace"
                    );
                    return None;
                }
            }
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    %error,
                    "Ambient UDP producer: could not compare pod vs host netns identity; \
                     refusing to install pod UDP rules (fail closed)"
                );
                return None;
            }
        }

        // Best-effort in-netns teardown helper (pod removal / failure paths).
        // `Fn` (clones its captures per call) so it can be borrowed on the error
        // paths AND moved into the loop's cleanup task.
        let teardown = {
            let netns = netns.clone();
            let teardown_script = teardown_script.clone();
            move || {
                let netns = netns.clone();
                let teardown_script = teardown_script.clone();
                let _ = super::netns_capture::run_in_netns(netns.as_ref(), move || {
                    run_shell_script(&teardown_script)
                });
            }
        };
        // Capture-only cleanup leaves the pre-bind fail-closed guard in place.
        // Used on bind/adoption/setup failures so a retry never reopens egress.
        let teardown_capture_rules = {
            let netns = netns.clone();
            let capture_teardown_script = capture_teardown_script.clone();
            move || {
                let netns = netns.clone();
                let capture_teardown_script = capture_teardown_script.clone();
                let _ = super::netns_capture::run_in_netns(netns.as_ref(), move || {
                    run_shell_script(&capture_teardown_script)
                });
            }
        };

        // Install a scope-exact DROP guard first, then reap/rebuild the normal
        // capture state and bind the socket — all inside the pod netns on one
        // `setns`-bound thread. The guard uses independent alternating chains, so
        // neither stale-state cleanup nor a retry flushes the active guard. It is
        // removed only after the socket is adopted below and the complete TPROXY
        // ruleset is live.
        let bind_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            self.capture_port,
        );
        let setup_for_thread = setup_script;
        let teardown_pre = capture_teardown_script.clone();
        let fail_closed_for_thread = fail_closed_script;
        let bind_result = super::netns_capture::run_in_netns(netns.as_ref(), move || {
            // Guard before touching stale state or attempting the unprivileged
            // bind. A workload that pre-bound the port can no longer win a
            // capture-bypass window between cleanup and bind failure.
            run_shell_script(&fail_closed_for_thread)?;
            // Reap only normal capture state; the dedicated guard stays live.
            let _ = run_shell_script(&teardown_pre);
            let (socket, bound_addr, v4_origdst, v6_origdst) =
                super::mesh_udp_capture::bind_mesh_udp_capture_socket(bind_addr)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            if let Err(error) = run_shell_script(&setup_for_thread) {
                let _ = run_shell_script(&teardown_pre);
                return Err(error);
            }
            Ok((socket, bound_addr, v4_origdst, v6_origdst))
        });
        let (std_socket, bound_addr, v4_origdst, v6_origdst) = match bind_result {
            Ok(result) => result,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    %error,
                    "Ambient UDP producer: in-netns guard / socket bind / rule install failed; fail-closed guard retained when installed"
                );
                return None;
            }
        };

        let frontend_socket = match tokio::net::UdpSocket::from_std(std_socket) {
            Ok(socket) => socket,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    %error,
                    "Ambient UDP producer: could not adopt in-netns capture socket; retaining fail-closed guard"
                );
                teardown_capture_rules();
                return None;
            }
        };

        // The Tokio socket now owns the bound descriptor and the complete live
        // capture rules are installed. Remove the temporary guard so traffic
        // switches directly from fail-closed DROP to TPROXY capture. If setns or
        // guard cleanup fails, keep the guard and remove normal capture state;
        // the next reconcile retries without a plaintext bypass.
        let guard_teardown = {
            let script = fail_closed_teardown_script;
            super::netns_capture::run_in_netns(netns.as_ref(), move || run_shell_script(&script))
        };
        if let Err(error) = guard_teardown {
            warn!(
                pod_uid = %target.pod_uid,
                %error,
                "Ambient UDP producer: could not remove pre-bind fail-closed guard; retaining guard and retrying"
            );
            teardown_capture_rules();
            return None;
        }

        let reply_socket_factory: Arc<dyn super::mesh_udp_capture::ReplySocketFactory> = Arc::new(
            super::mesh_udp_capture::PodNetnsReplySocketFactory::new(netns.clone()),
        );
        let runtime = super::mesh_udp_capture::MeshUdpCaptureRuntime {
            state: self.state.clone(),
            cleanup_interval_seconds: self.cleanup_interval_seconds,
            recvmmsg_batch_size: self.recvmmsg_batch_size,
            session_shard_amount: self.session_shard_amount,
            session_limiter: self.session_limiter.clone(),
            reply_socket_factory,
        };

        let (stop_tx, stop_rx) = watch::channel(false);
        let global_shutdown = self.global_shutdown.clone();
        let pod_uid = target.pod_uid.clone();
        info!(
            pod_uid = %pod_uid,
            bound = %bound_addr,
            v4_origdst,
            v6_origdst,
            "Ambient UDP producer: per-pod-netns capture socket bound and rules installed"
        );
        // Keep the supervising task's handle so graceful shutdown can await its
        // in-netns teardown (codex): the task runs the capture loop until stopped,
        // then removes THIS netns's UDP rules.
        let task = tokio::spawn(async move {
            let _ = super::mesh_udp_capture::run_mesh_udp_capture_on_socket(
                frontend_socket,
                bound_addr,
                v4_origdst,
                v6_origdst,
                runtime,
                stop_rx,
                Some(global_shutdown),
                None,
            )
            .await;
            // The loop ended (pod removed / shutdown / error): tear down THIS
            // netns's UDP rules. `setns` + `sh -c` are blocking, so run them off
            // the runtime. Best-effort: an already-gone pod netns is expected.
            let _ = tokio::task::spawn_blocking(move || {
                teardown();
                debug!(pod_uid = %pod_uid, "Ambient UDP producer: per-pod-netns UDP rules torn down");
            })
            .await;
        });

        Some(OpenedUdpCapture::new(stop_tx, task))
    }
}

#[cfg(not(target_os = "linux"))]
impl NetnsUdpBackend for ProxyNetnsUdpBackend {
    fn netns_key(&self, _target: &PodCaptureTarget) -> Result<u64, String> {
        Err("Ambient per-pod-netns UDP capture is Linux-only".to_string())
    }

    fn open_udp_capture(
        &self,
        _target: &PodCaptureTarget,
        _expected_netns: u64,
    ) -> Option<OpenedUdpCapture> {
        // Touch every field so the non-Linux build does not flag them dead.
        let _ = (
            &self.state,
            &self.capture_config,
            self.capture_port,
            &self.session_limiter,
            self.cleanup_interval_seconds,
            self.recvmmsg_batch_size,
            self.session_shard_amount,
            &self.global_shutdown,
        );
        warn!("Ambient per-pod-netns UDP capture is Linux-only; not opening");
        None
    }
}

/// Run a shell script (`sh -c`) synchronously and fail on a non-zero exit. Called
/// only from inside a `setns`-bound thread ([`super::netns_capture::run_in_netns`]),
/// so the child process inherits the pod netns — the same mechanism `ip netns
/// exec` uses. An empty script is a no-op. Setup scripts carry `set -e` (fail
/// closed); teardown scripts carry per-command `|| true` guards (best-effort).
#[cfg(target_os = "linux")]
fn run_shell_script(script: &str) -> std::io::Result<()> {
    if script.trim().is_empty() {
        return Ok(());
    }
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "in-netns script failed (exit {:?}): {}",
            output.status.code(),
            stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// One ordered lifecycle event, recorded so the reopen-after-close ordering
    /// (teardown-before-install) can be asserted, not just the open/close sets.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Opened(u64),
        TornDown(u64),
    }

    /// Mock backend: maps each pod cgroup path to a caller-provided netns inode
    /// and records every open/close so the reconcile diff can be asserted without
    /// a real netns, `setns`, or iptables.
    struct MockBackend {
        netns_by_cgroup: Mutex<HashMap<String, Option<u64>>>,
        open_netns_by_cgroup: Mutex<HashMap<String, Option<u64>>>,
        opened: Arc<Mutex<Vec<u64>>>,
        closed: Arc<Mutex<Vec<u64>>>,
        /// Ordered open/teardown log across all netns, used by the reopen-race
        /// regression test to prove a prior teardown completes before reinstall.
        events: Arc<Mutex<Vec<Event>>>,
        /// netns inodes for which `open_udp_capture` should fail (retry testing).
        fail_open: Mutex<HashSet<u64>>,
        /// When true, `close()` returns a real supervising task that records the
        /// teardown only AFTER yielding — so a reopen that does not await it would
        /// record `Opened(N)` before `TornDown(N)` in `events`. This models the
        /// production lagging fire-and-forget teardown the fix must serialize.
        slow_teardown: bool,
    }

    impl MockBackend {
        fn new(mapping: &[(&str, Option<u64>)]) -> Self {
            Self {
                netns_by_cgroup: Mutex::new(
                    mapping.iter().map(|(c, n)| (c.to_string(), *n)).collect(),
                ),
                open_netns_by_cgroup: Mutex::new(HashMap::new()),
                opened: Arc::new(Mutex::new(Vec::new())),
                closed: Arc::new(Mutex::new(Vec::new())),
                events: Arc::new(Mutex::new(Vec::new())),
                fail_open: Mutex::new(HashSet::new()),
                slow_teardown: false,
            }
        }

        /// Variant whose closed producers carry a real (lagging) teardown task, so
        /// the reopen path must await it. Mirrors the production supervising task.
        fn new_with_slow_teardown(mapping: &[(&str, Option<u64>)]) -> Self {
            let mut backend = Self::new(mapping);
            backend.slow_teardown = true;
            backend
        }

        fn set_netns(&self, cgroup: &str, netns: Option<u64>) {
            self.netns_by_cgroup
                .lock()
                .unwrap()
                .insert(cgroup.to_string(), netns);
        }

        fn set_open_netns(&self, cgroup: &str, netns: Option<u64>) {
            self.open_netns_by_cgroup
                .lock()
                .unwrap()
                .insert(cgroup.to_string(), netns);
        }

        fn set_fail_open(&self, netns: u64, fail: bool) {
            let mut set = self.fail_open.lock().unwrap();
            if fail {
                set.insert(netns);
            } else {
                set.remove(&netns);
            }
        }
    }

    impl NetnsUdpBackend for MockBackend {
        fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
            match self
                .netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
            {
                Some(Some(netns)) => Ok(*netns),
                _ => Err(format!("netns unresolved for {}", target.cgroup_path)),
            }
        }

        fn open_udp_capture(
            &self,
            target: &PodCaptureTarget,
            expected_netns: u64,
        ) -> Option<OpenedUdpCapture> {
            let open_netns = self
                .open_netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
                .copied();
            let netns = open_netns
                .unwrap_or_else(|| {
                    *self
                        .netns_by_cgroup
                        .lock()
                        .unwrap()
                        .get(&target.cgroup_path)
                        .unwrap()
                })
                .unwrap();
            if netns != expected_netns {
                return None;
            }
            if self.fail_open.lock().unwrap().contains(&netns) {
                return None;
            }
            self.opened.lock().unwrap().push(netns);
            self.events.lock().unwrap().push(Event::Opened(netns));
            let (stop_tx, mut stop_rx) = watch::channel(false);
            let closed = self.closed.clone();
            let events = self.events.clone();
            if self.slow_teardown {
                // Real supervising task, like production: wait for the stop
                // signal, then yield before recording teardown so a non-awaited
                // reopen would interleave ahead of it.
                let task = tokio::spawn(async move {
                    let _ = stop_rx.changed().await;
                    tokio::task::yield_now().await;
                    tokio::task::yield_now().await;
                    closed.lock().unwrap().push(netns);
                    events.lock().unwrap().push(Event::TornDown(netns));
                });
                Some(OpenedUdpCapture::new(stop_tx, task))
            } else {
                Some(OpenedUdpCapture::with_on_close(
                    stop_tx,
                    Box::new(move || {
                        closed.lock().unwrap().push(netns);
                        events.lock().unwrap().push(Event::TornDown(netns));
                    }),
                ))
            }
        }
    }

    impl NetnsUdpCleanupBackend for MockBackend {
        fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
            match self
                .netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
            {
                Some(Some(netns)) => Ok(*netns),
                _ => Err(format!("netns unresolved for {}", target.cgroup_path)),
            }
        }

        fn cleanup_udp_capture(&self, target: &PodCaptureTarget, expected_netns: u64) -> bool {
            let netns = *self
                .netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
                .unwrap();
            let Some(netns) = netns else {
                return false;
            };
            if netns != expected_netns || self.fail_open.lock().unwrap().contains(&netns) {
                return false;
            }
            self.closed.lock().unwrap().push(netns);
            self.events.lock().unwrap().push(Event::TornDown(netns));
            true
        }
    }

    struct StaticSource(Mutex<Vec<PodCaptureTarget>>);
    impl PodCaptureSource for StaticSource {
        fn list_targets(&self) -> Vec<PodCaptureTarget> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|t| PodCaptureTarget {
                    pod_uid: t.pod_uid.clone(),
                    cgroup_path: t.cgroup_path.clone(),
                    source_ips: t.source_ips,
                })
                .collect()
        }
    }

    fn target(uid: &str, cgroup: &str) -> PodCaptureTarget {
        PodCaptureTarget {
            pod_uid: uid.to_string(),
            cgroup_path: cgroup.to_string(),
            source_ips: Default::default(),
        }
    }

    fn manager(
        source: Arc<StaticSource>,
        backend: MockBackend,
    ) -> NetnsUdpCaptureManager<MockBackend> {
        NetnsUdpCaptureManager::new(15011, source, backend, Duration::from_secs(2))
    }

    fn cleanup_manager(
        source: Arc<StaticSource>,
        backend: MockBackend,
    ) -> NetnsUdpCleanupManager<MockBackend> {
        NetnsUdpCleanupManager::new(source, backend, Duration::from_secs(2))
    }

    #[tokio::test]
    async fn opens_one_producer_per_netns_and_dedupes_shared_netns() {
        // Two pods in ONE netns (shared) + one pod in another → 2 producers.
        let source = Arc::new(StaticSource(Mutex::new(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
            target("pod-c", "/cg/c"),
        ])));
        let backend = MockBackend::new(&[
            ("/cg/a", Some(100)),
            ("/cg/b", Some(100)),
            ("/cg/c", Some(200)),
        ]);
        let opened = backend.opened.clone();
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once().await, 2);
        let mut got = opened.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200], "one producer per distinct netns");
        // Idempotent: a second reconcile opens nothing new.
        assert_eq!(mgr.reconcile_once().await, 2);
        assert_eq!(opened.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn closes_producer_and_cleans_up_when_pod_removed() {
        let targets = Mutex::new(vec![target("pod-a", "/cg/a")]);
        let source = Arc::new(StaticSource(targets));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let closed = backend.closed.clone();
        let mut mgr = manager(source.clone(), backend);
        assert_eq!(mgr.reconcile_once().await, 1);
        // Pod removed from the registry → producer closed + cleanup invoked.
        source.0.lock().unwrap().clear();
        assert_eq!(mgr.reconcile_once().await, 0);
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "closing a producer must run its teardown"
        );
    }

    #[tokio::test]
    async fn transient_unresolvable_netns_does_not_flap_producer() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let closed = backend.closed.clone();
        // Take a raw pointer-free reference by keeping the source Arc; we mutate
        // the backend map through a shared handle instead.
        let netns_map_probe = "/cg/a";
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once().await, 1);
        // Netns momentarily unresolvable (container restart) — producer retained.
        mgr.backend.set_netns(netns_map_probe, None);
        assert_eq!(
            mgr.reconcile_once().await,
            1,
            "an unresolvable-but-still-registered pod keeps its producer (grace)"
        );
        assert!(
            closed.lock().unwrap().is_empty(),
            "must not flap on a PID race"
        );
        // Resolves again → still one, no reopen.
        mgr.backend.set_netns(netns_map_probe, Some(100));
        assert_eq!(mgr.reconcile_once().await, 1);
    }

    #[tokio::test]
    async fn pod_moving_netns_reopens_in_new_netns() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let opened = backend.opened.clone();
        let closed = backend.closed.clone();
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once().await, 1);
        // Pod's sandbox restarted into a new netns inode.
        mgr.backend.set_netns("/cg/a", Some(300));
        assert_eq!(mgr.reconcile_once().await, 1);
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "old netns producer closed"
        );
        assert_eq!(*opened.lock().unwrap(), vec![100, 300], "new netns opened");
    }

    #[tokio::test]
    async fn open_failure_is_retried_next_reconcile() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        backend.set_fail_open(100, true);
        let opened = backend.opened.clone();
        let mut mgr = manager(source, backend);
        // First pass fails to open → no active producer.
        assert_eq!(mgr.reconcile_once().await, 0);
        assert!(opened.lock().unwrap().is_empty());
        // Recover → next reconcile opens it.
        mgr.backend.set_fail_open(100, false);
        assert_eq!(mgr.reconcile_once().await, 1);
        assert_eq!(*opened.lock().unwrap(), vec![100]);
    }

    #[tokio::test]
    async fn opened_netns_mismatch_skips_stale_key_and_retries() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        backend.set_open_netns("/cg/a", Some(200));
        let opened = backend.opened.clone();
        let mut mgr = manager(source, backend);

        assert_eq!(
            mgr.reconcile_once().await,
            0,
            "a producer must not be marked active under a stale reconciled inode"
        );
        assert!(
            opened.lock().unwrap().is_empty(),
            "mismatched second lookup must not install rules"
        );

        mgr.backend.set_netns("/cg/a", Some(200));
        assert_eq!(mgr.reconcile_once().await, 1);
        assert_eq!(
            *opened.lock().unwrap(),
            vec![200],
            "the next consistent reconcile opens under the actual netns"
        );
    }

    #[tokio::test]
    async fn shutdown_all_closes_every_producer() {
        let source = Arc::new(StaticSource(Mutex::new(vec![
            target("pod-a", "/cg/a"),
            target("pod-c", "/cg/c"),
        ])));
        let backend = MockBackend::new(&[("/cg/a", Some(100)), ("/cg/c", Some(200))]);
        let closed = backend.closed.clone();
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once().await, 2);
        mgr.shutdown_all().await;
        let mut got = closed.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200], "shutdown closes every producer");
    }

    /// The core codex fix: a registry flap (a pod's netns closed, then the same
    /// netns reopened before the old teardown finished) must AWAIT the prior
    /// teardown to completion BEFORE the new producer installs its rules — so the
    /// lagging teardown can never delete the fresh `FERRUM_MESH_UDP_*` chains and
    /// silently drop the pod out of mesh capture. With the (lagging) slow-teardown
    /// mock, a fire-and-forget close would record `Opened(100)` before
    /// `TornDown(100)`; the fix forces `TornDown(100)` first.
    #[tokio::test]
    async fn reopening_same_netns_awaits_prior_teardown_before_reinstall() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new_with_slow_teardown(&[("/cg/a", Some(100))]);
        let events = backend.events.clone();
        let mut mgr = manager(source.clone(), backend);
        // Open the producer for netns 100.
        assert_eq!(mgr.reconcile_once().await, 1);
        // Registry file for the pod disappears → producer closed (teardown starts
        // but lags, mirroring the fire-and-forget supervising task).
        source.0.lock().unwrap().clear();
        assert_eq!(mgr.reconcile_once().await, 0);
        // Registry file reappears for the SAME pod netns → producer reopened. The
        // reopen must await the lagging teardown first.
        source.0.lock().unwrap().push(target("pod-a", "/cg/a"));
        assert_eq!(mgr.reconcile_once().await, 1);
        // Ordering proof: the first netns-100 teardown completed BEFORE the second
        // netns-100 open, so the old teardown cannot delete the new chains.
        let log = events.lock().unwrap().clone();
        let second_open = log
            .iter()
            .enumerate()
            .filter(|(_, e)| **e == Event::Opened(100))
            .nth(1)
            .map(|(i, _)| i)
            .expect("netns 100 must be opened twice (flap → reopen)");
        let first_teardown = log
            .iter()
            .position(|e| *e == Event::TornDown(100))
            .expect("the first producer must have been torn down");
        assert!(
            first_teardown < second_open,
            "prior teardown must complete before reinstall; got {log:?}"
        );
    }

    /// A netns closed but not reopened must still have its lagging teardown drained
    /// on shutdown (not just the currently-active producers), so the process does
    /// not exit ahead of that netns's in-netns rule deletion.
    #[tokio::test]
    async fn shutdown_drains_pending_teardown_of_closed_producer() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new_with_slow_teardown(&[("/cg/a", Some(100))]);
        let closed = backend.closed.clone();
        let mut mgr = manager(source.clone(), backend);
        assert_eq!(mgr.reconcile_once().await, 1);
        // Pod removed → producer closed; its teardown is still in flight (pending).
        source.0.lock().unwrap().clear();
        assert_eq!(mgr.reconcile_once().await, 0);
        // Shutdown must await the pending teardown, so it is recorded by the time
        // shutdown returns.
        mgr.shutdown_all().await;
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "shutdown must drain the pending teardown of a closed-but-not-reopened producer"
        );
    }

    #[tokio::test]
    async fn disabled_cleanup_reaps_each_netns_once_and_dedupes_shared_netns() {
        let source = Arc::new(StaticSource(Mutex::new(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
            target("pod-c", "/cg/c"),
        ])));
        let backend = MockBackend::new(&[
            ("/cg/a", Some(100)),
            ("/cg/b", Some(100)),
            ("/cg/c", Some(200)),
        ]);
        let cleaned = backend.closed.clone();
        let mut mgr = cleanup_manager(source, backend);

        assert_eq!(mgr.cleanup_once(), 2);
        let mut got = cleaned.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200], "cleanup runs once per netns");

        assert_eq!(mgr.cleanup_once(), 0, "already-cleaned netns are skipped");
        let mut got = cleaned.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200]);
    }

    #[tokio::test]
    async fn disabled_cleanup_retries_failed_netns_cleanup() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        backend.set_fail_open(100, true);
        let cleaned = backend.closed.clone();
        let mut mgr = cleanup_manager(source, backend);

        assert_eq!(mgr.cleanup_once(), 0);
        assert!(cleaned.lock().unwrap().is_empty());

        mgr.backend.set_fail_open(100, false);
        assert_eq!(mgr.cleanup_once(), 1);
        assert_eq!(*cleaned.lock().unwrap(), vec![100]);
    }

    #[test]
    fn preflight_probe_checks_required_ip6tables_mangle_table() {
        let probe = preflight_capture_tools_probe(true);
        assert!(probe.contains("command -v ip6tables"));
        assert!(
            probe.contains("ip6tables -t mangle"),
            "IPv6 UDP preflight must probe the mangle table, not only the binary: {probe}"
        );
        assert!(
            !probe.contains("ip6tables -t nat"),
            "UDP preflight must not probe the nat table: {probe}"
        );
    }
}

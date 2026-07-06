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
//!   1. binds a transparent UDP capture socket INSIDE the pod netns, then
//!   2. installs the UDP TPROXY rules INSIDE the pod netns (socket first, so the
//!      rules never divert into a not-yet-bound socket — no black-hole window),
//!   3. runs the shared capture/session/egress loop
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
    /// loop INSIDE the target pod's netns. `None` on failure (retried next
    /// reconcile); the backend must leave no partial rules behind on failure.
    fn open_udp_capture(&self, target: &PodCaptureTarget) -> Option<OpenedUdpCapture>;
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
        self.shutdown_all().await;
    }

    /// One reconcile pass: open producers for newly enrolled pod netns, close
    /// producers whose pods are all gone. Returns the count of active producers
    /// (used by tests).
    fn reconcile_once(&mut self) -> usize {
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
                // Pod removal: fire-and-forget. Dropping the handle does not abort
                // the supervising task, so its in-netns rule teardown still runs.
                let _ = active.handle.close();
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
            match self.backend.open_udp_capture(target) {
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
    let mut probe =
        String::from("command -v ip >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1");
    if require_ip6tables {
        probe.push_str(" && command -v ip6tables >/dev/null 2>&1");
    }
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
            "`ip`, `iptables`, and `ip6tables` (IPv6 UDP capture is set to `required`)"
        } else {
            "`ip` and/or `iptables`"
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

/// Production backend: resolves each pod's netns from its cgroup, installs the
/// UDP TPROXY rules + binds the transparent capture socket INSIDE that netns, and
/// runs the shared capture loop with a pod-netns reply-socket factory.
pub struct ProxyNetnsUdpBackend {
    state: Arc<super::ProxyState>,
    capture_config: crate::capture::CaptureConfig,
    capture_port: u16,
    max_sessions: usize,
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
            max_sessions,
            cleanup_interval_seconds,
            recvmmsg_batch_size,
            session_shard_amount,
            global_shutdown,
        }
    }
}

#[cfg(target_os = "linux")]
impl NetnsUdpBackend for ProxyNetnsUdpBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Result<u64, String> {
        super::netns_capture::netns_inode_for_cgroup(&target.cgroup_path).map_err(|e| e.to_string())
    }

    fn open_udp_capture(&self, target: &PodCaptureTarget) -> Option<OpenedUdpCapture> {
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

        // Bind the capture socket, THEN install the rules — both INSIDE the pod
        // netns, on one `setns`-bound thread. Socket-first means the TPROXY rules
        // never divert into a not-yet-bound socket (no black-hole window). A
        // reconfigure reaps stale rules first (idempotent teardown) so a changed
        // port/mark can't leave a stale rule ahead of the new one.
        let bind_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            self.capture_port,
        );
        let setup_for_thread = setup_script;
        let teardown_pre = teardown_script.clone();
        let bind_result = super::netns_capture::run_in_netns(netns.as_ref(), move || {
            // Reap any stale UDP rules from a prior crashed producer first.
            let _ = run_shell_script(&teardown_pre);
            let (socket, bound_addr, v4_origdst, v6_origdst) =
                super::mesh_udp_capture::bind_mesh_udp_capture_socket(bind_addr)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            run_shell_script(&setup_for_thread)?;
            Ok((socket, bound_addr, v4_origdst, v6_origdst))
        });
        let (std_socket, bound_addr, v4_origdst, v6_origdst) = match bind_result {
            Ok(result) => result,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    %error,
                    "Ambient UDP producer: in-netns socket bind / rule install failed; cleaning up"
                );
                teardown();
                return None;
            }
        };

        let frontend_socket = match tokio::net::UdpSocket::from_std(std_socket) {
            Ok(socket) => socket,
            Err(error) => {
                warn!(
                    pod_uid = %target.pod_uid,
                    %error,
                    "Ambient UDP producer: could not adopt in-netns capture socket; cleaning up"
                );
                teardown();
                return None;
            }
        };

        let reply_socket_factory: Arc<dyn super::mesh_udp_capture::ReplySocketFactory> = Arc::new(
            super::mesh_udp_capture::PodNetnsReplySocketFactory::new(netns.clone()),
        );
        let runtime = super::mesh_udp_capture::MeshUdpCaptureRuntime {
            state: self.state.clone(),
            max_sessions: self.max_sessions,
            cleanup_interval_seconds: self.cleanup_interval_seconds,
            recvmmsg_batch_size: self.recvmmsg_batch_size,
            session_shard_amount: self.session_shard_amount,
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

    fn open_udp_capture(&self, _target: &PodCaptureTarget) -> Option<OpenedUdpCapture> {
        // Touch every field so the non-Linux build does not flag them dead.
        let _ = (
            &self.state,
            &self.capture_config,
            self.capture_port,
            self.max_sessions,
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

    /// Mock backend: maps each pod cgroup path to a caller-provided netns inode
    /// and records every open/close so the reconcile diff can be asserted without
    /// a real netns, `setns`, or iptables.
    struct MockBackend {
        netns_by_cgroup: Mutex<HashMap<String, Option<u64>>>,
        opened: Arc<Mutex<Vec<u64>>>,
        closed: Arc<Mutex<Vec<u64>>>,
        /// netns inodes for which `open_udp_capture` should fail (retry testing).
        fail_open: Mutex<HashSet<u64>>,
    }

    impl MockBackend {
        fn new(mapping: &[(&str, Option<u64>)]) -> Self {
            Self {
                netns_by_cgroup: Mutex::new(
                    mapping.iter().map(|(c, n)| (c.to_string(), *n)).collect(),
                ),
                opened: Arc::new(Mutex::new(Vec::new())),
                closed: Arc::new(Mutex::new(Vec::new())),
                fail_open: Mutex::new(HashSet::new()),
            }
        }

        fn set_netns(&self, cgroup: &str, netns: Option<u64>) {
            self.netns_by_cgroup
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

        fn open_udp_capture(&self, target: &PodCaptureTarget) -> Option<OpenedUdpCapture> {
            let netns = *self
                .netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
                .unwrap()
                .as_ref()
                .unwrap();
            if self.fail_open.lock().unwrap().contains(&netns) {
                return None;
            }
            self.opened.lock().unwrap().push(netns);
            let (stop_tx, _stop_rx) = watch::channel(false);
            let closed = self.closed.clone();
            Some(OpenedUdpCapture::with_on_close(
                stop_tx,
                Box::new(move || closed.lock().unwrap().push(netns)),
            ))
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

    #[test]
    fn opens_one_producer_per_netns_and_dedupes_shared_netns() {
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
        assert_eq!(mgr.reconcile_once(), 2);
        let mut got = opened.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200], "one producer per distinct netns");
        // Idempotent: a second reconcile opens nothing new.
        assert_eq!(mgr.reconcile_once(), 2);
        assert_eq!(opened.lock().unwrap().len(), 2);
    }

    #[test]
    fn closes_producer_and_cleans_up_when_pod_removed() {
        let targets = Mutex::new(vec![target("pod-a", "/cg/a")]);
        let source = Arc::new(StaticSource(targets));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let closed = backend.closed.clone();
        let mut mgr = manager(source.clone(), backend);
        assert_eq!(mgr.reconcile_once(), 1);
        // Pod removed from the registry → producer closed + cleanup invoked.
        source.0.lock().unwrap().clear();
        assert_eq!(mgr.reconcile_once(), 0);
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "closing a producer must run its teardown"
        );
    }

    #[test]
    fn transient_unresolvable_netns_does_not_flap_producer() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let closed = backend.closed.clone();
        // Take a raw pointer-free reference by keeping the source Arc; we mutate
        // the backend map through a shared handle instead.
        let netns_map_probe = "/cg/a";
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once(), 1);
        // Netns momentarily unresolvable (container restart) — producer retained.
        mgr.backend.set_netns(netns_map_probe, None);
        assert_eq!(
            mgr.reconcile_once(),
            1,
            "an unresolvable-but-still-registered pod keeps its producer (grace)"
        );
        assert!(
            closed.lock().unwrap().is_empty(),
            "must not flap on a PID race"
        );
        // Resolves again → still one, no reopen.
        mgr.backend.set_netns(netns_map_probe, Some(100));
        assert_eq!(mgr.reconcile_once(), 1);
    }

    #[test]
    fn pod_moving_netns_reopens_in_new_netns() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        let opened = backend.opened.clone();
        let closed = backend.closed.clone();
        let mut mgr = manager(source, backend);
        assert_eq!(mgr.reconcile_once(), 1);
        // Pod's sandbox restarted into a new netns inode.
        mgr.backend.set_netns("/cg/a", Some(300));
        assert_eq!(mgr.reconcile_once(), 1);
        assert_eq!(
            *closed.lock().unwrap(),
            vec![100],
            "old netns producer closed"
        );
        assert_eq!(*opened.lock().unwrap(), vec![100, 300], "new netns opened");
    }

    #[test]
    fn open_failure_is_retried_next_reconcile() {
        let source = Arc::new(StaticSource(Mutex::new(vec![target("pod-a", "/cg/a")])));
        let backend = MockBackend::new(&[("/cg/a", Some(100))]);
        backend.set_fail_open(100, true);
        let opened = backend.opened.clone();
        let mut mgr = manager(source, backend);
        // First pass fails to open → no active producer.
        assert_eq!(mgr.reconcile_once(), 0);
        assert!(opened.lock().unwrap().is_empty());
        // Recover → next reconcile opens it.
        mgr.backend.set_fail_open(100, false);
        assert_eq!(mgr.reconcile_once(), 1);
        assert_eq!(*opened.lock().unwrap(), vec![100]);
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
        assert_eq!(mgr.reconcile_once(), 2);
        mgr.shutdown_all().await;
        let mut got = closed.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![100, 200], "shutdown closes every producer");
    }
}

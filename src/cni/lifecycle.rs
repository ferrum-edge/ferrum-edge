//! Install lifecycle for the chained `ferrum-cni` plugin: readiness-gated
//! automatic rollback, and the readiness marker the Helm cleanup hook uses to
//! report completion.
//!
//! # Why a rollback watcher exists
//!
//! Once `ferrum-cni install` writes the chained conflist, every pod ADD on
//! that node traverses `ferrum-cni`, and an unanswered ADD fails closed. That
//! is the intended capture-race posture, but it means an install that never
//! reaches a usable node-agent is a node-wide pod-creation outage rather than
//! a degraded optimization (issue #3609).
//!
//! The watcher runs beside the node-agent in the same pod. It polls the CNI
//! STATUS verb — the same readiness boundary kubelet would observe — and:
//!
//! - the moment STATUS answers `Ok`, it retains the artifacts permanently for
//!   that pod. A node-agent that later crashes is NOT rolled back: it was
//!   proven usable once, so removing the chain would silently drop capture
//!   for pods that are still expected to be enrolled.
//! - if STATUS never answers `Ok` before the deadline, it removes the
//!   artifacts **this pod's own installer wrote** and exits non-zero, so the
//!   node keeps creating pods and the failure stays visible.
//!
//! # Why the readiness budget does not start at container start
//!
//! The watcher is a native sidecar and therefore starts *before* the
//! installer init container. If its budget started immediately it could
//! expire while the installer was still working, delete this generation's
//! staged state, and then watch the installer publish a conflist nothing was
//! left to remove — manufacturing exactly the stranded chain the watcher
//! exists to prevent.
//!
//! So the run has two phases with distinct ownership:
//!
//! 1. **Publication.** Poll until the generated conflist carries *this*
//!    owner and generation. That file is written last and atomically, so its
//!    presence is the only observable proof that the install completed and
//!    the node now depends on the node-agent. An installer that never
//!    publishes never created a dependency of ITS OWN, so there is nothing
//!    for this watcher to roll back and it reports
//!    [`RollbackWatchOutcome::NeverPublished`].
//!
//!    That is only safe because a previous generation's chain is not this
//!    watcher's problem either: a failed same-owner upgrade lifts the chain
//!    it found itself, on `install`'s own error path and under the same lock
//!    (see [`crate::cni::install::install`]). Without that, a generation-N
//!    watcher would time out as `NeverPublished` while generation N-1's chain
//!    still routed every pod ADD through a socket nothing would answer.
//! 2. **Readiness.** Only now does the budget start, and only now is STATUS
//!    probed at all. A STATUS answer observed *before* publication says
//!    nothing about this generation — the socket path is node-scoped and a
//!    previous node-agent generation can still be answering on it — so
//!    treating it as readiness would permanently disarm the rollback for a
//!    chain that had not been written yet.
//!
//! Cleanup additionally takes the node's install lock
//! ([`crate::cni::install::INSTALL_LOCK_FILE_NAME`]) for its whole run, and
//! re-reads the ownership markers under that lock, so it cannot interleave
//! with a still-running installer at all — and re-verifies the exact
//! device/inode it is about to unlink.
//!
//! Time only decides *when* to act. What may be removed is decided by the
//! ownership evidence written at install: the watcher pins both the owner and
//! the install generation, so a slow start that is overtaken by a newer
//! install (a rollout, an upgrade) can never delete the newer generation's
//! artifacts — that run reports `retained-other-generation` instead.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cni::install::{
    self, CniArtifactOutcome, CniInstallError, CniUninstallConfig, CniUninstallReport,
};

/// Default budget for the node-agent to reach CNI readiness, measured from
/// the moment this generation's conflist is observed on disk. Deliberately
/// generous: a healthy but slow start (image pull, BPF fs mount, initial pod
/// relist on a large node) must not be mistaken for a broken install.
pub const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(300);

/// Default budget for this generation's installer to publish its conflist.
/// Exceeding it means no chain was ever installed by this pod, which is not a
/// node-wide dependency and therefore not something to roll back.
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(300);

/// Default gap between STATUS probes.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Upper bounds so a mistyped value cannot park the watcher forever.
const MAX_READY_TIMEOUT_SECS: u64 = 3600;
const MAX_POLL_INTERVAL_SECS: u64 = 300;

/// Network name used for the STATUS probe when the generated conflist is not
/// (yet) present. STATUS readiness does not depend on the network name; the
/// node-agent only requires a well-formed one.
pub const FALLBACK_STATUS_NETWORK_NAME: &str = "ferrum-mesh";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackWatchConfig {
    pub socket_path: String,
    /// How long this generation's installer gets to publish its conflist
    /// before the watcher concludes no chain was ever installed.
    pub publish_timeout: Duration,
    pub ready_timeout: Duration,
    pub poll_interval: Duration,
    /// Scope of what a rollback may remove. The Helm chart pins both
    /// `expected_owner` and `expected_generation` here.
    pub uninstall: CniUninstallConfig,
}

impl RollbackWatchConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        let ready_timeout = duration_from_env(
            "READY_TIMEOUT_SECS",
            DEFAULT_READY_TIMEOUT,
            MAX_READY_TIMEOUT_SECS,
        )?;
        let publish_timeout = duration_from_env(
            "PUBLISH_TIMEOUT_SECS",
            DEFAULT_PUBLISH_TIMEOUT,
            MAX_READY_TIMEOUT_SECS,
        )?;
        let poll_interval = duration_from_env(
            "POLL_INTERVAL_SECS",
            DEFAULT_POLL_INTERVAL,
            MAX_POLL_INTERVAL_SECS,
        )?;
        Ok(Self {
            socket_path: required_env("SOCKET_PATH")?,
            publish_timeout,
            ready_timeout,
            poll_interval: poll_interval.min(ready_timeout).min(publish_timeout),
            uninstall: CniUninstallConfig::from_env()?,
        })
    }
}

/// How a rollback watch ended.
///
/// The variants are deliberately not collapsed into "rolled back": a run that
/// deleted nothing, and a run that tried and failed, must not be reported to
/// an operator as if the node-wide dependency had been lifted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackWatchOutcome {
    /// The node-agent answered STATUS; artifacts are retained for the
    /// lifetime of this pod.
    Ready,
    /// This generation never published a conflist within the publish budget,
    /// so it never became a node-wide pod-creation dependency. Nothing was
    /// removed here; a previous same-owner chain, if one was present, was
    /// already lifted by the failing installer itself.
    NeverPublished,
    /// The deadline passed and the generation-scoped cleanup removed the
    /// chain: pod creation on this node no longer traverses `ferrum-cni`.
    RolledBack(CniUninstallReport),
    /// The deadline passed, cleanup ran, and the chained conflist is STILL
    /// present — a foreign or unremovable file occupies the configured path.
    /// The node-wide dependency was not lifted.
    RollbackIncomplete(CniUninstallReport),
    /// The deadline passed but a newer install now owns the artifacts. This
    /// run deliberately deleted nothing; the newer generation's own watcher
    /// is responsible for it.
    Superseded(CniUninstallReport),
}

impl RollbackWatchOutcome {
    /// True only when this node no longer depends on the node-agent because
    /// of *this* generation.
    pub fn dependency_cleared(&self) -> bool {
        match self {
            Self::Ready | Self::Superseded(_) => false,
            Self::NeverPublished => true,
            Self::RolledBack(report) | Self::RollbackIncomplete(report) => report.chain_lifted(),
        }
    }
}

/// Poll `probe` until it returns true or the readiness budget is exhausted,
/// then roll back this generation's artifacts.
///
/// `probe` is injected so the decision loop is testable without a live
/// node-agent; the binary passes [`probe_node_agent_status`].
pub fn run_rollback_watch(
    config: &RollbackWatchConfig,
    probe: &mut dyn FnMut() -> bool,
) -> Result<RollbackWatchOutcome, CniInstallError> {
    // Phase 1 — publication. The budget below must not start while the
    // installer may still be working, and cleanup must never run against an
    // install that has not completed.
    //
    // Readiness is deliberately NOT probed here. The STATUS socket is a
    // node-scoped path that outlives any one install: a still-running previous
    // node-agent generation, or a socket left behind by one, answers `Ok` for
    // a chain this generation has not published yet. Accepting that answer
    // would return `Ready` and disarm the rollback permanently — the watcher
    // then holds until the pod dies while the generation it is scoped to goes
    // on to publish a conflist nothing is left to remove. The only thing that
    // may end this phase is *this* generation's own publication marker, or the
    // publish deadline.
    let publish_deadline = Instant::now() + config.publish_timeout;
    loop {
        if this_generation_is_published(config) {
            break;
        }
        let now = Instant::now();
        if now >= publish_deadline {
            return Ok(RollbackWatchOutcome::NeverPublished);
        }
        std::thread::sleep(config.poll_interval.min(publish_deadline - now));
    }

    // Phase 2 — readiness, measured from the completed install.
    let deadline = Instant::now() + config.ready_timeout;
    loop {
        if probe() {
            return Ok(RollbackWatchOutcome::Ready);
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        // Never sleep past the deadline: a long poll interval must not extend
        // the window in which the node cannot create pods.
        std::thread::sleep(config.poll_interval.min(deadline - now));
    }

    // `uninstall` takes the node install lock for its whole run and re-reads
    // every ownership marker under it, so a newer installer that started
    // while this budget was expiring is either excluded or observed — never
    // half-observed.
    let report = install::uninstall(&config.uninstall)?;
    Ok(classify_rollback(report))
}

/// True when the generated conflist on disk carries exactly the owner and
/// generation this watcher is scoped to.
fn this_generation_is_published(config: &RollbackWatchConfig) -> bool {
    let conf_dir = &config.uninstall.host_conf_dir;
    let conf_file = &config.uninstall.conf_file_name;
    install::published_conflist_ownership(conf_dir, conf_file)
        .is_some_and(|found| config.uninstall.owns(&found))
}

fn classify_rollback(report: CniUninstallReport) -> RollbackWatchOutcome {
    match report.conflist {
        CniArtifactOutcome::Removed | CniArtifactOutcome::AlreadyAbsent => {
            RollbackWatchOutcome::RolledBack(report)
        }
        CniArtifactOutcome::RetainedOtherOwner | CniArtifactOutcome::RetainedOtherGeneration => {
            RollbackWatchOutcome::Superseded(report)
        }
        CniArtifactOutcome::RetainedForeign(_) | CniArtifactOutcome::RetainedDeliberate(_) => {
            RollbackWatchOutcome::RollbackIncomplete(report)
        }
    }
}

/// One CNI STATUS round-trip against the node-agent socket.
///
/// Returns true only for an explicit `Ok`. A missing socket, an IPC failure,
/// a `Rejected` (initial pod sync incomplete / Kubernetes probe failed), or a
/// malformed request all read as "not ready" — the same fail-closed reading
/// the CNI binary applies to STATUS on the request path.
#[cfg(unix)]
pub fn probe_node_agent_status(config: &RollbackWatchConfig) -> bool {
    use crate::cni::client::{DEFAULT_RPC_TIMEOUT, send_rpc};
    use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
    use crate::cni::spec::is_safe_cni_network_name;

    let conf_dir = &config.uninstall.host_conf_dir;
    let conf_file = &config.uninstall.conf_file_name;
    let network_name = install::generated_network_name(conf_dir, conf_file)
        .filter(|name| is_safe_cni_network_name(name))
        .unwrap_or_else(|| FALLBACK_STATUS_NETWORK_NAME.to_string());

    let request = CniRpcRequest {
        verb: RpcVerb::Status,
        network_name,
        pod_namespace: String::new(),
        pod_name: String::new(),
        pod_uid: None,
        container_id: String::new(),
        ifname: None,
        netns_path: None,
        args: Default::default(),
        valid_attachments: Vec::new(),
    };
    if request.validate().is_err() {
        return false;
    }
    matches!(
        send_rpc(&config.socket_path, &request, DEFAULT_RPC_TIMEOUT),
        Ok(CniRpcResponse::Ok)
    )
}

#[cfg(not(unix))]
pub fn probe_node_agent_status(_config: &RollbackWatchConfig) -> bool {
    false
}

/// Scope of the `await-cleanup` gate that fronts the Helm pre-delete phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupWaitConfig {
    pub namespace: String,
    pub daemonset_name: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl CleanupWaitConfig {
    pub fn from_env() -> Result<Self, CniInstallError> {
        let timeout = duration_from_env(
            "CLEANUP_TIMEOUT_SECS",
            DEFAULT_CLEANUP_TIMEOUT,
            MAX_READY_TIMEOUT_SECS,
        )?;
        let poll_interval = duration_from_env(
            "POLL_INTERVAL_SECS",
            DEFAULT_POLL_INTERVAL,
            MAX_POLL_INTERVAL_SECS,
        )?;
        Ok(Self {
            namespace: required_env("RELEASE_NAMESPACE")?,
            daemonset_name: required_env("CLEANUP_DAEMONSET_NAME")?,
            timeout,
            poll_interval: poll_interval.min(timeout),
        })
    }
}

/// Default budget for every node's cleanup pod to finish.
pub const DEFAULT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a controller-observed "no node matches this DaemonSet" status has
/// to hold before it counts as "there was nothing to clean".
///
/// A DaemonSet that was created moments ago also reports `0/0`, so a single
/// snapshot of it proves nothing. Requiring the controller's own observed
/// generation *and* a settle window separates "the controller has looked and
/// there are genuinely no nodes" from "the controller has not looked yet".
const ZERO_DESIRED_SETTLE: Duration = Duration::from_secs(15);

/// What the cleanup DaemonSet's status said when the wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupWaitReport {
    pub desired: i32,
    pub ready: i32,
}

impl CleanupWaitReport {
    /// True when the DaemonSet scheduled onto no node at all, so no node was
    /// cleaned — reported explicitly rather than as "0 of 0 succeeded".
    pub fn scheduled_nowhere(&self) -> bool {
        self.desired == 0
    }

    /// Whether deleting the release is safe based on this completion report.
    ///
    /// At least one cleanup pod must have been scheduled and every scheduled
    /// pod must be Ready. A controller-observed `0/0` is useful diagnostic
    /// evidence, but never proof that no node still has the chained CNI file.
    pub fn release_deletion_is_safe(&self) -> bool {
        self.desired > 0 && self.ready >= self.desired
    }
}

/// Run the whole Helm `pre-delete` completion boundary: block until every
/// node's cleanup pod is Ready — that is, until `ferrum-cni uninstall` has
/// succeeded on each node the DaemonSet scheduled onto — then remove the
/// cleanup DaemonSet and prove it is gone.
///
/// This exists because Helm's hook wait only watches `Job` and `Pod` kinds: a
/// hook DaemonSet is created and then immediately left behind, which would let
/// the release (and the node-agent socket) be deleted while cleanup pods were
/// still starting. Running this as a later-weighted hook **Job** gives the
/// phase a completion boundary Helm does understand, and makes a node that
/// cannot be cleaned fail the uninstall instead of passing silently.
///
/// The DaemonSet is deleted here rather than by a Helm `hook-succeeded`
/// policy because that policy would also delete it the moment the *DaemonSet*
/// hook "succeeded" — which for a non-waitable kind is immediately — and,
/// worse, Helm 3.19+ / v4 additionally delete every previously succeeded
/// `hook-succeeded` resource when a later hook in the same phase fails.
/// Owning the deletion here is what lets a failed wait leave the DaemonSet,
/// its logs, and its pods in place, on every Helm version.
pub async fn run_cleanup_phase(config: &CleanupWaitConfig) -> Result<CleanupWaitReport, String> {
    use k8s_openapi::api::apps::v1::DaemonSet;
    use kube::Api;

    let client = crate::k8s_controller::try_default_kube_client()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);
    // `CLEANUP_TIMEOUT_SECS` is the budget for this entire pre-delete phase,
    // not one full budget for readiness followed by another full budget for
    // deletion. Keeping one deadline ensures the hook fits inside the Helm
    // timeout operators configure around it.
    let deadline = Instant::now() + config.timeout;

    let report = await_cleanup_daemonset(&api, config, deadline).await?;
    if !report.release_deletion_is_safe() {
        return Err(
            "the cleanup DaemonSet scheduled onto no node, so no node was cleaned. The release \
             will be retained because deleting the node-agent could strand a chained CNI \
             configuration. If the cluster has no schedulable nodes, clean them with the manual \
             steps in docs/node_agent.md before retrying."
                .to_string(),
        );
    }
    // The cleanup DaemonSet is a `pre-delete` hook that deliberately carries
    // NO `hook-succeeded` deletion policy, so Helm leaves it alone. Removing
    // it is this Job's job, and it happens only after every node reported
    // success: while it exists, the pods it owns keep holding, and the release
    // is not yet allowed to disappear underneath them.
    delete_cleanup_daemonset(&api, config, deadline).await?;
    Ok(report)
}

/// Completion requires the DaemonSet controller to have observed the object
/// (`status.observedGeneration >= metadata.generation`; a status that carries
/// no observed generation at all is treated as unobserved, never as
/// observed-and-idle). An all-zero status additionally has to persist for
/// [`ZERO_DESIRED_SETTLE`], so a freshly created DaemonSet's initial `0/0`
/// snapshot can never be mistaken for "nothing to do".
async fn await_cleanup_daemonset(
    api: &kube::Api<k8s_openapi::api::apps::v1::DaemonSet>,
    config: &CleanupWaitConfig,
    deadline: Instant,
) -> Result<CleanupWaitReport, String> {
    let mut last = CleanupWaitReport {
        desired: 0,
        ready: 0,
    };
    let mut zero_since: Option<Instant> = None;
    loop {
        match api.get_status(&config.daemonset_name).await {
            Ok(daemonset) => {
                let generation = daemonset.metadata.generation;
                if let Some(status) = daemonset.status.as_ref() {
                    last = CleanupWaitReport {
                        desired: status.desired_number_scheduled,
                        ready: status.number_ready,
                    };
                    let observed = match (generation, status.observed_generation) {
                        (Some(generation), Some(observed)) => observed >= generation,
                        // A generation the controller has not reported on is
                        // unobserved. Treating a missing observed generation
                        // as "observed" is what let an all-zero initial status
                        // pass as a completed cleanup.
                        (Some(_), None) => false,
                        (None, _) => true,
                    };
                    if !observed || last.desired > 0 {
                        zero_since = None;
                    }
                    if observed && last.desired > 0 && last.ready >= last.desired {
                        return Ok(last);
                    }
                    if observed && last.desired == 0 {
                        let settled = *zero_since.get_or_insert_with(Instant::now);
                        if settled.elapsed() >= ZERO_DESIRED_SETTLE {
                            return Ok(last);
                        }
                    }
                }
            }
            Err(err) => {
                // A transient API error must not be read as "cleanup done".
                // This runs from the CLI, which installs no tracing
                // subscriber, so the operator only sees stderr.
                zero_since = None;
                eprintln!(
                    "ferrum-cni: could not read the status of DaemonSet {}; retrying: {err}",
                    config.daemonset_name
                );
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "cleanup did not finish on every node within {}s: {} of {} node cleanup pods \
                 reported success. The chained CNI configuration may still be present on the \
                 remaining nodes; inspect `kubectl -n {} logs daemonset/{}` before retrying.",
                config.timeout.as_secs(),
                last.ready,
                last.desired,
                config.namespace,
                config.daemonset_name
            ));
        }
        let nap = config.poll_interval.min(deadline - now);
        tokio::time::sleep(nap).await;
    }
}

/// Delete the cleanup DaemonSet and do not return until the API server no
/// longer serves it.
///
/// Foreground propagation is deliberate: the object survives its own delete
/// call until the garbage collector has removed the pods it owns, so a `404`
/// here is proof that no cleanup pod is still running anywhere on the cluster.
/// Only then may `helm uninstall` proceed to delete the node-agent.
///
/// Failing to delete fails the whole phase. That is the fail-closed direction:
/// the release-owned identity and RBAC this Job runs as are ordinary release
/// resources, not hook resources, so they are still there for a retry, and a
/// re-run of `helm uninstall` re-creates the DaemonSet
/// (`before-hook-creation`) and drives the same wait again.
async fn delete_cleanup_daemonset(
    api: &kube::Api<k8s_openapi::api::apps::v1::DaemonSet>,
    config: &CleanupWaitConfig,
    deadline: Instant,
) -> Result<(), String> {
    use kube::api::{DeleteParams, PropagationPolicy};

    if Instant::now() >= deadline {
        return Err(format!(
            "cleanup finished on every node but the shared {}s cleanup phase budget expired \
             before the DaemonSet could be deleted. Its pods are still running; inspect \
             `kubectl -n {} get daemonset {}` and re-run `helm uninstall`.",
            config.timeout.as_secs(),
            config.namespace,
            config.daemonset_name
        ));
    }
    let params = DeleteParams {
        propagation_policy: Some(PropagationPolicy::Foreground),
        ..DeleteParams::default()
    };
    match api.delete(&config.daemonset_name, &params).await {
        Ok(_) => {}
        // Already gone (a concurrent retry, an operator) is the state this
        // function is trying to reach, so it is a success, not an error.
        Err(kube::Error::Api(err)) if err.code == 404 => return Ok(()),
        Err(err) => {
            return Err(format!(
                "cleanup finished on every node but DaemonSet {} could not be deleted: {err}. \
                 The cleanup pods are still running; re-run `helm uninstall` once the API error \
                 is resolved.",
                config.daemonset_name
            ));
        }
    }

    loop {
        match api.get_opt(&config.daemonset_name).await {
            Ok(None) => return Ok(()),
            Ok(Some(_)) => {}
            Err(err) => {
                // Never read an API failure as "it is gone".
                eprintln!(
                    "ferrum-cni: could not confirm DaemonSet {} was deleted; retrying: {err}",
                    config.daemonset_name
                );
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "cleanup finished on every node but DaemonSet {} was still present {}s after it \
                 was deleted. Its pods may still be terminating; inspect `kubectl -n {} get \
                 daemonset {}` and re-run `helm uninstall`.",
                config.daemonset_name,
                config.timeout.as_secs(),
                config.namespace,
                config.daemonset_name
            ));
        }
        tokio::time::sleep(config.poll_interval.min(deadline - now)).await;
    }
}

/// Contents of the readiness marker. Purely diagnostic — readiness is the
/// existence of the file, not anything inside it.
const READY_MARKER_CONTENTS: &[u8] = b"ferrum-cni cleanup complete\n";

/// Retract any readiness marker left behind by an EARLIER start of this
/// container, before the current invocation does any work.
///
/// The cleanup container restarts after a failed run and its marker lives in
/// an `emptyDir`, which survives that restart. A marker from a previous start
/// would make the `exec` readiness probe pass while the *current* invocation
/// had not cleaned anything yet — Helm would read "cleanup finished on this
/// node" from a run that had barely begun, and delete the node-agent out from
/// under a node whose chain is still installed.
///
/// Nothing is followed and nothing is traversed. The path is inspected with
/// `symlink_metadata`, and only a plain regular file is unlinked; `remove_file`
/// unlinks the directory entry itself, so even if the entry were swapped for a
/// symlink between the stat and the unlink, the target is never reached.
/// Anything else at that path — a symlink, a directory, a device — is refused
/// rather than deleted: a cleanup run that cannot own its own marker must fail
/// loudly instead of publishing readiness through someone else's file.
pub fn clear_stale_ready_marker(path: &str) -> Result<(), CniInstallError> {
    let marker = Path::new(path);
    let meta = match std::fs::symlink_metadata(marker) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CniInstallError::Io {
                path: path.to_string(),
                source,
            });
        }
    };
    if !meta.file_type().is_file() {
        return Err(CniInstallError::UnsafeReadyMarker {
            path: path.to_string(),
        });
    }
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CniInstallError::Io {
            path: path.to_string(),
            source,
        }),
    }
}

/// Publish the marker the Helm pre-delete hook's readiness probe reads.
///
/// The hook pod cannot report "cleanup finished" by exiting — Helm waits for
/// the hook resource to become ready, and a DaemonSet pod that exits is
/// restarted. So the container completes its cleanup, drops this marker, and
/// stays up; readiness then flips exactly once the work is done, and a failed
/// cleanup never publishes it.
///
/// The write goes through the installer's atomic publish: an unguessable
/// `O_EXCL | O_NOFOLLOW` sibling renamed into place. A probe therefore never
/// observes a partially written marker, and the publish never follows a
/// symlink planted at the marker path.
pub fn write_ready_marker(path: &str) -> Result<(), CniInstallError> {
    let marker = Path::new(path);
    if let Some(parent) = marker.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| CniInstallError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    install::atomic_write_file(marker, READY_MARKER_CONTENTS, Some(0o600))
}

/// True when THIS invocation published the marker.
///
/// `symlink_metadata` plus a regular-file check, so a symlink at the marker
/// path is never readiness — only the file this run wrote is.
pub fn ready_marker_present(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// Marker path for the cleanup hold/readiness pair. Shared by the cleanup
/// container and its readiness probe, which inherit the same environment.
pub fn ready_marker_path_from_env() -> Result<String, CniInstallError> {
    required_env("READY_MARKER_PATH")
}

fn required_env(name: &'static str) -> Result<String, CniInstallError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(CniInstallError::MissingEnv(name))
}

fn duration_from_env(
    name: &'static str,
    default: Duration,
    max_secs: u64,
) -> Result<Duration, CniInstallError> {
    let Some(raw) = std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(default);
    };
    let Ok(parsed) = raw.trim().parse::<u64>() else {
        return Err(CniInstallError::InvalidEnvValue {
            name,
            expected: "a whole number of seconds",
        });
    };
    if parsed == 0 || parsed > max_secs {
        return Err(CniInstallError::InvalidEnvValue {
            name,
            expected: "a whole number of seconds within the supported range",
        });
    }
    Ok(Duration::from_secs(parsed))
}

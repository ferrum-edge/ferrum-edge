//! Kubernetes CRD controller (Layer 8).
//!
//! Watches Istio + Gateway API CRDs via kube-rs reflectors and feeds them
//! through `config_sources::k8s::translate_k8s_objects()` into the canonical
//! Layer 2 mesh model. Enabled in CP mode with `FERRUM_K8S_CONTROLLER_ENABLED=true`.

pub mod convert;
pub mod istio_status;
pub mod metrics;
pub mod reconciler;
pub mod resource_store;
pub mod status;
pub mod status_plan;
pub mod watcher;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{broadcast, watch};
use tracing::{error, info, warn};

use crate::config::types::GatewayConfig;
use crate::grpc::cp_server::{CpScope, DpNodeRegistry, NamespaceBroadcasts};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::MeshConfigBroadcast;
use istio_status::IstioStatusWriter;
use metrics::ControllerMetrics;
pub use reconciler::ReconcileBroadcasters;
pub use reconciler::{
    CpPublicationGate, K8sOverlaySlot, compose_db_with_k8s_overlay, empty_k8s_overlay_slot,
};
use reconciler::{ReconcilerConfig, spawn_reconcile_loop};
use resource_store::ResourceStoreSet;
use status::GatewayApiStatusWriter;
use watcher::{RelistPolicy, WatcherSelection, spawn_crd_reprobe_task, start_crd_watchers};

pub struct K8sControllerConfig {
    pub namespace: String,
    pub controller_namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub watch_istio: bool,
    /// `FERRUM_K8S_WATCH_MESH_CONFIG` — opt-out for clusters where the
    /// gateway runs in a different trust boundary from `istio-system` and
    /// cannot easily grant cross-namespace `configmaps` RBAC. Only
    /// effective when `watch_istio` is true (without Istio CRDs there is
    /// no Telemetry resource that would consume meshConfig providers).
    pub watch_mesh_config: bool,
    pub watch_gateway_api: bool,
    pub pod_discovery_enabled: bool,
    pub watch_node_locality: bool,
    pub gateway_api_data_plane_service_namespace: Option<String>,
    pub gateway_api_data_plane_service_name: Option<String>,
    pub gateway_api_status_address: Option<String>,
    /// Effective Sidecar `ingress[]` materialization gate
    /// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`).
    /// Threaded to the Istio status writer so it reports `ingress_modeled` only
    /// when the data plane actually materializes the listeners (F6 §6.2),
    /// matching the slice builder's ingress gate.
    pub mesh_sidecar_ingress_enforced: bool,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    /// `FERRUM_K8S_WATCH_IDLE_RELIST_SECS`, already clamped to
    /// `0..=86_400` by the env parser. Rebuild a watch scope's reflector from
    /// an authoritative list when it has delivered no event for this long; `0`
    /// disables it. This is the only bound on a watch that stalls without
    /// failing — `full_sync_interval_secs` re-reconciles from the same
    /// reflector store, so it cannot recover objects the store never received.
    pub watch_idle_relist_secs: u64,
    pub kubeconfig_path: Option<String>,
}

/// A controller task that failed to terminate cleanly (panic or cancellation).
#[derive(Debug, Clone)]
pub struct K8sControllerTaskFailure {
    pub task: String,
    /// `true` when the task panicked, `false` when it was cancelled/aborted
    /// externally. Both are unexpected for a controller task that is supposed
    /// to observe the shutdown watch channel and return.
    pub panicked: bool,
    pub detail: String,
}

/// Terminal disposition of every task owned by [`K8sControllerHandle`].
///
/// Returned by [`K8sControllerHandle::shutdown`] so the control plane can log
/// and propagate controller-task failures instead of detaching them (#3220).
#[derive(Debug, Default)]
pub struct K8sControllerShutdownOutcome {
    /// Tasks that were still running when shutdown was requested and then
    /// observed it and returned within the grace period.
    pub completed: Vec<String>,
    /// Tasks that returned *before* their shutdown receiver had observed
    /// `true`. A watcher, reconciler, or reprobe loop returning during normal
    /// operation means that part of the controller silently stopped
    /// reconciling — degraded service, not a clean exit — so it is reported
    /// separately and fails the process through [`Self::failure_error`].
    pub exited_before_shutdown: Vec<String>,
    /// Tasks that panicked or were cancelled by something other than this
    /// shutdown path.
    pub failed: Vec<K8sControllerTaskFailure>,
    /// Tasks still running at the grace deadline. They are aborted, and the
    /// abort is reported instead of silently detaching them.
    pub timed_out: Vec<String>,
    /// Subset of [`Self::timed_out`] whose terminal join was *not* confirmed
    /// inside the abort-settle budget. For these the abort was issued but no
    /// happens-before boundary was established, so the task may still be
    /// unwinding when `shutdown()` returns. Reported explicitly rather than
    /// claimed as settled.
    pub abort_unconfirmed: Vec<String>,
}

impl K8sControllerShutdownOutcome {
    /// `true` when every owned task stopped on its own, on time, without a
    /// panic and without having exited early.
    pub fn is_clean(&self) -> bool {
        // `abort_unconfirmed` is a subset of `timed_out`, so it needs no
        // separate term here.
        self.exited_before_shutdown.is_empty()
            && self.failed.is_empty()
            && self.timed_out.is_empty()
    }

    /// An error describing abnormally terminated controller tasks, if any.
    ///
    /// Two conditions are process-failing:
    ///
    /// * a panicked/cancelled task — a real defect;
    /// * a task that returned successfully *before* shutdown was requested —
    ///   a silently dead watcher/reconciler/reprobe loop is degraded service,
    ///   and a control plane that keeps running with one is worse than one
    ///   that exits and gets restarted.
    ///
    /// A grace-period timeout is deliberately *not* an error: a stuck task is
    /// aborted and warned about, mirroring background-task drain elsewhere in
    /// the modes.
    pub fn failure_error(&self) -> Option<anyhow::Error> {
        if self.failed.is_empty() && self.exited_before_shutdown.is_empty() {
            return None;
        }
        let mut details: Vec<String> = self
            .failed
            .iter()
            .map(|failure| {
                let kind = if failure.panicked {
                    "panicked"
                } else {
                    "cancelled"
                };
                format!("{} {kind}: {}", failure.task, failure.detail)
            })
            .collect();
        for task in &self.exited_before_shutdown {
            details.push(format!("{task} exited before shutdown was requested"));
        }
        Some(anyhow::anyhow!(
            "Kubernetes controller task(s) terminated abnormally: {}",
            details.join("; ")
        ))
    }
}

/// How long a deadline-aborted task gets to reach its terminal join before the
/// abort is reported as unconfirmed. Keeps total teardown bounded at
/// `grace + ABORT_SETTLE_BUDGET`; an abort normally lands in microseconds, so
/// this only matters for a task wedged in a blocking `Drop`.
const ABORT_SETTLE_BUDGET: Duration = Duration::from_secs(1);

/// What a controller task's own lifecycle wrapper observed when the task
/// returned.
struct TaskCompletion {
    /// The shutdown watch's value, read inside the controller task itself in
    /// the same poll that resolved the task's future — there is no `.await`
    /// between the two, so the task cannot be descheduled in the window.
    ///
    /// Sampling it anywhere else (a separate supervisor task awaiting an
    /// already-spawned `JoinHandle`, `is_finished()`, a teardown-time scan)
    /// races the global watch flip: a task that returned while the watch was
    /// still `false` would be re-read as `true` on another runtime thread's
    /// timeline, and a silently dead watcher would be reported as a clean
    /// shutdown.
    shutdown_observed: bool,
}

/// One controller task owned by [`ControllerTaskRegistry`].
struct SupervisedTask {
    name: String,
    /// Join handle of the controller task itself, running inside
    /// [`run_supervised_task`]. Never drop this while the task is live:
    /// dropping a `JoinHandle` *detaches* the task, which is precisely the
    /// defect #3220 exists to close.
    handle: tokio::task::JoinHandle<TaskCompletion>,
    /// Abort handle for the same task, kept separately so the grace-deadline
    /// path can stop the work while `handle` is owned by the join set.
    abort: tokio::task::AbortHandle,
}

/// Terminal classification of a single controller task, resolved once and then
/// materialized into [`K8sControllerShutdownOutcome`] in registration order.
enum TaskDisposition {
    Completed,
    ExitedBeforeShutdown,
    Failed(K8sControllerTaskFailure),
    TimedOut { abort_confirmed: bool },
}

/// Run a controller task and record the shutdown state at its own completion
/// boundary.
///
/// `fut.await` and the `borrow()` below run in one poll of this future: when
/// `fut` resolves, control returns here synchronously, so the read happens
/// before the task yields back to the scheduler.
async fn run_supervised_task<F>(fut: F, shutdown: watch::Receiver<bool>) -> TaskCompletion
where
    F: Future<Output = ()>,
{
    fut.await;
    TaskCompletion {
        shutdown_observed: *shutdown.borrow(),
    }
}

/// Shared owner of every task the Kubernetes controller spawns (#3220).
///
/// Controller tasks are never `tokio::spawn`ed directly. They go through
/// [`Self::spawn_named`], which wraps the future in [`run_supervised_task`] and
/// keeps the resulting `JoinHandle` here, so:
///
/// * the CRD reprobe loop's *dynamically created* replacement watchers are
///   owned exactly like the startup ones. They used to be spawned and dropped
///   on the floor, so a watcher created after startup outlived control-plane
///   teardown with no terminal join boundary at all;
/// * registration and the shutdown-time close are one atomic step under the
///   same lock, so a reprobe racing teardown either hands its watcher over
///   (and it is awaited) or is refused *before the task is ever spawned*.
///   There is no window in which a just-created watcher exists unowned.
pub(crate) struct ControllerTaskRegistry {
    state: std::sync::Mutex<RegistryState>,
}

struct RegistryState {
    /// Set once by [`ControllerTaskRegistry::close_and_take`]; refuses new
    /// registrations from then on.
    closed: bool,
    next_seq: u64,
    tasks: Vec<SupervisedTask>,
}

impl ControllerTaskRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: std::sync::Mutex::new(RegistryState {
                closed: false,
                next_seq: 0,
                tasks: Vec::new(),
            }),
        })
    }

    /// Recover a poisoned guard instead of propagating the panic: every
    /// critical section here is a handful of infallible field writes plus
    /// `tokio::spawn`, and shutdown must not panic.
    fn state(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Spawn `fut` as an owned controller task named `{label}#{seq}`.
    ///
    /// `label` must be built from compile-time identifiers only (the task's
    /// role plus a static Kubernetes kind from `ISTIO_CRDS` /
    /// `GATEWAY_API_CRDS` / the core resource tables) — never from cluster
    /// object contents — because the name is logged and carried in shutdown
    /// errors. `seq` is a monotonic registration counter, so names are unique
    /// and the shutdown outcome is reported in a deterministic order.
    ///
    /// Returns `false` when shutdown has already closed the registry. The task
    /// is **not** spawned in that case, so a caller that loses the race leaks
    /// nothing and should abandon whatever it was setting up.
    pub(crate) fn spawn_named<F>(
        &self,
        label: &str,
        fut: F,
        shutdown: watch::Receiver<bool>,
    ) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // Spawn *inside* the lock so registration is atomic with the closed
        // check: shutdown can never observe a task that exists but is unowned.
        let mut state = self.state();
        if state.closed {
            return false;
        }
        let seq = state.next_seq;
        state.next_seq += 1;
        let handle = tokio::spawn(run_supervised_task(fut, shutdown));
        let abort = handle.abort_handle();
        state.tasks.push(SupervisedTask {
            name: format!("{label}#{seq}"),
            handle,
            abort,
        });
        true
    }

    /// `true` once shutdown has taken ownership of the task set. Lets a
    /// long-running producer (the CRD reprobe loop) stop promptly instead of
    /// looping on refusals.
    pub(crate) fn is_closed(&self) -> bool {
        self.state().closed
    }

    /// Stop accepting new tasks and take everything registered so far.
    /// Idempotent: a second call returns an empty set.
    fn close_and_take(&self) -> Vec<SupervisedTask> {
        let mut state = self.state();
        state.closed = true;
        std::mem::take(&mut state.tasks)
    }
}

pub struct K8sControllerHandle {
    pub metrics: Arc<ControllerMetrics>,
    registry: Arc<ControllerTaskRegistry>,
}

impl K8sControllerHandle {
    /// Take terminal ownership of a controller task registry.
    ///
    /// Kept crate-visible plus a `_test_support` seam so external tests can
    /// drive the real registry and the real shutdown path with synthetic tasks
    /// without widening the production API.
    pub(crate) fn new(
        metrics: Arc<ControllerMetrics>,
        registry: Arc<ControllerTaskRegistry>,
    ) -> Self {
        Self { metrics, registry }
    }

    /// Signal shutdown, then await every owned task with a bounded grace
    /// period, aborting whatever is still running at the deadline and
    /// confirming those aborts within a bounded settle phase.
    ///
    /// The signal is sent here (idempotently — `watch::Sender::send` on an
    /// already-`true` channel still notifies) so the ordering is structural:
    /// no caller can await controller tasks that were never told to stop.
    /// Whether a task exited early was already decided inside the task itself
    /// at its completion boundary, not by the state of the channel here.
    pub async fn shutdown(
        self,
        shutdown_tx: &watch::Sender<bool>,
        grace: Duration,
    ) -> K8sControllerShutdownOutcome {
        // Ignore the send result: with no receivers left there is nothing to
        // notify, and every task is already gone or about to be joined.
        let _ = shutdown_tx.send(true);

        // Signal first, then close. Closing stops the CRD reprobe loop from
        // registering further watchers, and the two steps together drain the
        // reprobe race: a probe already inside `start_crd_watchers` either
        // registered its replacement watcher before this point (so it is in
        // `tasks` and awaited below) or is refused after it (so the watcher is
        // never spawned). Neither outcome loses a live task.
        let tasks = self.registry.close_and_take();

        let mut outcome = K8sControllerShutdownOutcome::default();
        for (name, disposition) in await_controller_tasks(tasks, grace).await {
            match disposition {
                TaskDisposition::Completed => outcome.completed.push(name),
                TaskDisposition::ExitedBeforeShutdown => {
                    error!(
                        task = %name,
                        "Kubernetes controller task exited before shutdown was requested"
                    );
                    outcome.exited_before_shutdown.push(name);
                }
                TaskDisposition::Failed(failure) => {
                    error!(
                        task = %failure.task,
                        panicked = failure.panicked,
                        error = %failure.detail,
                        "Kubernetes controller task did not terminate cleanly"
                    );
                    outcome.failed.push(failure);
                }
                TaskDisposition::TimedOut { abort_confirmed } => {
                    if !abort_confirmed {
                        warn!(
                            task = %name,
                            settle_secs = ABORT_SETTLE_BUDGET.as_secs_f64(),
                            "Kubernetes controller task abort was not confirmed within the \
                             settle budget; its termination is not established"
                        );
                        outcome.abort_unconfirmed.push(name.clone());
                    }
                    outcome.timed_out.push(name);
                }
            }
        }
        outcome
    }
}

/// Await supervised controller tasks concurrently under a single deadline,
/// then abort and settle whatever is left.
///
/// Concurrent (rather than sequential) so a slow watcher does not hide a
/// reconciler panic behind it, and so the whole set — startup watchers,
/// reconciler, reprobe, and any watcher the reprobe registered later — shares
/// one grace budget. Returns dispositions in registration order regardless of
/// completion order, so the outcome is deterministic.
async fn await_controller_tasks(
    tasks: Vec<SupervisedTask>,
    grace: Duration,
) -> Vec<(String, TaskDisposition)> {
    use futures_util::stream::{FuturesUnordered, StreamExt};
    use std::collections::{BTreeMap, BTreeSet};

    if tasks.is_empty() {
        return Vec::new();
    }

    let mut names: Vec<String> = Vec::with_capacity(tasks.len());
    let mut dispositions: BTreeMap<usize, TaskDisposition> = BTreeMap::new();
    // Task abort handles, keyed by registration index. The `JoinHandle`s
    // themselves move into `futures` below and are never dropped while their
    // task is still live, so no controller task is ever detached here.
    let mut pending: BTreeMap<usize, tokio::task::AbortHandle> = BTreeMap::new();
    let mut futures = FuturesUnordered::new();
    for (index, task) in tasks.into_iter().enumerate() {
        names.push(task.name.clone());
        pending.insert(index, task.abort);
        let handle = task.handle;
        futures.push(async move { (index, handle.await) });
    }

    let deadline = tokio::time::Instant::now() + grace;
    let mut timed_out: Vec<usize> = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, futures.next()).await {
            Ok(Some((index, joined))) => {
                pending.remove(&index);
                let name = names.get(index).cloned().unwrap_or_default();
                dispositions.insert(index, classify_completion(name, joined));
            }
            Ok(None) => break,
            Err(_) => {
                for (index, abort) in std::mem::take(&mut pending) {
                    if let Some(name) = names.get(index) {
                        warn!(
                            task = %name,
                            grace_secs = grace.as_secs_f64(),
                            "Kubernetes controller task still running at grace deadline; aborting"
                        );
                    }
                    abort.abort();
                    timed_out.push(index);
                }
                break;
            }
        }
    }

    // Bounded abort-settle phase: an aborted task's `JoinHandle` resolves only
    // after its future has actually been dropped, so awaiting the handles here
    // is what turns "abort was requested" into "termination happened".
    // Dropping `futures` without this would reintroduce detach-on-drop.
    if !timed_out.is_empty() {
        let mut confirmed: BTreeSet<usize> = BTreeSet::new();
        let settle_deadline = tokio::time::Instant::now() + ABORT_SETTLE_BUDGET;
        while confirmed.len() < timed_out.len() {
            match tokio::time::timeout_at(settle_deadline, futures.next()).await {
                Ok(Some((index, joined))) => {
                    // The task was aborted by *this* path, so a cancellation
                    // JoinError is the expected terminal state and must not be
                    // double-counted as a separate failure. A panic racing the
                    // abort is logged but keeps the `timed_out` classification
                    // for the same reason.
                    let name = names.get(index).cloned().unwrap_or_default();
                    if let Err(err) = &joined
                        && err.is_panic()
                    {
                        error!(
                            task = %name,
                            error = %err,
                            "Kubernetes controller task panicked while being aborted at the \
                             grace deadline"
                        );
                    }
                    confirmed.insert(index);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        for index in timed_out {
            dispositions.insert(
                index,
                TaskDisposition::TimedOut {
                    abort_confirmed: confirmed.contains(&index),
                },
            );
        }
    }

    // Anything still unresolved here was already aborted above, so its future
    // is being torn down rather than left running. The situation is reported
    // as `abort_unconfirmed` rather than claimed as a settled termination.
    drop(futures);

    let mut resolved: Vec<(String, TaskDisposition)> = Vec::with_capacity(names.len());
    for (index, name) in names.into_iter().enumerate() {
        let disposition = match dispositions.remove(&index) {
            Some(disposition) => disposition,
            // Unreachable: every index is either joined above, or aborted and
            // recorded by the settle phase. Classified conservatively rather
            // than panicking on the shutdown path.
            None => TaskDisposition::TimedOut {
                abort_confirmed: false,
            },
        };
        resolved.push((name, disposition));
    }
    resolved
}

/// Turn a controller task's join result into a terminal disposition.
fn classify_completion(
    name: String,
    joined: Result<TaskCompletion, tokio::task::JoinError>,
) -> TaskDisposition {
    match joined {
        Ok(completion) if completion.shutdown_observed => TaskDisposition::Completed,
        // Returned successfully while the shutdown watch was still `false` at
        // the task's own completion boundary: that part of the controller
        // stopped reconciling on its own.
        Ok(_) => TaskDisposition::ExitedBeforeShutdown,
        // A panic inside the task unwinds through the lifecycle wrapper, so it
        // never records a completion; the same arm also covers a cancellation
        // from outside this shutdown path.
        Err(err) => TaskDisposition::Failed(K8sControllerTaskFailure {
            task: name,
            panicked: err.is_panic(),
            detail: err.to_string(),
        }),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_k8s_controller(
    controller_config: K8sControllerConfig,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    cp_scope: CpScope,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    publication_gate: CpPublicationGate,
    shutdown: watch::Receiver<bool>,
) -> Result<K8sControllerHandle, anyhow::Error> {
    info!(
        watch_istio = controller_config.watch_istio,
        watch_gateway_api = controller_config.watch_gateway_api,
        pod_discovery_enabled = controller_config.pod_discovery_enabled,
        watch_node_locality = controller_config.watch_node_locality,
        gateway_api_data_plane_service_namespace = ?controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name = ?controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address = ?controller_config.gateway_api_status_address,
        istio_root_namespace = %controller_config.istio_root_namespace,
        watch_namespaces = ?controller_config.watch_namespaces,
        namespace = controller_config.namespace,
        controller_namespace = controller_config.controller_namespace,
        "Starting Kubernetes controller"
    );

    let client = build_kube_client(&controller_config.kubeconfig_path).await?;

    let store_set = Arc::new(tokio::sync::Mutex::new(ResourceStoreSet::new()));
    let metrics = Arc::new(ControllerMetrics::new());
    let watcher_selection = WatcherSelection {
        watch_istio: controller_config.watch_istio,
        watch_gateway_api: controller_config.watch_gateway_api,
        watch_core: controller_config.pod_discovery_enabled,
        watch_gateway_api_data_plane_service: controller_config.watch_gateway_api
            && controller_config
                .gateway_api_data_plane_service_namespace
                .is_some()
            && controller_config
                .gateway_api_data_plane_service_name
                .is_some(),
        watch_node_locality: controller_config.watch_node_locality,
        // Without Istio CRDs there is no Telemetry resource that would
        // consume meshConfig providers, so the configmaps watch and its
        // associated RBAC requirement are skipped automatically.
        watch_mesh_config: controller_config.watch_istio && controller_config.watch_mesh_config,
    };
    let controller_namespace = controller_config.controller_namespace.clone();
    let istio_root_namespace = controller_config.istio_root_namespace.clone();
    let gateway_api_data_plane_service_namespace = controller_config
        .gateway_api_data_plane_service_namespace
        .clone();

    // Every controller task — startup watchers, the reconciler, the CRD
    // reprobe loop, and the replacement watchers that loop creates later — is
    // registered here, so `K8sControllerHandle::shutdown` has a terminal join
    // boundary for all of them (#3220).
    let registry = ControllerTaskRegistry::new();

    let relist_policy = RelistPolicy::from_idle_secs(controller_config.watch_idle_relist_secs);
    if relist_policy.idle_window.is_none() {
        warn!(
            "FERRUM_K8S_WATCH_IDLE_RELIST_SECS=0 disables watch-staleness recovery: a watch \
             that stops delivering without failing will keep serving its last-known objects \
             until the control plane restarts"
        );
    }

    let watchers_started = start_crd_watchers(
        client.clone(),
        store_set.clone(),
        watcher_selection,
        controller_config.watch_namespaces.clone(),
        controller_namespace.clone(),
        istio_root_namespace.clone(),
        gateway_api_data_plane_service_namespace.clone(),
        relist_policy,
        metrics.clone(),
        shutdown.clone(),
        &registry,
        STARTUP_WATCHER_LABEL,
    )
    .await;

    info!(
        watchers = watchers_started,
        watch_idle_relist_secs = controller_config.watch_idle_relist_secs,
        "CRD watchers started"
    );

    let reconciler_config = ReconcilerConfig {
        namespace: controller_config.namespace,
        controller_namespace: controller_config.controller_namespace,
        trust_domain: controller_config.trust_domain,
        cluster_domain: controller_config.cluster_domain,
        istio_root_namespace: controller_config.istio_root_namespace,
        watch_namespaces: controller_config.watch_namespaces.clone(),
        debounce_ms: controller_config.debounce_ms,
        full_sync_interval_secs: controller_config.full_sync_interval_secs,
        pod_discovery_enabled: controller_config.pod_discovery_enabled,
        gateway_api_data_plane_service_namespace: controller_config
            .gateway_api_data_plane_service_namespace,
        gateway_api_data_plane_service_name: controller_config.gateway_api_data_plane_service_name,
        gateway_api_status_address: controller_config.gateway_api_status_address,
        mesh_sidecar_ingress_enforced: controller_config.mesh_sidecar_ingress_enforced,
        // Kubernetes owns mesh state only when it actually watches a
        // mesh-contributing kind (issue #2452): Istio CRDs, Gateway API
        // (waypoint bindings and Gateway-derived mesh services), or core
        // Pod/Service/EndpointSlice discovery. A controller watching none of
        // them owns no mesh objects and must never withdraw mesh state that a
        // native/file/xDS source published.
        mesh_overlay_authority: controller_config.watch_istio
            || controller_config.watch_gateway_api
            || controller_config.pod_discovery_enabled,
    };
    let gateway_status_writer = controller_config
        .watch_gateway_api
        .then(|| GatewayApiStatusWriter::new(client.clone()));
    // T2-B: the Istio status writer mirrors the Gateway API writer's
    // construction — only build it when the controller is actually
    // watching Istio CRDs, so non-Istio installs don't pay the (tiny)
    // overhead of an unused writer carrying a kube client clone.
    let istio_status_writer = controller_config
        .watch_istio
        .then(|| IstioStatusWriter::new(client.clone()));

    let reconciler_registered = spawn_reconcile_loop(
        store_set.clone(),
        config_arc,
        overlay_slot,
        ReconcileBroadcasters {
            broadcasts,
            cp_scope,
            dp_registry,
            mesh_update_tx,
            mesh_registry,
            publication_gate,
        },
        reconciler_config,
        gateway_status_writer,
        istio_status_writer,
        metrics.clone(),
        shutdown.clone(),
        &registry,
    );
    report_if_unregistered(reconciler_registered, "reconciler");

    let reprobe_registered = spawn_crd_reprobe_task(
        client,
        store_set,
        watcher_selection,
        controller_config.watch_namespaces,
        controller_namespace,
        istio_root_namespace,
        gateway_api_data_plane_service_namespace,
        relist_policy,
        metrics.clone(),
        shutdown,
        Duration::from_secs(300),
        &registry,
    );
    report_if_unregistered(reprobe_registered, "crd-reprobe");

    Ok(K8sControllerHandle::new(metrics, registry))
}

/// Label prefix for the watchers started during controller startup.
pub(crate) const STARTUP_WATCHER_LABEL: &str = "crd-watcher";

/// Label prefix for the replacement watchers the CRD reprobe loop creates when
/// a CRD group shows up after startup. Distinguishing them keeps a shutdown
/// report readable without putting any cluster-supplied text in a task name.
pub(crate) const REPROBE_WATCHER_LABEL: &str = "crd-watcher-reprobe";

/// Startup registration is expected to always succeed: the registry is created
/// in [`start_k8s_controller`] and is only closed by
/// [`K8sControllerHandle::shutdown`], which consumes a handle that does not
/// exist yet. A refusal means the task was never spawned — nothing is detached
/// — but the controller would be silently missing a component, so say so.
fn report_if_unregistered(registered: bool, task: &str) {
    if !registered {
        error!(
            task,
            "Kubernetes controller task was refused by a closed task registry; \
             the controller is running without it"
        );
    }
}

async fn build_kube_client(
    kubeconfig_path: &Option<String>,
) -> Result<kube::Client, anyhow::Error> {
    let config = if let Some(path) = kubeconfig_path {
        info!(path, "Loading kubeconfig from explicit path");
        let kubeconfig = kube::config::Kubeconfig::read_from(path)?;
        kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default()).await?
    } else {
        match kube::Config::incluster() {
            Ok(c) => {
                info!("Using in-cluster Kubernetes config");
                c
            }
            Err(in_cluster_err) => match kube::Config::infer().await {
                Ok(c) => {
                    info!("Using inferred kubeconfig (not in-cluster)");
                    c
                }
                Err(infer_err) => {
                    error!(
                        in_cluster_error = %in_cluster_err,
                        infer_error = %infer_err,
                        "Failed to build Kubernetes client config"
                    );
                    return Err(anyhow::anyhow!(
                        "Cannot create Kubernetes client: in-cluster failed ({in_cluster_err}), \
                         kubeconfig inference failed ({infer_err}). \
                         Set FERRUM_K8S_KUBECONFIG_PATH for out-of-cluster use."
                    ));
                }
            },
        }
    };

    Ok(kube::Client::try_from(config)?)
}

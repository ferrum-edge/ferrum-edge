use std::collections::BTreeSet;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{
    K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_collecting_skips,
};
use crate::grpc::cp_server::{CpGrpcServer, CpScope, DpNodeRegistry, NamespaceBroadcasts};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::{MeshConfigBroadcast, MeshGrpcServer};
use crate::identity::spiffe::TrustDomain;
use crate::k8s_controller::ControllerTaskRegistry;
use crate::k8s_controller::istio_status::{
    IstioStatusWriter, plan_istio_status_updates, plan_istio_status_updates_budgeted,
};
use crate::k8s_controller::metrics::ControllerMetrics;
use crate::k8s_controller::resource_store::ResourceStoreSet;
use crate::k8s_controller::status::{
    GatewayApiStatusContext, GatewayApiStatusWriter, StatusTranslationReuse,
    gateway_api_data_plane_service_ready, plan_gateway_api_status_updates_budgeted,
    plan_gateway_api_status_updates_with_context,
};
use crate::k8s_controller::status_plan::{DEFAULT_STATUS_PLAN_WORK_BUDGET, StatusPlanBudget};
use crate::k8s_controller::watcher::namespaces_with_istio_root;

const INITIAL_STORE_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP: usize = DEFAULT_STATUS_PLAN_WORK_BUDGET;
const STATUS_PATCH_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Last reconciler-accepted Kubernetes translation, held independently of the
/// DB-authored `GatewayConfig` snapshot. CP full reloads re-merge this overlay
/// before publication so a DB poll can no longer wipe in-memory K8s-derived
/// state and broadcast the wipe (issues #2982 / #2984).
/// Deliberately not `Debug`: `translation` is a `GatewayConfig`, which carries
/// consumer credentials. Matching the CP-side `FullLoadMultiOutcome` /
/// `PartitionComposeOutcome` contract keeps the overlay out of any log line.
#[derive(Clone)]
pub struct AcceptedK8sOverlay {
    pub translation: GatewayConfig,
    pub managed_namespaces: BTreeSet<String>,
}

/// Shared slot written by the K8s reconciler and read by CP DB publication.
pub type K8sOverlaySlot = Arc<ArcSwap<Option<AcceptedK8sOverlay>>>;

/// Create an empty overlay slot (no K8s translation accepted yet).
pub fn empty_k8s_overlay_slot() -> K8sOverlaySlot {
    Arc::new(ArcSwap::from_pointee(None))
}

/// Serializes CP configuration publication so the order in which snapshots are
/// committed to `config_arc` is the order in which DP and mesh subscribers
/// observe them.
///
/// Both CP writers — the DB poll loop and the K8s reconciler — compare-and-swap
/// into the same `ArcSwap` and then broadcast. CAS alone only makes each commit
/// atomic; it says nothing about the emissions that follow. Without a shared
/// gate the two steps interleave: the poller commits DB snapshot `D1`, the
/// reconciler commits `D1 + overlay` and broadcasts it, and the poller then
/// broadcasts its older `D1` — leaving every DP and mesh node on a snapshot
/// older than `config_arc`. The reverse order lets a reconciler full snapshot
/// land after a newer poll delta and erase it. Neither consumer can repair the
/// inversion: `ConfigUpdate.version` is informational on the DP and
/// `MeshConfigBroadcast::Full` carries no monotonic generation, so both apply
/// strictly in arrival order.
///
/// Deliberately a plain synchronous mutex. Everything it guards is a background
/// task's CAS, serialization, and `broadcast::Sender::send` — all synchronous
/// and short. Nothing on the proxy request path takes it, and because
/// [`Self::publish`] accepts a synchronous `FnOnce`, a future can never hold it
/// across an `.await`; that is enforced by the signature, not by convention.
#[derive(Clone, Default)]
pub struct CpPublicationGate {
    inner: Arc<Mutex<()>>,
}

impl CpPublicationGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `publish` with exclusive CP publication rights.
    ///
    /// Poison-free by construction: the gate guards `()`, so a panic in another
    /// publication leaves behind no state a later publisher could misread. The
    /// poison flag is therefore recovered rather than propagated — a panic in
    /// one background task must not wedge config distribution for the process,
    /// and recovering here keeps the path free of `unwrap`/`expect`.
    pub fn publish<R>(&self, publish: impl FnOnce() -> R) -> R {
        let _guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        publish()
    }
}

/// Record the last accepted K8s translation for later CP full-reload re-merge.
///
/// Only ever called after a translation SUCCEEDS, so a failed translate never
/// overwrites the last accepted overlay with an empty one.
///
/// Mesh retention matches [`merge_k8s_translation`]: a successful translate that
/// omits `mesh` must not erase a previously accepted mesh block. The overlay
/// slot is the sole mesh source on CP full-reload re-merge (DB snapshots clear
/// `mesh`), so dropping it here would let the next DB poll wipe mesh from
/// `config_arc` even though merging the same translate into the live snapshot
/// would have kept it (#2982).
pub fn store_accepted_k8s_overlay(
    slot: &K8sOverlaySlot,
    mut translation: GatewayConfig,
    managed_namespaces: BTreeSet<String>,
) {
    if translation.mesh.is_none()
        && let Some(previous) = slot.load_full().as_ref()
    {
        translation.mesh = previous.translation.mesh.clone();
    }
    slot.store(Arc::new(Some(AcceptedK8sOverlay {
        translation,
        managed_namespaces,
    })));
}

/// Compose a DB-authored snapshot with the independently owned K8s overlay.
///
/// When the slot is empty the DB snapshot is returned unchanged.
pub fn compose_db_with_k8s_overlay(
    db_config: &GatewayConfig,
    overlay_slot: &K8sOverlaySlot,
) -> GatewayConfig {
    let slot = overlay_slot.load_full();
    let Some(overlay) = slot.as_ref() else {
        return db_config.clone();
    };
    merge_k8s_translation(db_config, &overlay.translation, &overlay.managed_namespaces)
}

pub struct ReconcilerConfig {
    pub namespace: String,
    pub controller_namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    pub pod_discovery_enabled: bool,
    pub gateway_api_data_plane_service_namespace: Option<String>,
    pub gateway_api_data_plane_service_name: Option<String>,
    pub gateway_api_status_address: Option<String>,
    /// Effective Sidecar `ingress[]` materialization gate
    /// (`FERRUM_MESH_SIDECAR_ENFORCED && !FERRUM_MESH_SIDECAR_ENFORCED_DRY_RUN`),
    /// passed to the Istio status writer so it reports `ingress_modeled` only
    /// when the data plane actually materializes the listeners (F6 §6.2).
    pub mesh_sidecar_ingress_enforced: bool,
}

pub struct ReconcileBroadcasters {
    pub broadcasts: Arc<NamespaceBroadcasts>,
    pub cp_scope: CpScope,
    pub dp_registry: Arc<DpNodeRegistry>,
    pub mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    pub mesh_registry: Arc<MeshNodeRegistry>,
    /// Shared with the CP DB poll loop so reconciler and poller publications
    /// are totally ordered against each other (see [`CpPublicationGate`]).
    pub publication_gate: CpPublicationGate,
}

/// Register the reconcile loop with `registry`, returning whether it was
/// accepted (it is refused only if shutdown already closed the registry).
///
/// Registering rather than returning a `JoinHandle` is what gives control-plane
/// teardown a terminal join boundary for the reconciler (#3220).
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasters: ReconcileBroadcasters,
    reconciler_config: ReconcilerConfig,
    gateway_status_writer: Option<GatewayApiStatusWriter>,
    istio_status_writer: Option<IstioStatusWriter>,
    metrics: Arc<ControllerMetrics>,
    shutdown: watch::Receiver<bool>,
    registry: &ControllerTaskRegistry,
) -> bool {
    // Funnel the loop through a named `async fn` so the spawned future has a
    // concrete type signature (no anonymous future generated from an
    // `async move { ... }`). The previous inline form tripped a rustc HRTB
    // limitation on `tokio::spawn`'s `Send + 'static` bound for the
    // `&Arc<tokio::sync::Mutex<ResourceStoreSet>>` borrows held across the
    // `do_reconcile(...).await` calls.
    let reconcile_task = run_reconcile_loop(
        store_set,
        config_arc,
        overlay_slot,
        broadcasters,
        reconciler_config,
        gateway_status_writer,
        istio_status_writer,
        metrics,
        shutdown.clone(),
    );

    registry.spawn_named("reconciler", reconcile_task, shutdown)
}

#[allow(clippy::too_many_arguments)]
async fn run_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    overlay_slot: K8sOverlaySlot,
    broadcasters: ReconcileBroadcasters,
    reconciler_config: ReconcilerConfig,
    gateway_status_writer: Option<GatewayApiStatusWriter>,
    istio_status_writer: Option<IstioStatusWriter>,
    metrics: Arc<ControllerMetrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut change_rx = {
        let set = store_set.lock().await;
        set.subscribe()
    };

    let debounce = Duration::from_millis(reconciler_config.debounce_ms);
    let full_sync_interval = full_sync_interval_duration(reconciler_config.full_sync_interval_secs);
    if reconciler_config.full_sync_interval_secs == 0 {
        warn!(
            "FERRUM_K8S_FULL_SYNC_INTERVAL_SECS=0 is invalid, clamping K8s full-sync interval to 1s"
        );
    }
    let mut full_sync_timer = tokio::time::interval(full_sync_interval);
    full_sync_timer.tick().await; // skip first immediate tick

    let trust_domain = match TrustDomain::new(&reconciler_config.trust_domain) {
        Ok(td) => td,
        Err(e) => {
            error!(
                trust_domain = reconciler_config.trust_domain,
                error = %e,
                "Invalid trust domain for K8s controller, stopping reconciler"
            );
            return;
        }
    };

    if !wait_for_initial_store_readiness(Arc::clone(&store_set), &mut change_rx, &mut shutdown)
        .await
    {
        return;
    }

    // Initial reconciliation — block until first success.
    do_reconcile(
        Arc::clone(&store_set),
        ReconcileContext {
            config_arc: Arc::clone(&config_arc),
            overlay_slot: Arc::clone(&overlay_slot),
            broadcasts: Arc::clone(&broadcasters.broadcasts),
            cp_scope: broadcasters.cp_scope.clone(),
            dp_registry: Arc::clone(&broadcasters.dp_registry),
            mesh_update_tx: broadcasters.mesh_update_tx.clone(),
            mesh_registry: Arc::clone(&broadcasters.mesh_registry),
            publication_gate: broadcasters.publication_gate.clone(),
            namespace: reconciler_config.namespace.clone(),
            controller_namespace: reconciler_config.controller_namespace.clone(),
            cluster_domain: reconciler_config.cluster_domain.clone(),
            istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
            watch_namespaces: reconciler_config.watch_namespaces.clone(),
            trust_domain: trust_domain.clone(),
            pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
            gateway_api_data_plane_service_namespace: reconciler_config
                .gateway_api_data_plane_service_namespace
                .clone(),
            gateway_api_data_plane_service_name: reconciler_config
                .gateway_api_data_plane_service_name
                .clone(),
            gateway_api_status_address: reconciler_config.gateway_api_status_address.clone(),
            mesh_sidecar_ingress_enforced: reconciler_config.mesh_sidecar_ingress_enforced,
            gateway_status_writer: gateway_status_writer.clone(),
            istio_status_writer: istio_status_writer.clone(),
            metrics: Arc::clone(&metrics),
        },
    )
    .await;

    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("K8s reconciler shutting down");
                    return;
                }
            }
            _ = full_sync_timer.tick() => {
                debug!("Periodic full-sync reconciliation");
                metrics.full_syncs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                do_reconcile(
                    Arc::clone(&store_set),
                    ReconcileContext {
                        config_arc: Arc::clone(&config_arc),
                        overlay_slot: Arc::clone(&overlay_slot),
                        broadcasts: Arc::clone(&broadcasters.broadcasts),
                        cp_scope: broadcasters.cp_scope.clone(),
                        dp_registry: Arc::clone(&broadcasters.dp_registry),
                        mesh_update_tx: broadcasters.mesh_update_tx.clone(),
                        mesh_registry: Arc::clone(&broadcasters.mesh_registry),
                        publication_gate: broadcasters.publication_gate.clone(),
                        namespace: reconciler_config.namespace.clone(),
                        controller_namespace: reconciler_config.controller_namespace.clone(),
                        cluster_domain: reconciler_config.cluster_domain.clone(),
                        istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
                        watch_namespaces: reconciler_config.watch_namespaces.clone(),
                        trust_domain: trust_domain.clone(),
                        pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
                        gateway_api_data_plane_service_namespace: reconciler_config
                            .gateway_api_data_plane_service_namespace
                            .clone(),
                        gateway_api_data_plane_service_name: reconciler_config
                            .gateway_api_data_plane_service_name
                            .clone(),
                        gateway_api_status_address: reconciler_config
                            .gateway_api_status_address
                            .clone(),
                        mesh_sidecar_ingress_enforced: reconciler_config
                            .mesh_sidecar_ingress_enforced,
                        gateway_status_writer: gateway_status_writer.clone(),
                        istio_status_writer: istio_status_writer.clone(),
                        metrics: Arc::clone(&metrics),
                    },
                ).await;
            }
            result = change_rx.changed() => {
                if result.is_err() {
                    info!("Change channel closed, stopping reconciler");
                    return;
                }
                // Debounce: wait for events to settle before reconciling.
                debounce_events(&mut change_rx, debounce).await;
                do_reconcile(
                    Arc::clone(&store_set),
                    ReconcileContext {
                        config_arc: Arc::clone(&config_arc),
                        overlay_slot: Arc::clone(&overlay_slot),
                        broadcasts: Arc::clone(&broadcasters.broadcasts),
                        cp_scope: broadcasters.cp_scope.clone(),
                        dp_registry: Arc::clone(&broadcasters.dp_registry),
                        mesh_update_tx: broadcasters.mesh_update_tx.clone(),
                        mesh_registry: Arc::clone(&broadcasters.mesh_registry),
                        publication_gate: broadcasters.publication_gate.clone(),
                        namespace: reconciler_config.namespace.clone(),
                        controller_namespace: reconciler_config.controller_namespace.clone(),
                        cluster_domain: reconciler_config.cluster_domain.clone(),
                        istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
                        watch_namespaces: reconciler_config.watch_namespaces.clone(),
                        trust_domain: trust_domain.clone(),
                        pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
                        gateway_api_data_plane_service_namespace: reconciler_config
                            .gateway_api_data_plane_service_namespace
                            .clone(),
                        gateway_api_data_plane_service_name: reconciler_config
                            .gateway_api_data_plane_service_name
                            .clone(),
                        gateway_api_status_address: reconciler_config
                            .gateway_api_status_address
                            .clone(),
                        mesh_sidecar_ingress_enforced: reconciler_config
                            .mesh_sidecar_ingress_enforced,
                        gateway_status_writer: gateway_status_writer.clone(),
                        istio_status_writer: istio_status_writer.clone(),
                        metrics: Arc::clone(&metrics),
                    },
                ).await;
            }
        }
    }
}

async fn debounce_events(change_rx: &mut watch::Receiver<u64>, window: Duration) {
    let started = tokio::time::Instant::now();
    let mut deadline = started + window;
    let hard_cap = started + window * 4;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || tokio::time::Instant::now() >= hard_cap {
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep(remaining) => break,
            result = change_rx.changed() => {
                if result.is_err() {
                    break;
                }
                deadline = refresh_debounce_deadline(tokio::time::Instant::now(), window, hard_cap);
            }
        }
    }
}

fn refresh_debounce_deadline(
    now: tokio::time::Instant,
    window: Duration,
    hard_cap: tokio::time::Instant,
) -> tokio::time::Instant {
    let next_deadline = now + window;
    if next_deadline < hard_cap {
        next_deadline
    } else {
        hard_cap
    }
}

fn full_sync_interval_duration(configured_secs: u64) -> Duration {
    Duration::from_secs(configured_secs.max(1))
}

async fn wait_for_initial_store_readiness(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    change_rx: &mut watch::Receiver<u64>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    wait_for_initial_store_readiness_with_timeout(
        store_set,
        change_rx,
        shutdown,
        INITIAL_STORE_READINESS_TIMEOUT,
    )
    .await
}

async fn wait_for_initial_store_readiness_with_timeout(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    change_rx: &mut watch::Receiver<u64>,
    shutdown: &mut watch::Receiver<bool>,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if tokio::time::Instant::now() >= deadline {
            warn!(
                timeout_ms = timeout.as_millis(),
                "Timed out waiting for initial K8s reflector stores; reconciling available state"
            );
            return true;
        }

        let stores = {
            // See `do_reconcile` rustdoc on `lock_owned` for the HRTB Send
            // reasoning: same constraint here, same fix.
            let set = Arc::clone(&store_set).lock_owned().await;
            set.stores()
        };

        if !stores.is_empty() {
            for store in stores {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    warn!(
                        timeout_ms = timeout.as_millis(),
                        "Timed out waiting for initial K8s reflector stores; reconciling available state"
                    );
                    return true;
                }
                tokio::select! {
                    // `wait_until_ready_owned` captures the `Arc<CrdResourceStore>`
                    // by value so no `&CrdResourceStore` borrow is held across
                    // the timeout's `.await`. See `CrdResourceStore::wait_until_ready_owned`.
                    result = tokio::time::timeout(remaining, store.wait_until_ready_owned()) => {
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                warn!(
                                    error = %e,
                                    "K8s reflector store failed before initial readiness; reconciling available state"
                                );
                                return true;
                            }
                            Err(_) => {
                                warn!(
                                    timeout_ms = timeout.as_millis(),
                                    "Timed out waiting for initial K8s reflector stores; reconciling available state"
                                );
                                return true;
                            }
                        }
                    }
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            info!("K8s reconciler shutting down before initial store readiness");
                            return false;
                        }
                    }
                }
            }
            return true;
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("K8s reconciler shutting down before any CRD stores became available");
                    return false;
                }
            }
            _ = tokio::time::sleep(deadline.saturating_duration_since(tokio::time::Instant::now())) => {
                warn!(
                    timeout_ms = timeout.as_millis(),
                    "Timed out waiting for initial K8s CRD stores; reconciling available state"
                );
                return true;
            }
            changed = change_rx.changed() => {
                if changed.is_err() {
                    info!("K8s CRD store change channel closed before initial readiness");
                    return false;
                }
            }
        }
    }
}

/// Owned ReconcileContext — every field is an owned value or a cheap-to-clone
/// `Arc`. Previously this struct carried `&'a` references with a lifetime
/// parameter, which tripped a rustc HRTB inference bug on `tokio::spawn`'s
/// `Send + 'static` bound: the compiler proved `Send` for `&'0 T` for a
/// specific `'0` but not for all lifetimes, so the spawned future was rejected.
/// Cloning `Arc`s (refcount bumps) and the small `Clone` writer/notifier
/// values once per reconcile is cheap relative to the reconciliation work.
struct ReconcileContext {
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    /// Independently owned last-accepted K8s translation for CP full-reload
    /// re-merge (issues #2982 / #2984).
    overlay_slot: K8sOverlaySlot,
    broadcasts: Arc<NamespaceBroadcasts>,
    cp_scope: CpScope,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    publication_gate: CpPublicationGate,
    namespace: String,
    controller_namespace: String,
    cluster_domain: String,
    istio_root_namespace: String,
    watch_namespaces: Vec<String>,
    trust_domain: TrustDomain,
    pod_discovery_enabled: bool,
    gateway_api_data_plane_service_namespace: Option<String>,
    gateway_api_data_plane_service_name: Option<String>,
    gateway_api_status_address: Option<String>,
    mesh_sidecar_ingress_enforced: bool,
    gateway_status_writer: Option<GatewayApiStatusWriter>,
    /// T2-B: Istio CRD status sub-resource patcher. `None` when the
    /// controller couldn't be built (no Istio CRD watching, or the
    /// kube client isn't available). The reconciler short-circuits to
    /// a no-op when None — every other code path stays unchanged.
    istio_status_writer: Option<IstioStatusWriter>,
    metrics: Arc<ControllerMetrics>,
}

fn namespaces_for_broadcast(
    config: &GatewayConfig,
    fallback_namespace: &str,
    cp_scope: &CpScope,
    broadcasts: &NamespaceBroadcasts,
) -> Vec<String> {
    let mut namespaces = BTreeSet::new();
    namespaces.extend(config.known_namespaces.iter().cloned());
    namespaces.extend(config.proxies.iter().map(|p| p.namespace.clone()));
    namespaces.extend(config.consumers.iter().map(|c| c.namespace.clone()));
    namespaces.extend(config.plugin_configs.iter().map(|pc| pc.namespace.clone()));
    namespaces.extend(config.upstreams.iter().map(|u| u.namespace.clone()));
    if let Some(mesh) = config.mesh.as_ref() {
        namespaces.extend(mesh.workloads.iter().map(|w| w.namespace.clone()));
        namespaces.extend(mesh.services.iter().map(|s| s.namespace.clone()));
        namespaces.extend(mesh.mesh_policies.iter().map(|p| p.namespace.clone()));
        namespaces.extend(
            mesh.peer_authentications
                .iter()
                .map(|p| p.namespace.clone()),
        );
        namespaces.extend(mesh.service_entries.iter().map(|e| e.namespace.clone()));
        namespaces.extend(
            mesh.request_authentications
                .iter()
                .map(|r| r.namespace.clone()),
        );
        namespaces.extend(mesh.telemetry_resources.iter().map(|t| t.namespace.clone()));
        namespaces.extend(mesh.destination_rules.iter().map(|d| d.namespace.clone()));
        namespaces.extend(mesh.proxy_configs.iter().map(|p| p.namespace.clone()));
        namespaces.extend(mesh.sidecars.iter().map(|s| s.namespace.clone()));
        namespaces.extend(mesh.waypoint_bindings.iter().map(|w| w.namespace.clone()));
    }
    match cp_scope {
        CpScope::Single(namespace) => {
            namespaces.insert(namespace.clone());
        }
        CpScope::Set(scope_namespaces) => {
            namespaces.extend(scope_namespaces.iter().cloned());
        }
        CpScope::All => {
            namespaces.extend(broadcasts.namespaces());
        }
    }
    namespaces.retain(|namespace| !namespace.trim().is_empty());
    if namespaces.is_empty() {
        namespaces.insert(fallback_namespace.to_string());
    }
    namespaces.into_iter().collect()
}

/// Publish an accepted K8s translation: record the overlay, CAS the merged
/// snapshot into `config_arc`, and emit the per-namespace DP updates plus the
/// mesh full snapshot — all inside one [`CpPublicationGate`] section, so the
/// CP DB poll loop can never slip a commit or a broadcast between them.
///
/// Returns the published snapshot, or `None` when the merge produced no
/// content change (nothing committed, nothing broadcast).
///
/// The overlay slot is still written BEFORE the CAS. Holding the gate means
/// there is no losing CAS writer in practice, but the ordering is preserved so
/// the CAS retry loops stay correct on their own terms: a writer that did lose
/// re-composes against the newest accepted overlay rather than an older one.
#[allow(clippy::too_many_arguments)]
pub fn publish_k8s_reconcile(
    publication_gate: &CpPublicationGate,
    config_arc: &ArcSwap<GatewayConfig>,
    overlay_slot: &K8sOverlaySlot,
    translation: &GatewayConfig,
    managed_namespaces: &BTreeSet<String>,
    fallback_namespace: &str,
    broadcasts: &NamespaceBroadcasts,
    dp_registry: &DpNodeRegistry,
    cp_scope: &CpScope,
    mesh_update_tx: &broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: &MeshNodeRegistry,
) -> Option<Arc<GatewayConfig>> {
    publication_gate.publish(|| {
        // Persist the translation independently of `config_arc` so CP DB full
        // reloads can re-merge it instead of broadcasting a wipe (#2982).
        store_accepted_k8s_overlay(
            overlay_slot,
            translation.clone(),
            managed_namespaces.clone(),
        );
        let new_config = swap_merged_k8s_translation(config_arc, translation, managed_namespaces)?;

        // Notify DPs and mesh subscribers of the config change.
        for namespace in
            namespaces_for_broadcast(&new_config, fallback_namespace, cp_scope, broadcasts)
        {
            CpGrpcServer::broadcast_namespace_update(
                broadcasts,
                &namespace,
                &new_config,
                dp_registry,
                cp_scope,
            );
        }
        MeshGrpcServer::broadcast_full_with_registry(
            mesh_update_tx,
            Arc::clone(&new_config),
            mesh_registry,
        );
        Some(new_config)
    })
}

async fn do_reconcile(store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>, ctx: ReconcileContext) {
    let start = std::time::Instant::now();
    ctx.metrics
        .reconciliations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let objects = {
        // `lock_owned` keeps the guard from holding a `&Mutex<…>` borrow across
        // the `.await`, which would otherwise force rustc into an HRTB Send
        // analysis it can't satisfy when the future is `tokio::spawn`-ed.
        let set = Arc::clone(&store_set).lock_owned().await;
        set.snapshot_all()
    };

    let resource_count = objects.len();
    debug!(resource_count, "Starting reconciliation");

    let source_namespaces =
        namespaces_with_istio_root(&ctx.watch_namespaces, &ctx.istio_root_namespace);
    let options = K8sTranslationOptions::new(ctx.namespace.clone(), ctx.trust_domain.clone())
        .with_cluster_domain(ctx.cluster_domain.clone())
        .with_istio_root_namespace(ctx.istio_root_namespace.clone())
        .with_node_waypoint_namespace(ctx.controller_namespace.clone())
        .with_source_namespaces(source_namespaces)
        .with_pod_source_namespaces(ctx.watch_namespaces.clone())
        .with_pod_discovery_enabled(ctx.pod_discovery_enabled)
        .with_mesh_sidecar_ingress_enforced(ctx.mesh_sidecar_ingress_enforced);
    let Some((translation, translation_errors)) =
        translate_with_skip_retries(&objects, options.clone(), &ctx.metrics)
    else {
        return;
    };
    let gateway_api_status_context = gateway_api_status_context(&objects, &ctx);
    let status_reuse = StatusTranslationReuse {
        translation: Arc::new(translation),
        errors: Arc::new(translation_errors),
    };
    let translation = status_reuse.translation.as_ref();

    for warning in &translation.warnings {
        warn!(warning, "K8s translation warning");
    }

    let managed_namespaces = managed_k8s_namespaces(
        &ctx.namespace,
        &ctx.watch_namespaces,
        &translation.config.known_namespaces,
    );
    // Commit and broadcast as one publication, serialized against the CP DB
    // poll loop. Kubernetes status-patch I/O stays outside the section.
    let published = publish_k8s_reconcile(
        &ctx.publication_gate,
        &ctx.config_arc,
        &ctx.overlay_slot,
        &translation.config,
        &managed_namespaces,
        &ctx.namespace,
        ctx.broadcasts.as_ref(),
        &ctx.dp_registry,
        &ctx.cp_scope,
        &ctx.mesh_update_tx,
        &ctx.mesh_registry,
    );
    let Some(new_config) = published else {
        debug!("No config changes detected, skipping swap");
        // Status writers share one immutable `Arc<[K8sObject]>` generation
        // (see [`shared_status_objects_snapshot`]). Deployments that don't
        // watch Gateway API / Istio CRDs (the default) pay zero per-
        // reconcile move cost.
        run_status_patchers(
            ctx.gateway_status_writer,
            ctx.istio_status_writer,
            objects,
            &options,
            Some(&translation.route_conflicts),
            gateway_api_status_context,
            Some(&status_reuse),
            &ctx.metrics,
        )
        .await;
        let elapsed = start.elapsed();
        ctx.metrics.last_reconcile_duration_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return;
    };

    // Same shared-snapshot contract as the no-change branch above.
    run_status_patchers(
        ctx.gateway_status_writer,
        ctx.istio_status_writer,
        objects,
        &options,
        Some(&translation.route_conflicts),
        gateway_api_status_context,
        Some(&status_reuse),
        &ctx.metrics,
    )
    .await;

    let elapsed = start.elapsed();
    ctx.metrics.last_reconcile_duration_ms.store(
        elapsed.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );

    info!(
        resource_count,
        proxies = new_config.proxies.len(),
        upstreams = new_config.upstreams.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "Reconciliation complete"
    );
}

/// Build the immutable object generation shared by Gateway API and Istio
/// status writers for one reconcile.
///
/// Returns `None` when neither writer will run so the default deployment
/// (no Gateway API / Istio status watching) pays zero snapshot cost and the
/// caller's `Vec` is dropped without wrapping. When at least one writer is
/// present, the already-owned reconcile `Vec<K8sObject>` is moved into one
/// `Arc<[K8sObject]>` without cloning elements or their `spec`/`status`
/// payloads; a second writer only bumps the refcount.
///
/// The Arc keeps planner futures `Send + 'static` across the reconciler's
/// `tokio::spawn` HRTB boundary without aliasing the store's mutable
/// reflector state — each reconcile owns a distinct generation.
pub(crate) fn shared_status_objects_snapshot(
    objects: Vec<K8sObject>,
    gateway_writer_present: bool,
    istio_writer_present: bool,
) -> Option<Arc<[K8sObject]>> {
    if !gateway_writer_present && !istio_writer_present {
        return None;
    }
    // `From<Vec<T>> for Arc<[T]>` moves the allocation; do not use
    // `Arc::from(&[T])`, which deep-clones every `K8sObject` (#2397).
    Some(Arc::<[K8sObject]>::from(objects))
}

/// Dispatch to whichever status patchers are configured.
///
/// Both writers observe the same immutable object generation
/// ([`shared_status_objects_snapshot`]) while retaining independent bounded
/// update plans, patch concurrency, route-conflict inputs, and failure
/// handling. Writers are taken by value so they can be moved into the helper
/// futures (required for `tokio::spawn`'s HRTB Send check — see the
/// `Send is not general enough` history in `spawn_reconcile_loop`).
async fn run_status_patchers(
    gateway_writer: Option<GatewayApiStatusWriter>,
    istio_writer: Option<IstioStatusWriter>,
    objects: Vec<K8sObject>,
    options: &K8sTranslationOptions,
    route_conflicts: Option<&[crate::config_sources::k8s::GatewayApiRouteConflict]>,
    gateway_api_status_context: GatewayApiStatusContext,
    translation_reuse: Option<&StatusTranslationReuse>,
    metrics: &ControllerMetrics,
) {
    let Some(snapshot) =
        shared_status_objects_snapshot(objects, gateway_writer.is_some(), istio_writer.is_some())
    else {
        return;
    };

    if let Some(writer) = gateway_writer {
        patch_gateway_api_statuses(
            writer,
            Arc::clone(&snapshot),
            options.clone(),
            route_conflicts.map(<[_]>::to_vec).unwrap_or_default(),
            gateway_api_status_context,
            translation_reuse,
            metrics,
        )
        .await;
    }
    if let Some(writer) = istio_writer {
        patch_istio_statuses(writer, snapshot, options.clone(), translation_reuse).await;
    }
}

async fn patch_gateway_api_statuses(
    writer: GatewayApiStatusWriter,
    objects: Arc<[K8sObject]>,
    options: K8sTranslationOptions,
    route_conflicts: Vec<crate::config_sources::k8s::GatewayApiRouteConflict>,
    status_context: GatewayApiStatusContext,
    translation_reuse: Option<&StatusTranslationReuse>,
    metrics: &ControllerMetrics,
) {
    let cursor = metrics
        .gateway_api_status_plan_cursor
        .load(std::sync::atomic::Ordering::Relaxed) as usize;
    let outcome = plan_gateway_api_status_updates_budgeted(
        &objects,
        options,
        &route_conflicts,
        status_context,
        translation_reuse,
        StatusPlanBudget::new(GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP, cursor),
    );
    metrics.gateway_api_status_plan_cursor.store(
        outcome.next_cursor as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    let updates = outcome.updates;
    if updates.is_empty() {
        return;
    }
    if outcome.eligible_candidates > GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP {
        warn!(
            eligible = outcome.eligible_candidates,
            planned = outcome.planned_candidates,
            updates = updates.len(),
            cap = GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP,
            cursor,
            next_cursor = outcome.next_cursor,
            "Budgeted Gateway API status planning for this reconcile round"
        );
    }
    let updates_len = updates.len();
    match await_status_patch_batch(writer.patch_updates(updates), STATUS_PATCH_BATCH_TIMEOUT).await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(
                error = %error,
                updates = updates_len,
                "Failed to patch Gateway API status"
            );
        }
        Err(_) => {
            warn!(
                updates = updates_len,
                timeout_secs = STATUS_PATCH_BATCH_TIMEOUT.as_secs(),
                "Gateway API status patch batch timed out; unfinished updates will retry on a later reconcile"
            );
        }
    }
}

fn gateway_api_status_context(
    objects: &[K8sObject],
    ctx: &ReconcileContext,
) -> GatewayApiStatusContext {
    let data_plane_ready = match (
        ctx.gateway_api_data_plane_service_namespace.as_deref(),
        ctx.gateway_api_data_plane_service_name.as_deref(),
    ) {
        (Some(namespace), Some(name)) => {
            gateway_api_data_plane_service_ready(objects, namespace, name)
        }
        _ => true,
    };
    GatewayApiStatusContext {
        data_plane_ready,
        status_address: ctx.gateway_api_status_address.clone(),
    }
}

/// T2-B: emit `status.conditions[]` patches for the Istio CRDs supported
/// by [`plan_istio_status_updates`]. No-op when the writer wasn't built
/// (Istio CRD watching is off, or kube client unavailable) or when the
/// plan is empty (no supported Istio CRDs in the snapshot). Failures
/// are logged and never abort reconcile. Shares the same immutable
/// object generation as the Gateway API writer when both are enabled.
async fn patch_istio_statuses(
    writer: IstioStatusWriter,
    objects: Arc<[K8sObject]>,
    options: K8sTranslationOptions,
    translation_reuse: Option<&StatusTranslationReuse>,
) {
    let updates = plan_istio_status_updates_budgeted(
        &objects,
        options,
        translation_reuse,
        StatusPlanBudget::unlimited(0),
    )
    .updates;
    if updates.is_empty() {
        return;
    }
    let updates_len = updates.len();
    match await_status_patch_batch(writer.patch_updates(updates), STATUS_PATCH_BATCH_TIMEOUT).await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(
                error = %error,
                updates = updates_len,
                "Failed to patch Istio status (CRD may not have a status subresource)"
            );
        }
        Err(_) => {
            warn!(
                updates = updates_len,
                timeout_secs = STATUS_PATCH_BATCH_TIMEOUT.as_secs(),
                "Istio status patch batch timed out; unfinished updates will retry on a later reconcile"
            );
        }
    }
}

async fn await_status_patch_batch<F, E>(
    future: F,
    timeout: Duration,
) -> Result<Result<(), E>, tokio::time::error::Elapsed>
where
    F: Future<Output = Result<(), E>>,
{
    tokio::time::timeout(timeout, future).await
}

pub fn swap_merged_k8s_translation(
    config_arc: &ArcSwap<GatewayConfig>,
    k8s_config: &GatewayConfig,
    managed_namespaces: &BTreeSet<String>,
) -> Option<Arc<GatewayConfig>> {
    let mut old_config = config_arc.load();

    loop {
        let new_config = Arc::new(merge_k8s_translation(
            old_config.as_ref(),
            k8s_config,
            managed_namespaces,
        ));
        if !gateway_config_content_changed(&new_config, old_config.as_ref()) {
            return None;
        }

        let previous = config_arc.compare_and_swap(&*old_config, new_config.clone());
        if Arc::ptr_eq(&*old_config, &*previous) {
            return Some(new_config);
        }

        old_config = previous;
    }
}

fn gateway_config_content_changed(new_config: &GatewayConfig, old_config: &GatewayConfig) -> bool {
    stable_config_value(new_config) != stable_config_value(old_config)
}

const K8S_MANAGED_PROXY_ID_PREFIXES: &[&str] = &["gwapi-route-", "gwapi-l4-", "istio-vs-"];
const K8S_MANAGED_UPSTREAM_ID_PREFIXES: &[&str] = &["gwapi-route-upstream-", "istio-vs-upstream-"];
const K8S_MANAGED_PLUGIN_CONFIG_ID_PREFIXES: &[&str] = &[
    "istio-vs-cors-",
    "istio-vs-fi-",
    "istio-vs-mirror-",
    "istio-vs-mrd-",
    "istio-vs-rt-",
    "istio-vs-req-xform-",
    "istio-vs-resp-xform-",
];

fn managed_k8s_namespaces(
    namespace: &str,
    watch_namespaces: &[String],
    k8s_known_namespaces: &[String],
) -> BTreeSet<String> {
    if watch_namespaces.is_empty() {
        return BTreeSet::new();
    }

    let mut namespaces: BTreeSet<String> = watch_namespaces.iter().cloned().collect();
    namespaces.extend(k8s_known_namespaces.iter().cloned());
    if namespaces.is_empty() {
        namespaces.insert(namespace.to_string());
    }
    namespaces
}

fn namespace_is_managed(namespace: &str, managed_namespaces: &BTreeSet<String>) -> bool {
    managed_namespaces.is_empty() || managed_namespaces.contains(namespace)
}

pub fn merge_k8s_translation(
    active: &GatewayConfig,
    k8s_config: &GatewayConfig,
    managed_namespaces: &BTreeSet<String>,
) -> GatewayConfig {
    let mut merged = active.clone();

    merged.proxies.retain(|proxy| {
        !(namespace_is_managed(&proxy.namespace, managed_namespaces)
            && has_any_prefix(&proxy.id, K8S_MANAGED_PROXY_ID_PREFIXES))
    });
    merged.upstreams.retain(|upstream| {
        !(namespace_is_managed(&upstream.namespace, managed_namespaces)
            && has_any_prefix(&upstream.id, K8S_MANAGED_UPSTREAM_ID_PREFIXES))
    });
    merged.plugin_configs.retain(|plugin| {
        !(namespace_is_managed(&plugin.namespace, managed_namespaces)
            && has_any_prefix(&plugin.id, K8S_MANAGED_PLUGIN_CONFIG_ID_PREFIXES))
    });

    merged.proxies.extend(k8s_config.proxies.clone());
    merged.upstreams.extend(k8s_config.upstreams.clone());
    merged
        .plugin_configs
        .extend(k8s_config.plugin_configs.clone());
    merge_k8s_frontend_tls(&mut merged, k8s_config);

    let mut namespaces: BTreeSet<String> = merged.known_namespaces.iter().cloned().collect();
    namespaces.extend(k8s_config.known_namespaces.iter().cloned());
    merged.known_namespaces = namespaces.into_iter().collect();

    if k8s_config.mesh.is_some() {
        merged.mesh = k8s_config.mesh.clone();
    }

    merged.normalize_fields();
    merged
}

fn merge_k8s_frontend_tls(merged: &mut GatewayConfig, k8s_config: &GatewayConfig) {
    let k8s_supplies_tls = !k8s_config.frontend_tls_namespace_sources.is_empty()
        || k8s_config.frontend_tls_cert_path.is_some()
        || k8s_config.frontend_tls_key_path.is_some();
    if k8s_supplies_tls {
        merged.frontend_tls_cert_path = k8s_config.frontend_tls_cert_path.clone();
        merged.frontend_tls_key_path = k8s_config.frontend_tls_key_path.clone();
        merged.frontend_tls_source_namespace = k8s_config.frontend_tls_source_namespace.clone();
        merged.frontend_tls_namespace_sources = k8s_config.frontend_tls_namespace_sources.clone();
        return;
    }

    if merged.frontend_tls_source_namespace.is_some()
        || !merged.frontend_tls_namespace_sources.is_empty()
    {
        merged.frontend_tls_cert_path = None;
        merged.frontend_tls_key_path = None;
        merged.frontend_tls_source_namespace = None;
        merged.frontend_tls_namespace_sources.clear();
    }
}

fn has_any_prefix(id: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| id.starts_with(prefix))
}

fn stable_config_value(config: &GatewayConfig) -> Value {
    let mut value = serde_json::json!({
        "version": &config.version,
        "proxies": &config.proxies,
        "consumers": &config.consumers,
        "plugin_configs": &config.plugin_configs,
        "upstreams": &config.upstreams,
        "known_namespaces": &config.known_namespaces,
        "frontend_tls_cert_path": &config.frontend_tls_cert_path,
        "frontend_tls_key_path": &config.frontend_tls_key_path,
        "frontend_tls_source_namespace": &config.frontend_tls_source_namespace,
        "frontend_tls_namespace_sources": &config.frontend_tls_namespace_sources,
        "mesh": &config.mesh,
    });
    strip_volatile_timestamps(&mut value);
    sort_top_level_collection(&mut value, "proxies", "id");
    sort_top_level_collection(&mut value, "consumers", "id");
    sort_top_level_collection(&mut value, "plugin_configs", "id");
    sort_top_level_collection(&mut value, "upstreams", "id");
    sort_string_array(&mut value, "known_namespaces");
    sort_mesh_collection(&mut value, "workloads", "spiffe_id");
    sort_mesh_collection(&mut value, "services", "name");
    sort_mesh_service_workloads(&mut value);
    value
}

fn strip_volatile_timestamps(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("loaded_at");
            map.remove("created_at");
            map.remove("updated_at");
            for child in map.values_mut() {
                strip_volatile_timestamps(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                strip_volatile_timestamps(item);
            }
        }
        _ => {}
    }
}

fn sort_top_level_collection(value: &mut Value, field: &str, key: &str) {
    let Some(items) = value.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };

    items.sort_by(|left, right| {
        let left_key = left.get(key).and_then(Value::as_str).unwrap_or_default();
        let right_key = right.get(key).and_then(Value::as_str).unwrap_or_default();
        left_key.cmp(right_key)
    });
}

fn sort_string_array(value: &mut Value, field: &str) {
    let Some(items) = value.get_mut(field).and_then(Value::as_array_mut) else {
        return;
    };

    items.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
}

fn sort_mesh_collection(value: &mut Value, field: &str, key: &str) {
    let Some(items) = value
        .get_mut("mesh")
        .and_then(Value::as_object_mut)
        .and_then(|mesh| mesh.get_mut(field))
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    items.sort_by_cached_key(|item| {
        (
            item.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            canonical_json_sort_key(item),
        )
    });
}

fn sort_mesh_service_workloads(value: &mut Value) {
    let Some(services) = value
        .get_mut("mesh")
        .and_then(Value::as_object_mut)
        .and_then(|mesh| mesh.get_mut("services"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };

    for service in services {
        let Some(workloads) = service.get_mut("workloads").and_then(Value::as_array_mut) else {
            continue;
        };
        workloads.sort_by_cached_key(|item| {
            (
                item.get("spiffe_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                canonical_json_sort_key(item),
            )
        });
    }
}

fn canonical_json_sort_key(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut key = String::from("{");
            for (index, (name, child)) in entries.into_iter().enumerate() {
                if index > 0 {
                    key.push(',');
                }
                key.push_str(&serde_json::to_string(name).unwrap_or_default());
                key.push(':');
                key.push_str(&canonical_json_sort_key(child));
            }
            key.push('}');
            key
        }
        Value::Array(items) => {
            let mut key = String::from("[");
            for (index, child) in items.iter().enumerate() {
                if index > 0 {
                    key.push(',');
                }
                key.push_str(&canonical_json_sort_key(child));
            }
            key.push(']');
            key
        }
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        FrontendTlsNamespaceSource, PluginConfig, PluginScope, Proxy, Upstream,
    };
    use crate::config_sources::k8s::{K8sMetadata, K8sObject};
    use crate::identity::spiffe::SpiffeId;
    use crate::k8s_controller::resource_store::CrdResourceStore;
    use crate::modes::mesh::config::{
        MeshConfig, MeshPolicy, MeshService, PolicyScope, Workload, WorkloadRef, WorkloadSelector,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use kube::api::ApiResource;
    use kube::runtime::reflector;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    fn plugin_config(id: &str, config: Value) -> PluginConfig {
        PluginConfig {
            id: id.to_string(),
            plugin_name: "rate_limiting".to_string(),
            namespace: "ferrum".to_string(),
            config,
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn proxy(id: &str, backend_host: &str) -> Proxy {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "hosts": ["example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": backend_host,
            "backend_port": 80
        }))
        .expect("test proxy should deserialize")
    }

    fn upstream(id: &str, host: &str) -> Upstream {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "name": id,
            "targets": [{
                "host": host,
                "port": 80,
                "weight": 1
            }]
        }))
        .expect("test upstream should deserialize")
    }

    fn root_policy_only_config() -> GatewayConfig {
        GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                istio_root_namespace: "istio-system".to_string(),
                mesh_policies: vec![MeshPolicy {
                    name: "root-authz".to_string(),
                    namespace: "istio-system".to_string(),
                    scope: PolicyScope::MeshWide,
                    rules: Vec::new(),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn shared_status_snapshot_skipped_when_no_writers() {
        let objects = vec![status_snapshot_object("ConfigMap", "cm")];
        assert!(shared_status_objects_snapshot(objects, false, false).is_none());
    }

    #[test]
    fn shared_status_snapshot_built_once_for_single_writer() {
        let objects = vec![status_snapshot_object("HTTPRoute", "api")];
        let expected = objects.clone();
        let gateway_only = shared_status_objects_snapshot(objects.clone(), true, false)
            .expect("gateway writer requires a snapshot");
        let istio_only = shared_status_objects_snapshot(objects, false, true)
            .expect("istio writer requires a snapshot");
        assert_eq!(gateway_only.as_ref(), expected.as_slice());
        assert_eq!(istio_only.as_ref(), expected.as_slice());
        assert_eq!(Arc::strong_count(&gateway_only), 1);
        assert_eq!(Arc::strong_count(&istio_only), 1);
    }

    #[test]
    fn shared_status_snapshot_moves_owned_vec_without_element_deep_copy() {
        let mut large_spec = serde_json::Map::new();
        large_spec.insert("payload".to_string(), Value::String("x".repeat(64 * 1024)));
        let objects = vec![K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            metadata: K8sMetadata {
                name: "large".to_string(),
                uid: "uid-large".to_string(),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: Value::Object(large_spec),
            status: json!({"observedGeneration": 1}),
        }];
        // Heap pointers inside the moved `K8sObject` must be preserved. A
        // slice-based `Arc::from(&[T])` deep clone would allocate new String
        // buffers and change these addresses.
        let name_ptr = objects[0].metadata.name.as_ptr();
        let payload_ptr = objects[0].spec["payload"]
            .as_str()
            .expect("payload")
            .as_ptr();

        let snapshot = shared_status_objects_snapshot(objects, true, true)
            .expect("both writers share one snapshot");
        assert_eq!(snapshot[0].metadata.name.as_ptr(), name_ptr);
        assert_eq!(
            snapshot[0].spec["payload"]
                .as_str()
                .expect("payload")
                .as_ptr(),
            payload_ptr
        );
        assert_eq!(Arc::strong_count(&snapshot), 1);

        // Simulate the reconciler handoff: each writer receives an Arc clone,
        // not a second deep copy of the large JSON payloads.
        let gateway_view = Arc::clone(&snapshot);
        let istio_view = Arc::clone(&snapshot);
        assert!(Arc::ptr_eq(&gateway_view, &istio_view));
        assert_eq!(Arc::strong_count(&snapshot), 3);
        assert_eq!(
            gateway_view[0].spec["payload"].as_str().map(str::len),
            Some(64 * 1024)
        );
        // Dropping one writer view must not invalidate the other.
        drop(gateway_view);
        assert_eq!(Arc::strong_count(&snapshot), 2);
        assert_eq!(istio_view.len(), 1);
    }

    #[test]
    fn shared_status_snapshot_is_one_arc_generation_for_both_writers() {
        let mut large_spec = serde_json::Map::new();
        large_spec.insert("payload".to_string(), Value::String("x".repeat(64 * 1024)));
        let objects = vec![K8sObject {
            api_version: "gateway.networking.k8s.io/v1".to_string(),
            kind: "HTTPRoute".to_string(),
            metadata: K8sMetadata {
                name: "large".to_string(),
                uid: "uid-large".to_string(),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: Value::Object(large_spec),
            status: json!({"observedGeneration": 1}),
        }];

        let snapshot = shared_status_objects_snapshot(objects, true, true)
            .expect("both writers share one snapshot");
        assert_eq!(Arc::strong_count(&snapshot), 1);

        let gateway_view = Arc::clone(&snapshot);
        let istio_view = Arc::clone(&snapshot);
        assert!(Arc::ptr_eq(&gateway_view, &istio_view));
        assert_eq!(Arc::strong_count(&snapshot), 3);
    }

    #[test]
    fn shared_status_snapshot_reload_replaces_generation_without_aliasing() {
        let first_objects = vec![
            status_snapshot_object("HTTPRoute", "keep"),
            status_snapshot_object("VirtualService", "gone"),
        ];
        let first =
            shared_status_objects_snapshot(first_objects, true, true).expect("initial generation");

        let reloaded_objects = vec![status_snapshot_object("HTTPRoute", "keep")];
        let reloaded = shared_status_objects_snapshot(reloaded_objects, true, true)
            .expect("reload generation");

        assert!(!Arc::ptr_eq(&first, &reloaded));
        assert_eq!(first.len(), 2);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].metadata.name, "keep");
        assert!(
            !reloaded.iter().any(|object| object.metadata.name == "gone"),
            "deleted objects must not appear in the reload generation"
        );
        // Prior generation remains independently readable after reload.
        assert!(first.iter().any(|object| object.metadata.name == "gone"));
    }

    #[test]
    fn shared_status_snapshot_planning_parity_matches_slice_inputs() {
        let objects = vec![
            status_snapshot_object("HTTPRoute", "api"),
            status_snapshot_object("VirtualService", "vs"),
            status_snapshot_object("ConfigMap", "noise"),
        ];
        let snapshot = shared_status_objects_snapshot(objects.clone(), true, true)
            .expect("both writers present");
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        );

        let gateway_from_slice = plan_gateway_api_status_updates_with_context(
            &objects,
            options.clone(),
            &[],
            Default::default(),
        );
        let gateway_from_arc = plan_gateway_api_status_updates_with_context(
            &snapshot,
            options.clone(),
            &[],
            Default::default(),
        );
        assert_status_update_identity_parity(&gateway_from_slice, &gateway_from_arc);

        let istio_from_slice = plan_istio_status_updates(&objects, options.clone());
        let istio_from_arc = plan_istio_status_updates(&snapshot, options);
        assert_eq!(istio_from_slice.len(), istio_from_arc.len());
        for (left, right) in istio_from_slice.iter().zip(istio_from_arc.iter()) {
            assert_eq!(left.kind, right.kind);
            assert_eq!(left.namespace, right.namespace);
            assert_eq!(left.name, right.name);
            assert_eq!(left.ferrum_detail, right.ferrum_detail);
        }
    }

    #[test]
    fn status_writer_plans_stay_independent_on_shared_snapshot() {
        let objects = vec![
            status_snapshot_object("HTTPRoute", "api"),
            status_snapshot_object("VirtualService", "vs"),
        ];
        let snapshot =
            shared_status_objects_snapshot(objects, true, true).expect("both writers present");
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        );

        let gateway = plan_gateway_api_status_updates_with_context(
            &snapshot,
            options.clone(),
            &[],
            Default::default(),
        );
        let istio = plan_istio_status_updates(&snapshot, options);

        assert!(
            gateway.iter().all(|update| {
                matches!(
                    update.kind.as_str(),
                    "HTTPRoute"
                        | "Gateway"
                        | "GatewayClass"
                        | "GRPCRoute"
                        | "TCPRoute"
                        | "TLSRoute"
                )
            }),
            "gateway planner must not emit Istio kinds"
        );
        assert!(
            istio.iter().all(|update| update.kind != "HTTPRoute"),
            "istio planner must not emit Gateway API kinds"
        );
        // Independent planners: an empty Gateway plan must not suppress Istio
        // updates (and vice versa) when both kinds are present.
        assert!(
            !istio.is_empty(),
            "VirtualService on the shared snapshot must still plan Istio status"
        );
    }

    fn status_snapshot_object(kind: &str, name: &str) -> K8sObject {
        let (api_version, spec) = match kind {
            "HTTPRoute" => (
                "gateway.networking.k8s.io/v1",
                json!({
                    "parentRefs": [{"name": "edge"}],
                    "rules": [{"backendRefs": [{"name": "svc", "port": 80}]}]
                }),
            ),
            "VirtualService" => (
                "networking.istio.io/v1beta1",
                json!({
                    "hosts": ["example.com"],
                    "http": [{"route": [{"destination": {"host": "svc"}}]}]
                }),
            ),
            _ => ("v1", json!({})),
        };
        K8sObject {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            metadata: K8sMetadata {
                name: name.to_string(),
                uid: format!("uid-{name}"),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec,
            status: Value::Object(serde_json::Map::new()),
        }
    }

    fn assert_status_update_identity_parity(
        left: &[crate::k8s_controller::status::GatewayApiStatusUpdate],
        right: &[crate::k8s_controller::status::GatewayApiStatusUpdate],
    ) {
        assert_eq!(left.len(), right.len());
        for (a, b) in left.iter().zip(right.iter()) {
            assert_eq!(a.api_version, b.api_version);
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.namespace, b.namespace);
            assert_eq!(a.name, b.name);
            assert_eq!(a.patch_gateway_addresses, b.patch_gateway_addresses);
            assert_eq!(a.patch_gateway_listeners, b.patch_gateway_listeners);
        }
    }

    #[test]
    fn broadcast_namespaces_include_explicit_cp_scope_namespaces() {
        let mut scope = HashSet::new();
        scope.insert("tenant-a".to_string());
        scope.insert("tenant-b".to_string());
        let broadcasts = NamespaceBroadcasts::new(4);

        let namespaces = namespaces_for_broadcast(
            &root_policy_only_config(),
            "fallback",
            &CpScope::Set(scope),
            &broadcasts,
        );

        assert!(namespaces.iter().any(|namespace| namespace == "tenant-a"));
        assert!(namespaces.iter().any(|namespace| namespace == "tenant-b"));
        assert!(
            namespaces
                .iter()
                .any(|namespace| namespace == "istio-system")
        );
    }

    #[test]
    fn broadcast_namespaces_include_all_scope_subscribed_namespaces() {
        let broadcasts = NamespaceBroadcasts::new(4);
        let _ = broadcasts.sender_for("tenant-a");

        let namespaces = namespaces_for_broadcast(
            &root_policy_only_config(),
            "fallback",
            &CpScope::All,
            &broadcasts,
        );

        assert!(namespaces.iter().any(|namespace| namespace == "tenant-a"));
        assert!(
            namespaces
                .iter()
                .any(|namespace| namespace == "istio-system")
        );
    }

    fn mesh_workload(service_account: &str) -> Workload {
        let trust_domain = TrustDomain::new("cluster.local").expect("test trust domain");
        Workload {
            spiffe_id: SpiffeId::new(format!(
                "spiffe://cluster.local/ns/default/sa/{service_account}"
            ))
            .expect("test SPIFFE ID"),
            selector: WorkloadSelector::default(),
            service_name: "reviews".to_string(),
            addresses: vec!["10.1.0.10".to_string()],
            ports: Vec::new(),
            trust_domain,
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: Some(service_account.to_string()),
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }
    }

    fn mesh_workload_ref(service_account: &str) -> WorkloadRef {
        WorkloadRef {
            spiffe_id: SpiffeId::new(format!(
                "spiffe://cluster.local/ns/default/sa/{service_account}"
            ))
            .expect("test SPIFFE ID"),
        }
    }

    fn mesh_service_with_workloads(workloads: Vec<WorkloadRef>) -> MeshService {
        MeshService {
            cluster_ips: Vec::new(),
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ports: Vec::new(),
            workloads,
            protocol_overrides: HashMap::new(),
        }
    }

    #[test]
    fn content_change_detects_same_count_plugin_edit() {
        let mut old_config = GatewayConfig::default();
        old_config.plugin_configs.push(plugin_config(
            "rate",
            json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}),
        ));
        let mut new_config = old_config.clone();
        new_config.plugin_configs[0].config =
            json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 200}]});

        assert!(gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_volatile_timestamps() {
        let mut old_config = GatewayConfig::default();
        old_config.plugin_configs.push(plugin_config(
            "rate",
            json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}),
        ));
        let mut new_config = old_config.clone();
        new_config.loaded_at = old_config.loaded_at + ChronoDuration::seconds(5);
        new_config.plugin_configs[0].updated_at =
            old_config.plugin_configs[0].updated_at + ChronoDuration::seconds(5);

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_top_level_resource_order() {
        let mut old_config = GatewayConfig::default();
        old_config
            .plugin_configs
            .push(plugin_config("b", json!({"value": 2})));
        old_config
            .plugin_configs
            .push(plugin_config("a", json!({"value": 1})));
        let mut new_config = old_config.clone();
        new_config.plugin_configs.reverse();

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_mesh_workload_order() {
        let old_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![mesh_workload("b"), mesh_workload("a")],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let mut new_config = old_config.clone();
        new_config
            .mesh
            .as_mut()
            .expect("mesh config")
            .workloads
            .reverse();

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_duplicate_spiffe_mesh_workload_order() {
        let mut workload_a = mesh_workload("reviews");
        workload_a.addresses = vec!["10.1.0.10".to_string()];
        let mut workload_b = mesh_workload("reviews");
        workload_b.addresses = vec!["10.1.0.11".to_string()];
        let old_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![workload_a, workload_b],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let mut new_config = old_config.clone();
        new_config
            .mesh
            .as_mut()
            .expect("mesh config")
            .workloads
            .reverse();

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_mesh_service_workload_ref_order() {
        let workload_a = mesh_workload_ref("a");
        let workload_b = mesh_workload_ref("b");
        let old_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![mesh_service_with_workloads(vec![
                    workload_b.clone(),
                    workload_a.clone(),
                ])],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let new_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![mesh_service_with_workloads(vec![workload_a, workload_b])],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn content_change_ignores_mesh_service_order() {
        let mut service_a = mesh_service_with_workloads(vec![mesh_workload_ref("a")]);
        service_a.name = "api".to_string();
        let mut service_b = mesh_service_with_workloads(vec![mesh_workload_ref("b")]);
        service_b.name = "reviews".to_string();
        let old_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![service_b.clone(), service_a.clone()],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let new_config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                services: vec![service_a, service_b],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };

        assert!(!gateway_config_content_changed(&new_config, &old_config));
    }

    #[test]
    fn merge_k8s_translation_preserves_db_resources_and_replaces_k8s_overlay() {
        let mut active = GatewayConfig::default();
        active.proxies.push(proxy("db-proxy", "db.internal"));
        active.plugin_configs.push(plugin_config(
            "operator-rate-limit",
            json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]}),
        ));
        active
            .proxies
            .push(proxy("gwapi-route-ferrum-old-0", "old.internal"));
        active.upstreams.push(upstream(
            "gwapi-route-upstream-ferrum-old-0",
            "old.internal",
        ));
        active.plugin_configs.push(plugin_config(
            "istio-vs-mrd-ferrum-old-0",
            json!({"rules": [{"match": {"methods": ["GET"]}, "destination": {"upstream_id": "old"}}]}),
        ));
        active.plugin_configs.push(plugin_config(
            "istio-vs-rt-ferrum-old-0",
            json!({"status_code": 404, "message": "unsupported Istio VirtualService match predicate"}),
        ));
        active.plugin_configs.push(plugin_config(
            "istio-vs-mirror-ferrum-old-0",
            json!({"mirror_host": "old-mirror.internal", "mirror_port": 8080, "percentage": 100.0}),
        ));
        active.known_namespaces.push("db".to_string());

        let mut k8s = GatewayConfig::default();
        k8s.proxies
            .push(proxy("gwapi-route-ferrum-new-0", "new.internal"));
        k8s.upstreams.push(upstream(
            "gwapi-route-upstream-ferrum-new-0",
            "new.internal",
        ));
        k8s.plugin_configs.push(plugin_config(
            "istio-vs-mrd-ferrum-new-0",
            json!({"rules": [{"match": {"methods": ["GET"]}, "destination": {"upstream_id": "new"}}]}),
        ));
        k8s.plugin_configs.push(plugin_config(
            "istio-vs-mirror-ferrum-new-0",
            json!({"mirror_host": "new-mirror.internal", "mirror_port": 8080, "percentage": 100.0}),
        ));
        k8s.known_namespaces.push("k8s".to_string());

        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.proxies.iter().any(|proxy| proxy.id == "db-proxy"));
        assert!(
            merged
                .proxies
                .iter()
                .any(|proxy| proxy.id == "gwapi-route-ferrum-new-0")
        );
        assert!(
            merged
                .proxies
                .iter()
                .all(|proxy| proxy.id != "gwapi-route-ferrum-old-0")
        );
        assert!(
            merged
                .upstreams
                .iter()
                .all(|upstream| upstream.id != "gwapi-route-upstream-ferrum-old-0")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == "operator-rate-limit")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == "istio-vs-mrd-ferrum-new-0")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != "istio-vs-mrd-ferrum-old-0")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != "istio-vs-rt-ferrum-old-0")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == "istio-vs-mirror-ferrum-new-0")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .all(|plugin| plugin.id != "istio-vs-mirror-ferrum-old-0")
        );
        assert!(merged.known_namespaces.contains(&"db".to_string()));
        assert!(merged.known_namespaces.contains(&"k8s".to_string()));
    }

    #[test]
    fn merge_k8s_translation_preserves_operator_frontend_tls_when_k8s_has_none() {
        let active = GatewayConfig {
            frontend_tls_cert_path: Some("/etc/ferrum/operator.crt".to_string()),
            frontend_tls_key_path: Some("/etc/ferrum/operator.key".to_string()),
            frontend_tls_source_namespace: None,
            ..GatewayConfig::default()
        };
        let k8s = GatewayConfig::default();

        let merged = merge_k8s_translation(&active, &k8s, &BTreeSet::new());

        assert_eq!(
            merged.frontend_tls_cert_path.as_deref(),
            Some("/etc/ferrum/operator.crt")
        );
        assert_eq!(
            merged.frontend_tls_key_path.as_deref(),
            Some("/etc/ferrum/operator.key")
        );
        assert_eq!(merged.frontend_tls_source_namespace, None);
    }

    #[test]
    fn merge_k8s_translation_clears_stale_gateway_frontend_tls_when_k8s_has_none() {
        let active = GatewayConfig {
            frontend_tls_cert_path: Some("k8s://default/cert#tls.crt?sha256=old".to_string()),
            frontend_tls_key_path: Some("k8s://default/cert#tls.key?sha256=old".to_string()),
            frontend_tls_source_namespace: Some("default".to_string()),
            ..GatewayConfig::default()
        };
        let k8s = GatewayConfig::default();

        let merged = merge_k8s_translation(&active, &k8s, &BTreeSet::new());

        assert_eq!(merged.frontend_tls_cert_path, None);
        assert_eq!(merged.frontend_tls_key_path, None);
        assert_eq!(merged.frontend_tls_source_namespace, None);
    }

    #[test]
    fn merge_k8s_translation_replaces_operator_frontend_tls_when_k8s_supplies_gateway_tls() {
        let active = GatewayConfig {
            frontend_tls_cert_path: Some("/etc/ferrum/operator.crt".to_string()),
            frontend_tls_key_path: Some("/etc/ferrum/operator.key".to_string()),
            frontend_tls_source_namespace: None,
            ..GatewayConfig::default()
        };
        let k8s = GatewayConfig {
            frontend_tls_cert_path: Some("k8s://default/cert#tls.crt?sha256=new".to_string()),
            frontend_tls_key_path: Some("k8s://default/cert#tls.key?sha256=new".to_string()),
            frontend_tls_source_namespace: Some("default".to_string()),
            ..GatewayConfig::default()
        };

        let merged = merge_k8s_translation(&active, &k8s, &BTreeSet::new());

        assert_eq!(
            merged.frontend_tls_cert_path.as_deref(),
            Some("k8s://default/cert#tls.crt?sha256=new")
        );
        assert_eq!(
            merged.frontend_tls_key_path.as_deref(),
            Some("k8s://default/cert#tls.key?sha256=new")
        );
        assert_eq!(
            merged.frontend_tls_source_namespace.as_deref(),
            Some("default")
        );
    }

    #[test]
    fn merge_k8s_translation_preserves_namespace_scoped_gateway_frontend_tls() {
        let active = GatewayConfig {
            frontend_tls_cert_path: Some("/etc/ferrum/operator.crt".to_string()),
            frontend_tls_key_path: Some("/etc/ferrum/operator.key".to_string()),
            frontend_tls_source_namespace: None,
            ..GatewayConfig::default()
        };
        let k8s = GatewayConfig {
            frontend_tls_cert_path: Some("k8s://ns-a/cert#tls.crt?sha256=a".to_string()),
            frontend_tls_key_path: Some("k8s://ns-a/cert#tls.key?sha256=a".to_string()),
            frontend_tls_source_namespace: Some("ns-a".to_string()),
            frontend_tls_namespace_sources: vec![
                FrontendTlsNamespaceSource {
                    namespace: "ns-a".to_string(),
                    cert_path: "k8s://ns-a/cert#tls.crt?sha256=a".to_string(),
                    key_path: "k8s://ns-a/cert#tls.key?sha256=a".to_string(),
                },
                FrontendTlsNamespaceSource {
                    namespace: "ns-b".to_string(),
                    cert_path: "k8s://ns-b/cert#tls.crt?sha256=b".to_string(),
                    key_path: "k8s://ns-b/cert#tls.key?sha256=b".to_string(),
                },
            ],
            ..GatewayConfig::default()
        };

        let merged = merge_k8s_translation(&active, &k8s, &BTreeSet::new());

        assert_eq!(merged.frontend_tls_namespace_sources.len(), 2);
        assert!(
            merged
                .frontend_tls_namespace_sources
                .iter()
                .any(|source| source.namespace == "ns-a")
        );
        assert!(
            merged
                .frontend_tls_namespace_sources
                .iter()
                .any(|source| source.namespace == "ns-b")
        );
    }

    #[test]
    fn merge_k8s_translation_removes_stale_vs_l4_and_cors_resources() {
        // VirtualService L4 stream proxies (istio-vs-tls-/istio-vs-tcp-) and the
        // per-route cors plugin (istio-vs-cors-) must be cleaned up by the
        // managed-prefix retain. Otherwise a deleted/changed VirtualService
        // leaks its old stream proxy and the translator appends duplicate copies
        // on every later reconcile.
        let mut active = GatewayConfig::default();
        active
            .proxies
            .push(proxy("istio-vs-ferrum-secure-tls-0-0", "old-tls.internal"));
        active
            .proxies
            .push(proxy("istio-vs-ferrum-raw-tcp-0-0", "old-tcp.internal"));
        active.plugin_configs.push(plugin_config(
            "istio-vs-cors-istio-vs-ferrum-api-0",
            json!({"allowed_origins": ["https://old.example.com"]}),
        ));

        // VirtualService removed from the cluster → empty k8s overlay.
        let k8s = GatewayConfig::default();
        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(
            merged
                .proxies
                .iter()
                .all(|p| p.id != "istio-vs-ferrum-secure-tls-0-0"),
            "stale VS tls[] stream proxy must be removed on reconcile, got {:?}",
            merged.proxies.iter().map(|p| &p.id).collect::<Vec<_>>()
        );
        assert!(
            merged
                .proxies
                .iter()
                .all(|p| p.id != "istio-vs-ferrum-raw-tcp-0-0"),
            "stale VS tcp[] stream proxy must be removed on reconcile"
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .all(|p| p.id != "istio-vs-cors-istio-vs-ferrum-api-0"),
            "stale VS cors plugin must be removed on reconcile, got {:?}",
            merged
                .plugin_configs
                .iter()
                .map(|p| &p.id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_k8s_translation_preserves_existing_mesh_when_k8s_has_none() {
        let mut active = GatewayConfig {
            mesh: Some(Box::new(MeshConfig::default())),
            ..GatewayConfig::default()
        };
        active.mesh.as_mut().expect("mesh exists").services.push(
            crate::modes::mesh::config::MeshService {
                cluster_ips: Vec::new(),
                name: "stale".to_string(),
                namespace: "ferrum".to_string(),
                ports: Vec::new(),
                workloads: Vec::new(),
                protocol_overrides: std::collections::HashMap::new(),
            },
        );

        let k8s = GatewayConfig::default();

        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.mesh.is_some());
    }

    #[test]
    fn merge_k8s_translation_preserves_prefixed_operator_resources_outside_managed_namespaces() {
        let mut active = GatewayConfig::default();
        active
            .proxies
            .push(proxy("gwapi-route-operator-owned", "db.internal"));
        active.proxies[0].namespace = "ops".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-operator-owned",
            "db.internal",
        ));
        active.upstreams[0].namespace = "ops".to_string();
        active.plugin_configs.push(plugin_config(
            "istio-vs-mrd-operator-owned",
            json!({"rules": [{"match": {"methods": ["GET"]}, "destination": {"upstream_id": "operator"}}]}),
        ));
        active.plugin_configs[0].namespace = "ops".to_string();

        let k8s = GatewayConfig::default();
        let managed = BTreeSet::from(["ferrum".to_string()]);
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(
            merged
                .proxies
                .iter()
                .any(|proxy| proxy.id == "gwapi-route-operator-owned")
        );
        assert!(
            merged
                .upstreams
                .iter()
                .any(|upstream| upstream.id == "gwapi-route-upstream-operator-owned")
        );
        assert!(
            merged
                .plugin_configs
                .iter()
                .any(|plugin| plugin.id == "istio-vs-mrd-operator-owned")
        );
    }

    #[test]
    fn merge_k8s_translation_prunes_k8s_overlay_from_all_namespaces_when_watch_all() {
        let mut active = GatewayConfig::default();
        active
            .proxies
            .push(proxy("gwapi-route-default-old-0", "old.default.internal"));
        active.proxies[0].namespace = "default".to_string();
        active
            .proxies
            .push(proxy("gwapi-route-prod-old-0", "old.prod.internal"));
        active.proxies[1].namespace = "prod".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-default-old-0",
            "old.default.internal",
        ));
        active.upstreams[0].namespace = "default".to_string();
        active.upstreams.push(upstream(
            "gwapi-route-upstream-prod-old-0",
            "old.prod.internal",
        ));
        active.upstreams[1].namespace = "prod".to_string();
        active.plugin_configs.push(plugin_config(
            "istio-vs-fi-default-old-0",
            json!({"abort": {"percentage": 10.0, "status_code": 503}}),
        ));
        active.plugin_configs[0].namespace = "default".to_string();
        active.plugin_configs.push(plugin_config(
            "istio-vs-mrd-prod-old-0",
            json!({"rules": [{"match": {"methods": ["GET"]}, "destination": {"upstream_id": "old"}}]}),
        ));
        active.plugin_configs[1].namespace = "prod".to_string();
        active.plugin_configs.push(plugin_config(
            "istio-vs-rt-default-old-0",
            json!({"status_code": 404, "message": "unsupported Istio VirtualService match predicate"}),
        ));
        active.plugin_configs[2].namespace = "default".to_string();

        let k8s = GatewayConfig::default();
        let managed = BTreeSet::new();
        let merged = merge_k8s_translation(&active, &k8s, &managed);

        assert!(merged.proxies.is_empty());
        assert!(merged.upstreams.is_empty());
        assert!(merged.plugin_configs.is_empty());
    }

    fn gateway_selector_reconcile_objects(selector: Value) -> Vec<K8sObject> {
        let metadata = |name: &str, namespace: &str| K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        };
        let mut tenant = K8sObject {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
            metadata: metadata("tenant", ""),
            spec: json!({}),
            status: json!({}),
        };
        tenant
            .metadata
            .labels
            .insert("team".to_string(), "payments".to_string());
        vec![
            tenant,
            K8sObject {
                api_version: "gateway.networking.k8s.io/v1".to_string(),
                kind: "Gateway".to_string(),
                metadata: metadata("edge", "platform"),
                spec: json!({
                    "gatewayClassName": "ferrum",
                    "listeners": [{
                        "name": "web",
                        "port": 80,
                        "protocol": "HTTP",
                        "allowedRoutes": {
                            "namespaces": {
                                "from": "Selector",
                                "selector": selector
                            }
                        }
                    }]
                }),
                status: json!({}),
            },
            K8sObject {
                api_version: "gateway.networking.k8s.io/v1".to_string(),
                kind: "HTTPRoute".to_string(),
                metadata: metadata("payments", "tenant"),
                spec: json!({
                    "parentRefs": [{
                        "name": "edge",
                        "namespace": "platform",
                        "sectionName": "web"
                    }],
                    "rules": [{
                        "backendRefs": [{"name": "payments", "port": 8080}]
                    }]
                }),
                status: json!({}),
            },
        ]
    }

    fn gateway_selector_translation(objects: &[K8sObject]) -> K8sTranslation {
        let options = K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
        .with_source_namespaces(Vec::new());
        translate_with_skip_retries(objects, options, &ControllerMetrics::default())
            .expect("reconciliation translation")
            .0
    }

    #[test]
    fn reconcile_withdraws_invalid_selector_attachment_and_recovers_without_stale_state() {
        let valid_objects =
            gateway_selector_reconcile_objects(json!({"matchLabels": {"team": "payments"}}));
        let valid = gateway_selector_translation(&valid_objects);
        let managed = BTreeSet::new();
        let active = merge_k8s_translation(&GatewayConfig::default(), &valid.config, &managed);
        assert_eq!(active.proxies.len(), 1);

        let invalid_objects = gateway_selector_reconcile_objects(json!({
            "matchExpressions": [
                {"key": "team", "operator": "In", "values": ["payments"]},
                {"key": "security", "operator": "In", "values": []}
            ]
        }));
        let invalid = gateway_selector_translation(&invalid_objects);
        let withdrawn = merge_k8s_translation(&active, &invalid.config, &managed);
        assert!(
            withdrawn.proxies.is_empty(),
            "valid-to-invalid reload must remove the prior attachment"
        );

        let recovered = gateway_selector_translation(&valid_objects);
        let restored = merge_k8s_translation(&withdrawn, &recovered.config, &managed);
        assert_eq!(restored.proxies.len(), 1);

        let route_deleted = gateway_selector_translation(&valid_objects[..2]);
        let after_route_delete = merge_k8s_translation(&restored, &route_deleted.config, &managed);
        assert!(after_route_delete.proxies.is_empty());

        let gateway_deleted = gateway_selector_translation(&valid_objects[..1]);
        let after_gateway_delete =
            merge_k8s_translation(&restored, &gateway_deleted.config, &managed);
        assert!(after_gateway_delete.proxies.is_empty());
    }

    #[test]
    fn full_sync_interval_zero_is_clamped_before_timer_creation() {
        assert_eq!(full_sync_interval_duration(0), Duration::from_secs(1));
        assert_eq!(full_sync_interval_duration(300), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn stalled_status_patch_batch_releases_the_reconcile_loop() {
        let stalled = std::future::pending::<Result<(), ()>>();
        let result = await_status_patch_batch(stalled, Duration::from_millis(1)).await;

        assert!(
            result.is_err(),
            "a stalled Kubernetes status request must not retain the reconcile loop"
        );
    }

    #[test]
    fn debounce_deadline_refreshes_without_exceeding_hard_cap() {
        let start = tokio::time::Instant::now();
        let window = Duration::from_millis(100);
        let hard_cap = start + Duration::from_millis(250);

        assert_eq!(
            refresh_debounce_deadline(start + Duration::from_millis(50), window, hard_cap),
            start + Duration::from_millis(150)
        );
        assert_eq!(
            refresh_debounce_deadline(start + Duration::from_millis(200), window, hard_cap),
            hard_cap
        );
    }

    #[tokio::test]
    async fn initial_readiness_timeout_reconciles_available_state_for_never_ready_store() {
        let ar = ApiResource {
            group: "example.com".to_string(),
            version: "v1".to_string(),
            api_version: "example.com/v1".to_string(),
            kind: "Widget".to_string(),
            plural: "widgets".to_string(),
        };
        let writer = reflector::store::Writer::new(ar);
        let store = Arc::new(CrdResourceStore::new(
            "example.com/v1".to_string(),
            "Widget".to_string(),
            writer.as_reader(),
        ));

        let mut set = ResourceStoreSet::new();
        assert!(set.add_store(store));
        let store_set = Arc::new(tokio::sync::Mutex::new(set));
        let mut change_rx = {
            let set = store_set.lock().await;
            set.subscribe()
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let ready = wait_for_initial_store_readiness_with_timeout(
            Arc::clone(&store_set),
            &mut change_rx,
            &mut shutdown_rx,
            Duration::from_millis(5),
        )
        .await;

        assert!(
            ready,
            "timed-out readiness should continue with available stores"
        );
    }
}

fn translate_with_skip_retries(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    metrics: &ControllerMetrics,
) -> Option<(
    K8sTranslation,
    std::collections::HashMap<crate::config_sources::k8s::K8sResourceKey, K8sTranslateError>,
)> {
    let outcome = translate_k8s_objects_collecting_skips(objects, options);
    if let Some((_, ref errors)) = outcome {
        let skipped = errors.len() as u64;
        if skipped > 0 {
            metrics
                .errors
                .fetch_add(skipped, std::sync::atomic::Ordering::Relaxed);
            for error in errors.values() {
                log_skipped_resource(error);
            }
        }
    } else {
        metrics
            .errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        error!("K8s translation failed repeatedly on the same resource");
    }
    outcome
}

fn log_skipped_resource(error: &K8sTranslateError) {
    match error {
        K8sTranslateError::Unsupported(resource) => {
            warn!(
                kind = resource.kind,
                namespace = resource.namespace,
                name = resource.name,
                reason = resource.reason,
                "Unsupported K8s resource skipped"
            );
        }
        K8sTranslateError::InvalidResource {
            kind,
            namespace,
            name,
            message,
        } => {
            warn!(
                kind,
                namespace, name, message, "Invalid K8s resource, skipping"
            );
        }
    }
}

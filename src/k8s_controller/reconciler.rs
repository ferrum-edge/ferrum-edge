use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde_json::Value;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info, warn};

use crate::config::types::GatewayConfig;
use crate::config_sources::k8s::{
    K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects_with_filter,
};
use crate::grpc::cp_server::{CpGrpcServer, DpNodeRegistry};
use crate::grpc::mesh_registry::MeshNodeRegistry;
use crate::grpc::mesh_server::{MeshConfigBroadcast, MeshGrpcServer};
use crate::grpc::proto::ConfigUpdate;
use crate::identity::spiffe::TrustDomain;
use crate::k8s_controller::istio_status::{IstioStatusWriter, plan_istio_status_updates};
use crate::k8s_controller::metrics::ControllerMetrics;
use crate::k8s_controller::resource_store::ResourceStoreSet;
use crate::k8s_controller::status::{GatewayApiStatusWriter, plan_gateway_api_status_updates};
use crate::k8s_controller::watcher::namespaces_with_istio_root;

const INITIAL_STORE_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP: usize = 256;

pub struct ReconcilerConfig {
    pub namespace: String,
    pub trust_domain: String,
    pub cluster_domain: String,
    pub istio_root_namespace: String,
    pub watch_namespaces: Vec<String>,
    pub debounce_ms: u64,
    pub full_sync_interval_secs: u64,
    pub pod_discovery_enabled: bool,
}

pub struct ReconcileBroadcasters {
    pub update_tx: broadcast::Sender<ConfigUpdate>,
    pub dp_registry: Arc<DpNodeRegistry>,
    pub mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    pub mesh_registry: Arc<MeshNodeRegistry>,
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
    broadcasters: ReconcileBroadcasters,
    reconciler_config: ReconcilerConfig,
    gateway_status_writer: Option<GatewayApiStatusWriter>,
    istio_status_writer: Option<IstioStatusWriter>,
    metrics: Arc<ControllerMetrics>,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    // Funnel the loop through a named `async fn` so the spawned future has a
    // concrete type signature (no anonymous future generated from an
    // `async move { ... }`). The previous inline form tripped a rustc HRTB
    // limitation on `tokio::spawn`'s `Send + 'static` bound for the
    // `&Arc<tokio::sync::Mutex<ResourceStoreSet>>` borrows held across the
    // `do_reconcile(...).await` calls.
    tokio::spawn(run_reconcile_loop(
        store_set,
        config_arc,
        broadcasters,
        reconciler_config,
        gateway_status_writer,
        istio_status_writer,
        metrics,
        shutdown,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_reconcile_loop(
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    config_arc: Arc<ArcSwap<GatewayConfig>>,
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
            update_tx: broadcasters.update_tx.clone(),
            dp_registry: Arc::clone(&broadcasters.dp_registry),
            mesh_update_tx: broadcasters.mesh_update_tx.clone(),
            mesh_registry: Arc::clone(&broadcasters.mesh_registry),
            namespace: reconciler_config.namespace.clone(),
            cluster_domain: reconciler_config.cluster_domain.clone(),
            istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
            watch_namespaces: reconciler_config.watch_namespaces.clone(),
            trust_domain: trust_domain.clone(),
            pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
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
                        update_tx: broadcasters.update_tx.clone(),
                        dp_registry: Arc::clone(&broadcasters.dp_registry),
                        mesh_update_tx: broadcasters.mesh_update_tx.clone(),
                        mesh_registry: Arc::clone(&broadcasters.mesh_registry),
                        namespace: reconciler_config.namespace.clone(),
                        cluster_domain: reconciler_config.cluster_domain.clone(),
                        istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
                        watch_namespaces: reconciler_config.watch_namespaces.clone(),
                        trust_domain: trust_domain.clone(),
                        pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
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
                        update_tx: broadcasters.update_tx.clone(),
                        dp_registry: Arc::clone(&broadcasters.dp_registry),
                        mesh_update_tx: broadcasters.mesh_update_tx.clone(),
                        mesh_registry: Arc::clone(&broadcasters.mesh_registry),
                        namespace: reconciler_config.namespace.clone(),
                        cluster_domain: reconciler_config.cluster_domain.clone(),
                        istio_root_namespace: reconciler_config.istio_root_namespace.clone(),
                        watch_namespaces: reconciler_config.watch_namespaces.clone(),
                        trust_domain: trust_domain.clone(),
                        pod_discovery_enabled: reconciler_config.pod_discovery_enabled,
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
    update_tx: broadcast::Sender<ConfigUpdate>,
    dp_registry: Arc<DpNodeRegistry>,
    mesh_update_tx: broadcast::Sender<MeshConfigBroadcast>,
    mesh_registry: Arc<MeshNodeRegistry>,
    namespace: String,
    cluster_domain: String,
    istio_root_namespace: String,
    watch_namespaces: Vec<String>,
    trust_domain: TrustDomain,
    pod_discovery_enabled: bool,
    gateway_status_writer: Option<GatewayApiStatusWriter>,
    /// T2-B: Istio CRD status sub-resource patcher. `None` when the
    /// controller couldn't be built (no Istio CRD watching, or the
    /// kube client isn't available). The reconciler short-circuits to
    /// a no-op when None — every other code path stays unchanged.
    istio_status_writer: Option<IstioStatusWriter>,
    metrics: Arc<ControllerMetrics>,
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
        .with_source_namespaces(source_namespaces)
        .with_pod_discovery_enabled(ctx.pod_discovery_enabled);
    let Some(translation) = translate_with_skip_retries(&objects, options.clone(), &ctx.metrics)
    else {
        return;
    };

    for warning in &translation.warnings {
        warn!(warning, "K8s translation warning");
    }

    let managed_namespaces = managed_k8s_namespaces(
        &ctx.namespace,
        &ctx.watch_namespaces,
        &translation.config.known_namespaces,
    );
    let Some(new_config) =
        swap_merged_k8s_translation(&ctx.config_arc, &translation.config, &managed_namespaces)
    else {
        debug!("No config changes detected, skipping swap");
        // Owned `Vec<...>` parameters keep the patch futures Send across
        // `tokio::spawn`'s HRTB analysis — `&[T]` parameters previously
        // tripped the same "Send not general enough" error as the
        // `&Mutex<...>` borrow above. But the helpers immediately return
        // when their writer is `None`, so gate the calls on the writer
        // existing before paying for the deep-clone of `objects`
        // (`K8sObject` carries serde-cloned `spec`/`status` JSON) or for
        // `options` / `route_conflicts`. Deployments that don't watch
        // Gateway API / Istio CRDs (the default) get zero per-reconcile
        // clone cost.
        run_status_patchers(
            ctx.gateway_status_writer,
            ctx.istio_status_writer,
            &objects,
            &options,
            Some(&translation.route_conflicts),
        )
        .await;
        let elapsed = start.elapsed();
        ctx.metrics.last_reconcile_duration_ms.store(
            elapsed.as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return;
    };

    // Notify DPs and mesh subscribers of the config change.
    CpGrpcServer::broadcast_update_with_registry(&ctx.update_tx, &new_config, &ctx.dp_registry);
    MeshGrpcServer::broadcast_full_with_registry(
        &ctx.mesh_update_tx,
        new_config.clone(),
        &ctx.mesh_registry,
    );
    // Same clone-elision contract as the no-change branch above; see the
    // comment over `run_status_patchers` there.
    run_status_patchers(
        ctx.gateway_status_writer,
        ctx.istio_status_writer,
        &objects,
        &options,
        Some(&translation.route_conflicts),
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

/// Dispatch to whichever status patchers are configured, paying the
/// `objects` / `options` / `route_conflicts` clone cost only for the writers
/// that actually exist. Callers in `do_reconcile` previously always cloned —
/// a regression in deployments that don't watch Gateway API or Istio CRDs
/// (the default), since `K8sObject` carries serde-cloned `spec`/`status`
/// JSON and the clone is O(snapshot size) per reconcile. Both writers are
/// taken by value so they can be moved into the helper futures (required
/// for `tokio::spawn`'s HRTB Send check — see the `Send is not general
/// enough` history in `spawn_reconcile_loop`).
async fn run_status_patchers(
    gateway_writer: Option<GatewayApiStatusWriter>,
    istio_writer: Option<IstioStatusWriter>,
    objects: &[K8sObject],
    options: &K8sTranslationOptions,
    route_conflicts: Option<&[crate::config_sources::k8s::GatewayApiRouteConflict]>,
) {
    if let Some(writer) = gateway_writer {
        patch_gateway_api_statuses(
            writer,
            objects.to_vec(),
            options.clone(),
            route_conflicts.map(<[_]>::to_vec).unwrap_or_default(),
        )
        .await;
    }
    if let Some(writer) = istio_writer {
        patch_istio_statuses(writer, objects.to_vec(), options.clone()).await;
    }
}

async fn patch_gateway_api_statuses(
    writer: GatewayApiStatusWriter,
    objects: Vec<K8sObject>,
    options: K8sTranslationOptions,
    route_conflicts: Vec<crate::config_sources::k8s::GatewayApiRouteConflict>,
) {
    let mut updates = plan_gateway_api_status_updates(&objects, options, &route_conflicts);
    if updates.is_empty() {
        return;
    }
    if updates.len() > GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP {
        warn!(
            updates = updates.len(),
            cap = GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP,
            "Capping Gateway API status updates for this reconcile round"
        );
        updates.truncate(GATEWAY_API_STATUS_UPDATES_PER_RECONCILE_CAP);
    }
    let updates_len = updates.len();
    if let Err(error) = writer.patch_updates(updates).await {
        warn!(
            error = %error,
            updates = updates_len,
            "Failed to patch Gateway API status"
        );
    }
}

/// T2-B: emit `status.conditions[]` patches for the Istio CRDs supported
/// by [`plan_istio_status_updates`]. No-op when the writer wasn't built
/// (Istio CRD watching is off, or kube client unavailable) or when the
/// plan is empty (no supported Istio CRDs in the snapshot). Failures
/// are logged and never abort reconcile.
async fn patch_istio_statuses(
    writer: IstioStatusWriter,
    objects: Vec<K8sObject>,
    options: K8sTranslationOptions,
) {
    let updates = plan_istio_status_updates(&objects, options);
    if updates.is_empty() {
        return;
    }
    let updates_len = updates.len();
    if let Err(error) = writer.patch_updates(updates).await {
        warn!(
            error = %error,
            updates = updates_len,
            "Failed to patch Istio status (CRD may not have a status subresource)"
        );
    }
}

fn swap_merged_k8s_translation(
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

fn merge_k8s_translation(
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

    let mut namespaces: BTreeSet<String> = merged.known_namespaces.iter().cloned().collect();
    namespaces.extend(k8s_config.known_namespaces.iter().cloned());
    merged.known_namespaces = namespaces.into_iter().collect();

    if k8s_config.mesh.is_some() {
        merged.mesh = k8s_config.mesh.clone();
    }

    merged.normalize_fields();
    merged
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
    use crate::config::types::{PluginConfig, PluginScope, Proxy, Upstream};
    use crate::identity::spiffe::SpiffeId;
    use crate::k8s_controller::resource_store::CrdResourceStore;
    use crate::modes::mesh::config::{
        MeshConfig, MeshService, Workload, WorkloadRef, WorkloadSelector,
    };
    use chrono::{Duration as ChronoDuration, Utc};
    use kube::api::ApiResource;
    use kube::runtime::reflector;
    use serde_json::json;
    use std::collections::HashMap;

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

    #[test]
    fn full_sync_interval_zero_is_clamped_before_timer_creation() {
        assert_eq!(full_sync_interval_duration(0), Duration::from_secs(1));
        assert_eq!(full_sync_interval_duration(300), Duration::from_secs(300));
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct K8sResourceKey {
    kind: String,
    namespace: String,
    name: String,
}

impl K8sResourceKey {
    fn from_object(object: &K8sObject) -> Self {
        Self {
            kind: object.kind.clone(),
            namespace: object.metadata.namespace.clone(),
            name: object.metadata.name.clone(),
        }
    }

    fn from_error(error: &K8sTranslateError) -> Self {
        match error {
            K8sTranslateError::Unsupported(resource) => Self {
                kind: resource.kind.clone(),
                namespace: resource.namespace.clone(),
                name: resource.name.clone(),
            },
            K8sTranslateError::InvalidResource {
                kind,
                namespace,
                name,
                ..
            } => Self {
                kind: kind.clone(),
                namespace: namespace.clone(),
                name: name.clone(),
            },
        }
    }
}

fn translate_with_skip_retries(
    objects: &[K8sObject],
    options: K8sTranslationOptions,
    metrics: &ControllerMetrics,
) -> Option<K8sTranslation> {
    let mut skipped = std::collections::HashSet::new();

    loop {
        let translation = translate_k8s_objects_with_filter(objects, options.clone(), |object| {
            !skipped.contains(&K8sResourceKey::from_object(object))
        });

        match translation {
            Ok(translation) => return Some(translation),
            Err(error) => {
                metrics
                    .errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log_skipped_resource(&error);

                let key = K8sResourceKey::from_error(&error);
                if !skipped.insert(key) {
                    error!(error = %error, "K8s translation failed repeatedly on the same resource");
                    return None;
                }
            }
        }
    }
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

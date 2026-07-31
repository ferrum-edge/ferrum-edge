use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, TryStreamExt};
use kube::api::{ApiResource, DynamicObject};
use kube::discovery;
use kube::runtime::reflector;
use kube::runtime::watcher;
use kube::{Api, Client};
use tracing::{debug, error, info, warn};

use super::metrics::ControllerMetrics;
use super::resource_store::{CrdResourceStore, ResourceChangeNotifier, ResourceStoreSet};
use super::{ControllerTaskRegistry, REPROBE_WATCHER_LABEL};

pub struct CrdSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub namespaced: bool,
}

pub struct CoreResourceSpec {
    pub group: &'static str,
    pub version: &'static str,
    pub kind: &'static str,
    pub plural: &'static str,
    pub namespaced: bool,
    /// Optional Kubernetes field selector applied to the watcher. Used to
    /// scope a namespaced watcher to a single named object (e.g.,
    /// `metadata.name=istio`) so unrelated objects in that namespace don't
    /// trigger no-op reconciliations. `None` watches every object in scope.
    pub field_selector: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub struct WatcherSelection {
    pub watch_istio: bool,
    pub watch_gateway_api: bool,
    pub watch_core: bool,
    pub watch_gateway_api_data_plane_service: bool,
    pub watch_node_locality: bool,
    pub watch_mesh_config: bool,
}

pub const ISTIO_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "AuthorizationPolicy",
        plural: "authorizationpolicies",
        namespaced: true,
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "PeerAuthentication",
        plural: "peerauthentications",
        namespaced: true,
    },
    CrdSpec {
        group: "security.istio.io",
        version: "v1",
        kind: "RequestAuthentication",
        plural: "requestauthentications",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "VirtualService",
        plural: "virtualservices",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "DestinationRule",
        plural: "destinationrules",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "ServiceEntry",
        plural: "serviceentries",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "WorkloadEntry",
        plural: "workloadentries",
        namespaced: true,
    },
    CrdSpec {
        group: "networking.istio.io",
        version: "v1",
        kind: "Sidecar",
        plural: "sidecars",
        namespaced: true,
    },
    CrdSpec {
        group: "telemetry.istio.io",
        version: "v1",
        kind: "Telemetry",
        plural: "telemetries",
        namespaced: true,
    },
    // Served as networking.istio.io/v1beta1 only (Istio has no v1 ProxyConfig).
    // Discovered at runtime via find_crd_resource; absent clusters skip
    // registration and the reprobe task restarts the watcher once installed —
    // same last-known-good / relist path as every other ISTIO_CRDS entry.
    CrdSpec {
        group: "networking.istio.io",
        version: "v1beta1",
        kind: "ProxyConfig",
        plural: "proxyconfigs",
        namespaced: true,
    },
];

pub const GATEWAY_API_CRDS: &[CrdSpec] = &[
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "GatewayClass",
        plural: "gatewayclasses",
        namespaced: false,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "GatewayClass",
        plural: "gatewayclasses",
        namespaced: false,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "Gateway",
        plural: "gateways",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "Gateway",
        plural: "gateways",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "HTTPRoute",
        plural: "httproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "HTTPRoute",
        plural: "httproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "GRPCRoute",
        plural: "grpcroutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TLSRoute",
        plural: "tlsroutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1alpha2",
        kind: "TCPRoute",
        plural: "tcproutes",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1",
        kind: "ReferenceGrant",
        plural: "referencegrants",
        namespaced: true,
    },
    CrdSpec {
        group: "gateway.networking.k8s.io",
        version: "v1beta1",
        kind: "ReferenceGrant",
        plural: "referencegrants",
        namespaced: true,
    },
];

pub const K8S_CORE_RESOURCES: &[CoreResourceSpec] = &[
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Pod",
        plural: "pods",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Service",
        plural: "services",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "discovery.k8s.io",
        version: "v1",
        kind: "EndpointSlice",
        plural: "endpointslices",
        namespaced: true,
        field_selector: None,
    },
];

pub const K8S_NAMESPACE_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "Namespace",
    plural: "namespaces",
    namespaced: false,
    field_selector: None,
}];

pub const GATEWAY_API_CORE_RESOURCES: &[CoreResourceSpec] = &[
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Secret",
        plural: "secrets",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "",
        version: "v1",
        kind: "Service",
        plural: "services",
        namespaced: true,
        field_selector: None,
    },
    CoreResourceSpec {
        group: "discovery.k8s.io",
        version: "v1",
        kind: "EndpointSlice",
        plural: "endpointslices",
        namespaced: true,
        field_selector: None,
    },
];

pub const GATEWAY_API_DATA_PLANE_STATUS_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "discovery.k8s.io",
    version: "v1",
    kind: "EndpointSlice",
    plural: "endpointslices",
    namespaced: true,
    field_selector: None,
}];

pub const K8S_NODE_LOCALITY_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "Node",
    plural: "nodes",
    namespaced: false,
    field_selector: None,
}];

// The only ConfigMap Ferrum consumes from the istio root namespace is the
// `istio` MeshConfig. Scoping the watch with a name field selector means
// unrelated ConfigMap churn (CA root cert, sidecar injector, dashboards, ...)
// does not trigger no-op reconciliations.
pub const ISTIO_MESH_CONFIG_RESOURCES: &[CoreResourceSpec] = &[CoreResourceSpec {
    group: "",
    version: "v1",
    kind: "ConfigMap",
    plural: "configmaps",
    namespaced: true,
    field_selector: Some("metadata.name=istio"),
}];

// Node labels can enrich workloads with topology.kubernetes.io/{region,zone},
// but locality is optional. Keep Node out of the unconditional pod-discovery
// watcher set so namespaced discovery does not require cluster-scoped RBAC.
fn selected_core_resources(watch_node_locality: bool) -> Vec<&'static CoreResourceSpec> {
    let mut resources: Vec<&'static CoreResourceSpec> = K8S_CORE_RESOURCES.iter().collect();
    if watch_node_locality {
        resources.extend(K8S_NODE_LOCALITY_RESOURCES);
    }
    resources
}

fn watch_scopes(namespaces: &[String]) -> Vec<Option<String>> {
    if namespaces.is_empty() {
        return vec![None];
    }
    namespaces.iter().cloned().map(Some).collect()
}

fn watch_scope_label(scope: Option<&str>) -> String {
    match scope {
        Some(namespace) => format!("namespace:{namespace}"),
        None => "all".to_string(),
    }
}

pub(crate) fn namespaces_with_istio_root(
    namespaces: &[String],
    istio_root_namespace: &str,
) -> Vec<String> {
    if namespaces.is_empty() {
        return Vec::new();
    }

    let mut merged = namespaces.to_vec();
    if !istio_root_namespace.is_empty()
        && !merged
            .iter()
            .any(|namespace| namespace == istio_root_namespace)
    {
        merged.push(istio_root_namespace.to_string());
    }
    merged
}

fn crd_watch_namespaces(
    crd: &CrdSpec,
    namespaces: &[String],
    istio_root_namespace: &str,
) -> Vec<String> {
    if crd.group.ends_with(".istio.io") {
        namespaces_with_istio_root(namespaces, istio_root_namespace)
    } else {
        namespaces.to_vec()
    }
}

fn pod_discovery_core_watch_namespaces(
    resource: &CoreResourceSpec,
    namespaces: &[String],
    node_waypoint_namespace: &str,
) -> Vec<String> {
    if resource.kind != "Pod" || namespaces.is_empty() || node_waypoint_namespace.is_empty() {
        return namespaces.to_vec();
    }
    let mut merged = namespaces.to_vec();
    if !merged
        .iter()
        .any(|namespace| namespace == node_waypoint_namespace)
    {
        merged.push(node_waypoint_namespace.to_string());
    }
    merged
}

fn gateway_api_data_plane_status_watch_namespaces(
    namespaces: &[String],
    data_plane_service_namespace: Option<&str>,
) -> Vec<String> {
    if namespaces.is_empty() {
        return Vec::new();
    }
    let mut status_namespaces = namespaces.to_vec();
    if let Some(namespace) = data_plane_service_namespace
        && !namespace.is_empty()
        && !status_namespaces
            .iter()
            .any(|existing| existing == namespace)
    {
        status_namespaces.push(namespace.to_string());
    }
    status_namespaces
}

fn build_apis_for_resource(
    client: &Client,
    ar: &ApiResource,
    namespaces: &[String],
    namespaced: bool,
) -> Vec<(Api<DynamicObject>, ApiResource, String)> {
    let scopes = if namespaced {
        watch_scopes(namespaces)
    } else {
        vec![None]
    };
    scopes
        .into_iter()
        .map(|scope| {
            let api = match scope.as_deref() {
                Some(namespace) => Api::namespaced_with(client.clone(), namespace, ar),
                None => Api::all_with(client.clone(), ar),
            };
            let scope_label = watch_scope_label(scope.as_deref());
            (api, ar.clone(), scope_label)
        })
        .collect()
}

fn find_crd_resource(api_group: &discovery::ApiGroup, crd: &CrdSpec) -> Option<ApiResource> {
    api_group
        .versioned_resources(crd.version)
        .into_iter()
        .map(|(ar, _caps)| ar)
        .find(|ar| ar.kind == crd.kind && ar.plural == crd.plural)
}

/// Identity of one watched `(apiVersion, kind, scope)` triple, plus the static
/// label used when logging about it. Every field is compile-time-derived or a
/// namespace from configuration — never cluster object contents.
#[derive(Clone)]
pub(crate) struct WatchTarget {
    pub api_version: String,
    pub kind: String,
    pub scope: String,
    pub resource: ApiResource,
    /// `"CRD watcher"` or `"K8s core watcher"`, so one shared task body keeps
    /// the two families' log wording.
    pub watcher_label: &'static str,
}

/// Documented opt-out for `FERRUM_K8S_WATCH_IDLE_RELIST_SECS`: no idle relist.
pub const K8S_WATCH_IDLE_RELIST_SECS_MIN: u64 = 0;

/// Upper bound for `FERRUM_K8S_WATCH_IDLE_RELIST_SECS` (24 hours).
///
/// The parser clamps to this, which is what keeps every duration derived from
/// the window inside its own range: [`RelistPolicy::readiness_timeout`]
/// multiplies it by two, the watcher adds it to a [`tokio::time::Instant`], and
/// the jitter converts a quarter of it to milliseconds. An unbounded `u64` from
/// the environment would expose all three to an overflow panic at startup.
pub const K8S_WATCH_IDLE_RELIST_SECS_MAX: u64 = 86_400;

/// Default idle-relist window.
///
/// Bookmarks are consumed inside kube-rs, so a healthy but quiet scope is
/// indistinguishable from a stalled one and *will* relist on every window. A
/// controller watching three namespaces runs on the order of 39 scope watchers
/// (about 69 with Istio and core resources enabled), and the count grows with
/// the namespace count — so the window is a per-scope full-list rate against
/// the API server, not just a recovery bound. Five minutes keeps that load
/// modest while still bounding staleness well below an operator's patience.
pub const K8S_WATCH_IDLE_RELIST_SECS_DEFAULT: u64 = 300;

/// When a watcher rebuilds its reflector from an authoritative list.
///
/// A kube-rs `watcher` surfaces an error only when the watch *fails*. A watch
/// that stops delivering without failing — a silently stalled or black-holed
/// connection, where no FIN, RST, or HTTP/2 GOAWAY ever arrives — leaves the
/// task alive, the reflector store serving whatever it held when delivery
/// stopped, and objects created in Kubernetes from then on absent from every
/// reconcile snapshot. `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` does not help — it
/// re-reconciles from the same stale store — so this is the only bound on that
/// blindness. The recovery is deliberately cause-agnostic: it is driven by the
/// observable symptom (no event for a whole window), not by any particular
/// diagnosis of where the stream was lost.
#[derive(Clone, Copy)]
pub(crate) struct RelistPolicy {
    /// Rebuild the reflector when the scope has produced no event for this
    /// long. `None` disables idle relisting
    /// (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS=0`).
    ///
    /// Watch bookmarks are consumed inside kube-rs and never reach us, so
    /// "no event" cannot distinguish a quiet scope from a dead one. The window
    /// is therefore a bound on *staleness*, and a busy scope never pays it.
    pub idle_window: Option<Duration>,
    /// How long a replacement generation may take to finish its initial list
    /// before it is abandoned and another one is started. Without this, a
    /// replacement that inherited the same stalled path would leave the scope
    /// pinned to its last-known-good state forever.
    pub readiness_timeout: Duration,
}

impl RelistPolicy {
    pub(crate) fn from_idle_secs(idle_relist_secs: u64) -> Self {
        // The parser clamps to `K8S_WATCH_IDLE_RELIST_SECS_MAX`; clamp again
        // here so a direct caller (tests, future call sites) can never build a
        // window whose doubling below would overflow.
        let idle_relist_secs = idle_relist_secs.min(K8S_WATCH_IDLE_RELIST_SECS_MAX);
        let idle_window = (idle_relist_secs > 0).then(|| Duration::from_secs(idle_relist_secs));
        // Two idle windows, floored, so a replacement gets a generous but
        // bounded chance to list before it is retried.
        let readiness_timeout = idle_window
            .map(|window| (window * 2).max(MIN_RELIST_READINESS_TIMEOUT))
            .unwrap_or(MIN_RELIST_READINESS_TIMEOUT);
        Self {
            idle_window,
            readiness_timeout,
        }
    }
}

/// Floor for [`RelistPolicy::readiness_timeout`]; also the value used when idle
/// relisting is disabled (where it is unreachable, since no replacement
/// generation is ever started).
const MIN_RELIST_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// One random seed per controller process, folded into every scope's jitter.
///
/// Without it the offset would be a pure function of the watched triple, so
/// every control-plane replica would compute the *same* offset for the same
/// scope and issue its full list in the same instant — the thundering herd the
/// jitter exists to prevent, just moved from "all scopes on one replica" to
/// "one scope on all replicas". `RandomState` is the standard library's own
/// per-instance random seed, so this needs no new dependency and no RNG crate.
fn process_relist_jitter_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};

    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(0);
        hasher.finish()
    })
}

/// Bounded per-scope offset added to the idle deadline so that watchers which
/// went quiet together (typically all of them, right after startup) do not
/// relist in the same tick. Spreads over the first quarter of the window.
///
/// Stable *within* a process — a scope's deadline must not wander between
/// iterations — but seeded per process by [`process_relist_jitter_seed`], so
/// replicas of the same control plane stagger independently. Callers must
/// therefore never assume a particular offset; only that it is in
/// `0..window/4`.
pub(crate) fn idle_relist_jitter(
    api_version: &str,
    kind: &str,
    scope: &str,
    idle_window: Option<Duration>,
) -> Duration {
    let Some(window) = idle_window else {
        return Duration::ZERO;
    };
    // The window is clamped to `K8S_WATCH_IDLE_RELIST_SECS_MAX`, so a quarter
    // of it in milliseconds is far inside `u64`.
    let spread = (window.as_millis() / 4) as u64;
    if spread == 0 {
        return Duration::ZERO;
    }
    // FNV-1a over the watched triple, offset-basis-mixed with the process seed:
    // distinct scopes land on distinct offsets, distinct processes on distinct
    // sets of offsets.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ process_relist_jitter_seed();
    for part in [
        api_version.as_bytes(),
        "|".as_bytes(),
        kind.as_bytes(),
        "|".as_bytes(),
        scope.as_bytes(),
    ] {
        for byte in part {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    }
    Duration::from_millis(hash % spread)
}

async fn sleep_until_or_pending(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Drive one watch scope for the lifetime of the controller task, rebuilding
/// its reflector whenever the scope goes idle for longer than the policy allows.
///
/// Generation 0 uses `initial_writer`, whose store the caller has already
/// registered in `store_set` (so duplicate-start detection and the reconciler's
/// initial readiness wait both see it synchronously). Later generations build
/// their own writer/store pair and are swapped in **make-before-break**: the
/// previous store stays registered, serving its last-known-good objects, until
/// the replacement reports `InitDone`. There is no window in which the scope
/// contributes nothing, so a relist can never be mistaken for a mass deletion.
///
/// Ownership is unchanged: this is one task per scope for the process lifetime.
/// Relisting spawns nothing, registers nothing new with the task registry, and
/// leaves the stream-end contract (deregister the scope, return, let the CRD
/// reprobe loop restart it) exactly as it was.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_watcher_generations<S, F>(
    target: WatchTarget,
    initial_writer: reflector::store::Writer<DynamicObject>,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    change_notifier: ResourceChangeNotifier,
    policy: RelistPolicy,
    metrics: Arc<ControllerMetrics>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut make_stream: F,
) where
    F: FnMut(reflector::store::Writer<DynamicObject>) -> S,
    S: Stream<Item = Result<watcher::Event<DynamicObject>, watcher::Error>>,
{
    let jitter = idle_relist_jitter(
        &target.api_version,
        &target.kind,
        &target.scope,
        policy.idle_window,
    );
    let mut initial_writer = Some(initial_writer);

    loop {
        // `pending` is `Some` only for a replacement generation, i.e. exactly
        // while an older store is still the one registered for this scope.
        let (writer, mut pending) = match initial_writer.take() {
            Some(writer) => (writer, None),
            None => {
                let writer = reflector::store::Writer::new(target.resource.clone());
                let store = Arc::new(CrdResourceStore::new_scoped(
                    target.api_version.clone(),
                    target.kind.clone(),
                    target.scope.clone(),
                    writer.as_reader(),
                ));
                (writer, Some(store))
            }
        };

        let stream = make_stream(writer);
        tokio::pin!(stream);

        let generation_start = tokio::time::Instant::now();
        let mut last_event = generation_start;

        loop {
            let deadline = match pending.as_ref() {
                Some(_) => Some(generation_start + policy.readiness_timeout),
                None => policy
                    .idle_window
                    .map(|window| last_event + window + jitter),
            };

            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!(
                            kind = %target.kind,
                            scope = %target.scope,
                            "Watcher shutting down"
                        );
                        return;
                    }
                }
                _ = sleep_until_or_pending(deadline) => {
                    metrics
                        .watch_idle_relists
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if pending.is_some() {
                        warn!(
                            kind = %target.kind,
                            api_version = %target.api_version,
                            scope = %target.scope,
                            timeout_secs = policy.readiness_timeout.as_secs_f64(),
                            "Replacement {} did not finish its initial list in time; \
                             retrying (the previous store keeps serving meanwhile)",
                            target.watcher_label
                        );
                    } else {
                        debug!(
                            kind = %target.kind,
                            api_version = %target.api_version,
                            scope = %target.scope,
                            "{} idle past the relist window; rebuilding its reflector from \
                             an authoritative list",
                            target.watcher_label
                        );
                    }
                    break;
                }
                item = stream.try_next() => {
                    match item {
                        Ok(Some(event)) => {
                            last_event = tokio::time::Instant::now();
                            let Some(store) = pending.take() else {
                                change_notifier.notify_change();
                                continue;
                            };
                            if !matches!(event, watcher::Event::InitDone) {
                                // Still listing. The replacement's objects are
                                // buffered inside its writer and become visible
                                // atomically at `InitDone`.
                                pending = Some(store);
                                continue;
                            }
                            let replaced = {
                                let mut set = store_set.lock().await;
                                if set.replace_store_for_scope(Arc::clone(&store)) {
                                    true
                                } else {
                                    // The scope was deregistered while this
                                    // generation was listing. Re-register rather
                                    // than leave the watcher feeding a store the
                                    // reconciler cannot see.
                                    set.add_store(store)
                                }
                            };
                            debug!(
                                kind = %target.kind,
                                api_version = %target.api_version,
                                scope = %target.scope,
                                replaced,
                                "Relisted {} store is live",
                                target.watcher_label
                            );
                        }
                        Ok(None) => {
                            error!(
                                kind = %target.kind,
                                api_version = %target.api_version,
                                scope = %target.scope,
                                "{} stream ended unexpectedly; \
                                 removing stale store so reprobe will restart",
                                target.watcher_label
                            );
                            let removed = store_set
                                .lock()
                                .await
                                .remove_store_for_scope(
                                    &target.api_version,
                                    &target.kind,
                                    &target.scope,
                                );
                            if !removed {
                                debug!(
                                    kind = %target.kind,
                                    api_version = %target.api_version,
                                    scope = %target.scope,
                                    "Stale store already absent at stream end"
                                );
                            }
                            return;
                        }
                        Err(e) => {
                            error!(
                                kind = %target.kind,
                                scope = %target.scope,
                                error = %e,
                                "Watch error, kube-rs will retry with backoff"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Start every selected CRD and core-resource watcher, registering each one
/// with `registry` so the control plane owns it (#3220).
///
/// Returns the number of watchers started. Watcher tasks are never handed back
/// as bare `JoinHandle`s: a dropped handle detaches the task, and the CRD
/// reprobe loop calls this function too, so its replacement watchers must land
/// in the same owned set as the startup ones.
///
/// `task_label` is the registry label prefix (`crd-watcher` at startup,
/// `crd-watcher-reprobe` from the reprobe loop); the per-watcher suffix is the
/// static Kubernetes kind, never cluster object data.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_crd_watchers(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    selection: WatcherSelection,
    namespaces: Vec<String>,
    node_waypoint_namespace: String,
    istio_root_namespace: String,
    gateway_api_data_plane_service_namespace: Option<String>,
    relist_policy: RelistPolicy,
    metrics: Arc<ControllerMetrics>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    registry: &ControllerTaskRegistry,
    task_label: &str,
) -> usize {
    let mut started = 0usize;

    let mut crd_specs: Vec<&CrdSpec> = Vec::new();
    if selection.watch_istio {
        crd_specs.extend(ISTIO_CRDS);
    }
    if selection.watch_gateway_api {
        crd_specs.extend(GATEWAY_API_CRDS);
    }

    // Deduplicate discovery by group, but gate watcher registration by the
    // exact served kind/version below. A cluster can expose a group without
    // serving every optional CRD version Ferrum knows about.
    let mut checked_groups = HashSet::new();
    let mut installed_groups: HashMap<&'static str, discovery::ApiGroup> = HashMap::new();

    for crd in &crd_specs {
        if !checked_groups.insert(crd.group) {
            continue;
        }
        match discovery::oneshot::group(&client, crd.group).await {
            Ok(api_group) => {
                installed_groups.insert(crd.group, api_group);
                info!(group = crd.group, "CRD group detected");
            }
            Err(e) => {
                warn!(
                    group = crd.group,
                    error = %e,
                    "CRD group not installed, its resources will not be watched. \
                     Install the CRDs and restart the controller to enable."
                );
            }
        }
    }

    for crd in crd_specs {
        let Some(api_group) = installed_groups.get(crd.group) else {
            continue;
        };
        let api_version = format!("{}/{}", crd.group, crd.version);
        let kind = crd.kind.to_string();

        let Some(ar) = find_crd_resource(api_group, crd) else {
            debug!(
                group = crd.group,
                version = crd.version,
                kind = crd.kind,
                "CRD kind/version not served, skipping watcher registration"
            );
            continue;
        };

        let crd_namespaces = crd_watch_namespaces(crd, &namespaces, &istio_root_namespace);
        for (api, ar, scope) in
            build_apis_for_resource(&client, &ar, &crd_namespaces, crd.namespaced)
        {
            if store_set
                .lock()
                .await
                .has_store_for_scope(&api_version, &kind, &scope)
            {
                debug!(
                    kind = %kind,
                    api_version = %api_version,
                    scope = %scope,
                    "CRD watcher already running, skipping duplicate start"
                );
                continue;
            }

            let writer = reflector::store::Writer::new(ar.clone());
            let store = writer.as_reader();
            let crd_store = Arc::new(CrdResourceStore::new_scoped(
                api_version.clone(),
                kind.clone(),
                scope.clone(),
                store,
            ));

            let change_notifier = {
                let mut set = store_set.lock().await;
                if !set.add_store(crd_store) {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "CRD watcher already running, skipping duplicate start"
                    );
                    continue;
                }
                set.change_notifier()
            };

            let watcher_config = watcher::Config::default();
            let target = WatchTarget {
                api_version: api_version.clone(),
                kind: kind.clone(),
                scope: scope.clone(),
                resource: ar.clone(),
                watcher_label: "CRD watcher",
            };
            let watcher_task = run_watcher_generations(
                target,
                writer,
                store_set.clone(),
                change_notifier,
                relist_policy,
                Arc::clone(&metrics),
                shutdown.clone(),
                move |writer| {
                    reflector::reflector(writer, watcher(api.clone(), watcher_config.clone()))
                },
            );

            let name = format!("{task_label}/{}", crd.kind);
            if !registry.spawn_named(&name, watcher_task, shutdown.clone()) {
                abandon_watcher_start(&store_set, &api_version, &kind, &scope).await;
                return started;
            }

            started += 1;
            info!(
                kind = crd.kind,
                group = crd.group,
                scope = %scope,
                "Started CRD watcher"
            );
        }
    }

    let mut core_watch_plan: Vec<(&CoreResourceSpec, Vec<String>)> = Vec::new();
    if selection.watch_core {
        core_watch_plan.extend(
            selected_core_resources(selection.watch_node_locality)
                .into_iter()
                .map(|resource| {
                    (
                        resource,
                        pod_discovery_core_watch_namespaces(
                            resource,
                            &namespaces,
                            &node_waypoint_namespace,
                        ),
                    )
                }),
        );
    }
    if selection.watch_gateway_api {
        core_watch_plan.extend(
            K8S_NAMESPACE_RESOURCES
                .iter()
                .map(|resource| (resource, Vec::new())),
        );
        core_watch_plan.extend(
            GATEWAY_API_CORE_RESOURCES
                .iter()
                .map(|resource| (resource, namespaces.clone())),
        );
    }
    if selection.watch_gateway_api_data_plane_service {
        let status_namespaces = gateway_api_data_plane_status_watch_namespaces(
            &namespaces,
            gateway_api_data_plane_service_namespace.as_deref(),
        );
        core_watch_plan.extend(
            GATEWAY_API_DATA_PLANE_STATUS_RESOURCES
                .iter()
                .map(|resource| (resource, status_namespaces.clone())),
        );
    }
    if selection.watch_mesh_config {
        core_watch_plan.extend(
            ISTIO_MESH_CONFIG_RESOURCES
                .iter()
                .map(|resource| (resource, vec![istio_root_namespace.clone()])),
        );
    }

    if !core_watch_plan.is_empty() {
        for (resource, resource_namespaces) in core_watch_plan {
            let api_version = if resource.group.is_empty() {
                resource.version.to_string()
            } else {
                format!("{}/{}", resource.group, resource.version)
            };
            let ar = ApiResource {
                group: resource.group.to_string(),
                version: resource.version.to_string(),
                api_version: api_version.clone(),
                kind: resource.kind.to_string(),
                plural: resource.plural.to_string(),
            };
            let kind = resource.kind.to_string();

            for (api, ar, scope) in
                build_apis_for_resource(&client, &ar, &resource_namespaces, resource.namespaced)
            {
                if store_set
                    .lock()
                    .await
                    .has_store_for_scope(&api_version, &kind, &scope)
                {
                    debug!(
                        kind = %kind,
                        api_version = %api_version,
                        scope = %scope,
                        "K8s core watcher already running, skipping duplicate start"
                    );
                    continue;
                }

                let writer = reflector::store::Writer::new(ar.clone());
                let store = writer.as_reader();
                let crd_store = Arc::new(CrdResourceStore::new_scoped(
                    api_version.clone(),
                    kind.clone(),
                    scope.clone(),
                    store,
                ));

                let change_notifier = {
                    let mut set = store_set.lock().await;
                    if !set.add_store(crd_store) {
                        debug!(
                            kind = %kind,
                            api_version = %api_version,
                            scope = %scope,
                            "K8s core watcher already running, skipping duplicate start"
                        );
                        continue;
                    }
                    set.change_notifier()
                };

                let watcher_config = match resource.field_selector {
                    Some(selector) => watcher::Config::default().fields(selector),
                    None => watcher::Config::default(),
                };
                let target = WatchTarget {
                    api_version: api_version.clone(),
                    kind: kind.clone(),
                    scope: scope.clone(),
                    resource: ar.clone(),
                    watcher_label: "K8s core watcher",
                };
                let watcher_task = run_watcher_generations(
                    target,
                    writer,
                    store_set.clone(),
                    change_notifier,
                    relist_policy,
                    Arc::clone(&metrics),
                    shutdown.clone(),
                    move |writer| {
                        reflector::reflector(writer, watcher(api.clone(), watcher_config.clone()))
                    },
                );

                let name = format!("{task_label}/{}", resource.kind);
                if !registry.spawn_named(&name, watcher_task, shutdown.clone()) {
                    abandon_watcher_start(&store_set, &api_version, &kind, &scope).await;
                    return started;
                }

                started += 1;
                info!(
                    kind = resource.kind,
                    group = resource.group,
                    scope = %scope,
                    "Started K8s core watcher"
                );
            }
        }
    }

    started
}

/// Roll back the half-finished registration of one watcher.
///
/// Reached only when the controller task registry was closed by shutdown
/// between adding this watcher's store and registering its task. The task was
/// never spawned, so nothing is detached; the store it would have fed is
/// removed so it cannot linger as a source no watcher updates. The caller stops
/// starting further watchers.
async fn abandon_watcher_start(
    store_set: &Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    api_version: &str,
    kind: &str,
    scope: &str,
) {
    store_set
        .lock()
        .await
        .remove_store_for_scope(api_version, kind, scope);
    debug!(
        kind = %kind,
        api_version = %api_version,
        scope = %scope,
        "Controller shutdown closed the task registry; stopping watcher startup"
    );
}

/// Register the CRD reprobe loop with `registry`, returning whether it was
/// accepted (it is refused only if shutdown already closed the registry).
///
/// The loop is itself an owned controller task, and every watcher it creates is
/// registered with the same registry, so a CRD group that appears after startup
/// no longer produces watchers outside structured ownership (#3220).
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_crd_reprobe_task(
    client: Client,
    store_set: Arc<tokio::sync::Mutex<ResourceStoreSet>>,
    selection: WatcherSelection,
    namespaces: Vec<String>,
    node_waypoint_namespace: String,
    istio_root_namespace: String,
    gateway_api_data_plane_service_namespace: Option<String>,
    relist_policy: RelistPolicy,
    metrics: Arc<ControllerMetrics>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    interval: Duration,
    registry: &Arc<ControllerTaskRegistry>,
) -> bool {
    let mut reprobe_shutdown = shutdown.clone();
    let watcher_shutdown = shutdown.clone();
    // Weak on purpose: the registry owns this task's `JoinHandle`, so holding a
    // strong reference back would make a cycle that keeps every handle alive.
    // A failed upgrade means the controller handle is gone, which is a reason
    // to stop — never a reason to spawn a watcher nobody owns.
    let registry_ref = Arc::downgrade(registry);

    let reprobe_task = async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await; // skip first

        loop {
            tokio::select! {
                biased;
                _ = reprobe_shutdown.changed() => {
                    if *reprobe_shutdown.borrow() {
                        return;
                    }
                }
                _ = timer.tick() => {
                    let Some(registry) = registry_ref.upgrade() else {
                        debug!("Controller task registry released; stopping CRD reprobe");
                        return;
                    };
                    debug!("Re-probing CRD group availability");
                    let new_watchers = start_crd_watchers(
                        client.clone(),
                        store_set.clone(),
                        selection,
                        namespaces.clone(),
                        node_waypoint_namespace.clone(),
                        istio_root_namespace.clone(),
                        gateway_api_data_plane_service_namespace.clone(),
                        relist_policy,
                        Arc::clone(&metrics),
                        watcher_shutdown.clone(),
                        &registry,
                        REPROBE_WATCHER_LABEL,
                    ).await;
                    if new_watchers > 0 {
                        info!(watchers = new_watchers, "CRD reprobe started additional watchers");
                    }
                    if registry.is_closed() {
                        // Shutdown began while this probe was in flight; the
                        // watchers above (if any) were handed over, and further
                        // registrations would be refused.
                        debug!("Controller shutdown closed the task registry; stopping reprobe");
                        return;
                    }
                }
            }
        }
    };

    registry.spawn_named("crd-reprobe", reprobe_task, shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_scopes_uses_all_namespaces_when_unset() {
        assert_eq!(watch_scopes(&[]), vec![None]);
    }

    #[test]
    fn watch_scopes_preserves_each_configured_namespace() {
        assert_eq!(
            watch_scopes(&["default".to_string(), "prod".to_string()]),
            vec![Some("default".to_string()), Some("prod".to_string())]
        );
        assert_eq!(
            watch_scope_label(Some("prod")),
            "namespace:prod".to_string()
        );
    }

    #[test]
    fn istio_watch_namespaces_include_root_namespace_when_namespaced() {
        assert_eq!(
            namespaces_with_istio_root(&["default".to_string()], "istio-system"),
            vec!["default".to_string(), "istio-system".to_string()]
        );
        assert_eq!(
            namespaces_with_istio_root(
                &["default".to_string(), "istio-system".to_string()],
                "istio-system"
            ),
            vec!["default".to_string(), "istio-system".to_string()]
        );
    }

    #[test]
    fn pod_discovery_pod_watch_includes_mesh_namespace_when_scoped() {
        let pod = K8S_CORE_RESOURCES
            .iter()
            .find(|resource| resource.kind == "Pod")
            .expect("pod resource");
        assert_eq!(
            pod_discovery_core_watch_namespaces(
                pod,
                &["prod".to_string(), "staging".to_string()],
                "ferrum-system",
            ),
            vec![
                "prod".to_string(),
                "staging".to_string(),
                "ferrum-system".to_string(),
            ]
        );
    }

    #[test]
    fn pod_discovery_non_pod_and_all_namespace_watches_stay_unchanged() {
        let service = K8S_CORE_RESOURCES
            .iter()
            .find(|resource| resource.kind == "Service")
            .expect("service resource");
        assert_eq!(
            pod_discovery_core_watch_namespaces(service, &["prod".to_string()], "ferrum-system"),
            vec!["prod".to_string()]
        );

        let pod = K8S_CORE_RESOURCES
            .iter()
            .find(|resource| resource.kind == "Pod")
            .expect("pod resource");
        assert!(pod_discovery_core_watch_namespaces(pod, &[], "ferrum-system").is_empty());
    }

    #[test]
    fn istio_watch_namespaces_keep_cluster_wide_scope_when_unset() {
        assert!(
            namespaces_with_istio_root(&[], "istio-system").is_empty(),
            "empty namespace list means Api::all and already includes root"
        );
    }

    #[test]
    fn crd_watch_namespaces_only_add_root_for_istio_crds() {
        let authz = ISTIO_CRDS
            .iter()
            .find(|resource| resource.kind == "AuthorizationPolicy")
            .expect("AuthorizationPolicy spec");
        let http_route = GATEWAY_API_CRDS
            .iter()
            .find(|resource| resource.kind == "HTTPRoute")
            .expect("HTTPRoute spec");

        assert_eq!(
            crd_watch_namespaces(authz, &["default".to_string()], "istio-system"),
            vec!["default".to_string(), "istio-system".to_string()]
        );
        assert_eq!(
            crd_watch_namespaces(http_route, &["default".to_string()], "istio-system"),
            vec!["default".to_string()]
        );
    }

    #[test]
    fn proxy_config_is_watched_as_networking_v1beta1() {
        let proxy_config = ISTIO_CRDS
            .iter()
            .find(|resource| resource.kind == "ProxyConfig")
            .expect("ProxyConfig must be in ISTIO_CRDS");
        assert_eq!(proxy_config.group, "networking.istio.io");
        assert_eq!(proxy_config.version, "v1beta1");
        assert_eq!(proxy_config.plural, "proxyconfigs");
        assert!(
            proxy_config.namespaced,
            "ProxyConfig is a namespaced Istio CRD"
        );
        assert_eq!(
            crd_watch_namespaces(proxy_config, &["default".to_string()], "istio-system"),
            vec!["default".to_string(), "istio-system".to_string()],
            "ProxyConfig watches configured namespaces plus the Istio root namespace"
        );
        assert!(
            namespaces_with_istio_root(&[], "istio-system").is_empty(),
            "empty watch list keeps Api::all (already includes root); no extra scoped store"
        );
    }

    #[test]
    fn istio_watch_selection_registers_proxy_config_with_other_crds() {
        let kinds: HashSet<&str> = ISTIO_CRDS.iter().map(|crd| crd.kind).collect();
        assert!(kinds.contains("ProxyConfig"));
        assert_eq!(
            ISTIO_CRDS.len(),
            10,
            "ten Istio kinds are watched (nine historical + ProxyConfig)"
        );
        // Selection gate: watch_istio drives registration from ISTIO_CRDS only.
        let selection = WatcherSelection {
            watch_istio: true,
            watch_gateway_api: false,
            watch_core: false,
            watch_gateway_api_data_plane_service: false,
            watch_node_locality: false,
            watch_mesh_config: false,
        };
        assert!(selection.watch_istio);
        let mut planned = Vec::new();
        if selection.watch_istio {
            planned.extend(ISTIO_CRDS.iter().map(|crd| crd.kind));
        }
        assert!(
            planned.contains(&"ProxyConfig"),
            "watch_istio selection must plan a ProxyConfig watcher"
        );
    }

    #[test]
    fn data_plane_status_watch_namespaces_include_configured_service_namespace() {
        assert_eq!(
            gateway_api_data_plane_status_watch_namespaces(&["routes".to_string()], Some("ferrum")),
            vec!["routes".to_string(), "ferrum".to_string()]
        );
        assert_eq!(
            gateway_api_data_plane_status_watch_namespaces(&["ferrum".to_string()], Some("ferrum")),
            vec!["ferrum".to_string()]
        );
        assert!(
            gateway_api_data_plane_status_watch_namespaces(&[], Some("ferrum")).is_empty(),
            "empty watch namespace list keeps Api::all semantics"
        );
    }

    #[test]
    fn k8s_core_resources_cover_required_namespaced_pod_discovery_inputs() {
        let kinds: HashSet<&str> = K8S_CORE_RESOURCES
            .iter()
            .map(|resource| resource.kind)
            .collect();
        assert!(kinds.contains("Pod"));
        assert!(kinds.contains("Service"));
        assert!(kinds.contains("EndpointSlice"));
        assert!(
            !kinds.contains("Node"),
            "Node locality is optional and must not require cluster-scoped RBAC for pod discovery"
        );
    }

    #[test]
    fn selected_core_resources_adds_node_only_for_locality_enrichment() {
        let base_kinds: HashSet<&str> = selected_core_resources(false)
            .into_iter()
            .map(|resource| resource.kind)
            .collect();
        let locality_kinds: HashSet<&str> = selected_core_resources(true)
            .into_iter()
            .map(|resource| resource.kind)
            .collect();

        assert!(!base_kinds.contains("Node"));
        assert!(locality_kinds.contains("Node"));
        assert!(locality_kinds.contains("Pod"));
        assert!(locality_kinds.contains("Service"));
        assert!(locality_kinds.contains("EndpointSlice"));
    }

    #[test]
    fn gateway_api_data_plane_status_resources_watch_endpoint_slices() {
        let kinds: HashSet<&str> = GATEWAY_API_DATA_PLANE_STATUS_RESOURCES
            .iter()
            .map(|resource| resource.kind)
            .collect();

        assert_eq!(kinds, HashSet::from(["EndpointSlice"]));
    }

    #[test]
    fn gateway_api_watches_gateway_class_cluster_scoped() {
        let gateway_class = GATEWAY_API_CRDS
            .iter()
            .find(|resource| resource.kind == "GatewayClass")
            .expect("GatewayClass watcher spec");

        assert!(!gateway_class.namespaced);
        assert_eq!(gateway_class.plural, "gatewayclasses");
    }

    #[test]
    fn gateway_api_core_resources_cover_backend_refs_and_certificate_refs() {
        let kinds: HashSet<&str> = GATEWAY_API_CORE_RESOURCES
            .iter()
            .map(|resource| resource.kind)
            .collect();
        assert_eq!(kinds, HashSet::from(["Secret", "Service", "EndpointSlice"]));

        for resource in GATEWAY_API_CORE_RESOURCES {
            assert!(
                resource.namespaced,
                "{} Gateway API core watch should be namespaced",
                resource.kind
            );
        }
    }

    #[test]
    fn gateway_api_watches_served_v1beta1_compatibility_versions() {
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "Gateway" && resource.version == "v1beta1" && resource.namespaced
        }));
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "HTTPRoute" && resource.version == "v1beta1" && resource.namespaced
        }));
        assert!(GATEWAY_API_CRDS.iter().any(|resource| {
            resource.kind == "ReferenceGrant" && resource.version == "v1" && resource.namespaced
        }));
    }

    #[test]
    fn mesh_config_watcher_resource_is_root_namespace_configmap_only() {
        assert_eq!(ISTIO_MESH_CONFIG_RESOURCES.len(), 1);
        let resource = &ISTIO_MESH_CONFIG_RESOURCES[0];
        assert_eq!(resource.group, "");
        assert_eq!(resource.version, "v1");
        assert_eq!(resource.kind, "ConfigMap");
        assert_eq!(resource.plural, "configmaps");
        assert!(
            resource.namespaced,
            "Istio meshConfig lives in the root namespace ConfigMap"
        );
        assert_eq!(
            resource.field_selector,
            Some("metadata.name=istio"),
            "mesh-config watcher must be name-scoped so unrelated ConfigMaps in \
             the istio root namespace do not trigger no-op reconciliations"
        );
    }

    #[test]
    fn k8s_core_resources_have_no_field_selector() {
        for resource in K8S_CORE_RESOURCES {
            assert!(
                resource.field_selector.is_none(),
                "core resource {} should match every object in scope",
                resource.kind
            );
        }
        for resource in K8S_NODE_LOCALITY_RESOURCES {
            assert!(
                resource.field_selector.is_none(),
                "node-locality resource {} should match every object in scope",
                resource.kind
            );
        }
    }
}

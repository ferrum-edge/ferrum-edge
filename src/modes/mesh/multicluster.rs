//! Cross-cluster endpoint discovery (Tier 3b).
//!
//! Today "multi-cluster" in Ferrum is east-west SNI passthrough
//! ([`materialize_east_west_gateway_proxies`](super::materialize_east_west_gateway_proxies))
//! plus federated trust bundles ([`super::federation`]). The
//! [`RemoteCluster.control_plane_url`](crate::modes::mesh::config::RemoteCluster)
//! field was inert — referenced only by a non-empty validation, never dialed.
//! This module makes it functional: it dials each remote cluster's control
//! plane, fetches that cluster's service endpoints (workloads + services), and
//! stores them in an `ArcSwap`-held snapshot. The slice-apply path merges that
//! snapshot into the local mesh `workloads` / `services` (see
//! [`merge_remote_endpoints_into_mesh`]), tagging remote workloads with a
//! distinct locality so the existing **locality-aware priority-tier load
//! balancer** fails over local → remote at the endpoint level: local targets
//! sit in the source region/zone tier, and remote targets only receive traffic
//! once the local tier has no healthy endpoints.
//!
//! Design notes (kept in lock-step with [`super::federation`]):
//!
//! - **Lock-free hot path**: the slice-apply reader loads the snapshot via
//!   [`RemoteEndpointStore::snapshot`] (one `ArcSwap` deref). The request hot
//!   path is unchanged — remote endpoints become ordinary `Upstream` targets.
//! - **Mockable source**: [`RemoteServiceSource`] abstracts the remote fetch.
//!   The production implementation ([`NativeRemoteSource`]) dials the remote CP
//!   over the native `MeshSubscribe` gRPC stream and reuses the DP gRPC TLS /
//!   JWT machinery; tests inject a deterministic mock. This lets the full
//!   discovery + aggregation + failover path be verified without a live remote
//!   control plane.
//! - **Fail-closed mTLS**: a remote cluster is only polled when cross-cluster
//!   trust is established (a federated trust bundle for the remote trust domain
//!   exists, matching the fail-closed posture of [`super::federation`]). A
//!   failed poll keeps the last-good endpoints and bumps a failure metric;
//!   once-and-only-once failures never delete previously fetched endpoints.
//! - **Backoff**: each remote cluster runs its own task with jittered
//!   exponential backoff (1s → 30s, ±25%) matching the federation poller and
//!   `src/grpc/dp_client.rs`.
//! - **Shutdown**: every loop watches the gateway shutdown channel.
//!
//! ## Live-verification status
//!
//! The aggregation + failover path and the poll loop are covered by unit tests
//! with a mock [`RemoteServiceSource`]. The [`NativeRemoteSource`] gRPC dialer
//! is exercised structurally but a full two-control-plane round trip is not
//! reproduced in this environment; the remaining live-verification step is a
//! CP-to-CP integration deployment (two mesh control planes federated). This is
//! documented for operators in `docs/mesh.md` "Cross-Cluster Endpoint
//! Discovery".

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::BackendAllowIps;
use crate::grpc::dp_client::{DpGrpcTlsConfig, GrpcJwtSecret};
use crate::identity::TrustDomain;
use crate::modes::mesh::config::{AppProtocol, MeshService, MultiClusterConfig, Workload};

/// Backoff bounds shared with [`super::federation`] and
/// `src/grpc/dp_client.rs`. One cross-cluster backoff curve for operators to
/// reason about.
pub(crate) const REMOTE_BACKOFF_INITIAL_SECS: u64 = 1;
pub(crate) const REMOTE_BACKOFF_MAX_SECS: u64 = 30;

/// Defense-in-depth cap on the number of workloads / services a single remote
/// cluster may contribute. A misbehaving (or compromised) remote CP cannot
/// balloon local memory or the load-balancer target lists. Realistic clusters
/// are far below this.
const REMOTE_MAX_WORKLOADS_PER_CLUSTER: usize = 50_000;
const REMOTE_MAX_SERVICES_PER_CLUSTER: usize = 10_000;

/// The endpoints one remote cluster contributes: its `workloads` (carrying
/// addresses, ports, and locality) and `services` (name/namespace/ports +
/// workload refs). These are merged into the local mesh registry at slice
/// apply.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RemoteClusterEndpoints {
    pub workloads: Vec<Workload>,
    pub services: Vec<MeshService>,
}

/// One installed remote cluster's endpoints plus provenance.
#[derive(Debug, Clone)]
pub struct RemoteClusterEntry {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    /// Network label of the remote cluster, used to default workload locality
    /// when the remote workload carries none.
    pub network: Option<String>,
    pub endpoints: RemoteClusterEndpoints,
    pub fetched_at_unix_seconds: u64,
}

/// Snapshot the store hands out to slice apply and the admin API. Keyed by
/// remote cluster name (`RemoteCluster.name` is validated unique).
#[derive(Debug, Default, Clone)]
pub struct RemoteEndpointSnapshot {
    pub clusters: HashMap<String, RemoteClusterEntry>,
}

impl RemoteEndpointSnapshot {
    pub fn is_empty(&self) -> bool {
        self.clusters.is_empty()
    }
}

/// Lock-free shared state populated by the discovery poller and consumed by the
/// slice-apply path. Mirrors [`super::federation::FederationStore`].
#[derive(Clone)]
pub struct RemoteEndpointStore {
    inner: Arc<ArcSwap<RemoteEndpointSnapshot>>,
    first_ready: Arc<AtomicBool>,
    /// Bumped on every successful install/remove so the slice-apply task
    /// re-runs even when the local CP config is unchanged (a remote cluster
    /// scaling up/down must re-materialize the aggregated upstream targets).
    revision_tx: Arc<watch::Sender<u64>>,
    /// Monotonically-increasing generation counter. `RemoteDiscoveryManager`
    /// stamps each poll task with the generation at launch; `install` checks
    /// that the task's generation is still current before committing an update.
    /// This prevents a task that was aborted during a mid-flight `fetch()` from
    /// installing its (now stale) result after `remove()` has already cleared
    /// the cluster — closing the abort→install race (F6).
    generation: Arc<AtomicU64>,
    /// Generation at which each cluster was last registered. Stored alongside
    /// the snapshot so `install` can compare atomically.
    cluster_generation: Arc<ArcSwap<HashMap<String, u64>>>,
}

impl Default for RemoteEndpointStore {
    fn default() -> Self {
        let (revision_tx, _) = watch::channel(0u64);
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(RemoteEndpointSnapshot::default()))),
            first_ready: Arc::new(AtomicBool::new(false)),
            revision_tx: Arc::new(revision_tx),
            generation: Arc::new(AtomicU64::new(0)),
            cluster_generation: Arc::new(ArcSwap::new(Arc::new(HashMap::new()))),
        }
    }
}

impl RemoteEndpointStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock-free read.
    pub fn snapshot(&self) -> Arc<RemoteEndpointSnapshot> {
        self.inner.load_full()
    }

    /// `true` after at least one remote cluster has been successfully polled.
    #[cfg(test)]
    pub fn has_first_success(&self) -> bool {
        self.first_ready.load(Ordering::Acquire)
    }

    /// Subscribe to install events. Mirrors `MeshRuntimeState::subscribe()`.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// Test helper: register a cluster and immediately install its entry in one
    /// step. Production code must use `register_cluster` + `install` so the
    /// generation token is passed through the poll task.
    #[cfg(test)]
    pub fn install_for_test(&self, entry: RemoteClusterEntry) {
        let new_gen = self.register_cluster(&entry.cluster_name);
        self.install(entry, new_gen);
    }

    /// Register a newly-started poll task for `cluster_name` and return its
    /// generation token. The task must pass this token back to `install`; if the
    /// token no longer matches the cluster's current generation (because the
    /// cluster was removed and re-added, or removed and not re-added) the
    /// install is silently dropped, preventing the abort→install race (F6).
    pub(crate) fn register_cluster(&self, cluster_name: &str) -> u64 {
        let new_gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.cluster_generation.rcu(|current| {
            let mut next = (**current).clone();
            next.insert(cluster_name.to_string(), new_gen);
            Arc::new(next)
        });
        new_gen
    }

    /// Install remote endpoints for a cluster **only** when `task_generation`
    /// still matches the cluster's registered generation. A task whose cluster
    /// was removed (or removed + re-started at a newer generation) while the
    /// task was mid-`fetch` will find a mismatched generation and its result
    /// is discarded — closing the abort→install race (F6).
    ///
    /// When the endpoints are byte-identical to what is already stored, the
    /// revision is NOT bumped and the apply task is not woken (F2).
    ///
    /// Returns `true` only when this call actually mutated the snapshot (a real
    /// install), so callers can avoid logging "installed" on a deduped or
    /// retired-cluster no-op.
    fn install(&self, entry: RemoteClusterEntry, task_generation: u64) -> bool {
        let name = entry.cluster_name.clone();
        // Fast-path generation check: bail out early if the task's cluster slot
        // was already retired, avoiding the dedup load + clone for stale tasks.
        // This is re-validated atomically inside the rcu below — it is only an
        // optimization, not the authoritative check.
        if !self.cluster_generation_matches(&name, task_generation) {
            return false;
        }
        // No-op dedup: skip the revision bump when the endpoints are unchanged.
        {
            let current = self.inner.load();
            if current
                .clusters
                .get(&name)
                .is_some_and(|existing| existing.endpoints == entry.endpoints)
            {
                // Endpoints are identical — do not wake the apply task.
                return false;
            }
        }
        // CAS loop so two concurrent successful polls (different clusters)
        // cannot stomp each other's snapshot clone. The generation is re-checked
        // INSIDE the closure so the check-and-insert is atomic with respect to
        // `remove()`: `remove` retires the generation (in `cluster_generation`)
        // BEFORE clearing endpoints (in `inner`). So if a `remove` races this
        // mid-flight install, either (a) this rcu commits first and `remove`'s
        // subsequent `inner` clear drops the endpoints, or (b) `remove`'s `inner`
        // clear wins the CAS, this closure retries, re-reads the now-retired
        // generation, and skips — never reintroducing endpoints for a removed
        // cluster. Without the in-closure recheck, a stale task could insert
        // after `remove` had already cleared the cluster (the F6 race, widened
        // to the trust-withdrawal case).
        let mut installed = false;
        self.inner.rcu(|current| {
            if !self.cluster_generation_matches(&name, task_generation) {
                installed = false;
                return Arc::clone(current);
            }
            let mut next = (**current).clone();
            next.clusters.insert(name.clone(), entry.clone());
            installed = true;
            Arc::new(next)
        });
        if installed {
            self.first_ready.store(true, Ordering::Release);
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
        installed
    }

    /// Whether `task_generation` still matches the cluster's registered
    /// generation slot. Returns `false` once `remove()` has retired the slot (or
    /// it was re-registered at a newer generation), which is how an in-flight
    /// poll task for a removed/untrusted cluster is prevented from installing.
    fn cluster_generation_matches(&self, cluster_name: &str, task_generation: u64) -> bool {
        self.cluster_generation
            .load()
            .get(cluster_name)
            .is_some_and(|&g| g == task_generation)
    }

    /// Remove a remote cluster's endpoints (slice no longer lists it or trust was
    /// withdrawn). Also retires the generation slot so any in-flight poll task
    /// for this cluster sees a stale generation and cannot reinstall after removal.
    /// No-op if untracked.
    pub fn remove(&self, cluster_name: &str) {
        // Retire the cluster's generation so any in-flight task sees mismatch.
        self.cluster_generation.rcu(|current| {
            if current.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.remove(cluster_name);
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        let mut changed = false;
        self.inner.rcu(|current| {
            if current.clusters.contains_key(cluster_name) {
                let mut next = (**current).clone();
                next.clusters.remove(cluster_name);
                changed = true;
                Arc::new(next)
            } else {
                Arc::clone(current)
            }
        });
        if changed {
            self.revision_tx.send_modify(|revision| *revision += 1);
        }
    }
}

/// Abstracts the remote-cluster endpoint fetch so the discovery loop is
/// testable without a live remote control plane. The production implementation
/// is [`NativeRemoteSource`]; tests inject a deterministic mock.
#[async_trait]
pub trait RemoteServiceSource: Send + Sync {
    /// Fetch the remote cluster's current service endpoints. Returns `Err` on
    /// any transport / auth / decode failure so the poll loop keeps the
    /// last-good snapshot and backs off.
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String>;
}

/// Locality tag applied to a remote workload that carries no locality of its
/// own, so it still tiers BELOW the local source region in the priority-tier
/// load balancer. Format is `region/zone` where the region is a synthetic
/// `remote-<cluster>` that can never collide with a real local region.
fn default_remote_locality(cluster_name: &str, network: Option<&str>) -> String {
    match network {
        Some(network) if !network.is_empty() => format!("remote-{cluster_name}/{network}"),
        _ => format!("remote-{cluster_name}"),
    }
}

/// Tag a remote cluster's workloads with provenance and a fail-safe locality.
///
/// - `cluster` is stamped so introspection / metrics can attribute the target.
/// - `network` is preserved (multi-network routing).
/// - `locality` is always rewritten to a synthetic `remote-<cluster>` locality.
///   A remote CP can legitimately report the same region/zone strings as the
///   local cluster, but remote endpoints must stay below the local priority tier
///   until local endpoints are exhausted.
///
/// Workloads are NOT renamed or re-keyed: a remote workload keeps its SPIFFE
/// id, service_name, addresses, and ports so [`MeshServiceDiscoverer`] resolves
/// it against the same `MeshService` the local cluster advertises.
fn tag_remote_workloads(
    endpoints: &mut RemoteClusterEndpoints,
    cluster_name: &str,
    network: Option<&str>,
) {
    for workload in &mut endpoints.workloads {
        if workload.cluster.is_none() {
            workload.cluster = Some(cluster_name.to_string());
        }
        if workload.network.is_none()
            && let Some(network) = network
            && !network.is_empty()
        {
            workload.network = Some(network.to_string());
        }
        workload.locality = Some(default_remote_locality(cluster_name, network));
    }
}

fn workload_endpoint_key(workload: &Workload) -> WorkloadEndpointKey {
    let mut addresses = workload.addresses.clone();
    addresses.sort();
    let mut ports: Vec<(u16, AppProtocol, Option<String>)> = workload
        .ports
        .iter()
        .map(|port| (port.port, port.protocol, port.name.clone()))
        .collect();
    ports.sort_by(|left, right| {
        (left.0, app_protocol_sort_key(left.1), left.2.as_deref()).cmp(&(
            right.0,
            app_protocol_sort_key(right.1),
            right.2.as_deref(),
        ))
    });
    WorkloadEndpointKey {
        spiffe_id: workload.spiffe_id.as_str().to_string(),
        namespace: workload.namespace.clone(),
        service_name: workload.service_name.clone(),
        addresses,
        ports,
    }
}

fn app_protocol_sort_key(protocol: AppProtocol) -> u8 {
    match protocol {
        AppProtocol::Http => 0,
        AppProtocol::Http2 => 1,
        AppProtocol::Grpc => 2,
        AppProtocol::Tcp => 3,
        AppProtocol::Tls => 4,
        AppProtocol::Mongo => 5,
        AppProtocol::Redis => 6,
        AppProtocol::Mysql => 7,
        AppProtocol::Postgres => 8,
        AppProtocol::Unknown => 9,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WorkloadEndpointKey {
    spiffe_id: String,
    namespace: String,
    service_name: String,
    addresses: Vec<String>,
    ports: Vec<(u16, AppProtocol, Option<String>)>,
}

/// Merge the remote-endpoint snapshot into a slice's local `workloads` /
/// `services`. Returns the merged vectors; the slice-apply path uses these to
/// build `GatewayConfig.mesh` so [`MeshServiceDiscoverer`] resolves both local
/// and remote endpoints for a service.
///
/// Merge rules:
/// - Remote workloads are appended after local ones. Exact endpoint duplicates
///   are skipped, but workloads with the same SPIFFE ID and different addresses
///   are retained; multi-cluster services can legitimately expose replicas with
///   the same service account identity in multiple clusters.
/// - Remote services are merged by `(namespace, name)`: a service the local
///   cluster already advertises keeps the local definition (ports / overrides);
///   only the remote `workloads` refs are unioned in so the local service can
///   resolve the remote endpoints. A service that exists ONLY remotely is added
///   wholesale.
///
/// `local_workloads` / `local_services` are cloned and extended; callers pass
/// the slice's own vectors.
pub fn merge_remote_endpoints_into_mesh(
    local_workloads: &[Workload],
    local_services: &[MeshService],
    snapshot: &RemoteEndpointSnapshot,
) -> (Vec<Workload>, Vec<MeshService>) {
    if snapshot.is_empty() {
        return (local_workloads.to_vec(), local_services.to_vec());
    }

    let mut workloads = local_workloads.to_vec();
    let mut seen_workloads: std::collections::HashSet<WorkloadEndpointKey> =
        workloads.iter().map(workload_endpoint_key).collect();

    let mut services = local_services.to_vec();
    // Index local services by (namespace, name) for ref-union.
    let mut service_index: HashMap<(String, String), usize> = services
        .iter()
        .enumerate()
        .map(|(idx, svc)| ((svc.namespace.clone(), svc.name.clone()), idx))
        .collect();

    // Deterministic order: iterate clusters by name so the merged target list
    // is stable across snapshots (avoids LB hash-ring churn from HashMap order).
    let mut cluster_names: Vec<&String> = snapshot.clusters.keys().collect();
    cluster_names.sort();

    for cluster_name in cluster_names {
        let Some(entry) = snapshot.clusters.get(cluster_name) else {
            continue;
        };
        for workload in &entry.endpoints.workloads {
            if seen_workloads.insert(workload_endpoint_key(workload)) {
                workloads.push(workload.clone());
            }
        }
        for remote_svc in &entry.endpoints.services {
            let key = (remote_svc.namespace.clone(), remote_svc.name.clone());
            if let Some(&idx) = service_index.get(&key) {
                // Local service wins on ports/overrides; union remote refs so
                // the local service resolves the remote workloads too.
                let local = &mut services[idx];
                for wref in &remote_svc.workloads {
                    if !local
                        .workloads
                        .iter()
                        .any(|w| w.spiffe_id == wref.spiffe_id)
                    {
                        local.workloads.push(wref.clone());
                    }
                }
            } else {
                let new_idx = services.len();
                services.push(remote_svc.clone());
                service_index.insert(key, new_idx);
            }
        }
    }

    (workloads, services)
}

/// Per-cluster poll target derived from a [`MultiClusterConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteClusterPollTarget {
    cluster_name: String,
    trust_domain: TrustDomain,
    network: Option<String>,
    control_plane_url: String,
}

struct RunningRemoteDiscovery {
    target: RemoteClusterPollTarget,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<()>,
}

type RemoteSourceFactory =
    Arc<dyn Fn(&RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> + Send + Sync>;

/// Manager that reconciles remote-cluster discovery tasks against the latest
/// mesh slice and trust-bundle state.
pub struct RemoteDiscoveryManager {
    config: Option<RemoteDiscoveryConfig>,
    store: RemoteEndpointStore,
    source_factory: RemoteSourceFactory,
    running: HashMap<String, RunningRemoteDiscovery>,
}

impl RemoteDiscoveryManager {
    pub fn new<F>(
        config: Option<RemoteDiscoveryConfig>,
        store: RemoteEndpointStore,
        source_factory: F,
    ) -> Self
    where
        F: Fn(&RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> + Send + Sync + 'static,
    {
        Self {
            config,
            store,
            source_factory: Arc::new(source_factory),
            running: HashMap::new(),
        }
    }

    /// Start/stop per-cluster pollers to match the latest slice and trust state.
    /// Removing an ineligible cluster also removes its last-good endpoints so a
    /// stale snapshot cannot keep serving a cluster after trust or config is
    /// withdrawn.
    pub fn reconcile(
        &mut self,
        multi_cluster: Option<&MultiClusterConfig>,
        trust_bundle_domains: std::collections::HashSet<TrustDomain>,
    ) {
        let (Some(config), Some(multi_cluster)) = (self.config.clone(), multi_cluster) else {
            self.stop_all(true);
            return;
        };
        let targets = poll_targets_for_multi_cluster(multi_cluster, &trust_bundle_domains);
        if targets.is_empty() {
            self.stop_all(true);
            debug!("No remote clusters eligible for endpoint discovery; pollers stopped");
            return;
        }

        let targets_by_name: HashMap<String, RemoteClusterPollTarget> = targets
            .into_iter()
            .map(|target| (target.cluster_name.clone(), target))
            .collect();

        let stale: Vec<String> = self
            .running
            .iter()
            .filter_map(|(name, running)| {
                let desired = targets_by_name.get(name)?;
                (&running.target != desired).then(|| name.clone())
            })
            .collect();
        let removed: Vec<String> = self
            .running
            .keys()
            .filter(|name| !targets_by_name.contains_key(*name))
            .cloned()
            .collect();
        for name in stale.into_iter().chain(removed) {
            self.stop_cluster(&name, true);
        }

        for target in targets_by_name.into_values() {
            if !self.running.contains_key(&target.cluster_name) {
                self.start_cluster(target, config.clone());
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.stop_all(false);
    }

    #[cfg(test)]
    fn running_cluster_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.running.keys().cloned().collect();
        names.sort();
        names
    }

    fn start_cluster(&mut self, target: RemoteClusterPollTarget, config: RemoteDiscoveryConfig) {
        let ctx = RemoteClusterPollContext {
            cluster_name: target.cluster_name.clone(),
            trust_domain: target.trust_domain.clone(),
            network: target.network.clone(),
            control_plane_url: target.control_plane_url.clone(),
            config,
        };
        let source = (self.source_factory)(&ctx);
        let task_store = self.store.clone();
        // Register a generation token *before* spawning so the task's first
        // install can be validated. The generation is bumped again in `remove`,
        // so a task aborted mid-fetch cannot reinstall after its cluster is
        // removed (F6).
        let task_generation = self.store.register_cluster(&target.cluster_name);
        let (cluster_shutdown_tx, cluster_shutdown_rx) = watch::channel(false);
        let url_for_logs = sanitize_url_for_logging(&target.control_plane_url);
        info!(
            cluster = %target.cluster_name,
            trust_domain = %target.trust_domain,
            control_plane = %url_for_logs,
            poll_interval_seconds = ctx.config.poll_interval.as_secs(),
            "Spawning remote-cluster endpoint discovery"
        );
        let handle = tokio::spawn(async move {
            remote_discovery_loop(
                ctx,
                source,
                task_store,
                cluster_shutdown_rx,
                task_generation,
            )
            .await;
        });
        self.running.insert(
            target.cluster_name.clone(),
            RunningRemoteDiscovery {
                target,
                shutdown_tx: cluster_shutdown_tx,
                handle,
            },
        );
    }

    fn stop_cluster(&mut self, cluster_name: &str, remove_endpoints: bool) {
        if let Some(running) = self.running.remove(cluster_name) {
            let _ = running.shutdown_tx.send(true);
            running.handle.abort();
            if remove_endpoints {
                self.store.remove(cluster_name);
            }
        }
    }

    fn stop_all(&mut self, remove_endpoints: bool) {
        let names: Vec<String> = self.running.keys().cloned().collect();
        for name in names {
            self.stop_cluster(&name, remove_endpoints);
        }
    }
}

#[derive(Clone, Default)]
pub struct RemoteDiscoveryTlsConfig {
    pub tls_urls: Option<DpGrpcTlsConfig>,
    pub plain_urls: Option<DpGrpcTlsConfig>,
}

impl RemoteDiscoveryTlsConfig {
    fn for_control_plane_url(&self, url: &str) -> Option<DpGrpcTlsConfig> {
        // URLs reaching this method are already normalized by
        // `normalize_control_plane_url` (grpcs→https, grpc→http), so matching
        // on `https` is sufficient. The `grpcs` arm is retained as belt-and-
        // suspenders for any caller that passes a non-normalized URL.
        match reqwest::Url::parse(url)
            .ok()
            .map(|parsed| parsed.scheme().to_string())
        {
            Some(scheme) if scheme == "https" || scheme == "grpcs" => self.tls_urls.clone(),
            _ => self.plain_urls.clone(),
        }
    }
}

/// Knobs derived from `EnvConfig`. Not `Debug` because `DpGrpcTlsConfig`
/// carries key material and is intentionally not `Debug`.
#[derive(Clone)]
pub struct RemoteDiscoveryConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    /// JWT secret + issuer for the remote CP gRPC handshake (reuses the
    /// CP→DP secret). `None` disables discovery (no secret → cannot dial).
    pub jwt_secret: Option<GrpcJwtSecret>,
    /// This DP's node id, sent in the remote subscribe request.
    pub node_id: String,
    /// Namespace scope requested from the remote CP.
    pub namespace: String,
    /// Optional DP gRPC client TLS material, split by remote CP URL scheme so an
    /// HTTPS remote is not affected by the local CP URL scheme.
    pub tls_config: RemoteDiscoveryTlsConfig,
    /// Backend IP allow policy applied to resolved remote CP hostnames.
    pub backend_allow_ips: BackendAllowIps,
}

impl RemoteDiscoveryConfig {
    /// Returns `None` when discovery should be disabled (interval 0 or no JWT
    /// secret available to authenticate to the remote CP).
    pub fn new(
        interval_seconds: u64,
        timeout_seconds: u64,
        jwt_secret: Option<GrpcJwtSecret>,
        node_id: String,
        namespace: String,
        tls_config: RemoteDiscoveryTlsConfig,
        backend_allow_ips: BackendAllowIps,
    ) -> Option<Self> {
        if interval_seconds == 0 {
            return None;
        }
        Some(Self {
            poll_interval: Duration::from_secs(interval_seconds),
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            jwt_secret,
            node_id,
            namespace,
            tls_config,
            backend_allow_ips,
        })
    }
}

/// Resolve the poll-target list from a [`MultiClusterConfig`].
///
/// A remote cluster is polled only when it BOTH declares a `control_plane_url`
/// AND has cross-cluster trust established — i.e. a federated trust bundle for
/// its trust domain is present in `trust_bundle_domains`. This keeps
/// cross-cluster discovery fail-closed: Ferrum will not dial (and merge
/// endpoints from) a cluster it cannot mutually authenticate, mirroring the
/// federation poller's posture.
fn poll_targets_for_multi_cluster(
    multi_cluster: &MultiClusterConfig,
    trust_bundle_domains: &std::collections::HashSet<TrustDomain>,
) -> Vec<RemoteClusterPollTarget> {
    multi_cluster
        .remote_clusters
        .iter()
        .filter_map(|remote| {
            let url = remote.control_plane_url.as_deref()?.trim();
            if url.is_empty() {
                return None;
            }
            if !trust_bundle_domains.contains(&remote.trust_domain) {
                warn!(
                    cluster = %remote.name,
                    trust_domain = %remote.trust_domain,
                    "Skipping remote-cluster discovery: no federated trust bundle for the remote \
                     trust domain (cross-cluster discovery is fail-closed). Configure trust \
                     federation for this cluster first."
                );
                return None;
            }
            if let Err(err) = validate_control_plane_url(url) {
                warn!(
                    cluster = %remote.name,
                    error = %err,
                    "Dropping remote-cluster control_plane_url that failed validation"
                );
                return None;
            }
            Some(RemoteClusterPollTarget {
                cluster_name: remote.name.clone(),
                trust_domain: remote.trust_domain.clone(),
                network: remote.network.clone(),
                // Normalize grpc:// → http:// and grpcs:// → https:// so the
                // dialer and TLS-selection logic always see canonical schemes.
                control_plane_url: normalize_control_plane_url(url),
            })
        })
        .collect()
}

/// Normalize a `control_plane_url` for dialing.
///
/// `grpc://` is normalized to `http://` and `grpcs://` to `https://` so that:
/// - `tonic::Channel::from_shared` receives a scheme it understands (`http`/`https`).
/// - TLS selection in [`RemoteDiscoveryTlsConfig::for_control_plane_url`] keys off
///   `https` correctly: a `grpcs://` CP gets TLS; a `grpc://` CP gets plaintext.
///
/// `http`/`https` URLs are returned unchanged.
pub(crate) fn normalize_control_plane_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("grpcs://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("grpc://") {
        format!("http://{rest}")
    } else {
        url.to_string()
    }
}

/// Validate a `control_plane_url`: must parse, must be
/// `http`/`https`/`grpc`/`grpcs`, and must carry a host. Cloud-metadata /
/// link-local hosts are rejected (SSRF defense), mirroring
/// [`super::federation::validate_federation_endpoint`]. Loopback is allowed
/// for local development / integration-test control planes.
///
/// `grpc://` and `grpcs://` are accepted and normalized to `http://` /
/// `https://` by [`normalize_control_plane_url`] before dialing so that
/// `tonic::Channel::from_shared` receives a scheme it understands.
pub(crate) fn validate_control_plane_url(url: &str) -> Result<(), String> {
    // Normalise before parsing so the scheme check is on the canonical form.
    let normalized = normalize_control_plane_url(url);
    let parsed =
        reqwest::Url::parse(&normalized).map_err(|e| format!("invalid control_plane_url: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(format!("unsupported control_plane_url scheme '{other}'")),
    }
    let Some(host) = parsed.host() else {
        return Err("control_plane_url has no host".to_string());
    };
    match host {
        url::Host::Ipv4(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_link_local() || ip.octets() == [169, 254, 169, 254] {
                return Err(format!(
                    "control_plane_url refuses link-local / cloud-metadata host {ip} (SSRF defense)"
                ));
            }
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv4 host {ip}"
                ));
            }
        }
        url::Host::Ipv6(ip) => {
            if ip.is_loopback() {
                return Ok(());
            }
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!(
                    "control_plane_url refuses non-unicast IPv6 host {ip}"
                ));
            }
            if ip.segments()[0] & 0xffc0 == 0xfe80 {
                return Err(format!(
                    "control_plane_url refuses link-local IPv6 host {ip}"
                ));
            }
        }
        url::Host::Domain(_) => {
            // Hostnames resolve at dial time. Domain-based SSRF defense relies
            // on operator network controls; Ferrum does not resolve or validate
            // the resulting IP for tonic-dialed remote CPs (see F5).
        }
    }
    Ok(())
}

/// Build the trust-domain set from a slice's federated + live-polled trust
/// bundles. Used to gate which remote clusters may be dialed.
pub fn trust_domains_from_bundles(
    slice_bundles: Option<&crate::modes::mesh::config::TrustBundleSet>,
    federation: &super::federation::FederationSnapshot,
) -> std::collections::HashSet<TrustDomain> {
    let mut domains = std::collections::HashSet::new();
    if let Some(bundles) = slice_bundles {
        domains.insert(bundles.local.trust_domain.clone());
        for tb in &bundles.federated {
            domains.insert(tb.trust_domain.clone());
        }
    }
    for td in federation.bundles.keys() {
        domains.insert(td.clone());
    }
    domains
}

/// Context passed to the source factory and the poll loop.
#[derive(Clone)]
pub struct RemoteClusterPollContext {
    pub cluster_name: String,
    pub trust_domain: TrustDomain,
    pub network: Option<String>,
    pub control_plane_url: String,
    pub config: RemoteDiscoveryConfig,
}

async fn remote_discovery_loop(
    ctx: RemoteClusterPollContext,
    source: Arc<dyn RemoteServiceSource>,
    store: RemoteEndpointStore,
    mut shutdown_rx: watch::Receiver<bool>,
    task_generation: u64,
) {
    let mut backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
    let url_for_logs = sanitize_url_for_logging(&ctx.control_plane_url);

    loop {
        if *shutdown_rx.borrow() {
            return;
        }

        let attempt_started_at = std::time::Instant::now();
        let result = source.fetch().await.and_then(|mut endpoints| {
            validate_remote_endpoints(&ctx.cluster_name, &endpoints)?;
            tag_remote_workloads(&mut endpoints, &ctx.cluster_name, ctx.network.as_deref());
            Ok(endpoints)
        });

        let (succeeded, sleep_duration) = match result {
            Ok(endpoints) => {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let workload_count = endpoints.workloads.len();
                let entry = RemoteClusterEntry {
                    cluster_name: ctx.cluster_name.clone(),
                    trust_domain: ctx.trust_domain.clone(),
                    network: ctx.network.clone(),
                    endpoints,
                    fetched_at_unix_seconds: now,
                };
                // Capture the summary fields before moving `entry` into
                // `install`, so the log can fire on the actual install result.
                let log_trust_domain = entry.trust_domain.clone();
                let log_network = entry.network.clone();
                let log_fetched_at = entry.fetched_at_unix_seconds;
                let installed = store.install(entry, task_generation);
                if installed {
                    info!(
                        cluster = %ctx.cluster_name,
                        trust_domain = %log_trust_domain,
                        network = log_network.as_deref().unwrap_or(""),
                        fetched_at_unix_seconds = log_fetched_at,
                        control_plane = %url_for_logs,
                        workloads = workload_count,
                        "Installed remote-cluster endpoints"
                    );
                } else {
                    // Poll succeeded but the snapshot was unchanged — endpoints
                    // identical (F2 dedup) or the cluster's generation was
                    // retired mid-flight (removed / trust withdrawn). Not an
                    // "installed" event; keep it at debug to avoid steady-state
                    // INFO spam every poll interval.
                    debug!(
                        cluster = %ctx.cluster_name,
                        control_plane = %url_for_logs,
                        workloads = workload_count,
                        "Remote-cluster poll succeeded with no endpoint change; not re-installing"
                    );
                }
                backoff_secs = REMOTE_BACKOFF_INITIAL_SECS;
                let elapsed = attempt_started_at.elapsed();
                (true, ctx.config.poll_interval.saturating_sub(elapsed))
            }
            Err(err) => {
                warn!(
                    cluster = %ctx.cluster_name,
                    control_plane = %url_for_logs,
                    error = %err,
                    "Remote-cluster endpoint discovery failed; keeping last-good endpoints if any"
                );
                (false, jittered_backoff(backoff_secs))
            }
        };

        if !succeeded {
            backoff_secs = next_backoff_secs(backoff_secs);
        }

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            _ = wait_for_shutdown(&mut shutdown_rx) => return,
        }
    }
}

fn validate_remote_endpoints(
    cluster_name: &str,
    endpoints: &RemoteClusterEndpoints,
) -> Result<(), String> {
    if endpoints.workloads.len() > REMOTE_MAX_WORKLOADS_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} workloads (max {REMOTE_MAX_WORKLOADS_PER_CLUSTER})",
            endpoints.workloads.len()
        ));
    }
    if endpoints.services.len() > REMOTE_MAX_SERVICES_PER_CLUSTER {
        return Err(format!(
            "remote cluster '{cluster_name}' returned {} services (max {REMOTE_MAX_SERVICES_PER_CLUSTER})",
            endpoints.services.len()
        ));
    }
    Ok(())
}

async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    while !*shutdown_rx.borrow() {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

fn jittered_backoff(backoff_secs: u64) -> Duration {
    // ±25% jitter, identical curve to federation / dp_client.
    let base_ms = backoff_secs.saturating_mul(1000);
    let jitter_span = base_ms / 4;
    let jitter = if jitter_span == 0 {
        0
    } else {
        // Cheap deterministic-ish jitter without pulling in rand: mix the
        // monotonic clock. Range is [-jitter_span, +jitter_span).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        (nanos % (jitter_span * 2)) as i64 - jitter_span as i64
    };
    let total = (base_ms as i64 + jitter).max(0) as u64;
    Duration::from_millis(total)
}

fn next_backoff_secs(current: u64) -> u64 {
    current.saturating_mul(2).min(REMOTE_BACKOFF_MAX_SECS)
}

fn sanitize_url_for_logging(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        Err(_) => "<unparseable>".to_string(),
    }
}

// ── Native gRPC remote source ─────────────────────────────────────────────

/// Production [`RemoteServiceSource`]: dials the remote CP's native
/// `MeshSubscribe` gRPC stream, takes the first non-heartbeat slice, and
/// extracts its `workloads` / `services` as the remote cluster's endpoints.
///
/// The subscribe is one-shot per poll: connect, read the first applicable
/// slice, drop the stream. The poll cadence (re-dialing on the configured
/// interval) gives eventual consistency without holding a long-lived stream per
/// remote cluster — keeping the failure model identical to the federation
/// poller (each poll is independent; a failure keeps the last-good snapshot).
pub struct NativeRemoteSource {
    control_plane_url: String,
    node_id: String,
    namespace: String,
    jwt_secret: GrpcJwtSecret,
    tls_config: Option<DpGrpcTlsConfig>,
    request_timeout: Duration,
    backend_allow_ips: BackendAllowIps,
}

impl NativeRemoteSource {
    pub fn new(ctx: &RemoteClusterPollContext, jwt_secret: GrpcJwtSecret) -> Self {
        Self {
            control_plane_url: ctx.control_plane_url.clone(),
            node_id: ctx.config.node_id.clone(),
            namespace: ctx.config.namespace.clone(),
            jwt_secret,
            tls_config: ctx
                .config
                .tls_config
                .for_control_plane_url(&ctx.control_plane_url),
            request_timeout: ctx.config.request_timeout,
            backend_allow_ips: ctx.config.backend_allow_ips.clone(),
        }
    }
}

#[async_trait]
impl RemoteServiceSource for NativeRemoteSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        fetch_remote_slice_endpoints(
            &self.control_plane_url,
            &self.node_id,
            &self.namespace,
            &self.jwt_secret,
            self.tls_config.as_ref(),
            self.request_timeout,
            &self.backend_allow_ips,
        )
        .await
    }
}

/// Factory wiring [`NativeRemoteSource`] for production use. Requires a JWT
/// secret; returns a source that always fails (logged) when none is configured
/// so the poll loop simply backs off rather than panicking.
pub fn native_source_factory(ctx: &RemoteClusterPollContext) -> Arc<dyn RemoteServiceSource> {
    match ctx.config.jwt_secret.clone() {
        Some(secret) => Arc::new(NativeRemoteSource::new(ctx, secret)),
        None => Arc::new(MissingSecretSource {
            cluster_name: ctx.cluster_name.clone(),
        }),
    }
}

/// Sentinel source used when no gRPC JWT secret is configured. Always errors so
/// the poll loop logs + backs off instead of dialing unauthenticated.
struct MissingSecretSource {
    cluster_name: String,
}

#[async_trait]
impl RemoteServiceSource for MissingSecretSource {
    async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
        Err(format!(
            "remote cluster '{}' has no CP↔DP gRPC JWT secret configured; cannot authenticate to \
             the remote control plane (set FERRUM_CP_DP_GRPC_JWT_SECRET)",
            self.cluster_name
        ))
    }
}

/// One-shot remote MeshSubscribe: connect, read the first non-heartbeat slice,
/// return its workloads/services. Bounded by `request_timeout`.
async fn fetch_remote_slice_endpoints(
    control_plane_url: &str,
    node_id: &str,
    namespace: &str,
    jwt_secret: &GrpcJwtSecret,
    tls_config: Option<&DpGrpcTlsConfig>,
    request_timeout: Duration,
    backend_allow_ips: &BackendAllowIps,
) -> Result<RemoteClusterEndpoints, String> {
    use crate::grpc::dp_client::generate_dp_jwt_with_issuer;
    use crate::grpc::proto::MeshSubscribeRequest;
    use crate::grpc::proto::mesh_config_sync_client::MeshConfigSyncClient;
    use crate::modes::mesh::config_consumer::common::tonic_tls_config;
    use crate::modes::mesh::slice::MeshSlice;
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;

    let attempt = async {
        validate_control_plane_url_resolved_ips(control_plane_url, backend_allow_ips).await?;
        let mut endpoint = Channel::from_shared(control_plane_url.to_string())
            .map_err(|e| format!("invalid control_plane_url: {e}"))?
            .connect_timeout(Duration::from_secs(10));
        if let Some(tls) = tls_config {
            let mut client_tls = tonic_tls_config(tls);
            if let Ok(uri) = control_plane_url.parse::<http::Uri>()
                && let Some(host) = uri.host()
            {
                client_tls = client_tls.domain_name(host);
            }
            endpoint = endpoint
                .tls_config(client_tls)
                .map_err(|e| format!("remote CP TLS config: {e}"))?;
        }
        let channel = endpoint
            .connect()
            .await
            .map_err(|e| format!("connect to remote CP: {e}"))?;
        let auth_token =
            generate_dp_jwt_with_issuer(jwt_secret.as_str(), node_id, jwt_secret.issuer())
                .map_err(|e| format!("mint remote CP JWT: {e}"))?;
        let token: MetadataValue<_> = format!("Bearer {auth_token}")
            .parse()
            .map_err(|e| format!("build auth metadata: {e}"))?;
        #[allow(clippy::result_large_err)]
        let mut client =
            MeshConfigSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
                req.metadata_mut().insert("authorization", token.clone());
                Ok(req)
            });
        let request = tonic::Request::new(MeshSubscribeRequest {
            node_id: node_id.to_string(),
            ferrum_version: crate::FERRUM_VERSION.to_string(),
            namespace: namespace.to_string(),
            workload_spiffe_id: String::new(),
            labels: HashMap::new(),
            waypoint_name: String::new(),
        });
        let mut stream = client
            .mesh_subscribe(request)
            .await
            .map_err(|e| format!("remote MeshSubscribe failed: {e}"))?
            .into_inner();
        while let Some(update) = stream
            .message()
            .await
            .map_err(|e| format!("remote MeshSubscribe stream error: {e}"))?
        {
            if update.heartbeat {
                continue;
            }
            let slice = serde_json::from_str::<MeshSlice>(&update.mesh_slice_json)
                .map_err(|e| format!("invalid remote MeshSubscribe slice JSON: {e}"))?;
            return Ok(RemoteClusterEndpoints {
                workloads: slice.workloads,
                services: slice.services,
            });
        }
        Err("remote MeshSubscribe stream closed before delivering a slice".to_string())
    };

    tokio::time::timeout(request_timeout, attempt)
        .await
        .map_err(|_| "remote MeshSubscribe timed out".to_string())?
}

async fn validate_control_plane_url_resolved_ips(
    control_plane_url: &str,
    backend_allow_ips: &BackendAllowIps,
) -> Result<(), String> {
    let uri = control_plane_url
        .parse::<http::Uri>()
        .map_err(|e| format!("invalid control_plane_url: {e}"))?;
    let host = uri
        .host()
        .ok_or_else(|| "control_plane_url has no host".to_string())?;
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });
    let mut resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve remote CP host '{host}': {e}"))?;
    let mut saw_any = false;
    for addr in &mut resolved {
        saw_any = true;
        let ip = addr.ip();
        if !crate::config::check_backend_ip_allowed(&ip, backend_allow_ips) {
            return Err(format!(
                "resolved remote CP host '{host}' to disallowed IP {ip} under FERRUM_BACKEND_ALLOW_IPS={backend_allow_ips}"
            ));
        }
    }
    if !saw_any {
        return Err(format!(
            "resolve remote CP host '{host}': no addresses returned"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::LocalityPreference;
    use crate::identity::spiffe::SpiffeId;
    use crate::modes::mesh::config::{RemoteCluster, ServicePort, WorkloadRef, WorkloadSelector};
    use std::sync::Mutex;

    fn td(raw: &str) -> TrustDomain {
        TrustDomain::new(raw).expect("trust domain")
    }

    fn spiffe(raw: &str) -> SpiffeId {
        SpiffeId::new(raw.to_string()).expect("spiffe id")
    }

    fn workload(spiffe_id: &str, service: &str, address: &str, locality: Option<&str>) -> Workload {
        Workload {
            spiffe_id: spiffe(spiffe_id),
            selector: WorkloadSelector::default(),
            service_name: service.to_string(),
            addresses: vec![address.to_string()],
            ports: vec![],
            trust_domain: td("cluster.local"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: locality.map(str::to_string),
            service_account: None,
        }
    }

    fn service(name: &str, refs: &[&str]) -> MeshService {
        MeshService {
            name: name.to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 8080,
                protocol: Default::default(),
                name: Some("http".to_string()),
            }],
            workloads: refs
                .iter()
                .map(|r| WorkloadRef {
                    spiffe_id: spiffe(r),
                })
                .collect(),
            protocol_overrides: HashMap::new(),
        }
    }

    fn snapshot_with(cluster: &str, endpoints: RemoteClusterEndpoints) -> RemoteEndpointSnapshot {
        let mut clusters = HashMap::new();
        clusters.insert(
            cluster.to_string(),
            RemoteClusterEntry {
                cluster_name: cluster.to_string(),
                trust_domain: td("remote.local"),
                network: Some("net2".to_string()),
                endpoints,
                fetched_at_unix_seconds: 1,
            },
        );
        RemoteEndpointSnapshot { clusters }
    }

    #[test]
    fn default_remote_locality_distinguishes_region() {
        assert_eq!(
            default_remote_locality("west", Some("net2")),
            "remote-west/net2"
        );
        assert_eq!(default_remote_locality("west", None), "remote-west");
        // The synthetic region differs from any plausible local region, so a
        // remote target never lands in the local source-region tier.
        let local = LocalityPreference::parse("us-east-1/zone-a").unwrap();
        let remote = LocalityPreference::parse(&default_remote_locality("west", None)).unwrap();
        assert!(!local.same_region(&remote));
    }

    #[test]
    fn tag_remote_workloads_applies_locality_and_cluster() {
        let mut endpoints = RemoteClusterEndpoints {
            workloads: vec![
                workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                ),
                workload(
                    "spiffe://remote.local/ns/default/sa/b",
                    "reviews",
                    "10.2.0.2",
                    Some("us-west-2/zone-c"),
                ),
            ],
            services: vec![],
        };
        tag_remote_workloads(&mut endpoints, "west", Some("net2"));
        // Remote workloads always get the synthetic remote locality, even when
        // the remote CP supplied a real locality that could collide with local.
        assert_eq!(
            endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );
        assert_eq!(endpoints.workloads[0].cluster.as_deref(), Some("west"));
        assert_eq!(endpoints.workloads[0].network.as_deref(), Some("net2"));
        assert_eq!(
            endpoints.workloads[1].locality.as_deref(),
            Some("remote-west/net2")
        );
    }

    #[test]
    fn merge_appends_remote_workloads_and_unions_service_refs() {
        let local_workloads = vec![workload(
            "spiffe://cluster.local/ns/default/sa/local",
            "reviews",
            "10.1.0.1",
            Some("us-east-1/zone-a"),
        )];
        let local_services = vec![service(
            "reviews",
            &["spiffe://cluster.local/ns/default/sa/local"],
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/remote",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![service(
                "reviews",
                &["spiffe://remote.local/ns/default/sa/remote"],
            )],
        };
        let snapshot = snapshot_with("west", remote);

        let (workloads, services) =
            merge_remote_endpoints_into_mesh(&local_workloads, &local_services, &snapshot);

        assert_eq!(workloads.len(), 2, "remote workload appended");
        // Single merged `reviews` service with BOTH refs so the discoverer
        // resolves local + remote endpoints.
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].workloads.len(), 2);
    }

    #[test]
    fn merge_keeps_same_spiffe_remote_workload_with_distinct_endpoint() {
        // The same service account identity can legitimately appear in multiple
        // clusters. Only exact endpoint duplicates are collapsed.
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/shared",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://cluster.local/ns/default/sa/shared",
                "reviews",
                "10.9.9.9",
                None,
            )],
            services: vec![],
        };
        let snapshot = snapshot_with("west", remote);
        let (workloads, _) = merge_remote_endpoints_into_mesh(&local, &[], &snapshot);
        assert_eq!(workloads.len(), 2);
        assert_eq!(workloads[0].addresses, vec!["10.1.0.1".to_string()]);
        assert_eq!(workloads[1].addresses, vec!["10.9.9.9".to_string()]);
    }

    #[test]
    fn merge_skips_exact_remote_workload_duplicate() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/shared",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let remote = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://cluster.local/ns/default/sa/shared",
                "reviews",
                "10.1.0.1",
                None,
            )],
            services: vec![],
        };
        let snapshot = snapshot_with("west", remote);
        let (workloads, _) = merge_remote_endpoints_into_mesh(&local, &[], &snapshot);
        assert_eq!(workloads.len(), 1);
    }

    #[test]
    fn merge_empty_snapshot_is_identity() {
        let local = vec![workload(
            "spiffe://cluster.local/ns/default/sa/a",
            "reviews",
            "10.1.0.1",
            None,
        )];
        let (workloads, services) = merge_remote_endpoints_into_mesh(
            &local,
            &[service(
                "reviews",
                &["spiffe://cluster.local/ns/default/sa/a"],
            )],
            &RemoteEndpointSnapshot::default(),
        );
        assert_eq!(workloads.len(), 1);
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn store_install_and_snapshot_round_trip() {
        let store = RemoteEndpointStore::new();
        assert!(!store.has_first_success());
        assert!(store.snapshot().is_empty());

        store.install_for_test(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at_unix_seconds: 1,
        });
        assert!(store.has_first_success());
        let snapshot = store.snapshot();
        let entry = snapshot.clusters.get("west").expect("installed entry");
        assert_eq!(entry.trust_domain.as_str(), "remote.local");
        assert_eq!(entry.endpoints.workloads.len(), 1);
        assert_eq!(entry.fetched_at_unix_seconds, 1);

        store.remove("west");
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn poll_targets_require_federated_trust() {
        let mc = MultiClusterConfig {
            remote_clusters: vec![
                RemoteCluster {
                    name: "trusted".to_string(),
                    trust_domain: td("trusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.trusted.example:15010".to_string()),
                    federation_endpoint: None,
                },
                RemoteCluster {
                    name: "untrusted".to_string(),
                    trust_domain: td("untrusted.local"),
                    network: None,
                    control_plane_url: Some("https://cp.untrusted.example:15010".to_string()),
                    federation_endpoint: None,
                },
            ],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("trusted.local"));

        let targets = poll_targets_for_multi_cluster(&mc, &trusted);
        assert_eq!(targets.len(), 1, "only the federated cluster is dialed");
        assert_eq!(targets[0].cluster_name, "trusted");
    }

    #[tokio::test]
    async fn manager_reconciles_trust_changes_and_removes_stale_endpoints() {
        let store = RemoteEndpointStore::new();
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig::default(),
        };
        let mut manager = RemoteDiscoveryManager::new(Some(config), store.clone(), |ctx| {
            Arc::new(MissingSecretSource {
                cluster_name: ctx.cluster_name.clone(),
            })
        });
        let mc = MultiClusterConfig {
            remote_clusters: vec![RemoteCluster {
                name: "west".to_string(),
                trust_domain: td("remote.local"),
                network: None,
                control_plane_url: Some("https://cp.remote.example:15010".to_string()),
                federation_endpoint: None,
            }],
            ..MultiClusterConfig::default()
        };
        let mut trusted = std::collections::HashSet::new();
        trusted.insert(td("remote.local"));

        manager.reconcile(Some(&mc), trusted);
        assert_eq!(manager.running_cluster_names(), vec!["west"]);
        store.install_for_test(RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/a",
                    "reviews",
                    "10.2.0.1",
                    None,
                )],
                services: vec![],
            },
            fetched_at_unix_seconds: 1,
        });
        assert!(!store.snapshot().is_empty());

        manager.reconcile(Some(&mc), std::collections::HashSet::new());
        assert!(manager.running_cluster_names().is_empty());
        assert!(
            store.snapshot().is_empty(),
            "trust withdrawal removes stale remote endpoints"
        );
        manager.shutdown();
    }

    #[test]
    fn validate_control_plane_url_rejects_metadata_and_bad_scheme() {
        assert!(validate_control_plane_url("https://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("http://cp.example:15010").is_ok());
        // grpc:// and grpcs:// are normalized to http:// / https:// before
        // validation (F3), so they must be accepted.
        assert!(validate_control_plane_url("grpc://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("grpcs://cp.example:15010").is_ok());
        assert!(validate_control_plane_url("ftp://cp.example").is_err());
        assert!(validate_control_plane_url("https://169.254.169.254/").is_err());
        assert!(validate_control_plane_url("not a url").is_err());
    }

    #[test]
    fn normalize_control_plane_url_translates_grpc_schemes() {
        assert_eq!(
            normalize_control_plane_url("grpc://cp.example:15010"),
            "http://cp.example:15010"
        );
        assert_eq!(
            normalize_control_plane_url("grpcs://cp.example:15010"),
            "https://cp.example:15010"
        );
        // http/https pass through unchanged.
        assert_eq!(
            normalize_control_plane_url("https://cp.example:15010"),
            "https://cp.example:15010"
        );
        assert_eq!(
            normalize_control_plane_url("http://cp.example:15010"),
            "http://cp.example:15010"
        );
    }

    #[test]
    fn tls_selection_respects_grpcs_scheme() {
        let tls_cfg = RemoteDiscoveryTlsConfig {
            tls_urls: Some(DpGrpcTlsConfig {
                no_verify: true,
                ..DpGrpcTlsConfig::default()
            }),
            plain_urls: None,
        };
        // grpcs normalizes to https — must pick TLS config.
        assert!(
            tls_cfg
                .for_control_plane_url("grpcs://cp.example:15010")
                .is_some()
        );
        // grpc normalizes to http — must pick plain config (None here).
        assert!(
            tls_cfg
                .for_control_plane_url("grpc://cp.example:15010")
                .is_none()
        );
    }

    #[test]
    fn native_source_tls_selection_follows_remote_url_scheme() {
        let config = RemoteDiscoveryConfig {
            poll_interval: Duration::from_secs(60),
            request_timeout: Duration::from_secs(1),
            jwt_secret: None,
            node_id: "dp-1".to_string(),
            namespace: "default".to_string(),
            tls_config: RemoteDiscoveryTlsConfig {
                tls_urls: Some(DpGrpcTlsConfig {
                    no_verify: true,
                    ..DpGrpcTlsConfig::default()
                }),
                plain_urls: None,
            },
        };
        let https_ctx = RemoteClusterPollContext {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            control_plane_url: "https://cp.remote.example:15010".to_string(),
            config: config.clone(),
        };
        let http_ctx = RemoteClusterPollContext {
            control_plane_url: "http://cp.remote.example:15010".to_string(),
            ..https_ctx.clone()
        };

        let secret = GrpcJwtSecret::new("secret-padding-for-32-char-min!!".to_string());
        assert!(
            NativeRemoteSource::new(&https_ctx, secret.clone())
                .tls_config
                .is_some()
        );
        assert!(
            NativeRemoteSource::new(&http_ctx, secret)
                .tls_config
                .is_none()
        );
    }

    struct MockSource {
        responses: Mutex<Vec<Result<RemoteClusterEndpoints, String>>>,
    }

    #[async_trait]
    impl RemoteServiceSource for MockSource {
        async fn fetch(&self) -> Result<RemoteClusterEndpoints, String> {
            let mut responses = self.responses.lock().expect("lock");
            if responses.is_empty() {
                return Err("no more mock responses".to_string());
            }
            responses.remove(0)
        }
    }

    #[tokio::test]
    async fn discovery_loop_installs_then_keeps_last_good_on_failure() {
        let store = RemoteEndpointStore::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let source = Arc::new(MockSource {
            responses: Mutex::new(vec![
                Ok(RemoteClusterEndpoints {
                    workloads: vec![workload(
                        "spiffe://remote.local/ns/default/sa/a",
                        "reviews",
                        "10.2.0.1",
                        None,
                    )],
                    services: vec![],
                }),
                Err("transient".to_string()),
            ]),
        });

        let ctx = RemoteClusterPollContext {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: Some("net2".to_string()),
            control_plane_url: "https://cp.remote.example:15010".to_string(),
            config: RemoteDiscoveryConfig {
                // Tiny interval so the loop reaches the second (failing) poll
                // quickly; the test shuts it down right after.
                poll_interval: Duration::from_millis(20),
                request_timeout: Duration::from_secs(1),
                jwt_secret: None,
                node_id: "dp-1".to_string(),
                namespace: "default".to_string(),
                tls_config: RemoteDiscoveryTlsConfig::default(),
            },
        };

        let task_store = store.clone();
        let task_gen = store.register_cluster("west");
        let handle = tokio::spawn(async move {
            remote_discovery_loop(ctx, source, task_store, shutdown_rx, task_gen).await
        });

        // Wait for the first successful install.
        let mut rx = store.subscribe();
        tokio::time::timeout(Duration::from_secs(2), rx.changed())
            .await
            .expect("install event")
            .expect("revision channel open");
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1
        );

        // The remote workload was tagged with the synthetic locality.
        let snap = store.snapshot();
        let entry = snap.clusters.get("west").expect("west entry");
        assert_eq!(
            entry.endpoints.workloads[0].locality.as_deref(),
            Some("remote-west/net2")
        );

        // Let the second (failing) poll run; the last-good snapshot survives.
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            store
                .snapshot()
                .clusters
                .values()
                .map(|entry| entry.endpoints.workloads.len())
                .sum::<usize>(),
            1,
            "a failed poll must keep the last-good endpoints"
        );

        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    /// F6: a stale task whose cluster was removed (generation retired) cannot
    /// reinstall endpoints after removal. Simulates the abort→install race:
    /// task fetches successfully but `remove` runs before the task calls
    /// `install`. With the generation guard the install must be a no-op.
    #[test]
    fn install_after_remove_is_blocked_by_generation_check() {
        let store = RemoteEndpointStore::new();
        // Register "west" and grab its generation (simulates start_cluster).
        let stale_gen = store.register_cluster("west");
        // Now remove the cluster (simulates trust withdrawal / reconcile remove).
        store.remove("west");
        // The stale task completes its fetch and tries to install.
        let entry = RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            endpoints: RemoteClusterEndpoints {
                workloads: vec![workload(
                    "spiffe://remote.local/ns/default/sa/stale",
                    "reviews",
                    "10.2.0.99",
                    None,
                )],
                services: vec![],
            },
            fetched_at_unix_seconds: 1,
        };
        // The install must be silently dropped — the generation slot is gone.
        store.install(entry, stale_gen);
        assert!(
            store.snapshot().is_empty(),
            "install with retired generation must not reinstate removed cluster"
        );
        assert!(
            !store.has_first_success(),
            "first_ready must not be set by a generation-blocked install"
        );
    }

    /// F2: no-op polls (identical endpoints) must not bump the revision or
    /// wake the slice-apply task.
    #[test]
    fn install_with_identical_endpoints_does_not_bump_revision() {
        let store = RemoteEndpointStore::new();
        let mut rx = store.subscribe();
        let endpoints = RemoteClusterEndpoints {
            workloads: vec![workload(
                "spiffe://remote.local/ns/default/sa/a",
                "reviews",
                "10.2.0.1",
                Some("remote-west"),
            )],
            services: vec![],
        };
        let entry = || RemoteClusterEntry {
            cluster_name: "west".to_string(),
            trust_domain: td("remote.local"),
            network: None,
            endpoints: endpoints.clone(),
            fetched_at_unix_seconds: 1,
        };
        // First install: should bump the revision.
        store.install_for_test(entry());
        assert!(
            rx.has_changed().unwrap(),
            "first install must bump revision"
        );
        rx.mark_unchanged();
        // Re-register to match the generation tracking (simulates the same
        // task running its next poll with identical results).
        let same_gen = store.register_cluster("west");
        store.install(entry(), same_gen);
        assert!(
            !rx.has_changed().unwrap(),
            "no-op poll with identical endpoints must not bump revision"
        );
    }
}

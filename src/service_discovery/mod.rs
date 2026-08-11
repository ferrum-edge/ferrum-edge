//! Service discovery for dynamic upstream target resolution.
//!
//! Provides background polling of external service registries (DNS-SD,
//! Kubernetes, Consul) to discover backend targets for upstreams. Discovered
//! targets are merged with static targets and pushed into the LoadBalancerCache
//! via atomic updates, keeping the hot proxy path lock-free.
//!
//! Provider-specific blocking-query cursors (Consul `X-Consul-Index`) travel
//! with each [`DiscoverySnapshot`] and are committed only after shared target
//! admission and successful publication by the discovery manager.

pub mod consul;
pub mod dns_sd;
pub mod http_body;
pub mod kubernetes;
pub mod mesh;

use crate::config::types::{
    GatewayConfig, MAX_TARGET_WEIGHT, SdProvider, ServiceDiscoveryConfig, Upstream, UpstreamTarget,
};
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::load_balancer::{LoadBalancerCache, target_host_port_key};
use crate::plugins::PluginHttpClient;
use crate::request_epoch::RequestEpochStore;
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// How long to wait for a task to exit after signaling before falling back to abort.
const TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// A running service discovery task with its cancellation handle.
struct TaskEntry {
    /// Per-task cancel signal. Sending `true` tells the loop to exit.
    cancel_tx: tokio::sync::watch::Sender<bool>,
    /// The spawned task handle — used for join or last-resort abort.
    handle: JoinHandle<()>,
}

/// Pending provider cursor update produced with a successfully parsed snapshot.
///
/// Dropping without [`DiscoveryCursorCommit::commit`] retains the previously
/// committed cursor. Only the discovery manager (via
/// [`apply_discovered_snapshot`]) may commit after shared admission and
/// successful publication — or after confirming an already-installed snapshot.
pub struct DiscoveryCursorCommit {
    slot: std::sync::Arc<std::sync::atomic::AtomicU64>,
    index: u64,
}

impl DiscoveryCursorCommit {
    /// Create a commit handle for a shared atomic cursor slot.
    pub(crate) fn new(slot: std::sync::Arc<std::sync::atomic::AtomicU64>, index: u64) -> Self {
        Self { slot, index }
    }

    /// Index that will be stored on [`commit`](Self::commit).
    pub(crate) fn index(&self) -> u64 {
        self.index
    }

    /// Persist the candidate index as the next blocking-query cursor.
    ///
    /// Crate-private so external `ServiceDiscoverer` callers cannot commit
    /// before load-balancer publication.
    pub(crate) fn commit(self) {
        use std::sync::atomic::Ordering;
        let previous = self.slot.load(Ordering::Relaxed);
        self.slot.store(self.index, Ordering::Relaxed);
        let registry = crate::plugins::prometheus_metrics::global_registry();
        if self.index < previous {
            registry.record_service_discovery_cursor_rollback();
            warn!(
                previous_index = previous,
                new_index = self.index,
                reason = "consul_index_rollback",
                "Service discovery: blocking-query cursor rolled back after admitted snapshot (registry likely restarted)"
            );
        } else if self.index > previous {
            registry.record_service_discovery_cursor_advance();
            debug!(
                previous_index = previous,
                new_index = self.index,
                reason = "consul_index_advance",
                "Service discovery: blocking-query cursor advanced after admitted snapshot"
            );
        }
    }
}

/// Typed snapshot admission policy. Carried with each poll result so Consul
/// atomic cursor rules do not change DNS-SD / Kubernetes / mesh semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotAdmissionPolicy {
    /// Pre-PR behavior: after shared filtering, an empty target set is accepted
    /// (including when every normalized entry was removed).
    AcceptFilteredEmpty,
    /// Consul atomic cursor admission: distinguish a legitimate empty catalog
    /// (`provider_item_count == 0`) from a non-empty provider payload whose
    /// every entry was rejected during provider normalization or shared
    /// host/egress admission.
    AtomicCursor {
        /// Raw provider catalog item count before provider normalization
        /// (Consul JSON array length).
        provider_item_count: usize,
    },
}

/// Successfully parsed discovery poll result.
///
/// Targets and optional cursor stay associated until the manager admits and
/// installs (or confirms) this exact snapshot. Dropping without a manager
/// commit retains the prior cursor. Ordinary callers cannot detach the cursor
/// or swap the target set while keeping the pending index.
pub struct DiscoverySnapshot {
    targets: Vec<UpstreamTarget>,
    cursor: Option<DiscoveryCursorCommit>,
    admission_policy: SnapshotAdmissionPolicy,
}

impl DiscoverySnapshot {
    /// Snapshot with no provider cursor (DNS-SD, Kubernetes, mesh).
    pub fn from_targets(targets: Vec<UpstreamTarget>) -> Self {
        Self {
            targets,
            cursor: None,
            admission_policy: SnapshotAdmissionPolicy::AcceptFilteredEmpty,
        }
    }

    /// Consul snapshot paired with a pending cursor and atomic admission policy.
    pub(crate) fn with_atomic_cursor(
        targets: Vec<UpstreamTarget>,
        provider_item_count: usize,
        cursor: DiscoveryCursorCommit,
    ) -> Self {
        Self {
            targets,
            cursor: Some(cursor),
            admission_policy: SnapshotAdmissionPolicy::AtomicCursor {
                provider_item_count,
            },
        }
    }

    /// Consul snapshot when `X-Consul-Index` was absent/unusable (no cursor).
    pub(crate) fn with_atomic_targets(
        targets: Vec<UpstreamTarget>,
        provider_item_count: usize,
    ) -> Self {
        Self {
            targets,
            cursor: None,
            admission_policy: SnapshotAdmissionPolicy::AtomicCursor {
                provider_item_count,
            },
        }
    }

    /// Provider-normalized targets (before shared host/egress admission).
    #[allow(dead_code)] // exercised by external tests; dead in the binary target
    pub fn targets(&self) -> &[UpstreamTarget] {
        &self.targets
    }

    /// Pending blocking-query index for this snapshot, if any.
    pub fn pending_cursor_index(&self) -> Option<u64> {
        self.cursor.as_ref().map(DiscoveryCursorCommit::index)
    }

    /// Admission policy carried with this snapshot.
    #[allow(dead_code)] // exercised by external unit tests; dead in the binary target
    pub fn admission_policy(&self) -> SnapshotAdmissionPolicy {
        self.admission_policy
    }
}

impl std::fmt::Debug for DiscoverySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoverySnapshot")
            .field("target_count", &self.targets.len())
            .field("pending_cursor_index", &self.pending_cursor_index())
            .field("admission_policy", &self.admission_policy)
            .finish()
    }
}

impl std::ops::Deref for DiscoverySnapshot {
    type Target = [UpstreamTarget];

    fn deref(&self) -> &Self::Target {
        &self.targets
    }
}

/// Result of shared target admission for a parsed discovery snapshot.
pub enum SnapshotAdmission {
    /// Snapshot may be published; the manager commits `cursor` only after
    /// publication succeeds (or when the admitted set already matches an
    /// installed snapshot).
    Accepted {
        targets: Vec<UpstreamTarget>,
        cursor: Option<DiscoveryCursorCommit>,
    },
    /// Snapshot rejected atomically; the provider cursor must not advance and
    /// last-known targets must be retained.
    Rejected {
        /// Bounded structured reason for logs/metrics correlation.
        reason: &'static str,
        /// Candidate blocking-query index from the rejected snapshot, if any.
        /// Retained only for deduplicated diagnostics — never committed.
        candidate_index: Option<u64>,
        /// Raw provider catalog item count (bounded diagnostic field).
        provider_items: usize,
        /// Provider-normalized target count before shared host/egress filtering.
        normalized_targets: usize,
    },
}

/// Apply shared host/egress validation and the snapshot's typed admission
/// policy.
///
/// - [`SnapshotAdmissionPolicy::AcceptFilteredEmpty`] preserves pre-PR DNS-SD /
///   Kubernetes / mesh behavior (empty after filtering is accepted).
/// - [`SnapshotAdmissionPolicy::AtomicCursor`] accepts a legitimate empty
///   Consul catalog (`provider_item_count == 0`) and mixed subsets, but rejects
///   a non-empty provider payload that yields zero admitted targets.
///
/// Operator-facing rejection warnings are emitted by
/// [`apply_discovered_snapshot`] with bounded duplicate suppression. This
/// function only classifies admission.
pub fn admit_discovered_snapshot(
    upstream_id: &str,
    provider_name: &str,
    snapshot: DiscoverySnapshot,
    backend_allow_ips: crate::config::BackendEgressPolicy,
) -> SnapshotAdmission {
    let DiscoverySnapshot {
        targets: raw,
        cursor,
        admission_policy,
    } = snapshot;
    let candidate_index = cursor.as_ref().map(DiscoveryCursorCommit::index);

    match admission_policy {
        SnapshotAdmissionPolicy::AcceptFilteredEmpty => {
            let filtered =
                filter_discovered_targets(upstream_id, provider_name, raw, backend_allow_ips);
            // Propagate any pending cursor so commit still occurs strictly after
            // publication (DNS-SD / Kubernetes / mesh currently carry none).
            SnapshotAdmission::Accepted {
                targets: filtered,
                cursor,
            }
        }
        SnapshotAdmissionPolicy::AtomicCursor {
            provider_item_count,
        } => {
            if provider_item_count > 0 && raw.is_empty() {
                // Drop the pending cursor without committing (fail closed).
                drop(cursor);
                return SnapshotAdmission::Rejected {
                    reason: "provider_normalization_rejected",
                    candidate_index,
                    provider_items: provider_item_count,
                    normalized_targets: 0,
                };
            }
            let raw_len = raw.len();
            let filtered =
                filter_discovered_targets(upstream_id, provider_name, raw, backend_allow_ips);
            if provider_item_count > 0 && filtered.is_empty() {
                drop(cursor);
                return SnapshotAdmission::Rejected {
                    reason: "shared_admission_rejected",
                    candidate_index,
                    provider_items: provider_item_count,
                    normalized_targets: raw_len,
                };
            }
            SnapshotAdmission::Accepted {
                targets: filtered,
                cursor,
            }
        }
    }
}

/// Trait for service discovery providers.
#[async_trait::async_trait]
pub trait ServiceDiscoverer: Send + Sync {
    /// Discover current targets from the external registry.
    ///
    /// On success, any provider cursor in the snapshot must be committed by the
    /// manager only after shared admission and successful publication.
    async fn discover(&self) -> Result<DiscoverySnapshot, anyhow::Error>;
    /// Human-readable provider name for logging.
    fn provider_name(&self) -> &str;
}

/// Manages background service discovery tasks for all upstreams.
///
/// Each upstream with a `service_discovery` config gets a dedicated background
/// task that periodically polls its provider and updates the LoadBalancerCache
/// when targets change.
pub struct ServiceDiscoveryManager {
    /// Running tasks keyed by `namespace|upstream_id`.
    tasks: DashMap<String, TaskEntry>,
    load_balancer_cache: Arc<LoadBalancerCache>,
    request_epoch: Option<Arc<RequestEpochStore>>,
    dns_cache: DnsCache,
    health_checker: Arc<HealthChecker>,
    /// Shared HTTP client for Kubernetes and Consul discovery calls.
    /// Inherits the gateway's pool config, DNS cache, trust store, and
    /// `FERRUM_TLS_NO_VERIFY` setting.
    http_client: PluginHttpClient,
}

impl ServiceDiscoveryManager {
    pub fn new(
        load_balancer_cache: Arc<LoadBalancerCache>,
        dns_cache: DnsCache,
        health_checker: Arc<HealthChecker>,
        http_client: PluginHttpClient,
        request_epoch: Option<Arc<RequestEpochStore>>,
    ) -> Self {
        Self {
            tasks: DashMap::new(),
            load_balancer_cache,
            request_epoch,
            dns_cache,
            health_checker,
            http_client,
        }
    }

    /// Start service discovery tasks for all upstreams in the config that have
    /// service discovery configured.
    pub fn start(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        for upstream in &config.upstreams {
            if let Some(sd_config) = &upstream.service_discovery {
                self.start_upstream_task(upstream, sd_config, shutdown_rx.clone());
            }
        }
    }

    /// Reconcile running tasks with the current config. Stops tasks for removed
    /// upstreams and starts tasks for new/modified upstreams.
    ///
    /// Tasks are signaled to stop via their per-task cancel channel and given
    /// up to [`TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS`] to finish their current
    /// write before a last-resort `abort()`.
    pub fn reconcile(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        // Collect namespace-qualified upstream identities that should have SD tasks.
        let desired: std::collections::HashSet<String> = config
            .upstreams
            .iter()
            .filter(|u| u.service_discovery.is_some())
            .map(|u| service_discovery_task_key(&u.namespace, &u.id))
            .collect();

        // Stop tasks for removed upstreams
        let current_keys: Vec<String> = self.tasks.iter().map(|e| e.key().clone()).collect();
        for key in &current_keys {
            if !desired.contains(key)
                && let Some((_, entry)) = self.tasks.remove(key)
            {
                graceful_stop_task(entry, key);
            }
        }

        // Start/restart tasks for upstreams with SD config
        for upstream in &config.upstreams {
            if let Some(sd_config) = &upstream.service_discovery {
                // Stop existing task if any (config may have changed)
                let task_key = service_discovery_task_key(&upstream.namespace, &upstream.id);
                if let Some((_, entry)) = self.tasks.remove(&task_key) {
                    graceful_stop_task(entry, &task_key);
                }
                self.start_upstream_task(upstream, sd_config, shutdown_rx.clone());
            }
        }
    }

    /// Stop all running service discovery tasks gracefully.
    ///
    /// Signals every task via its cancel channel, then drains the map. Each
    /// task gets up to [`TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS`] to exit before
    /// a last-resort `abort()`.
    pub fn stop(&self) {
        // Signal all tasks first so they can begin exiting in parallel.
        for entry in self.tasks.iter() {
            let _ = entry.value().cancel_tx.send(true);
        }

        // Drain the map and collect entries for joining.
        let entries: Vec<(String, TaskEntry)> = self
            .tasks
            .iter()
            .map(|e| e.key().clone())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| self.tasks.remove(&id))
            .collect();

        // Spawn a single task that awaits all joins with timeout, then logs.
        if entries.is_empty() {
            info!("Service discovery: all tasks stopped");
            return;
        }
        tokio::spawn(async move {
            let timeout = std::time::Duration::from_secs(TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
            for (id, entry) in entries {
                let abort_handle = entry.handle.abort_handle();
                match tokio::time::timeout(timeout, entry.handle).await {
                    Ok(_) => {
                        debug!(
                            "Service discovery: task for upstream {} stopped gracefully",
                            id
                        );
                    }
                    Err(_) => {
                        warn!(
                            "Service discovery: task for upstream {} did not exit within {}s, aborting",
                            id, TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS
                        );
                        abort_handle.abort();
                    }
                }
            }
            info!("Service discovery: all tasks stopped");
        });
    }

    fn start_upstream_task(
        &self,
        upstream: &Upstream,
        sd_config: &ServiceDiscoveryConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        let upstream_id = upstream.id.as_str();
        let upstream_namespace = upstream.namespace.as_str();
        let discoverer: Box<dyn ServiceDiscoverer> = match sd_config.provider {
            SdProvider::DnsSd => {
                if let Some(dns_config) = &sd_config.dns_sd {
                    Box::new(dns_sd::DnsSdDiscoverer::new(
                        self.dns_cache.clone(),
                        dns_config.service_name.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has dns_sd provider but no dns_sd config",
                        upstream_id
                    );
                    return;
                }
            }
            SdProvider::Kubernetes => {
                if let Some(k8s_config) = &sd_config.kubernetes {
                    // Screen the in-cluster API endpoint before starting the
                    // poller: KubernetesDiscoverer reads KUBERNETES_SERVICE_HOST
                    // and dials `https://{host}:{port}` via the raw client
                    // (`.send()`), bypassing execute_request, and reqwest skips
                    // the resolver for an IP-literal host. A denied literal (e.g.
                    // a private API IP under `FERRUM_BACKEND_ALLOW_IPS=public`)
                    // must be rejected before the service-account bearer token is
                    // ever sent.
                    if let Ok(api_host) = std::env::var("KUBERNETES_SERVICE_HOST")
                        && let Some(ip) = api_host
                            .strip_prefix('[')
                            .and_then(|h| h.strip_suffix(']'))
                            .unwrap_or(api_host.as_str())
                            .parse::<IpAddr>()
                            .ok()
                        && let Some(reason) = self.http_client.backend_allow_ips().deny_reason(&ip)
                    {
                        warn!(
                            "Service discovery: upstream {} Kubernetes API host {} blocked by egress policy: {}",
                            upstream_id, api_host, reason
                        );
                        return;
                    }
                    Box::new(kubernetes::KubernetesDiscoverer::new(
                        self.http_client.get().clone(),
                        k8s_config.namespace.clone(),
                        k8s_config.service_name.clone(),
                        k8s_config.port_name.clone(),
                        k8s_config.label_selector.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has kubernetes provider but no kubernetes config",
                        upstream_id
                    );
                    return;
                }
            }
            SdProvider::Consul => {
                if let Some(consul_config) = &sd_config.consul {
                    // Screen the Consul API endpoint before starting the poller:
                    // the discoverer dials `address` via the raw client
                    // (`.send()`), bypassing execute_request's literal-IP guard,
                    // and reqwest skips the DnsCacheResolver for IP literals — so
                    // a denied literal address (e.g. http://169.254.169.254:8500,
                    // which would also leak any X-Consul-Token) must be rejected
                    // here. Hostname addresses are screened by the resolver when
                    // the client polls.
                    if let Ok(parsed) = url::Url::parse(&consul_config.address)
                        .or_else(|_| url::Url::parse(&format!("http://{}", consul_config.address)))
                        && let Err(e) = crate::plugins::utils::log_helpers::screen_url_host_egress(
                            "service_discovery.consul",
                            "address",
                            &parsed,
                            self.http_client.backend_allow_ips(),
                        )
                    {
                        warn!(
                            "Service discovery: upstream {} Consul address blocked by egress policy: {}",
                            upstream_id, e
                        );
                        return;
                    }
                    Box::new(consul::ConsulDiscoverer::new(
                        self.http_client.get().clone(),
                        consul_config.address.clone(),
                        consul_config.service_name.clone(),
                        consul_config.datacenter.clone(),
                        consul_config.tag.clone(),
                        consul_config.healthy_only,
                        consul_config.token.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has consul provider but no consul config",
                        upstream_id
                    );
                    return;
                }
            }
            SdProvider::Mesh => {
                if let Some(mesh_config) = &sd_config.mesh {
                    if let Some(request_epoch) = &self.request_epoch {
                        Box::new(mesh::MeshServiceDiscoverer::new(
                            request_epoch.clone(),
                            mesh_config.service_name.clone(),
                            mesh_config
                                .namespace
                                .clone()
                                .unwrap_or_else(|| upstream_namespace.to_string()),
                            mesh_config.port,
                            sd_config.default_weight,
                            mesh_config.topology,
                        ))
                    } else {
                        warn!(
                            "Service discovery: upstream {} has mesh provider but no request epoch is available",
                            upstream_id
                        );
                        return;
                    }
                } else {
                    warn!(
                        "Service discovery: upstream {} has mesh provider but no mesh config",
                        upstream_id
                    );
                    return;
                }
            }
        };

        let poll_interval = match sd_config.provider {
            SdProvider::DnsSd => sd_config
                .dns_sd
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
            SdProvider::Kubernetes => sd_config
                .kubernetes
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
            SdProvider::Consul => sd_config
                .consul
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
            SdProvider::Mesh => sd_config
                .mesh
                .as_ref()
                .map_or(30, |c| c.poll_interval_seconds),
        };

        let upstream_id_owned = upstream_id.to_string();
        let upstream_namespace_owned = upstream_namespace.to_string();
        let lb_cache = self.load_balancer_cache.clone();
        let request_epoch = self.request_epoch.clone();
        let static_targets = upstream.targets.clone();
        let algorithm = upstream.algorithm;
        let hash_on = upstream.hash_on.clone();
        let dns_cache = self.dns_cache.clone();
        let health_checker = self.health_checker.clone();

        // Per-task cancel channel — signaled on reconcile/stop.
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(async move {
            run_discovery_loop(
                &upstream_namespace_owned,
                &upstream_id_owned,
                discoverer,
                &lb_cache,
                request_epoch,
                &static_targets,
                algorithm,
                hash_on,
                poll_interval,
                shutdown_rx,
                cancel_rx,
                &dns_cache,
                &health_checker,
            )
            .await;
        });

        let task_key = service_discovery_task_key(upstream_namespace, upstream_id);
        self.tasks.insert(task_key, TaskEntry { cancel_tx, handle });
        info!(
            "Service discovery: started {} task for upstream {} (poll interval: {}s)",
            sd_config.provider.as_str(),
            upstream_id,
            poll_interval,
        );
    }
}

/// Namespace-qualified ownership key for a service-discovery task.
///
/// Upstream IDs are only unique within a namespace. Using the bare ID here
/// would overwrite one tenant's task handle when another tenant configured the
/// same ID, leaving the displaced poller unmanaged.
pub(crate) fn service_discovery_task_key(namespace: &str, upstream_id: &str) -> String {
    crate::config::db_backend::namespaced_runtime_key(namespace, upstream_id)
}

impl Drop for ServiceDiscoveryManager {
    fn drop(&mut self) {
        self.stop();
    }
}

impl SdProvider {
    pub fn as_str(&self) -> &str {
        match self {
            SdProvider::DnsSd => "dns_sd",
            SdProvider::Kubernetes => "kubernetes",
            SdProvider::Consul => "consul",
            SdProvider::Mesh => "mesh",
        }
    }
}

/// Signal a single task to stop and spawn a background join/abort.
///
/// This is used during reconcile where we cannot `.await` (the method is
/// synchronous). The task is signaled immediately; a detached future handles
/// the join with a timeout and last-resort abort.
fn graceful_stop_task(entry: TaskEntry, upstream_id: &str) {
    let _ = entry.cancel_tx.send(true);
    graceful_join_or_abort(entry, upstream_id);
}

/// Wait (blocking-compatible) for a task to finish after its cancel signal
/// has been sent. If the task does not exit within
/// [`TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS`], abort it as a last resort.
///
/// Spawns a detached tokio task so the caller does not need to `.await`.
fn graceful_join_or_abort(entry: TaskEntry, upstream_id: &str) {
    let id = upstream_id.to_string();
    // Grab an AbortHandle before consuming the JoinHandle so we can force-
    // kill the task if the timeout expires (dropping a JoinHandle merely
    // detaches the task — it does not abort it).
    let abort_handle = entry.handle.abort_handle();
    tokio::spawn(async move {
        let timeout = std::time::Duration::from_secs(TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
        match tokio::time::timeout(timeout, entry.handle).await {
            Ok(_) => {
                debug!(
                    "Service discovery: task for upstream {} stopped gracefully",
                    id
                );
            }
            Err(_) => {
                warn!(
                    "Service discovery: task for upstream {} did not exit within {}s, aborting",
                    id, TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS
                );
                abort_handle.abort();
            }
        }
    });
}

/// Wait for a cancellation signal on a per-task cancel watch channel.
async fn wait_for_cancel(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            // Sender dropped — treat as cancel.
            return;
        }
    }
}

/// Wait for a shutdown signal on a watch channel.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Whether `proxy` routes to the discovered upstream identity.
///
/// Upstream ids are per-namespace, so BOTH the namespace and the id must match.
/// Matching on `upstream_id` alone would let a discovery update in one tenant
/// prune the same-id upstream's passive-health state in a *different* tenant's
/// proxy (issue #3094 follow-up).
pub(crate) fn proxy_targets_discovered_upstream(
    proxy: &crate::config::types::Proxy,
    upstream_namespace: &str,
    upstream_id: &str,
) -> bool {
    proxy.namespace == upstream_namespace && proxy.upstream_id.as_deref() == Some(upstream_id)
}

/// Bounded key for suppressing duplicate all-rejected warnings while a Consul
/// catalog stays rejected at the same candidate index for the same reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RejectionWarnKey {
    reason: &'static str,
    candidate_index: Option<u64>,
}

/// Per-task state retained across discovery poll iterations.
#[derive(Debug, Default)]
pub(crate) struct DiscoveryLoopState {
    /// Last admitted discovered targets that this loop installed (or confirmed).
    last_discovered: Vec<UpstreamTarget>,
    /// Whether this loop has successfully published/confirmed at least one
    /// admitted snapshot. The first admitted snapshot must take the publication
    /// path even when empty so prior LB cache contents cannot outlive an
    /// uncommitted empty Consul catalog.
    snapshot_installed: bool,
    /// Last rejection warn already emitted for this task. Suppresses sustained
    /// duplicate warnings for the same reason/candidate without unbounded
    /// cardinality (fixed reason strings + optional u64 index only).
    last_rejection_warn: Option<RejectionWarnKey>,
}

impl DiscoveryLoopState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn snapshot_installed(&self) -> bool {
        self.snapshot_installed
    }

    #[allow(dead_code)] // reached via `_test_support` from the external test crate
    pub(crate) fn last_discovered(&self) -> &[UpstreamTarget] {
        &self.last_discovered
    }
}

/// Control flow after processing one discovery poll result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiscoveryApplyControl {
    /// Keep polling.
    Continue,
    /// Exit the discovery task (cancel/shutdown observed around publication).
    Stop,
}

/// Exact production admission → publication → cursor-commit pipeline for one
/// successful `discover()` result. Used by [`run_discovery_loop`] and exposed
/// to external tests through `_test_support` so coverage cannot bypass the
/// manager boundary with an early public cursor commit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_discovered_snapshot(
    upstream_namespace: &str,
    upstream_id: &str,
    provider_name: &str,
    snapshot: DiscoverySnapshot,
    state: &mut DiscoveryLoopState,
    lb_cache: &LoadBalancerCache,
    request_epoch: &Option<Arc<RequestEpochStore>>,
    static_targets: &[UpstreamTarget],
    algorithm: crate::config::types::LoadBalancerAlgorithm,
    hash_on: &Option<String>,
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
    shutdown_rx: &Option<tokio::sync::watch::Receiver<bool>>,
    dns_cache: &DnsCache,
    health_checker: &HealthChecker,
) -> DiscoveryApplyControl {
    let admission = admit_discovered_snapshot(
        upstream_id,
        provider_name,
        snapshot,
        dns_cache.backend_allow_ips(),
    );
    let (discovered, pending_cursor) = match admission {
        SnapshotAdmission::Accepted { targets, cursor } => {
            state.last_rejection_warn = None;
            (targets, cursor)
        }
        SnapshotAdmission::Rejected {
            reason,
            candidate_index,
            provider_items,
            normalized_targets,
        } => {
            let registry = crate::plugins::prometheus_metrics::global_registry();
            match reason {
                "provider_normalization_rejected" => {
                    registry.record_service_discovery_provider_normalization_rejected();
                }
                "shared_admission_rejected" => {
                    registry.record_service_discovery_shared_admission_rejected();
                }
                _ => {}
            }

            let warn_key = RejectionWarnKey {
                reason,
                candidate_index,
            };
            if state.last_rejection_warn != Some(warn_key) {
                match reason {
                    "provider_normalization_rejected" => {
                        warn!(
                            upstream = %upstream_id,
                            provider = provider_name,
                            provider_items,
                            reason,
                            "Service discovery: non-empty provider catalog produced zero normalized targets; retaining last-known targets and blocking-query cursor"
                        );
                    }
                    "shared_admission_rejected" => {
                        warn!(
                            upstream = %upstream_id,
                            provider = provider_name,
                            provider_items,
                            normalized_targets,
                            reason,
                            "Service discovery: snapshot rejected by shared target validation; retaining last-known targets and blocking-query cursor"
                        );
                    }
                    _ => {
                        warn!(
                            upstream = %upstream_id,
                            provider = provider_name,
                            reason,
                            "Service discovery: snapshot rejected; retaining last-known targets and blocking-query cursor"
                        );
                    }
                }
                state.last_rejection_warn = Some(warn_key);
            } else {
                debug!(
                    upstream = %upstream_id,
                    provider = provider_name,
                    reason,
                    "Service discovery: snapshot not admitted (same rejection as prior poll); retaining last-known targets and blocking-query cursor"
                );
            }
            return DiscoveryApplyControl::Continue;
        }
    };

    // A canceled task may have completed its discover() call after the cancel
    // signal fired. Check before publishing so we never overwrite the new
    // config's LB state with stale data. Drop the pending cursor without
    // committing.
    if *cancel_rx.borrow() {
        info!(
            "Service discovery: task for upstream {} canceled during discovery, discarding results",
            upstream_id,
        );
        return DiscoveryApplyControl::Stop;
    }
    if let Some(rx) = shutdown_rx
        && *rx.borrow()
    {
        info!(
            "Service discovery: shutting down task for upstream {} during discovery, discarding results",
            upstream_id,
        );
        return DiscoveryApplyControl::Stop;
    }

    // First admitted snapshot always publishes (even when empty) so prior
    // dynamic targets in the LB cache cannot remain installed while a Consul
    // empty catalog cursor would otherwise commit against a fresh empty local
    // vector. Later polls may skip publication when the admitted set already
    // matches the installed discovered set — and may still commit the cursor.
    let needs_publish =
        !state.snapshot_installed || !targets_equal(&discovered, &state.last_discovered);

    if needs_publish {
        if !state.snapshot_installed {
            // Avoid the misleading `0 -> 0 targets changed` wording for an
            // intentional first install (including an empty catalog that clears
            // stale shared LB state after task restart/reconcile).
            info!(
                "Service discovery [{}]: upstream {} installing initial discovered snapshot ({} discovered targets)",
                provider_name,
                upstream_id,
                discovered.len(),
            );
        } else {
            info!(
                "Service discovery [{}]: upstream {} targets changed ({} -> {} discovered targets)",
                provider_name,
                upstream_id,
                state.last_discovered.len(),
                discovered.len(),
            );
        }

        let merged = merge_targets(static_targets, &discovered);

        let hostnames: Vec<(String, Option<String>, Option<u64>)> = discovered
            .iter()
            .map(|t| (t.host.clone(), None, None))
            .collect();
        if !hostnames.is_empty() {
            dns_cache.warmup(hostnames).await;
        }

        // Cancellation could have fired during the DNS warmup await.
        if *cancel_rx.borrow() {
            debug!(
                "Service discovery: task for upstream {} canceled during DNS warmup, discarding results",
                upstream_id,
            );
            return DiscoveryApplyControl::Stop;
        }
        if let Some(rx) = shutdown_rx
            && *rx.borrow()
        {
            debug!(
                "Service discovery: shutting down task for upstream {} during DNS warmup, discarding results",
                upstream_id,
            );
            return DiscoveryApplyControl::Stop;
        }

        if let Some(epoch_store) = request_epoch {
            let published = epoch_store.update_load_balancer(
                |current| {
                    Some(LoadBalancerCache::build_update_targets_inner(
                        &current.load_balancer,
                        upstream_namespace,
                        upstream_id,
                        merged.clone(),
                        algorithm,
                        hash_on.clone(),
                    ))
                },
                |published| {
                    lb_cache.store_inner(Arc::clone(&published.load_balancer));
                },
            );
            if let Err(error) = published {
                warn!(
                    "Service discovery [{}]: upstream {} target publication failed: {}. Keeping last-known targets and blocking-query cursor.",
                    provider_name, upstream_id, error,
                );
                // Drop pending cursor without committing.
                return DiscoveryApplyControl::Continue;
            }
        } else {
            lb_cache.update_targets(
                upstream_namespace,
                upstream_id,
                merged.clone(),
                algorithm,
                hash_on.clone(),
            );
        }

        health_checker.remove_stale_targets(upstream_namespace, upstream_id, &merged);
        if let Some(epoch_store) = request_epoch {
            let epoch = epoch_store.load();
            for proxy in epoch.config.proxies.iter().filter(|proxy| {
                proxy_targets_discovered_upstream(proxy, upstream_namespace, upstream_id)
            }) {
                health_checker.remove_stale_passive_targets_for_proxy(
                    &proxy.namespace,
                    &proxy.id,
                    &merged,
                );
            }
        }

        state.last_discovered = discovered;
        state.snapshot_installed = true;
    }

    // Snapshot is installed (just published, or already matched after a prior
    // install). Commit the provider cursor for this exact admitted response.
    if let Some(cursor) = pending_cursor {
        cursor.commit();
    }

    DiscoveryApplyControl::Continue
}

/// Background discovery loop for a single upstream.
///
/// Exits when either the global `shutdown_rx` fires or the per-task
/// `cancel_rx` is signaled (e.g. during config reconcile).
#[allow(clippy::too_many_arguments)]
async fn run_discovery_loop(
    upstream_namespace: &str,
    upstream_id: &str,
    discoverer: Box<dyn ServiceDiscoverer>,
    lb_cache: &LoadBalancerCache,
    request_epoch: Option<Arc<RequestEpochStore>>,
    static_targets: &[UpstreamTarget],
    algorithm: crate::config::types::LoadBalancerAlgorithm,
    hash_on: Option<String>,
    poll_interval_seconds: u64,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    dns_cache: &DnsCache,
    health_checker: &HealthChecker,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(poll_interval_seconds));
    let mut state = DiscoveryLoopState::new();

    loop {
        // Wait for next tick, global shutdown, or per-task cancel.
        tokio::select! {
            _ = interval.tick() => {}
            _ = wait_for_cancel(cancel_rx.clone()) => {
                info!(
                    "Service discovery: task for upstream {} canceled (config reconcile)",
                    upstream_id,
                );
                return;
            }
            _ = async {
                if let Some(ref rx) = shutdown_rx {
                    wait_for_shutdown(rx.clone()).await;
                } else {
                    // No global shutdown channel — pend forever so the other
                    // branches drive the select.
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Service discovery: shutting down task for upstream {}", upstream_id);
                return;
            }
        }

        // Discover targets. Provider cursors (e.g. Consul X-Consul-Index) stay
        // pending until shared admission and publication succeed for this exact
        // snapshot — dropping the commit handle retains the prior cursor.
        match discoverer.discover().await {
            Ok(snapshot) => {
                match apply_discovered_snapshot(
                    upstream_namespace,
                    upstream_id,
                    discoverer.provider_name(),
                    snapshot,
                    &mut state,
                    lb_cache,
                    &request_epoch,
                    static_targets,
                    algorithm,
                    &hash_on,
                    &cancel_rx,
                    &shutdown_rx,
                    dns_cache,
                    health_checker,
                )
                .await
                {
                    DiscoveryApplyControl::Continue => {}
                    DiscoveryApplyControl::Stop => return,
                }
            }
            Err(e) => {
                warn!(
                    "Service discovery [{}]: upstream {} discovery failed: {}. Keeping last-known targets.",
                    discoverer.provider_name(),
                    upstream_id,
                    e,
                );
            }
        }
    }
}

/// Check if two target lists are equivalent (same host:port:policy-port:weight
/// and tags, ignoring order).
/// Uses borrowed tuples sorted in place to avoid per-poll string allocations while
/// preserving multiplicity (duplicate targets are compared correctly).
pub fn targets_equal(a: &[UpstreamTarget], b: &[UpstreamTarget]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Build sortable borrowed tuples — no String allocations.
    type TargetSortKey<'a> = (&'a str, u16, Option<u16>, u32, Vec<(&'a str, &'a str)>);

    fn to_key(t: &UpstreamTarget) -> TargetSortKey<'_> {
        let mut tag_pairs: Vec<(&str, &str)> = t
            .tags
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        tag_pairs.sort();
        (
            t.host.as_str(),
            t.port,
            t.service_port_policy_key,
            t.weight,
            tag_pairs,
        )
    }
    let mut a_keys: Vec<_> = a.iter().map(to_key).collect();
    let mut b_keys: Vec<_> = b.iter().map(to_key).collect();
    a_keys.sort();
    b_keys.sort();
    a_keys == b_keys
}

/// Merge static targets with discovered targets. If a discovered target has the
/// same host:port as a static target, the static target takes precedence (its
/// weight and tags are preserved).
pub fn merge_targets(
    static_targets: &[UpstreamTarget],
    discovered: &[UpstreamTarget],
) -> Vec<UpstreamTarget> {
    let static_keys: std::collections::HashSet<String> =
        static_targets.iter().map(target_host_port_key).collect();

    let mut merged = static_targets.to_vec();
    for target in discovered {
        let key = target_host_port_key(target);
        if !static_keys.contains(&key) {
            merged.push(target.clone());
        }
    }
    merged
}

/// Validate discovered targets before they become routable.
///
/// - Hostnames must pass the same hostname validator as proxy host entries.
/// - IP literals are accepted only when allowed by `FERRUM_BACKEND_ALLOW_IPS`.
/// - Ambient cross-cluster HBONE targets may carry an opaque synthetic
///   `target.host`; validate their real dial/CONNECT authority tags instead.
pub fn filter_discovered_targets(
    upstream_id: &str,
    provider_name: &str,
    targets: Vec<UpstreamTarget>,
    backend_allow_ips: crate::config::BackendEgressPolicy,
) -> Vec<UpstreamTarget> {
    targets
        .into_iter()
        .filter(
            |target| match validate_discovered_target_host(target, &backend_allow_ips) {
            Ok(()) => true,
            Err(reason) => {
                warn!(
                    "Service discovery [{}]: upstream {} skipping invalid discovered target {}:{} ({})",
                    provider_name, upstream_id, target.host, target.port, reason
                );
                false
            }
            },
        )
        .collect()
}

fn validate_discovered_target_host(
    target: &UpstreamTarget,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
) -> Result<(), String> {
    if is_synthetic_cross_cluster_hbone_target(target) {
        let dial_host = crate::proxy::hbone_pool::target_hbone_dial_host(target)
            .map_err(|err| err.to_string())?;
        validate_discovered_real_host(
            dial_host,
            backend_allow_ips,
            crate::proxy::hbone_pool::HBONE_DIAL_HOST_TAG,
        )?;
        let authority_host = crate::proxy::hbone_pool::target_hbone_authority_host(target)
            .map_err(|err| err.to_string())?;
        validate_discovered_real_host(
            authority_host,
            backend_allow_ips,
            crate::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG,
        )?;
        return Ok(());
    }

    validate_discovered_real_host(target.host.as_str(), backend_allow_ips, "host")
}

fn validate_discovered_real_host(
    host: &str,
    backend_allow_ips: &crate::config::BackendEgressPolicy,
    label: &str,
) -> Result<(), String> {
    if let Ok(addr) = host.parse::<IpAddr>() {
        if let Some(reason) = backend_allow_ips.deny_reason(&addr) {
            return Err(format!(
                "{label} IP denied by backend egress policy: {reason}"
            ));
        }
        return Ok(());
    }
    crate::config::types::validate_host_entry(host).map_err(|reason| format!("{label}: {reason}"))
}

fn is_synthetic_cross_cluster_hbone_target(target: &UpstreamTarget) -> bool {
    target
        .host
        .starts_with(crate::proxy::hbone_pool::HBONE_CROSS_CLUSTER_SYNTHETIC_HOST_PREFIX)
        && crate::proxy::hbone_pool::target_hbone_enabled(target)
        && crate::proxy::hbone_pool::target_hbone_cross_cluster(target)
        && target
            .tags
            .contains_key(crate::proxy::hbone_pool::HBONE_DIAL_HOST_TAG)
        && target
            .tags
            .contains_key(crate::proxy::hbone_pool::HBONE_AUTHORITY_HOST_TAG)
        && target
            .tags
            .contains_key(crate::proxy::mesh_mtls_pool::MESH_EASTWEST_SNI_TAG)
        && target
            .tags
            .contains_key(crate::proxy::mesh_mtls_pool::MESH_TRUST_DOMAIN_TAG)
}

/// Admit an untrusted registry-reported port into a dialable `u16`.
///
/// Accepts `1..=u16::MAX`. Rejects `0` and any value outside that range so
/// narrowing casts cannot wrap (for example `65537` must not become port `1`).
/// Aligns standalone Kubernetes EndpointSlice polling with the controller
/// path's nonzero / `<= u16::MAX` filter.
pub(crate) fn admit_registry_port(raw: u64) -> Option<u16> {
    u16::try_from(raw).ok().filter(|port| *port != 0)
}

/// Admit an untrusted Consul `Weights.Passing` value into a routable target weight.
///
/// Accepts `1..=MAX_TARGET_WEIGHT` — the same nonzero contract as static
/// targets and `ServiceDiscoveryConfig::default_weight`. Rejects zero and
/// values that would wrap or coerce under a narrowing cast.
///
/// Callers treat a *missing* `Weights` / `Passing` field separately by
/// applying `default_weight`; only an explicitly present value is passed here.
pub(crate) fn admit_registry_target_weight(raw: u64) -> Option<u32> {
    u32::try_from(raw)
        .ok()
        .filter(|weight| (1..=MAX_TARGET_WEIGHT).contains(weight))
}

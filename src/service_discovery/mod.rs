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
pub mod health;
pub mod http_body;
pub mod kubernetes;
pub mod mesh;

use crate::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, SdProvider, ServiceDiscoveryConfig,
    Upstream, UpstreamTarget,
};
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::load_balancer::{LoadBalancerCache, target_host_port_key};
use crate::plugins::PluginHttpClient;
use crate::request_epoch::RequestEpochStore;
use dashmap::DashMap;
use health::{
    DiscoveryFailureReason, DiscoveryStaleness, FencedPublish, FencedWithdrawal, WithdrawalAttempt,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// How long to wait for a task to exit after signaling before falling back to abort.
const TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// Immutable specification of one discovery task's material inputs.
///
/// Reconcile compares this instead of restarting unconditionally (issue #3722):
/// two configs that produce an equal spec produce an identical poller, so the
/// running generation is kept — preserving its provider cursor (Consul
/// `X-Consul-Index`), its in-flight registry call, and its staleness anchor.
///
/// Everything that materially changes the discoverer, its poll cadence, its
/// published target set, or its staleness policy belongs here. Manager-scoped
/// inputs (HTTP client, DNS cache, health checker, request epoch, egress
/// policy) are deliberately excluded: they are process-lifetime singletons that
/// cannot differ between two reconciles of the same process.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DiscoveryTaskSpec {
    namespace: String,
    upstream_id: String,
    /// Full provider configuration, including provider selection and poll
    /// interval.
    sd_config: ServiceDiscoveryConfig,
    /// Static targets merged under every published snapshot.
    static_targets: Vec<UpstreamTarget>,
    algorithm: LoadBalancerAlgorithm,
    hash_on: Option<String>,
    /// Resolved (not merely configured) staleness bound and expiry policy, so a
    /// changed poll interval or policy override replaces the task.
    staleness: DiscoveryStaleness,
    /// Whether this upstream requested unbounded retention without the process
    /// opt-in. Carried here rather than warned about during `build` so the
    /// operator message is emitted exactly once per started task generation
    /// (see [`health::resolve_upstream_staleness`]) instead of once per
    /// reconcile, including reconciles caused by unrelated config churn.
    unbounded_request_refused: bool,
}

impl DiscoveryTaskSpec {
    fn build(upstream: &Upstream, sd_config: &ServiceDiscoveryConfig) -> Self {
        let poll_interval = sd_poll_interval_seconds(sd_config);
        let resolved = health::resolve_upstream_staleness(
            sd_config.max_stale_seconds,
            sd_config.stale_policy,
            poll_interval,
        );
        Self {
            namespace: upstream.namespace.clone(),
            upstream_id: upstream.id.clone(),
            sd_config: sd_config.clone(),
            static_targets: upstream.targets.clone(),
            algorithm: upstream.algorithm,
            hash_on: upstream.hash_on.clone(),
            staleness: resolved.staleness,
            unbounded_request_refused: resolved.unbounded_request_refused,
        }
    }
}

/// A running service discovery supervisor with its cancellation handle.
struct TaskEntry {
    /// Per-task cancel signal. Sending `true` tells the supervisor and its
    /// poller to exit.
    cancel_tx: tokio::sync::watch::Sender<bool>,
    /// The spawned supervisor handle — used for join or last-resort abort.
    handle: JoinHandle<()>,
    /// Monotonic generation fencing this task against superseded restarts and
    /// publications.
    generation: u64,
    /// Material inputs this task was started from (issue #3722).
    spec: Arc<DiscoveryTaskSpec>,
}

/// Aborts a spawned task when the owning future is dropped.
///
/// The supervisor spawns its poller so a panic surfaces as a `JoinError`
/// instead of killing the supervisor. Dropping a `JoinHandle` only detaches, so
/// aborting a supervisor (graceful-stop timeout) would otherwise leak the
/// poller it was awaiting.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Why a poller loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryLoopExit {
    /// Per-task cancel signal observed (config reconcile / manager stop).
    Canceled,
    /// Global shutdown signal observed.
    Shutdown,
}

/// Poll interval for a provider configuration, matching each provider's default.
///
/// Floored at one second: `tokio::time::interval` panics on a zero period, and
/// a poller that panics on construction would otherwise burn its whole restart
/// budget before an operator saw the misconfiguration.
fn sd_poll_interval_seconds(sd_config: &ServiceDiscoveryConfig) -> u64 {
    sd_configured_poll_interval_seconds(sd_config).max(1)
}

fn sd_configured_poll_interval_seconds(sd_config: &ServiceDiscoveryConfig) -> u64 {
    match sd_config.provider {
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
    }
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
    /// Monotonic task generation counter. Every started task takes the next
    /// value; superseded generations can neither restart nor publish.
    next_generation: AtomicU64,
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
            next_generation: AtomicU64::new(1),
        }
    }

    /// Start service discovery tasks for all upstreams in the config that have
    /// service discovery configured.
    pub fn start(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        self.reconcile(config, shutdown_rx);
    }

    /// Reconcile running tasks with the current config.
    ///
    /// Tasks whose effective specification is unchanged are **kept running**
    /// (issue #3722): restarting them would drop each Consul poller's
    /// blocking-query cursor, cancel any in-flight registry call before it
    /// could publish, reset its staleness anchor, and generate an
    /// O(discovered upstreams) burst of registry traffic on every unrelated
    /// config change. Only removed, changed, and new upstreams are touched.
    ///
    /// Replaced/removed tasks are signaled through their per-task cancel channel
    /// and given up to [`TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS`] to finish their
    /// current write before a last-resort `abort()`.
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

        let mut kept = 0u64;
        let mut started = 0u64;
        let mut replaced = 0u64;
        let mut stopped = 0u64;

        // Stop tasks for removed upstreams
        let current_keys: Vec<String> = self.tasks.iter().map(|e| e.key().clone()).collect();
        for key in &current_keys {
            if !desired.contains(key)
                && let Some((_, entry)) = self.tasks.remove(key)
            {
                stopped += 1;
                graceful_stop_task(entry, key);
            }
        }

        for upstream in &config.upstreams {
            let Some(sd_config) = &upstream.service_discovery else {
                continue;
            };
            let task_key = service_discovery_task_key(&upstream.namespace, &upstream.id);
            let spec = Arc::new(DiscoveryTaskSpec::build(upstream, sd_config));

            // Decide under a short-lived read borrow; never hold a DashMap ref
            // across the `remove` below.
            let unchanged = self
                .tasks
                .get(&task_key)
                .is_some_and(|entry| *entry.spec == *spec && !entry.handle.is_finished());
            if unchanged {
                kept += 1;
                continue;
            }

            let was_running = match self.tasks.remove(&task_key) {
                Some((_, entry)) => {
                    replaced += 1;
                    graceful_stop_task(entry, &task_key);
                    true
                }
                None => false,
            };
            // A rejected provider configuration (missing provider block, denied
            // registry endpoint) starts nothing; it must not be counted as a
            // started task.
            if self.start_upstream_task(upstream, sd_config, spec, shutdown_rx.clone())
                && !was_running
            {
                started += 1;
            }
        }

        let registry = crate::plugins::prometheus_metrics::global_registry();
        registry.record_service_discovery_tasks_kept(kept);
        registry.record_service_discovery_tasks_started(started);
        registry.record_service_discovery_tasks_replaced(replaced);
        registry.record_service_discovery_tasks_stopped(stopped);
        if started > 0 || replaced > 0 || stopped > 0 {
            info!(
                kept,
                started, replaced, stopped, "Service discovery: reconciled discovery tasks"
            );
        } else {
            debug!(
                kept,
                "Service discovery: reconcile kept every running discovery task"
            );
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
                let generation = entry.generation;
                let abort_handle = entry.handle.abort_handle();
                let outcome = tokio::time::timeout(timeout, entry.handle).await;
                report_task_join(&id, generation, outcome, &abort_handle);
            }
            info!("Service discovery: all tasks stopped");
        });
    }

    fn start_upstream_task(
        &self,
        upstream: &Upstream,
        sd_config: &ServiceDiscoveryConfig,
        spec: Arc<DiscoveryTaskSpec>,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> bool {
        let upstream_id = upstream.id.as_str();
        let upstream_namespace = upstream.namespace.as_str();
        let discoverer: Arc<dyn ServiceDiscoverer> = match sd_config.provider {
            SdProvider::DnsSd => {
                if let Some(dns_config) = &sd_config.dns_sd {
                    Arc::new(dns_sd::DnsSdDiscoverer::new(
                        self.dns_cache.clone(),
                        dns_config.service_name.clone(),
                        sd_config.default_weight,
                    ))
                } else {
                    warn!(
                        "Service discovery: upstream {} has dns_sd provider but no dns_sd config",
                        upstream_id
                    );
                    return false;
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
                        return false;
                    }
                    Arc::new(kubernetes::KubernetesDiscoverer::new(
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
                    return false;
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
                        return false;
                    }
                    Arc::new(consul::ConsulDiscoverer::new(
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
                    return false;
                }
            }
            SdProvider::Mesh => {
                if let Some(mesh_config) = &sd_config.mesh {
                    if let Some(request_epoch) = &self.request_epoch {
                        Arc::new(mesh::MeshServiceDiscoverer::new(
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
                        return false;
                    }
                } else {
                    warn!(
                        "Service discovery: upstream {} has mesh provider but no mesh config",
                        upstream_id
                    );
                    return false;
                }
            }
        };

        let poll_interval = sd_poll_interval_seconds(sd_config);
        let task_key = service_discovery_task_key(upstream_namespace, upstream_id);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);

        // Registering here (before the spawn) makes this generation the current
        // owner immediately, so a superseded supervisor still winding down can
        // neither restart nor publish under the same key.
        health::register_task(
            &task_key,
            generation,
            sd_config.provider.as_str(),
            spec.staleness,
        );

        let ctx = Arc::new(DiscoveryTaskContext {
            key: task_key.clone(),
            generation,
            upstream_namespace: upstream_namespace.to_string(),
            upstream_id: upstream_id.to_string(),
            provider_name: sd_config.provider.as_str(),
            lb_cache: self.load_balancer_cache.clone(),
            request_epoch: self.request_epoch.clone(),
            static_targets: upstream.targets.clone(),
            algorithm: upstream.algorithm,
            hash_on: upstream.hash_on.clone(),
            dns_cache: self.dns_cache.clone(),
            health_checker: self.health_checker.clone(),
            poll_interval_seconds: poll_interval,
            staleness: spec.staleness,
        });

        // Per-task cancel channel — signaled on reconcile/stop.
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

        let handle = tokio::spawn(supervise_discovery_task(
            ctx,
            discoverer,
            shutdown_rx,
            cancel_rx,
        ));

        let max_stale_seconds = spec.staleness.max_stale_seconds();
        let stale_policy = spec.staleness.policy.as_str();
        // Emitted here, not from the staleness resolver: reconcile rebuilds
        // every discovery-backed upstream's spec on every config change, so
        // warning at resolve time repeated this message for unrelated churn.
        // A started generation is exactly one active occurrence of the
        // condition — an upstream that keeps the invalid request across a
        // spec-preserving reconcile keeps its running task and stays quiet,
        // and a corrected/removed upstream that later reintroduces the request
        // starts a new generation and warns again. No warning-key cache and no
        // new metric labels are involved.
        if spec.unbounded_request_refused {
            warn!(
                upstream = %upstream_id,
                namespace = %upstream_namespace,
                generation,
                effective_max_stale_seconds = max_stale_seconds,
                "Service discovery: upstream requested unbounded last-known retention \
                 (max_stale_seconds=0) without FERRUM_SERVICE_DISCOVERY_ALLOW_UNBOUNDED_STALE=true; \
                 applying the bounded default"
            );
        }
        self.tasks.insert(
            task_key,
            TaskEntry {
                cancel_tx,
                handle,
                generation,
                spec,
            },
        );
        info!(
            upstream = %upstream_id,
            provider = sd_config.provider.as_str(),
            poll_interval_seconds = poll_interval,
            generation,
            max_stale_seconds,
            stale_policy,
            "Service discovery: started discovery task"
        );
        true
    }
}

/// Owned inputs shared by a supervisor and every poller generation it spawns.
pub(crate) struct DiscoveryTaskContext {
    key: String,
    generation: u64,
    upstream_namespace: String,
    upstream_id: String,
    provider_name: &'static str,
    lb_cache: Arc<LoadBalancerCache>,
    request_epoch: Option<Arc<RequestEpochStore>>,
    static_targets: Vec<UpstreamTarget>,
    algorithm: LoadBalancerAlgorithm,
    hash_on: Option<String>,
    dns_cache: DnsCache,
    health_checker: Arc<HealthChecker>,
    poll_interval_seconds: u64,
    staleness: DiscoveryStaleness,
}

/// Supervise one upstream's poller for the lifetime of its generation.
///
/// The poller runs in its own spawned task so a panic is observable as a
/// `JoinError` instead of tearing down the supervisor with it (issue #3721).
/// Clean cancel/shutdown ends supervision; an unexpected exit is restarted with
/// bounded, jittered exponential backoff. Every restart is fenced on the
/// generation: once the manager registers a replacement, the superseded
/// supervisor exits instead of restarting or publishing.
async fn supervise_discovery_task(
    ctx: Arc<DiscoveryTaskContext>,
    discoverer: Arc<dyn ServiceDiscoverer>,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let registry = crate::plugins::prometheus_metrics::global_registry();

    loop {
        let poller_ctx = Arc::clone(&ctx);
        let poller_discoverer = Arc::clone(&discoverer);
        let poller_cancel = cancel_rx.clone();
        let poller_shutdown = shutdown_rx.clone();
        let poller = tokio::spawn(async move {
            run_discovery_loop(
                poller_ctx,
                poller_discoverer,
                poller_shutdown,
                poller_cancel,
            )
            .await
        });
        // If the supervisor itself is aborted while awaiting, this guard keeps
        // the poller from surviving as an orphan.
        let abort_guard = AbortOnDrop(poller.abort_handle());
        let outcome = poller.await;
        drop(abort_guard);

        match outcome {
            Ok(DiscoveryLoopExit::Canceled) => {
                health::record_clean_exit(&ctx.key, ctx.generation);
                info!(
                    upstream = %ctx.upstream_id,
                    generation = ctx.generation,
                    "Service discovery: task canceled (config reconcile)"
                );
                return;
            }
            Ok(DiscoveryLoopExit::Shutdown) => {
                health::record_clean_exit(&ctx.key, ctx.generation);
                info!(
                    upstream = %ctx.upstream_id,
                    generation = ctx.generation,
                    "Service discovery: task stopped for shutdown"
                );
                return;
            }
            Err(join_error) if join_error.is_cancelled() => {
                // The poller was aborted — only reachable through this
                // supervisor's own drop guard. Not a crash; do not count it.
                health::record_clean_exit(&ctx.key, ctx.generation);
                debug!(
                    upstream = %ctx.upstream_id,
                    generation = ctx.generation,
                    reason = "aborted",
                    "Service discovery: poller aborted"
                );
                return;
            }
            Err(_) => {
                registry.record_service_discovery_task_panic();
                warn!(
                    upstream = %ctx.upstream_id,
                    provider = ctx.provider_name,
                    generation = ctx.generation,
                    reason = "poller_panic",
                    "Service discovery: poller exited unexpectedly; targets are retained under the staleness policy while the supervisor restarts it"
                );
            }
        }

        // Generation fence: a reconcile that replaced this task already owns the
        // key, so this supervisor must not restart a superseded poller.
        let Some(backoff) = health::record_unexpected_exit(&ctx.key, ctx.generation) else {
            debug!(
                upstream = %ctx.upstream_id,
                generation = ctx.generation,
                "Service discovery: superseded generation not restarted"
            );
            return;
        };
        registry.record_service_discovery_task_restart();

        // Wait out the backoff, but stay responsive to cancel/shutdown so a
        // reconcile during backoff does not have to wait for the full delay —
        // and keep the staleness deadline armed. A poller that panics before it
        // ever reaches its own timer would otherwise postpone fail-closed
        // expiry/withdrawal for as long as it keeps crash-looping, because the
        // backoff grows while the staleness bound stays fixed (issue #3717).
        // The crash-looping generation is still the current owner, so applying
        // expiry here is the same fenced action its poller would have taken.
        let backoff_deadline = tokio::time::Instant::now() + backoff;
        loop {
            // `None` once this episode's expiry action has run, so an already
            // expired generation waits only on the backoff deadline.
            let stale_deadline = health::next_stale_deadline(&ctx.key, ctx.generation);
            let expired = tokio::select! {
                // Cancellation and shutdown win a simultaneous wake-up: neither
                // routing state nor the expiry episode may be touched once the
                // task is on its way out.
                biased;
                _ = wait_for_cancel(cancel_rx.clone()) => {
                    health::record_clean_exit(&ctx.key, ctx.generation);
                    info!(
                        upstream = %ctx.upstream_id,
                        generation = ctx.generation,
                        "Service discovery: task canceled during restart backoff"
                    );
                    return;
                }
                _ = async {
                    if let Some(ref rx) = shutdown_rx {
                        wait_for_shutdown(rx.clone()).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    health::record_clean_exit(&ctx.key, ctx.generation);
                    info!(
                        upstream = %ctx.upstream_id,
                        generation = ctx.generation,
                        "Service discovery: shutting down during restart backoff"
                    );
                    return;
                }
                _ = tokio::time::sleep_until(backoff_deadline) => false,
                _ = async {
                    match stale_deadline {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => true,
            };
            if !expired {
                break;
            }
            // No poller state exists here: the crashed poller's installed view
            // died with it, and the restart publishes its first admitted
            // snapshot unconditionally.
            match apply_staleness_expiry(&ctx, None, &cancel_rx, &shutdown_rx) {
                // Applied (or a failure that armed its own bounded retry
                // deadline): keep waiting out the remaining backoff.
                StalenessExpiryOutcome::Applied | StalenessExpiryOutcome::PublishFailed => {}
                // A lifecycle signal landed; the next pass takes the biased
                // cancel/shutdown branch and exits cleanly.
                StalenessExpiryOutcome::Aborted => {}
                // A replacement owns the key: stop waiting and let the fence
                // check below end this supervisor.
                StalenessExpiryOutcome::Superseded => break,
            }
        }

        // Re-check both fences after sleeping: the backoff window is exactly
        // when a reconcile is most likely to have replaced this task.
        if *cancel_rx.borrow() || !health::generation_is_current(&ctx.key, ctx.generation) {
            debug!(
                upstream = %ctx.upstream_id,
                generation = ctx.generation,
                "Service discovery: superseded or canceled during restart backoff"
            );
            return;
        }
    }
}

/// Handle to a supervised task started through the test seam below.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub struct SupervisedTaskForTest {
    /// Cancel signal; sending `true` ends supervision cleanly.
    pub cancel_tx: tokio::sync::watch::Sender<bool>,
    /// Supervisor join handle.
    pub handle: JoinHandle<()>,
    /// Health-registry key for this task.
    pub key: String,
    /// Generation this task was registered under.
    pub generation: u64,
}

/// Start the production supervisor with an injected discoverer.
///
/// Only provider construction is substituted: supervision, generation fencing,
/// restart backoff, publication, and staleness expiry all run exactly as they
/// do under [`ServiceDiscoveryManager::start`], so external coverage of
/// panic/restart/withdraw behavior cannot drift from production.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn spawn_supervised_discovery_task_for_test(
    upstream_namespace: &str,
    upstream_id: &str,
    provider_name: &'static str,
    discoverer: Arc<dyn ServiceDiscoverer>,
    lb_cache: Arc<LoadBalancerCache>,
    request_epoch: Option<Arc<RequestEpochStore>>,
    health_checker: Arc<HealthChecker>,
    dns_cache: DnsCache,
    static_targets: Vec<UpstreamTarget>,
    algorithm: LoadBalancerAlgorithm,
    poll_interval_seconds: u64,
    max_stale_seconds: u64,
    policy: crate::config::types::SdStalePolicy,
    generation: u64,
) -> SupervisedTaskForTest {
    let key = service_discovery_task_key(upstream_namespace, upstream_id);
    let staleness = health::resolve_staleness(max_stale_seconds, policy, poll_interval_seconds);
    health::register_task(&key, generation, provider_name, staleness);

    let ctx = Arc::new(DiscoveryTaskContext {
        key: key.clone(),
        generation,
        upstream_namespace: upstream_namespace.to_string(),
        upstream_id: upstream_id.to_string(),
        provider_name,
        lb_cache,
        request_epoch,
        static_targets,
        algorithm,
        hash_on: None,
        dns_cache,
        health_checker,
        poll_interval_seconds,
        staleness,
    });

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(supervise_discovery_task(ctx, discoverer, None, cancel_rx));
    SupervisedTaskForTest {
        cancel_tx,
        handle,
        key,
        generation,
    }
}

/// Test-only probe over the production staleness-expiry path.
///
/// Registers the generation exactly as [`ServiceDiscoveryManager::start`] does,
/// then lets an external test drive `apply_staleness_expiry` synchronously.
/// Cancellation, shutdown, and generation replacement are therefore observed at
/// an exact point instead of racing a live poller's timer, which is what makes
/// the lifecycle-versus-expiry contract testable deterministically.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub struct StalenessExpiryProbeForTest {
    ctx: Arc<DiscoveryTaskContext>,
    state: DiscoveryLoopState,
    cancel_tx: tokio::sync::watch::Sender<bool>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    /// Health-registry key this probe registered.
    pub key: String,
    /// Generation this probe registered under.
    pub generation: u64,
}

#[allow(dead_code)] // reached from the external test crate; dead in the bin target
impl StalenessExpiryProbeForTest {
    /// Raise this task's cancel signal, as a config reconcile or manager stop
    /// does before it registers a replacement.
    pub fn cancel(&self) {
        let _ = self.cancel_tx.send(true);
    }

    /// Raise the global shutdown signal wired into this probe.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Seed the installed discovered view a live poller would have built, so a
    /// withdrawal has something to withdraw.
    pub fn set_installed_discovered(&mut self, targets: Vec<UpstreamTarget>) {
        self.state.last_discovered = targets;
        self.state.snapshot_installed = true;
    }

    /// Discovered targets this probe still believes are installed.
    pub fn installed_discovered(&self) -> &[UpstreamTarget] {
        &self.state.last_discovered
    }

    /// Run the production expiry application once.
    pub fn apply_expiry(&mut self) -> StalenessExpiryOutcome {
        apply_staleness_expiry(
            &self.ctx,
            Some(&mut self.state),
            &self.cancel_rx,
            &self.shutdown_rx,
        )
    }
}

/// Build a [`StalenessExpiryProbeForTest`] over the production expiry path.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn staleness_expiry_probe_for_test(
    upstream_namespace: &str,
    upstream_id: &str,
    provider_name: &'static str,
    lb_cache: Arc<LoadBalancerCache>,
    request_epoch: Option<Arc<RequestEpochStore>>,
    health_checker: Arc<HealthChecker>,
    dns_cache: DnsCache,
    static_targets: Vec<UpstreamTarget>,
    algorithm: LoadBalancerAlgorithm,
    poll_interval_seconds: u64,
    max_stale_seconds: u64,
    policy: crate::config::types::SdStalePolicy,
    generation: u64,
    with_shutdown_channel: bool,
) -> StalenessExpiryProbeForTest {
    let key = service_discovery_task_key(upstream_namespace, upstream_id);
    let staleness = health::resolve_staleness(max_stale_seconds, policy, poll_interval_seconds);
    health::register_task(&key, generation, provider_name, staleness);

    let ctx = Arc::new(DiscoveryTaskContext {
        key: key.clone(),
        generation,
        upstream_namespace: upstream_namespace.to_string(),
        upstream_id: upstream_id.to_string(),
        provider_name,
        lb_cache,
        request_epoch,
        static_targets,
        algorithm,
        hash_on: None,
        dns_cache,
        health_checker,
        poll_interval_seconds,
        staleness,
    });

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    StalenessExpiryProbeForTest {
        ctx,
        state: DiscoveryLoopState::new(),
        cancel_tx,
        cancel_rx,
        shutdown_tx,
        shutdown_rx: with_shutdown_channel.then_some(shutdown_rx),
        key,
        generation,
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
    pub const fn as_str(self) -> &'static str {
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
    let generation = entry.generation;
    // Grab an AbortHandle before consuming the JoinHandle so we can force-
    // kill the task if the timeout expires (dropping a JoinHandle merely
    // detaches the task — it does not abort it).
    let abort_handle = entry.handle.abort_handle();
    tokio::spawn(async move {
        let timeout = std::time::Duration::from_secs(TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS);
        let outcome = tokio::time::timeout(timeout, entry.handle).await;
        report_task_join(&id, generation, outcome, &abort_handle);
    });
}

/// Classify a supervisor join result explicitly (issue #3721).
///
/// The pre-#3721 code matched `Ok(_)`, so `Ok(Err(JoinError))` — a panicked or
/// aborted supervisor — was logged as "stopped gracefully". Each nested shape
/// now gets its own diagnostic, and only a genuinely clean exit is reported as
/// graceful.
fn report_task_join(
    upstream_id: &str,
    generation: u64,
    outcome: Result<Result<(), tokio::task::JoinError>, tokio::time::error::Elapsed>,
    abort_handle: &tokio::task::AbortHandle,
) {
    match outcome {
        Ok(Ok(())) => {
            health::remove_task(upstream_id, generation);
            debug!(
                upstream = %upstream_id,
                "Service discovery: task stopped gracefully"
            );
        }
        Ok(Err(join_error)) if join_error.is_cancelled() => {
            health::remove_task(upstream_id, generation);
            debug!(
                upstream = %upstream_id,
                reason = "aborted",
                "Service discovery: task was aborted before it could exit cleanly"
            );
        }
        Ok(Err(_)) => {
            // Panic. Never reported as graceful: the poller for this upstream
            // stopped without publishing, and the supervisor itself is gone.
            health::remove_task(upstream_id, generation);
            crate::plugins::prometheus_metrics::global_registry()
                .record_service_discovery_task_panic();
            warn!(
                upstream = %upstream_id,
                reason = "supervisor_panic",
                "Service discovery: supervisor panicked while stopping; discovery for this upstream is not running"
            );
        }
        Err(_) => {
            warn!(
                upstream = %upstream_id,
                timeout_seconds = TASK_GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                "Service discovery: task did not exit within the graceful timeout, aborting"
            );
            abort_handle.abort();
            health::remove_task(upstream_id, generation);
        }
    }
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

/// Whether this task must stop writing routing state: its own cancel signal
/// (config reconcile / manager stop) or global shutdown is already raised.
///
/// Cheap and synchronous, so it is safe to call inside a publication fence.
fn lifecycle_signaled(
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
    shutdown_rx: &Option<tokio::sync::watch::Receiver<bool>>,
) -> bool {
    // The async wait helpers treat a dropped sender as a lifecycle signal.
    // Keep the synchronous in-fence check identical: otherwise a sender could
    // disappear after the select woke but before publication and the task
    // would still be allowed to mutate routing state.
    if *cancel_rx.borrow() || cancel_rx.has_changed().is_err() {
        return true;
    }
    shutdown_rx
        .as_ref()
        .is_some_and(|rx| *rx.borrow() || rx.has_changed().is_err())
}

/// Classify a loop exit taken because a lifecycle signal was observed off the
/// select's own cancel/shutdown branches.
fn lifecycle_exit(cancel_rx: &tokio::sync::watch::Receiver<bool>) -> DiscoveryLoopExit {
    if *cancel_rx.borrow() || cancel_rx.has_changed().is_err() {
        DiscoveryLoopExit::Canceled
    } else {
        DiscoveryLoopExit::Shutdown
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

/// Outcome of one staleness-expiry application.
///
/// The three failure-shaped outcomes are deliberately distinct: only
/// [`StalenessExpiryOutcome::PublishFailed`] is a real publication failure that
/// schedules a bounded retry and records a failure. A generation that was
/// superseded, canceled, or shut down published nothing and owes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessExpiryOutcome {
    /// The expiry action ran for this episode: a `retain` claim, or a published
    /// static-only withdrawal (claimed exactly once per episode).
    Applied,
    /// A replacement generation owns the key; nothing was published or claimed.
    Superseded,
    /// Cancellation or global shutdown won; nothing was published or claimed,
    /// no retry was scheduled, and no failure was recorded.
    Aborted,
    /// The static-only republication was attempted and failed; the episode
    /// stays unclaimed and a bounded retry is scheduled.
    PublishFailed,
}

/// Outcome of awaiting one asynchronous publication-preparation step under the
/// owning generation's staleness deadline and lifecycle signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparationOutcome {
    /// Preparation finished; publication may proceed.
    Ready,
    /// The staleness deadline elapsed while preparation was pending and the
    /// configured policy withdraws, so the fenced static-only withdrawal ran
    /// (or is retrying) and this pending snapshot must be abandoned.
    Expired,
    /// Cancellation or global shutdown was observed.
    Aborted,
    /// A replacement generation owns the key.
    Superseded,
}

/// Test-only hold on asynchronous publication preparation.
///
/// External lifecycle tests need an *admitted* snapshot whose preparation is
/// provably still pending while the staleness deadline elapses or a reconcile
/// cancels the task. Real DNS warmup latency is not controllable, so a
/// deliberately blocked step is the only deterministic way to cover the
/// contract. Production never installs a hold.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub struct PublicationPreparationHold {
    gate: tokio::sync::Semaphore,
    entered: AtomicU64,
}

#[allow(dead_code)] // reached from the external test crate; dead in the bin target
impl PublicationPreparationHold {
    /// How many publication preparations have parked on this hold.
    pub fn entered(&self) -> u64 {
        self.entered.load(Ordering::SeqCst)
    }

    /// Let every parked and future preparation through.
    pub fn release(&self) {
        self.gate.close();
    }

    async fn wait(&self) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        // `Err` means the hold was released; either way, proceed.
        let _ = self.gate.acquire().await;
    }
}

static PUBLICATION_PREPARATION_HOLD: std::sync::RwLock<Option<Arc<PublicationPreparationHold>>> =
    std::sync::RwLock::new(None);

/// Install a hold that blocks publication preparation until it is released.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn hold_discovery_publication_preparation_for_test() -> Arc<PublicationPreparationHold> {
    let hold = Arc::new(PublicationPreparationHold {
        gate: tokio::sync::Semaphore::new(0),
        entered: AtomicU64::new(0),
    });
    if let Ok(mut guard) = PUBLICATION_PREPARATION_HOLD.write() {
        *guard = Some(Arc::clone(&hold));
    }
    hold
}

/// Remove any installed hold, releasing whatever is parked on it.
#[allow(dead_code)] // reached from the external test crate; dead in the bin target
pub fn clear_discovery_publication_preparation_hold_for_test() {
    let previous = PUBLICATION_PREPARATION_HOLD
        .write()
        .ok()
        .and_then(|mut guard| guard.take());
    if let Some(hold) = previous {
        hold.release();
    }
}

/// Installed hold, if any. One uncontended read lock per publishing poll —
/// never on a request path.
fn publication_preparation_hold() -> Option<Arc<PublicationPreparationHold>> {
    PUBLICATION_PREPARATION_HOLD
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(Arc::clone))
}

/// Await one asynchronous publication-preparation step (DNS warmup) while the
/// owning generation's staleness deadline, cancel signal, global shutdown, and
/// supersession stay live (issue #3717).
///
/// A large catalog or an unresponsive DNS set must not postpone fail-closed
/// withdrawal past `max_stale_seconds`: the advertised bound is on how long the
/// old dynamic targets may stay routable, and admission alone does not make
/// them fresh. At the deadline the expiry action runs through exactly the same
/// fenced static-only withdrawal the poll loop uses, and the pending snapshot
/// (and its uncommitted provider cursor) is abandoned rather than published
/// over that action.
///
/// Preparation is polled *first*: a step that is already complete publishes as
/// before, so an ordinary poll that lands on an already-elapsed anchor still
/// recovers by publishing instead of withdrawing. The deadline and lifecycle
/// branches act only while preparation is genuinely pending.
///
/// `state` is the poller's own installed view, reborrowed exclusively inside
/// the timer branch while `prepare` is suspended — there is no concurrent
/// mutable access.
async fn prepare_publication_under_deadline(
    prepare: impl std::future::Future<Output = ()>,
    ctx: Option<&DiscoveryTaskContext>,
    state: &mut DiscoveryLoopState,
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
    shutdown_rx: &Option<tokio::sync::watch::Receiver<bool>>,
) -> PreparationOutcome {
    tokio::pin!(prepare);
    loop {
        // `None` without a supervised generation (external test seam), and
        // `None` once this episode's expiry action has been claimed — which is
        // what keeps an expired generation from spinning on an elapsed
        // deadline while it finishes preparing.
        let stale_deadline =
            ctx.and_then(|ctx| health::next_stale_deadline(&ctx.key, ctx.generation));

        tokio::select! {
            biased;
            () = &mut prepare => return PreparationOutcome::Ready,
            _ = wait_for_cancel(cancel_rx.clone()) => return PreparationOutcome::Aborted,
            _ = async {
                if let Some(rx) = shutdown_rx {
                    wait_for_shutdown(rx.clone()).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => return PreparationOutcome::Aborted,
            _ = async {
                match stale_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                // Unreachable without a ctx: `stale_deadline` is `None` there,
                // so this branch stays pending.
                let Some(ctx) = ctx else { continue };
                match apply_staleness_expiry(ctx, Some(&mut *state), cancel_rx, shutdown_rx) {
                    StalenessExpiryOutcome::Aborted => return PreparationOutcome::Aborted,
                    StalenessExpiryOutcome::Superseded => return PreparationOutcome::Superseded,
                    StalenessExpiryOutcome::Applied | StalenessExpiryOutcome::PublishFailed => {
                        if ctx.staleness.policy.withdraws() {
                            // Routing is now static-only (or a bounded
                            // withdrawal retry is armed). Publishing this
                            // snapshot — or committing its cursor — would
                            // undo the fail-closed action with data that is
                            // stale by the operator's own definition.
                            return PreparationOutcome::Expired;
                        }
                        // `retain` records the episode without touching
                        // routing, so the pending snapshot is still exactly
                        // what should publish once preparation finishes. The
                        // claim clears the deadline, so this cannot spin.
                    }
                }
            }
        }
    }
}

/// Outcome of one fenced installation of a merged target set.
#[derive(Debug)]
enum FencedInstall {
    /// Targets were installed into the load balancer / request epoch.
    Published,
    /// Installation was attempted and failed; last-known targets are retained.
    Failed(String),
    /// Cancel or shutdown was observed inside the fence; nothing was published.
    Aborted,
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
    lifecycle: Option<&DiscoveryLifecycle>,
    // Supervised task context, when one exists. Carries the staleness policy
    // and the withdrawal inputs that keep the deadline armed across
    // asynchronous publication preparation; `lifecycle` is the same
    // generation's fence handle. `None` from the external test seam, which has
    // no supervised generation at all.
    supervised: Option<&DiscoveryTaskContext>,
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
            // A refused payload leaves the installed set exactly as stale as no
            // answer at all, so it must not refresh the staleness anchor.
            if let Some(lifecycle) = lifecycle {
                lifecycle.record_failure(DiscoveryFailureReason::SnapshotRejected);
            }
            return DiscoveryApplyControl::Continue;
        }
    };

    // Early exit for a task that was already superseded while `discover()` was
    // in flight: the replacement owns the load-balancer state for this upstream
    // (issue #3721). This check only avoids wasted merge/DNS-warmup work — the
    // authoritative fence is around the publication itself, below, because any
    // check performed *before* an unfenced publish can be overtaken by the
    // reconcile that registers the replacement.
    if let Some(lifecycle) = lifecycle
        && !lifecycle.is_current()
    {
        info!(
            upstream = %upstream_id,
            "Service discovery: superseded task discarding discovery results without publishing"
        );
        return DiscoveryApplyControl::Stop;
    }

    // A canceled task may have completed its discover() call after the cancel
    // signal fired. Check before publishing so we never overwrite the new
    // config's LB state with stale data. Drop the pending cursor without
    // committing.
    if lifecycle_signaled(cancel_rx, shutdown_rx) {
        info!(
            "Service discovery: task for upstream {} canceled or shutting down during discovery, discarding results",
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

        // Publication preparation is asynchronous and unbounded in principle: a
        // large catalog or a slow/unresponsive DNS set can take arbitrarily
        // long. It runs under this generation's staleness deadline, cancel
        // signal, shutdown signal, and ownership fence so the advertised bound
        // on how long unconfirmed dynamic targets stay routable holds across it
        // (issue #3717).
        let prepared = prepare_publication_under_deadline(
            async {
                if let Some(hold) = publication_preparation_hold() {
                    // Test-only: never installed in production.
                    hold.wait().await;
                }
                if !hostnames.is_empty() {
                    dns_cache.warmup(hostnames).await;
                }
            },
            supervised,
            state,
            cancel_rx,
            shutdown_rx,
        )
        .await;

        match prepared {
            PreparationOutcome::Ready => {}
            PreparationOutcome::Superseded => {
                info!(
                    upstream = %upstream_id,
                    "Service discovery: superseded task discarding discovery results without publishing"
                );
                return DiscoveryApplyControl::Stop;
            }
            PreparationOutcome::Aborted => {
                debug!(
                    "Service discovery: task for upstream {} canceled or shutting down while preparing publication, discarding results",
                    upstream_id,
                );
                return DiscoveryApplyControl::Stop;
            }
            PreparationOutcome::Expired => {
                // The fenced static-only withdrawal already ran (or armed its
                // bounded retry). Drop the pending cursor uncommitted and let
                // the next poll recover through the ordinary path.
                warn!(
                    upstream = %upstream_id,
                    provider = provider_name,
                    "Service discovery: staleness bound elapsed while preparing publication; the pending snapshot was discarded without publishing or committing its cursor"
                );
                return DiscoveryApplyControl::Continue;
            }
        }

        // Everything that decides whether this task may still write routing
        // state runs inside the fence: cancellation (which a reconcile signals
        // *before* it registers the replacement) and the load-balancer /
        // request-epoch installation. While the fence is held, a reconcile
        // cannot register the replacement generation, so the check and the
        // publication cannot be interleaved.
        let install = || {
            if lifecycle_signaled(cancel_rx, shutdown_rx) {
                return FencedInstall::Aborted;
            }
            match install_merged_targets(
                upstream_namespace,
                upstream_id,
                &merged,
                lb_cache,
                request_epoch,
                algorithm,
                hash_on,
                health_checker,
            ) {
                Ok(()) => FencedInstall::Published,
                Err(error) => FencedInstall::Failed(error),
            }
        };

        let installed = match lifecycle {
            Some(lifecycle) => match lifecycle.publish_fenced(install) {
                FencedPublish::Published(installed) => installed,
                FencedPublish::Superseded => {
                    info!(
                        upstream = %upstream_id,
                        "Service discovery: superseded task discarding discovery results without publishing"
                    );
                    return DiscoveryApplyControl::Stop;
                }
            },
            // No supervised generation behind this call (external test seam):
            // there is no ownership entry to fence against.
            None => install(),
        };

        match installed {
            FencedInstall::Published => {}
            FencedInstall::Aborted => {
                debug!(
                    "Service discovery: task for upstream {} canceled or shutting down before publication, discarding results",
                    upstream_id,
                );
                return DiscoveryApplyControl::Stop;
            }
            FencedInstall::Failed(error) => {
                warn!(
                    "Service discovery [{}]: upstream {} target publication failed: {}. Keeping last-known targets and blocking-query cursor.",
                    provider_name, upstream_id, error,
                );
                if let Some(lifecycle) = lifecycle {
                    lifecycle.record_failure(DiscoveryFailureReason::PublishFailed);
                }
                // Drop pending cursor without committing.
                return DiscoveryApplyControl::Continue;
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

    // The staleness anchor advances only here: past this point the admitted set
    // is what the load balancer is serving (issue #3717).
    if let Some(lifecycle) = lifecycle {
        lifecycle.record_success();
    }

    DiscoveryApplyControl::Continue
}

/// Publish a merged target set and prune health state that no longer applies.
///
/// Shared by ordinary snapshot publication and by staleness withdrawal so both
/// paths install through the same epoch/load-balancer contract.
#[allow(clippy::too_many_arguments)]
fn install_merged_targets(
    upstream_namespace: &str,
    upstream_id: &str,
    merged: &[UpstreamTarget],
    lb_cache: &LoadBalancerCache,
    request_epoch: &Option<Arc<RequestEpochStore>>,
    algorithm: crate::config::types::LoadBalancerAlgorithm,
    hash_on: &Option<String>,
    health_checker: &HealthChecker,
) -> Result<(), String> {
    if let Some(epoch_store) = request_epoch {
        let _published = epoch_store.update_load_balancer(
            |current| {
                Some(LoadBalancerCache::build_update_targets_inner(
                    &current.load_balancer,
                    upstream_namespace,
                    upstream_id,
                    merged.to_vec(),
                    algorithm,
                    hash_on.clone(),
                ))
            },
            |published| {
                lb_cache.store_inner(Arc::clone(&published.load_balancer));
            },
        )?;
    } else {
        lb_cache.update_targets(
            upstream_namespace,
            upstream_id,
            merged.to_vec(),
            algorithm,
            hash_on.clone(),
        );
    }

    health_checker.remove_stale_targets(upstream_namespace, upstream_id, merged);
    if let Some(epoch_store) = request_epoch {
        let epoch = epoch_store.load();
        for proxy in epoch.config.proxies.iter().filter(|proxy| {
            proxy_targets_discovered_upstream(proxy, upstream_namespace, upstream_id)
        }) {
            health_checker.remove_stale_passive_targets_for_proxy(
                &proxy.namespace,
                &proxy.id,
                merged,
            );
        }
    }
    Ok(())
}

/// Health-registry handle for one supervised task generation.
///
/// Every mutation is generation-fenced, so a superseded task can neither
/// advance the staleness anchor nor publish lifecycle state for the generation
/// that replaced it.
pub(crate) struct DiscoveryLifecycle {
    key: String,
    generation: u64,
}

impl DiscoveryLifecycle {
    pub(crate) fn new(key: String, generation: u64) -> Self {
        Self { key, generation }
    }

    fn is_current(&self) -> bool {
        health::generation_is_current(&self.key, self.generation)
    }

    /// Run `publish` under this generation's ownership fence.
    ///
    /// The ownership check and the publication are atomic with respect to
    /// generation replacement: see [`health::publish_if_current`].
    fn publish_fenced<T>(&self, publish: impl FnOnce() -> T) -> FencedPublish<T> {
        health::publish_if_current(&self.key, self.generation, publish)
    }

    fn record_success(&self) {
        health::record_success(&self.key, self.generation);
    }

    fn record_failure(&self, reason: DiscoveryFailureReason) {
        health::record_failure(&self.key, self.generation, reason);
    }
}

/// Background discovery loop for a single upstream.
///
/// Exits when either the global shutdown signal fires or the per-task cancel
/// signal is raised (e.g. during config reconcile). An unexpected exit or panic
/// is the supervisor's problem, not this function's.
async fn run_discovery_loop(
    ctx: Arc<DiscoveryTaskContext>,
    discoverer: Arc<dyn ServiceDiscoverer>,
    shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
) -> DiscoveryLoopExit {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        ctx.poll_interval_seconds.max(1),
    ));
    let mut state = DiscoveryLoopState::new();
    let lifecycle = DiscoveryLifecycle::new(ctx.key.clone(), ctx.generation);

    loop {
        // Arm the staleness deadline alongside the poll tick so expiry acts on
        // time rather than at the next (possibly far later) poll (issue #3717).
        // Returns `None` once the expiry action has run for this episode, which
        // is what keeps an expired task from spinning on an elapsed deadline.
        let stale_deadline = health::next_stale_deadline(&ctx.key, ctx.generation);

        tokio::select! {
            _ = interval.tick() => {}
            _ = async {
                match stale_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let expiry =
                    apply_staleness_expiry(&ctx, Some(&mut state), &cancel_rx, &shutdown_rx);
                if expiry == StalenessExpiryOutcome::Aborted {
                    return lifecycle_exit(&cancel_rx);
                }
                continue;
            }
            _ = wait_for_cancel(cancel_rx.clone()) => {
                return DiscoveryLoopExit::Canceled;
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
                return DiscoveryLoopExit::Shutdown;
            }
        }

        // Keep cancellation, shutdown, and the staleness deadline live while a
        // provider call is in flight. A hung registry request must not postpone
        // fail-closed withdrawal beyond the configured bound.
        let discover_result = {
            let discover_future = discoverer.discover();
            tokio::pin!(discover_future);
            loop {
                let stale_deadline = health::next_stale_deadline(&ctx.key, ctx.generation);
                tokio::select! {
                    result = &mut discover_future => break result,
                    _ = async {
                        match stale_deadline {
                            Some(deadline) => tokio::time::sleep_until(deadline).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        let expiry = apply_staleness_expiry(
                            &ctx,
                            Some(&mut state),
                            &cancel_rx,
                            &shutdown_rx,
                        );
                        if expiry == StalenessExpiryOutcome::Aborted {
                            return lifecycle_exit(&cancel_rx);
                        }
                    }
                    _ = wait_for_cancel(cancel_rx.clone()) => {
                        return DiscoveryLoopExit::Canceled;
                    }
                    _ = async {
                        if let Some(ref rx) = shutdown_rx {
                            wait_for_shutdown(rx.clone()).await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        return DiscoveryLoopExit::Shutdown;
                    }
                }
            }
        };

        // Provider cursors (e.g. Consul X-Consul-Index) stay pending until
        // shared admission and publication succeed for this exact snapshot —
        // dropping the commit handle retains the prior cursor.
        match discover_result {
            Ok(snapshot) => {
                match apply_discovered_snapshot(
                    &ctx.upstream_namespace,
                    &ctx.upstream_id,
                    discoverer.provider_name(),
                    snapshot,
                    &mut state,
                    &ctx.lb_cache,
                    &ctx.request_epoch,
                    &ctx.static_targets,
                    ctx.algorithm,
                    &ctx.hash_on,
                    &cancel_rx,
                    &shutdown_rx,
                    &ctx.dns_cache,
                    &ctx.health_checker,
                    Some(&lifecycle),
                    Some(ctx.as_ref()),
                )
                .await
                {
                    DiscoveryApplyControl::Continue => {}
                    DiscoveryApplyControl::Stop => {
                        return if *cancel_rx.borrow() {
                            DiscoveryLoopExit::Canceled
                        } else {
                            DiscoveryLoopExit::Shutdown
                        };
                    }
                }
            }
            Err(e) => {
                // The provider error may embed a registry URL; it is logged at
                // the existing operator log site only. Lifecycle state records a
                // closed-set reason token instead.
                warn!(
                    "Service discovery [{}]: upstream {} discovery failed: {}. Keeping last-known targets.",
                    discoverer.provider_name(),
                    ctx.upstream_id,
                    e,
                );
                lifecycle.record_failure(DiscoveryFailureReason::DiscoverFailed);
            }
        }
    }
}

/// Apply the configured expiry action once the staleness bound elapses.
///
/// `withdraw` / `fail_readiness` republish the upstream with **static targets
/// only**: an operator-declared target stays routable, while endpoints Ferrum
/// can no longer confirm with the registry stop being selectable. `retain`
/// records the expiry for health and metrics without touching routing.
///
/// The episode is claimed exactly once, so a registry outage produces one
/// withdrawal, not a republish per timer wakeup. Recovery clears it: the next
/// admitted snapshot republishes through the ordinary path because the loop's
/// `last_discovered` was reset here.
///
/// Withdrawal publishes through the same ownership fence as an ordinary
/// snapshot, so a superseded generation cannot install static-only targets over
/// the replacement's routing state. Cancellation and global shutdown are
/// checked before the episode is claimed and again *inside* that fence,
/// immediately before the routing mutation: a task canceled by a reconcile (or
/// a gateway shutting down) must not write static-only targets over the state
/// its replacement is about to own, and must not consume the replacement's
/// expiry episode. An abort is not a publication failure — no retry is
/// scheduled and no failure is recorded.
///
/// `state` is the poller's installed view where one exists. The supervisor
/// applies expiry during restart backoff without it: the crashed poller's view
/// died with it, and the restarted poller starts from a fresh state that
/// republishes its first admitted snapshot anyway.
fn apply_staleness_expiry(
    ctx: &DiscoveryTaskContext,
    state: Option<&mut DiscoveryLoopState>,
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
    shutdown_rx: &Option<tokio::sync::watch::Receiver<bool>>,
) -> StalenessExpiryOutcome {
    let policy = ctx.staleness.policy;
    let registry = crate::plugins::prometheus_metrics::global_registry();

    if lifecycle_signaled(cancel_rx, shutdown_rx) {
        debug!(
            upstream = %ctx.upstream_id,
            generation = ctx.generation,
            "Service discovery: canceled or shutting down before staleness expiry could be applied"
        );
        return StalenessExpiryOutcome::Aborted;
    }

    if !policy.withdraws() {
        if health::claim_expiry(&ctx.key, ctx.generation) {
            registry.record_service_discovery_stale_expiry();
            warn!(
                upstream = %ctx.upstream_id,
                provider = ctx.provider_name,
                max_stale_seconds = ctx.staleness.max_stale_seconds(),
                policy = policy.as_str(),
                "Service discovery: last admitted snapshot exceeded the staleness bound; retaining discovered targets under the configured policy"
            );
        }
        return StalenessExpiryOutcome::Applied;
    }

    let withdrawn_count = state.as_ref().map(|s| s.last_discovered.len() as u64);
    let merged = merge_targets(&ctx.static_targets, &[]);
    // The static-only republication, the lifecycle re-check, and the expiry
    // claim run under the same ownership fence as ordinary publication: a
    // generation replaced while this withdrawal was being computed can neither
    // overwrite the replacement's load-balancer state nor consume its expiry
    // episode, and a cancel/shutdown that lands inside the fence stops the
    // routing mutation before it happens.
    let fenced = health::publish_withdrawal_if_current(&ctx.key, ctx.generation, || {
        if lifecycle_signaled(cancel_rx, shutdown_rx) {
            return WithdrawalAttempt::Aborted;
        }
        match install_merged_targets(
            &ctx.upstream_namespace,
            &ctx.upstream_id,
            &merged,
            &ctx.lb_cache,
            &ctx.request_epoch,
            ctx.algorithm,
            &ctx.hash_on,
            &ctx.health_checker,
        ) {
            Ok(()) => WithdrawalAttempt::Published,
            Err(error) => WithdrawalAttempt::Failed(error),
        }
    });
    let withdrawal = match fenced {
        FencedPublish::Published(withdrawal) => withdrawal,
        FencedPublish::Superseded => {
            debug!(
                upstream = %ctx.upstream_id,
                generation = ctx.generation,
                "Service discovery: superseded task did not publish a staleness withdrawal"
            );
            return StalenessExpiryOutcome::Superseded;
        }
    };

    match withdrawal {
        FencedWithdrawal::Aborted => {
            debug!(
                upstream = %ctx.upstream_id,
                generation = ctx.generation,
                "Service discovery: canceled or shutting down inside the withdrawal fence; nothing was published or claimed"
            );
            StalenessExpiryOutcome::Aborted
        }
        FencedWithdrawal::Published { claimed } => {
            // Reset the installed view so recovery republishes the fresh
            // snapshot even when it is byte-identical to the withdrawn set.
            if let Some(state) = state {
                state.last_discovered.clear();
                state.snapshot_installed = true;
            }
            if claimed {
                registry.record_service_discovery_stale_expiry();
                registry.record_service_discovery_stale_withdrawal();
                warn!(
                    upstream = %ctx.upstream_id,
                    provider = ctx.provider_name,
                    max_stale_seconds = ctx.staleness.max_stale_seconds(),
                    policy = policy.as_str(),
                    withdrawn_targets = withdrawn_count,
                    retained_static_targets = ctx.static_targets.len(),
                    "Service discovery: last admitted snapshot exceeded the staleness bound; withdrew discovered targets and retained static targets"
                );
            }
            StalenessExpiryOutcome::Applied
        }
        FencedWithdrawal::Failed(error) => {
            // Keep the expiry unapplied and retry with bounded backoff. Marking
            // it applied here would retain stale dynamic targets indefinitely;
            // leaving the elapsed deadline unchanged would hot-loop.
            let retry_after = health::defer_expiry_retry(&ctx.key, ctx.generation);
            warn!(
                upstream = %ctx.upstream_id,
                provider = ctx.provider_name,
                error = %error,
                retry_after_seconds = retry_after.map(|duration| duration.as_secs()),
                "Service discovery: staleness withdrawal could not be published; discovered targets remain installed and withdrawal will be retried"
            );
            StalenessExpiryOutcome::PublishFailed
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

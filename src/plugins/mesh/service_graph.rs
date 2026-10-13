//! Lock-free mesh service graph aggregation.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde::Serialize;

use crate::plugins::TransactionSummary;
use crate::plugins::mesh::prometheus_helpers::MeshRequestKey;
use crate::plugins::utils::log_sampling::warn_sampled;

/// Minimum age of a published snapshot before a reader rebuilds it.
const SNAPSHOT_REFRESH_MIN_MS: u64 = 1_000;
const EDGE_RETENTION_MS: u64 = 5 * 60 * 1_000;
/// How often the background worker evicts edges idle past
/// [`EDGE_RETENTION_MS`]. Eviction only bounds memory; snapshots apply the
/// retention window themselves, so a coarse interval never shows a stale edge.
const EDGE_PRUNE_INTERVAL_MS: u64 = 30_000;
/// Hard cap on live edges per data plane (issue #6626).
///
/// Several key fields (workload, namespace, app, service) can be influenced
/// by the peer in some topologies, so the edge map must not grow with them.
/// A real node-local graph is far smaller. Once full, transactions for NEW
/// edges are dropped (with a sampled warning) until retention frees a slot;
/// edges already tracked keep counting.
const MAX_SERVICE_GRAPH_EDGES: usize = 10_000;
/// Sentinel for "no snapshot built yet", so the first read always rebuilds.
const SNAPSHOT_NEVER_PUBLISHED: u64 = u64::MAX;

static GLOBAL_SERVICE_GRAPH: LazyLock<Arc<ServiceGraphRegistry>> =
    LazyLock::new(|| Arc::new(ServiceGraphRegistry::default()));

pub fn global_service_graph() -> &'static ServiceGraphRegistry {
    GLOBAL_SERVICE_GRAPH.as_ref()
}

pub fn record_transaction_with_mesh_key(
    summary: &TransactionSummary,
    mesh_key: Option<&MeshRequestKey>,
) {
    GLOBAL_SERVICE_GRAPH.ensure_snapshot_worker();
    GLOBAL_SERVICE_GRAPH.record_transaction_with_mesh_key(summary, mesh_key);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServiceGraphKey {
    source_principal: Arc<str>,
    source_workload: Arc<str>,
    source_namespace: Arc<str>,
    source_app: Arc<str>,
    source_service: Arc<str>,
    destination_principal: Arc<str>,
    destination_workload: Arc<str>,
    destination_namespace: Arc<str>,
    destination_app: Arc<str>,
    destination_service: Arc<str>,
    request_protocol: Arc<str>,
    connection_security_policy: Arc<str>,
}

#[derive(Debug)]
struct ServiceGraphCounters {
    requests_total: AtomicU64,
    errors_total: AtomicU64,
    duration_micros_total: AtomicU64,
    last_seen_unix_ms: AtomicU64,
}

impl ServiceGraphCounters {
    fn new(now_unix_ms: u64) -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
            duration_micros_total: AtomicU64::new(0),
            last_seen_unix_ms: AtomicU64::new(now_unix_ms),
        }
    }

    fn observe(&self, latency_total_ms: f64, is_error: bool, now_unix_ms: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if is_error {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }
        self.duration_micros_total
            .fetch_add(duration_micros(latency_total_ms), Ordering::Relaxed);
        self.last_seen_unix_ms.store(now_unix_ms, Ordering::Relaxed);
    }

    fn snapshot(&self, key: &ServiceGraphKey) -> ServiceGraphEdge {
        let requests_total = self.requests_total.load(Ordering::Relaxed);
        let duration_ms_total = self.duration_micros_total.load(Ordering::Relaxed) as f64 / 1_000.0;
        let last_seen_unix_ms = self.last_seen_unix_ms.load(Ordering::Relaxed);
        ServiceGraphEdge {
            source_principal: key.source_principal.to_string(),
            source_workload: key.source_workload.to_string(),
            source_namespace: key.source_namespace.to_string(),
            source_app: key.source_app.to_string(),
            source_service: key.source_service.to_string(),
            destination_principal: key.destination_principal.to_string(),
            destination_workload: key.destination_workload.to_string(),
            destination_namespace: key.destination_namespace.to_string(),
            destination_app: key.destination_app.to_string(),
            destination_service: key.destination_service.to_string(),
            request_protocol: key.request_protocol.to_string(),
            connection_security_policy: key.connection_security_policy.to_string(),
            requests_total,
            errors_total: self.errors_total.load(Ordering::Relaxed),
            duration_ms_total,
            duration_ms_avg: if requests_total == 0 {
                0.0
            } else {
                duration_ms_total / requests_total as f64
            },
            last_seen_unix_ms,
            last_seen: unix_ms_rfc3339(last_seen_unix_ms),
        }
    }
}

#[derive(Debug)]
pub struct ServiceGraphRegistry {
    edges: DashMap<ServiceGraphKey, ServiceGraphCounters>,
    /// Live edge count, maintained alongside `edges` so admission never takes
    /// an all-shard `DashMap::len()`. Reserved before an insert and released
    /// on eviction, so it never exceeds [`MAX_SERVICE_GRAPH_EDGES`].
    edge_count: AtomicUsize,
    dropped_edge_transactions: AtomicU64,
    snapshot: ArcSwap<ServiceGraphSnapshot>,
    /// Monotonic publication instant (`socket_opts::monotonic_now_ms`), or
    /// [`SNAPSHOT_NEVER_PUBLISHED`]. Refresh throttling must not use wall
    /// time: a backward clock step would make an old snapshot look fresh and
    /// freeze the graph until the wall clock caught up.
    last_snapshot_monotonic_ms: AtomicU64,
    snapshot_rebuilding: AtomicBool,
    snapshot_worker_started: AtomicBool,
}

impl Default for ServiceGraphRegistry {
    fn default() -> Self {
        Self {
            edges: DashMap::with_shard_amount(super::observability_shard_amount()),
            edge_count: AtomicUsize::new(0),
            dropped_edge_transactions: AtomicU64::new(0),
            snapshot: ArcSwap::from_pointee(ServiceGraphSnapshot::default()),
            last_snapshot_monotonic_ms: AtomicU64::new(SNAPSHOT_NEVER_PUBLISHED),
            snapshot_rebuilding: AtomicBool::new(false),
            snapshot_worker_started: AtomicBool::new(false),
        }
    }
}

struct SnapshotWorkerGuard {
    registry: Arc<ServiceGraphRegistry>,
}

impl Drop for SnapshotWorkerGuard {
    fn drop(&mut self) {
        self.registry
            .snapshot_worker_started
            .store(false, Ordering::Release);
    }
}

impl ServiceGraphRegistry {
    pub fn record_transaction_with_mesh_key(
        &self,
        summary: &TransactionSummary,
        mesh_key: Option<&MeshRequestKey>,
    ) {
        if summary.mirror {
            return;
        }
        let Some(mesh_key) = mesh_key else {
            return;
        };
        let now_unix_ms = now_unix_ms();
        let key = ServiceGraphKey {
            source_principal: Arc::clone(&mesh_key.source_principal),
            source_workload: Arc::clone(&mesh_key.source_workload),
            source_namespace: Arc::clone(&mesh_key.source_namespace),
            source_app: Arc::clone(&mesh_key.source_app),
            source_service: Arc::clone(&mesh_key.source_service),
            destination_principal: Arc::clone(&mesh_key.destination_principal),
            destination_workload: Arc::clone(&mesh_key.destination_workload),
            destination_namespace: Arc::clone(&mesh_key.destination_namespace),
            destination_app: Arc::clone(&mesh_key.destination_app),
            destination_service: Arc::clone(&mesh_key.destination_service),
            request_protocol: Arc::clone(&mesh_key.request_protocol),
            connection_security_policy: Arc::clone(&mesh_key.connection_security_policy),
        };
        let is_error = service_graph_error(summary, mesh_key);
        // Steady state: the edge exists, so a shard read lock suffices.
        if let Some(counters) = self.edges.get(&key) {
            counters.observe(summary.latency_total_ms, is_error, now_unix_ms);
            return;
        }
        // A miss takes the shard write lock and only a genuinely new edge
        // reserves capacity. A request that lost the insert race to another
        // request for the same edge lands in `Occupied` and is always counted,
        // even when that insert took the last slot.
        match self.edges.entry(key) {
            Entry::Occupied(entry) => {
                entry
                    .get()
                    .observe(summary.latency_total_ms, is_error, now_unix_ms);
            }
            Entry::Vacant(entry) => {
                if self
                    .edge_count
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (count < MAX_SERVICE_GRAPH_EDGES).then_some(count + 1)
                    })
                    .is_err()
                {
                    // Release the shard before logging.
                    drop(entry);
                    let dropped = self
                        .dropped_edge_transactions
                        .fetch_add(1, Ordering::Relaxed)
                        .saturating_add(1);
                    warn_sampled!(
                        max_edges = MAX_SERVICE_GRAPH_EDGES,
                        dropped_transactions_total = dropped,
                        "mesh service graph is at its edge cap; dropping transactions for new edges until idle edges expire"
                    );
                    return;
                }
                entry
                    .insert(ServiceGraphCounters::new(now_unix_ms))
                    .observe(summary.latency_total_ms, is_error, now_unix_ms);
            }
        }
    }

    /// The current graph, rebuilt on demand when the published snapshot is
    /// older than [`SNAPSHOT_REFRESH_MIN_MS`].
    ///
    /// Only readers (the JWT-gated admin endpoint) pay for a rebuild, and at
    /// most once per refresh interval however often they poll: concurrent
    /// readers that lose the rebuild race return the published snapshot.
    pub fn snapshot(&self) -> Arc<ServiceGraphSnapshot> {
        self.refresh_snapshot_if_stale(crate::socket_opts::monotonic_now_ms(), now_unix_ms());
        self.snapshot.load_full()
    }

    /// Throttled on the monotonic clock; `now_unix_ms` only stamps the
    /// published snapshot and judges edge retention.
    fn refresh_snapshot_if_stale(&self, now_monotonic_ms: u64, now_unix_ms: u64) {
        let is_stale = |last: u64| {
            last == SNAPSHOT_NEVER_PUBLISHED
                || now_monotonic_ms.saturating_sub(last) >= SNAPSHOT_REFRESH_MIN_MS
        };
        if !is_stale(self.last_snapshot_monotonic_ms.load(Ordering::Acquire)) {
            return;
        }
        if self
            .snapshot_rebuilding
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        // Another reader may have published while this one raced for the flag.
        if is_stale(self.last_snapshot_monotonic_ms.load(Ordering::Acquire)) {
            self.rebuild_snapshot_at(now_monotonic_ms, now_unix_ms);
        }
        self.snapshot_rebuilding.store(false, Ordering::Release);
    }

    fn ensure_snapshot_worker(self: &Arc<Self>) {
        // Hot path: `record_transaction` calls this on every mesh request. Relaxed
        // is sufficient — we only need to observe that the worker is started, not
        // any memory it has written. The compare_exchange below provides the actual
        // ordering for the one-time spawn.
        if self.snapshot_worker_started.load(Ordering::Relaxed) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self
            .snapshot_worker_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let registry = Arc::clone(self);
        handle.spawn(async move {
            let _worker_guard = SnapshotWorkerGuard {
                registry: Arc::clone(&registry),
            };
            // Eviction only: snapshots are built on demand by readers, so an
            // unread graph costs one retention sweep per interval, not a
            // clone-and-sort of every edge every second.
            let mut interval = tokio::time::interval(Duration::from_millis(EDGE_PRUNE_INTERVAL_MS));
            loop {
                interval.tick().await;
                registry.prune_stale_edges(now_unix_ms());
            }
        });
    }

    fn prune_stale_edges(&self, now_unix_ms: u64) {
        let mut removed = 0usize;
        self.edges.retain(|_, counters| {
            let fresh = edge_is_fresh(
                counters.last_seen_unix_ms.load(Ordering::Relaxed),
                now_unix_ms,
            );
            if !fresh {
                removed += 1;
            }
            fresh
        });
        if removed > 0 {
            self.edge_count.fetch_sub(removed, Ordering::Relaxed);
        }
    }

    fn rebuild_snapshot_at(&self, now_monotonic_ms: u64, generated_at_unix_ms: u64) {
        self.prune_stale_edges(generated_at_unix_ms);
        // `iter_mut` holds each shard's WRITE lock while its edges are read.
        // Updates hold the read (or write) lock across all of an edge's
        // counter increments, so every edge is captured between observations:
        // `errors_total <= requests_total` and the duration total describe the
        // same request count.
        let mut edges: Vec<ServiceGraphEdge> = self
            .edges
            .iter_mut()
            .map(|entry| entry.value().snapshot(entry.key()))
            .collect();
        edges.sort_by(compare_service_graph_edges);
        self.snapshot.store(Arc::new(ServiceGraphSnapshot {
            generated_at_unix_ms,
            generated_at: unix_ms_rfc3339(generated_at_unix_ms),
            edge_count: edges.len(),
            edges,
        }));
        self.last_snapshot_monotonic_ms
            .store(now_monotonic_ms, Ordering::Release);
    }

    #[cfg(test)]
    fn force_rebuild_snapshot(&self) {
        self.force_rebuild_snapshot_at(now_unix_ms());
    }

    #[cfg(test)]
    fn force_rebuild_snapshot_at(&self, generated_at_unix_ms: u64) {
        self.rebuild_snapshot_at(crate::socket_opts::monotonic_now_ms(), generated_at_unix_ms);
    }

    #[cfg(test)]
    fn clear_for_tests(&self) {
        self.edges.clear();
        self.edge_count.store(0, Ordering::Relaxed);
        self.dropped_edge_transactions.store(0, Ordering::Relaxed);
        self.last_snapshot_monotonic_ms
            .store(SNAPSHOT_NEVER_PUBLISHED, Ordering::Relaxed);
        self.snapshot
            .store(Arc::new(ServiceGraphSnapshot::default()));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceGraphSnapshot {
    pub generated_at_unix_ms: u64,
    pub generated_at: String,
    pub edge_count: usize,
    pub edges: Vec<ServiceGraphEdge>,
}

impl Default for ServiceGraphSnapshot {
    fn default() -> Self {
        let generated_at_unix_ms = now_unix_ms();
        Self {
            generated_at_unix_ms,
            generated_at: unix_ms_rfc3339(generated_at_unix_ms),
            edge_count: 0,
            edges: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceGraphEdge {
    pub source_principal: String,
    pub source_workload: String,
    pub source_namespace: String,
    pub source_app: String,
    pub source_service: String,
    pub destination_principal: String,
    pub destination_workload: String,
    pub destination_namespace: String,
    pub destination_app: String,
    pub destination_service: String,
    pub request_protocol: String,
    pub connection_security_policy: String,
    pub requests_total: u64,
    pub errors_total: u64,
    pub duration_ms_total: f64,
    pub duration_ms_avg: f64,
    pub last_seen_unix_ms: u64,
    pub last_seen: String,
}

fn compare_service_graph_edges(
    left: &ServiceGraphEdge,
    right: &ServiceGraphEdge,
) -> std::cmp::Ordering {
    left.source_principal
        .cmp(&right.source_principal)
        .then_with(|| left.destination_principal.cmp(&right.destination_principal))
        .then_with(|| left.source_workload.cmp(&right.source_workload))
        .then_with(|| left.source_namespace.cmp(&right.source_namespace))
        .then_with(|| left.source_app.cmp(&right.source_app))
        .then_with(|| left.source_service.cmp(&right.source_service))
        .then_with(|| left.destination_workload.cmp(&right.destination_workload))
        .then_with(|| left.destination_namespace.cmp(&right.destination_namespace))
        .then_with(|| left.destination_app.cmp(&right.destination_app))
        .then_with(|| left.destination_service.cmp(&right.destination_service))
        .then_with(|| left.request_protocol.cmp(&right.request_protocol))
        .then_with(|| {
            left.connection_security_policy
                .cmp(&right.connection_security_policy)
        })
}

fn service_graph_error(summary: &TransactionSummary, mesh_key: &MeshRequestKey) -> bool {
    summary.response_status_code >= 500
        || summary.grpc_status().is_some_and(|status| status != 0)
        || mesh_key.response_flags.as_ref() != "-"
        || summary.error_class.is_some()
        || summary.body_error_class.is_some()
        || summary.client_disconnected
}

fn duration_micros(latency_total_ms: f64) -> u64 {
    if !latency_total_ms.is_finite() || latency_total_ms <= 0.0 {
        return 0;
    }
    (latency_total_ms * 1_000.0)
        .round()
        .clamp(0.0, u64::MAX as f64) as u64
}

fn edge_is_fresh(last_seen_unix_ms: u64, generated_at_unix_ms: u64) -> bool {
    generated_at_unix_ms.saturating_sub(last_seen_unix_ms) <= EDGE_RETENTION_MS
}

fn now_unix_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn unix_ms_rfc3339(unix_ms: u64) -> String {
    DateTime::<Utc>::from_timestamp_millis(unix_ms as i64)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::plugins::mesh::prometheus_helpers::mesh_request_key;

    use super::*;

    #[test]
    fn aggregates_requests_by_source_and_destination_principal() {
        let registry = ServiceGraphRegistry::default();
        let source = "spiffe://cluster.local/ns/default/sa/frontend";
        let destination = "spiffe://cluster.local/ns/default/sa/reviews";

        record_for_test(&registry, &summary(source, destination, 200, 12.5));
        record_for_test(&registry, &summary(source, destination, 503, 37.5));
        registry.force_rebuild_snapshot();

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.edge_count, 1);
        let edge = &snapshot.edges[0];
        assert_eq!(edge.source_principal, source);
        assert_eq!(edge.destination_principal, destination);
        assert_eq!(edge.source_workload, "frontend");
        assert_eq!(edge.destination_workload, "reviews");
        assert_eq!(edge.requests_total, 2);
        assert_eq!(edge.errors_total, 1);
        assert_eq!(edge.duration_ms_total, 50.0);
        assert_eq!(edge.duration_ms_avg, 25.0);
    }

    #[test]
    fn ignores_non_mesh_and_mirror_summaries() {
        let registry = ServiceGraphRegistry::default();
        record_for_test(
            &registry,
            &TransactionSummary {
                response_status_code: 200,
                latency_total_ms: 1.0,
                ..TransactionSummary::default()
            },
        );
        record_for_test(
            &registry,
            &TransactionSummary {
                mirror: true,
                response_status_code: 200,
                latency_total_ms: 1.0,
                metadata: mesh_metadata(
                    "spiffe://cluster.local/ns/default/sa/frontend",
                    "spiffe://cluster.local/ns/default/sa/reviews",
                ),
                ..TransactionSummary::default()
            },
        );
        registry.force_rebuild_snapshot();

        assert!(registry.snapshot().edges.is_empty());
    }

    #[test]
    fn separates_edges_with_shared_principals_but_distinct_labels() {
        let registry = ServiceGraphRegistry::default();
        let source = "spiffe://cluster.local/ns/default/sa/shared";
        let destination = "spiffe://cluster.local/ns/default/sa/backend";

        let mut frontend = summary(source, destination, 200, 10.0);
        frontend
            .metadata
            .insert("mesh.source.workload".to_string(), "frontend".to_string());
        frontend
            .metadata
            .insert("mesh.source.service".to_string(), "frontend".to_string());

        let mut checkout = summary(source, destination, 200, 20.0);
        checkout
            .metadata
            .insert("mesh.source.workload".to_string(), "checkout".to_string());
        checkout
            .metadata
            .insert("mesh.source.service".to_string(), "checkout".to_string());

        record_for_test(&registry, &frontend);
        record_for_test(&registry, &checkout);
        registry.force_rebuild_snapshot();

        let snapshot = registry.snapshot();
        assert_eq!(snapshot.edge_count, 2);
        assert!(
            snapshot
                .edges
                .iter()
                .any(|edge| edge.source_workload == "frontend" && edge.duration_ms_total == 10.0)
        );
        assert!(
            snapshot
                .edges
                .iter()
                .any(|edge| edge.source_workload == "checkout" && edge.duration_ms_total == 20.0)
        );
    }

    #[test]
    fn edge_sort_includes_app_and_service_labels() {
        let base = service_graph_edge_for_sort("frontend", "frontend", "reviews", "reviews");

        for edge in [
            service_graph_edge_for_sort("checkout", "frontend", "reviews", "reviews"),
            service_graph_edge_for_sort("frontend", "checkout", "reviews", "reviews"),
            service_graph_edge_for_sort("frontend", "frontend", "ratings", "reviews"),
            service_graph_edge_for_sort("frontend", "frontend", "reviews", "ratings"),
        ] {
            assert_ne!(
                compare_service_graph_edges(&base, &edge),
                std::cmp::Ordering::Equal
            );
        }
    }

    #[test]
    fn snapshot_rebuild_evicts_stale_edges() {
        let registry = ServiceGraphRegistry::default();
        record_for_test(
            &registry,
            &summary(
                "spiffe://cluster.local/ns/default/sa/frontend",
                "spiffe://cluster.local/ns/default/sa/reviews",
                200,
                10.0,
            ),
        );
        let last_seen = registry
            .edges
            .iter()
            .next()
            .expect("seeded edge")
            .value()
            .last_seen_unix_ms
            .load(Ordering::Relaxed);

        registry.force_rebuild_snapshot_at(last_seen + EDGE_RETENTION_MS);
        assert_eq!(registry.snapshot().edge_count, 1);

        registry.force_rebuild_snapshot_at(last_seen + EDGE_RETENTION_MS + 1);
        assert_eq!(registry.snapshot().edge_count, 0);
        assert!(registry.edges.is_empty());
    }

    #[test]
    fn global_registry_can_be_reset_for_tests() {
        let registry = global_service_graph();
        registry.clear_for_tests();
        record_global_for_test(&summary(
            "spiffe://cluster.local/ns/default/sa/a",
            "spiffe://cluster.local/ns/default/sa/b",
            200,
            1.0,
        ));
        registry.force_rebuild_snapshot();
        assert_eq!(registry.snapshot().edge_count, 1);

        registry.clear_for_tests();
        assert_eq!(registry.snapshot().edge_count, 0);
    }

    #[test]
    fn snapshot_worker_can_restart_after_runtime_teardown() {
        let registry = Arc::new(ServiceGraphRegistry::default());

        {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("test runtime");
            runtime.block_on(async {
                registry.ensure_snapshot_worker();
                tokio::task::yield_now().await;
            });
            assert!(registry.snapshot_worker_started.load(Ordering::Acquire));
        }

        for _ in 0..50 {
            if !registry.snapshot_worker_started.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !registry.snapshot_worker_started.load(Ordering::Acquire),
            "dropping the runtime should let the next caller spawn a fresh worker"
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("replacement test runtime");
        runtime.block_on(async {
            registry.ensure_snapshot_worker();
            tokio::task::yield_now().await;
        });
        assert!(registry.snapshot_worker_started.load(Ordering::Acquire));
    }

    #[test]
    fn new_edges_beyond_the_cap_are_dropped_until_retention_frees_slots() {
        let registry = ServiceGraphRegistry::default();
        let summary = summary(
            "spiffe://cluster.local/ns/default/sa/frontend",
            "spiffe://cluster.local/ns/default/sa/reviews",
            200,
            1.0,
        );
        let base = mesh_request_key(&summary).expect("mesh key");
        let keyed = |index: usize| {
            let mut key = base.clone();
            key.source_workload = Arc::from(format!("workload-{index}"));
            key
        };

        for index in 0..MAX_SERVICE_GRAPH_EDGES {
            registry.record_transaction_with_mesh_key(&summary, Some(&keyed(index)));
        }
        assert_eq!(registry.edges.len(), MAX_SERVICE_GRAPH_EDGES);
        assert_eq!(
            registry.edge_count.load(Ordering::Relaxed),
            MAX_SERVICE_GRAPH_EDGES
        );

        // A new edge past the cap is dropped; tracked edges keep counting.
        registry.record_transaction_with_mesh_key(&summary, Some(&keyed(MAX_SERVICE_GRAPH_EDGES)));
        registry.record_transaction_with_mesh_key(&summary, Some(&keyed(0)));
        assert_eq!(registry.edges.len(), MAX_SERVICE_GRAPH_EDGES);
        assert_eq!(
            registry.dropped_edge_transactions.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            registry
                .edges
                .iter()
                .map(|entry| entry.value().requests_total.load(Ordering::Relaxed))
                .sum::<u64>(),
            MAX_SERVICE_GRAPH_EDGES as u64 + 1
        );

        // Retention eviction releases the slots for new edges.
        registry.prune_stale_edges(now_unix_ms() + EDGE_RETENTION_MS + 60_000);
        assert!(registry.edges.is_empty());
        assert_eq!(registry.edge_count.load(Ordering::Relaxed), 0);
        registry.record_transaction_with_mesh_key(&summary, Some(&keyed(MAX_SERVICE_GRAPH_EDGES)));
        assert_eq!(registry.edges.len(), 1);
    }

    #[test]
    fn snapshots_are_rebuilt_on_read_at_most_once_per_refresh_interval() {
        let registry = ServiceGraphRegistry::default();
        record_for_test(
            &registry,
            &summary(
                "spiffe://cluster.local/ns/default/sa/frontend",
                "spiffe://cluster.local/ns/default/sa/reviews",
                200,
                1.0,
            ),
        );
        // No worker and no forced rebuild: the first read builds the snapshot.
        assert_eq!(registry.snapshot().edge_count, 1);

        // A read inside the refresh interval serves the published snapshot.
        record_for_test(
            &registry,
            &summary(
                "spiffe://cluster.local/ns/default/sa/checkout",
                "spiffe://cluster.local/ns/default/sa/reviews",
                200,
                1.0,
            ),
        );
        assert_eq!(registry.snapshot().edge_count, 1);

        // Once the interval has passed, the next read sees both edges.
        let published = registry.last_snapshot_monotonic_ms.load(Ordering::Acquire);
        registry.refresh_snapshot_if_stale(published + SNAPSHOT_REFRESH_MIN_MS, now_unix_ms());
        assert_eq!(registry.snapshot().edge_count, 2);
    }

    #[test]
    fn a_backward_wall_clock_step_does_not_freeze_snapshot_refresh() {
        let registry = ServiceGraphRegistry::default();
        let unix_now = now_unix_ms();
        registry.refresh_snapshot_if_stale(1_000, unix_now);
        assert_eq!(registry.snapshot.load().generated_at_unix_ms, unix_now);

        // The wall clock steps back ten minutes while monotonic time advances
        // past the refresh interval: the snapshot must still be rebuilt.
        let rolled_back = unix_now - 10 * 60 * 1_000;
        registry.refresh_snapshot_if_stale(1_000 + SNAPSHOT_REFRESH_MIN_MS, rolled_back);
        assert_eq!(registry.snapshot.load().generated_at_unix_ms, rolled_back);

        // Inside the interval nothing is rebuilt, whatever the wall clock says.
        registry.refresh_snapshot_if_stale(1_000 + SNAPSHOT_REFRESH_MIN_MS + 1, unix_now + 60_000);
        assert_eq!(registry.snapshot.load().generated_at_unix_ms, rolled_back);
    }

    #[test]
    fn concurrent_requests_for_the_last_slot_are_all_counted() {
        let registry = Arc::new(ServiceGraphRegistry::default());
        let summary = summary(
            "spiffe://cluster.local/ns/default/sa/frontend",
            "spiffe://cluster.local/ns/default/sa/reviews",
            200,
            1.0,
        );
        let base = mesh_request_key(&summary).expect("mesh key");
        // Occupy every slot but one with unrelated edges.
        registry
            .edge_count
            .store(MAX_SERVICE_GRAPH_EDGES - 1, Ordering::Relaxed);

        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                let summary = summary.clone();
                let key = base.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..PER_THREAD {
                        registry.record_transaction_with_mesh_key(&summary, Some(&key));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }

        assert_eq!(
            registry.dropped_edge_transactions.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            registry.edge_count.load(Ordering::Relaxed),
            MAX_SERVICE_GRAPH_EDGES
        );
        let requests: u64 = registry
            .edges
            .iter()
            .map(|entry| entry.value().requests_total.load(Ordering::Relaxed))
            .sum();
        assert_eq!(requests, (THREADS * PER_THREAD) as u64);
    }

    #[test]
    fn snapshots_never_mix_counter_states_under_concurrent_updates() {
        let registry = Arc::new(ServiceGraphRegistry::default());
        let failing = summary(
            "spiffe://cluster.local/ns/default/sa/frontend",
            "spiffe://cluster.local/ns/default/sa/reviews",
            503,
            1.0,
        );
        let key = mesh_request_key(&failing).expect("mesh key");
        registry.record_transaction_with_mesh_key(&failing, Some(&key));

        let stop = Arc::new(AtomicBool::new(false));
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let stop = Arc::clone(&stop);
                let failing = failing.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        registry.record_transaction_with_mesh_key(&failing, Some(&key));
                    }
                })
            })
            .collect();
        for _ in 0..200 {
            registry.force_rebuild_snapshot();
            let snapshot = registry.snapshot.load_full();
            let edge = &snapshot.edges[0];
            // Every observation is one failed 1 ms request, so a coherent
            // capture has all three totals equal.
            assert_eq!(edge.errors_total, edge.requests_total);
            assert_eq!(edge.duration_ms_total, edge.requests_total as f64);
        }
        stop.store(true, Ordering::Relaxed);
        for writer in writers {
            writer.join().expect("writer");
        }
    }

    fn summary(
        source_principal: &str,
        destination_principal: &str,
        status: u16,
        latency_total_ms: f64,
    ) -> TransactionSummary {
        TransactionSummary {
            namespace: "default".to_string(),
            proxy_id: Some("reviews".to_string()),
            proxy_name: Some("reviews".to_string()),
            response_status_code: status,
            latency_total_ms,
            metadata: mesh_metadata(source_principal, destination_principal),
            ..TransactionSummary::default()
        }
    }

    fn mesh_metadata(
        source_principal: &str,
        destination_principal: &str,
    ) -> HashMap<String, String> {
        HashMap::from([
            (
                "mesh.source.principal".to_string(),
                source_principal.to_string(),
            ),
            ("mesh.source.namespace".to_string(), "default".to_string()),
            ("mesh.source.workload".to_string(), "frontend".to_string()),
            ("mesh.source.app".to_string(), "frontend".to_string()),
            ("mesh.source.service".to_string(), "frontend".to_string()),
            (
                "mesh.destination.principal".to_string(),
                destination_principal.to_string(),
            ),
            (
                "mesh.destination.namespace".to_string(),
                "default".to_string(),
            ),
            (
                "mesh.destination.workload".to_string(),
                "reviews".to_string(),
            ),
            ("mesh.destination.app".to_string(), "reviews".to_string()),
            (
                "mesh.destination.service".to_string(),
                "reviews".to_string(),
            ),
            ("mesh.request_protocol".to_string(), "http".to_string()),
            (
                "mesh.connection_security_policy".to_string(),
                "mutual_tls".to_string(),
            ),
        ])
    }

    fn service_graph_edge_for_sort(
        source_app: &str,
        source_service: &str,
        destination_app: &str,
        destination_service: &str,
    ) -> ServiceGraphEdge {
        ServiceGraphEdge {
            source_principal: "spiffe://cluster.local/ns/default/sa/frontend".to_string(),
            source_workload: "frontend".to_string(),
            source_namespace: "default".to_string(),
            source_app: source_app.to_string(),
            source_service: source_service.to_string(),
            destination_principal: "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
            destination_workload: "reviews".to_string(),
            destination_namespace: "default".to_string(),
            destination_app: destination_app.to_string(),
            destination_service: destination_service.to_string(),
            request_protocol: "http".to_string(),
            connection_security_policy: "mutual_tls".to_string(),
            requests_total: 1,
            errors_total: 0,
            duration_ms_total: 1.0,
            duration_ms_avg: 1.0,
            last_seen_unix_ms: 0,
            last_seen: unix_ms_rfc3339(0),
        }
    }

    fn record_for_test(registry: &ServiceGraphRegistry, summary: &TransactionSummary) {
        let mesh_key = mesh_request_key(summary);
        registry.record_transaction_with_mesh_key(summary, mesh_key.as_ref());
    }

    fn record_global_for_test(summary: &TransactionSummary) {
        let mesh_key = mesh_request_key(summary);
        record_transaction_with_mesh_key(summary, mesh_key.as_ref());
    }
}

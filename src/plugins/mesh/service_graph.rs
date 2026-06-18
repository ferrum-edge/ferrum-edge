//! Lock-free mesh service graph aggregation.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::Serialize;

use crate::plugins::TransactionSummary;
use crate::plugins::mesh::prometheus_helpers::{MeshRequestKey, mesh_request_key};

const SNAPSHOT_REFRESH_MIN_MS: u64 = 1_000;
const EDGE_RETENTION_MS: u64 = 5 * 60 * 1_000;

static GLOBAL_SERVICE_GRAPH: LazyLock<Arc<ServiceGraphRegistry>> =
    LazyLock::new(|| Arc::new(ServiceGraphRegistry::default()));

pub fn global_service_graph() -> &'static ServiceGraphRegistry {
    GLOBAL_SERVICE_GRAPH.as_ref()
}

pub fn record_transaction(summary: &TransactionSummary) {
    GLOBAL_SERVICE_GRAPH.ensure_snapshot_worker();
    GLOBAL_SERVICE_GRAPH.record_transaction(summary);
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
    snapshot: ArcSwap<ServiceGraphSnapshot>,
    last_snapshot_unix_ms: AtomicU64,
    snapshot_worker_started: AtomicBool,
}

impl Default for ServiceGraphRegistry {
    fn default() -> Self {
        Self {
            // `edges.entry().or_insert_with()` is a genuine write per mesh
            // request, so this map rides the per-request hot path and must
            // follow the hot-path `DashMap` sharding invariant. As a
            // process-global it cannot read `env_config.pool_shard_amount`, so
            // it auto-derives from CPU topology via `pool_shard_amount(0)`
            // (`next_power_of_two(max(64, num_cpus * 16))`) — same pattern as
            // `backend_conn_limit` / `backend_pending_limit`.
            edges: DashMap::with_shard_amount(crate::util::sharding::pool_shard_amount(0)),
            snapshot: ArcSwap::from_pointee(ServiceGraphSnapshot::default()),
            last_snapshot_unix_ms: AtomicU64::new(0),
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
    pub fn record_transaction(&self, summary: &TransactionSummary) {
        if summary.mirror {
            return;
        }
        let Some(mesh_key) = mesh_request_key(summary) else {
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
        self.edges
            .entry(key)
            .or_insert_with(|| ServiceGraphCounters::new(now_unix_ms))
            .observe(
                summary.latency_total_ms,
                service_graph_error(summary, &mesh_key),
                now_unix_ms,
            );
    }

    pub fn snapshot(&self) -> Arc<ServiceGraphSnapshot> {
        self.snapshot.load_full()
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
            let mut interval =
                tokio::time::interval(Duration::from_millis(SNAPSHOT_REFRESH_MIN_MS));
            loop {
                interval.tick().await;
                registry.rebuild_snapshot(now_unix_ms());
            }
        });
    }

    fn rebuild_snapshot(&self, generated_at_unix_ms: u64) {
        self.last_snapshot_unix_ms
            .store(generated_at_unix_ms, Ordering::Relaxed);
        self.edges.retain(|_, counters| {
            edge_is_fresh(
                counters.last_seen_unix_ms.load(Ordering::Relaxed),
                generated_at_unix_ms,
            )
        });
        let mut edges: Vec<ServiceGraphEdge> = self
            .edges
            .iter()
            .map(|entry| entry.value().snapshot(entry.key()))
            .collect();
        edges.sort_by(compare_service_graph_edges);
        self.snapshot.store(Arc::new(ServiceGraphSnapshot {
            generated_at_unix_ms,
            generated_at: unix_ms_rfc3339(generated_at_unix_ms),
            edge_count: edges.len(),
            edges,
        }));
    }

    #[cfg(test)]
    fn force_rebuild_snapshot(&self) {
        self.force_rebuild_snapshot_at(now_unix_ms());
    }

    #[cfg(test)]
    fn force_rebuild_snapshot_at(&self, generated_at_unix_ms: u64) {
        self.last_snapshot_unix_ms
            .store(generated_at_unix_ms, Ordering::Relaxed);
        self.rebuild_snapshot(generated_at_unix_ms);
    }

    #[cfg(test)]
    fn clear_for_tests(&self) {
        self.edges.clear();
        self.last_snapshot_unix_ms.store(0, Ordering::Relaxed);
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

    use super::*;

    #[test]
    fn aggregates_requests_by_source_and_destination_principal() {
        let registry = ServiceGraphRegistry::default();
        let source = "spiffe://cluster.local/ns/default/sa/frontend";
        let destination = "spiffe://cluster.local/ns/default/sa/reviews";

        registry.record_transaction(&summary(source, destination, 200, 12.5));
        registry.record_transaction(&summary(source, destination, 503, 37.5));
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
        registry.record_transaction(&TransactionSummary {
            response_status_code: 200,
            latency_total_ms: 1.0,
            ..TransactionSummary::default()
        });
        registry.record_transaction(&TransactionSummary {
            mirror: true,
            response_status_code: 200,
            latency_total_ms: 1.0,
            metadata: mesh_metadata(
                "spiffe://cluster.local/ns/default/sa/frontend",
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
            ..TransactionSummary::default()
        });
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

        registry.record_transaction(&frontend);
        registry.record_transaction(&checkout);
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
        registry.record_transaction(&summary(
            "spiffe://cluster.local/ns/default/sa/frontend",
            "spiffe://cluster.local/ns/default/sa/reviews",
            200,
            10.0,
        ));
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
        record_transaction(&summary(
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
}

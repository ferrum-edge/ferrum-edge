use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::info;

pub struct ControllerMetrics {
    pub reconciliations: AtomicU64,
    pub full_syncs: AtomicU64,
    pub errors: AtomicU64,
    pub last_reconcile_duration_ms: AtomicU64,
    /// Rotating Gateway API status-plan cursor (#2397).
    ///
    /// Advanced after a successful budgeted planning pass when the update plan
    /// is empty (fairness must still progress), or after a successful
    /// status-patch batch on the serialized reconcile path. Patch errors and
    /// batch timeouts leave the cursor unchanged so the same bounded window is
    /// retried on the next reconcile.
    pub gateway_api_status_plan_cursor: AtomicU64,
    /// Reflector generations restarted because a watch scope produced no event
    /// for the configured idle window (`FERRUM_K8S_WATCH_IDLE_RELIST_SECS`), or
    /// because a replacement generation never finished its initial list.
    ///
    /// A quiet scope relists on every window even when it is perfectly healthy
    /// — bookmarks never reach us, so idleness is not evidence of a fault — so
    /// this counter measures relist *rate*, not error rate. What is diagnostic
    /// is a scope that relists while the cluster is known to be changing.
    pub watch_idle_relists: AtomicU64,
    /// Watch `Delete` events observed across every watched scope (issue #4491).
    ///
    /// A withdrawn object reaches the reconciler either as a `Delete` event or,
    /// if the stream missed it, only when a relist rebuilds the scope's store.
    /// This counter is the first of those two paths, so it answers the question
    /// a black-box "deleted route kept serving" failure cannot: whether the
    /// control plane ever *observed* the withdrawal. Unlabeled and
    /// scope-agnostic — object identity stays out of metric series.
    pub watch_deletes: AtomicU64,
    /// Reconciles that committed a changed gateway configuration snapshot
    /// (issue #4491).
    ///
    /// [`Self::reconciliations`] counts passes started, including the ones that
    /// find nothing to swap; only a publication proves the reconciler turned an
    /// observed cluster change into new served config. The pair separates "the
    /// controller never saw it" from "the controller published and the data
    /// plane still serves the old route".
    pub config_publications: AtomicU64,
    /// Watch stream errors across every watched scope (issue #4491): refused
    /// initial lists, failed watch starts, mid-stream failures, and API-server
    /// `Status` errors. kube-rs backs the stream off between attempts and the
    /// watcher logs the fault once per transition, so this counter is the
    /// per-attempt view: a steady rise is a scope that cannot succeed — most
    /// often an RBAC gap on a served kind.
    pub watch_errors: AtomicU64,
    /// Objects an authoritative relist found missing from the store it
    /// replaced (issue #4491): withdrawals no `Delete` event delivered. This is
    /// the proof of a missed delete, as opposed to a delete that was observed
    /// and reconciled. A small count on a churning scope can also be an object
    /// deleted inside the relist's own list window.
    pub watch_relist_missed_deletes: AtomicU64,
    /// Objects an authoritative relist found that the store it replaced never
    /// held: creations no `Apply` event delivered.
    pub watch_relist_missed_adds: AtomicU64,
    /// Monotonic millisecond stamp of the last rate-limited idle-reconcile log
    /// line (issue #4491). Bookkeeping for [`should_log_idle_reconcile`], not a
    /// metric; deliberately absent from [`MetricsSnapshot`].
    pub idle_reconcile_last_logged_ms: AtomicU64,
    /// Successful Gateway API route parent-status patches.
    pub route_status_publications: AtomicU64,
    /// Milliseconds from the patched route's Kubernetes `creationTimestamp` to
    /// the successful Ferrum parent-status write. Zero until the first
    /// successful publication that carried a parseable creation timestamp.
    ///
    /// This is the wait the Gateway API conformance suite observes (object
    /// exists → parent status appears). kube-rs does not expose a watch-event
    /// timestamp, so this is not a reflector-observation clock.
    pub last_route_status_publish_latency_ms: AtomicU64,
    /// Kubernetes status read/write operations abandoned because they exceeded
    /// their wall-clock budget (issue #4239).
    ///
    /// A status patch batch is awaited inline on the serialized reconcile loop,
    /// so an unbounded stalled request stops every other object's status from
    /// being published. Each expiry here is one object left for the next
    /// reconcile, not a lost write; a sustained rise means the API server's
    /// status path is degrading before it costs a whole reconcile round.
    pub status_request_timeouts: AtomicU64,
    /// Status patch batches abandoned by the reconciler's defensive outer
    /// timeout. The batch bounds itself, so this should stay at zero; any
    /// increase means a patch path escaped its own budget.
    pub status_batch_timeouts: AtomicU64,
    /// Istio status JSON Merge Patch 409s observed while applying Ferrum-owned
    /// conditions. Unlabeled: object identity and API error strings stay out.
    pub istio_status_conflicts: AtomicU64,
    /// Istio status writes that succeeded after at least one 409 retry.
    pub istio_status_retries: AtomicU64,
    /// Istio status writes that exhausted the bounded conflict retry budget
    /// without falling back to an unversioned patch.
    pub istio_status_retry_exhausted: AtomicU64,
    /// Istio status writes aborted because the live UID no longer matched the
    /// planned object (delete/recreate under the same name).
    pub istio_status_recreated: AtomicU64,
    /// Istio status writes aborted because the status read or write returned
    /// HTTP 404. Kubernetes answers a CRD that declares no `status` subresource
    /// with the same ordinary object-not-found response it uses for a deleted
    /// object, so that case lands here rather than under
    /// [`Self::istio_status_unsupported`].
    pub istio_status_not_found: AtomicU64,
    /// Istio status writes aborted because the API server does not serve the
    /// resource at all: HTTP 405, or a 404 whose body says the requested
    /// resource could not be found.
    pub istio_status_unsupported: AtomicU64,
    /// Istio status writes refused because the planned watch-snapshot UID was
    /// missing, so the write could not bind object identity.
    pub istio_status_missing_uid: AtomicU64,
}

impl Default for ControllerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ControllerMetrics {
    pub fn new() -> Self {
        Self {
            reconciliations: AtomicU64::new(0),
            full_syncs: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_reconcile_duration_ms: AtomicU64::new(0),
            gateway_api_status_plan_cursor: AtomicU64::new(0),
            watch_idle_relists: AtomicU64::new(0),
            watch_deletes: AtomicU64::new(0),
            config_publications: AtomicU64::new(0),
            watch_errors: AtomicU64::new(0),
            watch_relist_missed_deletes: AtomicU64::new(0),
            watch_relist_missed_adds: AtomicU64::new(0),
            idle_reconcile_last_logged_ms: AtomicU64::new(0),
            route_status_publications: AtomicU64::new(0),
            last_route_status_publish_latency_ms: AtomicU64::new(0),
            status_request_timeouts: AtomicU64::new(0),
            status_batch_timeouts: AtomicU64::new(0),
            istio_status_conflicts: AtomicU64::new(0),
            istio_status_retries: AtomicU64::new(0),
            istio_status_retry_exhausted: AtomicU64::new(0),
            istio_status_recreated: AtomicU64::new(0),
            istio_status_not_found: AtomicU64::new(0),
            istio_status_unsupported: AtomicU64::new(0),
            istio_status_missing_uid: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            reconciliations: self.reconciliations.load(Ordering::Relaxed),
            full_syncs: self.full_syncs.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_reconcile_duration_ms: self.last_reconcile_duration_ms.load(Ordering::Relaxed),
            watch_idle_relists: self.watch_idle_relists.load(Ordering::Relaxed),
            watch_deletes: self.watch_deletes.load(Ordering::Relaxed),
            config_publications: self.config_publications.load(Ordering::Relaxed),
            watch_errors: self.watch_errors.load(Ordering::Relaxed),
            watch_relist_missed_deletes: self.watch_relist_missed_deletes.load(Ordering::Relaxed),
            watch_relist_missed_adds: self.watch_relist_missed_adds.load(Ordering::Relaxed),
            route_status_publications: self.route_status_publications.load(Ordering::Relaxed),
            last_route_status_publish_latency_ms: self
                .last_route_status_publish_latency_ms
                .load(Ordering::Relaxed),
            status_request_timeouts: self.status_request_timeouts.load(Ordering::Relaxed),
            status_batch_timeouts: self.status_batch_timeouts.load(Ordering::Relaxed),
            istio_status_conflicts: self.istio_status_conflicts.load(Ordering::Relaxed),
            istio_status_retries: self.istio_status_retries.load(Ordering::Relaxed),
            istio_status_retry_exhausted: self.istio_status_retry_exhausted.load(Ordering::Relaxed),
            istio_status_recreated: self.istio_status_recreated.load(Ordering::Relaxed),
            istio_status_not_found: self.istio_status_not_found.load(Ordering::Relaxed),
            istio_status_unsupported: self.istio_status_unsupported.load(Ordering::Relaxed),
            istio_status_missing_uid: self.istio_status_missing_uid.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    pub reconciliations: u64,
    pub full_syncs: u64,
    pub errors: u64,
    pub last_reconcile_duration_ms: u64,
    pub watch_idle_relists: u64,
    pub watch_deletes: u64,
    pub config_publications: u64,
    pub watch_errors: u64,
    pub watch_relist_missed_deletes: u64,
    pub watch_relist_missed_adds: u64,
    pub route_status_publications: u64,
    pub last_route_status_publish_latency_ms: u64,
    pub status_request_timeouts: u64,
    pub status_batch_timeouts: u64,
    pub istio_status_conflicts: u64,
    pub istio_status_retries: u64,
    pub istio_status_retry_exhausted: u64,
    pub istio_status_recreated: u64,
    pub istio_status_not_found: u64,
    pub istio_status_unsupported: u64,
    pub istio_status_missing_uid: u64,
}

/// Minimum spacing between `info`-level log lines for reconciles that changed
/// nothing (issue #4491).
///
/// `Reconciliation complete` is emitted only when a reconcile swaps
/// configuration, so before this a missed delete and a quiet cluster produced
/// identical logs. One line per interval carrying the watch counters keeps the
/// idle case visible without turning a 15 s full-sync into a log firehose.
pub const IDLE_RECONCILE_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Whether an idle reconcile observed at `now_ms` (any monotonic millisecond
/// clock) should log at info level, given the stamp of the last such line.
///
/// Claims the slot when it answers `true`, so two callers reading the same
/// stamp cannot both log. A zero stamp means "never logged", so the stored
/// stamp is floored at one.
pub fn should_log_idle_reconcile(last_logged_ms: &AtomicU64, now_ms: u64) -> bool {
    let interval_ms = u64::try_from(IDLE_RECONCILE_LOG_INTERVAL.as_millis()).unwrap_or(u64::MAX);
    let previous = last_logged_ms.load(Ordering::Relaxed);
    if previous != 0 && now_ms.saturating_sub(previous) < interval_ms {
        return false;
    }
    last_logged_ms
        .compare_exchange(
            previous,
            now_ms.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_ok()
}

/// Milliseconds since the first call in this process, from a monotonic clock.
pub fn monotonic_now_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Milliseconds from `creation_rfc3339` to `published_unix_ms`.
///
/// `None` when the creation timestamp is missing or not RFC 3339. A publish
/// instant earlier than creation (clock skew) saturates at zero rather than
/// wrapping.
pub fn route_status_publish_latency_ms(
    creation_rfc3339: Option<&str>,
    published_unix_ms: u64,
) -> Option<u64> {
    let created = chrono::DateTime::parse_from_rfc3339(creation_rfc3339?).ok()?;
    let created_ms = u64::try_from(created.timestamp_millis()).ok()?;
    Some(published_unix_ms.saturating_sub(created_ms))
}

pub fn unix_now_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

/// Record a successful Gateway API route parent-status patch.
///
/// Non-route kinds (Gateway, GatewayClass, policies) are ignored so the
/// latency gauge stays a route-status signal.
pub fn record_route_status_publication(
    metrics: &ControllerMetrics,
    kind: &str,
    namespace: &str,
    name: &str,
    creation_rfc3339: Option<&str>,
    published_unix_ms: u64,
) {
    if !matches!(
        kind,
        "HTTPRoute" | "GRPCRoute" | "TCPRoute" | "TLSRoute" | "UDPRoute"
    ) {
        return;
    }
    metrics
        .route_status_publications
        .fetch_add(1, Ordering::Relaxed);
    let Some(latency_ms) = route_status_publish_latency_ms(creation_rfc3339, published_unix_ms)
    else {
        return;
    };
    metrics
        .last_route_status_publish_latency_ms
        .store(latency_ms, Ordering::Relaxed);
    info!(
        kind,
        namespace, name, latency_ms, "Gateway API route parent status published"
    );
}

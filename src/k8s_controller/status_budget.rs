//! Wall-clock budgets for Kubernetes status writes on the serialized reconcile
//! loop (issue #4239).
//!
//! Gateway API and Istio status patch batches are awaited *inline* on the single
//! reconcile task: while a batch runs, no watch event and no full-sync tick can
//! produce a new reconcile, so no other object's status can be published. Before
//! #4239 the only bound on that batch was a single 60-second whole-batch
//! timeout, and the individual API requests inside it were unbounded (the shared
//! kube client's read timeout is measured in minutes and cannot be lowered
//! without breaking the reflector watches that use the same client).
//!
//! One stalled status request therefore froze *all* reconciliation for a full 60
//! seconds — exactly the Gateway API conformance suite's own parent-status wait,
//! so any route created inside that window failed deterministically on whichever
//! arbitrary test happened to be running. Run 32913920801 shows the shape: a
//! reconcile with `elapsed_ms: 60036` around a `updates: 3` batch timeout, with
//! every neighbouring reconcile completing in 35–275 ms.
//!
//! The budgets here make the blockage bounded and attributable:
//!
//! * every individual API request is bounded by [`STATUS_REQUEST_BUDGET`],
//! * every object's whole read-modify-write is bounded by [`STATUS_UPDATE_BUDGET`],
//! * every batch is bounded by [`STATUS_BATCH_BUDGET`], which also clamps the
//!   two budgets above so a batch can never overrun by a whole request,
//! * [`STATUS_BATCH_BACKSTOP`] stays as a defensive outer timeout in the
//!   reconciler and should no longer be reachable.
//!
//! A budget expiry is *not* a lost write. The reconciler leaves the status-plan
//! cursor unchanged on any patch error, so the same bounded window is replanned
//! and retried on the next reconcile; objects that already succeeded drop out of
//! the plan, so the tail of a slow batch moves up rather than starving. A window
//! that fails `STATUS_WINDOW_MAX_FAILED_BATCHES` times in a row is advanced past
//! (#6370) so a persistently failing object cannot starve candidates outside it;
//! its own write is retried when the rotation wraps back.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;
use tracing::warn;

use super::metrics::ControllerMetrics;

/// Budget for one Kubernetes API request (a status read, or a status write).
pub const STATUS_REQUEST_BUDGET: Duration = Duration::from_secs(5);

/// Budget for one object's complete status update: its status read, its
/// guarded write, and any bounded conflict retries in between.
pub const STATUS_UPDATE_BUDGET: Duration = Duration::from_secs(10);

/// Budget for a whole status patch batch, and therefore the longest a single
/// stalled Kubernetes status write can hold the serialized reconcile loop.
///
/// Deliberately far below the Gateway API conformance suite's 60-second
/// parent-status wait *and* no longer than the lab's 15-second full-sync
/// interval, so a stall costs at most one reconcile round rather than the
/// observer's entire patience.
pub const STATUS_BATCH_BUDGET: Duration = Duration::from_secs(15);

/// Defensive outer timeout the reconciler still wraps a batch in. The batch
/// bounds itself with [`STATUS_BATCH_BUDGET`], so reaching this means a patch
/// path escaped its own budget — worth a distinct counter and warning.
pub const STATUS_BATCH_BACKSTOP: Duration = Duration::from_secs(20);

/// A batch that completes but takes longer than this is reported, so a
/// degrading cluster is visible before it starts costing whole reconciles.
pub const STATUS_BATCH_SLOW_WARN: Duration = Duration::from_secs(2);

/// Remaining budget for one operation, clamped by the batch deadline.
///
/// `None` means the batch deadline has already passed, so the caller must fail
/// the operation immediately instead of issuing a request that cannot finish
/// inside the batch's budget.
pub fn status_operation_budget(
    now: Instant,
    deadline: Instant,
    per_operation: Duration,
) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.min(per_operation))
    }
}

/// Identity of the status operation being budgeted, for logs and errors.
#[derive(Clone, Copy)]
pub struct StatusOperation<'a> {
    /// What was being attempted: `"read"`, `"patch"`, or `"update"`.
    pub phase: &'a str,
    pub kind: &'a str,
    pub namespace: &'a str,
    pub name: &'a str,
}

/// Synthesize the `kube::Error` a timed-out status operation reports.
///
/// Modeled as an API `Status` failure with HTTP 504 and reason `Timeout` so it
/// flows through the existing error handling unchanged: it is not a 409, so no
/// conflict-retry path treats it as a lost CAS race, and the reconciler's
/// bounded "leave the cursor unchanged and retry this window" branch already
/// covers it.
pub fn status_timeout_error(
    operation: StatusOperation<'_>,
    budget: Option<Duration>,
) -> kube::Error {
    let message = match budget {
        Some(budget) => format!(
            "Ferrum status {} for {}/{} {} exceeded its {}ms budget",
            operation.phase,
            operation.namespace,
            operation.name,
            operation.kind,
            budget.as_millis()
        ),
        None => format!(
            "Ferrum status {} for {}/{} {} was refused: the status batch budget was already spent",
            operation.phase, operation.namespace, operation.name, operation.kind
        ),
    };
    let mut status = kube::core::Status::failure(&message, "Timeout");
    status.code = 504;
    kube::Error::Api(status.boxed())
}

/// `true` when `error` is a budget expiry synthesized by
/// [`status_timeout_error`] rather than a real API server response.
pub fn is_status_timeout_error(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(status) if status.code == 504 && status.reason == "Timeout")
}

/// Run one budgeted status operation.
///
/// Returns the operation's own result when it finishes inside
/// `min(per_operation, deadline - now)`. Otherwise the in-flight request is
/// dropped and a [`status_timeout_error`] is returned, counted, and logged with
/// the object identity — the evidence that was missing when the whole batch was
/// dropped by one outer timeout.
///
/// Dropping the client future does **not** prove the API server rejected the
/// request: a timed-out write can still finish later. Safety therefore comes
/// from compare-and-swap, not from cancellation. Gateway/GatewayClass/ListenerSet
/// SSA documents carry the freshly read `metadata.resourceVersion`; route/policy
/// merge patches already did. A late apply against a newer live object is a 409,
/// not a stale overwrite of Ferrum-owned conditions. A live read that fails or
/// lacks a non-empty `resourceVersion` must not issue the write.
pub async fn await_status_operation<T, F>(
    operation: StatusOperation<'_>,
    deadline: Instant,
    per_operation: Duration,
    metrics: Option<&ControllerMetrics>,
    request: F,
) -> Result<T, kube::Error>
where
    F: Future<Output = Result<T, kube::Error>>,
{
    let Some(budget) = status_operation_budget(Instant::now(), deadline, per_operation) else {
        return Err(record_status_timeout(operation, None, metrics));
    };
    match tokio::time::timeout(budget, request).await {
        Ok(result) => result,
        Err(_) => Err(record_status_timeout(operation, Some(budget), metrics)),
    }
}

fn record_status_timeout(
    operation: StatusOperation<'_>,
    budget: Option<Duration>,
    metrics: Option<&ControllerMetrics>,
) -> kube::Error {
    if let Some(metrics) = metrics {
        metrics
            .status_request_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }
    warn!(
        phase = operation.phase,
        kind = operation.kind,
        namespace = operation.namespace,
        name = operation.name,
        budget_ms = budget.map(|budget| budget.as_millis() as u64),
        "Kubernetes status operation exceeded its budget; releasing the reconcile loop and \
         retrying this object on the next reconcile"
    );
    status_timeout_error(operation, budget)
}

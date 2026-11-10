//! In-memory bounded ring of recent `mesh_authz` deny events used by the
//! `GET /mesh/policy-denies/recent` admin endpoint.
//!
//! ## Hot-path invariant
//!
//! Mesh request processing is dominated by the **allow** path; a deny is an
//! exception, not steady state. The recorder is therefore deliberately
//! `std::sync::Mutex`-backed and grabbed only when `mesh_authz` decides to
//! reject a request (HTTP/H3/gRPC/HBONE) or terminate a stream connection.
//! No code on the allow path touches the recorder. The lock is held for a
//! handful of operations (push to ring + drop oldest if full), so even on a
//! deny burst the contention envelope is small.
//!
//! The admin query path filters by `at >= now - window`, groups by the
//! `(rule, source, destination, reason, reevaluation)` tuple, then sorts by
//! count descending (tie-breaking on `last_at` descending) and truncates to
//! `limit`. This is a cold path — admin operators poll at human cadence.

use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Default capacity when no `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` override is
/// configured. Sized to bound memory: each record is ~200–400 bytes, so 10_000
/// entries occupies a few MiB at worst.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// Lower bound on the recorder's ring capacity. The recorder degrades to a
/// no-op when capacity is `0` to make disabling cheap, but we forbid weird
/// "single-slot" rings that would be impossible to interpret for triage.
const MIN_NON_ZERO_CAPACITY: usize = 2;

/// Global process-wide recorder. Constructed lazily on first touch with the
/// [`DEFAULT_CAPACITY`]; the mesh runtime calls [`configure_global_capacity`]
/// at startup to override from the env config when `FERRUM_MODE=mesh`. The
/// global recorder lives forever — non-mesh modes never touch it, so the
/// `LazyLock` allocation is paid only when the mesh boot path calls into us
/// (or a test does).
static GLOBAL_RECORDER: LazyLock<Arc<PolicyDenyRecorder>> =
    LazyLock::new(|| Arc::new(PolicyDenyRecorder::with_capacity(DEFAULT_CAPACITY)));

/// Set at most once by the mesh runtime startup path. Lets `configure_global_capacity`
/// be idempotent across the apply-loop and the bootstrap sequence; subsequent
/// reconfigure attempts are logged at debug and ignored to preserve historical
/// records.
static GLOBAL_CAPACITY_CONFIGURED: OnceLock<()> = OnceLock::new();

/// Snapshot of a single deny event captured by `mesh_authz`.
#[derive(Debug, Clone)]
pub struct PolicyDenyEvent {
    /// Name (or synthetic identifier) of the `MeshPolicy` rule that fired the
    /// deny. Synthesised reasons (`unauthenticated_baggage`,
    /// `trust_domain_mismatch`, `untrusted_assertor`) reuse the reason string
    /// here so operators can still pivot on "rule".
    pub rule: String,
    /// SPIFFE id of the source workload, when known. HBONE traffic without
    /// trusted baggage falls back to the peer cert id; non-HBONE traffic uses
    /// the peer SPIFFE id (or `None` when authentication never produced one).
    pub source: Option<String>,
    /// SPIFFE id of the destination workload, when known. For HTTP-family
    /// dispatch this is the locally injected workload identity; stream
    /// connections may not carry one.
    pub destination: Option<String>,
    /// Categorical reason captured from `ctx.metadata`. Matches the value the
    /// `mesh_authz` deny path writes to `mesh_authz.deny_policy`.
    pub reason: String,
    /// Wall-clock time the deny was observed. Recorded as UTC `DateTime` so
    /// admin payloads can render RFC 3339 without re-deriving from an
    /// `Instant`.
    pub at: DateTime<Utc>,
    /// `true` when this deny came from an HBONE admission-fence sweep
    /// re-judging an ALREADY-ADMITTED live tunnel (the `mesh_authz.reevaluation`
    /// metadata marker), not from a request the peer just made.
    ///
    /// Load-bearing for triage: a swept revocation is one record per revoked
    /// tunnel for a principal that issued no new request, and without this flag
    /// it is byte-identical to a request-time denial — an operator would read
    /// "denied requests" for traffic that never arrived. Part of the grouping
    /// key so the two never merge into one row.
    pub reevaluation: bool,
}

#[derive(Default, Debug)]
struct RecorderInner {
    /// Bounded FIFO of deny events. Front is the oldest; back is the newest.
    /// Capacity is fixed at construction so push is O(1).
    ring: VecDeque<PolicyDenyEvent>,
    /// Maximum number of events the ring can hold. `0` means the recorder is
    /// disabled (cheap no-op on the deny path).
    capacity: usize,
}

/// Process-singleton recorder for mesh authorization denies.
///
/// Construct one explicitly for tests via [`Self::with_capacity`]; production
/// code goes through [`global`] / [`record_global`] to share state with the
/// admin handler.
#[derive(Debug)]
pub struct PolicyDenyRecorder {
    inner: Mutex<RecorderInner>,
}

impl PolicyDenyRecorder {
    /// Build a recorder with the supplied ring capacity. `0` disables
    /// recording entirely.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = sanitize_capacity(capacity);
        Self {
            inner: Mutex::new(RecorderInner {
                ring: VecDeque::with_capacity(capacity),
                capacity,
            }),
        }
    }

    /// Reset capacity in-place. Used by tests to exercise eviction; the
    /// production path uses [`configure_global_capacity`] instead and never
    /// touches a live recorder.
    #[cfg(test)]
    fn reset_capacity_for_tests(&self, capacity: usize) {
        let capacity = sanitize_capacity(capacity);
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.capacity = capacity;
        guard.ring.clear();
        guard.ring.reserve(capacity);
    }

    /// Push a deny event into the ring. Evicts the oldest entry when full.
    /// O(1).
    pub fn record(&self, event: PolicyDenyEvent) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        if guard.capacity == 0 {
            return;
        }
        if guard.ring.len() == guard.capacity {
            guard.ring.pop_front();
        }
        guard.ring.push_back(event);
    }

    /// Snapshot events whose timestamp is `>= cutoff`, group by the
    /// `(rule, source, destination, reason, reevaluation)` tuple, sort by count
    /// descending (tie-break by `last_at` descending), and truncate to `limit`.
    ///
    /// `limit == 0` is treated as "no grouped output" and returns an empty
    /// grouping slice with the total filtered count preserved so the admin
    /// payload can still report `total_denies` for the window.
    pub fn aggregate_recent(&self, cutoff: DateTime<Utc>, limit: usize) -> PolicyDenyAggregate {
        let snapshot: Vec<PolicyDenyEvent> = {
            let guard = match self.inner.lock() {
                Ok(g) => g,
                Err(poison) => poison.into_inner(),
            };
            guard
                .ring
                .iter()
                .filter(|event| event.at >= cutoff)
                .cloned()
                .collect()
        };

        let total_denies = snapshot.len() as u64;
        if limit == 0 || snapshot.is_empty() {
            return PolicyDenyAggregate {
                total_denies,
                grouped: Vec::new(),
            };
        }

        let mut grouped: Vec<PolicyDenyGroup> = Vec::new();
        // Linear-scan grouping. The expected snapshot is at most
        // `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY` records (default 10k); the
        // unique 4-tuple cardinality is typically far smaller, so a flat
        // walk avoids allocating per-key hashes for what is otherwise a
        // throwaway admin response. Operators with pathological churn can
        // shrink the cap.
        for event in snapshot {
            let existing = grouped.iter_mut().find(|group| {
                group.rule == event.rule
                    && group.source == event.source
                    && group.destination == event.destination
                    && group.reason == event.reason
                    && group.reevaluation == event.reevaluation
            });
            match existing {
                Some(group) => {
                    group.count = group.count.saturating_add(1);
                    if event.at < group.first_at {
                        group.first_at = event.at;
                    }
                    if event.at > group.last_at {
                        group.last_at = event.at;
                    }
                }
                None => {
                    grouped.push(PolicyDenyGroup {
                        rule: event.rule.clone(),
                        source: event.source.clone(),
                        destination: event.destination.clone(),
                        reason: event.reason.clone(),
                        reevaluation: event.reevaluation,
                        count: 1,
                        first_at: event.at,
                        last_at: event.at,
                    });
                }
            }
        }

        grouped.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| b.last_at.cmp(&a.last_at))
                .then_with(|| a.rule.cmp(&b.rule))
                .then_with(|| a.reason.cmp(&b.reason))
        });
        if grouped.len() > limit {
            grouped.truncate(limit);
        }

        PolicyDenyAggregate {
            total_denies,
            grouped,
        }
    }

    /// Number of events currently retained in the ring (post-eviction).
    ///
    /// Introspection surface preserved for future admin endpoints / diagnostic
    /// tooling — see `docs/mesh.md` Policy Deny Drill-down section. Kept under
    /// `#[allow(dead_code)]` instead of a blanket file-level allow so any other
    /// unused symbol in this module still surfaces.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.ring.len()
    }

    /// Whether the ring currently holds zero events.
    ///
    /// See [`Self::len`] for the dead-code rationale.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Live capacity (post-`with_capacity` / `reset_capacity_for_tests` cap).
    ///
    /// See [`Self::len`] for the dead-code rationale.
    #[allow(dead_code)]
    pub fn capacity(&self) -> usize {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard.capacity
    }
}

fn sanitize_capacity(requested: usize) -> usize {
    if requested == 0 {
        return 0;
    }
    requested.max(MIN_NON_ZERO_CAPACITY)
}

/// Aggregated response payload returned by [`PolicyDenyRecorder::aggregate_recent`].
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDenyAggregate {
    /// Number of individual deny events observed in the requested window.
    pub total_denies: u64,
    /// Top-N grouped denies sorted by count descending (tie-break by
    /// `last_at` descending, then `rule` ascending, then `reason` ascending
    /// for stability).
    pub grouped: Vec<PolicyDenyGroup>,
}

/// One grouped row in the admin response payload. Fields use `Option<String>`
/// because mesh denies can fire before either identity is known
/// (unauthenticated HBONE baggage, non-mesh sources, stream-only denies).
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDenyGroup {
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    pub reason: String,
    /// Always serialized, never omitted: an operator filtering request-time
    /// denials must not have to treat an absent field as `false`. See
    /// [`PolicyDenyEvent::reevaluation`].
    pub reevaluation: bool,
    pub count: u64,
    pub first_at: DateTime<Utc>,
    pub last_at: DateTime<Utc>,
}

/// Borrow the process-singleton recorder. Cheap (clone of an `Arc`).
pub fn global() -> Arc<PolicyDenyRecorder> {
    Arc::clone(&GLOBAL_RECORDER)
}

/// Record one deny event against the process-singleton recorder. Called from
/// the `mesh_authz` deny branch; cheap no-op when the ring capacity is `0`.
pub fn record_global(event: PolicyDenyEvent) {
    GLOBAL_RECORDER.record(event);
}

/// Set the global recorder's ring capacity from `FERRUM_MESH_POLICY_DENY_LOG_CAPACITY`.
///
/// Idempotent — only the first call takes effect so accidental reapplies
/// (slice reload, restart-without-fork, etc.) do not wipe captured history.
/// Subsequent calls log at `debug!` and return without touching the recorder.
pub fn configure_global_capacity(capacity: usize) {
    if GLOBAL_CAPACITY_CONFIGURED.set(()).is_err() {
        tracing::debug!(
            requested_capacity = capacity,
            "policy-deny recorder capacity already configured; ignoring re-apply"
        );
        return;
    }
    let resolved = sanitize_capacity(capacity);
    if resolved == 0 {
        tracing::info!("policy-deny recorder disabled (capacity=0)");
    } else {
        tracing::info!(
            capacity = resolved,
            "policy-deny recorder ring capacity configured"
        );
    }
    // Construct a fresh recorder under the same Arc by clearing+reserving the
    // live one. `LazyLock` cannot be reassigned, but the ring itself is
    // mutable behind the inner mutex so we resize it in place.
    let recorder = global();
    let mut guard = match recorder.inner.lock() {
        Ok(g) => g,
        Err(poison) => poison.into_inner(),
    };
    guard.capacity = resolved;
    guard.ring.clear();
    guard.ring.reserve(resolved);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    fn event(rule: &str, reason: &str, at: DateTime<Utc>) -> PolicyDenyEvent {
        event_full(
            rule,
            Some("spiffe://cluster.local/ns/staging/sa/web"),
            Some("spiffe://cluster.local/ns/prod/sa/api"),
            reason,
            at,
        )
    }

    fn event_full(
        rule: &str,
        source: Option<&str>,
        destination: Option<&str>,
        reason: &str,
        at: DateTime<Utc>,
    ) -> PolicyDenyEvent {
        PolicyDenyEvent {
            rule: rule.to_string(),
            source: source.map(str::to_string),
            destination: destination.map(str::to_string),
            reason: reason.to_string(),
            at,
            reevaluation: false,
        }
    }

    #[test]
    fn sanitize_capacity_floors_single_slot_rings() {
        assert_eq!(sanitize_capacity(0), 0);
        assert_eq!(sanitize_capacity(1), MIN_NON_ZERO_CAPACITY);
        assert_eq!(sanitize_capacity(10), 10);
    }

    #[test]
    fn zero_capacity_recorder_is_a_noop() {
        let recorder = PolicyDenyRecorder::with_capacity(0);
        let now = Utc::now();
        recorder.record(event("rule-a", "deny", now));
        recorder.record(event("rule-b", "deny", now));
        assert!(recorder.is_empty());
        assert_eq!(recorder.capacity(), 0);
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        assert_eq!(aggregate.total_denies, 0);
        assert!(aggregate.grouped.is_empty());
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let recorder = PolicyDenyRecorder::with_capacity(3);
        let now = Utc::now();
        for i in 0..5u32 {
            recorder.record(event(
                &format!("rule-{i}"),
                "deny",
                now + ChronoDuration::seconds(i as i64),
            ));
        }
        assert_eq!(recorder.len(), 3);
        // Confirm the three retained events are the newest by aggregating —
        // older rules ("rule-0", "rule-1") must not appear.
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        let retained_rules: Vec<_> = aggregate.grouped.iter().map(|g| g.rule.as_str()).collect();
        assert!(retained_rules.contains(&"rule-2"));
        assert!(retained_rules.contains(&"rule-3"));
        assert!(retained_rules.contains(&"rule-4"));
        assert!(!retained_rules.contains(&"rule-0"));
        assert!(!retained_rules.contains(&"rule-1"));
    }

    #[test]
    fn aggregate_filters_by_window() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        recorder.record(event(
            "rule-old",
            "deny",
            now - ChronoDuration::seconds(600),
        ));
        recorder.record(event(
            "rule-recent",
            "deny",
            now - ChronoDuration::seconds(10),
        ));
        recorder.record(event(
            "rule-recent",
            "deny",
            now - ChronoDuration::seconds(5),
        ));

        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        assert_eq!(aggregate.total_denies, 2);
        assert_eq!(aggregate.grouped.len(), 1);
        let group = &aggregate.grouped[0];
        assert_eq!(group.rule, "rule-recent");
        assert_eq!(group.count, 2);
    }

    #[test]
    fn aggregate_groups_by_four_tuple() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        recorder.record(event("rule-a", "namespace_mismatch", now));
        recorder.record(event("rule-a", "namespace_mismatch", now));
        recorder.record(event_full(
            "rule-a",
            Some("spiffe://cluster.local/ns/staging/sa/other"),
            Some("spiffe://cluster.local/ns/prod/sa/api"),
            "namespace_mismatch",
            now,
        ));
        recorder.record(event("rule-a", "different_reason", now));

        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        assert_eq!(aggregate.total_denies, 4);
        // Three distinct groups: (rule, src, dst, reason) all participate
        // (different source ⇒ separate group; different reason ⇒ separate).
        assert_eq!(aggregate.grouped.len(), 3);
        let top = &aggregate.grouped[0];
        assert_eq!(top.count, 2);
        assert_eq!(top.rule, "rule-a");
        assert_eq!(top.reason, "namespace_mismatch");
    }

    #[test]
    fn aggregate_sorts_by_count_desc_then_last_at_desc() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        // Group A: 3 events, oldest last_at
        for delta in [60, 50, 40] {
            recorder.record(event_full(
                "rule-a",
                Some("spiffe://cluster.local/ns/a/sa/x"),
                Some("spiffe://cluster.local/ns/api/sa/y"),
                "deny",
                now - ChronoDuration::seconds(delta),
            ));
        }
        // Group B: 3 events, newest last_at — should sort BEFORE A on tie.
        for delta in [20, 10, 5] {
            recorder.record(event_full(
                "rule-b",
                Some("spiffe://cluster.local/ns/b/sa/x"),
                Some("spiffe://cluster.local/ns/api/sa/y"),
                "deny",
                now - ChronoDuration::seconds(delta),
            ));
        }
        // Group C: 1 event, alone — should sort after both 3-count groups.
        recorder.record(event_full(
            "rule-c",
            Some("spiffe://cluster.local/ns/c/sa/x"),
            Some("spiffe://cluster.local/ns/api/sa/y"),
            "deny",
            now - ChronoDuration::seconds(1),
        ));

        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(120), 50);
        assert_eq!(aggregate.total_denies, 7);
        assert_eq!(aggregate.grouped.len(), 3);
        assert_eq!(aggregate.grouped[0].rule, "rule-b");
        assert_eq!(aggregate.grouped[0].count, 3);
        assert_eq!(aggregate.grouped[1].rule, "rule-a");
        assert_eq!(aggregate.grouped[1].count, 3);
        assert_eq!(aggregate.grouped[2].rule, "rule-c");
        assert_eq!(aggregate.grouped[2].count, 1);
    }

    #[test]
    fn aggregate_respects_limit_cap() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        for i in 0..5u32 {
            recorder.record(event(&format!("rule-{i}"), "deny", now));
        }
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 2);
        assert_eq!(aggregate.total_denies, 5);
        assert_eq!(aggregate.grouped.len(), 2);
    }

    #[test]
    fn aggregate_zero_limit_skips_grouping_but_keeps_total() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        recorder.record(event("rule-a", "deny", now));
        recorder.record(event("rule-b", "deny", now));
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 0);
        assert_eq!(aggregate.total_denies, 2);
        assert!(aggregate.grouped.is_empty());
    }

    #[test]
    fn aggregate_first_at_tracks_earliest_in_group() {
        let recorder = PolicyDenyRecorder::with_capacity(16);
        let now = Utc::now();
        recorder.record(event("rule-a", "deny", now - ChronoDuration::seconds(50)));
        recorder.record(event("rule-a", "deny", now - ChronoDuration::seconds(10)));
        recorder.record(event("rule-a", "deny", now - ChronoDuration::seconds(30)));
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        let group = &aggregate.grouped[0];
        assert_eq!(group.count, 3);
        // Earliest of the three.
        assert!(group.first_at <= now - ChronoDuration::seconds(49));
        assert!(group.first_at >= now - ChronoDuration::seconds(51));
        // Latest of the three.
        assert!(group.last_at <= now - ChronoDuration::seconds(9));
        assert!(group.last_at >= now - ChronoDuration::seconds(11));
    }

    #[test]
    fn recorder_handles_null_principals() {
        let recorder = PolicyDenyRecorder::with_capacity(8);
        let now = Utc::now();
        recorder.record(event_full(
            "unauthenticated_baggage",
            None,
            None,
            "unauthenticated_baggage",
            now,
        ));
        recorder.record(event_full(
            "unauthenticated_baggage",
            None,
            None,
            "unauthenticated_baggage",
            now,
        ));
        let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 50);
        assert_eq!(aggregate.grouped.len(), 1);
        assert_eq!(aggregate.grouped[0].count, 2);
        assert!(aggregate.grouped[0].source.is_none());
        assert!(aggregate.grouped[0].destination.is_none());
    }

    #[test]
    fn reset_capacity_for_tests_clears_state() {
        let recorder = PolicyDenyRecorder::with_capacity(4);
        let now = Utc::now();
        recorder.record(event("rule-a", "deny", now));
        assert_eq!(recorder.len(), 1);
        recorder.reset_capacity_for_tests(8);
        assert_eq!(recorder.len(), 0);
        assert_eq!(recorder.capacity(), 8);
    }
}

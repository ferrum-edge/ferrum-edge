//! UDP response-amplification budget and fixed-cardinality observability.
//!
//! Accounting is **cumulative per admitted client request**: every backend
//! response datagram charges the same remaining payload-byte budget. Each
//! policy-admitted client datagram **accrues** its per-request budget onto the
//! session's remaining budget instead of resetting it, so an in-flight reply is
//! charged against the budget its request earned rather than a later, smaller
//! request's budget. Accrual is saturating and capped at a fixed multiple of a
//! single per-request budget, so a long-lived session can neither accumulate
//! unbounded credit nor overflow the accumulator, while the aggregate bound —
//! a session's total outbound bytes never exceeds `factor ×` its total inbound
//! bytes — is preserved exactly. A per-datagram size check is not sufficient —
//! several in-budget replies to one small request would otherwise amplify
//! without bound. A zero-length response still consumes one unit of remaining
//! budget so a finite factor cannot admit an unbounded packet count.
//!
//! Sessions start at zero; each admitted request is credited exactly once,
//! immediately before its backend send. Credit remains live until charged or
//! the session expires. Exhausting the budget leaves no credit for the next
//! exchange. UDP has no generic request-completion marker, so a short reply
//! does not retire unused credit that may still fund delayed reply datagrams.
//!
//! Metrics are process-wide and unlabeled except for the Prometheus plugin's
//! own gateway-namespace series. They never carry route, backend, source,
//! factor, or error-text labels.

use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;

/// Finite response-amplification default applied to every UDP/DTLS proxy that
/// has no more specific valid policy, regardless of configuration source.
///
/// `Proxy::normalize_fields()` projects this onto any UDP/DTLS proxy whose
/// `udp_max_response_amplification_factor` is unset, so file, database, admin
/// API, CP→DP, mesh, and Gateway API proxies all start bounded. Operators who
/// genuinely need unlimited replies set the explicit `0` sentinel
/// (`factor_is_unlimited`).
pub const DEFAULT_UDP_AMPLIFICATION_FACTOR: f32 = 8.0;

/// Inclusive ceiling for a finite amplification factor. Values above this are
/// rejected at admission; protocols that need more must use the explicit
/// unlimited override.
pub const MAX_UDP_AMPLIFICATION_FACTOR: f32 = 1024.0;

/// Fixed multiple of a single per-request budget that caps how much remaining
/// response budget a session may hold at once. Accrual never lowers the
/// accumulator below what it already holds, so a smaller follow-up request can
/// never clamp away credit earned by a larger in-flight request; the cap only
/// stops credit from growing without bound across a long-lived session. The
/// amplification bound itself is independent of this constant: a session's
/// total outbound bytes remain bounded by `factor ×` its total inbound bytes
/// regardless of the cap.
pub const UDP_AMPLIFICATION_BUDGET_CAP_MULTIPLE: u64 = 16;

/// Ferrum-owned Direct Policy Attachment group.
pub const UDP_AMPLIFICATION_POLICY_GROUP: &str = "gateway.ferrum.io";
/// CRD version watched by the Kubernetes controller.
pub const UDP_AMPLIFICATION_POLICY_VERSION: &str = "v1alpha1";
/// Kind of the Ferrum UDP amplification policy CRD.
pub const UDP_AMPLIFICATION_POLICY_KIND: &str = "UDPResponseAmplificationPolicy";
/// Plural resource name.
pub const UDP_AMPLIFICATION_POLICY_PLURAL: &str = "udpresponseamplificationpolicies";

/// Independently cache-line padded so allowed/drop/policy counters do not
/// false-share on the UDP response path.
static RESPONSES_ALLOWED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static RESPONSES_DROPPED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static POLICY_INVALID: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
static POLICY_UNLIMITED: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));

/// Snapshot of the unlabeled amplification counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpAmplificationMetricsSnapshot {
    pub responses_allowed: u64,
    pub responses_dropped: u64,
    pub policy_invalid: u64,
    pub policy_unlimited: u64,
}

/// Process-wide unlabeled counters for Prometheus.
pub fn metrics_snapshot() -> UdpAmplificationMetricsSnapshot {
    UdpAmplificationMetricsSnapshot {
        responses_allowed: RESPONSES_ALLOWED.load(Ordering::Relaxed),
        responses_dropped: RESPONSES_DROPPED.load(Ordering::Relaxed),
        policy_invalid: POLICY_INVALID.load(Ordering::Relaxed),
        policy_unlimited: POLICY_UNLIMITED.load(Ordering::Relaxed),
    }
}

pub fn record_response_allowed() {
    RESPONSES_ALLOWED.fetch_add(1, Ordering::Relaxed);
}

/// Record a dropped response. Returns the new process-wide drop count for
/// rate-limited diagnostics.
pub fn record_response_dropped() -> u64 {
    RESPONSES_DROPPED.fetch_add(1, Ordering::Relaxed) + 1
}

pub fn record_policy_invalid() {
    POLICY_INVALID.fetch_add(1, Ordering::Relaxed);
}

pub fn record_policy_unlimited() {
    POLICY_UNLIMITED.fetch_add(1, Ordering::Relaxed);
}

/// Whether `factor` is an admissible finite amplification ratio.
///
/// Deliberately excludes `0.0`: `udp_amplification_response_budget` relies on
/// this predicate to fail closed to a zero budget, so the explicit-unlimited
/// sentinel must never reach it as a "valid" ratio.
pub fn factor_is_valid(factor: f32) -> bool {
    factor.is_finite() && factor > 0.0 && factor <= MAX_UDP_AMPLIFICATION_FACTOR
}

/// Whether `factor` is admissible at config validation for a UDP/DTLS proxy.
///
/// Accepts every finite ratio `factor_is_valid` accepts, plus the explicit
/// unlimited sentinel `0`. Negatives, NaN, infinities, and values above
/// `MAX_UDP_AMPLIFICATION_FACTOR` are still rejected.
pub fn factor_is_valid_or_unlimited(factor: f32) -> bool {
    factor == 0.0 || factor_is_valid(factor)
}

/// Whether a configured factor means "no amplification limit".
///
/// `None` is an un-normalized proxy (a test fixture or an internal
/// constructor) that never had a budget; `Some(0.0)` is the operator's
/// explicit opt-out. Both skip the response guard.
#[inline]
pub fn factor_is_unlimited(factor: Option<f32>) -> bool {
    match factor {
        None => true,
        Some(configured) => configured == 0.0,
    }
}

/// Maximum response payload allowed by the UDP amplification guard for one
/// admitted client request.
///
/// A zero-length request receives an explicit one-byte reply allowance so the
/// legal datagram does not create a black-holed session. Nonempty requests keep
/// the configured payload ratio exactly. Invalid factors fail closed to a zero
/// budget so no response is forwarded.
pub fn udp_amplification_response_budget(request_size: u64, factor: f32) -> u64 {
    if !factor_is_valid(factor) {
        return 0;
    }
    if request_size == 0 {
        return 1;
    }
    let product = request_size as f64 * f64::from(factor);
    if !product.is_finite() || product < 0.0 {
        0
    } else if product >= u64::MAX as f64 {
        u64::MAX
    } else {
        product as u64
    }
}

/// Accrue the response budget earned by a newly admitted client datagram onto
/// the session's remaining budget, saturating at a fixed multiple of this
/// request's own budget.
///
/// Unlike a reset, accrual never discards budget a prior in-flight request
/// earned, so a backend reply for request *N* is charged against the budget
/// request *N* accumulated rather than a later, smaller request's budget. The
/// accumulator is monotonic under accrual: when credit from larger requests
/// already exceeds this request's cap, the smaller cap does not lower it. The
/// cap keeps a long-lived session from accumulating unbounded credit while the
/// aggregate bound — outbound bytes ≤ `factor ×` inbound bytes — is preserved
/// exactly. Returns the new remaining budget.
///
/// Initialize `remaining` to zero, including for the first request: seeding it
/// with that request's budget and then publishing would double its allowance.
pub fn publish_request_budget(remaining: &AtomicU64, request_size: u64, factor: f32) -> u64 {
    let budget = udp_amplification_response_budget(request_size, factor);
    if budget == 0 {
        return 0;
    }
    let cap = budget.saturating_mul(UDP_AMPLIFICATION_BUDGET_CAP_MULTIPLE);
    loop {
        let current = remaining.load(Ordering::Acquire);
        let next = current.saturating_add(budget).min(cap).max(current);
        match remaining.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(_) => continue,
        }
    }
}

/// Atomically charge `bytes` against a session's remaining response budget.
///
/// Nonempty datagrams charge their payload size exactly. A zero-length
/// datagram still consumes one unit so a finite budget cannot admit an
/// unbounded number of empty replies. Returns `true` when the datagram is
/// admitted. The check is fail-closed: insufficient remaining refuses without
/// partial consumption. Several in-budget datagrams still fail closed once
/// their cumulative charge exceeds the accumulated budget.
pub fn charge_response_budget(remaining: &AtomicU64, bytes: u64) -> bool {
    let charge = bytes.max(1);
    loop {
        let current = remaining.load(Ordering::Acquire);
        if current < charge {
            return false;
        }
        match remaining.compare_exchange_weak(
            current,
            current - charge,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(_) => continue,
        }
    }
}

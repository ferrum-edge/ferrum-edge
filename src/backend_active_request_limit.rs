//! Destination-wide **active-request** circuit breaker for HTTP-family backend
//! dispatch.
//!
//! Enforces Istio DestinationRule `connectionPool.http.http2MaxRequests`:
//!
//! > Maximum number of active requests to a destination. Applicable to both
//! > HTTP1.1 and HTTP2.
//!
//! and its Envoy equivalent, the cluster circuit breaker
//! `thresholds[].max_requests` (maximum parallel requests to an upstream
//! cluster). It is **not** an HTTP/2 transport setting: Istio's neighbouring
//! `connectionPool.http.maxConcurrentStreams` is the per-connection HTTP/2
//! stream control, which Ferrum maps separately onto
//! `Proxy.pool_http2_max_concurrent_streams` and the hyper
//! `http2::Builder::max_concurrent_streams` / `initial_max_send_streams` knobs
//! (see [`crate::config::types::UpstreamPortOverride`]).
//!
//! # Why a gateway-side counter and not SETTINGS
//!
//! A per-connection stream cap cannot express this field:
//!
//! * HTTP/1.1 has no stream concept at all, yet the Istio field explicitly
//!   applies to it.
//! * Every physical H2/gRPC connection — and every pool shard — is built with
//!   its own allowance, so `N` connections admit `N × cap` requests.
//! * Peer SETTINGS replace the local initial bound, so the operator's ceiling is
//!   not durable.
//! * `max_concurrent_streams` on a server builder also describes streams the
//!   *peer* may open toward Ferrum, which is not an outbound request budget.
//!
//! The authoritative budget therefore lives here: one shared counter per
//! logical destination, consulted by every HTTP-family upstream attempt before
//! backend dispatch, and released only when that attempt's
//! request/response exchange is completely over.
//!
//! # Scope key — logical destination, not socket address
//!
//! The lane is keyed by the **effective policy identity** of the destination:
//!
//! ```text
//! <namespace>|<logical destination>|<policy port>|<subset>
//! ```
//!
//! * `namespace` isolates tenants.
//! * `logical destination` is the referenced upstream id (the Kubernetes
//!   Service / DestinationRule cluster) when the proxy has one, else the proxy
//!   id for a direct-backend route. It deliberately is **not** the resolved
//!   backend host/IP: Envoy's breaker is per cluster, so every endpoint of one
//!   destination shares one budget, and two Services that happen to resolve to
//!   the same pods keep independent budgets (issue #3778's logical-scope
//!   contract, which this module is compatible with but does not depend on).
//! * `policy port` is the DestinationRule policy port
//!   (`dispatch_policy_port_for_target`), so a `targetPort` remap does not split
//!   one destination's budget and an explicit `portLevelSettings[{port}]` cap is
//!   visible to every frontend.
//! * `subset` is the selected DestinationRule subset (`None` is a distinct lane
//!   from every named subset), length-prefixed so a hostile subset name cannot
//!   collide with a sibling lane.
//!
//! The lane is deliberately stable across config generations. A reload must
//! not mint a fresh allowance while requests admitted by the previous config
//! are still active: every acquire applies the current cap to the shared count.
//! Lowering a cap therefore sheds until the count drains below the new value;
//! raising it takes effect immediately; removing a cap stops new acquisitions
//! while existing guards keep the lane counted; and re-adding it cannot ignore
//! those guards. A lane is evicted the moment its count returns to zero, so
//! service/subset churn cannot grow the map without bound.
//!
//! # Lifetime — the whole exchange, not the headers
//!
//! The permit is acquired during backend admission (before any backend socket
//! is dialed or any byte is sent) and is carried as an owned RAII guard by the
//! response body, so it is released exactly once on every terminal path:
//! buffered completion, streamed body EOF, gRPC trailers, client disconnect,
//! backend reset/GOAWAY, deadline, task cancellation, and graceful shutdown.
//! Releasing at response headers would leave a streaming or long-lived gRPC
//! response uncounted while it still occupies backend capacity — the exact
//! failure the Istio field exists to prevent.
//!
//! A sequential retry is a new active request: the previous attempt's permit is
//! released before the next attempt acquires, and concurrently-active attempts
//! each hold their own permit.
//!
//! # Overflow behaviour
//!
//! A saturated destination sheds the request **before** a backend attempt
//! exists: no dial, no bytes, no backend signal. The rejection is therefore
//! classified as a gateway-side policy overload (HTTP 503, gRPC `UNAVAILABLE`
//! through the existing admission-rejection shaping) and is neutral to passive
//! health, the circuit breaker, and adaptive concurrency. Nothing is queued
//! behind the limiter.
//!
//! # Hot-path discipline (mirrors [`crate::backend_pending_limit`])
//!
//! * No configured cap (`cap == None`) returns `Ok(None)` after one `Option`
//!   check and never touches the `DashMap`.
//! * The capped hit path builds its key into a reused thread-local `String` and
//!   looks the lane up by borrowed `&str` (`String: Borrow<str>`), so a repeat
//!   request to a known destination allocates nothing. Only the cold first
//!   request for a lane allocates the owned key.
//! * The map is a sharded [`dashmap::DashMap`] sized by
//!   [`crate::util::sharding::pool_shard_amount`]; each counter is
//!   [`crossbeam_utils::CachePadded`] so a hot destination does not false-share.
//! * Check-and-reserve happens **together under the shard lock**, and the
//!   drop-time decrement + at-zero eviction run in one `remove_if` under that
//!   same lock, so an acquirer can never resurrect an orphaned counter (cap
//!   bypass) nor strand a zero-count lane.
//!
//! # Observability
//!
//! Fixed-cardinality process totals only ([`render_prometheus`]): active
//! permits, admitted total, and rejected total. Raw Service / subset / host /
//! namespace identity is deliberately never a metric label — it is unbounded
//! operator-controlled input. A lock-free gateway-wide limiter bounds the
//! rejection summary to one line per second and reports the suppressed count.

use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crossbeam_utils::CachePadded;
use dashmap::DashMap;

/// Currently held destination active-request permits, process-wide.
static ACTIVE_PERMITS: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
/// Permits granted since start, process-wide.
static ADMITTED_TOTAL: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));
/// Requests shed because their destination was at its active-request ceiling.
static REJECTED_TOTAL: CachePadded<AtomicU64> = CachePadded::new(AtomicU64::new(0));

thread_local! {
    /// Reused per-thread buffer for destination-lane key lookups on the capped
    /// hot path. Mirrors the zero-allocation strategy of
    /// `backend_pending_limit` / `backend_capabilities` / `pool`.
    static ACTIVE_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}

/// The effective policy identity of one logical destination.
///
/// Borrowed for the duration of an acquire; the limiter copies what it needs
/// into the flat lane key, so nothing here is retained.
#[derive(Debug, Clone, Copy)]
pub struct DestinationScope<'a> {
    /// Tenant/namespace of the route's effective proxy.
    pub namespace: &'a str,
    /// Logical destination: the referenced upstream id when the proxy has one,
    /// else the proxy id. Never a resolved backend host or IP.
    pub destination: &'a str,
    /// DestinationRule policy port (`dispatch_policy_port_for_target`).
    pub policy_port: u16,
    /// Selected DestinationRule subset. `None` is its own lane.
    pub subset: Option<&'a str>,
}

/// Write the flat lane key. Every variable-length component is length-prefixed
/// so no operator-controlled value can forge another lane's key.
#[inline]
fn write_active_key(buf: &mut String, scope: &DestinationScope<'_>) {
    let _ = write!(buf, "n{}:", scope.namespace.len());
    buf.push_str(scope.namespace);
    let _ = write!(buf, "|d{}:", scope.destination.len());
    buf.push_str(scope.destination);
    let _ = write!(buf, "|{}|", scope.policy_port);
    match scope.subset {
        Some(subset) => {
            let _ = write!(buf, "s{}:", subset.len());
            buf.push_str(subset);
        }
        None => buf.push('n'),
    }
}

/// Shared per-destination active-request counter map.
///
/// One instance lives on `ProxyState` and is shared by every HTTP-family
/// upstream attempt for the gateway lifetime, so the cap bounds active requests
/// per logical destination across all transports, connections, and pool shards.
pub struct BackendActiveRequestLimiter {
    inner: Arc<DashMap<String, Arc<BackendActiveRequestCounter>>>,
    rejection_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    rejection_warn_epoch: Instant,
}

#[derive(Debug)]
struct BackendActiveRequestCounter {
    key: String,
    count: CachePadded<AtomicU64>,
}

impl Default for BackendActiveRequestLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendActiveRequestLimiter {
    /// Construct a limiter with `DashMap` sharding sized for the hot path.
    ///
    /// A `0` shard override means "auto" (`max(64, num_cpus * 16)`), matching
    /// every other hot-path map in the codebase.
    pub fn new() -> Self {
        Self::with_shard_amount(crate::util::sharding::pool_shard_amount(0))
    }

    /// Construct a limiter with an explicit shard amount so callers can honor
    /// the operator-facing `FERRUM_POOL_SHARD_AMOUNT` knob.
    pub fn with_shard_amount(shards: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::with_shard_amount(shards)),
            rejection_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new(),
            rejection_warn_epoch: Instant::now(),
        }
    }

    /// Record one saturation diagnostic and return the number suppressed since
    /// the previous emitted summary. One limiter covers the gateway-wide
    /// destination map, bounding adversarial saturation logs without adding a
    /// second per-destination map or retaining churned destination identities.
    #[inline]
    pub(crate) fn record_rejection_warning(&self) -> Option<u64> {
        let now_ms =
            u64::try_from(self.rejection_warn_epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.rejection_warn.on_event(now_ms)
    }

    /// Reserve one active-request slot for `scope`.
    ///
    /// `cap == None` (no configured `http2MaxRequests`) is the common case and
    /// costs one `Option` check. `Ok(Some(guard))` means the slot is held until
    /// the guard drops; `Err` means the destination is saturated and the caller
    /// must shed the request before dispatching a backend attempt.
    pub fn try_acquire(
        &self,
        scope: DestinationScope<'_>,
        cap: Option<u32>,
    ) -> Result<Option<BackendActiveRequestGuard>, BackendActiveRequestLimitExceeded> {
        let Some(cap) = cap else {
            return Ok(None);
        };
        let cap_u64 = u64::from(cap);
        // A zero cap denies everything — reject BEFORE touching the map. No
        // guard is ever handed out for it, so the drop-time eviction could never
        // fire and a created lane would be permanent. `http2MaxRequests: 0` is
        // rejected at translate time, so this is defensive.
        if cap_u64 == 0 {
            REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
            return Err(BackendActiveRequestLimitExceeded { current: 0, cap: 0 });
        }
        let counter = ACTIVE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_active_key(&mut buf, &scope);
            // Hit path: borrowed `&str` `get_mut` write-locks only this shard
            // and allocates no key. The cap check and the reservation happen
            // under that one lock, so they are atomic with a concurrent
            // release's eviction.
            if let Some(existing) = self.inner.get_mut(buf.as_str()) {
                let current = existing.count.load(Ordering::Relaxed);
                if current >= cap_u64 {
                    return Err(BackendActiveRequestLimitExceeded {
                        current,
                        cap: cap_u64,
                    });
                }
                existing.count.fetch_add(1, Ordering::Relaxed);
                return Ok(existing.clone());
            }
            // Cold path: a new lane — allocate the owned key once and take the
            // first slot. `entry` re-resolves under the shard lock in case a
            // concurrent acquirer inserted between the `get_mut` miss and here.
            let entry = self.inner.entry(buf.clone()).or_insert_with(|| {
                Arc::new(BackendActiveRequestCounter {
                    key: buf.clone(),
                    count: CachePadded::new(AtomicU64::new(0)),
                })
            });
            let current = entry.count.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendActiveRequestLimitExceeded {
                    current,
                    cap: cap_u64,
                });
            }
            entry.count.fetch_add(1, Ordering::Relaxed);
            Ok(entry.clone())
        });
        let counter = match counter {
            Ok(counter) => counter,
            Err(exceeded) => {
                REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
                return Err(exceeded);
            }
        };
        ACTIVE_PERMITS.fetch_add(1, Ordering::Relaxed);
        ADMITTED_TOTAL.fetch_add(1, Ordering::Relaxed);
        Ok(Some(BackendActiveRequestGuard {
            counters: Arc::clone(&self.inner),
            counter,
        }))
    }

    /// Current active-request count for a destination lane. Test/diagnostics
    /// only — the hot path uses [`Self::try_acquire`] directly.
    pub fn current(&self, scope: DestinationScope<'_>) -> u64 {
        ACTIVE_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_active_key(&mut buf, &scope);
            self.inner
                .get(buf.as_str())
                .map(|counter| counter.count.load(Ordering::Relaxed))
                .unwrap_or(0)
        })
    }

    /// Number of resident lanes. Test/diagnostics only.
    pub fn resident_lanes(&self) -> usize {
        self.inner.len()
    }
}

/// RAII permit for one active request to a logical destination.
///
/// Must be held for the ENTIRE upstream exchange (through response-body EOF /
/// trailers / disconnect / error), never released at response headers.
#[derive(Debug)]
pub struct BackendActiveRequestGuard {
    counters: Arc<DashMap<String, Arc<BackendActiveRequestCounter>>>,
    counter: Arc<BackendActiveRequestCounter>,
}

impl Drop for BackendActiveRequestGuard {
    fn drop(&mut self) {
        // Release and evict-if-last in ONE shard-locked `remove_if`: the
        // predicate runs under the DashMap shard write lock, so the decrement
        // and the at-zero removal are atomic with respect to `try_acquire`
        // (which checks-and-increments under the same lock). That mutual
        // exclusion is what makes an orphaned-counter cap bypass and a stranded
        // zero-count lane structurally impossible.
        //
        // `fetch_sub` returning 1 means this drop took the lane to zero → remove
        // it, so destination/subset churn cannot grow the map for the
        // gateway lifetime. `fetch_sub` (not `saturating_sub`) so a
        // double-release bug underflows loudly instead of being masked.
        self.counters
            .remove_if(self.counter.key.as_str(), |_, current| {
                current.count.fetch_sub(1, Ordering::AcqRel) == 1
            });
        ACTIVE_PERMITS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Returned when a destination is already at its `http2MaxRequests` ceiling.
#[derive(Debug, Clone, Copy)]
pub struct BackendActiveRequestLimitExceeded {
    pub current: u64,
    pub cap: u64,
}

impl std::fmt::Display for BackendActiveRequestLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend http2MaxRequests reached: {} active requests (cap {})",
            self.current, self.cap
        )
    }
}

impl std::error::Error for BackendActiveRequestLimitExceeded {}

/// Backend-admission permit wrapper so the destination guard rides the same
/// carrier as adaptive-concurrency permits and is therefore released exactly
/// when the client-visible response body reaches a terminal state.
///
/// It records no backend outcome: the breaker is a capacity gate, not a health
/// signal.
pub struct DestinationActiveRequestPermit {
    _guard: BackendActiveRequestGuard,
}

impl DestinationActiveRequestPermit {
    pub fn new(guard: BackendActiveRequestGuard) -> Self {
        Self { _guard: guard }
    }
}

impl crate::plugins::BackendAdmissionPermit for DestinationActiveRequestPermit {
    fn record_backend_outcome(&self, _outcome: crate::plugins::BackendAdmissionOutcome) {}
}

/// Fixed-cardinality snapshot of the destination breaker. No per-destination
/// labels — see the module docs.
pub fn render_prometheus(output: &mut String, gateway_ns_label: &str) {
    output.push_str(
        "# HELP ferrum_destination_active_requests Active upstream requests currently holding a DestinationRule http2MaxRequests permit.\n",
    );
    output.push_str("# TYPE ferrum_destination_active_requests gauge\n");
    render_value(
        output,
        "ferrum_destination_active_requests",
        ACTIVE_PERMITS.load(Ordering::Relaxed),
        gateway_ns_label,
    );
    output.push_str(
        "# HELP ferrum_destination_active_requests_admitted_total Upstream requests admitted through the DestinationRule http2MaxRequests breaker.\n",
    );
    output.push_str("# TYPE ferrum_destination_active_requests_admitted_total counter\n");
    render_value(
        output,
        "ferrum_destination_active_requests_admitted_total",
        ADMITTED_TOTAL.load(Ordering::Relaxed),
        gateway_ns_label,
    );
    output.push_str(
        "# HELP ferrum_destination_active_requests_rejected_total Upstream requests shed because their destination was at its http2MaxRequests ceiling.\n",
    );
    output.push_str("# TYPE ferrum_destination_active_requests_rejected_total counter\n");
    render_value(
        output,
        "ferrum_destination_active_requests_rejected_total",
        REJECTED_TOTAL.load(Ordering::Relaxed),
        gateway_ns_label,
    );
}

/// Emit one sample, mirroring the shared `gateway_<namespace>` label convention
/// (the label string carries its own leading comma, or is empty).
fn render_value(output: &mut String, name: &str, value: u64, gateway_ns_label: &str) {
    if gateway_ns_label.is_empty() {
        let _ = writeln!(output, "{name} {value}");
    } else {
        let labels = gateway_ns_label
            .strip_prefix(',')
            .unwrap_or(gateway_ns_label);
        let _ = writeln!(output, "{name}{{{labels}}} {value}");
    }
}

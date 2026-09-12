//! Circuit breaker for preventing cascading failures.
//!
//! Implements a three-state circuit breaker pattern:
//! - **Closed**: Normal operation, requests pass through.
//! - **Open**: After repeated failures, requests are rejected with 503.
//! - **Half-Open**: After a timeout, a limited number of probe requests are allowed.

use crate::config::types::CircuitBreakerConfig;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tracing::{info, warn};

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

// The breaker's open `generation`, its `state`, and its `half_open_in_flight`
// probe counter are packed into a SINGLE `AtomicU64` so that every state
// transition, probe admission, and generation bump is ONE atomic
// compare-exchange. With separate atomics, no ordering of two stores can make
// "publish state X", "set/clear the probe count", and "advance the generation"
// happen together, leaving race windows in which a concurrent `can_execute()`
// observes a transient triple and over-admits, admits after a reopen, wedges the
// breaker at capacity, OR (#1649) captures a stale/loser-advanced generation.
// Fusing them removes every window: the high 32 bits hold the generation, the
// next 2 bits hold the state, and the low 30 bits hold the in-flight count (far
// beyond any realistic `half_open_max_requests`). Because the generation bump
// rides the SAME CAS as the OPEN transition, only the transition winner advances
// it, and the new generation is visible to any observer that sees OPEN — so a
// deferred streaming outcome captured at admission compares against a coherent
// generation (#1649 R5 finding 2 / R7 — no bump-before/after race, no loser
// bumps). The generation is compared for equality only; 32 bits (4 billion opens
// of a single breaker within one streaming request's lifetime) cannot collide in
// practice, and it wraps harmlessly.
const STATE_SHIFT: u32 = 30;
const COUNT_MASK: u32 = (1u32 << STATE_SHIFT) - 1;

#[inline]
const fn pack_full(generation: u32, state: u8, count: u32) -> u64 {
    ((generation as u64) << 32)
        | (((state as u32) << STATE_SHIFT) as u64)
        | ((count & COUNT_MASK) as u64)
}

#[inline]
const fn packed_generation(packed: u64) -> u32 {
    (packed >> 32) as u32
}

#[inline]
const fn packed_state(packed: u64) -> u8 {
    ((packed as u32) >> STATE_SHIFT) as u8
}

#[inline]
const fn packed_count(packed: u64) -> u32 {
    (packed as u32) & COUNT_MASK
}

/// Circuit breaker state for a single proxy or target.
pub struct CircuitBreaker {
    /// Packed `(open_generation, state, half_open_in_flight)` — high 32 bits
    /// generation, next 2 bits state, low 30 bits probe count. See the
    /// module-level note above for why these are fused.
    ///
    /// The generation is advanced on every CLOSED→OPEN / HALF_OPEN→OPEN
    /// transition (one "open generation"), in the SAME CAS that publishes OPEN. A
    /// request captures it at admission (`can_execute`); a deferred streaming
    /// outcome compares it at completion so a stream admitted under one generation
    /// cannot heal/reopen a *later* HALF_OPEN cycle it never probed (#1649 — the
    /// breaker stays correct even though the streaming CB outcome is recorded at
    /// body completion). HALF_OPEN admission does NOT advance it — it is the same
    /// open cycle.
    packed: AtomicU64,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    /// Process-relative monotonic tick of the failure that opened/reopened the
    /// breaker. This is the only timestamp consulted for state transitions.
    last_failure_tick_ms: AtomicU64,
    /// Unix epoch milliseconds for diagnostics only. Never consulted for a
    /// breaker state transition, so wall-clock jumps cannot change recovery.
    last_failure_epoch_ms: AtomicU64,
    /// Process-relative monotonic tick of the NEWEST HALF_OPEN probe admission
    /// of the current open cycle, and the dwell's only time input.
    ///
    /// Probe slots are anonymous — a release does not say which admission it
    /// settles — so the dwell is armed off the newest admission rather than a
    /// per-slot timestamp: if the newest admission is older than the dwell,
    /// then EVERY slot still held was admitted at least a dwell ago. That is
    /// strictly conservative (it can never reclaim a probe that was admitted
    /// within the dwell) which is the direction that matters, because a reclaim
    /// while a real probe is still in flight lets a second probe reach the
    /// backend the breaker is protecting.
    ///
    /// Written before the CAS that admits a probe (and before the CAS that
    /// publishes HALF_OPEN) so any thread that observes this cycle's packed
    /// value also observes this cycle's tick, never one left over from an
    /// earlier cycle. A thread that then loses its CAS has only refreshed the
    /// tick, which delays a reclaim by at most one dwell — the safe direction.
    half_open_admission_tick_ms: AtomicU64,
    /// Reclaimed-but-not-yet-settled probe slots in the current open cycle.
    ///
    /// A reclaim returns a slot on behalf of a probe that may still settle
    /// later. Because slots are anonymous, that late settle cannot be told
    /// apart from a live probe's; letting it decrement a second time would
    /// make the in-flight count UNDER-state the probes actually running and
    /// over-admit. Instead each reclaim records one unit of debt and the next
    /// release consumes it instead of decrementing, so a reclaim plus its
    /// stale settle costs exactly one slot in aggregate — the same
    /// exactly-once property `HalfOpenProbeGuard::take_slot` gives the
    /// dispatch paths. Cleared whenever the count is zeroed en masse (reopen
    /// or close), because those transitions already forget every slot.
    half_open_reclaim_debt: AtomicU32,
    /// Monotonic count of probe slots this breaker has reclaimed. Exported as
    /// `ferrum_circuit_breaker_probe_reclaimed_total`; any non-zero value is a
    /// probe-slot leak that the dwell has downgraded from a permanent outage
    /// to a bounded delay.
    probe_reclaimed: AtomicU64,
    /// Effective dwell in milliseconds, derived once from
    /// `half_open_probe_dwell_seconds` / `timeout_seconds`.
    half_open_probe_dwell_ms: u64,
    /// Cache key (`namespace|proxy_id` or `namespace|proxy_id::host:port`).
    /// Used ONLY to name the proxy and target in the reclaim warning; the
    /// `host:port` is deliberately confined to the log and never becomes a
    /// metric label.
    identity: String,
    config: CircuitBreakerConfig,
}

/// Outcome of one bounded attempt to claim a HALF_OPEN probe slot.
enum SlotClaim {
    /// Admitted as a half-open probe; the caller owns one slot.
    Probe,
    /// The breaker recovered to CLOSED under us — ordinary admission.
    Closed,
    /// Every probe slot is held by a probe that has not settled.
    Exhausted,
    /// The breaker is (re)OPEN — reject.
    Rejected,
}

/// Effective HALF_OPEN dwell, in milliseconds.
///
/// Unset derives `max(timeout_seconds * 2, 60)` seconds: long enough that an
/// ordinary slow backend dispatch finishes first, and never shorter than a
/// minute even for a breaker configured with a tiny `timeout_seconds`. A
/// configured value is clamped up to `timeout_seconds` (a dwell shorter than
/// the open window would reclaim probes faster than the breaker admits them)
/// and to at least 1 second (a zero dwell would reclaim every probe on the
/// very next admission attempt).
fn derive_half_open_probe_dwell_ms(config: &CircuitBreakerConfig) -> u64 {
    let seconds = match config.half_open_probe_dwell_seconds {
        Some(configured) => configured.max(config.timeout_seconds).max(1),
        None => config.timeout_seconds.saturating_mul(2).max(60),
    };
    seconds.saturating_mul(1000)
}

/// Error returned when the circuit is open.
#[derive(Debug)]
pub struct CircuitOpenError;

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit breaker is open")
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self::with_identity(String::new(), config)
    }

    /// Cache-backed constructor. `identity` is the breaker's cache key, carried
    /// solely so the probe-reclaim warning can name the proxy and target.
    fn with_identity(identity: String, config: CircuitBreakerConfig) -> Self {
        let half_open_probe_dwell_ms = derive_half_open_probe_dwell_ms(&config);
        Self {
            packed: AtomicU64::new(pack_full(0, STATE_CLOSED, 0)),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_tick_ms: AtomicU64::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            half_open_admission_tick_ms: AtomicU64::new(0),
            half_open_reclaim_debt: AtomicU32::new(0),
            probe_reclaimed: AtomicU64::new(0),
            half_open_probe_dwell_ms,
            identity,
            config,
        }
    }

    /// Check if a request can proceed.
    ///
    /// Returns `Ok(true)` if the request was admitted as a half-open probe
    /// (the caller MUST pass `is_half_open_probe=true` to `record_success`/
    /// `record_failure` so the in-flight counter is decremented correctly).
    /// Returns `Ok(false)` for normal closed-state admission.
    /// Returns `Err` if the circuit is open and the request must be rejected.
    #[inline]
    pub fn can_execute(&self) -> Result<bool, CircuitOpenError> {
        self.can_execute_inner(None)
    }

    /// Deterministic-clock variant used by external unit tests.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn can_execute_at_for_test(&self, monotonic_now_ms: u64) -> Result<bool, CircuitOpenError> {
        self.can_execute_inner(Some(monotonic_now_ms))
    }

    #[inline]
    fn can_execute_inner(&self, monotonic_now_ms: Option<u64>) -> Result<bool, CircuitOpenError> {
        // Acquire pairs with the Release in record_failure() when transitioning
        // CLOSED → OPEN, ensuring visibility of last_failure_tick_ms and
        // failure_count. Using Relaxed here would risk stale reads on ARM/weak-
        // memory architectures, allowing requests to leak through after the
        // circuit opens. The ~5-15ns cost of Acquire is acceptable given that
        // circuit breaker checks are not the bottleneck at scale.
        let packed = self.packed.load(Ordering::Acquire);
        match packed_state(packed) {
            STATE_CLOSED => Ok(false),
            STATE_OPEN => {
                // OPEN recovery is elapsed-time state, so it uses the single
                // process-local monotonic origin. The clock is read only in
                // OPEN; the common CLOSED request path remains one atomic load.
                let now = monotonic_now_ms.unwrap_or_else(crate::socket_opts::monotonic_now_ms);
                let last_failure = self.last_failure_tick_ms.load(Ordering::Relaxed);
                let timeout_ms = self.config.timeout_seconds.saturating_mul(1000);

                if now.saturating_sub(last_failure) >= timeout_ms {
                    // Transition OPEN → HALF_OPEN AND claim the first probe slot
                    // in ONE CAS: the published HALF_OPEN already carries
                    // count=1. There is no instant where HALF_OPEN is visible
                    // with a stale/zeroed count (so no over-admission during a
                    // reopen), and the transition winner *is* an admission, so it
                    // can never be rejected after publishing HALF_OPEN (no wedge).
                    // OPEN always carries count=0 — reopen/close zero the count
                    // atomically and slot releases are no-ops at 0 — so the
                    // expected value below is exact. The generation is PRESERVED
                    // (OPEN→HALF_OPEN is the same open cycle): the desired value
                    // carries the same generation observed in `packed`.
                    let generation = packed_generation(packed);
                    // Arm this cycle's dwell BEFORE publishing HALF_OPEN, so a
                    // concurrent `can_execute` that observes the new HALF_OPEN
                    // cannot read a tick left over from an earlier cycle and
                    // immediately "reclaim" the probe this CAS is admitting.
                    self.half_open_admission_tick_ms
                        .store(now, Ordering::Relaxed);
                    match self.packed.compare_exchange(
                        pack_full(generation, STATE_OPEN, 0),
                        pack_full(generation, STATE_HALF_OPEN, 1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            self.success_count.store(0, Ordering::Relaxed);
                            info!("Circuit breaker transitioning from Open to Half-Open");
                            Ok(true)
                        }
                        Err(actual) => match packed_state(actual) {
                            // Another thread already opened the half-open cycle;
                            // claim a slot through the same bounded CAS.
                            STATE_HALF_OPEN => self.try_acquire_half_open_slot(Some(now)),
                            // Recovered to closed in the meantime.
                            STATE_CLOSED => Ok(false),
                            // Still open (lost the race to a concurrent reopen) —
                            // reject.
                            _ => Err(CircuitOpenError),
                        },
                    }
                } else {
                    Err(CircuitOpenError)
                }
            }
            STATE_HALF_OPEN => self.try_acquire_half_open_slot(monotonic_now_ms),
            _ => Ok(false),
        }
    }

    /// Claim one half-open probe slot, reclaiming a stalled one first if the
    /// dwell has elapsed.
    ///
    /// The OPEN→HALF_OPEN transition winner claims its first slot directly in
    /// `can_execute()` (count=1 is published atomically with HALF_OPEN). The
    /// remaining admission paths — a transition CAS-loser that finds the state
    /// already HALF_OPEN, and a steady-state HALF_OPEN request — funnel through
    /// here.
    ///
    /// When every slot is held, one stalled slot is reclaimed if the dwell has
    /// elapsed (see [`Self::reclaim_stalled_half_open_slot`]) and admission is
    /// re-evaluated once for this caller. Without a reclaim this is exactly the
    /// pre-existing bounded-CAS admission.
    fn try_acquire_half_open_slot(
        &self,
        monotonic_now_ms: Option<u64>,
    ) -> Result<bool, CircuitOpenError> {
        // HALF_OPEN is the recovery path, not the hot path: the CLOSED arm of
        // `can_execute` is still one atomic load and never reads the clock.
        let now = monotonic_now_ms.unwrap_or_else(crate::socket_opts::monotonic_now_ms);
        match self.claim_half_open_slot(now) {
            SlotClaim::Probe => Ok(true),
            SlotClaim::Closed => Ok(false),
            SlotClaim::Rejected => Err(CircuitOpenError),
            SlotClaim::Exhausted => {
                if !self.reclaim_stalled_half_open_slot(now) {
                    return Err(CircuitOpenError);
                }
                // Exactly one retry: the reclaim freed one slot, and losing it
                // to a concurrent admission is an ordinary rejection.
                match self.claim_half_open_slot(now) {
                    SlotClaim::Probe => Ok(true),
                    SlotClaim::Closed => Ok(false),
                    _ => Err(CircuitOpenError),
                }
            }
        }
    }

    /// Claim one half-open probe slot without exceeding the limit, checking the
    /// state and the count together in a single CAS, and distinguishing "every
    /// slot is held" (which the dwell may act on) from "the breaker left
    /// HALF_OPEN" (which it must not).
    ///
    /// Because the expected value carries BOTH the state and the count, an
    /// admission cannot succeed once the breaker has left HALF_OPEN (a
    /// concurrent reopen or close), which closes the admit-after-reopen race,
    /// and the number of concurrently admitted probes can never exceed
    /// `half_open_max_requests`.
    ///
    /// The limit is floored at 1 (a breaker configured with
    /// `half_open_max_requests == 0` must still admit a single probe to be able
    /// to recover) and capped at the 30-bit count field.
    fn claim_half_open_slot(&self, monotonic_now_ms: u64) -> SlotClaim {
        let max = self.config.half_open_max_requests.clamp(1, COUNT_MASK);
        loop {
            let packed = self.packed.load(Ordering::Acquire);
            match packed_state(packed) {
                STATE_HALF_OPEN => {
                    let count = packed_count(packed);
                    if count >= max {
                        return SlotClaim::Exhausted;
                    }
                    // Arm the dwell off this admission BEFORE the CAS publishes
                    // it, so the admitted slot can never be observed with a
                    // stale tick. Losing the CAS only refreshes the tick, which
                    // delays a reclaim by at most one dwell.
                    self.half_open_admission_tick_ms
                        .store(monotonic_now_ms, Ordering::Relaxed);
                    // Preserve the generation (steady-state HALF_OPEN admission is
                    // the same open cycle); `packed` already carries it.
                    match self.packed.compare_exchange_weak(
                        packed,
                        pack_full(packed_generation(packed), STATE_HALF_OPEN, count + 1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return SlotClaim::Probe,
                        // State or count moved under us — re-evaluate against the
                        // fresh value (which may now be OPEN/CLOSED).
                        Err(_) => continue,
                    }
                }
                // Reopened after the caller observed HALF_OPEN — do not admit.
                STATE_OPEN => return SlotClaim::Rejected,
                // Recovered to closed — normal closed-state admission.
                STATE_CLOSED => return SlotClaim::Closed,
                _ => return SlotClaim::Closed,
            }
        }
    }

    /// Reclaim ONE probe slot that has been held past the dwell (issue #4980).
    ///
    /// Defence in depth behind `HalfOpenProbeGuard` (GHSA-4cq4-3f3f-mq76): every
    /// known dispatch path settles its slot structurally, but the state machine
    /// has no other timer out of HALF_OPEN, so a slot that some future path
    /// leaks would shed the backend with `503 circuit_breaker_open` for the rest
    /// of the process lifetime. With the dwell that outage degrades to a bounded
    /// delay, and `ferrum_circuit_breaker_probe_reclaimed_total` plus the warning
    /// below make the leak visible instead of silent.
    ///
    /// Health counters are deliberately untouched: a reclaim is not evidence
    /// about the backend, so it neither heals nor reopens the breaker — it only
    /// returns the slot so the next probe can be admitted.
    ///
    /// Returns whether a slot was actually reclaimed.
    fn reclaim_stalled_half_open_slot(&self, monotonic_now_ms: u64) -> bool {
        let stalled_since = self.half_open_admission_tick_ms.load(Ordering::Acquire);
        if monotonic_now_ms.saturating_sub(stalled_since) < self.half_open_probe_dwell_ms {
            return false;
        }
        // Claim the right to reclaim by advancing the tick: only one thread can
        // move it off `stalled_since`, so concurrent callers that all observe
        // the same stalled cycle reclaim ONE slot between them, and the next
        // reclaim is a full dwell away. A breaker whose every slot leaked is
        // therefore drained one slot per dwell, with one warning each.
        if self
            .half_open_admission_tick_ms
            .compare_exchange(
                stalled_since,
                monotonic_now_ms,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let reclaimed = self
            .packed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
                // A reopen/close since the stall check already zeroed the count
                // and forgot every slot; there is nothing to reclaim.
                if packed_state(packed) != STATE_HALF_OPEN {
                    return None;
                }
                let count = packed_count(packed);
                if count == 0 {
                    return None;
                }
                Some(pack_full(
                    packed_generation(packed),
                    STATE_HALF_OPEN,
                    count - 1,
                ))
            })
            .is_ok();
        if !reclaimed {
            return false;
        }
        // Record the debt the next release consumes, so the leaked probe
        // settling late cannot decrement a second time.
        let _ =
            self.half_open_reclaim_debt
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |debt| {
                    Some(debt.saturating_add(1))
                });
        self.probe_reclaimed.fetch_add(1, Ordering::Relaxed);
        warn!(
            "Circuit breaker reclaimed a half-open probe slot for {} after {}s without a settle: \
             the probe never released it. A fresh probe is admitted now; if this repeats, a \
             dispatch path is leaking probe slots (see \
             ferrum_circuit_breaker_probe_reclaimed_total).",
            self.log_identity(),
            self.half_open_probe_dwell_ms / 1000
        );
        true
    }

    /// Record a successful response, transitioning from half-open to closed
    /// after enough successes reach the configured threshold.
    ///
    /// `is_half_open_probe` must be `true` when this request was admitted as a
    /// half-open probe (i.e., `can_execute()` returned `Ok(true)`). Only probe
    /// requests decrement the `half_open_in_flight` counter. Requests admitted
    /// during CLOSED state that complete late (after a CLOSED->OPEN transition)
    /// must NOT decrement the counter since they never held a slot.
    #[allow(dead_code)] // Public API — called by retry/proxy logic when circuit is half-open
    pub fn record_success(&self, is_half_open_probe: bool) {
        match packed_state(self.packed.load(Ordering::Acquire)) {
            STATE_HALF_OPEN => {
                if is_half_open_probe {
                    // Decrement in-flight counter so new probe requests can be admitted
                    self.release_half_open_slot();
                }
                // Re-check state: another thread may have reopened the circuit
                // between our initial load and now.
                if packed_state(self.packed.load(Ordering::Acquire)) != STATE_HALF_OPEN {
                    return;
                }
                let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.config.success_threshold {
                    // HALF_OPEN → CLOSED, clearing the in-flight count in the
                    // SAME CAS. Loop so a concurrent admission (count change)
                    // does not abandon the close; bail if another thread already
                    // moved the breaker out of HALF_OPEN.
                    loop {
                        let p = self.packed.load(Ordering::Acquire);
                        if packed_state(p) != STATE_HALF_OPEN {
                            break;
                        }
                        // Closing preserves the generation (recovery is not a new
                        // open cycle — only opens advance it).
                        if self
                            .packed
                            .compare_exchange_weak(
                                p,
                                pack_full(packed_generation(p), STATE_CLOSED, 0),
                                Ordering::SeqCst,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            info!("Circuit breaker closing (recovered)");
                            self.failure_count.store(0, Ordering::Relaxed);
                            self.success_count.store(0, Ordering::Relaxed);
                            // The close zeroed the count and forgot every slot,
                            // so any outstanding reclaim debt is settled too.
                            self.half_open_reclaim_debt.store(0, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
            STATE_OPEN if is_half_open_probe => {
                // A concurrent record_failure already reopened the circuit between
                // our can_execute() and this record_success(). We still own a slot
                // from when the breaker was HALF_OPEN, so release it (a no-op if
                // the reopen already cleared the count).
                self.release_half_open_slot();
            }
            STATE_CLOSED => {
                // A different half-open probe can close the breaker before
                // this probe records success. The request still owns one
                // half-open slot from its can_execute() admission, so release
                // it even though the state is already CLOSED (a no-op if the
                // close already cleared the count).
                if is_half_open_probe {
                    self.release_half_open_slot();
                }
                // Reset failure count on success
                if self.failure_count.load(Ordering::Relaxed) > 0 {
                    self.failure_count.store(0, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }

    /// Record a neutral outcome that should not affect breaker health state.
    ///
    /// Used for client-caused aborts where no backend result exists, while
    /// still releasing any reserved half-open probe slot.
    pub fn record_neutral(&self, is_half_open_probe: bool) {
        if !is_half_open_probe {
            return;
        }
        self.release_half_open_slot();
    }

    /// Record a failed response.
    ///
    /// `connection_error` indicates whether this was a connection-level failure
    /// (TCP refused, DNS, TLS handshake, connect timeout) rather than an actual
    /// HTTP response from the backend. When `true`, the failure is controlled by
    /// `trip_on_connection_errors` independently of `failure_status_codes`.
    ///
    /// `is_half_open_probe` must be `true` when this request was admitted as a
    /// half-open probe (i.e., `can_execute()` returned `Ok(true)`). Only probe
    /// requests decrement the `half_open_in_flight` counter. Requests admitted
    /// during CLOSED state that complete after the breaker has transitioned to
    /// OPEN must NOT decrement the counter since they never held a slot.
    pub fn record_failure(
        &self,
        status_code: u16,
        connection_error: bool,
        is_half_open_probe: bool,
    ) {
        self.record_failure_inner(status_code, connection_error, is_half_open_probe, None);
    }

    /// Deterministic-clock variant used by external unit tests. Wall time is
    /// injected separately to prove it remains diagnostic-only.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn record_failure_at_for_test(
        &self,
        status_code: u16,
        connection_error: bool,
        is_half_open_probe: bool,
        monotonic_now_ms: u64,
        wall_epoch_ms: u64,
    ) {
        self.record_failure_inner(
            status_code,
            connection_error,
            is_half_open_probe,
            Some((monotonic_now_ms, wall_epoch_ms)),
        );
    }

    fn record_failure_inner(
        &self,
        status_code: u16,
        connection_error: bool,
        is_half_open_probe: bool,
        injected_time: Option<(u64, u64)>,
    ) {
        if connection_error {
            if !self.config.trip_on_connection_errors {
                // Filtered failure — release the probe slot without state transition
                if is_half_open_probe {
                    self.release_half_open_slot();
                }
                return;
            }
        } else if !self.config.failure_status_codes.contains(&status_code) {
            // Non-failure status codes are neutral — release probe slot without
            // state transition
            if is_half_open_probe {
                self.release_half_open_slot();
            }
            return;
        }

        let packed = self.packed.load(Ordering::Acquire);
        let (failure_tick_ms, failure_epoch_ms) = injected_time
            .unwrap_or_else(|| (crate::socket_opts::monotonic_now_ms(), wall_now_epoch_ms()));

        match packed_state(packed) {
            STATE_CLOSED => {
                self.last_failure_tick_ms
                    .store(failure_tick_ms, Ordering::Relaxed);
                self.last_failure_epoch_ms
                    .store(failure_epoch_ms, Ordering::Relaxed);
                // A half-open probe whose failure arrives only AFTER the breaker
                // has already left HALF_OPEN — a sibling reached the success
                // threshold and closed it, or this is a stale straggler from a
                // bygone half-open cycle that outlived a full reopen→close cycle —
                // is processed against the CURRENT closed state, matching standard
                // breaker semantics (e.g. sony/gobreaker): release the slot it
                // nominally still holds (a no-op once the close cleared the count)
                // and count the failure toward the closed-state failure_threshold.
                // It is deliberately NOT special-cased into a reopen: a probe that
                // observes CLOSED here cannot be distinguished from an
                // arbitrarily-stale straggler without per-probe generation
                // tracking, so reopening would let a long-hung straggler trip a
                // breaker that has since recovered. The "any probe failure reopens"
                // rule still holds while the breaker is HALF_OPEN (the arm below):
                // a failure that observes HALF_OPEN is current-cycle by
                // construction and reopens even if it then races a sibling close.
                if is_half_open_probe {
                    self.release_half_open_slot();
                }
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= self.config.failure_threshold {
                    // Re-read the counter before and after the transition attempt.
                    // A concurrent CLOSED-state success may reset failure_count
                    // after our fetch_add; opening on that stale `failures` value
                    // would turn a broken consecutive-failure streak into an OPEN
                    // circuit. CAS still ensures only one thread performs the
                    // CLOSED→OPEN transition, while the counter checks keep the
                    // transition tied to the current consecutive-failure count.
                    if self.failure_count.load(Ordering::Acquire) < self.config.failure_threshold {
                        return;
                    }
                    // CLOSED always carries count=0, so the expected/desired values
                    // both hold count=0; the transition flips state and advances the
                    // generation in the SAME CAS.
                    //
                    // Advancing the generation atomically with the OPEN transition is
                    // what makes the streaming-outcome accounting correct (#1649 R5
                    // finding 2 + R7): (1) only the CAS WINNER advances the
                    // generation — a concurrent failure that loses the CAS leaves it
                    // untouched, so it cannot stale a valid probe that already
                    // captured the winner's generation; and (2) the new generation is
                    // published WITH OPEN, so any observer that sees OPEN (and can
                    // immediately re-enter HALF_OPEN when `timeout_seconds == 0`)
                    // reads the new generation, never the pre-open value. The
                    // generation comes from a fresh load of the CLOSED state; if it
                    // changed under us the CAS simply fails (a sibling opened). On the
                    // rare rollback path below the generation stays advanced — the
                    // only effect is that a CLOSED-admitted (non-probe) deferred
                    // outcome captured just before this point is dropped instead of
                    // recorded, which is negligible and conservative.
                    let generation = packed_generation(self.packed.load(Ordering::Acquire));
                    if self
                        .packed
                        .compare_exchange(
                            pack_full(generation, STATE_CLOSED, 0),
                            pack_full(generation.wrapping_add(1), STATE_OPEN, 0),
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        let current_failures = self.failure_count.load(Ordering::Acquire);
                        if current_failures < self.config.failure_threshold {
                            // Roll back OPEN→CLOSED, keeping the advanced generation
                            // (see note above).
                            let _ = self.packed.compare_exchange(
                                pack_full(generation.wrapping_add(1), STATE_OPEN, 0),
                                pack_full(generation.wrapping_add(1), STATE_CLOSED, 0),
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            );
                            return;
                        }
                        warn!(
                            "Circuit breaker opening after {} failures",
                            current_failures
                        );
                    }
                }
            }
            STATE_HALF_OPEN => {
                self.last_failure_tick_ms
                    .store(failure_tick_ms, Ordering::Relaxed);
                self.last_failure_epoch_ms
                    .store(failure_epoch_ms, Ordering::Relaxed);
                self.reopen_after_probe_failure();
            }
            STATE_OPEN if is_half_open_probe => {
                // A concurrent record_failure already reopened the circuit between
                // our can_execute() (when it was HALF_OPEN) and now. Release our
                // slot (a no-op if the reopen already cleared the count). Do not
                // refresh either failure timestamp: the reopen that published OPEN
                // already started the recovery timeout.
                self.release_half_open_slot();
            }
            _ => {}
        }
    }

    /// Reopen the breaker after a failure that was observed WHILE the breaker is
    /// HALF_OPEN (the only caller — the top-level `STATE_HALF_OPEN` arm).
    /// Publishes OPEN and clears the in-flight count in ONE CAS — so HALF_OPEN
    /// admissions stop at the same instant the count is zeroed (no over-admission
    /// window during the reopen). The loop also reopens a breaker that a
    /// concurrent sibling success closed between this failure observing HALF_OPEN
    /// and the CAS (the sibling-close race): such a failure is current-cycle by
    /// construction, so reopening is correct. A failure that instead observes
    /// CLOSED at the top of `record_failure` is NOT routed here — it counts
    /// toward the closed-state threshold — because it cannot be distinguished
    /// from a stale straggler. Only an already-published OPEN is left alone. The
    /// failing probe's slot is subsumed by the count reset, and a straggler from
    /// this cycle releases as a no-op at 0.
    fn reopen_after_probe_failure(&self) {
        self.success_count.store(0, Ordering::Relaxed);
        loop {
            let p = self.packed.load(Ordering::Acquire);
            match packed_state(p) {
                // A sibling probe failure already reopened — done.
                STATE_OPEN => break,
                // HALF_OPEN or CLOSED → reopen, clearing the count AND advancing the
                // generation in the same CAS. Bundling the generation bump into the
                // CAS means only the reopen winner advances it (no loser bumps) and
                // the new generation is visible to any observer that sees OPEN —
                // exactly as on the CLOSED→OPEN path (#1649 R5 finding 2 + R7). If a
                // sibling already reopened, the `STATE_OPEN` arm above leaves it
                // alone; a stream from the superseded cycle is correctly stale.
                _ => {
                    if self
                        .packed
                        .compare_exchange_weak(
                            p,
                            pack_full(packed_generation(p).wrapping_add(1), STATE_OPEN, 0),
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        warn!("Circuit breaker reopening (probe failed)");
                        // The reopen zeroed the count and forgot every slot, so
                        // any outstanding reclaim debt is settled too.
                        self.half_open_reclaim_debt.store(0, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
    }

    /// Release one half-open probe slot, decrementing the in-flight count while
    /// preserving the state bits and never underflowing. A no-op once the count
    /// is already 0 — e.g. the slot was cleared en masse by a concurrent
    /// reopen/close — so a straggler from a previous half-open cycle can neither
    /// drive the counter below 0 nor perturb the packed state.
    fn release_half_open_slot(&self) {
        // A dwell reclaim already returned one slot on behalf of a probe that
        // had not settled. Slots are anonymous, so the FIRST release after a
        // reclaim is taken as the compensating one: consume the debt instead of
        // decrementing again. In aggregate a reclaim plus its late settle costs
        // exactly one slot, which is what keeps the in-flight count from
        // under-stating the probes actually running (and over-admitting).
        if self
            .half_open_reclaim_debt
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |debt| {
                debt.checked_sub(1)
            })
            .is_ok()
        {
            return;
        }
        let _ = self
            .packed
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
                let count = packed_count(packed);
                if count == 0 {
                    None
                } else {
                    // Preserve the generation and state; only the count changes.
                    Some(pack_full(
                        packed_generation(packed),
                        packed_state(packed),
                        count - 1,
                    ))
                }
            });
    }

    /// Get the config for this circuit breaker.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Current open generation. Captured at admission (`can_execute`) and
    /// re-checked when a deferred streaming outcome settles so a stream admitted
    /// under one generation cannot heal/reopen a later HALF_OPEN cycle (#1649).
    /// Advanced (in the same CAS) on every transition INTO `Open`; HALF_OPEN
    /// admission does not change it (same open cycle).
    pub fn open_epoch(&self) -> u64 {
        packed_generation(self.packed.load(Ordering::Acquire)) as u64
    }

    /// Current failure count (for metrics).
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }

    /// Current success count (for metrics).
    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::Relaxed)
    }

    /// Current half-open in-flight counter (for testing).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn half_open_in_flight(&self) -> u32 {
        packed_count(self.packed.load(Ordering::Acquire))
    }

    /// Probe slots this breaker has reclaimed after the HALF_OPEN dwell.
    ///
    /// Exported per proxy as `ferrum_circuit_breaker_probe_reclaimed_total`.
    /// Any non-zero value means a dispatch path leaked a probe slot and the
    /// dwell downgraded the resulting outage to a bounded delay (#4980).
    pub fn probe_reclaimed_total(&self) -> u64 {
        self.probe_reclaimed.load(Ordering::Relaxed)
    }

    /// Effective HALF_OPEN dwell in milliseconds, after the derivation and
    /// clamps in [`derive_half_open_probe_dwell_ms`].
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn half_open_probe_dwell_ms(&self) -> u64 {
        self.half_open_probe_dwell_ms
    }

    /// Name used for the probe-reclaim warning: the cache key when the breaker
    /// is cached, and an explicit placeholder for a transient (uncached) one.
    fn log_identity(&self) -> &str {
        if self.identity.is_empty() {
            "<uncached breaker>"
        } else {
            &self.identity
        }
    }

    /// Last failure timestamp in epoch milliseconds (for testing).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn last_failure_epoch_ms(&self) -> u64 {
        self.last_failure_epoch_ms.load(Ordering::Relaxed)
    }

    /// Last state-machine failure tick (for deterministic tests).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn last_failure_tick_ms_for_test(&self) -> u64 {
        self.last_failure_tick_ms.load(Ordering::Relaxed)
    }

    /// Current state name (for metrics/logging).
    pub fn state_name(&self) -> &'static str {
        match packed_state(self.packed.load(Ordering::Relaxed)) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

/// Build the cache key for a circuit breaker.
///
/// Keys are namespace-qualified (`namespace|proxy_id`) so the same proxy id in
/// two tenants cannot share or leak breaker state. When a concrete target is
/// provided, the breaker is scoped to that host:port
/// (`namespace|proxy_id::host:port`). HTTP dispatch always supplies a target,
/// including direct-backend proxies (`backend_host:backend_port`). UDP/DTLS
/// direct-backend sessions still omit the target, producing `namespace|proxy_id`.
fn circuit_breaker_key(namespace: &str, proxy_id: &str, target_key: Option<&str>) -> String {
    match target_key {
        Some(tk) => format!("{namespace}|{proxy_id}::{tk}"),
        None => crate::config::db_backend::namespaced_runtime_key(namespace, proxy_id),
    }
}

/// Build a target key string from host and port (e.g. `"10.0.0.1:8080"`).
pub fn target_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Cache key HTTP dispatch mints for a concrete `host:port` target.
///
/// Direct-backend proxies use `backend_host:backend_port`; upstream and
/// service-discovery targets use the selected target's host and port. The
/// result is `namespace|proxy_id::host:port`.
pub fn scoped_cache_key(namespace: &str, proxy_id: &str, host: &str, port: u16) -> String {
    circuit_breaker_key(namespace, proxy_id, Some(&target_key(host, port)))
}

/// Cache of circuit breakers, keyed per namespace-qualified proxy unless dispatch
/// supplies an effective target (`namespace|proxy_id::host:port`) for upstream
/// targets or direct backend overrides.
///
/// Admission uses an atomic entry counter coordinated with DashMap `entry`
/// semantics so concurrent same-key creation, changed-config replacement, and
/// distinct-key capacity checks stay correct without a process-wide lock.
/// Matching-config hits stay on the shard read path (`DashMap::get`).
pub struct CircuitBreakerCache {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    /// Exact resident-entry count coordinated with insert/remove. Capacity
    /// admission loads this atomic instead of `DashMap::len()`, which would
    /// take a read guard on every shard.
    entry_count: AtomicUsize,
    max_entries: usize,
    /// Monotonic count of admissions refused because the cache was at
    /// `max_entries`. Exported as
    /// `ferrum_circuit_breaker_cache_admission_refused_total` so ceiling
    /// pressure is observable before circuit breaking silently degrades to
    /// transient (stateless) breakers for every newly discovered target.
    admission_refused: AtomicU64,
}

impl Default for CircuitBreakerCache {
    fn default() -> Self {
        Self::with_max_entries(10_000)
    }
}

impl CircuitBreakerCache {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_max_entries(10_000)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self::with_max_entries_and_shard_amount(
            max_entries,
            crate::util::sharding::pool_shard_amount(0),
        )
    }

    pub fn with_max_entries_and_shard_amount(max_entries: usize, shard_amount: usize) -> Self {
        Self {
            breakers: DashMap::with_shard_amount(shard_amount),
            entry_count: AtomicUsize::new(0),
            max_entries,
            admission_refused: AtomicU64::new(0),
        }
    }

    /// Get or create a circuit breaker for a proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the request resolved to
    /// a concrete upstream target or direct backend override, and `None` when a
    /// direct backend proxy should use one breaker for the proxy.
    /// If the config has changed, replaces the breaker with a fresh one.
    ///
    /// Concurrent callers for the same key/config generation receive the same
    /// `Arc`. New distinct keys are admitted only while under `max_entries`;
    /// when the cache is genuinely full, a **transient** (uncached) breaker is
    /// returned so the request can still proceed without retaining split or
    /// unbounded state. Existing keys remain replaceable at capacity (config
    /// change).
    pub fn get_or_create(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        use dashmap::mapref::entry::Entry;

        let key = circuit_breaker_key(namespace, proxy_id, target_key);
        // Hot path: matching-config hits use a shard read lock only.
        if let Some(existing) = self.breakers.get(&key)
            && existing.config() == config
        {
            return existing.clone();
        }

        // Miss or config change: per-key entry API holds the shard write lock
        // for create/replace so concurrent same-key callers share one Arc, and
        // vacant keys reserve capacity before publishing.
        match self.breakers.entry(key) {
            Entry::Occupied(mut occupied) => {
                if occupied.get().config() == config {
                    return occupied.get().clone();
                }
                let identity = occupied.key().clone();
                let cb = Arc::new(CircuitBreaker::with_identity(identity, config.clone()));
                occupied.insert(cb.clone());
                cb
            }
            Entry::Vacant(vacant) => {
                if !self.try_reserve_entry_slot() {
                    self.admission_refused.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Circuit breaker cache at capacity ({}), skipping new entry for {}",
                        self.max_entries,
                        vacant.key()
                    );
                    // Transient breaker: not cached, so overflow traffic does
                    // not retain state across requests and cannot grow the map.
                    return Arc::new(CircuitBreaker::with_identity(
                        vacant.key().clone(),
                        config.clone(),
                    ));
                }
                let identity = vacant.key().clone();
                let cb = Arc::new(CircuitBreaker::with_identity(identity, config.clone()));
                vacant.insert(cb.clone());
                cb
            }
        }
    }

    fn try_reserve_entry_slot(&self) -> bool {
        self.entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    fn release_entry_slot(&self) {
        let _ = self
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            });
    }

    /// Read-only lookup of the breaker currently cached for a proxy (+target),
    /// WITHOUT creating or replacing one.
    ///
    /// Unlike [`get_or_create`](Self::get_or_create), this never writes to the
    /// cache, so a long-lived deferred streaming completion that outlives a config
    /// reload cannot resurrect a request-scoped (old-config) breaker into the live
    /// cache (#1649 R8). Returns `None` when no breaker is cached for the key (it
    /// was evicted or replaced by a reload), which the deferred stale check treats
    /// as "the admitted cycle is gone → stale".
    pub fn peek(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
    ) -> Option<Arc<CircuitBreaker>> {
        let key = circuit_breaker_key(namespace, proxy_id, target_key);
        self.breakers.get(&key).map(|entry| entry.value().clone())
    }

    /// Check if a request can proceed for a given proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the proxy uses an upstream,
    /// or `None` for direct backend proxies.
    ///
    /// Returns `Ok((cb, is_half_open_probe))`. The caller MUST thread
    /// `is_half_open_probe` into every subsequent `record_success` /
    /// `record_failure` call on this breaker so that the half-open in-flight
    /// counter is decremented only for requests that actually hold a probe slot.
    pub fn can_execute(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Result<(Arc<CircuitBreaker>, bool), CircuitOpenError> {
        let cb = self.get_or_create(namespace, proxy_id, target_key, config);
        let is_half_open_probe = cb.can_execute()?;
        Ok((cb, is_half_open_probe))
    }

    /// Like [`can_execute`](Self::can_execute), but also returns the breaker's open
    /// generation captured BEFORE the admission decision.
    ///
    /// Because the snapshot is taken before `can_execute`, the returned epoch is
    /// always `<=` the generation the request is actually admitted under: a
    /// concurrent open racing this admission can only make a later deferred
    /// streaming outcome look *stale* (neutralized — recovered by the next probe),
    /// never *too new* (which would let a request heal/reopen a HALF_OPEN cycle it
    /// never probed). Combined with the bump-before-publish ordering in
    /// `record_failure`/`reopen_after_probe_failure`, a probe admitted into the
    /// current OPEN cycle still captures that cycle's generation in the common
    /// (non-racy) case. Used by the #1649 streaming-deferral admission sites — the
    /// initial admission and every retry-target rotation — where the backend-health
    /// outcome is recorded at response-body completion. (#1649 R6 finding 3)
    pub fn can_execute_with_admission_epoch(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Result<(Arc<CircuitBreaker>, bool, u64), CircuitOpenError> {
        let cb = self.get_or_create(namespace, proxy_id, target_key, config);
        let admission_open_epoch = cb.open_epoch();
        let is_half_open_probe = cb.can_execute()?;
        Ok((cb, is_half_open_probe, admission_open_epoch))
    }

    /// Snapshot of all circuit breaker states for metrics.
    pub fn snapshot(&self) -> Vec<(String, &'static str, u32, u32)> {
        self.breakers
            .iter()
            .map(|entry| {
                let cb = entry.value();
                (
                    entry.key().clone(),
                    cb.state_name(),
                    cb.failure_count(),
                    cb.success_count(),
                )
            })
            .collect()
    }

    /// Per-breaker count of HALF_OPEN probe slots reclaimed after the dwell.
    ///
    /// Keys are the same runtime keys [`Self::snapshot`] returns, so the metric
    /// renderer aggregates them per proxy without ever exposing the `host:port`
    /// suffix as a label.
    pub fn probe_reclaimed_snapshot(&self) -> Vec<(String, u64)> {
        self.breakers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().probe_reclaimed_total()))
            .collect()
    }

    /// Remove circuit breakers for proxies that no longer exist in config.
    /// Removes both direct-backend keys (`namespace|proxy_id`) and per-target
    /// keys (`namespace|proxy_id::host:port`) for each removed proxy identity.
    pub fn prune(&self, removed_proxies: &[crate::config::db_backend::NamespacedResourceId]) {
        self.breakers.retain(|key, _| {
            let keep = !removed_proxies.iter().any(|resource| {
                crate::config::db_backend::runtime_key_matches_resource(
                    key,
                    &resource.namespace,
                    &resource.id,
                )
            });
            if !keep {
                self.release_entry_slot();
            }
            keep
        });
    }

    /// Remove circuit breakers for targets that are no longer live.
    ///
    /// `active_target_keys` must be the keys dispatch currently mints:
    /// per-proxy `namespace|id::host:port` for every live upstream or
    /// service-discovery target and every direct-backend
    /// `backend_host:backend_port`. Keys without `::` are the proxy-scoped
    /// form used by UDP/DTLS direct backends and are reclaimed by
    /// [`Self::prune`] when the proxy itself is removed.
    pub fn prune_stale_targets(&self, active_target_keys: &std::collections::HashSet<String>) {
        self.breakers.retain(|key, _| {
            // Proxy-scoped keys (no "::") are managed by prune() via proxy removal.
            if !key.contains("::") {
                return true;
            }
            let keep = active_target_keys.contains(key);
            if !keep {
                self.release_entry_slot();
            }
            keep
        });
    }

    /// Remove circuit breakers for one proxy's targets that are no longer live.
    ///
    /// Scoped counterpart to [`Self::prune_stale_targets`], called from the
    /// service-discovery publish path (`install_merged_targets`) so retired
    /// pod/endpoint churn reclaims breaker entries without waiting for a
    /// `GatewayConfig` delta. Without it, every retired target permanently
    /// holds one admission slot until the cache reaches `max_entries`, after
    /// which `get_or_create` returns uncached transient breakers and circuit
    /// breaking stops working for every newly discovered target (issue #4516).
    ///
    /// A key is removed only when ALL of the following hold:
    /// - it is a per-target key (contains `::`),
    /// - it is inside exactly this proxy's `namespace|proxy_id::` scope, and
    /// - its `host:port` suffix is absent from `live_targets`.
    ///
    /// Every key outside this proxy's scope is left untouched. That scoping is
    /// what makes this safe where recomputing a global active-key set from a
    /// single upstream's publication would not be (the #4159 over-prune).
    /// Resource ids cannot contain `:` (`validate_resource_id`), so the scope
    /// prefix cannot straddle a neighbouring proxy's key.
    ///
    /// The scope prefix is built from the same key helper `scoped_cache_key`
    /// uses, so the minting and reclaiming forms cannot drift.
    pub fn prune_stale_targets_for_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
        live_targets: &[crate::config::types::UpstreamTarget],
    ) {
        let scope_prefix = format!(
            "{}::",
            crate::config::db_backend::namespaced_runtime_key(namespace, proxy_id)
        );
        let live: std::collections::HashSet<String> = live_targets
            .iter()
            .map(|target| target_key(&target.host, target.port))
            .collect();
        self.breakers.retain(|key, _| {
            // Not this proxy's per-target scope: another proxy's keys and the
            // proxy-scoped UDP/DTLS form (no "::") are never touched here.
            let Some(host_port) = key.strip_prefix(&scope_prefix) else {
                return true;
            };
            let keep = live.contains(host_port);
            if !keep {
                self.release_entry_slot();
            }
            keep
        });
    }

    /// Configured admission ceiling for distinct breaker keys.
    ///
    /// Exported as `ferrum_circuit_breaker_cache_max_entries` so operators can
    /// alert on the cache approaching the ceiling at which new proxy/target
    /// breakers stop being admitted.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Admissions refused so far because the cache was at `max_entries`.
    ///
    /// Every refusal is one request that received a transient, uncached
    /// breaker: its failures never accumulate, so the breaker for that target
    /// can never open. A non-zero and rising value means circuit breaking is
    /// silently degraded for newly seen proxy/target keys.
    pub fn admission_refused_total(&self) -> u64 {
        self.admission_refused.load(Ordering::Relaxed)
    }

    /// Current number of entries in the cache.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    /// Whether the cache is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Wall-clock diagnostic only; breaker transitions never read this value.
fn wall_now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

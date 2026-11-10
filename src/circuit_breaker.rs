//! Circuit breaker for preventing cascading failures.
//!
//! Implements a three-state circuit breaker pattern:
//! - **Closed**: Normal operation, requests pass through.
//! - **Open**: After repeated failures, requests are rejected with 503.
//! - **Half-Open**: After a timeout, a limited number of probe requests are allowed.

use crate::config::types::CircuitBreakerConfig;
use crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
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

/// Whether open generation `generation` is strictly older than `than`.
///
/// Generations wrap, so "older" is the wrapping distance read as signed: a
/// generation up to 2^31 opens behind `than` is older, one up to 2^31 opens
/// ahead is newer. Two generations a single in-flight settlement can observe
/// are never that far apart.
#[inline]
const fn generation_precedes(generation: u32, than: u32) -> bool {
    (than.wrapping_sub(generation) as i32) > 0
}

/// A breaker counter (`success_count` / `failure_count`) tagged with the open
/// generation of the cycle it counts, in ONE `AtomicU64`: the high 32 bits are
/// the generation, the low 32 bits the count.
///
/// Every increment is a compare-exchange that names the generation its caller
/// checked the breaker in, so the check and the increment are one atomic step
/// on this word (#7030). An increment for an OLDER cycle than the tag is
/// refused: a settlement that checked cycle `g`, then lost the race to a
/// sibling that reopened the breaker and started cycle `g + 1`, can no longer
/// add one count to the new cycle. An increment for a NEWER cycle than the tag
/// starts the new cycle at one, so a cycle never inherits a count it did not
/// earn even before anything re-tags the counter. Lock-free and allocation-free.
struct CycleCounter(AtomicU64);

#[inline]
const fn pack_counter(generation: u32, count: u32) -> u64 {
    ((generation as u64) << 32) | (count as u64)
}

#[inline]
const fn counter_generation(word: u64) -> u32 {
    (word >> 32) as u32
}

#[inline]
const fn counter_value(word: u64) -> u32 {
    word as u32
}

impl CycleCounter {
    const fn new() -> Self {
        Self(AtomicU64::new(pack_counter(0, 0)))
    }

    /// The count, whatever cycle it is tagged with (metrics and tests).
    #[inline]
    fn count(&self) -> u32 {
        counter_value(self.0.load(Ordering::Acquire))
    }

    /// The count of cycle `generation`: zero when the counter is tagged with
    /// any other cycle.
    #[inline]
    fn count_in_cycle(&self, generation: u32) -> u32 {
        let word = self.0.load(Ordering::Acquire);
        if counter_generation(word) == generation {
            counter_value(word)
        } else {
            0
        }
    }

    /// Count one event of open cycle `generation`. Returns the cycle's new
    /// count, or `None` when the counter already belongs to a newer cycle and
    /// the event is stale.
    #[inline]
    fn increment(&self, generation: u32) -> Option<u32> {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            let tag = counter_generation(current);
            let next = if tag == generation {
                pack_counter(generation, counter_value(current).saturating_add(1))
            } else if generation_precedes(tag, generation) {
                pack_counter(generation, 1)
            } else {
                return None;
            };
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(counter_value(next)),
                Err(actual) => current = actual,
            }
        }
    }

    /// Tag the counter with a cycle that is just starting, at zero, unless it
    /// already counts that cycle (a sibling of the new cycle may already have
    /// counted into it) or a newer one.
    #[inline]
    fn start_cycle(&self, generation: u32) {
        let _ = self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                generation_precedes(counter_generation(word), generation)
                    .then_some(pack_counter(generation, 0))
            });
    }

    /// Zero the count for cycle `generation`, unless the counter already
    /// belongs to a newer cycle. Writes nothing when it is already zero for
    /// that cycle, so the CLOSED success path stays one load.
    #[inline]
    fn clear(&self, generation: u32) {
        let _ = self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                let target = pack_counter(generation, 0);
                (word != target && !generation_precedes(generation, counter_generation(word)))
                    .then_some(target)
            });
    }
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
    /// CLOSED-state consecutive failures, tagged with the CLOSED cycle's open
    /// generation (see `CycleCounter`).
    failure_count: CycleCounter,
    /// HALF_OPEN successes, tagged with the HALF_OPEN cycle's open generation.
    success_count: CycleCounter,
    /// Process-relative monotonic tick of the failure that opened/reopened the
    /// breaker. This is the only timestamp consulted for state transitions.
    last_failure_tick_ms: AtomicU64,
    /// Unix epoch milliseconds for diagnostics only. Never consulted for a
    /// breaker state transition, so wall-clock jumps cannot change recovery.
    last_failure_epoch_ms: AtomicU64,
    config: CircuitBreakerConfig,
}

/// Error returned when the circuit is open.
#[derive(Debug)]
pub struct CircuitOpenError;

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit breaker is open")
    }
}

/// What one admission ([`CircuitBreaker::admit`]) handed its caller: either no
/// HALF_OPEN probe slot, or exactly one slot of exactly one open cycle (CB-1).
///
/// The slot and the generation it was claimed in are one value, so no caller
/// can settle a probe without also naming its cycle. Every settlement goes
/// through [`CircuitBreaker::settle`], which compares the generation inside the
/// CAS that releases the slot or moves health: a probe that outlives a reopen
/// can neither free a LATER cycle's slot (over-admitting past
/// `half_open_max_requests`) nor close or reopen a cycle it never probed.
///
/// In HALF_OPEN only the cycle's own probes decide (#7030): a
/// [`Self::NonProbe`] outcome reaching a HALF_OPEN breaker came from a request
/// admitted in an earlier CLOSED cycle and is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeTicket {
    /// Admitted while CLOSED (or after a concurrent recovery): holds no slot.
    NonProbe,
    /// Holds one HALF_OPEN probe slot of open generation `generation`, as
    /// published by the admitting CAS itself.
    Probe { generation: u32 },
    /// The OUTCOME of a HALF_OPEN probe of open generation `generation` whose
    /// slot is returned separately: a deferred streaming record whose slot was
    /// released at response-header time, or a record made while the request's
    /// guard still owns the slot it will release itself. It decides its own
    /// cycle exactly like [`Self::Probe`] but never returns a slot. Built with
    /// [`Self::without_slot`].
    SlotlessProbe { generation: u32 },
}

impl ProbeTicket {
    /// Whether this admission holds a HALF_OPEN probe slot.
    #[inline]
    pub const fn is_probe(self) -> bool {
        matches!(self, Self::Probe { .. })
    }

    /// Whether this ticket speaks for a HALF_OPEN probe of some cycle, with or
    /// without its slot.
    #[inline]
    pub const fn is_cycle_probe(self) -> bool {
        matches!(self, Self::Probe { .. } | Self::SlotlessProbe { .. })
    }

    /// The same admission's outcome without its slot: a probe becomes a
    /// [`Self::SlotlessProbe`] of the same cycle, every other ticket is
    /// returned unchanged.
    #[inline]
    pub const fn without_slot(self) -> Self {
        match self {
            Self::Probe { generation } | Self::SlotlessProbe { generation } => {
                Self::SlotlessProbe { generation }
            }
            Self::NonProbe => Self::NonProbe,
        }
    }

    /// Whether this ticket's outcome still belongs to the open cycle `packed`
    /// is in. A non-probe carries no cycle; [`CircuitBreaker::settle`] applies
    /// it to a CLOSED breaker and drops it in HALF_OPEN.
    #[inline]
    const fn in_cycle_of(self, packed: u64) -> bool {
        match self {
            Self::NonProbe => true,
            Self::Probe { generation } | Self::SlotlessProbe { generation } => {
                packed_generation(packed) == generation
            }
        }
    }
}

/// The outcome a request settles its [`ProbeTicket`] with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerOutcome {
    /// The backend answered healthily.
    Success,
    /// The backend failed. `connection_error` marks a connection-level failure
    /// (TCP refused, DNS, TLS handshake, connect timeout), gated by
    /// `trip_on_connection_errors`; otherwise `status_code` is checked against
    /// `failure_status_codes`. A failure the config does not count only returns
    /// the slot.
    Failure {
        status_code: u16,
        connection_error: bool,
    },
    /// No backend result exists (client abort, gateway-side refusal): return
    /// the slot without moving health.
    Neutral,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            packed: AtomicU64::new(pack_full(0, STATE_CLOSED, 0)),
            failure_count: CycleCounter::new(),
            success_count: CycleCounter::new(),
            last_failure_tick_ms: AtomicU64::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            config,
        }
    }

    /// Check if a request can proceed.
    ///
    /// Returns `Ok(true)` if the request was admitted as a half-open probe and
    /// `Ok(false)` for a normal closed-state admission. Returns `Err` if the
    /// circuit is open and the request must be rejected.
    ///
    /// The `bool` drops the probe's open generation, so production admission
    /// uses [`admit`](Self::admit), whose [`ProbeTicket`] carries it into
    /// [`settle`](Self::settle).
    #[inline]
    pub fn can_execute(&self) -> Result<bool, CircuitOpenError> {
        self.can_execute_inner(None)
            .map(|(ticket, _)| ticket.is_probe())
    }

    /// Admit a request, returning its [`ProbeTicket`] and the open generation
    /// the admission was decided in.
    ///
    /// For a HALF_OPEN probe the ticket's generation is the one carried by the
    /// SAME CAS that claimed the slot, so it is exact — never a pre- or
    /// post-admission snapshot (#6177). The returned `u64` is that same
    /// generation for a probe and, for a CLOSED admission, the generation the
    /// admitting load observed; deferred streaming outcomes stale-check against
    /// it (#1649).
    #[inline]
    pub fn admit(&self) -> Result<(ProbeTicket, u64), CircuitOpenError> {
        self.can_execute_inner(None)
            .map(|(ticket, generation)| (ticket, generation as u64))
    }

    /// Deterministic-clock variant used by external unit tests.
    #[doc(hidden)]
    pub fn can_execute_at_for_test(&self, monotonic_now_ms: u64) -> Result<bool, CircuitOpenError> {
        self.can_execute_inner(Some(monotonic_now_ms))
            .map(|(ticket, _)| ticket.is_probe())
    }

    /// Admission decision plus the open generation it was decided in. The
    /// generation of a probe admission is the one published by the admitting
    /// CAS; for a CLOSED admission it is informational only.
    #[inline]
    fn can_execute_inner(
        &self,
        monotonic_now_ms: Option<u64>,
    ) -> Result<(ProbeTicket, u32), CircuitOpenError> {
        // Acquire pairs with the release half of the AcqRel CAS that
        // transitions CLOSED → OPEN (`trip_after_closed_failure`), ensuring visibility of last_failure_tick_ms and
        // failure_count. Using Relaxed here would risk stale reads on ARM/weak-
        // memory architectures, allowing requests to leak through after the
        // circuit opens. The ~5-15ns cost of Acquire is acceptable given that
        // circuit breaker checks are not the bottleneck at scale.
        let packed = self.packed.load(Ordering::Acquire);
        match packed_state(packed) {
            STATE_CLOSED => Ok((ProbeTicket::NonProbe, packed_generation(packed))),
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
                    match self.packed.compare_exchange(
                        pack_full(generation, STATE_OPEN, 0),
                        pack_full(generation, STATE_HALF_OPEN, 1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // Tag the success counter with this cycle. A probe
                            // admitted right after the CAS may already have
                            // counted into it; `start_cycle` keeps that credit.
                            self.success_count.start_cycle(generation);
                            info!("Circuit breaker transitioning from Open to Half-Open");
                            Ok((ProbeTicket::Probe { generation }, generation))
                        }
                        Err(actual) => match packed_state(actual) {
                            // Another thread already opened the half-open cycle;
                            // claim a slot through the same bounded CAS.
                            STATE_HALF_OPEN => self.try_acquire_half_open_slot(),
                            // Recovered to closed in the meantime.
                            STATE_CLOSED => Ok((ProbeTicket::NonProbe, packed_generation(actual))),
                            // Still open (lost the race to a concurrent reopen) —
                            // reject.
                            _ => Err(CircuitOpenError),
                        },
                    }
                } else {
                    Err(CircuitOpenError)
                }
            }
            STATE_HALF_OPEN => self.try_acquire_half_open_slot(),
            _ => Ok((ProbeTicket::NonProbe, packed_generation(packed))),
        }
    }

    /// Claim one half-open probe slot without exceeding the limit, checking the
    /// state and the count together in a single CAS.
    ///
    /// The OPEN→HALF_OPEN transition winner claims its first slot directly in
    /// `can_execute()` (count=1 is published atomically with HALF_OPEN). The
    /// remaining admission paths — a transition CAS-loser that finds the state
    /// already HALF_OPEN, and a steady-state HALF_OPEN request — funnel through
    /// this bounded CAS, so the number of concurrently admitted probes can never
    /// exceed `half_open_max_requests`. Because the expected value carries BOTH
    /// the state and the count, an admission cannot succeed once the breaker has
    /// left HALF_OPEN (a concurrent reopen or close), which closes the
    /// admit-after-reopen race.
    ///
    /// The limit is floored at 1 (a breaker configured with
    /// `half_open_max_requests == 0` must still admit a single probe to be able
    /// to recover) and capped at the 30-bit count field.
    ///
    /// Returns the generation of the state the CAS succeeded against, which is
    /// the exact open cycle the slot belongs to.
    fn try_acquire_half_open_slot(&self) -> Result<(ProbeTicket, u32), CircuitOpenError> {
        let max = self.config.half_open_max_requests.clamp(1, COUNT_MASK);
        loop {
            let packed = self.packed.load(Ordering::Acquire);
            match packed_state(packed) {
                STATE_HALF_OPEN => {
                    let count = packed_count(packed);
                    if count >= max {
                        return Err(CircuitOpenError);
                    }
                    // Preserve the generation (steady-state HALF_OPEN admission is
                    // the same open cycle); `packed` already carries it.
                    let generation = packed_generation(packed);
                    match self.packed.compare_exchange_weak(
                        packed,
                        pack_full(generation, STATE_HALF_OPEN, count + 1),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Ok((ProbeTicket::Probe { generation }, generation)),
                        // State or count moved under us — re-evaluate against the
                        // fresh value (which may now be OPEN/CLOSED).
                        Err(_) => continue,
                    }
                }
                // Reopened after the caller observed HALF_OPEN — do not admit.
                STATE_OPEN => return Err(CircuitOpenError),
                // Recovered to closed — normal closed-state admission.
                STATE_CLOSED => return Ok((ProbeTicket::NonProbe, packed_generation(packed))),
                _ => return Ok((ProbeTicket::NonProbe, packed_generation(packed))),
            }
        }
    }

    /// Settle one admission: the SINGLE transition entry point for every
    /// request outcome (CB-1).
    ///
    /// `ticket` is the value [`admit`](Self::admit) returned for this request.
    /// A [`ProbeTicket::Probe`] belongs to exactly one open cycle, and every
    /// effect it has is checked against that cycle inside the CAS that applies
    /// it:
    ///
    /// * its slot release is a no-op once the breaker has left the ticket's
    ///   generation — the reopen that advanced it already zeroed the slot with
    ///   its cycle, so a stale release cannot free a LATER cycle's slot and
    ///   over-admit past `half_open_max_requests`;
    /// * a stale probe's success or failure is dropped: it cannot close, reopen,
    ///   or count toward a cycle it never probed.
    ///
    /// A [`ProbeTicket::SlotlessProbe`] is the same cycle-bound outcome without
    /// a slot to return.
    ///
    /// A [`ProbeTicket::NonProbe`] holds no slot and was admitted while the
    /// breaker was CLOSED. It is applied to a CLOSED breaker (a success resets
    /// the failure streak, a counted failure extends it) and dropped everywhere
    /// else (#7030): in HALF_OPEN only the cycle's own probes decide, so a
    /// straggler from an earlier CLOSED cycle can neither reopen the cycle nor
    /// count toward closing it.
    ///
    /// Counters (#7030): `success_count` and `failure_count` are each tagged
    /// with the open generation of the cycle they count (`CycleCounter`). Each
    /// increment is a compare-exchange carrying the generation this
    /// settlement checked the breaker in, so the check and the increment are
    /// one atomic step on the counter word: if a sibling reopens the breaker and
    /// a new cycle re-tags the counter between this settlement's check and its
    /// increment, the increment is refused instead of landing in the new cycle.
    /// The ticket's own transition CASes (slot release, close, reopen,
    /// CLOSED→OPEN) still re-check its cycle on the packed state word.
    ///
    /// Settlement is one Acquire load plus at most a few CASes on the packed
    /// state word and the counter word — no locks, no allocation.
    pub fn settle(&self, ticket: ProbeTicket, outcome: BreakerOutcome) {
        self.settle_inner(ticket, outcome, None);
    }

    fn settle_inner(
        &self,
        ticket: ProbeTicket,
        outcome: BreakerOutcome,
        injected_time: Option<(u64, u64)>,
    ) {
        match outcome {
            // Client-caused aborts and gateway-side refusals: no backend result
            // exists, so only the slot (if any) is returned.
            BreakerOutcome::Neutral => self.release_slot(ticket),
            BreakerOutcome::Success => self.settle_success(ticket),
            BreakerOutcome::Failure {
                status_code,
                connection_error,
            } => {
                if self.failure_trips(status_code, connection_error) {
                    self.settle_tripping_failure(ticket, injected_time);
                } else {
                    // Filtered failure (non-failure status, or a connection
                    // error with `trip_on_connection_errors` off): release the
                    // probe slot without a state transition.
                    self.release_slot(ticket);
                }
            }
        }
    }

    /// Whether a failure is counted by this breaker's config. `connection_error`
    /// indicates a connection-level failure (TCP refused, DNS, TLS handshake,
    /// connect timeout) rather than an HTTP response from the backend; it is
    /// gated by `trip_on_connection_errors` independently of
    /// `failure_status_codes`.
    #[inline]
    fn failure_trips(&self, status_code: u16, connection_error: bool) -> bool {
        if connection_error {
            self.config.trip_on_connection_errors
        } else {
            self.config.failure_status_codes.contains(&status_code)
        }
    }

    /// Success arm of [`settle`](Self::settle): HALF_OPEN → CLOSED after enough
    /// successes of the ticket's own cycle reach `success_threshold`.
    fn settle_success(&self, ticket: ProbeTicket) {
        let packed = self.packed.load(Ordering::Acquire);
        if !ticket.in_cycle_of(packed) {
            // Stale probe (CB-1): its cycle ended in a reopen that already
            // zeroed its slot. Crediting the success would let it release one of
            // the CURRENT cycle's slots and close a cycle it never probed.
            return;
        }
        match packed_state(packed) {
            STATE_HALF_OPEN => {
                if !ticket.is_cycle_probe() {
                    // A CLOSED-cycle straggler (#7030): only this cycle's own
                    // probes decide it, and a non-probe holds no slot.
                    return;
                }
                // Decrement in-flight counter so new probe requests can be
                // admitted (generation-checked in the same CAS).
                self.release_slot(ticket);
                // Re-check state AND cycle: another thread may have reopened the
                // circuit between our initial load and now.
                let current = self.packed.load(Ordering::Acquire);
                if packed_state(current) != STATE_HALF_OPEN || !ticket.in_cycle_of(current) {
                    return;
                }
                // Count the success for the cycle just checked. The counter
                // refuses it if a sibling has re-tagged the counter for a newer
                // cycle since that check (#7030). The close CAS below
                // re-checks the cycle on the state word.
                let Some(successes) = self.success_count.increment(packed_generation(current))
                else {
                    return;
                };
                if successes >= self.config.success_threshold {
                    // HALF_OPEN → CLOSED, clearing the in-flight count in the
                    // SAME CAS. Loop so a concurrent admission (count change)
                    // does not abandon the close; bail if another thread already
                    // moved the breaker out of HALF_OPEN or out of this probe's
                    // cycle.
                    loop {
                        let p = self.packed.load(Ordering::Acquire);
                        if packed_state(p) != STATE_HALF_OPEN || !ticket.in_cycle_of(p) {
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
                            // The CLOSED cycle that starts here keeps this
                            // generation: zero both counters for it.
                            let generation = packed_generation(p);
                            self.failure_count.clear(generation);
                            self.success_count.clear(generation);
                            break;
                        }
                    }
                }
            }
            // Same-cycle OPEN cannot follow a probe admission (every transition
            // into OPEN advances the generation); a non-probe holds no slot. The
            // release is a count-0 no-op kept for symmetry.
            STATE_OPEN => self.release_slot(ticket),
            STATE_CLOSED => {
                // A sibling probe of the same cycle closed the breaker before
                // this probe settled. Release the slot it nominally holds (a
                // no-op once the close cleared the count).
                self.release_slot(ticket);
                // Reset the failure streak of the CLOSED cycle this success was
                // checked in (a no-op write-free load when it is already zero,
                // and refused if a newer cycle has re-tagged the counter).
                self.failure_count.clear(packed_generation(packed));
            }
            _ => {}
        }
    }

    /// Failure arm of [`settle`](Self::settle) for a failure the config counts.
    fn settle_tripping_failure(&self, ticket: ProbeTicket, injected_time: Option<(u64, u64)>) {
        let packed = self.packed.load(Ordering::Acquire);
        if !ticket.in_cycle_of(packed) {
            // Stale probe (CB-1): the reopen that advanced the generation
            // already zeroed its slot and restarted the recovery timeout. It
            // must neither reopen a later HALF_OPEN cycle nor count toward a
            // later CLOSED cycle's failure streak.
            return;
        }
        let (failure_tick_ms, failure_epoch_ms) = injected_time
            .unwrap_or_else(|| (crate::socket_opts::monotonic_now_ms(), wall_now_epoch_ms()));

        match packed_state(packed) {
            STATE_CLOSED => {
                self.last_failure_tick_ms
                    .store(failure_tick_ms, Ordering::Relaxed);
                self.last_failure_epoch_ms
                    .store(failure_epoch_ms, Ordering::Relaxed);
                // A same-cycle half-open probe whose failure arrives only AFTER
                // a sibling reached the success threshold and closed the breaker
                // is processed against the CURRENT closed state, matching
                // standard breaker semantics (e.g. sony/gobreaker): release the
                // slot it nominally still holds (a no-op once the close cleared
                // the count) and count the failure toward the closed-state
                // failure_threshold. A probe from an EARLIER cycle never gets
                // here — it was dropped as stale above. The "any probe failure
                // reopens" rule still holds while the breaker is HALF_OPEN (the
                // arm below): a failure that observes HALF_OPEN is current-cycle
                // by construction and reopens even if it then races a sibling
                // close.
                self.release_slot(ticket);
                // Count the failure for the CLOSED cycle checked above. The
                // counter refuses it if a sibling has since moved the breaker
                // through a newer cycle that re-tagged the counter (#7030). The
                // CLOSED→OPEN transition is bound to the same cycle.
                let Some(failures) = self.failure_count.increment(packed_generation(packed)) else {
                    return;
                };
                if failures >= self.config.failure_threshold {
                    self.trip_after_closed_failure(packed_generation(packed));
                }
            }
            // A CLOSED-cycle straggler (#7030): only this cycle's own probes
            // decide it, so the failure neither reopens nor restarts recovery.
            STATE_HALF_OPEN if !ticket.is_cycle_probe() => {}
            STATE_HALF_OPEN => {
                self.last_failure_tick_ms
                    .store(failure_tick_ms, Ordering::Relaxed);
                self.last_failure_epoch_ms
                    .store(failure_epoch_ms, Ordering::Relaxed);
                self.reopen_after_probe_failure(ticket);
            }
            // Same-cycle OPEN cannot follow a probe admission; a non-probe holds
            // no slot. Do not refresh either failure timestamp: the reopen that
            // published OPEN already started the recovery timeout.
            STATE_OPEN => self.release_slot(ticket),
            _ => {}
        }
    }

    /// CLOSED→OPEN after a counted failure brought CLOSED cycle
    /// `entry_generation` to `failure_threshold`. Returns whether this call
    /// opened the breaker.
    ///
    /// The transition is bound to the cycle the failure was checked and
    /// counted in (#7030). Both counter rechecks read the count of THAT cycle
    /// (`CycleCounter::count_in_cycle`), and the CAS expects
    /// `CLOSED(entry_generation)`, so a failure that stalled while a sibling
    /// opened the breaker and a probe recovered it into a newer CLOSED cycle
    /// can never open the recovered cycle, whatever the counter holds at that
    /// instant (for example between the recovery CAS and its counter clear).
    ///
    /// The counter rechecks keep the transition tied to the current
    /// consecutive-failure streak: a concurrent CLOSED-state success may reset
    /// the count after the increment, and opening on the stale value would turn
    /// a broken streak into an OPEN circuit.
    ///
    /// CLOSED always carries count=0, so the expected and desired values both
    /// hold count=0; the transition flips state and advances the generation in
    /// the SAME CAS. Advancing the generation atomically with the OPEN
    /// transition is what makes the streaming-outcome accounting correct
    /// (#1649 R5 finding 2 + R7): (1) only the CAS WINNER advances the
    /// generation — a concurrent failure that loses the CAS leaves it
    /// untouched, so it cannot stale a valid probe that already captured the
    /// winner's generation; and (2) the new generation is published WITH OPEN,
    /// so any observer that sees OPEN (and can immediately re-enter HALF_OPEN
    /// when `timeout_seconds == 0`) reads the new generation, never the
    /// pre-open value. On the rare rollback path the generation stays
    /// advanced — the only effect is that a CLOSED-admitted (non-probe)
    /// deferred outcome captured just before this point is dropped instead of
    /// recorded, which is negligible and conservative.
    fn trip_after_closed_failure(&self, entry_generation: u32) -> bool {
        if self.failure_count.count_in_cycle(entry_generation) < self.config.failure_threshold {
            return false;
        }
        let opened_generation = entry_generation.wrapping_add(1);
        if self
            .packed
            .compare_exchange(
                pack_full(entry_generation, STATE_CLOSED, 0),
                pack_full(opened_generation, STATE_OPEN, 0),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // A sibling already opened this cycle, or the breaker has moved to
            // a newer cycle: this failure no longer decides anything.
            return false;
        }
        let current_failures = self.failure_count.count_in_cycle(entry_generation);
        if current_failures < self.config.failure_threshold {
            // Roll back OPEN→CLOSED, keeping the advanced generation (see
            // above).
            let _ = self.packed.compare_exchange(
                pack_full(opened_generation, STATE_OPEN, 0),
                pack_full(opened_generation, STATE_CLOSED, 0),
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
            return false;
        }
        warn!(
            "Circuit breaker opening after {} failures",
            current_failures
        );
        true
    }

    /// Reopen the breaker after a failure that was observed WHILE the breaker is
    /// HALF_OPEN (the only caller — the `STATE_HALF_OPEN` arm of
    /// [`settle_tripping_failure`](Self::settle_tripping_failure)). Publishes
    /// OPEN and clears the in-flight count in ONE CAS — so HALF_OPEN admissions
    /// stop at the same instant the count is zeroed (no over-admission window
    /// during the reopen). The loop also reopens a breaker that a concurrent
    /// sibling success closed between this failure observing HALF_OPEN and the
    /// CAS (the sibling-close race): such a failure is current-cycle by
    /// construction, so reopening is correct. A probe ticket stops reopening as
    /// soon as the breaker has left its cycle. Only an already-published OPEN is
    /// left alone. The failing probe's slot is subsumed by the count reset, and a
    /// straggler from this cycle releases as a no-op at 0. Only the reopen
    /// winner re-tags `success_count` for the new cycle, so a stale success of
    /// the reopened cycle can no longer count into the next one.
    fn reopen_after_probe_failure(&self, ticket: ProbeTicket) {
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
                    if !ticket.in_cycle_of(p) {
                        break;
                    }
                    let reopened_generation = packed_generation(p).wrapping_add(1);
                    if self
                        .packed
                        .compare_exchange_weak(
                            p,
                            pack_full(reopened_generation, STATE_OPEN, 0),
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        self.success_count.start_cycle(reopened_generation);
                        warn!("Circuit breaker reopening (probe failed)");
                        break;
                    }
                }
            }
        }
    }

    /// Return a probe ticket's slot, decrementing the in-flight count only if
    /// the breaker is still in the ticket's generation, in the same CAS that
    /// checks it. A generation mismatch means a reopen already cleared this
    /// probe's slot with its cycle, so the current cycle's count is left alone.
    /// Same-generation states carry the probe's slot (HALF_OPEN) or a zeroed
    /// count (CLOSED after recovery), and the count-0 no-op keeps the release
    /// from underflowing. A non-probe holds no slot.
    #[inline]
    fn release_slot(&self, ticket: ProbeTicket) {
        let ProbeTicket::Probe { generation } = ticket else {
            return;
        };
        let _ = self
            .packed
            .try_update(Ordering::AcqRel, Ordering::Acquire, |packed| {
                let count = packed_count(packed);
                if count == 0 || packed_generation(packed) != generation {
                    None
                } else {
                    Some(pack_full(generation, packed_state(packed), count - 1))
                }
            });
    }

    /// The ticket a legacy `bool` probe flag stands for: the cycle that is
    /// current at the call. Generation-blind by construction, so only the
    /// `#[doc(hidden)]` test conveniences below use it.
    fn current_cycle_ticket(&self, is_half_open_probe: bool) -> ProbeTicket {
        if is_half_open_probe {
            ProbeTicket::Probe {
                generation: packed_generation(self.packed.load(Ordering::Acquire)),
            }
        } else {
            ProbeTicket::NonProbe
        }
    }

    /// Test convenience: settle a success against the cycle that is current
    /// at the call. Production code must [`settle`](Self::settle) the ticket
    /// its admission returned instead; this form cannot tell a stale probe
    /// from a current one (CB-1).
    #[doc(hidden)]
    pub fn record_success(&self, is_half_open_probe: bool) {
        self.settle(
            self.current_cycle_ticket(is_half_open_probe),
            BreakerOutcome::Success,
        );
    }

    /// Test convenience: settle a neutral outcome against the cycle that is
    /// current at the call. See [`record_success`](Self::record_success).
    #[doc(hidden)]
    pub fn record_neutral(&self, is_half_open_probe: bool) {
        self.settle(
            self.current_cycle_ticket(is_half_open_probe),
            BreakerOutcome::Neutral,
        );
    }

    /// Test convenience: settle a failure against the cycle that is current at
    /// the call. See [`record_success`](Self::record_success).
    #[doc(hidden)]
    pub fn record_failure(
        &self,
        status_code: u16,
        connection_error: bool,
        is_half_open_probe: bool,
    ) {
        self.settle(
            self.current_cycle_ticket(is_half_open_probe),
            BreakerOutcome::Failure {
                status_code,
                connection_error,
            },
        );
    }

    /// Deterministic-clock variant used by external unit tests. Wall time is
    /// injected separately to prove it remains diagnostic-only.
    #[doc(hidden)]
    pub fn record_failure_at_for_test(
        &self,
        status_code: u16,
        connection_error: bool,
        is_half_open_probe: bool,
        monotonic_now_ms: u64,
        wall_epoch_ms: u64,
    ) {
        self.settle_inner(
            self.current_cycle_ticket(is_half_open_probe),
            BreakerOutcome::Failure {
                status_code,
                connection_error,
            },
            Some((monotonic_now_ms, wall_epoch_ms)),
        );
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
        self.failure_count.count()
    }

    /// Current success count (for metrics).
    pub fn success_count(&self) -> u32 {
        self.success_count.count()
    }

    /// Test seam for the counter half of a success settlement (#7030): count
    /// one HALF_OPEN success for open cycle `generation`, exactly as
    /// [`settle`](Self::settle) does after its state check observed that
    /// cycle. Returns `false` when the increment is refused because the
    /// counter already belongs to a newer cycle. Lets a test stage the
    /// check-then-reopen-then-increment interleaving deterministically.
    #[doc(hidden)]
    pub fn count_success_in_cycle_for_test(&self, generation: u64) -> bool {
        self.success_count.increment(generation as u32).is_some()
    }

    /// Test seam for the transition half of a CLOSED-state failure
    /// settlement (#7030): attempt CLOSED→OPEN for a failure that was checked
    /// and counted in CLOSED cycle `entry_generation`, exactly as
    /// [`settle`](Self::settle) does once the count reached
    /// `failure_threshold`. Returns whether the breaker opened.
    #[doc(hidden)]
    pub fn trip_after_closed_failure_for_test(&self, entry_generation: u64) -> bool {
        self.trip_after_closed_failure(entry_generation as u32)
    }

    /// Test seam: overwrite the failure counter with `count` tagged for
    /// `generation`, to stage a counter state a concurrent settlement can
    /// leave for an instant (for example a recovery between its close CAS and
    /// its counter clear). Never used by production code.
    #[doc(hidden)]
    pub fn stage_failure_count_for_test(&self, generation: u64, count: u32) {
        self.failure_count
            .0
            .store(pack_counter(generation as u32, count), Ordering::Release);
    }

    /// Test seam for the counter half of a CLOSED-state failure settlement
    /// (#7030). See [`count_success_in_cycle_for_test`](Self::count_success_in_cycle_for_test).
    #[doc(hidden)]
    pub fn count_failure_in_cycle_for_test(&self, generation: u64) -> bool {
        self.failure_count.increment(generation as u32).is_some()
    }

    /// Current half-open in-flight counter (for testing).
    #[doc(hidden)]
    pub fn half_open_in_flight(&self) -> u32 {
        packed_count(self.packed.load(Ordering::Acquire))
    }

    /// Last failure timestamp in epoch milliseconds (for testing).
    #[doc(hidden)]
    pub fn last_failure_epoch_ms(&self) -> u64 {
        self.last_failure_epoch_ms.load(Ordering::Relaxed)
    }

    /// Last state-machine failure tick (for deterministic tests).
    #[doc(hidden)]
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
    let mut key = String::new();
    write_circuit_breaker_key(&mut key, namespace, proxy_id, target_key);
    key
}

/// Clear `out` and write the [`circuit_breaker_key`] into it.
fn write_circuit_breaker_key(
    out: &mut String,
    namespace: &str,
    proxy_id: &str,
    target_key: Option<&str>,
) {
    crate::config::db_backend::write_namespaced_runtime_key(out, namespace, proxy_id);
    if let Some(tk) = target_key {
        out.reserve(2 + tk.len());
        out.push_str("::");
        out.push_str(tk);
    }
}

thread_local! {
    /// Scratch buffer for breaker lookups on the proxy hot path, so a cache
    /// hit does not allocate a key; only a miss allocates the owned key.
    static CB_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(96));
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
    /// Coalesces the at-capacity warning. Refused admissions arrive at request
    /// rate (an overflow key is never cached), so the warning emits at most
    /// once per window with a suppressed count; `admission_refused` stays exact.
    admission_refused_warn: AtomicLogRateLimiter,
    admission_refused_warn_epoch: Instant,
}

impl Default for CircuitBreakerCache {
    fn default() -> Self {
        Self::with_max_entries(10_000)
    }
}

impl CircuitBreakerCache {
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
            admission_refused_warn: AtomicLogRateLimiter::new(),
            admission_refused_warn_epoch: Instant::now(),
        }
    }

    /// Get or create a circuit breaker for a proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the request resolved to
    /// a concrete upstream target or direct backend override, and `None` when a
    /// direct backend proxy should use one breaker for the proxy.
    /// If the config has changed, replaces the breaker with a fresh one. That
    /// replacement belongs to ADMISSION only: a request completion settles on
    /// the breaker instance its admission returned, checked with
    /// [`is_current`](Self::is_current), and never resolves a breaker again
    /// from its captured (possibly older) config.
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

        // Hot path: matching-config hits use a shard read lock only and look up
        // through a thread-local key buffer instead of allocating.
        let hit = CB_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            write_circuit_breaker_key(&mut key, namespace, proxy_id, target_key);
            self.breakers
                .get(key.as_str())
                .filter(|existing| existing.config() == config)
                .map(|existing| existing.value().clone())
        });
        if let Some(existing) = hit {
            return existing;
        }
        let key = circuit_breaker_key(namespace, proxy_id, target_key);

        // Miss or config change: per-key entry API holds the shard write lock
        // for create/replace so concurrent same-key callers share one Arc, and
        // vacant keys reserve capacity before publishing.
        let refused_key = match self.breakers.entry(key) {
            Entry::Occupied(mut occupied) => {
                if occupied.get().config() == config {
                    return occupied.get().clone();
                }
                let cb = Arc::new(CircuitBreaker::new(config.clone()));
                occupied.insert(cb.clone());
                return cb;
            }
            Entry::Vacant(vacant) => {
                if self.try_reserve_entry_slot() {
                    let cb = Arc::new(CircuitBreaker::new(config.clone()));
                    vacant.insert(cb.clone());
                    return cb;
                }
                // Consuming the vacant entry releases the shard write lock
                // before any diagnostic work below.
                vacant.into_key()
            }
        };

        self.admission_refused.fetch_add(1, Ordering::Relaxed);
        if let Some(suppressed) = self.record_admission_refused_warning() {
            warn!(
                max_entries = self.max_entries,
                suppressed,
                "Circuit breaker cache at capacity, skipping new entry for {}",
                refused_key
            );
        }
        // Transient breaker: not cached, so overflow traffic does not retain
        // state across requests and cannot grow the map.
        Arc::new(CircuitBreaker::new(config.clone()))
    }

    /// Rate-limit the at-capacity warning; `Some(suppressed)` means emit now.
    fn record_admission_refused_warning(&self) -> Option<u64> {
        let now_ms = u64::try_from(self.admission_refused_warn_epoch.elapsed().as_millis())
            .unwrap_or(u64::MAX);
        self.admission_refused_warn.on_event(now_ms)
    }

    fn try_reserve_entry_slot(&self) -> bool {
        self.entry_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    fn release_entry_slot(&self) {
        let _ = self
            .entry_count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
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
        CB_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            write_circuit_breaker_key(&mut key, namespace, proxy_id, target_key);
            self.breakers
                .get(key.as_str())
                .map(|entry| entry.value().clone())
        })
    }

    /// Whether `admitted` — the breaker instance that admitted a request — is
    /// still the one cached for this proxy (+target), compared by identity.
    ///
    /// Admission ([`can_execute`](Self::can_execute)) replaces a cached breaker
    /// whose config differs, so a configuration change starts a fresh breaker
    /// at the next admission. A completion must settle on the exact breaker
    /// that admitted it: resolving it again by its captured config would either
    /// replace the live (possibly OPEN) breaker with a fresh CLOSED one (#6799)
    /// or, after an A→B→A reload or a prune that recreated the key with the same
    /// config, settle on a NEW instance it never ran against. A completion whose
    /// admitting breaker is no longer cached is stale: its outcome is discarded
    /// and any probe slot it holds is released on the admitting breaker itself.
    ///
    /// This is a shard read with the thread-local key buffer, like a
    /// `get_or_create` hit: no allocation and no write lock.
    pub fn is_current(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        admitted: &Arc<CircuitBreaker>,
    ) -> bool {
        CB_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            write_circuit_breaker_key(&mut key, namespace, proxy_id, target_key);
            self.breakers
                .get(key.as_str())
                .is_some_and(|entry| Arc::ptr_eq(entry.value(), admitted))
        })
    }

    /// Check if a request can proceed for a given proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the proxy uses an upstream,
    /// or `None` for direct backend proxies.
    ///
    /// Returns `Ok((cb, ticket, admission_generation))`. The caller settles
    /// `ticket` exactly once on `cb` with [`CircuitBreaker::settle`] (in the
    /// proxy, through `HalfOpenProbeGuard`), so a probe slot is returned only by
    /// the request that holds it and only within the open cycle it was claimed
    /// in (CB-1, #6177).
    ///
    /// `admission_generation` is the open generation the admission was decided
    /// in, taken from the same atomic operation that admitted the request (see
    /// [`CircuitBreaker::admit`]). Deferred streaming outcomes stale-check
    /// against it (#1649).
    pub fn can_execute(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Result<(Arc<CircuitBreaker>, ProbeTicket, u64), CircuitOpenError> {
        let cb = self.get_or_create(namespace, proxy_id, target_key, config);
        let (ticket, admission_generation) = cb.admit()?;
        Ok((cb, ticket, admission_generation))
    }

    /// Like [`can_execute`](Self::can_execute); the third element is the open
    /// generation the request is admitted under.
    ///
    /// The generation is the one the admitting atomic operation observed or
    /// published, so it is exactly the admission's own cycle: a concurrent open
    /// racing this admission can only make a later deferred streaming outcome
    /// look *stale* (neutralized — recovered by the next probe), never *too new*
    /// (which would let a request heal/reopen a HALF_OPEN cycle it never probed).
    /// Used by the #1649 streaming-deferral admission sites — the initial
    /// admission and every retry-target rotation — where the backend-health
    /// outcome is recorded at response-body completion. (#1649 R6 finding 3)
    pub fn can_execute_with_admission_epoch(
        &self,
        namespace: &str,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Result<(Arc<CircuitBreaker>, ProbeTicket, u64), CircuitOpenError> {
        self.can_execute(namespace, proxy_id, target_key, config)
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
    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    /// Whether the cache is empty.
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

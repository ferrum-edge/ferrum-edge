//! Lock-free rate limiter for hot-path diagnostic warnings.
//!
//! Mirrors [`LogRateLimiter`](super::accept_backoff::LogRateLimiter) semantics
//! without mutexes: emits the first event immediately, then at most one summary
//! per window carrying how many events were suppressed since the last emit. The
//! event that triggers an emit is logged and is never counted as suppressed.
//!
//! Pending event counts saturate at [`u64::MAX`] and never wrap. Composed gates
//! record each event at every scope before claiming an emit window, and clear
//! the pending counts only after every scope admits the warning. A denied
//! partner therefore delays the next attempt without discarding accounting.

use std::sync::atomic::{AtomicU64, Ordering};

/// Sentinel for "no emit yet" in [`AtomicLogRateLimiter::last_emit_ms`].
const UNSET_MS: u64 = u64::MAX;

/// Default emit window: at most one summary line per second.
pub const DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS: u64 = 1_000;

/// Bounds the rate of a repeated log line without locks.
#[derive(Debug)]
pub struct AtomicLogRateLimiter {
    last_emit_ms: AtomicU64,
    suppressed: AtomicU64,
    window_ms: u64,
}

impl Default for AtomicLogRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn fetch_add_saturating(counter: &AtomicU64, delta: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl AtomicLogRateLimiter {
    /// Create a limiter with [`DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS`].
    pub const fn new() -> Self {
        Self::with_window_ms(DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS)
    }

    /// Create a limiter with a custom window (millis).
    pub const fn with_window_ms(window_ms: u64) -> Self {
        Self {
            last_emit_ms: AtomicU64::new(UNSET_MS),
            suppressed: AtomicU64::new(0),
            window_ms,
        }
    }

    /// Record one event without making an emit decision.
    #[inline]
    fn record_event(&self) {
        fetch_add_saturating(&self.suppressed, 1);
    }

    /// Atomically claim this scope's next emit window.
    #[inline]
    fn try_claim_emit(&self, now_ms: u64) -> bool {
        let mut last_ms = self.last_emit_ms.load(Ordering::Relaxed);
        loop {
            if last_ms != UNSET_MS && now_ms.saturating_sub(last_ms) < self.window_ms {
                return false;
            }
            match self.last_emit_ms.compare_exchange_weak(
                last_ms,
                now_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => last_ms = observed,
            }
        }
    }

    /// Clear the events covered by a committed warning and exclude the warning's
    /// triggering event from the reported suppressed count. At saturation,
    /// preserve the sentinel maximum rather than wrapping or understating it.
    #[inline]
    fn take_suppressed_after_emit(&self) -> u64 {
        match self.suppressed.swap(0, Ordering::Relaxed) {
            u64::MAX => u64::MAX,
            recorded => recorded.saturating_sub(1),
        }
    }

    /// Single-scope convenience used by external utility regressions.
    #[inline]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn on_event(&self, now_ms: u64) -> Option<u64> {
        self.record_event();
        self.try_claim_emit(now_ms)
            .then(|| self.take_suppressed_after_emit())
    }

    /// Compose per-instance and process-wide scopes: record every rejection at
    /// both, emit only when both admit, and clear neither scope's aggregate when
    /// a partner denies. The instance claim intentionally precedes the global
    /// claim: a global window is advanced only for an actual warning.
    #[inline]
    pub(crate) fn dual_gate_emit(
        instance: &Self,
        global: &Self,
        now_ms: u64,
    ) -> Option<(u64, u64)> {
        instance.record_event();
        global.record_event();
        if !instance.try_claim_emit(now_ms) {
            return None;
        }
        if !global.try_claim_emit(now_ms) {
            return None;
        }
        Some((
            instance.take_suppressed_after_emit(),
            global.take_suppressed_after_emit(),
        ))
    }

    /// Clear state for isolated unit tests.
    #[doc(hidden)]
    pub fn reset_for_test(&self) {
        self.last_emit_ms.store(UNSET_MS, Ordering::Relaxed);
        self.suppressed.store(0, Ordering::Relaxed);
    }

    /// Observed suppressed-event accumulator. Test-only.
    #[doc(hidden)]
    pub fn suppressed_count_for_test(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }

    /// Seed limiter state for external regressions. Test-only.
    #[doc(hidden)]
    pub fn seed_for_test(&self, last_emit_ms: u64, suppressed: u64) {
        self.last_emit_ms.store(last_emit_ms, Ordering::Relaxed);
        self.suppressed.store(suppressed, Ordering::Relaxed);
    }
}

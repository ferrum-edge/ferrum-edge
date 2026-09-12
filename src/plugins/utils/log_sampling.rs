//! Fixed-cardinality warning sampling for request and delivery diagnostics.
//!
//! Each macro expansion owns one process-wide sampler, shared across plugin
//! instances and reloads. The gate and counter allocate nothing, use no map or
//! lock, and never depend on a client identity. Detailed events remain at debug.

use std::sync::atomic::{AtomicU64, Ordering};

/// Minimum spacing between warnings from the same source site.
pub const WARNING_INTERVAL_MS: u64 = 10_000;

/// An atomic warning gate driven by monotonic milliseconds.
#[derive(Default)]
pub struct WarningSampler {
    // Zero means never emitted; live ticks are offset by one.
    last_emitted_tick: AtomicU64,
    suppressed: AtomicU64,
}

impl WarningSampler {
    pub const fn new() -> Self {
        Self {
            last_emitted_tick: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Return the suppressed count when this event wins the warning slot.
    ///
    /// A concurrent event at the interval boundary may be counted in either
    /// adjacent summary, but is never lost or counted twice. A stale clock
    /// sample cannot move the gate backwards. The counter saturates on overflow.
    #[inline]
    pub fn on_event(&self, now_ms: u64) -> Option<u64> {
        let tick = now_ms.saturating_add(1);
        let last = self.last_emitted_tick.load(Ordering::Relaxed);
        if (last == 0 || tick.saturating_sub(last) >= WARNING_INTERVAL_MS)
            && self
                .last_emitted_tick
                .compare_exchange(last, tick, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        let _ = self
            .suppressed
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        None
    }
}

/// Emit the detailed event at debug and at most one warning per site per 10s.
///
/// Accepts tracing fields and format arguments, including an optional `target:`.
/// Warnings retain the sampled event and add `suppressed_events` and
/// `sample_interval_seconds`. No arguments are evaluated for a suppressed event
/// when debug is disabled. There is no timer: the next event emits the summary.
#[macro_export]
macro_rules! warn_sampled {
    (target: $target:expr, $($fields:tt)+) => {{
        tracing::debug!(target: $target, $($fields)+);
        if tracing::enabled!(target: $target, tracing::Level::WARN) {
            static SAMPLER: $crate::plugins::utils::log_sampling::WarningSampler =
                $crate::plugins::utils::log_sampling::WarningSampler::new();
            if let Some(suppressed) = SAMPLER.on_event($crate::socket_opts::monotonic_now_ms()) {
                tracing::warn!(
                    target: $target,
                    suppressed_events = suppressed,
                    sample_interval_seconds = 10_u64,
                    $($fields)+
                );
            }
        }
    }};
    ($($fields:tt)+) => {
        $crate::warn_sampled!(target: module_path!(), $($fields)+)
    };
}

pub use crate::warn_sampled;

//! Shared percent-roll helper for fault-injection style plugins.
//!
//! Both the proxy-scoped [`fault_injection`](crate::plugins::fault_injection)
//! plugin and the per-rule `Fault` action carried by
//! [`mesh_route_dispatch`](crate::plugins::mesh_route_dispatch) make the same
//! per-request "did this percentile roll hit?" decision. Keeping the math in
//! one place ensures both surfaces stay semantically identical: same RNG,
//! same threshold mapping, same handling of the `>= 100.0` short-circuit.
//!
//! ## Sampling model
//!
//! Each call to [`FaultRoller::roll_pair`] consumes one `AtomicU64::fetch_add`
//! and derives two domain-separated 64-bit samples from a per-instance seed.
//! Each sample is compared against `(percentage / 100) * 2^64` to decide
//! whether the roll hit. Positive percentages below one sampler bucket are
//! rounded up to that first bucket, so every accepted nonzero percentage can
//! trigger.
//!
//! ## Hot-path properties
//!
//! - Zero allocations.
//! - One relaxed atomic increment per call.
//! - Pure arithmetic after cold construction — no request-time RNG, syscalls,
//!   allocations, or locks.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

const PROBABILITY_DENOMINATOR: f64 = 18_446_744_073_709_551_616.0;
const DELAY_STREAM_DOMAIN: u64 = 0xD1B5_4A32_D192_ED03;
const ABORT_STREAM_DOMAIN: u64 = 0x94D0_49BB_1331_11EB;
const SECONDARY_ABORT_STREAM_DOMAIN: u64 = 0x517C_C1B7_2722_0A95;

/// Shared maximum accepted delay for proxy-scoped and route-local faults.
/// Long-lived transport cancellation is not uniformly available on every
/// protocol path, so the configuration boundary limits retained work to one
/// minute even when a downstream reset cannot yet be observed immediately.
pub const MAX_FAULT_DELAY_MS: u64 = 60_000;

static PROCESS_SEED: LazyLock<u64> = LazyLock::new(|| {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(0xF3A7_1A5E_1D6B_92C4);
    hasher.finish()
});
static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

/// Per-instance roll counter. Wrap one of these per plugin instance (or per
/// per-rule action carrier) so concurrent requests get distinct samples and
/// percentile distributions converge to the configured percentage.
#[derive(Debug)]
pub struct FaultRoller {
    counter: AtomicU64,
    seed: u64,
}

/// Outcome of one paired roll for delay + abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultRollOutcome {
    pub delay_triggered: bool,
    pub abort_triggered: bool,
}

impl FaultRoller {
    /// Construct a production sampler with a process-random, instance-unique
    /// stream seed. Seed creation happens only while plugin caches and route
    /// actions are built, never on the request hot path.
    pub fn new() -> Self {
        let stream_id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
        // XOR with a process-random secret and pass the result through a
        // bijective 64-bit mixer. Distinct stream ids therefore remain
        // distinct until the id counter wraps, while replicas start from
        // unrelated process seeds.
        Self::with_seed(splitmix64(*PROCESS_SEED ^ stream_id))
    }

    /// Construct a deterministic stream for tests and reproducible simulations.
    /// Production plugin constructors use [`Self::new`] so independently built
    /// instances and replicas do not share ordinal-aligned sequences.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed,
        }
    }

    /// Roll for both delay and abort percentages in one atomic-counter
    /// increment and two domain-separated SplitMix finalizations.
    ///
    /// `None` for either percentage skips that side (returns `false`).
    /// `Some(pct)` rolls a single 64-bit sample against `pct / 100`.
    /// `pct >= 100.0` is a definite hit, `pct <= 0.0` is a definite miss.
    pub fn roll_pair(
        &self,
        delay_percentage: Option<f64>,
        abort_percentage: Option<f64>,
    ) -> FaultRollOutcome {
        let ordinal = self.counter.fetch_add(1, Ordering::Relaxed);
        let stream_position = ordinal.wrapping_add(self.seed);
        let delay_sample = splitmix64(stream_position ^ DELAY_STREAM_DOMAIN);
        let abort_sample = splitmix64(stream_position ^ ABORT_STREAM_DOMAIN);
        FaultRollOutcome {
            delay_triggered: delay_percentage.is_some_and(|pct| probability_hit(delay_sample, pct)),
            abort_triggered: abort_percentage.is_some_and(|pct| probability_hit(abort_sample, pct)),
        }
    }

    /// Independent roll for a conditional secondary abort (evaluated only when
    /// the primary abort did not trigger). Uses a distinct domain-separated
    /// stream so its sample never correlates with the primary abort roll.
    pub fn roll_secondary_abort(&self, percentage: f64) -> bool {
        let ordinal = self.counter.fetch_add(1, Ordering::Relaxed);
        let stream_position = ordinal.wrapping_add(self.seed);
        let sample = splitmix64(stream_position ^ SECONDARY_ABORT_STREAM_DOMAIN);
        probability_hit(sample, percentage)
    }
}

impl Default for FaultRoller {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare a 64-bit sample against a percentage threshold.
///
/// `percentage >= 100.0` always hits; `percentage <= 0.0` never hits.
/// Non-finite (`NaN`, `+Inf`, `-Inf`) inputs are treated as misses so a
/// future bug that lets garbage reach the hot path can never accidentally
/// fire 100% faults. Config validators reject non-finite / out-of-range
/// inputs at construction; this is defense-in-depth.
pub fn probability_hit(sample: u64, percentage: f64) -> bool {
    if !percentage.is_finite() {
        return false;
    }
    if percentage >= 100.0 {
        return true;
    }
    if percentage <= 0.0 {
        return false;
    }
    let scaled = (percentage / 100.0) * PROBABILITY_DENOMINATOR;
    // `max(1.0)` also covers positive subnormal percentages whose division by
    // 100 underflows to zero. This is the documented round-up contract for
    // values below one 2^-64 bucket.
    let threshold = scaled.ceil().max(1.0) as u128;
    u128::from(sample) < threshold
}

/// 64-bit SplitMix used as a stateless mixer over a monotonic counter.
/// Identical constants to the canonical `splitmix64` finalizer — keeps
/// sample distribution identical to the original fault-injection plugin.
pub fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E3779B97F4A7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D049BB133111EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probability_hit_zero_and_below_never_hits() {
        assert!(!probability_hit(0, 0.0));
        assert!(!probability_hit(u64::MAX, 0.0));
        assert!(!probability_hit(u64::MAX, -10.0));
    }

    #[test]
    fn probability_hit_one_hundred_and_above_always_hits() {
        assert!(probability_hit(0, 100.0));
        assert!(probability_hit(u64::MAX, 100.0));
        assert!(probability_hit(u64::MAX, 150.0));
    }

    #[test]
    fn probability_hit_non_finite_never_hits() {
        assert!(!probability_hit(0, f64::NAN));
        assert!(!probability_hit(0, f64::INFINITY));
        assert!(!probability_hit(0, f64::NEG_INFINITY));
    }

    #[test]
    fn roll_pair_with_zero_percentages_never_triggers() {
        let roller = FaultRoller::with_seed(7);
        for _ in 0..1000 {
            let outcome = roller.roll_pair(Some(0.0), Some(0.0));
            assert!(!outcome.delay_triggered);
            assert!(!outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_with_full_percentages_always_triggers() {
        let roller = FaultRoller::with_seed(7);
        for _ in 0..1000 {
            let outcome = roller.roll_pair(Some(100.0), Some(100.0));
            assert!(outcome.delay_triggered);
            assert!(outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_with_none_returns_false_for_that_side() {
        let roller = FaultRoller::with_seed(7);
        // Even at 100% on the configured side, the unset side should never trigger.
        for _ in 0..100 {
            let outcome = roller.roll_pair(None, Some(100.0));
            assert!(!outcome.delay_triggered);
            assert!(outcome.abort_triggered);
        }
        // And vice versa.
        for _ in 0..100 {
            let outcome = roller.roll_pair(Some(100.0), None);
            assert!(outcome.delay_triggered);
            assert!(!outcome.abort_triggered);
        }
    }

    #[test]
    fn roll_pair_converges_to_configured_percentage() {
        // The sampler is deterministic given the counter sequence, so we can
        // assert a fairly tight bound. 50% over 10k draws should land near
        // 5000 hits; allow a 2.5% absolute slack to keep the test stable.
        let roller = FaultRoller::with_seed(0xC0FFEE);
        let n = 10_000;
        let mut hits = 0usize;
        for _ in 0..n {
            if roller.roll_pair(Some(50.0), None).delay_triggered {
                hits += 1;
            }
        }
        let ratio = hits as f64 / n as f64;
        assert!(
            (ratio - 0.5).abs() < 0.025,
            "50% over {n} draws produced {hits} hits ({ratio}); expected ~5000"
        );
    }

    #[test]
    fn every_positive_percentage_has_at_least_one_triggering_bucket() {
        for percentage in [f64::MIN_POSITIVE, f64::from_bits(1), 1.0e-30, 1.0e-18] {
            assert!(probability_hit(0, percentage));
            assert!(!probability_hit(1, percentage));
        }
    }

    #[test]
    fn percentages_round_at_the_first_nonzero_bucket() {
        let one_bucket_percent = 100.0 / PROBABILITY_DENOMINATOR;
        let immediately_below = f64::from_bits(one_bucket_percent.to_bits() - 1);
        let immediately_above = f64::from_bits(one_bucket_percent.to_bits() + 1);

        for percentage in [immediately_below, one_bucket_percent] {
            assert!(probability_hit(0, percentage));
            assert!(!probability_hit(1, percentage));
        }
        assert!(probability_hit(0, immediately_above));
        assert!(probability_hit(1, immediately_above));
        assert!(!probability_hit(2, immediately_above));
    }

    #[test]
    fn production_instances_have_distinct_sample_streams() {
        let left = FaultRoller::new();
        let right = FaultRoller::new();
        assert_ne!(left.seed, right.seed);

        // SplitMix is a permutation. Distinct same-ordinal inputs therefore
        // cannot produce the ordinal-identical raw sequence that the old
        // zero-seeded constructor emitted.
        for ordinal in 0..128_u64 {
            assert_ne!(
                splitmix64(ordinal.wrapping_add(left.seed) ^ DELAY_STREAM_DOMAIN),
                splitmix64(ordinal.wrapping_add(right.seed) ^ DELAY_STREAM_DOMAIN)
            );
        }
    }

    #[test]
    fn seeded_streams_are_reproducible_and_domain_separated() {
        let left = FaultRoller::with_seed(42);
        let right = FaultRoller::with_seed(42);
        for ordinal in 0..128_u64 {
            let a = left.roll_pair(Some(50.0), Some(50.0));
            let b = right.roll_pair(Some(50.0), Some(50.0));
            assert_eq!(a, b);
            let stream_position = ordinal.wrapping_add(42);
            assert_ne!(
                splitmix64(stream_position ^ DELAY_STREAM_DOMAIN),
                splitmix64(stream_position ^ ABORT_STREAM_DOMAIN)
            );
        }
    }
}

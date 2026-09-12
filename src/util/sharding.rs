//! Shared helper for sizing `DashMap` shard counts on hot pool/cache paths.
//!
//! `DashMap::new()` defaults to `4 * num_cpus` shards. That's fine for small
//! maps but at high cardinality (1K+ unique pool keys, distinct DNS hosts,
//! distinct client IPs) the default doesn't scale: write contention on any
//! one shard pins to a single internal `RwLock` while sibling shards sit
//! idle. Bumping the shard count to a power of two ≥ `max(64, num_cpus * 16)`
//! gives concurrent inserts/removals enough independent locks to actually
//! parallelise without wasting memory on near-empty shards.
//!
//! Operators can override the auto-sizing via `FERRUM_POOL_SHARD_AMOUNT`
//! ([`crate::config::EnvConfig::pool_shard_amount`]). `0` keeps the
//! auto-derived default; any positive value is rounded up to the next power
//! of two, with a minimum of two (DashMap requires more than one shard). Values too
//! large for `next_power_of_two` are saturated to [`MAX_SHARD_AMOUNT`] —
//! a billion shards is already 6 OOM beyond any sane configuration, and
//! we'd rather log + clamp than abort the gateway at startup.

/// Saturation ceiling for shard counts — `2^30` (just over a billion). Any
/// value above this returned from [`usize::next_power_of_two`] would either
/// overflow on 32-bit targets or describe a configuration so absurd it is
/// almost certainly a bug. Clamping here keeps the helper panic-free even
/// when a misconfigured operator passes `usize::MAX` via the env var.
pub const MAX_SHARD_AMOUNT: usize = 1 << 30;

/// Compute the DashMap shard amount for hot pool/cache maps.
///
/// Resolution order:
/// 1. If `override_value > 0`, round up to the next power of two via
///    [`usize::checked_next_power_of_two`]; on overflow, saturate to
///    [`MAX_SHARD_AMOUNT`]. The minimum explicit result is two, including for
///    an override of one, because DashMap rejects a single shard.
/// 2. Otherwise, derive from the host CPU topology:
///    `next_power_of_two(max(64, num_cpus * 16))`, also saturating.
///
/// The floor of 64 keeps small dev hosts (1–4 cores) from collapsing to a
/// shard count where pool churn serialises. The `num_cpus * 16` term scales
/// with the kind of write parallelism the runtime actually has available
/// (tokio worker threads ≈ `num_cpus`, each potentially racing pool
/// inserts on cold dispatch).
pub fn pool_shard_amount(override_value: usize) -> usize {
    fn saturating_next_pow2(n: usize) -> usize {
        n.checked_next_power_of_two().unwrap_or(MAX_SHARD_AMOUNT)
    }
    if override_value > 0 {
        return saturating_next_pow2(override_value).clamp(2, MAX_SHARD_AMOUNT);
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    saturating_next_pow2(cores.saturating_mul(16).max(64)).min(MAX_SHARD_AMOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Auto-sizing must always return a power of two — DashMap panics
    /// otherwise. The runtime topology is whatever the test host has, so we
    /// only assert the contract, not a specific number.
    #[test]
    fn auto_returns_power_of_two() {
        let s = pool_shard_amount(0);
        assert!(
            s.is_power_of_two(),
            "auto-sized shard count {s} is not a power of two"
        );
        assert!(s >= 64, "auto-sized shard count {s} below floor of 64");
    }

    /// An explicit override that is already a power of two must be returned
    /// unchanged.
    #[test]
    fn override_power_of_two_is_returned_verbatim() {
        for n in [2usize, 4, 16, 64, 128, 1024] {
            let s = pool_shard_amount(n);
            assert_eq!(s, n, "override {n} was rewritten to {s}");
        }
    }

    /// A non-power-of-two override is rounded up. Operators who write
    /// "shard=200" in their config must get a working DashMap, not a panic.
    #[test]
    fn override_non_power_of_two_rounds_up() {
        assert_eq!(pool_shard_amount(3), 4);
        assert_eq!(pool_shard_amount(100), 128);
        assert_eq!(pool_shard_amount(513), 1024);
    }

    /// Zero means auto — never treated as "0 shards" (DashMap would panic).
    #[test]
    fn zero_means_auto() {
        let auto = pool_shard_amount(0);
        assert!(auto.is_power_of_two());
        assert!(auto >= 64);
    }

    /// `usize::MAX` must not panic — `next_power_of_two` would overflow,
    /// so the helper saturates to `MAX_SHARD_AMOUNT`. This guards against a
    /// misconfigured operator (or test fixture) bringing the gateway down
    /// at startup with a numerical error.
    #[test]
    fn override_saturates_at_max_shard_amount_for_extremes() {
        let s = pool_shard_amount(usize::MAX);
        assert!(s.is_power_of_two());
        assert_eq!(s, MAX_SHARD_AMOUNT);
    }

    /// A value just below the saturation ceiling rounds up cleanly without
    /// hitting the saturation branch — proves the saturation only kicks in
    /// when the rounded-up value would overflow.
    #[test]
    fn override_just_below_ceiling_is_returned_verbatim() {
        let s = pool_shard_amount(MAX_SHARD_AMOUNT);
        assert_eq!(s, MAX_SHARD_AMOUNT);
    }
}

//! Adaptive buffer sizing for TCP/WebSocket tunnel copy buffers and UDP batch limits.
//!
//! Tracks bytes transferred per completed connection (TCP/WS) and datagrams per
//! batch cycle (UDP) using per-proxy EWMA, then selects optimal buffer sizes and
//! batch limits for new connections based on observed traffic patterns.
//!
//! Inspired by Envoy's watermark-based flow control with power-of-two memory
//! class bucketing, adapted for tokio's `copy_bidirectional_with_sizes` API.
//!
//! **Design invariants:**
//! - Lock-free hot path: `DashMap` sharded reads + `AtomicU64` CAS loops only.
//! - Zero allocation on hot path: `get_buffer_size()` / `get_batch_limit()` do
//!   one DashMap read + one atomic load + three comparisons.
//! - `record_connection()` / `record_batch_cycle()` allocate only on first-seen
//!   proxy_id (DashMap insert); subsequent calls are CAS-only.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ── EWMA constants ──────────────────────────────────────────────────────────

/// Fixed-point scale factor (1000 = 1.0), matching `load_balancer.rs` convention.
const EWMA_SCALE: u64 = 1000;

/// Sentinel: no data recorded yet for this proxy.
const UNSET: u64 = u64::MAX;

// ── Buffer size tiers (power-of-two, Envoy-inspired) ────────────────────────

/// Buffer sizes indexed by tier.
const BUFFER_TIER_SIZES: [usize; 4] = [
    8 * 1024,   // Tier 0: small messages
    32 * 1024,  // Tier 1: medium payloads
    64 * 1024,  // Tier 2: large payloads (previous static default)
    256 * 1024, // Tier 3: bulk transfers
];

/// Upper bounds (exclusive) for bytes-per-connection EWMA → tier selection.
const BUFFER_TIER_THRESHOLDS: [u64; 3] = [
    16 * 1024,  // < 16 KiB  → Tier 0
    256 * 1024, // < 256 KiB → Tier 1
    4 * 1024 * 1024, // < 4 MiB   → Tier 2
                // ≥ 4 MiB   → Tier 3
];

// ── UDP batch limit tiers ───────────────────────────────────────────────────

/// Batch limits indexed by tier.
const BATCH_TIER_LIMITS: [usize; 4] = [
    64,   // Tier 0: quiet proxy, maximize fairness
    256,  // Tier 1: moderate traffic
    2000, // Tier 2: active proxy
    6000, // Tier 3: burst traffic, maximize throughput
];

/// Upper bounds (exclusive) for datagrams-per-cycle EWMA → tier selection.
const BATCH_TIER_THRESHOLDS: [u64; 3] = [
    10,  // < 10   → Tier 0
    100, // < 100  → Tier 1
    1000, // < 1000 → Tier 2
         // ≥ 1000 → Tier 3
];

// ── Per-proxy state ─────────────────────────────────────────────────────────

/// Jitter EWMA threshold (microseconds) above which buffer tier is bumped.
/// 10ms of inter-arrival jitter indicates lossy/variable real-time traffic.
const JITTER_BUMP_THRESHOLD_US: u64 = 10_000;

/// Per-proxy EWMA state. All fields are atomic for lock-free concurrent access.
struct ProxyBufferState {
    /// EWMA of total bytes per connection (both directions summed).
    /// `UNSET` = no data recorded yet.
    bytes_ewma: AtomicU64,
    /// Number of connections recorded (diagnostics / warmup detection).
    bytes_sample_count: AtomicU64,
    /// EWMA of datagrams drained per batch cycle.
    /// `UNSET` = no data recorded yet.
    dgram_ewma: AtomicU64,
    /// Number of batch cycles recorded.
    dgram_sample_count: AtomicU64,
    /// EWMA of inter-arrival jitter in microseconds (for UDP real-time traffic).
    jitter_ewma: AtomicU64,
}

impl ProxyBufferState {
    fn new() -> Self {
        Self {
            bytes_ewma: AtomicU64::new(UNSET),
            bytes_sample_count: AtomicU64::new(0),
            dgram_ewma: AtomicU64::new(UNSET),
            dgram_sample_count: AtomicU64::new(0),
            jitter_ewma: AtomicU64::new(UNSET),
        }
    }
}

// ── Tier selection helpers ──────────────────────────────────────────────────

/// Select a tier index (0-3) based on EWMA value and threshold array.
#[inline]
fn select_tier(ewma: u64, thresholds: &[u64; 3]) -> usize {
    if ewma < thresholds[0] {
        0
    } else if ewma < thresholds[1] {
        1
    } else if ewma < thresholds[2] {
        2
    } else {
        3
    }
}

/// EWMA CAS loop. Updates `current` atomically using the EWMA formula.
/// On first sample (`UNSET`), seeds directly without smoothing.
///
/// Follows the identical pattern used in `load_balancer.rs` for latency EWMA.
fn update_ewma(current: &AtomicU64, sample: u64, alpha_fp: u64) {
    loop {
        let old = current.load(Ordering::Relaxed);
        let new_val = if old == UNSET {
            // First sample seeds directly.
            sample
        } else {
            // EWMA: new = α * sample + (1 - α) * old
            alpha_fp
                .saturating_mul(sample)
                .saturating_add((EWMA_SCALE - alpha_fp).saturating_mul(old))
                / EWMA_SCALE
        };
        if current
            .compare_exchange_weak(old, new_val, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
}

// ── Public tracker ──────────────────────────────────────────────────────────

/// Adaptive buffer and batch limit tracker.
///
/// Maintains per-proxy EWMA of bytes-per-connection and datagrams-per-batch-cycle,
/// selecting optimal buffer sizes and batch limits for new connections.
pub struct AdaptiveBufferTracker {
    /// Per-proxy state, keyed by proxy_id.
    state: DashMap<String, ProxyBufferState>,
    /// EWMA alpha as fixed-point (e.g., 300 = 0.3).
    alpha_fp: u64,
    /// Minimum buffer size (floor).
    min_buffer_size: usize,
    /// Maximum buffer size (ceiling).
    max_buffer_size: usize,
    /// Default buffer size when disabled or no data.
    default_buffer_size: usize,
    /// Default batch limit when disabled or no data.
    default_batch_limit: usize,
    /// Buffer adaptation enabled.
    buffer_enabled: bool,
    /// Batch limit adaptation enabled.
    batch_enabled: bool,
}

impl AdaptiveBufferTracker {
    /// Create a new tracker with the given configuration.
    ///
    /// `alpha_fp` is clamped to `[1, 999]`. `min_buffer_size` and `max_buffer_size`
    /// are clamped to `[1024, 1_048_576]`. If `min > max` after clamping, `min` is
    /// set to `max`.
    pub fn new(
        buffer_enabled: bool,
        batch_enabled: bool,
        alpha_fp: u64,
        min_buffer_size: usize,
        max_buffer_size: usize,
        default_buffer_size: usize,
        default_batch_limit: usize,
    ) -> Self {
        let alpha_fp = alpha_fp.clamp(1, 999);
        let min_buffer_size = min_buffer_size.clamp(1024, 1_048_576);
        let max_buffer_size = max_buffer_size.clamp(1024, 1_048_576);
        let min_buffer_size = min_buffer_size.min(max_buffer_size);
        let default_buffer_size = default_buffer_size.clamp(min_buffer_size, max_buffer_size);
        let default_batch_limit = default_batch_limit.max(1);

        Self {
            state: DashMap::new(),
            alpha_fp,
            min_buffer_size,
            max_buffer_size,
            default_buffer_size,
            default_batch_limit,
            buffer_enabled,
            batch_enabled,
        }
    }

    // ── Buffer size (TCP / WS tunnel) ───────────────────────────────────

    /// Returns the recommended buffer size for a new connection on the given proxy.
    ///
    /// Hot path: one DashMap read + one atomic load + three comparisons.
    /// Returns `default_buffer_size` when disabled or no data for this proxy.
    pub fn get_buffer_size(&self, proxy_id: &str) -> usize {
        if !self.buffer_enabled {
            return self.default_buffer_size;
        }
        let ewma = match self.state.get(proxy_id) {
            Some(entry) => entry.bytes_ewma.load(Ordering::Relaxed),
            None => return self.default_buffer_size,
        };
        if ewma == UNSET {
            return self.default_buffer_size;
        }
        let mut tier = select_tier(ewma, &BUFFER_TIER_THRESHOLDS);
        // If jitter EWMA > 10ms, bump up one tier for safety margin.
        // High jitter indicates lossy/variable real-time traffic that benefits
        // from larger buffers to absorb burst arrivals.
        if let Some(entry) = self.state.get(proxy_id) {
            let jitter_ewma = entry.jitter_ewma.load(Ordering::Relaxed);
            if jitter_ewma != UNSET && jitter_ewma > JITTER_BUMP_THRESHOLD_US && tier < 3 {
                tier += 1;
            }
        }
        BUFFER_TIER_SIZES[tier].clamp(self.min_buffer_size, self.max_buffer_size)
    }

    /// Record total bytes transferred on a completed connection.
    ///
    /// Updates the per-proxy bytes EWMA. First sample seeds directly.
    /// Allocates only on first-seen proxy_id (DashMap insert).
    pub fn record_connection(&self, proxy_id: &str, total_bytes: u64) {
        if !self.buffer_enabled {
            return;
        }
        let entry = self
            .state
            .entry(proxy_id.to_string())
            .or_insert_with(ProxyBufferState::new);
        update_ewma(&entry.bytes_ewma, total_bytes, self.alpha_fp);
        entry.bytes_sample_count.fetch_add(1, Ordering::Relaxed);
    }

    // ── Jitter tracking (UDP real-time traffic) ──────────────────────────

    /// Record an inter-arrival jitter measurement for a UDP session.
    /// Jitter is |actual_interval - expected_interval| in microseconds.
    /// Used to adapt UDP buffers for real-time traffic (VoIP, gaming).
    #[allow(dead_code)] // Wired into UDP proxy path incrementally.
    pub fn record_jitter(&self, proxy_id: &str, jitter_us: u64) {
        if !self.buffer_enabled {
            return;
        }
        let entry = self
            .state
            .entry(proxy_id.to_string())
            .or_insert_with(ProxyBufferState::new);
        update_ewma(&entry.jitter_ewma, jitter_us, self.alpha_fp);
    }

    // ── Batch limit (UDP) ───────────────────────────────────────────────

    /// Returns the recommended batch limit for the next recv cycle on the given proxy.
    ///
    /// Hot path: one DashMap read + one atomic load + three comparisons.
    /// Returns `default_batch_limit` when disabled or no data.
    pub fn get_batch_limit(&self, proxy_id: &str) -> usize {
        if !self.batch_enabled {
            return self.default_batch_limit;
        }
        let ewma = match self.state.get(proxy_id) {
            Some(entry) => entry.dgram_ewma.load(Ordering::Relaxed),
            None => return self.default_batch_limit,
        };
        if ewma == UNSET {
            return self.default_batch_limit;
        }
        let tier = select_tier(ewma, &BATCH_TIER_THRESHOLDS);
        BATCH_TIER_LIMITS[tier]
    }

    /// Record datagrams drained in one batch cycle.
    ///
    /// Updates the per-proxy dgram EWMA. First sample seeds directly.
    pub fn record_batch_cycle(&self, proxy_id: &str, datagrams_drained: u64) {
        if !self.batch_enabled {
            return;
        }
        let entry = self
            .state
            .entry(proxy_id.to_string())
            .or_insert_with(ProxyBufferState::new);
        update_ewma(&entry.dgram_ewma, datagrams_drained, self.alpha_fp);
        entry.dgram_sample_count.fetch_add(1, Ordering::Relaxed);
    }

    // ── Maintenance ─────────────────────────────────────────────────────

    /// Remove state for proxies that no longer exist in the config.
    /// Called on config reload to prevent unbounded DashMap growth.
    pub fn prune_missing(&self, active_proxy_ids: &[&str]) {
        self.state
            .retain(|key, _| active_proxy_ids.contains(&key.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_tier_buffer() {
        assert_eq!(select_tier(0, &BUFFER_TIER_THRESHOLDS), 0);
        assert_eq!(select_tier(8 * 1024, &BUFFER_TIER_THRESHOLDS), 0);
        assert_eq!(select_tier(16 * 1024, &BUFFER_TIER_THRESHOLDS), 1);
        assert_eq!(select_tier(100 * 1024, &BUFFER_TIER_THRESHOLDS), 1);
        assert_eq!(select_tier(256 * 1024, &BUFFER_TIER_THRESHOLDS), 2);
        assert_eq!(select_tier(2 * 1024 * 1024, &BUFFER_TIER_THRESHOLDS), 2);
        assert_eq!(select_tier(4 * 1024 * 1024, &BUFFER_TIER_THRESHOLDS), 3);
        assert_eq!(select_tier(100 * 1024 * 1024, &BUFFER_TIER_THRESHOLDS), 3);
    }

    #[test]
    fn test_select_tier_batch() {
        assert_eq!(select_tier(0, &BATCH_TIER_THRESHOLDS), 0);
        assert_eq!(select_tier(9, &BATCH_TIER_THRESHOLDS), 0);
        assert_eq!(select_tier(10, &BATCH_TIER_THRESHOLDS), 1);
        assert_eq!(select_tier(99, &BATCH_TIER_THRESHOLDS), 1);
        assert_eq!(select_tier(100, &BATCH_TIER_THRESHOLDS), 2);
        assert_eq!(select_tier(999, &BATCH_TIER_THRESHOLDS), 2);
        assert_eq!(select_tier(1000, &BATCH_TIER_THRESHOLDS), 3);
        assert_eq!(select_tier(50000, &BATCH_TIER_THRESHOLDS), 3);
    }

    #[test]
    fn test_update_ewma_first_sample_seeds_directly() {
        let val = AtomicU64::new(UNSET);
        update_ewma(&val, 100_000, 300);
        assert_eq!(val.load(Ordering::Relaxed), 100_000);
    }

    #[test]
    fn test_update_ewma_subsequent_smoothing() {
        let val = AtomicU64::new(100_000);
        update_ewma(&val, 200_000, 300);
        assert_eq!(val.load(Ordering::Relaxed), 130_000);
    }

    #[test]
    fn constructor_clamps_config_mutations_to_safe_bounds() {
        let low = AdaptiveBufferTracker::new(true, true, 0, 1, 512, 64, 0);
        assert_eq!(low.alpha_fp, 1);
        assert_eq!(low.min_buffer_size, 1024);
        assert_eq!(low.max_buffer_size, 1024);
        assert_eq!(low.default_buffer_size, 1024);
        assert_eq!(low.default_batch_limit, 1);

        let high = AdaptiveBufferTracker::new(
            true,
            true,
            1000,
            2 * 1024 * 1024,
            3 * 1024 * 1024,
            4 * 1024 * 1024,
            256,
        );
        assert_eq!(high.alpha_fp, 999);
        assert_eq!(high.min_buffer_size, 1_048_576);
        assert_eq!(high.max_buffer_size, 1_048_576);
        assert_eq!(high.default_buffer_size, 1_048_576);
        assert_eq!(high.default_batch_limit, 256);

        let inverted = AdaptiveBufferTracker::new(true, true, 300, 65_536, 8192, 16_384, 64);
        assert_eq!(inverted.min_buffer_size, 8192);
        assert_eq!(inverted.max_buffer_size, 8192);
        assert_eq!(inverted.default_buffer_size, 8192);
    }

    #[test]
    fn get_buffer_size_uses_default_until_enabled_samples_exist() {
        let tracker = AdaptiveBufferTracker::new(true, true, 300, 8192, 262_144, 65_536, 64);

        assert_eq!(tracker.get_buffer_size("missing"), 65_536);
        tracker.record_batch_cycle("p1", 500);

        assert_eq!(tracker.get_buffer_size("p1"), 65_536);
        assert_eq!(tracker.get_batch_limit("p1"), 2000);
    }

    #[test]
    fn disabled_buffer_recording_keeps_default_and_does_not_allocate_state() {
        let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 64);

        tracker.record_connection("p1", 8 * 1024 * 1024);

        assert_eq!(tracker.get_buffer_size("p1"), 65_536);
        assert!(tracker.state.get("p1").is_none());
    }

    #[test]
    fn connection_samples_seed_then_smooth_into_buffer_tiers() {
        let tracker = AdaptiveBufferTracker::new(true, true, 500, 8192, 262_144, 65_536, 64);

        tracker.record_connection("p1", 1024);
        assert_eq!(tracker.get_buffer_size("p1"), 8192);

        tracker.record_connection("p1", 8 * 1024 * 1024);
        assert_eq!(tracker.get_buffer_size("p1"), 262_144);

        let state = tracker.state.get("p1").expect("proxy state should exist");
        assert_eq!(state.bytes_sample_count.load(Ordering::Relaxed), 2);
        assert_eq!(state.bytes_ewma.load(Ordering::Relaxed), 4_194_816);
    }

    #[test]
    fn buffer_selection_clamps_selected_tier_to_configured_bounds() {
        let min_limited = AdaptiveBufferTracker::new(true, true, 300, 65_536, 262_144, 65_536, 64);
        min_limited.record_connection("p1", 1024);
        assert_eq!(min_limited.get_buffer_size("p1"), 65_536);

        let max_limited = AdaptiveBufferTracker::new(true, true, 300, 8192, 32 * 1024, 8192, 64);
        max_limited.record_connection("p1", 8 * 1024 * 1024);
        assert_eq!(max_limited.get_buffer_size("p1"), 32 * 1024);
    }

    #[test]
    fn jitter_bumps_buffer_tier_when_above_threshold() {
        let tracker = AdaptiveBufferTracker::new(true, true, 300, 8192, 262_144, 65_536, 64);

        tracker.record_connection("p1", 32 * 1024);
        tracker.record_jitter("p1", JITTER_BUMP_THRESHOLD_US);
        assert_eq!(tracker.get_buffer_size("p1"), 32 * 1024);

        tracker.record_jitter("p1", JITTER_BUMP_THRESHOLD_US + 4);
        assert_eq!(tracker.get_buffer_size("p1"), 64 * 1024);
    }

    #[test]
    fn batch_limit_uses_defaults_when_disabled_or_unsampled() {
        let disabled = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 128);
        disabled.record_batch_cycle("p1", 10_000);

        assert_eq!(disabled.get_batch_limit("missing"), 128);
        assert_eq!(disabled.get_batch_limit("p1"), 128);
        assert!(disabled.state.get("p1").is_none());

        let unsampled = AdaptiveBufferTracker::new(true, true, 300, 8192, 262_144, 65_536, 128);
        unsampled.record_connection("p1", 8 * 1024);
        assert_eq!(unsampled.get_batch_limit("p1"), 128);
    }

    #[test]
    fn batch_samples_seed_then_smooth_into_limit_tiers() {
        let tracker = AdaptiveBufferTracker::new(true, true, 500, 8192, 262_144, 65_536, 64);

        tracker.record_batch_cycle("p1", 9);
        assert_eq!(tracker.get_batch_limit("p1"), 64);

        tracker.record_batch_cycle("p1", 191);
        assert_eq!(tracker.get_batch_limit("p1"), 2000);

        tracker.record_batch_cycle("p1", 5000);
        assert_eq!(tracker.get_batch_limit("p1"), 6000);

        let state = tracker.state.get("p1").expect("proxy state should exist");
        assert_eq!(state.dgram_sample_count.load(Ordering::Relaxed), 3);
        assert_eq!(state.dgram_ewma.load(Ordering::Relaxed), 2550);
    }

    #[test]
    fn prune_missing_removes_only_inactive_proxy_state() {
        let tracker = AdaptiveBufferTracker::new(true, true, 300, 8192, 262_144, 65_536, 64);

        tracker.record_connection("keep", 1024);
        tracker.record_batch_cycle("drop", 100);
        tracker.record_jitter("drop", 20_000);
        tracker.prune_missing(&["keep"]);

        assert!(tracker.state.get("keep").is_some());
        assert!(tracker.state.get("drop").is_none());
    }

    #[test]
    fn test_record_jitter_disabled() {
        let tracker = AdaptiveBufferTracker::new(false, false, 300, 8192, 262_144, 65_536, 64);
        tracker.record_jitter("p1", 15_000);
        assert!(tracker.state.get("p1").is_none());
    }
}

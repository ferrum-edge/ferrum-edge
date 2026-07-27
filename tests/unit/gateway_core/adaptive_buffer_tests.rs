use ferrum_edge::adaptive_buffer::AdaptiveBufferTracker;

/// Default namespace used by the single-tenant cases below. Cross-namespace
/// isolation is covered separately at the end of this file.
const NS: &str = "ferrum";

// ── Buffer size tests ───────────────────────────────────────────────────────

#[test]
fn test_default_buffer_when_disabled() {
    let tracker = AdaptiveBufferTracker::new(
        false, // buffer disabled
        false, 300, 8192, 262_144, 65_536, 6000,
    );
    // Should always return default regardless of recordings.
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 65_536);
    tracker.record_connection(NS, "proxy-1", 10_000_000);
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 65_536);
}

#[test]
fn test_default_buffer_when_no_data() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    // No connections recorded → default.
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 65_536);
}

#[test]
fn test_tier0_small_connections() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    // Record small connections (~4 KiB each).
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 4 * 1024);
    }
    // EWMA should settle near 4 KiB → Tier 0 (8 KiB buffer).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 8 * 1024);
}

#[test]
fn test_tier1_medium_connections() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 64 * 1024);
    }
    // EWMA near 64 KiB → Tier 1 (32 KiB buffer).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 32 * 1024);
}

#[test]
fn test_tier2_large_connections() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 1024 * 1024);
    }
    // EWMA near 1 MiB → Tier 2 (64 KiB buffer).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 64 * 1024);
}

#[test]
fn test_tier3_bulk_connections() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 10 * 1024 * 1024);
    }
    // EWMA near 10 MiB → Tier 3 (256 KiB buffer).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 256 * 1024);
}

#[test]
fn test_ewma_smoothing_does_not_jump() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    // Record 10 small connections to stabilize EWMA at ~4 KiB.
    for _ in 0..10 {
        tracker.record_connection(NS, "proxy-1", 4 * 1024);
    }
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 8 * 1024); // Tier 0

    // Single large burst should NOT immediately jump to Tier 3.
    // α=0.3: new_ewma = 0.3 * 10MB + 0.7 * ~4KB ≈ 3 MiB → Tier 2, not Tier 3.
    tracker.record_connection(NS, "proxy-1", 10 * 1024 * 1024);
    let buf = tracker.get_buffer_size(NS, "proxy-1");
    // Should be Tier 2 (64 KiB), not Tier 3 (256 KiB) after one spike.
    assert_eq!(buf, 64 * 1024);
}

#[test]
fn test_min_max_clamping() {
    let tracker = AdaptiveBufferTracker::new(
        true,
        false,
        300,
        32 * 1024, // min = 32 KiB
        64 * 1024, // max = 64 KiB
        64 * 1024,
        6000,
    );
    // Record tiny connections → Tier 0 would be 8 KiB, but min clamps to 32 KiB.
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 1024);
    }
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 32 * 1024);

    // Record huge connections → Tier 3 would be 256 KiB, but max clamps to 64 KiB.
    let tracker2 =
        AdaptiveBufferTracker::new(true, false, 300, 32 * 1024, 64 * 1024, 64 * 1024, 6000);
    for _ in 0..5 {
        tracker2.record_connection(NS, "proxy-1", 50 * 1024 * 1024);
    }
    assert_eq!(tracker2.get_buffer_size(NS, "proxy-1"), 64 * 1024);
}

#[test]
fn test_first_sample_seeds_directly() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    // One connection at exactly 100 KiB → EWMA should be 100 KiB (no smoothing).
    tracker.record_connection(NS, "proxy-1", 100 * 1024);
    // 100 KiB is in [16 KiB, 256 KiB) → Tier 1 (32 KiB buffer).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 32 * 1024);
}

#[test]
fn test_prune_missing() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    tracker.record_connection(NS, "proxy-a", 1024);
    tracker.record_connection(NS, "proxy-b", 1024);
    tracker.record_connection(NS, "proxy-c", 1024);

    // Prune: only proxy-a and proxy-c remain.
    tracker.prune_missing(&[(NS, "proxy-a"), (NS, "proxy-c")]);

    // proxy-b should return default (entry removed).
    assert_eq!(tracker.get_buffer_size(NS, "proxy-b"), 65_536);
    // proxy-a and proxy-c should still have data.
    assert_ne!(tracker.get_buffer_size(NS, "proxy-a"), 65_536);
    assert_ne!(tracker.get_buffer_size(NS, "proxy-c"), 65_536);
}

#[test]
fn test_independent_proxy_state() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);
    // proxy-1 gets small traffic, proxy-2 gets large traffic.
    for _ in 0..5 {
        tracker.record_connection(NS, "proxy-1", 2 * 1024);
        tracker.record_connection(NS, "proxy-2", 10 * 1024 * 1024);
    }
    assert_eq!(tracker.get_buffer_size(NS, "proxy-1"), 8 * 1024); // Tier 0
    assert_eq!(tracker.get_buffer_size(NS, "proxy-2"), 256 * 1024); // Tier 3
}

// ── Batch limit tests ───────────────────────────────────────────────────────

#[test]
fn test_default_batch_when_disabled() {
    let tracker = AdaptiveBufferTracker::new(false, false, 300, 8192, 262_144, 65_536, 6000);
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 6000);
    tracker.record_batch_cycle(NS, "proxy-1", 5000);
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 6000);
}

#[test]
fn test_default_batch_when_no_data() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 6000);
}

#[test]
fn test_batch_tier0_quiet() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_batch_cycle(NS, "proxy-1", 3);
    }
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 64);
}

#[test]
fn test_batch_tier1_moderate() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_batch_cycle(NS, "proxy-1", 50);
    }
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 256);
}

#[test]
fn test_batch_tier2_active() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_batch_cycle(NS, "proxy-1", 500);
    }
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 2000);
}

#[test]
fn test_batch_tier3_burst() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);
    for _ in 0..5 {
        tracker.record_batch_cycle(NS, "proxy-1", 5000);
    }
    assert_eq!(tracker.get_batch_limit(NS, "proxy-1"), 6000);
}

// ── Jitter-based tier bumping ───────────────────────────────────────────────

#[test]
fn test_jitter_bumps_buffer_tier() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 64);
    tracker.record_connection(NS, "p1", 4096);
    assert_eq!(tracker.get_buffer_size(NS, "p1"), 8192);

    tracker.record_jitter(NS, "p1", 15_000);
    assert_eq!(tracker.get_buffer_size(NS, "p1"), 32 * 1024);
}

#[test]
fn test_jitter_no_bump_when_low() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 64);
    tracker.record_connection(NS, "p1", 4096);
    tracker.record_jitter(NS, "p1", 5_000);
    assert_eq!(tracker.get_buffer_size(NS, "p1"), 8192);
}

#[test]
fn test_jitter_no_bump_beyond_max_tier() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 1_048_576, 65_536, 64);
    tracker.record_connection(NS, "p1", 10 * 1024 * 1024);
    let size_before = tracker.get_buffer_size(NS, "p1");
    tracker.record_jitter(NS, "p1", 50_000);
    assert_eq!(tracker.get_buffer_size(NS, "p1"), size_before);
}

// ── Concurrency ────────────────────────────────────────────────────────────

#[test]
fn test_concurrent_recording() {
    use std::sync::Arc;
    let tracker = Arc::new(AdaptiveBufferTracker::new(
        true, true, 300, 8192, 262_144, 65_536, 6000,
    ));

    let mut handles = Vec::new();
    for i in 0..8 {
        let t = tracker.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                t.record_connection(NS, "proxy-1", (i + 1) * 10_000);
                t.record_batch_cycle(NS, "proxy-1", (i + 1) * 100);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Should not panic and should return a valid buffer size.
    let buf = tracker.get_buffer_size(NS, "proxy-1");
    assert!((8 * 1024..=256 * 1024).contains(&buf));
    let batch = tracker.get_batch_limit(NS, "proxy-1");
    assert!((64..=6000).contains(&batch));
}

// ── Namespace isolation ────────────────────────────────────────────────────
//
// Adaptive state is owned by the `(namespace, id)` pair. Two tenants that reuse
// the same proxy id must never observe each other's traffic profile, and
// pruning one tenant's proxy must leave the other's state intact.

const NS_A: &str = "team-a";
const NS_B: &str = "team-b";
const SHARED_ID: &str = "shared-proxy";

#[test]
fn same_proxy_id_in_two_namespaces_keeps_independent_buffer_state() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);

    // team-a sees tiny connections, team-b sees bulk transfers.
    for _ in 0..5 {
        tracker.record_connection(NS_A, SHARED_ID, 2 * 1024);
        tracker.record_connection(NS_B, SHARED_ID, 10 * 1024 * 1024);
    }

    assert_eq!(tracker.get_buffer_size(NS_A, SHARED_ID), 8 * 1024);
    assert_eq!(tracker.get_buffer_size(NS_B, SHARED_ID), 256 * 1024);
    // A third namespace reusing the id starts from the configured default.
    assert_eq!(tracker.get_buffer_size("team-c", SHARED_ID), 65_536);
}

#[test]
fn same_proxy_id_in_two_namespaces_keeps_independent_batch_state() {
    let tracker = AdaptiveBufferTracker::new(false, true, 300, 8192, 262_144, 65_536, 6000);

    for _ in 0..5 {
        tracker.record_batch_cycle(NS_A, SHARED_ID, 3);
        tracker.record_batch_cycle(NS_B, SHARED_ID, 5000);
    }

    assert_eq!(tracker.get_batch_limit(NS_A, SHARED_ID), 64);
    assert_eq!(tracker.get_batch_limit(NS_B, SHARED_ID), 6000);
    assert_eq!(tracker.get_batch_limit("team-c", SHARED_ID), 6000);
}

#[test]
fn jitter_bump_does_not_leak_across_namespaces() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 64);

    tracker.record_connection(NS_A, SHARED_ID, 4096);
    tracker.record_connection(NS_B, SHARED_ID, 4096);
    // Only team-b's traffic is jittery.
    tracker.record_jitter(NS_B, SHARED_ID, 15_000);

    assert_eq!(tracker.get_buffer_size(NS_A, SHARED_ID), 8192);
    assert_eq!(tracker.get_buffer_size(NS_B, SHARED_ID), 32 * 1024);
}

#[test]
fn prune_missing_removes_only_the_named_namespace_proxy() {
    let tracker = AdaptiveBufferTracker::new(true, true, 300, 8192, 262_144, 65_536, 6000);

    for _ in 0..5 {
        tracker.record_connection(NS_A, SHARED_ID, 2 * 1024);
        tracker.record_connection(NS_B, SHARED_ID, 10 * 1024 * 1024);
    }
    tracker.record_batch_cycle(NS_B, SHARED_ID, 5000);

    // team-a deletes its proxy; team-b still owns an identically-named one.
    tracker.prune_missing(&[(NS_B, SHARED_ID)]);

    assert_eq!(tracker.get_buffer_size(NS_A, SHARED_ID), 65_536);
    assert_eq!(tracker.get_buffer_size(NS_B, SHARED_ID), 256 * 1024);
    assert_eq!(tracker.get_batch_limit(NS_B, SHARED_ID), 6000);
}

#[test]
fn prune_missing_matches_full_namespace_and_id_not_a_prefix() {
    let tracker = AdaptiveBufferTracker::new(true, false, 300, 8192, 262_144, 65_536, 6000);

    // `team|a-proxy` and `team-a|proxy` must not be confusable through the
    // `namespace|id` runtime key.
    tracker.record_connection("team", "a-proxy", 10 * 1024 * 1024);
    tracker.record_connection("team-a", "proxy", 10 * 1024 * 1024);

    tracker.prune_missing(&[("team-a", "proxy")]);

    assert_eq!(tracker.get_buffer_size("team", "a-proxy"), 65_536);
    assert_eq!(tracker.get_buffer_size("team-a", "proxy"), 256 * 1024);
}

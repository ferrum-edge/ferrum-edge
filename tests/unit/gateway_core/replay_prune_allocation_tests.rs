//! Allocation regression for the process replay authority shared by HMAC and
//! DPoP. Reuse this target's thread-local allocator counter so sibling tests
//! cannot affect the measured prune window.

use std::time::Duration;

use ferrum_edge::plugins::utils::replay_authority::{
    ReplayAdmission, ReplayAuthority, ReplayDomain, process_lane,
};

use super::response_coalescing_allocation_tests::measure;

#[test]
fn replay_prune_allocates_nothing_for_small_and_mass_expirations() {
    let short_retention = Duration::from_millis(100);
    let live_retention = Duration::from_secs(60);
    for (policy, expired_count) in [("small", 3usize), ("mass", 4_096usize)] {
        let domain = ReplayDomain::new(
            "replay-prune-allocation-v1",
            "ferrum",
            "replay_prune_allocation_tests",
            policy,
            "0",
        );
        let cap = expired_count + 1;
        let authority = ReplayAuthority::process("test", &domain, cap, short_retention, 8).unwrap();
        let lane = process_lane(&authority).unwrap();
        // One principal per marker isolates the lane-wide reclamation bound
        // from the per-principal quota. All expire at exactly the same instant.
        for index in 0..expired_count {
            let marker = domain.marker(&[&index.to_le_bytes()]);
            assert_eq!(
                lane.admit_at(&marker, short_retention, cap, 0),
                ReplayAdmission::Admitted
            );
        }
        let live = domain.marker(&[b"live"]);
        assert_eq!(
            lane.admit_at(&live, live_retention, cap, 0),
            ReplayAdmission::Admitted
        );
        assert_eq!(lane.retained_entries(), cap);
        assert_eq!(lane.indexed_markers_for_tests(), cap);

        // The old implementation grew a Vec containing every due digest.
        // Measure only pruning: setup, marker hashing and assertions stay out.
        let ((allocations, bytes), reclaimed) =
            measure(|| lane.prune_expired_with_after_scan_for_tests(100, || {}));
        assert_eq!(reclaimed, expired_count);
        assert_eq!(allocations, 0, "{policy} prune must not allocate");
        assert_eq!(bytes, 0, "{policy} prune must reserve no heap bytes");
        assert_eq!(
            lane.prune_entries_examined_for_tests(),
            expired_count as u64
        );
        assert_eq!(lane.retained_entries(), 1);
        assert_eq!(lane.indexed_markers_for_tests(), 1);
        assert_eq!(lane.earliest_expiry_millis_for_tests(), 60_000);
        assert_eq!(
            lane.principal_entries_for_tests(&domain.marker(&[&0usize.to_le_bytes()])),
            0
        );
        assert_eq!(lane.principal_entries_for_tests(&live), 1);
        assert_eq!(
            lane.admit_at(&live, live_retention, cap, 100),
            ReplayAdmission::Replay,
            "reclamation must preserve the live claim"
        );
    }
}

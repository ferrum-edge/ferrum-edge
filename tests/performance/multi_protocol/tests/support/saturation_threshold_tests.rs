//! Boundary coverage for the saturation peak-alive gate (issue #6518).
//!
//! The documented verdict requires `peak_alive_connections >= 99% x N`.
//! The previous float comparison truncated the fractional threshold, so
//! counts on both sides of the fractional boundary are pinned here along
//! with the default (multiple-of-100) levels.

use super::peak_meets_threshold;

#[test]
fn fractional_boundary_rounds_up_not_down() {
    // 99% of 101 is 99.99, so a peak of 99 (~98.02%) must not pass and
    // the smallest passing integer peak is 100.
    assert!(!peak_meets_threshold(99, 101));
    assert!(peak_meets_threshold(100, 101));
    assert!(peak_meets_threshold(101, 101));
    // 99% of 201 is 198.99: 198 fails, 199 passes.
    assert!(!peak_meets_threshold(198, 201));
    assert!(peak_meets_threshold(199, 201));
}

#[test]
fn multiples_of_one_hundred_keep_the_exact_threshold() {
    assert!(!peak_meets_threshold(98, 100));
    assert!(peak_meets_threshold(99, 100));
    assert!(!peak_meets_threshold(9_899, 10_000));
    assert!(peak_meets_threshold(9_900, 10_000));
}

#[test]
fn degenerate_and_extreme_counts_do_not_overflow() {
    assert!(!peak_meets_threshold(0, 1));
    assert!(peak_meets_threshold(1, 1));
    assert!(peak_meets_threshold(0, 0));
    assert!(peak_meets_threshold(u64::MAX, u64::MAX));
    assert!(!peak_meets_threshold(u64::MAX / 2, u64::MAX));
}

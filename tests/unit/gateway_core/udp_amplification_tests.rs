//! Cumulative UDP amplification budget and charge accounting (#3836).

use ferrum_edge::udp_amplification::{
    MAX_UDP_AMPLIFICATION_FACTOR, UDP_AMPLIFICATION_BUDGET_CAP_MULTIPLE, charge_response_budget,
    factor_is_valid, publish_request_budget, udp_amplification_response_budget,
};
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn zero_length_request_receives_one_byte_allowance() {
    assert_eq!(udp_amplification_response_budget(0, 8.0), 1);
}

#[test]
fn nonempty_request_keeps_exact_ratio() {
    assert_eq!(udp_amplification_response_budget(100, 8.0), 800);
    assert_eq!(udp_amplification_response_budget(1, 8.0), 8);
}

#[test]
fn invalid_factors_fail_closed_to_zero_budget() {
    assert_eq!(udp_amplification_response_budget(100, f32::NAN), 0);
    assert_eq!(udp_amplification_response_budget(100, f32::INFINITY), 0);
    assert_eq!(udp_amplification_response_budget(100, -1.0), 0);
    assert_eq!(udp_amplification_response_budget(100, 0.0), 0);
    assert_eq!(
        udp_amplification_response_budget(100, MAX_UDP_AMPLIFICATION_FACTOR + 1.0),
        0
    );
}

#[test]
fn factor_admission_rejects_non_finite_zero_and_excessive() {
    assert!(factor_is_valid(8.0));
    assert!(factor_is_valid(MAX_UDP_AMPLIFICATION_FACTOR));
    assert!(!factor_is_valid(0.0));
    assert!(!factor_is_valid(-0.1));
    assert!(!factor_is_valid(f32::NAN));
    assert!(!factor_is_valid(f32::INFINITY));
    assert!(!factor_is_valid(MAX_UDP_AMPLIFICATION_FACTOR + 1.0));
}

#[test]
fn charge_admits_until_remaining_is_exhausted() {
    let remaining = AtomicU64::new(800);
    assert!(charge_response_budget(&remaining, 300));
    assert!(charge_response_budget(&remaining, 300));
    assert!(!charge_response_budget(&remaining, 300));
    assert_eq!(remaining.load(Ordering::Acquire), 200);
}

#[test]
fn oversize_datagram_does_not_partially_consume_budget() {
    let remaining = AtomicU64::new(100);
    assert!(!charge_response_budget(&remaining, 101));
    assert_eq!(remaining.load(Ordering::Acquire), 100);
    assert!(charge_response_budget(&remaining, 100));
    assert_eq!(remaining.load(Ordering::Acquire), 0);
}

#[test]
fn finite_budget_admits_only_a_finite_number_of_zero_length_responses() {
    let remaining = AtomicU64::new(3);
    assert!(charge_response_budget(&remaining, 0));
    assert!(charge_response_budget(&remaining, 0));
    assert!(charge_response_budget(&remaining, 0));
    assert!(!charge_response_budget(&remaining, 0));
    assert_eq!(remaining.load(Ordering::Acquire), 0);
}

#[test]
fn zero_remaining_budget_refuses_a_zero_length_response() {
    let remaining = AtomicU64::new(0);
    assert!(!charge_response_budget(&remaining, 0));
    assert_eq!(remaining.load(Ordering::Acquire), 0);
}

#[test]
fn zero_length_request_allowance_admits_one_empty_response() {
    let remaining = AtomicU64::new(udp_amplification_response_budget(0, 8.0));
    assert_eq!(remaining.load(Ordering::Acquire), 1);
    assert!(charge_response_budget(&remaining, 0));
    assert!(!charge_response_budget(&remaining, 0));
    assert_eq!(remaining.load(Ordering::Acquire), 0);
}

#[test]
fn nonempty_response_still_charges_exact_payload_bytes() {
    let remaining = AtomicU64::new(10);
    assert!(charge_response_budget(&remaining, 4));
    assert_eq!(remaining.load(Ordering::Acquire), 6);
    assert!(charge_response_budget(&remaining, 6));
    assert_eq!(remaining.load(Ordering::Acquire), 0);
}

// ---- issue #4771: per-request budget accrual instead of reset ----

#[test]
fn publish_accrues_budget_instead_of_resetting_it() {
    let remaining = AtomicU64::new(0);
    publish_request_budget(&remaining, 200, 8.0); // +1600
    publish_request_budget(&remaining, 20, 8.0); // +160
    assert_eq!(remaining.load(Ordering::Acquire), 1760);
}

#[test]
fn two_pipelined_requests_deliver_both_replies() {
    let remaining = AtomicU64::new(0);
    publish_request_budget(&remaining, 200, 8.0);
    publish_request_budget(&remaining, 20, 8.0);
    // The 1200-byte answer to the 200-byte request must survive the later,
    // smaller request's publish.
    assert!(charge_response_budget(&remaining, 1200));
    assert!(charge_response_budget(&remaining, 20));
}

#[test]
fn a_single_request_cannot_exceed_factor_times_size() {
    let remaining = AtomicU64::new(0);
    publish_request_budget(&remaining, 100, 8.0);
    assert!(charge_response_budget(&remaining, 800));
    assert!(!charge_response_budget(&remaining, 1));
}

#[test]
fn exhausted_exchanges_do_not_subsidize_a_later_over_budget_reply() {
    let remaining = AtomicU64::new(0);
    for _ in 0..32 {
        publish_request_budget(&remaining, 200, 8.0);
        assert!(charge_response_budget(&remaining, 1600));
        assert_eq!(remaining.load(Ordering::Acquire), 0);
    }

    assert_eq!(publish_request_budget(&remaining, 100, 8.0), 800);
    assert!(!charge_response_budget(&remaining, 900));
    assert!(charge_response_budget(&remaining, 300));
    assert!(charge_response_budget(&remaining, 300));
    assert!(!charge_response_budget(&remaining, 300));
}

#[test]
fn accrual_is_capped_at_a_fixed_multiple_of_the_per_request_budget() {
    let remaining = AtomicU64::new(0);
    for _ in 0..100_000 {
        publish_request_budget(&remaining, 100, 8.0);
    }
    let budget = udp_amplification_response_budget(100, 8.0);
    assert_eq!(
        remaining.load(Ordering::Acquire),
        budget * UDP_AMPLIFICATION_BUDGET_CAP_MULTIPLE
    );
}

#[test]
fn a_smaller_followup_request_does_not_clamp_away_inflight_credit() {
    let remaining = AtomicU64::new(0);
    publish_request_budget(&remaining, 8000, 8.0); // 64000
    publish_request_budget(&remaining, 1, 8.0); // budget 8, cap 128 (< 64000)
    assert_eq!(remaining.load(Ordering::Acquire), 64000);
    assert!(charge_response_budget(&remaining, 64000));
}

#[test]
fn a_zero_length_keepalive_does_not_kill_a_pending_answer() {
    let remaining = AtomicU64::new(0);
    publish_request_budget(&remaining, 200, 8.0); // +1600
    publish_request_budget(&remaining, 0, 8.0); // +1, must not reset or clamp
    assert!(charge_response_budget(&remaining, 1200));
}

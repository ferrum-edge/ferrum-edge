//! HTTP/3 frontend QUIC source-address validation admission.
//!
//! A handshake for an unvalidated source runs only inside the listener's
//! dedicated budget; past it the Initial gets a stateless Retry (or is refused
//! when a Retry is not permitted). A validated source never consumes the
//! budget.

use std::sync::Arc;

use ferrum_edge::http3::address_validation::{
    IncomingAdmission, UnvalidatedHandshakeBudget, classify_incoming,
};

#[test]
fn validated_sources_bypass_the_handshake_budget() {
    let budget = UnvalidatedHandshakeBudget::new(0);

    for may_retry in [true, false] {
        assert!(matches!(
            classify_incoming(true, may_retry, &budget),
            IncomingAdmission::Validated
        ));
    }
    assert_eq!(budget.in_flight(), 0);
}

#[test]
fn zero_budget_retries_every_unvalidated_source() {
    let budget = UnvalidatedHandshakeBudget::new(0);

    assert!(matches!(
        classify_incoming(false, true, &budget),
        IncomingAdmission::Retry
    ));
    assert_eq!(budget.in_flight(), 0);
}

#[test]
fn unvalidated_sources_are_admitted_until_the_budget_is_exhausted() {
    let budget = UnvalidatedHandshakeBudget::new(2);

    let first = classify_incoming(false, true, &budget);
    let second = classify_incoming(false, true, &budget);
    assert!(matches!(first, IncomingAdmission::Unvalidated(_)));
    assert!(matches!(second, IncomingAdmission::Unvalidated(_)));
    assert_eq!(budget.in_flight(), 2);

    // Past the budget: a stateless Retry, with no permit taken.
    assert!(matches!(
        classify_incoming(false, true, &budget),
        IncomingAdmission::Retry
    ));
    assert_eq!(budget.in_flight(), 2);

    // A permit is released when its handshake ends, reopening one slot.
    drop(first);
    assert_eq!(budget.in_flight(), 1);
    let third = classify_incoming(false, true, &budget);
    assert!(matches!(third, IncomingAdmission::Unvalidated(_)));
    assert_eq!(budget.in_flight(), 2);

    drop(second);
    drop(third);
    assert_eq!(budget.in_flight(), 0);
}

/// An Initial that already followed a Retry may not be retried again; over
/// budget it is refused rather than run outside the budget.
#[test]
fn over_budget_source_that_cannot_be_retried_is_refused() {
    let budget = UnvalidatedHandshakeBudget::new(0);

    assert!(matches!(
        classify_incoming(false, false, &budget),
        IncomingAdmission::Refuse
    ));
    assert_eq!(budget.in_flight(), 0);
}

#[test]
fn budget_never_exceeds_its_limit_under_concurrent_acquisition() {
    const LIMIT: usize = 8;
    const THREADS: usize = 32;

    let budget = UnvalidatedHandshakeBudget::new(LIMIT);
    let barrier = Arc::new(std::sync::Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let budget = Arc::clone(&budget);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                budget.try_acquire()
            })
        })
        .collect();
    let permits: Vec<_> = handles
        .into_iter()
        .filter_map(|handle| handle.join().expect("acquire thread"))
        .collect();

    assert_eq!(permits.len(), LIMIT);
    assert_eq!(budget.in_flight(), LIMIT);
    assert_eq!(budget.limit(), LIMIT);
    drop(permits);
    assert_eq!(budget.in_flight(), 0);
}

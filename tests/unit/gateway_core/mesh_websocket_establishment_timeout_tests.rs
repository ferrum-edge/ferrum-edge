//! Ambient HBONE WebSocket establishment timeout contract (issue #3620).
//!
//! One absolute connect budget covers byte-tunnel acquisition and the inner
//! H1 101 wait. The race is expiration-first: an already-elapsed deadline
//! and an exact timer/result tie must not accept a ready success.

use ferrum_edge::_test_support::await_deadline_first_for_test;
use std::time::Duration;

/// An already-elapsed deadline must expire even when the inner future is
/// immediately ready. `timeout_at` would accept that success.
#[tokio::test(start_paused = true)]
async fn elapsed_deadline_rejects_immediately_ready_success() {
    let deadline = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_millis(1)).await;
    let outcome =
        await_deadline_first_for_test(Some(deadline), std::future::ready("success")).await;
    assert_eq!(
        outcome,
        Err(()),
        "an already-elapsed deadline must not accept a ready success"
    );
}

/// When the timer and an immediately-ready result become ready together,
/// the deadline arm wins.
#[tokio::test(start_paused = true)]
async fn exact_tie_expires_rather_than_accepting_success() {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    tokio::time::advance(Duration::from_millis(10)).await;
    let outcome =
        await_deadline_first_for_test(Some(deadline), std::future::ready("success")).await;
    assert_eq!(
        outcome,
        Err(()),
        "an exact timer/result tie must expire, not accept the ready success"
    );
}

/// A live budget accepts an immediately-ready success.
#[tokio::test(start_paused = true)]
async fn live_budget_accepts_immediately_ready_success() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let outcome =
        await_deadline_first_for_test(Some(deadline), std::future::ready("success")).await;
    assert_eq!(
        outcome,
        Ok("success"),
        "a live budget must accept an immediately-ready success"
    );
}

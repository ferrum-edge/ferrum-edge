use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use ferrum_edge::_test_support::{
    websocket_deadline_plan, websocket_stop_reason_for_test,
    websocket_stop_reason_with_overload_for_test,
};
use ferrum_edge::overload::OverloadState;

#[test]
fn credential_deadline_wins_when_earlier_than_maximum_lifetime() {
    let (remaining, reason) =
        websocket_deadline_plan(Duration::from_secs(60), Some(Duration::from_secs(15)));
    assert_eq!(remaining, Duration::from_secs(15));
    assert_eq!(reason, "credential_expired");
}

#[test]
fn maximum_lifetime_bounds_credentials_without_authoritative_expiry() {
    let (remaining, reason) = websocket_deadline_plan(Duration::from_secs(30), None);
    assert_eq!(remaining, Duration::from_secs(30));
    assert_eq!(reason, "max_lifetime");
}

#[test]
fn maximum_lifetime_wins_when_credential_expires_later() {
    let (remaining, reason) =
        websocket_deadline_plan(Duration::from_secs(20), Some(Duration::from_secs(90)));
    assert_eq!(remaining, Duration::from_secs(20));
    assert_eq!(reason, "max_lifetime");
}

#[test]
fn exact_deadline_tie_fails_closed_as_credential_expiry() {
    let (remaining, reason) =
        websocket_deadline_plan(Duration::from_secs(10), Some(Duration::from_secs(10)));
    assert_eq!(remaining, Duration::from_secs(10));
    assert_eq!(reason, "credential_expired");
}

#[tokio::test(start_paused = true)]
async fn active_scheduler_progress_does_not_extend_absolute_credential_deadline() {
    let stop = tokio::spawn(websocket_stop_reason_for_test(
        Duration::from_secs(10),
        true,
        false,
        false,
    ));

    for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
    }

    assert_eq!(
        stop.await.expect("deadline waiter panicked"),
        "credential_expired"
    );
}

#[tokio::test]
async fn listener_shutdown_wins_before_a_later_session_deadline() {
    let reason = websocket_stop_reason_for_test(Duration::from_secs(60), false, true, false).await;
    assert_eq!(reason, "drain");
}

#[tokio::test]
async fn overload_drain_wins_before_a_later_session_deadline() {
    let reason = websocket_stop_reason_for_test(Duration::from_secs(60), false, false, true).await;
    assert_eq!(reason, "drain");
}

#[tokio::test(start_paused = true)]
async fn begin_drain_wakes_all_registered_waiters_without_advancing_a_poll_timer() {
    let overload = Arc::new(OverloadState::new());
    let started_at = tokio::time::Instant::now();
    let mut first_stop = Box::pin(websocket_stop_reason_with_overload_for_test(
        Duration::from_secs(60),
        Arc::clone(&overload),
    ));
    let mut second_stop = Box::pin(websocket_stop_reason_with_overload_for_test(
        Duration::from_secs(60),
        Arc::clone(&overload),
    ));

    assert!(matches!(
        futures_util::poll!(&mut first_stop),
        Poll::Pending
    ));
    assert!(matches!(
        futures_util::poll!(&mut second_stop),
        Poll::Pending
    ));
    ferrum_edge::overload::begin_drain(&overload);

    assert_eq!(first_stop.await, "drain");
    assert_eq!(second_stop.await, "drain");
    assert_eq!(
        tokio::time::Instant::now(),
        started_at,
        "drain wake must be event-driven rather than waiting for a timer tick"
    );
}

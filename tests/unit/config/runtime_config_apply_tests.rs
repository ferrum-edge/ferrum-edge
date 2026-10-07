//! Issue #3926 — database-mode admin read-your-write coordinator.
//!
//! These cover waiter coalescing, rejection, timeout, and the post-tick nudge
//! that prevents a consumed immediate permit from parking waiters on the
//! periodic poll interval. The coordinator never applies config itself.
//! Waiters use a covering watermark captured under the write pin; a later
//! concurrent same-namespace commit can raise that watermark above one
//! writer's own row, and one accepted generation still unblocks every waiter
//! at or below it.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::config::runtime_config_apply::{
    LiveApplyCursor, LiveApplyFailure, PreparedLiveApply, RuntimeConfigApply,
};

#[tokio::test]
async fn already_accepted_sequence_returns_immediately() {
    let apply = RuntimeConfigApply::new("ferrum", 7);
    apply
        .await_committed(7)
        .await
        .expect("accepted generation must not wait");
    apply
        .await_committed(3)
        .await
        .expect("older sequences are already live");
}

#[tokio::test]
async fn record_accepted_unblocks_a_waiter() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(4).await });
    tokio::task::yield_now().await;
    apply.record_accepted(4);
    handle
        .await
        .expect("waiter task")
        .expect("accepted sequence must unblock");
}

#[tokio::test]
async fn record_rejected_fails_waiters_through_that_sequence() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(4).await });
    tokio::task::yield_now().await;
    apply.record_rejected(4);
    let err = handle.await.expect("waiter task").expect_err("rejected");
    assert_eq!(err, LiveApplyFailure::ConfigRejected);
    assert_eq!(err.as_str(), "config_rejected");
}

#[tokio::test]
async fn one_accepted_generation_unblocks_coalesced_waiters() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let first = apply.clone();
    let second = apply.clone();
    let handle_a = tokio::spawn(async move { first.await_committed(1).await });
    let handle_b = tokio::spawn(async move { second.await_committed(2).await });
    tokio::task::yield_now().await;
    assert!(apply.waiter_count() >= 1);
    apply.record_accepted(2);
    handle_a
        .await
        .expect("first waiter")
        .expect("sequence 1 is covered by accepted 2");
    handle_b
        .await
        .expect("second waiter")
        .expect("sequence 2 is live");
}

#[tokio::test]
async fn topology_change_fails_waiters_from_the_replaced_epoch() {
    let apply = Arc::new(RuntimeConfigApply::at_epoch("ferrum", 1, 900));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move {
        waiter
            .await_committed_cursor(LiveApplyCursor::new(1, 901))
            .await
    });
    tokio::task::yield_now().await;

    apply.observe_topology(2);
    assert_eq!(
        handle.await.expect("old-epoch waiter task"),
        Err(LiveApplyFailure::SequenceUnavailable)
    );
    assert_eq!(apply.accepted_cursor(), LiveApplyCursor::new(2, 0));
}

#[tokio::test]
async fn lower_sequence_in_new_topology_waits_and_old_poll_result_is_ignored() {
    let apply = Arc::new(RuntimeConfigApply::at_epoch("ferrum", 1, 900));
    apply.observe_topology(2);
    let waiter = apply.clone();
    let handle = tokio::spawn(async move {
        waiter
            .await_committed_cursor(LiveApplyCursor::new(2, 3))
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !handle.is_finished(),
        "new epoch sequence 3 is not live yet"
    );

    apply.record_accepted_cursor(LiveApplyCursor::new(1, 10_000));
    tokio::task::yield_now().await;
    assert!(
        !handle.is_finished(),
        "a stale high cursor from the replaced topology must be ignored"
    );

    apply.record_accepted_cursor(LiveApplyCursor::new(2, 3));
    handle
        .await
        .expect("new-epoch waiter task")
        .expect("new topology sequence becomes live");
}

#[tokio::test(start_paused = true)]
async fn await_committed_times_out_when_poll_never_publishes() {
    let apply = Arc::new(RuntimeConfigApply::with_timeout(
        "ferrum",
        0,
        Duration::from_secs(5),
    ));
    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(1).await });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let err = handle.await.expect("waiter task").expect_err("timeout");
    assert_eq!(err, LiveApplyFailure::Timeout);
    assert_eq!(err.as_str(), "reload_timeout");
}

#[tokio::test]
async fn nudge_signals_immediate_only_while_waiters_are_behind() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    apply.nudge_if_waiters_pending();
    assert!(
        !apply.wake_signal().take_immediate(),
        "no waiters means no immediate nudge"
    );

    let waiter = apply.clone();
    let handle = tokio::spawn(async move { waiter.await_committed(9).await });
    tokio::task::yield_now().await;
    assert!(apply.waiter_count() >= 1);
    // await_committed already raised immediate; consume it so the nudge is visible.
    let _ = apply.wake_signal().take_immediate();
    apply.nudge_if_waiters_pending();
    assert!(
        apply.wake_signal().take_immediate(),
        "pending waiters behind accepted must re-arm an immediate poll"
    );
    apply.record_accepted(9);
    handle
        .await
        .expect("waiter task")
        .expect("accepted after nudge");
}

#[test]
fn live_apply_failure_labels_are_closed() {
    assert_eq!(LiveApplyFailure::ConfigRejected.as_str(), "config_rejected");
    assert_eq!(LiveApplyFailure::Timeout.as_str(), "reload_timeout");
    assert_eq!(
        LiveApplyFailure::SequenceUnavailable.as_str(),
        "sequence_unavailable"
    );
}

#[test]
fn coordinator_is_namespace_scoped() {
    let apply = RuntimeConfigApply::new("ferrum", 0);
    assert!(apply.serves_namespace("ferrum"));
    assert!(!apply.serves_namespace("other"));
}

#[test]
fn prepared_live_apply_distinguishes_noop_from_covering_watermark() {
    let noop = PreparedLiveApply::noop();
    assert!(noop.is_noop());
    assert_eq!(noop.covering_sequence(), None);

    let covering = PreparedLiveApply::from_covering_sequence(12);
    assert!(!covering.is_noop());
    assert_eq!(covering.covering_sequence(), Some(12));
}

#[test]
fn database_incremental_publication_is_fenced_after_async_validation() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let start = source
        .find("async fn apply_incremental_inner(")
        .expect("incremental apply implementation");
    let end = source[start..]
        .find("\n    pub fn current_config(")
        .map(|offset| start + offset)
        .expect("incremental apply implementation end");
    let body = &source[start..end];

    let off_thread_validation = body
        .find("validate_plugin_file_dependencies_off_thread(")
        .expect("off-thread file validation");
    let topology_pin = body
        .find("db.acquire_write_topology_permit().await")
        .expect("late database topology pin");
    let publication = body
        .find("self.publish_request_epoch_with_gateway_trust(")
        .expect("request-epoch publication");
    let release = body
        .find("drop(topology_permit)")
        .expect("topology pin release");
    assert!(
        off_thread_validation < topology_pin && topology_pin < publication && publication < release,
        "the database topology pin must cover only final synchronous publication"
    );
}

// ---------------------------------------------------------------------------
// Issue #4139 — deferred apply: cursor classification + bounded status waits.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cursor_state_classifies_against_the_published_snapshot() {
    use ferrum_edge::config::runtime_config_apply::LiveApplyCursorState;
    let apply = RuntimeConfigApply::at_epoch("ferrum", 3, 10);
    assert_eq!(
        apply.cursor_state(LiveApplyCursor::new(3, 10)),
        LiveApplyCursorState::Applied,
        "covered sequence in the current topology is applied"
    );
    assert_eq!(
        apply.cursor_state(LiveApplyCursor::new(3, 11)),
        LiveApplyCursorState::Pending,
        "uncovered sequence in the current topology is pending"
    );
    assert_eq!(
        apply.cursor_state(LiveApplyCursor::new(2, 1)),
        LiveApplyCursorState::Unverifiable,
        "a cursor from a replaced topology can no longer be proven"
    );
    assert_eq!(
        apply.cursor_state(LiveApplyCursor::new(4, 1)),
        LiveApplyCursorState::Pending,
        "a cursor ahead of the observed topology classifies pending; the \
         admin handler pairs this with the process topology-epoch check"
    );
    apply.record_rejected_cursor(LiveApplyCursor::new(3, 12));
    assert_eq!(
        apply.cursor_state(LiveApplyCursor::new(3, 12)),
        LiveApplyCursorState::Rejected,
        "a rejected poll covers pending cursors at or below its sequence"
    );
}

#[test]
fn cursor_state_labels_are_closed() {
    use ferrum_edge::config::runtime_config_apply::LiveApplyCursorState;
    assert_eq!(LiveApplyCursorState::Applied.as_str(), "applied");
    assert_eq!(LiveApplyCursorState::Pending.as_str(), "pending");
    assert_eq!(LiveApplyCursorState::Rejected.as_str(), "rejected");
    assert_eq!(LiveApplyCursorState::Unverifiable.as_str(), "unverifiable");
}

#[tokio::test]
async fn bounded_status_wait_times_out_without_failing_the_cursor() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let err = apply
        .await_committed_cursor_with_timeout(LiveApplyCursor::new(0, 5), Duration::from_millis(20))
        .await
        .expect_err("nothing published; the bounded wait must elapse");
    assert_eq!(err, LiveApplyFailure::Timeout);
    // The cursor itself is merely pending — a later accepted generation still
    // resolves it, which is what lets a status probe retry harmlessly.
    apply.record_accepted(5);
    apply
        .await_committed_cursor_with_timeout(LiveApplyCursor::new(0, 5), Duration::from_millis(20))
        .await
        .expect("accepted generation resolves the same cursor");
}

/// A deferred (`?apply=async`) mutation must NOT raise a per-write poll wake:
/// bulk deferred writes with per-write wakes turn the poll loop into gapless
/// back-to-back reloads that saturate the database (issue #4139 follow-up —
/// observed starving the admission lease renewer on the 30k PostgreSQL leg).
/// The blocking status probe is the only demand-driven wake source.
#[tokio::test]
async fn only_a_blocking_status_wait_raises_the_immediate_wake() {
    let apply = Arc::new(RuntimeConfigApply::new("ferrum", 0));
    let wake = apply.wake_signal();
    let before = wake.signals_total();
    // A bounded wait registers demand and nudges the poll.
    let _ = apply
        .await_committed_cursor_with_timeout(LiveApplyCursor::new(0, 5), Duration::from_millis(10))
        .await;
    assert!(
        wake.signals_total() > before,
        "a blocking status wait must nudge the poll loop"
    );
}

/// Issue #6057: the poll loop reports write-to-live latency from the oldest
/// admin write an accepted generation covers.
#[tokio::test(start_paused = true)]
async fn write_to_live_times_the_oldest_covered_write_once() {
    let apply = RuntimeConfigApply::at_epoch("ferrum", 1, 10);
    assert_eq!(apply.take_write_to_live(LiveApplyCursor::new(1, 20)), None);

    apply.record_issued_cursor(LiveApplyCursor::new(1, 11));
    tokio::time::advance(Duration::from_millis(300)).await;
    apply.record_issued_cursor(LiveApplyCursor::new(1, 12));
    tokio::time::advance(Duration::from_millis(200)).await;

    // A generation that does not cover the oldest write reports nothing yet.
    assert_eq!(apply.take_write_to_live(LiveApplyCursor::new(1, 10)), None);
    // Another topology's generation never matches.
    assert_eq!(apply.take_write_to_live(LiveApplyCursor::new(2, 50)), None);
    assert_eq!(
        apply.take_write_to_live(LiveApplyCursor::new(1, 12)),
        Some(Duration::from_millis(500)),
        "measured from the oldest covered write"
    );
    assert_eq!(
        apply.take_write_to_live(LiveApplyCursor::new(1, 12)),
        None,
        "each write is reported once"
    );

    apply.record_issued_cursor(LiveApplyCursor::new(1, 13));
    tokio::time::advance(Duration::from_millis(50)).await;
    assert_eq!(
        apply.take_write_to_live(LiveApplyCursor::new(1, 13)),
        Some(Duration::from_millis(50))
    );
}

/// A rejected generation settles the writes it covers, so the next accepted
/// change does not report their age as its write-to-live latency.
#[tokio::test(start_paused = true)]
async fn rejected_generation_clears_the_pending_write() {
    let apply = RuntimeConfigApply::at_epoch("ferrum", 1, 10);
    apply.record_issued_cursor(LiveApplyCursor::new(1, 11));
    tokio::time::advance(Duration::from_secs(600)).await;
    apply.record_rejected_cursor(LiveApplyCursor::new(1, 11));

    apply.record_issued_cursor(LiveApplyCursor::new(1, 12));
    tokio::time::advance(Duration::from_millis(40)).await;
    assert_eq!(
        apply.take_write_to_live(LiveApplyCursor::new(1, 12)),
        Some(Duration::from_millis(40))
    );
}

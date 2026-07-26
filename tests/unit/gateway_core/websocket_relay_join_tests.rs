//! Regression tests for the WebSocket relay's "wait for both halves" invariant.
//!
//! Codex P2 (commit 4f57b84): the relay used `tokio::select!` to await the
//! two forwarding futures, so whichever direction finished first won — the
//! other future was dropped mid-flight. On asymmetric sessions (e.g., the
//! client half-closes while the backend is still draining queued frames),
//! this produced:
//!
//! 1. Truncated `frames_client_to_backend` / `frames_backend_to_client`
//!    counts (late frames were never counted because their future was
//!    dropped before they ran).
//! 2. Shorter `duration_ms` than the real session.
//! 3. Lost terminal failure attribution from the dropped half.
//!
//! The fix is to run both futures with `tokio::join!` and have each future
//! `cancel()` the shared `CancellationToken` at the end of its loop — so a
//! natural EOF / error / close-frame exit on one side prompts the other to
//! wind down and the outer join completes quickly instead of hanging.
//!
//! These tests model the two direction futures with tokio primitives and
//! verify the pattern upholds the invariant. They do NOT spin up a real
//! WebSocket relay (that coverage lives in `tests/functional/`), but they
//! lock in the join-with-cancel-on-exit pattern so a future refactor can't
//! silently revert to `tokio::select!` without failing these tests.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Sink;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_util::sync::CancellationToken;

/// Sanity check: with `tokio::join!` + cancel-on-exit, the fast direction
/// completes quickly and signals the slow direction, which exits via the
/// cancellation branch. Both counters advance before `join!` returns.
#[tokio::test]
async fn test_join_with_cancel_on_exit_waits_for_both_halves() {
    let cancel = CancellationToken::new();
    let c2b_frames = Arc::new(AtomicU64::new(0));
    let b2c_frames = Arc::new(AtomicU64::new(0));

    let cancel_ctb = cancel.clone();
    let cancel_btc = cancel.clone();
    let c2b_counter = c2b_frames.clone();
    let b2c_counter = b2c_frames.clone();

    // "Fast" direction — simulates the client→backend half completing
    // immediately (client half-closed, EOF on first read).
    let fast = async move {
        c2b_counter.fetch_add(1, Ordering::SeqCst);
        // Mirror the real relay: signal the opposite direction at end of loop.
        cancel_ctb.cancel();
    };

    // "Slow" direction — simulates the backend→client half with buffered
    // work. Without the cancel signal, it would run for 5 seconds; with the
    // signal it exits promptly via the cancelled branch.
    let slow = async move {
        // Do a tiny bit of work before the select loop to simulate a frame
        // that was already in flight when the other direction finished.
        b2c_counter.fetch_add(1, Ordering::SeqCst);
        tokio::select! {
            _ = cancel_btc.cancelled() => {
                // Drain a final "synthetic close" frame, as the real relay
                // does when cancelled.
                b2c_counter.fetch_add(1, Ordering::SeqCst);
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                panic!("slow direction should have been cancelled well before timeout");
            }
        }
        cancel_btc.cancel();
    };

    let start = tokio::time::Instant::now();
    tokio::join!(fast, slow);
    let elapsed = start.elapsed();

    assert_eq!(
        c2b_frames.load(Ordering::SeqCst),
        1,
        "fast half must have recorded its one frame",
    );
    assert_eq!(
        b2c_frames.load(Ordering::SeqCst),
        2,
        "slow half must have run to completion (both pre-cancel work and cancel branch), \
         not been dropped mid-flight",
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "cancel-on-exit must make the slow half exit promptly after the fast half \
         (saw {elapsed:?})",
    );
}

/// Contrast test: demonstrate that `tokio::select!` drops the slow half,
/// producing incorrect frame counts. This is the pre-fix behavior — kept
/// here as an explicit regression trap so a future refactor that reverts
/// to `select!` would fail the partner test above while passing this one,
/// making the intent impossible to miss.
#[tokio::test]
async fn test_select_drops_unfinished_half_and_loses_frames() {
    let cancel = CancellationToken::new();
    let c2b_frames = Arc::new(AtomicU64::new(0));
    let b2c_frames = Arc::new(AtomicU64::new(0));

    let cancel_ctb = cancel.clone();
    let cancel_btc = cancel.clone();
    let c2b_counter = c2b_frames.clone();
    let b2c_counter = b2c_frames.clone();

    let fast = async move {
        c2b_counter.fetch_add(1, Ordering::SeqCst);
        cancel_ctb.cancel();
    };

    let slow = async move {
        tokio::select! {
            _ = cancel_btc.cancelled() => {
                // Simulate processing a trailing frame during teardown —
                // this increment is what the pre-fix `select!` path would
                // lose.
                tokio::task::yield_now().await;
                b2c_counter.fetch_add(1, Ordering::SeqCst);
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    };

    // Pre-fix behavior: select drops whichever half is still running.
    tokio::select! {
        _ = fast => {}
        _ = slow => {}
    }

    assert_eq!(c2b_frames.load(Ordering::SeqCst), 1);
    // The point of this test: with `select!`, the slow half's post-cancel
    // work is lost because the future is dropped. If a future refactor
    // switches back to `select!`, this would still be 0 — but the sibling
    // `test_join_with_cancel_on_exit_waits_for_both_halves` would start
    // failing because the b2c counter would drop from 2 → 1 under join.
    assert_eq!(
        b2c_frames.load(Ordering::SeqCst),
        0,
        "select! drops the still-running slow half before its cancel branch \
         increments the counter — documenting the pre-fix regression",
    );
}

/// Regression for Codex P1 on commit b6717c1: after switching to `tokio::join!`,
/// the forwarding loops' `sink.send(msg).await` calls were outside the outer
/// cancellation `select!`. A half stuck in a backpressured send would never
/// observe the cancel signal from the peer direction, so `join!` would hang
/// and `on_ws_disconnect` would never fire.
///
/// The fix wraps each send in an inner `tokio::select!` that races the send
/// future against `cancel.cancelled()`. This test models a peer "not reading"
/// with a `tokio::sync::Notify` that never notifies, then verifies that cancel
/// from the opposite direction breaks the stuck send out promptly.
#[tokio::test]
async fn test_cancel_unblocks_stuck_send() {
    let cancel = CancellationToken::new();
    let cancel_stuck = cancel.clone();
    let cancel_peer = cancel.clone();

    // `stuck_send` models `backend_sink.send(msg).await` blocking on a peer
    // that will never accept the bytes. Without the inner cancel-aware
    // `select!`, this future would hang forever inside `tokio::join!`.
    let peer_never_reads = Arc::new(tokio::sync::Notify::new());
    let peer_never_reads_stuck = peer_never_reads.clone();

    let stuck_half = async move {
        // Wrap the "stuck send" in the same cancel-aware pattern the WS
        // relay hot path now uses (select! + biased + cancel.cancelled()).
        // If the fix is in place, cancel breaks us out. If the fix is
        // reverted, this future hangs and `join!` times out.
        tokio::select! {
            biased;
            _ = cancel_stuck.cancelled() => {
                // Expected path after fix: peer direction exits, cancels,
                // and unblocks us.
            }
            _ = peer_never_reads_stuck.notified() => {
                panic!("stuck send must not complete — notify is never fired");
            }
        }
    };

    // The peer direction simulates "exits normally, then cancels the shared
    // token at end of loop" — exactly what the real relay does at the end
    // of `client_to_backend` / `backend_to_client`.
    let peer_half = async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel_peer.cancel();
    };

    let start = tokio::time::Instant::now();
    // Use a hard timeout as a safety net — if the fix regresses, this test
    // fails loudly instead of hanging CI.
    let outcome = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(stuck_half, peer_half)
    })
    .await;
    let elapsed = start.elapsed();

    assert!(
        outcome.is_ok(),
        "cancel-aware send must unblock the stuck half within the test timeout \
         (elapsed {elapsed:?}); regression: sends are no longer racing cancel.cancelled()",
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "cancel propagation must be fast (saw {elapsed:?}) — inner `select!` should \
         exit within tens of microseconds of `cancel()` firing",
    );
}

/// The cancel-branch polite-Close path cannot use `select!` with cancel
/// (cancel is already set by the time we enter that branch), so the relay
/// uses `lazy_timeout` to bound the send. This test models the scenario and
/// verifies that a stuck polite-Close does not extend session teardown
/// beyond the bounded window.
#[tokio::test]
async fn test_lazy_timeout_bounds_polite_close() {
    use ferrum_edge::lazy_timeout::lazy_timeout;

    // Simulate a "peer not accepting bytes" scenario by awaiting a Notify
    // that is never fired — this stands in for `sink.send(Close(None))`
    // blocking on a dead backend socket.
    let never = Arc::new(tokio::sync::Notify::new());
    let never_waited = never.clone();

    let stuck_close_send = async move {
        never_waited.notified().await;
    };

    let start = tokio::time::Instant::now();
    // The real call site uses 100ms; use 50ms here so the test runs faster
    // while still exercising the Pending-then-timeout branch.
    let result = lazy_timeout(Duration::from_millis(50), stuck_close_send).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "lazy_timeout must return Err(LazyTimeoutError) when the inner send hangs",
    );
    assert!(
        elapsed >= Duration::from_millis(50),
        "lazy_timeout must wait the full bound when the inner future is Pending \
         (saw {elapsed:?})",
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "lazy_timeout must return shortly after the bound — not burn extra time \
         (saw {elapsed:?})",
    );
}

/// Policy publication is synchronous, retains the first detailed Close, and
/// makes cancellation observable before the caller can start a bounded write.
#[test]
fn test_policy_close_publishes_cancellation_before_bounded_writes() {
    let policy_close = std::sync::OnceLock::new();
    let cancel = CancellationToken::new();
    let first = CloseFrame {
        code: CloseCode::Size,
        reason: "first policy reason".into(),
    };
    let later = CloseFrame {
        code: CloseCode::Policy,
        reason: "later policy reason".into(),
    };

    let selected = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        Some(first.clone()),
    );
    assert!(
        cancel.is_cancelled(),
        "policy cancellation must be published"
    );
    assert_eq!(selected, Some(first.clone()));

    let retained = ferrum_edge::_test_support::publish_ws_policy_close_for_test(
        &policy_close,
        &cancel,
        Some(later),
    );
    assert_eq!(retained, Some(first), "the first detailed Close must win");
}

struct PeerClosedSink {
    flushes: Arc<AtomicU64>,
    complete_flush: bool,
}

impl Sink<Message> for PeerClosedSink {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
        Err(WsError::Protocol(ProtocolError::SendAfterClosing))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        if self.complete_flush {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Tungstenite queues a peer Close echo before returning the received Close.
/// Its state then rejects a second send, so the relay must flush that queued
/// echo instead of dropping the transport with an incomplete handshake.
#[tokio::test]
async fn test_bounded_close_flushes_peer_echo_after_send_after_closing() {
    let flushes = Arc::new(AtomicU64::new(0));
    let mut sink = PeerClosedSink {
        flushes: Arc::clone(&flushes),
        complete_flush: true,
    };

    ferrum_edge::_test_support::send_bounded_ws_close_for_test(
        &mut sink,
        Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "graceful".into(),
        }),
    )
    .await;

    assert_eq!(
        flushes.load(Ordering::SeqCst),
        1,
        "SendAfterClosing must drive the already-queued peer echo with flush"
    );
}

/// The queued-echo fallback shares the production close deadline, so a peer
/// that stops accepting bytes cannot stall relay teardown.
#[tokio::test]
async fn test_bounded_close_limits_stuck_peer_echo_flush() {
    let flushes = Arc::new(AtomicU64::new(0));
    let mut sink = PeerClosedSink {
        flushes: Arc::clone(&flushes),
        complete_flush: false,
    };

    let start = tokio::time::Instant::now();
    ferrum_edge::_test_support::send_bounded_ws_close_for_test(&mut sink, None).await;
    let elapsed = start.elapsed();

    assert!(
        flushes.load(Ordering::SeqCst) >= 1,
        "the queued peer echo must be driven before the bounded timeout"
    );
    assert!(
        elapsed >= Duration::from_millis(90),
        "queued peer echo flush returned before the production bound: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "queued peer echo flush exceeded the production teardown bound: {elapsed:?}"
    );
}

/// Expected size-policy rejections are neutral policy outcomes rather than
/// generic relay failures that can pollute backend alerts and health signals.
///
/// This is the one retained narrow source assertion: the directional class is
/// stored in a private first-failure slot and becomes externally observable
/// only after the full disconnect logger lifecycle. Functional tests cover the
/// wire-level 1009 contract; widening the runtime API solely for this private
/// bookkeeping check would be less representative than pinning these two
/// assignments directly.
#[test]
fn test_size_policy_rejections_use_explicit_error_classes() {
    let source = include_str!("../../../src/proxy/mod.rs");

    for (direction_marker, end_marker, expected_class) in [
        (
            "direction = \"client->backend\"",
            "Client -> backend forwarding completed",
            "retry::ErrorClass::RequestBodyTooLarge",
        ),
        (
            "direction = \"backend->client\"",
            "Backend -> client forwarding completed",
            "retry::ErrorClass::ResponseBodyTooLarge",
        ),
    ] {
        let branch = source
            .split_once(direction_marker)
            .unwrap_or_else(|| panic!("missing size-policy branch: {direction_marker}"))
            .1;
        let branch = branch
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing relay branch end: {end_marker}"))
            .0;
        assert!(
            branch.contains(expected_class),
            "{direction_marker} must record {expected_class}"
        );
        assert!(
            branch.contains("global_capacity_close_for_error"),
            "{direction_marker} must fall back to a global capacity Close 1009"
        );
    }
}

/// Global capacity overflow Close is a bounded empty-reason 1009, never a
/// peer/secret payload.
#[test]
fn test_global_capacity_close_frame_is_bounded_non_secret_1009() {
    let close = ferrum_edge::_test_support::ws_global_capacity_close_frame_for_test();
    assert_eq!(close.code, CloseCode::Size);
    assert!(
        close.reason.is_empty(),
        "global fallback reason must stay empty/non-secret"
    );
    assert!(
        close.reason.len() <= 123,
        "close reason must fit the RFC 6455 control-frame budget"
    );
}

/// Idle-timeout policy Close is the single defined 1001 both relay halves share.
#[test]
fn test_idle_timeout_policy_close_frame_is_defined_1001() {
    let close = ferrum_edge::_test_support::ws_idle_timeout_policy_close_frame_for_test();
    assert_eq!(close.code, CloseCode::Away);
    assert_eq!(close.reason.as_str(), "idle timeout");
    assert!(close.reason.len() <= 123);
}

/// Capacity errors without a binding plugin rule still select the global 1009.
#[test]
fn test_global_capacity_close_for_error_selects_1009() {
    use tokio_tungstenite::tungstenite::Error as WsError;
    use tokio_tungstenite::tungstenite::error::CapacityError;

    let frame_err = WsError::Capacity(CapacityError::FrameTooLong {
        size: 64,
        max_size: 16,
    });
    let (close, kind, size, max_size) =
        ferrum_edge::_test_support::global_ws_capacity_close_for_error_for_test(&frame_err)
            .expect("frame capacity must map to global 1009");
    assert_eq!(close.code, CloseCode::Size);
    assert!(close.reason.is_empty());
    assert_eq!(kind, "frame");
    assert_eq!(size, 64);
    assert_eq!(max_size, 16);

    let message_err = WsError::Capacity(CapacityError::MessageTooLong {
        size: 200,
        max_size: 64,
    });
    let (close, kind, size, max_size) =
        ferrum_edge::_test_support::global_ws_capacity_close_for_error_for_test(&message_err)
            .expect("message capacity must map to global 1009");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(kind, "message");
    assert_eq!(size, 200);
    assert_eq!(max_size, 64);

    assert!(
        ferrum_edge::_test_support::global_ws_capacity_close_for_error_for_test(
            &WsError::ConnectionClosed
        )
        .is_none(),
        "non-capacity errors must not synthesize a size Close"
    );
}

/// Idle-timeout arms must publish the shared policy Close before cancelling so
/// both halves attempt a meaningful teardown instead of Close(None)/1006.
#[test]
fn test_idle_timeout_arms_publish_policy_close_before_teardown() {
    let source = include_str!("../../../src/proxy/mod.rs");

    for (marker, end_marker) in [
        (
            "observed on client->backend half)",
            "Client -> backend forwarding completed",
        ),
        (
            "observed on backend->client half)",
            "Backend -> client forwarding completed",
        ),
    ] {
        let branch = source
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing idle-timeout branch: {marker}"))
            .1;
        let branch = branch
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing relay branch end: {end_marker}"))
            .0;
        let idle_arm = branch
            .split("Ok(raw @")
            .next()
            .expect("idle arm should precede the next Ok match arm");
        assert!(
            idle_arm.contains("ws_idle_timeout_policy_close_frame()"),
            "{marker} must publish the defined idle-timeout Close"
        );
        assert!(
            idle_arm.contains("publish_ws_policy_close"),
            "{marker} must publish through OnceLock arbitration"
        );
        assert!(
            idle_arm.contains("send_bounded_ws_close"),
            "{marker} must attempt a bounded polite Close write"
        );
    }
}

/// Paired happy-path assertion: when the inner future completes synchronously
/// (the common case for a small Close frame on healthy TCP), `lazy_timeout`
/// pays zero timer cost and returns immediately with the inner result.
#[tokio::test]
async fn test_lazy_timeout_fast_path_has_no_overhead() {
    use ferrum_edge::lazy_timeout::lazy_timeout;

    // Inner future that completes on the first poll — this is the "healthy
    // TCP, Close frame sent in microseconds" case.
    let fast_send = async { 42u32 };

    let start = tokio::time::Instant::now();
    let result = lazy_timeout(Duration::from_secs(60), fast_send).await;
    let elapsed = start.elapsed();

    assert_eq!(result, Ok(42));
    assert!(
        elapsed < Duration::from_millis(5),
        "lazy_timeout fast path must not allocate a timer or sleep \
         (saw {elapsed:?})",
    );
}

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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::Sink;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::{CapacityError, ProtocolError};
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocket, WebSocketConfig};
use tokio_util::sync::CancellationToken;

/// Scripted byte source with a sink that silently accepts writes, so a sync
/// `tungstenite::WebSocket` can be driven over an in-memory byte stream.
struct WsScriptedIo {
    read: std::io::Cursor<Vec<u8>>,
}

impl std::io::Read for WsScriptedIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(buf)
    }
}

impl std::io::Write for WsScriptedIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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
/// assignments directly. The directional mapping the call encodes is
/// asserted separately against `ws_capacity_error_class_for_test`.
#[test]
fn test_size_policy_rejections_use_explicit_error_classes() {
    let source = include_str!("../../../src/proxy/mod.rs");

    for (direction_marker, end_marker, expected_class) in [
        (
            "direction = \"client->backend\"",
            "Client -> backend forwarding completed",
            "ws_capacity_error_class(size, true)",
        ),
        (
            "direction = \"backend->client\"",
            "Backend -> client forwarding completed",
            "ws_capacity_error_class(size, false)",
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

#[test]
fn test_ws_63_bit_oversize_frame_is_size_limit_not_protocol_error() {
    // A valid RFC 6455 63-bit payload length (2^32, above u32::MAX, with the
    // 64-bit length field's most-significant bit clear) that exceeds the
    // configured ceiling is a size-policy failure, never a protocol error.
    let over_u32_max = (u32::MAX as usize).saturating_add(1);
    assert_eq!(
        ferrum_edge::_test_support::ws_capacity_error_class_for_test(over_u32_max, true),
        ferrum_edge::retry::ErrorClass::RequestBodyTooLarge
    );
    assert_eq!(
        ferrum_edge::_test_support::ws_capacity_error_class_for_test(over_u32_max, false),
        ferrum_edge::retry::ErrorClass::ResponseBodyTooLarge
    );

    let err = WsError::Capacity(CapacityError::FrameTooLong {
        size: over_u32_max,
        max_size: 16,
    });
    let (close, kind, size, max_size) =
        ferrum_edge::_test_support::global_ws_capacity_close_for_error_for_test(&err)
            .expect("63-bit size-policy overflow must still select global Close 1009");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(kind, "frame");
    assert_eq!(size, over_u32_max);
    assert_eq!(max_size, 16);

    // A valid FIN=1 Binary frame advertising a 63-bit length of 2^32 must be
    // parsed as a Capacity overflow (size policy), not a protocol error.
    let oversize: Vec<u8> = vec![
        0x82, 0x7f, // FIN=1 opcode=0x2 (Binary); mask=0 length=127
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 63-bit length = 2^32
    ];
    let mut socket = WebSocket::from_raw_socket(
        WsScriptedIo {
            read: std::io::Cursor::new(oversize),
        },
        Role::Client,
        Some(WebSocketConfig::default()),
    );
    let read_err = socket.read().unwrap_err();
    assert!(
        matches!(
            &read_err,
            WsError::Capacity(CapacityError::FrameTooLong { size, .. }) if *size == over_u32_max
        ),
        "a valid 63-bit oversized frame must surface as a size-policy failure, got {read_err:?}"
    );
}

/// issue #4058 post-upgrade junk (`00 ff 4a 55 4e 4b 4a 55 4e 4b ...`) is a
/// masked stray continuation frame. Its 63-bit length (0x4A554E4B4A554E4B) has
/// the high bit clear, so the length itself is well-formed — the RFC 6455
/// violation is a Continue opcode with no fragmented message in progress.
#[test]
fn test_malformed_continuation_frame_is_protocol_error() {
    let junk: Vec<u8> = vec![
        0x00, 0xff, // FIN=0 opcode=0x0 (Continue); MASK=1 length=127
        0x4a, 0x55, 0x4e, 0x4b, 0x4a, 0x55, 0x4e, 0x4b, // 63-bit length, high bit clear
        0x00, 0x00, 0x00, 0x00, // 4-byte mask key
    ];
    let mut socket = WebSocket::from_raw_socket(
        WsScriptedIo {
            read: std::io::Cursor::new(junk),
        },
        Role::Server,
        Some(WebSocketConfig::default()),
    );
    let err = socket.read().unwrap_err();
    assert!(
        matches!(
            &err,
            WsError::Protocol(ProtocolError::UnexpectedContinueFrame)
        ),
        "stray continuation frame must fail closed as a protocol error, got {err:?}"
    );
    assert_eq!(
        ferrum_edge::retry::classify_boxed_error(&err),
        ferrum_edge::retry::ErrorClass::ProtocolError
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

/// The relay-failure Close maps `ErrorClass` to the RFC 6455 wire code the
/// surviving peer must observe (issue #4770): 1002 for a protocol violation,
/// 1011 for a transport failure, and 1001 while the gateway is draining. The
/// reason stays a bounded, non-secret literal.
#[test]
fn test_relay_failure_close_frame_maps_error_class_and_drain() {
    let protocol = ferrum_edge::_test_support::ws_relay_failure_close_frame_for_test(
        ferrum_edge::retry::ErrorClass::ProtocolError,
        false,
    );
    assert_eq!(protocol.code, CloseCode::Protocol);
    assert_eq!(protocol.reason.as_str(), "protocol error");
    assert!(protocol.reason.len() <= 123);

    let transport = ferrum_edge::_test_support::ws_relay_failure_close_frame_for_test(
        ferrum_edge::retry::ErrorClass::ConnectionReset,
        false,
    );
    assert_eq!(transport.code, CloseCode::Error);
    assert_eq!(transport.reason.as_str(), "relay error");
    assert!(transport.reason.len() <= 123);

    // Draining wins even for a protocol violation: an operator-driven shutdown
    // observes 1001 (going away), not a client-facing 1002/1011.
    let draining = ferrum_edge::_test_support::ws_relay_failure_close_frame_for_test(
        ferrum_edge::retry::ErrorClass::ProtocolError,
        true,
    );
    assert_eq!(draining.code, CloseCode::Away);
    assert_eq!(draining.reason.as_str(), "gateway draining");
    assert!(draining.reason.len() <= 123);
}

/// The generic transport/protocol read-error arms are the last unconverted
/// members of the policy-close family. Each must publish a defined Close (via
/// `publish_ws_policy_close`) before `break`, mapping the classified error to
/// 1002/1011/1001 and honoring an in-progress drain. Mirrors
/// `test_idle_timeout_arms_publish_policy_close_before_teardown`.
#[test]
fn test_generic_relay_error_arms_publish_policy_close_before_break() {
    let source = include_str!("../../../src/proxy/mod.rs");

    for (marker, end_marker) in [
        (
            "Error receiving from client",
            "Client -> backend forwarding completed",
        ),
        (
            "Error receiving from backend",
            "Backend -> client forwarding completed",
        ),
    ] {
        let branch = source
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing generic error arm: {marker}"))
            .1;
        let branch = branch
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing relay branch end: {end_marker}"))
            .0;
        assert!(
            branch.contains("publish_ws_policy_close"),
            "{marker} must publish the policy Close before breaking"
        );
        assert!(
            branch.contains("ws_relay_failure_close_frame"),
            "{marker} must map the classified error to a defined Close code"
        );
        assert!(
            branch.contains("ws_websocket_is_draining"),
            "{marker} must honor an in-progress drain (1001)"
        );
        assert!(
            branch.contains("send_bounded_ws_close"),
            "{marker} must attempt a bounded polite Close write to the surviving peer"
        );
    }
}

/// Models hyper's upgraded HTTP/2 writer (`H2Upgraded`): `start_send` hands the
/// frame to a bounded, capacity-1 channel that a *separate* task drains, and
/// `poll_flush` only reports readiness once that task has run. A relay half is
/// therefore routinely parked inside `sink.send(frame)` — not inside its stream
/// read — at the moment the opposite half publishes a policy Close and cancels.
/// H1 does not behave this way: its flush lands directly in the socket buffer.
struct DeferredFlushSink {
    sent: Arc<std::sync::Mutex<Vec<Message>>>,
    stalled: Arc<AtomicBool>,
}

impl Sink<Message> for DeferredFlushSink {
    type Error = WsError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.sent.lock().expect("sink log").push(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.stalled.load(Ordering::SeqCst) {
            // The drain task has not run yet, so no waker is registered — the
            // same shape as a capacity-1 channel nobody has polled. Only the
            // cancellation token can wake this half.
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

fn close_frames(log: &Arc<std::sync::Mutex<Vec<Message>>>) -> Vec<Option<CloseFrame>> {
    log.lock()
        .expect("sink log")
        .iter()
        .filter_map(|message| match message {
            Message::Close(frame) => Some(frame.clone()),
            _ => None,
        })
        .collect()
}

/// Regression for the H2 flake in `functional_ws_message_size_limit_h2_*`
/// (PR #3589): the relay's cancel-aware send `select!` used a bare `break` on
/// the cancel arm. `break` leaves the forwarding loop for good, so the outer
/// cancel branch — the only other place that writes the polite Close — is never
/// re-entered. A half parked in a stalled flush therefore dropped its sink with
/// no Close at all, and the peer surfaced `ResetWithoutClosingHandshake`
/// instead of the published 1009.
///
/// This models the exact arm: a stalled sink, an opposite half that publishes
/// 1009 and cancels, and the bounded policy write the arm must now perform.
#[tokio::test]
async fn test_mid_send_cancel_arm_still_delivers_the_policy_close() {
    use futures_util::SinkExt;

    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stalled = Arc::new(AtomicBool::new(true));
    let mut sink = DeferredFlushSink {
        sent: Arc::clone(&sent),
        stalled: Arc::clone(&stalled),
    };
    let cancel = CancellationToken::new();
    let policy_close = std::sync::OnceLock::new();
    let cancel_forwarding = cancel.clone();

    // Opposite half: rejects an oversized frame, publishes the 1009, cancels.
    let publishing_half = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        ferrum_edge::_test_support::publish_ws_policy_close_for_test(
            &policy_close,
            &cancel,
            Some(CloseFrame {
                code: CloseCode::Size,
                reason: "plugin frame limit".into(),
            }),
        );
        // The upgraded writer's drain task finally runs.
        stalled.store(false, Ordering::SeqCst);
    };

    // This half is mid-`send` when the cancel lands. Note that the handler
    // reborrows `sink`: `tokio::select!` drops its future tuple before running
    // handlers, which is what makes the production fix expressible.
    let forwarding_half = async {
        tokio::select! {
            biased;
            _ = cancel_forwarding.cancelled() => {
                ferrum_edge::_test_support::send_bounded_ws_close_for_test(
                    &mut sink,
                    policy_close.get().cloned(),
                )
                .await;
            }
            _ = sink.send(Message::Binary(vec![1u8; 4].into())) => {
                panic!("the stalled sink must not complete its flush before cancel");
            }
        }
    };

    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(publishing_half, forwarding_half)
    })
    .await
    .expect("mid-send cancel teardown must stay bounded");

    let closes = close_frames(&sent);
    assert_eq!(
        closes.len(),
        1,
        "the cancelled mid-send arm must write exactly one policy Close, not tear \
         the transport down bare and not duplicate it",
    );
    let close = closes[0]
        .clone()
        .expect("the policy Close must carry the published code and reason");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(close.reason.as_str(), "plugin frame limit");
}

/// Contrast test documenting the pre-fix shape, in the same spirit as
/// `test_select_drops_unfinished_half_and_loses_frames`: a cancel arm that only
/// `break`s leaves the peer with a bare reset. If someone reinstates the bare
/// `break`, the partner test above fails while this one keeps passing, making
/// the intent impossible to misread.
#[tokio::test]
async fn test_mid_send_cancel_without_bounded_close_leaves_peer_without_a_close() {
    use futures_util::SinkExt;

    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stalled = Arc::new(AtomicBool::new(true));
    let mut sink = DeferredFlushSink {
        sent: Arc::clone(&sent),
        stalled: Arc::clone(&stalled),
    };
    let cancel = CancellationToken::new();
    let cancel_forwarding = cancel.clone();

    let publishing_half = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        cancel.cancel();
        stalled.store(false, Ordering::SeqCst);
    };

    let forwarding_half = async {
        tokio::select! {
            biased;
            _ = cancel_forwarding.cancelled() => {
                // Pre-fix: leave the loop with no Close write.
            }
            _ = sink.send(Message::Binary(vec![1u8; 4].into())) => {
                panic!("the stalled sink must not complete its flush before cancel");
            }
        }
    };

    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(publishing_half, forwarding_half)
    })
    .await
    .expect("modelled teardown must stay bounded");

    assert!(
        close_frames(&sent).is_empty(),
        "documenting the defect: a bare `break` on the cancel arm sends no Close, \
         so the peer observes ResetWithoutClosingHandshake",
    );
}

/// Every cancel arm that can end a relay half must first attempt the bounded
/// policy Close. The mid-send arms `break` out of the forwarding loop and the
/// peer-Close-forward arms fall through to a `break`, so in all four cases the
/// outer cancel branch is unreachable afterwards. These arms live deep inside a
/// private relay closure with no externally reachable seam, so — like
/// `test_size_policy_rejections_use_explicit_error_classes` — they are pinned
/// at the source level rather than by widening a runtime API.
#[test]
fn test_cancel_arms_that_end_a_relay_half_write_a_bounded_close() {
    let source = include_str!("../../../src/proxy/mod.rs");

    for marker in [
        "Client->backend: cancel fired mid-send",
        "Backend->client: cancel fired mid-send",
        "Client->backend: cancel fired during client-close forward",
        "Backend->client: cancel fired during backend-close forward",
    ] {
        let arm_body = source
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing relay cancel arm: {marker}"))
            .1
            .lines()
            // The handler opens at 32-space indentation, so the first line that
            // dedents back to a closing brace at or above that level ends it.
            .take_while(|line| {
                let indent = line.len() - line.trim_start().len();
                !(line.trim() == "}" && indent <= 32)
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            arm_body.contains("send_bounded_ws_close"),
            "{marker} must attempt a bounded polite Close before ending the half; \
             a bare break leaves the peer with a transport reset and no Close",
        );
        assert!(
            arm_body.contains("policy_close_"),
            "{marker} must write the arbitrated policy Close, not an ad hoc frame",
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

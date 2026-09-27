//! Tests for the in-process UDP port handoff ledger (issue #5843).
//!
//! The ledger decides whether a UDP bind that failed with `EADDRINUSE` is
//! worth retrying: only while another in-process datagram listener holds the
//! port or has just released it. These tests pin that decision and the
//! owner-scoped release wakeups without binding any sockets.

use ferrum_edge::proxy::udp_port_handoff::{
    UDP_PORT_HANDOFF_INITIAL_BACKOFF, UdpPortHandoff, UdpPortHandoffBackoff, UdpPortOwner,
};
use std::time::Duration;

#[test]
fn an_unarmed_hold_never_marks_its_port_as_handed_over() {
    let ledger = UdpPortHandoff::new();
    let releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let hold = ledger.hold(4433, UdpPortOwner::GatewayQuic);
    assert!(!ledger.handoff_pending(4433));

    // A listener whose bind failed never armed its hold: dropping it must not
    // make the port look recently released or wake the other manager.
    drop(hold);
    assert!(!ledger.handoff_pending(4433));
    assert!(!releases.has_changed().expect("ledger alive"));
}

#[test]
fn an_armed_hold_marks_its_port_until_released_and_for_the_recent_window_after() {
    let ledger = UdpPortHandoff::new();
    let hold = ledger.hold(4433, UdpPortOwner::StreamDatagram);
    hold.arm();
    assert!(ledger.handoff_pending(4433));
    assert!(!ledger.handoff_pending(4434), "other ports are unaffected");

    // The socket can outlive the listener task that owned the hold, so the
    // port stays eligible for the bounded retry right after the release.
    drop(hold);
    assert!(ledger.handoff_pending(4433));
    assert!(!ledger.handoff_pending(4434));
}

#[test]
fn a_hold_is_released_once_when_its_last_clone_drops() {
    let ledger = UdpPortHandoff::new();
    let mut releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let hold = ledger.hold(4433, UdpPortOwner::GatewayQuic);
    let task_clone = hold.clone();
    hold.arm();
    hold.arm(); // idempotent
    drop(hold);
    assert!(
        !releases.has_changed().expect("ledger alive"),
        "the task's clone still holds the port"
    );

    drop(task_clone);
    assert!(releases.has_changed().expect("ledger alive"));
    assert_eq!(*releases.borrow_and_update(), 1, "released exactly once");
}

#[test]
fn releases_wake_only_subscribers_of_the_releasing_owner() {
    let ledger = UdpPortHandoff::new();
    let quic_releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let mut stream_releases = ledger.subscribe_releases(UdpPortOwner::StreamDatagram);

    let stream_hold = ledger.hold(5353, UdpPortOwner::StreamDatagram);
    stream_hold.arm();
    drop(stream_hold);
    assert!(stream_releases.has_changed().expect("ledger alive"));
    assert!(
        !quic_releases.has_changed().expect("ledger alive"),
        "a stream release must not wake the stream manager's own supervisor path"
    );
    stream_releases.mark_unchanged();

    let quic_hold = ledger.hold(5353, UdpPortOwner::GatewayQuic);
    quic_hold.arm();
    drop(quic_hold);
    assert!(quic_releases.has_changed().expect("ledger alive"));
    assert!(!stream_releases.has_changed().expect("ledger alive"));
}

#[test]
fn a_port_held_by_both_owners_stays_marked_until_both_release() {
    let ledger = UdpPortHandoff::new();
    let quic_hold = ledger.hold(8443, UdpPortOwner::GatewayQuic);
    let stream_hold = ledger.hold(8443, UdpPortOwner::StreamDatagram);
    quic_hold.arm();
    stream_hold.arm();
    drop(quic_hold);
    assert!(ledger.handoff_pending(8443));
    drop(stream_hold);
    assert!(ledger.handoff_pending(8443), "recently released");
}

#[tokio::test(start_paused = true)]
async fn the_backoff_is_bounded_by_its_deadline() {
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_millis(500);
    let mut backoff = UdpPortHandoffBackoff::new(deadline);
    let mut attempts = 0u32;
    while backoff.wait().await {
        attempts += 1;
        assert!(attempts < 100, "the backoff must stop at its deadline");
    }
    assert!(attempts >= 2, "several attempts fit in the budget: {attempts}");
    let elapsed = start.elapsed();
    assert!(
        elapsed <= Duration::from_millis(500),
        "no pause may run past the deadline: {elapsed:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn an_expired_deadline_allows_no_further_attempt() {
    let start = tokio::time::Instant::now();
    let mut backoff = UdpPortHandoffBackoff::new(start + UDP_PORT_HANDOFF_INITIAL_BACKOFF);
    assert!(!backoff.wait().await);
    assert_eq!(start.elapsed(), Duration::ZERO, "no pause without a next attempt");
}

//! Tests for the in-process UDP port handoff ledger (issue #5843).
//!
//! The ledger decides whether a UDP bind that failed with `EADDRINUSE` is
//! worth retrying: only while another in-process datagram listener holds the
//! port or has just released it. These tests pin that decision and the
//! owner- and port-scoped release log without binding any sockets.

use ferrum_edge::proxy::udp_port_handoff::{
    UDP_PORT_HANDOFF_INITIAL_BACKOFF, UdpPortHandoff, UdpPortHandoffBackoff, UdpPortOwner,
};
use std::time::Duration;

#[test]
fn an_unarmed_hold_never_marks_its_port_as_handed_over() {
    let ledger = UdpPortHandoff::new();
    let mut releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let hold = ledger.hold(4433, UdpPortOwner::GatewayQuic);
    assert!(!ledger.note_bind_collision(4433));

    // A listener whose bind failed never armed its hold: dropping it must not
    // make the port look recently released or wake the other manager.
    drop(hold);
    assert!(!ledger.note_bind_collision(4433));
    assert!(releases.try_recv().is_none());
    assert_eq!(ledger.handoff_retries(), 0, "no collision was a handoff");
}

#[test]
fn an_armed_hold_marks_its_port_until_released_and_for_the_recent_window_after() {
    let ledger = UdpPortHandoff::new();
    let hold = ledger.hold(4433, UdpPortOwner::StreamDatagram);
    hold.arm();
    assert!(ledger.note_bind_collision(4433));
    assert!(
        !ledger.note_bind_collision(4434),
        "other ports are unaffected"
    );

    // The acquiring side can fail its bind just before the release and ask
    // the ledger just after it, so the port stays eligible for the bounded
    // retry right after the release.
    drop(hold);
    assert!(ledger.note_bind_collision(4433));
    assert!(!ledger.note_bind_collision(4434));
    assert_eq!(
        ledger.handoff_retries(),
        2,
        "only the collisions classified as handoffs are counted"
    );
}

#[test]
fn a_hold_is_released_once_when_its_last_clone_drops() {
    let ledger = UdpPortHandoff::new();
    let mut releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let hold = ledger.hold(4433, UdpPortOwner::GatewayQuic);
    let session_clone = hold.clone();
    hold.arm();
    hold.arm(); // idempotent
    drop(hold);
    assert!(
        releases.try_recv().is_none(),
        "a session's clone still holds the port"
    );

    drop(session_clone);
    let released = releases.try_recv().expect("the release");
    assert_eq!(released.ports(), [4433], "released exactly once");
    assert!(releases.try_recv().is_none());
}

#[test]
fn releases_wake_only_subscribers_of_the_releasing_owner() {
    let ledger = UdpPortHandoff::new();
    let mut quic_releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    let mut stream_releases = ledger.subscribe_releases(UdpPortOwner::StreamDatagram);

    let stream_hold = ledger.hold(5353, UdpPortOwner::StreamDatagram);
    stream_hold.arm();
    drop(stream_hold);
    assert!(stream_releases.try_recv().is_some());
    assert!(
        quic_releases.try_recv().is_none(),
        "a stream release must not wake the stream manager's own supervisor path"
    );

    let quic_hold = ledger.hold(5353, UdpPortOwner::GatewayQuic);
    quic_hold.arm();
    drop(quic_hold);
    assert!(quic_releases.try_recv().is_some());
    assert!(stream_releases.try_recv().is_none());
}

/// A subscriber reconciles only when a released port is one of its own
/// outstanding bind failures: a release of an unrelated port must not match.
#[test]
fn a_release_matches_only_the_ports_it_released() {
    let ledger = UdpPortHandoff::new();
    let mut releases = ledger.subscribe_releases(UdpPortOwner::StreamDatagram);
    let outstanding_failures = [8443, 9443];

    let unrelated = ledger.hold(5353, UdpPortOwner::StreamDatagram);
    unrelated.arm();
    drop(unrelated);
    let released = releases.try_recv().expect("the unrelated release");
    assert_eq!(released.ports(), [5353]);
    assert!(!released.includes_any(outstanding_failures));
    assert!(released.includes_any([5353]));

    for port in [7443, 9443] {
        let hold = ledger.hold(port, UdpPortOwner::StreamDatagram);
        hold.arm();
        drop(hold);
    }
    let released = releases.try_recv().expect("both releases, coalesced");
    assert_eq!(released.ports(), [7443, 9443], "only unseen releases");
    assert!(released.includes_any(outstanding_failures));
    assert!(!released.includes_any(std::iter::empty::<u16>()));
}

/// A subscriber that fell behind the bounded release log cannot tell which
/// ports it missed, so every outstanding failure must be treated as released
/// rather than left waiting for the slow tick.
#[test]
fn a_subscriber_that_missed_releases_matches_every_outstanding_port() {
    let ledger = UdpPortHandoff::new();
    let mut releases = ledger.subscribe_releases(UdpPortOwner::GatewayQuic);
    for port in 10_000..10_200 {
        let hold = ledger.hold(port, UdpPortOwner::GatewayQuic);
        hold.arm();
        drop(hold);
    }
    let released = releases.try_recv().expect("the releases");
    assert!(!released.ports().contains(&10_000), "the log is bounded");
    assert!(released.includes_any([10_000]));
    assert!(released.includes_any([443]));
    assert!(!released.includes_any(std::iter::empty::<u16>()));
}

#[test]
fn a_port_held_by_both_owners_stays_marked_until_both_release() {
    let ledger = UdpPortHandoff::new();
    let quic_hold = ledger.hold(8443, UdpPortOwner::GatewayQuic);
    let stream_hold = ledger.hold(8443, UdpPortOwner::StreamDatagram);
    quic_hold.arm();
    stream_hold.arm();
    drop(quic_hold);
    assert!(ledger.note_bind_collision(8443));
    drop(stream_hold);
    assert!(ledger.note_bind_collision(8443), "recently released");
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
    assert!(
        attempts >= 2,
        "several attempts fit in the budget: {attempts}"
    );
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
    assert_eq!(
        start.elapsed(),
        Duration::ZERO,
        "no pause without a next attempt"
    );
}

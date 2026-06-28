//! Unit coverage for the admin connection limiter (`AdminConnLimiter`).
//!
//! Validates the management-plane connection cap independently of the accept
//! loop: global cap admits up to N and rejects N+1, permits release on drop,
//! the per-IP cap isolates sources, and the snapshot counters track active +
//! rejected connections by reason.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ferrum_edge::admin::{AdminConnLimiter, AdminConnRejectReason};

fn ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

#[test]
fn admits_up_to_cap_then_rejects() {
    let limiter = Arc::new(AdminConnLimiter::new(3, 0));

    let p1 = limiter.try_acquire(ip(1)).expect("1st admitted");
    let p2 = limiter.try_acquire(ip(2)).expect("2nd admitted");
    let p3 = limiter.try_acquire(ip(3)).expect("3rd admitted");

    // 4th is over the global cap.
    let err = limiter.try_acquire(ip(4)).expect_err("4th rejected");
    assert_eq!(err, AdminConnRejectReason::MaxConnections);

    let snap = limiter.snapshot();
    assert_eq!(snap.active_connections, 3);
    assert_eq!(snap.max_connections, 3);
    assert_eq!(snap.rejected_total, 1);
    assert_eq!(snap.rejected_max_connections, 1);
    assert_eq!(snap.rejected_max_connections_per_ip, 0);

    // Keep permits alive until after the assertions.
    drop((p1, p2, p3));
}

#[test]
fn releases_permit_on_drop() {
    let limiter = Arc::new(AdminConnLimiter::new(1, 0));

    let p1 = limiter.try_acquire(ip(1)).expect("admitted");
    assert!(limiter.try_acquire(ip(2)).is_err(), "at capacity");
    assert_eq!(limiter.snapshot().active_connections, 1);

    drop(p1);
    assert_eq!(limiter.snapshot().active_connections, 0);

    // A freed slot is reusable.
    let _p2 = limiter.try_acquire(ip(2)).expect("admitted after release");
    assert_eq!(limiter.snapshot().active_connections, 1);
}

#[test]
fn per_ip_cap_isolates_sources() {
    // Generous global cap, per-IP cap of 2.
    let limiter = Arc::new(AdminConnLimiter::new(100, 2));

    let _a1 = limiter.try_acquire(ip(1)).expect("A 1st");
    let _a2 = limiter.try_acquire(ip(1)).expect("A 2nd");
    let err = limiter.try_acquire(ip(1)).expect_err("A 3rd rejected");
    assert_eq!(err, AdminConnRejectReason::MaxConnectionsPerIp);

    // A different IP is unaffected.
    let _b1 = limiter.try_acquire(ip(2)).expect("B 1st");
    let _b2 = limiter.try_acquire(ip(2)).expect("B 2nd");

    let snap = limiter.snapshot();
    assert_eq!(snap.active_connections, 4);
    assert_eq!(snap.rejected_total, 1);
    assert_eq!(snap.rejected_max_connections_per_ip, 1);
    assert_eq!(snap.rejected_max_connections, 0);
}

#[test]
fn per_ip_slot_frees_on_drop() {
    let limiter = Arc::new(AdminConnLimiter::new(100, 1));

    let a1 = limiter.try_acquire(ip(1)).expect("A 1st");
    assert!(limiter.try_acquire(ip(1)).is_err(), "A at per-ip cap");
    drop(a1);
    // The per-IP slot is freed and the map entry evicted at zero.
    let _a2 = limiter.try_acquire(ip(1)).expect("A reusable after drop");
}

#[test]
fn global_rejection_does_not_consume_per_ip_slot() {
    // Global cap 1, per-IP cap 5: a global rejection must not leave a phantom
    // per-IP count behind (the global permit is released before per-IP tracking).
    let limiter = Arc::new(AdminConnLimiter::new(1, 5));
    let p1 = limiter.try_acquire(ip(1)).expect("1st admitted");
    assert!(limiter.try_acquire(ip(2)).is_err(), "global cap hit");
    drop(p1);
    // ip(2) was never tracked, so it can acquire cleanly now.
    let _p2 = limiter.try_acquire(ip(2)).expect("admitted after release");
    assert_eq!(limiter.snapshot().active_connections, 1);
}

#[test]
fn unlimited_never_rejects_but_tracks_active() {
    let limiter = AdminConnLimiter::unlimited();
    assert!(!limiter.is_enforcing());

    let mut permits = Vec::new();
    for n in 0..50 {
        permits.push(limiter.try_acquire(ip(n)).expect("unlimited admits"));
    }
    assert_eq!(limiter.snapshot().active_connections, 50);
    assert_eq!(limiter.snapshot().max_connections, 0);

    permits.clear();
    assert_eq!(limiter.snapshot().active_connections, 0);
}

#[test]
fn reject_reason_labels_are_stable() {
    assert_eq!(
        AdminConnRejectReason::MaxConnections.as_label(),
        "max_connections"
    );
    assert_eq!(
        AdminConnRejectReason::MaxConnectionsPerIp.as_label(),
        "max_connections_per_ip"
    );
}

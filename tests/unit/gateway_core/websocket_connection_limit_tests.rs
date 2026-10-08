use std::sync::Arc;
use std::sync::atomic::Ordering;

use ferrum_edge::proxy::{
    PerIpLimitExceeded, PerIpStreamAdmission, try_acquire_per_ip_slot,
    try_acquire_per_ip_websocket_session, try_acquire_websocket_connection_permit,
};

#[test]
fn websocket_connection_permit_is_optional() {
    let permit = try_acquire_websocket_connection_permit(None).unwrap();
    assert!(permit.is_none());
}

#[test]
fn websocket_connection_permit_rejects_when_limit_is_exhausted() {
    let limit = Arc::new(tokio::sync::Semaphore::new(1));
    let _first = try_acquire_websocket_connection_permit(Some(&limit))
        .unwrap()
        .expect("first permit should be available");

    let second = try_acquire_websocket_connection_permit(Some(&limit));
    assert!(second.is_err(), "second permit should be rejected");
}

#[test]
fn per_ip_websocket_session_is_disabled_when_unconfigured() {
    let guard = try_acquire_per_ip_websocket_session(None, "198.51.100.1", 1).unwrap();
    assert!(guard.is_none());
}

#[test]
fn per_ip_websocket_session_is_disabled_when_max_is_zero() {
    let counts = Arc::new(dashmap::DashMap::new());
    let guard = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 0).unwrap();
    assert!(guard.is_none());
    assert!(counts.is_empty());
}

#[test]
fn per_ip_websocket_session_rejects_when_limit_is_exhausted() {
    let counts = Arc::new(dashmap::DashMap::new());
    let first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first session should be admitted");
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        1
    );

    let second = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1);
    assert!(
        matches!(second, Err(PerIpLimitExceeded)),
        "a second session from the same source must be refused"
    );
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        1,
        "rejected acquire must not leak a slot"
    );

    drop(first);
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("counter exists")
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn per_ip_websocket_session_is_enforced_independently_per_source() {
    let counts = Arc::new(dashmap::DashMap::new());
    let _first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first source should be admitted");

    let other = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.2", 1)
        .unwrap()
        .expect("second source should still be admitted");
    assert_eq!(
        counts
            .get("198.51.100.1")
            .expect("first counter")
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        counts
            .get("198.51.100.2")
            .expect("second counter")
            .load(Ordering::Relaxed),
        1
    );
    drop(other);
}

#[test]
fn per_ip_websocket_session_slot_is_reusable_after_release() {
    let counts = Arc::new(dashmap::DashMap::new());
    let first = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("first session should be admitted");
    drop(first);

    let reused = try_acquire_per_ip_websocket_session(Some(&counts), "198.51.100.1", 1)
        .unwrap()
        .expect("released slot should be reusable");
    drop(reused);
}

// ── Generalised per-source slot (issue #4544) ────────────────────────────────
//
// `try_acquire_per_ip_slot` is the one primitive behind the WebSocket,
// TCP-stream and UDP/DTLS-stream per-source bounds. These pin the three
// properties every caller relies on.

#[test]
fn per_ip_slot_is_unlimited_when_max_is_zero() {
    let counts = Arc::new(dashmap::DashMap::new());
    for _ in 0..64 {
        let guard = try_acquire_per_ip_slot(Some(&counts), "198.51.100.7", 0)
            .expect("max == 0 must never refuse");
        assert!(
            guard.is_none(),
            "an unlimited dimension must not hand out a guard or touch the counter"
        );
    }
    assert!(
        counts.get("198.51.100.7").is_none(),
        "an unlimited dimension must not create counter entries"
    );
}

#[test]
fn per_ip_slot_refuses_the_acquisition_past_the_limit() {
    let counts = Arc::new(dashmap::DashMap::new());
    let max = 4u64;
    let mut guards = Vec::new();
    for n in 1..=max {
        guards.push(
            try_acquire_per_ip_slot(Some(&counts), "198.51.100.8", max)
                .unwrap_or_else(|_| panic!("acquisition {n} must be admitted"))
                .expect("an enabled dimension must hand out a guard"),
        );
    }
    assert_eq!(
        counts
            .get("198.51.100.8")
            .expect("counter")
            .load(Ordering::Relaxed),
        max
    );

    let refused = try_acquire_per_ip_slot(Some(&counts), "198.51.100.8", max);
    assert!(
        matches!(refused, Err(PerIpLimitExceeded)),
        "acquisition max + 1 must be refused"
    );
    assert_eq!(
        counts
            .get("198.51.100.8")
            .expect("counter")
            .load(Ordering::Relaxed),
        max,
        "a refused acquisition must drop its own increment"
    );

    // A different source is unaffected by a saturated neighbour.
    let other = try_acquire_per_ip_slot(Some(&counts), "198.51.100.9", max)
        .expect("a different source must still be admitted")
        .expect("guard");
    drop(other);
    drop(guards);
}

#[test]
fn per_ip_slot_counter_returns_to_zero_after_every_guard_drops() {
    let counts = Arc::new(dashmap::DashMap::new());
    let guards: Vec<_> = (0..8)
        .map(|_| {
            try_acquire_per_ip_slot(Some(&counts), "198.51.100.10", 8)
                .expect("admitted")
                .expect("guard")
        })
        .collect();
    assert_eq!(
        counts
            .get("198.51.100.10")
            .expect("counter")
            .load(Ordering::Relaxed),
        8
    );
    drop(guards);
    assert_eq!(
        counts
            .get("198.51.100.10")
            .expect("counter")
            .load(Ordering::Relaxed),
        0,
        "every guard drop must decrement; the sweeper only reclaims zero entries"
    );
}

#[test]
fn per_ip_slot_groups_ipv6_addresses_by_the_default_prefix() {
    let counts = Arc::new(dashmap::DashMap::new());
    let first = try_acquire_per_ip_slot(Some(&counts), "2001:db8:abcd:12::1", 1)
        .expect("first source admitted")
        .expect("guard");
    assert!(matches!(
        try_acquire_per_ip_slot(Some(&counts), "2001:db8:abcd:12::ffff", 1),
        Err(PerIpLimitExceeded)
    ));
    drop(first);
    assert!(counts.is_empty());
}

#[test]
fn per_ip_stream_admission_default_is_disabled() {
    let admission = PerIpStreamAdmission::default();
    assert_eq!(admission.max, 0);
    assert!(
        admission
            .try_acquire("198.51.100.11")
            .expect("a disabled dimension must never refuse")
            .is_none()
    );
}

#[test]
fn per_ip_stream_admission_enforces_its_configured_max() {
    let admission = PerIpStreamAdmission {
        counts: Some(Arc::new(dashmap::DashMap::new())),
        max: 2,
    };
    let _a = admission
        .try_acquire("198.51.100.12")
        .expect("first")
        .expect("guard");
    let _b = admission
        .try_acquire("198.51.100.12")
        .expect("second")
        .expect("guard");
    assert!(
        matches!(
            admission.try_acquire("198.51.100.12"),
            Err(PerIpLimitExceeded)
        ),
        "the third concurrent acquisition must be refused"
    );
}

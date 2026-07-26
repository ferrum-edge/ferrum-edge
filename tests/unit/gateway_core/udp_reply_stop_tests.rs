//! Regression coverage for UDP reply-task stop lost-wakeup (#2958) and the
//! `last_client` expired-cache clear.
//!
//! These tests exercise the production `udp_reply_recv_until_stop` helper
//! (the same unit `create_session`'s reply loop calls) through `_test_support`
//! so the stop interleave is deterministic: no sleeps and no backend datagrams.
//! Tests pass `pending()` as the cancel arm; production composes listener +
//! global shutdown into that arm instead.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::{
    signal_udp_reply_task_stop_for_test, take_udp_last_client_if_live_for_test,
    udp_reply_recv_until_stop_for_test,
};
use tokio::sync::Notify;

/// Stop signaled before the waiter starts must be observed immediately via the
/// flag / stored permit — without parking on a backend recv.
#[tokio::test(start_paused = true)]
async fn udp_reply_stop_before_waiter_returns_without_backend_traffic() {
    let stop_flag = AtomicBool::new(false);
    let stop_notify = Notify::new();
    signal_udp_reply_task_stop_for_test(&stop_flag, &stop_notify);

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        udp_reply_recv_until_stop_for_test(
            &stop_flag,
            &stop_notify,
            std::future::pending::<()>(),
            std::future::pending::<()>(),
        ),
    )
    .await
    .expect("pre-signaled stop must resolve without waiting on recv");

    assert!(
        outcome.is_none(),
        "stop must win; got Some(_) which implies pending recv completed"
    );
    assert!(
        stop_flag.load(Ordering::Acquire),
        "stop flag must remain set for loop-top checks"
    );
}

/// Classic lost-wakeup interleave: waiter parks on recv after register+flag
/// check, then cleanup signals. Must wake without any backend datagram.
#[tokio::test(start_paused = true)]
async fn udp_reply_stop_after_waiter_parks_wakes_without_backend_traffic() {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());

    let flag = Arc::clone(&stop_flag);
    let notify = Arc::clone(&stop_notify);
    let waiter = tokio::spawn(async move {
        udp_reply_recv_until_stop_for_test(
            flag.as_ref(),
            notify.as_ref(),
            std::future::pending::<()>(),
            std::future::pending::<()>(),
        )
        .await
    });

    // Let the waiter enable()+check(false) and park in select against pending.
    tokio::task::yield_now().await;

    signal_udp_reply_task_stop_for_test(stop_flag.as_ref(), stop_notify.as_ref());

    let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("stop notify must wake the reply waiter without backend traffic")
        .expect("waiter task panicked");

    assert!(
        outcome.is_none(),
        "stop branch must win over a never-ready backend recv"
    );
}

/// Permit-storing wake: signal after a false flag observation but before the
/// waiter has created its `Notified` future (the historical notify_waiters
/// lost-wakeup window). The next register-then-check await must still observe
/// stop via the stored permit and/or flag.
#[tokio::test(start_paused = true)]
async fn udp_reply_stop_permit_survives_pre_registration_gap() {
    let stop_flag = AtomicBool::new(false);
    let stop_notify = Notify::new();

    // Emulate the old gap: flag was false at loop top, then cleanup runs
    // before the waiter registers. notify_one must retain a permit.
    assert!(!stop_flag.load(Ordering::Acquire));
    signal_udp_reply_task_stop_for_test(&stop_flag, &stop_notify);

    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        udp_reply_recv_until_stop_for_test(
            &stop_flag,
            &stop_notify,
            std::future::pending::<()>(),
            std::future::pending::<()>(),
        ),
    )
    .await
    .expect("stored stop permit/flag must be observed on first await");

    assert!(outcome.is_none());
}

/// Many independent session stop races (one reply task per Notify) must all
/// observe stop without backend traffic.
#[tokio::test(start_paused = true)]
async fn udp_reply_stop_independent_sessions_all_observe_signal() {
    let mut waiters = Vec::new();
    let mut signals = Vec::new();

    for _ in 0..16 {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(Notify::new());
        let flag = Arc::clone(&stop_flag);
        let notify = Arc::clone(&stop_notify);
        waiters.push(tokio::spawn(async move {
            udp_reply_recv_until_stop_for_test(
                flag.as_ref(),
                notify.as_ref(),
                std::future::pending::<()>(),
                std::future::pending::<()>(),
            )
            .await
        }));
        signals.push((stop_flag, stop_notify));
    }

    tokio::task::yield_now().await;
    for (flag, notify) in &signals {
        signal_udp_reply_task_stop_for_test(flag.as_ref(), notify.as_ref());
    }

    for waiter in waiters {
        let outcome = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("each session stop must wake without backend traffic")
            .expect("waiter task panicked");
        assert!(outcome.is_none());
    }
}

struct CacheSession {
    expired: AtomicBool,
}

/// Fast-path expired check must drop the cached Arc so a quiet listener does
/// not pin an expired backend session until another datagram overwrites it.
#[test]
fn udp_last_client_expired_fast_path_clears_arc_cache() {
    let client: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let session = Arc::new(CacheSession {
        expired: AtomicBool::new(false),
    });
    let mut last_client = Some((client, Arc::clone(&session)));
    assert_eq!(Arc::strong_count(&session), 2);

    let live = take_udp_last_client_if_live_for_test(&mut last_client, client, |s| {
        s.expired.load(Ordering::Acquire)
    });
    assert!(live.is_some(), "live cache hit must return the session");
    assert!(
        last_client.is_some(),
        "live hit must leave the cache intact"
    );
    drop(live);

    session.expired.store(true, Ordering::Release);
    let expired_hit = take_udp_last_client_if_live_for_test(&mut last_client, client, |s| {
        s.expired.load(Ordering::Acquire)
    });
    assert!(
        expired_hit.is_none(),
        "expired fast-path must miss and force a map lookup"
    );
    assert!(
        last_client.is_none(),
        "expired fast-path must clear last_client"
    );
    assert_eq!(
        Arc::strong_count(&session),
        1,
        "clearing last_client must drop the cached Arc pin"
    );
}

#[test]
fn udp_last_client_addr_mismatch_leaves_cache_untouched() {
    let cached_addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let other_addr: SocketAddr = "127.0.0.1:5354".parse().unwrap();
    let session = Arc::new(CacheSession {
        expired: AtomicBool::new(true),
    });
    let mut last_client = Some((cached_addr, Arc::clone(&session)));

    let miss = take_udp_last_client_if_live_for_test(&mut last_client, other_addr, |s| {
        s.expired.load(Ordering::Acquire)
    });
    assert!(miss.is_none());
    assert!(
        last_client.is_some(),
        "addr mismatch must not clear a different client's cache entry"
    );
    assert_eq!(Arc::strong_count(&session), 2);
}

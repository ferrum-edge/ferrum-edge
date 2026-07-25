//! External regression coverage for DP serving-listener supervision (issue #2368).
//!
//! DP previously awaited listener JoinHandles sequentially after pushing the
//! long-lived TLS revision bridge first. A later listener panic stayed invisible
//! while the earlier pending handle blocked. These tests drive
//! [`ferrum_edge::modes::data_plane::await_dp_listener_handles`] with a pending
//! handle before a panicking/failing handle and keep a bridge-like task off the
//! supervised set.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ferrum_edge::_test_support::await_dp_listener_handles;

#[tokio::test]
async fn await_dp_listener_handles_observes_later_panic_while_earlier_listener_pending() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    // Bridge stand-in: lives until shared shutdown. Must NOT be in the
    // supervised listener set — sequential join of [bridge, ..., panicker]
    // was the production bug.
    let mut bridge_rx = shutdown_tx.subscribe();
    let bridge_finished = Arc::new(AtomicBool::new(false));
    let bridge_finished_flag = bridge_finished.clone();
    let bridge = tokio::spawn(async move {
        loop {
            if bridge_rx.changed().await.is_err() {
                break;
            }
            if *bridge_rx.borrow() {
                break;
            }
        }
        bridge_finished_flag.store(true, Ordering::SeqCst);
    });

    let mut pending_rx = shutdown_tx.subscribe();
    let pending = tokio::spawn(async move {
        let _ = pending_rx.changed().await;
    });

    let panicker = tokio::spawn(async {
        panic!("later DP listener crash");
    });

    let started = Instant::now();
    let result = await_dp_listener_handles(vec![pending, panicker], shutdown_tx).await;
    let elapsed = started.elapsed();

    let err = result.expect_err("later listener panic must surface while earlier listener pending");
    assert!(
        err.is_panic(),
        "JoinError should report panic for the crashed listener; got {err:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "panic must be observed promptly via concurrent supervision; took {elapsed:?}"
    );

    tokio::time::timeout(Duration::from_secs(1), bridge)
        .await
        .expect("bridge should observe shared shutdown after listener panic")
        .expect("bridge task should join cleanly");
    assert!(
        bridge_finished.load(Ordering::SeqCst),
        "bridge must drain via the panic-triggered shared shutdown"
    );
}

#[tokio::test]
async fn await_dp_listener_handles_drains_siblings_on_clean_external_shutdown() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut listener_a_rx = shutdown_tx.subscribe();
    let listener_a = tokio::spawn(async move {
        let _ = listener_a_rx.changed().await;
    });
    let mut listener_b_rx = shutdown_tx.subscribe();
    let listener_b = tokio::spawn(async move {
        let _ = listener_b_rx.changed().await;
    });

    let trigger = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = trigger.send(true);
    });

    let started = Instant::now();
    await_dp_listener_handles(vec![listener_a, listener_b], shutdown_tx)
        .await
        .expect("clean external shutdown must not surface a JoinError");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "external shutdown should drain listeners promptly; took {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn await_dp_listener_handles_waits_on_shutdown_when_no_listeners() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let trigger = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = trigger.send(true);
    });

    let started = Instant::now();
    await_dp_listener_handles(Vec::new(), shutdown_tx)
        .await
        .expect("empty listener set should return Ok after shutdown");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "empty supervision should unblock on shutdown; took {:?}",
        started.elapsed()
    );
}

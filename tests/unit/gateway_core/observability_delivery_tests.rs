//! Delivery lifecycle generations across in-process serving cycles (issue #3027).
//!
//! A drained delivery lifecycle is terminal by design: task and worker
//! admission stay closed and the bounded drain report stays cached so late
//! producers cannot reopen work behind a shutting-down process. In-process
//! callers that start, stop, and start the gateway again therefore need a
//! *fresh* generation, which `DeliverySlot::begin_cycle` installs.
//!
//! These regressions drive an owned [`DeliverySlot`] rather than the
//! process-global one. The serving-mode entry points call
//! `observability_delivery::begin_serving_cycle()`, which is the same
//! `begin_cycle` state machine on the process-global slot; driving an owned
//! slot keeps this coverage from closing global delivery admission out from
//! under the other tests in this binary, which run in parallel and register
//! real queue workers.

use std::sync::Arc;
use std::time::Duration;

use ferrum_edge::observability_delivery::{DeliverySlot, DeliveryWorkerControl};
use tokio::sync::Notify;

/// A queue worker that finishes cleanly as soon as admission closes.
fn spawn_draining_worker(plugin_name: &'static str) -> Arc<DeliveryWorkerControl> {
    let (worker, mut close_rx) = DeliveryWorkerControl::new(plugin_name, || 0);
    let completion = worker.completion();
    let task = tokio::spawn(async move {
        let mut completion = completion;
        if !*close_rx.borrow() {
            let _ = close_rx.changed().await;
        }
        completion.complete();
    });
    worker
        .install_abort_handle(task.abort_handle())
        .expect("worker abort handle installs once");
    drop(task);
    worker
}

/// A queue worker that never drains, holding `pending` unflushed records.
fn spawn_stuck_worker(plugin_name: &'static str, pending: u64) -> Arc<DeliveryWorkerControl> {
    let (worker, _close_rx) = DeliveryWorkerControl::new(plugin_name, move || pending);
    let completion = worker.completion();
    let task = tokio::spawn(async move {
        let _completion = completion;
        std::future::pending::<()>().await;
    });
    worker
        .install_abort_handle(task.abort_handle())
        .expect("worker abort handle installs once");
    drop(task);
    worker
}

#[tokio::test]
async fn second_serving_cycle_reopens_task_admission_after_a_completed_drain() {
    let slot = DeliverySlot::new(0);

    let first_generation = slot.begin_cycle();
    assert!(
        slot.spawn_terminal(async {}),
        "first serving cycle must admit terminal work"
    );
    assert!(
        slot.shutdown(Duration::from_secs(5)).await.complete(),
        "first drain must complete"
    );
    assert!(
        !slot.spawn_terminal(async {}),
        "a drained generation must stay closed to late producers"
    );

    let second_generation = slot.begin_cycle();
    assert_ne!(
        second_generation, first_generation,
        "a serving cycle after a drain must open a fresh generation"
    );
    assert!(
        slot.spawn_terminal(async {}),
        "second serving cycle must admit terminal work again"
    );
    assert!(
        slot.spawn_deadline_cleanup(async {}),
        "second serving cycle must admit deadline cleanup again"
    );
    assert!(
        slot.spawn_mirror(async {}),
        "second serving cycle must admit internal mirror work again"
    );

    assert!(
        slot.shutdown(Duration::from_secs(5)).await.complete(),
        "second drain must complete on its own generation"
    );
}

#[tokio::test]
async fn second_serving_cycle_reopens_worker_admission_after_a_completed_drain() {
    let slot = DeliverySlot::new(0);

    slot.begin_cycle();
    let first_worker = spawn_draining_worker("first_cycle_sink");
    slot.register_worker(Arc::clone(&first_worker));
    let first_report = slot.shutdown(Duration::from_secs(5)).await;
    assert!(first_report.complete(), "first worker drain must complete");
    assert!(first_worker.is_finished());

    // Without a fresh generation this registration is rejected and aborted.
    slot.begin_cycle();
    let second_worker = spawn_draining_worker("second_cycle_sink");
    slot.register_worker(Arc::clone(&second_worker));
    assert!(
        second_worker.accepting(),
        "worker registered in the second serving cycle must keep admitting records"
    );
    assert!(!second_worker.is_finished());

    let second_report = slot.shutdown(Duration::from_secs(5)).await;
    assert!(
        second_report.complete(),
        "second worker drain must complete"
    );
    assert!(second_worker.is_finished());
    assert_eq!(second_report.lost_worker_records, 0);
}

#[tokio::test]
async fn each_serving_cycle_reports_its_own_drain_instead_of_the_cached_one() {
    let slot = DeliverySlot::new(0);

    slot.begin_cycle();
    slot.register_worker(spawn_stuck_worker("stuck_sink", 3));
    let first_report = slot.shutdown(Duration::from_millis(50)).await;
    assert!(!first_report.complete());
    assert_eq!(first_report.lost_worker_records, 3);

    slot.begin_cycle();
    let worker = spawn_draining_worker("clean_sink");
    slot.register_worker(Arc::clone(&worker));
    let second_report = slot.shutdown(Duration::from_secs(5)).await;
    assert!(
        second_report.complete(),
        "the second cycle must not inherit the first cycle's cached drain report"
    );
    assert_eq!(second_report.lost_worker_records, 0);
    assert!(worker.is_finished());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cycle_started_mid_drain_is_not_admitted_into_or_closed_by_the_old_generation() {
    let slot = Arc::new(DeliverySlot::new(0));
    let first_generation = slot.begin_cycle();

    let release = Arc::new(Notify::new());
    let started = Arc::new(Notify::new());
    let task_release = Arc::clone(&release);
    let task_started = Arc::clone(&started);
    let admitted = slot.spawn_terminal(async move {
        task_started.notify_one();
        task_release.notified().await;
    });
    assert!(admitted, "first cycle must admit blocking terminal work");
    started.notified().await;

    let drain_slot = Arc::clone(&slot);
    let drain = tokio::spawn(async move { drain_slot.shutdown(Duration::from_secs(10)).await });

    // The old generation stops admitting external work as soon as its drain
    // starts. Wait for that edge so the new cycle below genuinely starts
    // mid-drain rather than before it.
    while slot.spawn_terminal(async {}) {
        tokio::task::yield_now().await;
    }

    let second_generation = slot.begin_cycle();
    assert_ne!(
        second_generation, first_generation,
        "a cycle starting while the previous generation drains must get a fresh generation"
    );
    assert!(
        slot.spawn_terminal(async {}),
        "the new generation must admit terminal work while the old one drains"
    );
    let worker = spawn_draining_worker("mid_drain_sink");
    slot.register_worker(Arc::clone(&worker));
    assert!(worker.accepting());

    release.notify_one();
    let first_report = drain.await.expect("drain task must join");
    assert!(
        first_report.complete(),
        "the old generation must drain cleanly"
    );

    // The stale generation's cleanup must not have closed the new generation.
    assert!(
        worker.accepting() && !worker.is_finished(),
        "a stale generation drain must not close the current generation's worker"
    );
    assert!(
        slot.spawn_terminal(async {}),
        "a stale generation drain must not close current task admission"
    );

    let second_report = slot.shutdown(Duration::from_secs(5)).await;
    assert!(second_report.complete());
    assert!(worker.is_finished());
    assert_eq!(second_report.lost_worker_records, 0);
}

#[tokio::test]
async fn begin_cycle_is_idempotent_while_the_generation_stays_open() {
    let slot = DeliverySlot::new(0);
    let generation = slot.begin_cycle();

    let worker = spawn_draining_worker("reentrant_sink");
    slot.register_worker(Arc::clone(&worker));

    assert_eq!(
        slot.begin_cycle(),
        generation,
        "re-entering an open cycle must not orphan already registered workers"
    );
    assert_eq!(slot.current_generation(), generation);
    assert!(worker.accepting());

    assert!(slot.shutdown(Duration::from_secs(5)).await.complete());
    assert!(worker.is_finished());
}

#[tokio::test]
async fn reinitialize_does_not_orphan_an_open_generation() {
    let slot = DeliverySlot::new(0);
    let generation = slot.begin_cycle();
    let worker = spawn_draining_worker("reinitialized_sink");
    slot.register_worker(Arc::clone(&worker));

    slot.initialize(32);

    assert_eq!(
        slot.current_generation(),
        generation,
        "changing the future shard override must preserve the open generation"
    );
    assert!(
        worker.accepting() && !worker.is_finished(),
        "reinitialization must not orphan a worker registered in the open generation"
    );

    assert!(slot.shutdown(Duration::from_secs(5)).await.complete());
    assert!(worker.is_finished());
    assert_ne!(
        slot.begin_cycle(),
        generation,
        "the updated override must take effect through a fresh post-drain generation"
    );
}

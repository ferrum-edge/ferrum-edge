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
use tokio::sync::{Notify, Semaphore};

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

/// Issue #3028: hold the task budget open, attempt far more admissions than the
/// cap, prove registry/permit counts stay bounded, observe rejects, then confirm
/// permits release so later work can admit again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_budget_caps_terminal_mirror_and_deadline_cleanup_admissions() {
    const BUDGET: usize = 8;
    const OVERFLOW: usize = 256;

    let slot = DeliverySlot::with_limits(0, BUDGET);
    slot.begin_cycle();
    assert_eq!(slot.max_tasks(), BUDGET);

    // Counting/closable semaphores rather than `Notify`: `notify_one` permits
    // saturate at one and `notify_waiters` only reaches waiters that already
    // registered, so several concurrently held tasks lose wakeups and this
    // regression would hang instead of failing.
    let release = Arc::new(Semaphore::new(0));
    let started = Arc::new(Semaphore::new(0));

    // Fill the aggregate budget with a mix of kinds so one kind cannot bypass
    // the shared registry cap.
    for kind in 0..BUDGET {
        let task_release = Arc::clone(&release);
        let task_started = Arc::clone(&started);
        let future = async move {
            task_started.add_permits(1);
            let _ = task_release.acquire().await;
        };
        let admitted = match kind % 3 {
            0 => slot.spawn_terminal(future),
            1 => slot.spawn_mirror(future),
            _ => slot.spawn_deadline_cleanup(future),
        };
        assert!(admitted, "budget fill admission {kind} must succeed");
    }

    started
        .acquire_many(BUDGET as u32)
        .await
        .expect("every held task reports started")
        .forget();

    assert_eq!(slot.active_tasks(), BUDGET);
    assert_eq!(slot.admitted_tasks(), BUDGET as u64);

    let rejected_before = slot.rejected_tasks();
    let mut overflow_rejects = 0u64;
    for i in 0..OVERFLOW {
        let admitted = match i % 3 {
            0 => slot.spawn_terminal(async {}),
            1 => slot.spawn_mirror(async {}),
            _ => slot.spawn_deadline_cleanup(async {}),
        };
        assert!(
            !admitted,
            "overflow admission {i} must reject once the budget is held open"
        );
        overflow_rejects += 1;
        assert!(
            slot.active_tasks() <= BUDGET,
            "registry must stay within the configured budget"
        );
        assert!(
            slot.admitted_tasks() <= BUDGET as u64,
            "admission permits must stay within the configured budget"
        );
    }

    assert_eq!(slot.active_tasks(), BUDGET);
    assert_eq!(slot.admitted_tasks(), BUDGET as u64);
    assert_eq!(
        slot.rejected_tasks(),
        rejected_before + overflow_rejects,
        "capacity rejects must remain observable without spawning more deferred work"
    );

    release.close();

    // Wait for held tasks to finish and release permits.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while slot.admitted_tasks() != 0 || slot.active_tasks() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "held tasks must release permits after completion"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert_eq!(slot.rejected_tasks(), rejected_before + overflow_rejects);

    let refill_release = Arc::new(Semaphore::new(0));
    let refill_started = Arc::new(Semaphore::new(0));
    for i in 0..BUDGET {
        let task_release = Arc::clone(&refill_release);
        let task_started = Arc::clone(&refill_started);
        assert!(
            slot.spawn_terminal(async move {
                task_started.add_permits(1);
                let _ = task_release.acquire().await;
            }),
            "permit release must reopen admission up to the budget (slot {i})"
        );
    }
    refill_started
        .acquire_many(BUDGET as u32)
        .await
        .expect("every refilled task reports started")
        .forget();
    assert_eq!(slot.admitted_tasks(), BUDGET as u64);
    assert!(
        !slot.spawn_terminal(async {}),
        "budget must still reject once refilled"
    );
    refill_release.close();
    assert!(
        slot.shutdown(Duration::from_secs(5)).await.complete(),
        "bounded admission must not disturb the shutdown drain deadline"
    );
}

/// Issue #3028 / GHSA-83h5-52mw-f33p: budget exhaustion must be distinguishable
/// from the closed-admission rejects that happen normally at shutdown, or the
/// aggregate reject counter cannot be alerted on for capacity at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capacity_rejects_are_counted_separately_from_closed_admission_rejects() {
    const BUDGET: usize = 2;

    let slot = DeliverySlot::with_limits(0, BUDGET);
    slot.begin_cycle();
    assert_eq!(slot.capacity_rejected_tasks(), 0);

    let release = Arc::new(Semaphore::new(0));
    let started = Arc::new(Semaphore::new(0));
    for i in 0..BUDGET {
        let task_release = Arc::clone(&release);
        let task_started = Arc::clone(&started);
        assert!(
            slot.spawn_terminal(async move {
                task_started.add_permits(1);
                let _ = task_release.acquire().await;
            }),
            "budget fill admission {i} must succeed"
        );
    }
    started
        .acquire_many(BUDGET as u32)
        .await
        .expect("every held task reports started")
        .forget();

    // Overflow while the budget is held: both the aggregate and the
    // budget-specific counter advance together.
    for _ in 0..5 {
        assert!(!slot.spawn_mirror(async {}));
    }
    assert_eq!(slot.capacity_rejected_tasks(), 5);
    assert_eq!(slot.rejected_tasks(), 5);

    release.close();
    assert!(
        slot.shutdown(Duration::from_secs(5)).await.complete(),
        "held tasks release on close so the drain completes"
    );

    // Post-drain admission is closed, not exhausted: the aggregate counter
    // advances while the capacity counter stays put.
    let capacity_after_drain = slot.capacity_rejected_tasks();
    let rejected_after_drain = slot.rejected_tasks();
    for _ in 0..4 {
        assert!(!slot.spawn_terminal(async {}));
    }
    assert_eq!(
        slot.capacity_rejected_tasks(),
        capacity_after_drain,
        "closed-admission rejects must not be attributed to the task budget"
    );
    assert_eq!(slot.rejected_tasks(), rejected_after_drain + 4);
}

#[tokio::test]
async fn task_budget_override_applies_to_the_next_generation() {
    let slot = DeliverySlot::with_limits(0, 4);
    let first = slot.begin_cycle();
    assert_eq!(slot.max_tasks(), 4);

    slot.initialize_with_limits(0, 2);
    assert_eq!(
        slot.current_generation(),
        first,
        "open generations keep their existing budget"
    );
    assert_eq!(slot.max_tasks(), 4);

    assert!(slot.shutdown(Duration::from_secs(5)).await.complete());
    let second = slot.begin_cycle();
    assert_ne!(second, first);
    assert_eq!(
        slot.max_tasks(),
        2,
        "the updated task budget must take effect on the fresh generation"
    );
}

/// A mirror admitted at the drain boundary must be drained (or cancelled and
/// counted), never left running behind a `tasks_drained` report.
///
/// A straggler request's inline `log_with_mirror` spawns mirror work through
/// internal admission, which stays open while the drain waits for terminal
/// work. The old lifecycle closed internal admission only after its single
/// task wait had already observed an empty registry. A `spawn_mirror` that
/// registered in that window was admitted (`spawn_mirror` returned `true`),
/// yet shutdown reported `complete()` before that mirror ran. That task was
/// neither awaited nor cancelled, so on process exit its record was lost
/// without being counted. The old wait also checked the registry before the
/// registration count, so a spawn that inserted and deregistered between the
/// two reads was missed the same way.
///
/// The window is a few instructions wide and only another thread can land in
/// it, so this races a mirror producer against many independent drains. The
/// producer waits for the registry to look empty, which is the moment the
/// drain re-checks it, then spawns after a varying delay. Each drain asserts
/// the invariant itself: every mirror admitted at any point had finished when
/// its complete report was returned. The phase machine closes internal
/// admission before a second, final wait, so no iteration can break it.
#[test]
fn a_mirror_admitted_at_the_drain_boundary_is_never_left_behind_a_drained_report() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const ITERATIONS: usize = 1_000;
    const MAX_MIRRORS_PER_ITERATION: usize = 256;
    const MAX_EMPTY_WAIT: Duration = Duration::from_millis(1);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime builds");

    for iteration in 0..ITERATIONS {
        let slot = Arc::new(DeliverySlot::new(0));
        let producer_started = Arc::new(AtomicBool::new(false));
        let admitted = Arc::new(AtomicU64::new(0));
        let finished = Arc::new(AtomicU64::new(0));

        let producer = {
            let slot = Arc::clone(&slot);
            let handle = runtime.handle().clone();
            let producer_started = Arc::clone(&producer_started);
            let admitted = Arc::clone(&admitted);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                // Spawning needs a runtime context; the producer stands in for
                // a request task finishing on another worker.
                let _entered = handle.enter();
                for attempt in 0..MAX_MIRRORS_PER_ITERATION {
                    let mirror_finished = Arc::clone(&finished);
                    let accepted = slot.spawn_mirror(async move {
                        tokio::task::yield_now().await;
                        mirror_finished.fetch_add(1, Ordering::SeqCst);
                    });
                    producer_started.store(true, Ordering::Release);
                    if !accepted {
                        // Internal admission closed: every later spawn is
                        // rejected and counted, so stop producing.
                        return;
                    }
                    admitted.fetch_add(1, Ordering::SeqCst);
                    // Line the next spawn up with the drain's emptiness
                    // check: wait for the registry to drain, then vary the
                    // delay so the registration lands at different offsets
                    // from that check.
                    let empty_wait = std::time::Instant::now();
                    while slot.active_tasks() != 0 && empty_wait.elapsed() < MAX_EMPTY_WAIT {
                        std::hint::spin_loop();
                    }
                    for _ in 0..((attempt % 32) * 8) {
                        std::hint::spin_loop();
                    }
                }
            })
        };
        while !producer_started.load(Ordering::Acquire) {
            std::thread::yield_now();
        }

        let (report, finished_at_report) = runtime.block_on(async {
            let report = slot.shutdown(Duration::from_secs(10)).await;
            // Sampled as the report is returned: a mirror the drain left
            // behind has not run yet.
            (report, finished.load(Ordering::SeqCst))
        });
        producer.join().expect("mirror producer joins");

        assert!(
            report.complete(),
            "iteration {iteration}: the bounded producer must let the drain finish in budget"
        );
        assert_eq!(
            finished_at_report,
            admitted.load(Ordering::SeqCst),
            "iteration {iteration}: every admitted mirror must finish before a complete drain returns"
        );
    }
}

//! Kubernetes controller shutdown supervision (issue #3220).
//!
//! CP mode used to keep the controller handle in an underscore-prefixed local
//! and drop it at the end of `run()`, which *detaches* the watcher, reconciler,
//! and CRD reprobe tasks instead of awaiting them; the old `join()` also threw
//! away every `JoinError`, and the CRD reprobe loop dropped the handles of the
//! replacement watchers it created, so those were never owned at all.
//!
//! These tests drive the real `ControllerTaskRegistry` + `K8sControllerHandle`
//! shutdown path with synthetic tasks (no Kubernetes API server required).
//! Registration goes through the same production `spawn_named` lifecycle
//! wrapper the watchers, reconciler, and reprobe loop use, so there is no
//! parallel mock classifier: delayed clean exit, panic propagation,
//! grace-deadline abort with a confirmed terminal drop, completion-boundary
//! early-exit classification under the real control-plane ordering, dynamic
//! (reprobe-style) registration, and refusal once shutdown closed the registry.
//!
//! Panic-inducing tests are `panic = "unwind"` only (issue #4166).
//!
//! Every test runs on the default `#[tokio::test]` current-thread runtime, so
//! task interleaving is deterministic instead of depending on a multi-thread
//! scheduler happening to poll in a particular order.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferrum_edge::_test_support::k8s_controller_registry_for_test;
use tokio::sync::{oneshot, watch};

/// Records that a task's future was actually dropped, which is what
/// distinguishes an aborted-and-joined task from a detached one.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A controller task that observes shutdown and then returns.
async fn run_until_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

/// A task that takes time to unwind after observing shutdown must be awaited,
/// not detached: `shutdown()` may not return before the task has exited.
#[tokio::test]
async fn shutdown_awaits_task_that_exits_after_a_delay() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();
    let exited = Arc::new(AtomicBool::new(false));

    let task_exited = exited.clone();
    let task_shutdown = shutdown_tx.subscribe();
    let watcher = async move {
        run_until_shutdown(task_shutdown).await;
        // Simulate a watcher finishing an in-flight status write before it
        // returns. A detached task would still be here when the caller moved on.
        tokio::time::sleep(Duration::from_millis(150)).await;
        task_exited.store(true, Ordering::SeqCst);
    };
    assert!(registry.spawn("crd-watcher/Pod", shutdown_tx.subscribe(), watcher));

    let outcome = registry
        .handle()
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert!(
        exited.load(Ordering::SeqCst),
        "shutdown() returned before the controller task finished"
    );
    assert!(outcome.is_clean(), "unexpected outcome: {outcome:?}");
    assert_eq!(outcome.completed, vec!["crd-watcher/Pod#0".to_string()]);
    assert!(outcome.failure_error().is_none());
    // shutdown() owns the signalling, so the channel is closed out even when
    // the caller had not already fired it.
    assert!(*shutdown_tx.borrow());
    assert!(registry.is_closed());
}

/// A panicking controller task must be reported, not silently discarded the way
/// the old `let _ = handle.await` did. Unwind-only (issue #4166).
#[cfg(panic = "unwind")]
#[tokio::test]
async fn shutdown_surfaces_a_panicked_controller_task() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();

    let clean = run_until_shutdown(shutdown_tx.subscribe());
    assert!(registry.spawn("crd-watcher/Pod", shutdown_tx.subscribe(), clean));

    let panicking_shutdown = shutdown_tx.subscribe();
    let panicking = async move {
        run_until_shutdown(panicking_shutdown).await;
        panic!("reconciler blew up during shutdown");
    };
    assert!(registry.spawn("reconciler", shutdown_tx.subscribe(), panicking));

    let outcome = registry
        .handle()
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert!(!outcome.is_clean(), "panic was reported as a clean exit");
    assert_eq!(outcome.failed.len(), 1, "unexpected outcome: {outcome:?}");
    assert_eq!(outcome.failed[0].task, "reconciler#1");
    assert!(outcome.failed[0].panicked);
    // The sibling is still awaited rather than short-circuited by the panic.
    assert_eq!(outcome.completed, vec!["crd-watcher/Pod#0".to_string()]);
    assert!(outcome.timed_out.is_empty());
    assert!(outcome.abort_unconfirmed.is_empty());
    assert!(outcome.exited_before_shutdown.is_empty());

    let err = outcome
        .failure_error()
        .expect("panicked task must produce an error for run() to propagate");
    assert!(err.to_string().contains("reconciler#1"), "error: {err}");
}

/// A task that ignores shutdown is bounded by the grace period and then
/// *aborted*, and the abort is settled before `shutdown()` returns. Dropping
/// its `JoinHandle` instead would detach it, so the test asserts the task's
/// future was already dropped by the time the call returned — no polling.
#[tokio::test]
async fn shutdown_aborts_a_task_still_running_at_the_grace_deadline() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();
    let dropped = Arc::new(AtomicBool::new(false));

    let flag = dropped.clone();
    let stuck = async move {
        let _guard = DropFlag(flag);
        // Deliberately never observes the shutdown channel.
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    assert!(registry.spawn("crd-reprobe", shutdown_tx.subscribe(), stuck));

    let outcome = registry
        .handle()
        .shutdown(&shutdown_tx, Duration::from_millis(150))
        .await;

    assert_eq!(outcome.timed_out, vec!["crd-reprobe#0".to_string()]);
    assert!(!outcome.is_clean());
    // A stuck task is an operational warning, not a process-failing defect.
    assert!(outcome.failure_error().is_none());
    assert!(outcome.failed.is_empty(), "unexpected: {outcome:?}");
    assert!(outcome.exited_before_shutdown.is_empty());
    // The abort-settle phase joined the aborted task, so its termination is an
    // established happens-before boundary rather than a hope.
    assert!(
        outcome.abort_unconfirmed.is_empty(),
        "abort should have settled well inside the budget: {outcome:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "timed-out controller task was detached instead of aborted and joined"
    );
}

/// Regression test for the completion-boundary race.
///
/// A watcher whose stream ended returns while the shutdown watch is still
/// `false`; the global watch then flips long before the controller handle is
/// torn down, which is the real control-plane ordering. Any classifier that
/// samples the watch *after* the task's own return — a separate supervisor task
/// awaiting an already-spawned `JoinHandle`, `is_finished()`, a teardown-time
/// scan — reads the post-flip `true` and misreports a silently dead watcher as
/// a clean shutdown. The scheduler is spun between the flip and teardown here
/// precisely so such a late sampler would have run; the assertion holds only
/// because the value was recorded inside the task itself.
#[tokio::test]
async fn early_exit_is_latched_at_the_completion_boundary_not_at_teardown() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();

    let (exited_tx, exited_rx) = oneshot::channel();
    let early = async move {
        // Returns during *normal* operation. The notification is sent from
        // inside the task, so the test cannot flip the watch before the
        // lifecycle wrapper reads it.
        let _ = exited_tx.send(());
    };
    assert!(registry.spawn("crd-watcher/Pod", shutdown_tx.subscribe(), early));

    let running = run_until_shutdown(shutdown_tx.subscribe());
    assert!(registry.spawn("reconciler", shutdown_tx.subscribe(), running));

    // The handle is built while the controller is still running normally,
    // exactly as `start_k8s_controller` builds it.
    let controller = registry.handle();

    exited_rx.await.expect("early watcher signalled its exit");
    shutdown_tx.shutdown();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_secs(5))
        .await;

    assert_eq!(
        outcome.exited_before_shutdown,
        vec!["crd-watcher/Pod#0".to_string()],
        "unexpected outcome: {outcome:?}"
    );
    assert!(!outcome.is_clean());
    assert!(outcome.failed.is_empty());
    assert!(outcome.timed_out.is_empty());
    assert!(outcome.abort_unconfirmed.is_empty());
    // The task that was still running when shutdown fired is the only clean
    // completion; the early exit is not double-counted as one.
    assert_eq!(outcome.completed, vec!["reconciler#1".to_string()]);

    // A silently dead controller is degraded service, so it fails the process
    // rather than only logging a warning.
    let err = outcome
        .failure_error()
        .expect("an early controller exit must fail the process");
    assert!(
        err.to_string().contains("crd-watcher/Pod#0"),
        "error should name the dead task: {err}"
    );
}

/// Watchers the CRD reprobe loop creates after startup must transfer into
/// controller-handle ownership. They used to be spawned and dropped on the
/// floor, so a replacement watcher stayed live past control-plane teardown with
/// no terminal join boundary — the exact defect class #3220 closes.
#[tokio::test]
async fn shutdown_owns_and_drains_watchers_registered_after_the_handle_exists() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();
    let controller = registry.handle();

    let watcher_dropped = Arc::new(AtomicBool::new(false));
    let (registered_tx, registered_rx) = oneshot::channel();

    let flag = watcher_dropped.clone();
    let dynamic_watcher = async move {
        let _guard = DropFlag(flag);
        // Ignores shutdown, so only real ownership can end it.
        std::future::pending::<()>().await;
    };

    // Stand-in for the CRD reprobe loop calling `start_crd_watchers` again once
    // a CRD group appears: it registers into the same registry the handle owns.
    let reprobe_registry = registry.clone();
    let reprobe_watcher_shutdown = shutdown_tx.subscribe();
    let reprobe = async move {
        let accepted = reprobe_registry.spawn(
            "crd-watcher-reprobe/HTTPRoute",
            reprobe_watcher_shutdown,
            dynamic_watcher,
        );
        let _ = registered_tx.send(accepted);
        std::future::pending::<()>().await;
    };
    assert!(registry.spawn("crd-reprobe", shutdown_tx.subscribe(), reprobe));

    assert!(
        registered_rx.await.expect("reprobe reported registration"),
        "a running controller must accept a dynamically created watcher"
    );

    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_millis(150))
        .await;

    assert_eq!(
        outcome.timed_out,
        vec![
            "crd-reprobe#0".to_string(),
            "crd-watcher-reprobe/HTTPRoute#1".to_string(),
        ],
        "the dynamically registered watcher must share the one grace budget \
         and be reported in registration order: {outcome:?}"
    );
    assert!(
        outcome.abort_unconfirmed.is_empty(),
        "both aborts should have settled inside the budget: {outcome:?}"
    );
    assert!(
        watcher_dropped.load(Ordering::SeqCst),
        "the reprobe-created watcher was still live when shutdown() returned"
    );
}

/// The other half of the reprobe race: once shutdown has closed the registry, a
/// probe still in flight is refused *before* its watcher is spawned, so there is
/// no window in which a just-created watcher exists without an owner.
#[tokio::test]
async fn shutdown_refuses_watchers_a_racing_reprobe_tries_to_register() {
    let (shutdown_tx, _keep_open) =
        ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(30));
    let registry = k8s_controller_registry_for_test();
    let controller = registry.handle();

    let outcome = controller
        .shutdown(&shutdown_tx, Duration::from_millis(50))
        .await;
    assert!(outcome.is_clean(), "unexpected outcome: {outcome:?}");
    assert!(registry.is_closed());

    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    let late_watcher = async move {
        flag.store(true, Ordering::SeqCst);
    };
    let accepted = registry.spawn(
        "crd-watcher-reprobe/Gateway",
        shutdown_tx.subscribe(),
        late_watcher,
    );

    assert!(!accepted, "a closed registry must refuse new tasks");
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        !ran.load(Ordering::SeqCst),
        "a refused task must never be spawned, so nothing can be left detached"
    );
}

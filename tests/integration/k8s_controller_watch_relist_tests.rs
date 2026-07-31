//! Recovery from a silently stale Kubernetes watch.
//!
//! A kube-rs `watcher` reports an error only when the watch *fails*. A watch
//! whose connection is black-holed (no FIN, no RST, no GOAWAY) never fails: the
//! task stays alive, the reflector store keeps serving whatever it held when
//! delivery stopped, and every object created from then on is simply absent
//! from every reconcile snapshot. That is what a Gateway API conformance run
//! saw — four TCPRoutes existed in the cluster while the controller reconciled
//! happily against a store that never received them — and
//! `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` could not help, because it
//! re-reconciles that same stale store rather than re-listing Kubernetes.
//!
//! These tests drive the production watcher task
//! (`k8s_controller::watcher::run_watcher_generations`) over scripted reflector
//! generations, so the real reflector `Store`, the real `ResourceStoreSet`, and
//! the real `snapshot_all` the reconciler reads are all in the loop. They run on
//! `start_paused` virtual time: the runtime advances to the next pending timer
//! only once every task is idle, so the idle relist fires deterministically
//! instead of racing a wall clock.

use std::time::Duration;

use ferrum_edge::_test_support::{K8sWatchScopeForTest, k8s_watch_scope_for_test};
use kube::runtime::watcher::Event;
use tokio::sync::watch;

const GROUP: &str = "gateway.networking.k8s.io";
const VERSION: &str = "v1alpha2";
const KIND: &str = "TCPRoute";
const PLURAL: &str = "tcproutes";
const NAMESPACE: &str = "gateway-conformance-infra";
const SCOPE: &str = "namespace:gateway-conformance-infra";
const IDLE_RELIST_SECS: u64 = 60;

/// Long enough to cross the idle window plus its deterministic per-scope jitter,
/// which is bounded by a quarter of the window.
const PAST_IDLE_WINDOW: Duration = Duration::from_secs(IDLE_RELIST_SECS * 2);

/// Short enough that it can never reach an idle deadline. Under `start_paused`
/// this just lets the watcher task run to its next suspension point.
const SETTLE: Duration = Duration::from_millis(50);

fn scope(
    generations: usize,
    idle_relist_secs: u64,
    shutdown: watch::Receiver<bool>,
) -> (K8sWatchScopeForTest, impl std::future::Future<Output = ()>) {
    k8s_watch_scope_for_test(
        GROUP,
        VERSION,
        KIND,
        PLURAL,
        SCOPE,
        idle_relist_secs,
        generations,
        shutdown,
    )
}

/// Complete one generation's initial list carrying `names`.
fn list(harness: &K8sWatchScopeForTest, generation: usize, names: &[&str]) {
    harness.emit(generation, Event::Init);
    for name in names {
        let object = harness.object(NAMESPACE, name);
        harness.emit(generation, Event::InitApply(object));
    }
    harness.emit(generation, Event::InitDone);
}

/// Deliver a post-list update for `name` on the live generation.
fn apply(harness: &K8sWatchScopeForTest, generation: usize, name: &str) {
    let object = harness.object(NAMESPACE, name);
    harness.emit(generation, Event::Apply(object));
}

/// The conformance failure, reproduced and then repaired: generation 0 lists an
/// empty namespace and then goes silent forever while objects are created in
/// Kubernetes. Nothing errors, so nothing restarts the watch — until the idle
/// window expires and the scope relists.
#[tokio::test(start_paused = true)]
async fn idle_watch_relists_and_discovers_objects_it_never_received() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(2, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    // Generation 0: the namespace is empty when the controller starts.
    list(&harness, 0, &[]);
    tokio::time::sleep(SETTLE).await;
    assert!(
        harness.visible_names().await.is_empty(),
        "an empty initial list must leave the scope empty"
    );

    // The four TCPRoutes are created in Kubernetes and the watch delivers
    // nothing at all — the failure mode. Re-reconciling cannot help.
    tokio::time::sleep(PAST_IDLE_WINDOW).await;

    // The idle relist rebuilt the reflector; its authoritative list carries the
    // objects the dead watch never delivered.
    let created = [
        "blackbox-tcp-main",
        "blackbox-tcp-cross",
        "blackbox-tcp-fail",
        "blackbox-tcp-delete",
    ];
    list(&harness, 1, &created);
    tokio::time::sleep(SETTLE).await;

    assert_eq!(
        harness.visible_names().await,
        vec![
            "blackbox-tcp-cross",
            "blackbox-tcp-delete",
            "blackbox-tcp-fail",
            "blackbox-tcp-main",
        ],
        "the relisted generation must make the missed objects visible"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// Make-before-break: the replacement generation must not become visible until
/// its initial list is complete, and the previous generation's objects must stay
/// visible the whole time. A gap here would look to the reconciler exactly like
/// every object being deleted, and would broadcast a config wipe to the data
/// planes before the relist finished.
#[tokio::test(start_paused = true)]
async fn relist_never_exposes_an_empty_or_partial_generation() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(2, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(harness.visible_names().await, vec!["blackbox-tcp-main"]);

    tokio::time::sleep(PAST_IDLE_WINDOW).await;

    // Generation 1 has started listing but has not finished. Its objects are
    // buffered inside its own writer.
    harness.emit(1, Event::Init);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-main"],
        "the previous generation must keep serving while the replacement lists"
    );

    for name in ["blackbox-tcp-main", "blackbox-tcp-cross"] {
        let object = harness.object(NAMESPACE, name);
        harness.emit(1, Event::InitApply(object));
    }
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-main"],
        "a half-listed replacement must not be visible to the reconciler"
    );

    harness.emit(1, Event::InitDone);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-cross", "blackbox-tcp-main"],
        "the replacement becomes visible atomically at InitDone"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// A relist is authoritative, so it must also retire objects deleted while the
/// watch was stale — the deletion half of the same staleness bug.
#[tokio::test(start_paused = true)]
async fn relist_retires_objects_deleted_while_the_watch_was_stale() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(2, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-delete", "blackbox-tcp-main"]);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-delete", "blackbox-tcp-main"]
    );

    tokio::time::sleep(PAST_IDLE_WINDOW).await;
    list(&harness, 1, &["blackbox-tcp-main"]);
    tokio::time::sleep(SETTLE).await;

    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-main"],
        "an object deleted during the stale window must be gone after the relist"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// A busy scope keeps its generation: events reset the idle deadline, so a
/// healthy watch never pays for a relist it does not need. Only generation 0 is
/// scripted here, so a relist would move the scope to a permanently silent
/// stream and the last update below would never land.
#[tokio::test(start_paused = true)]
async fn a_scope_that_keeps_delivering_events_is_never_relisted() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(1, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(IDLE_RELIST_SECS / 2)).await;
        apply(&harness, 0, "blackbox-tcp-main");
    }
    apply(&harness, 0, "blackbox-tcp-late");
    tokio::time::sleep(SETTLE).await;

    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-late", "blackbox-tcp-main"],
        "the original generation must still be the live one"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// `FERRUM_K8S_WATCH_IDLE_RELIST_SECS=0` opts out entirely: the watcher keeps
/// its generation no matter how long it stays silent.
#[tokio::test(start_paused = true)]
async fn idle_relist_can_be_disabled() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(1, 0, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    tokio::time::sleep(Duration::from_secs(3600)).await;

    // Generation 0 is still the live one, so its events still land.
    apply(&harness, 0, "blackbox-tcp-late");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-late", "blackbox-tcp-main"],
        "with relisting disabled the original watch generation stays live"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// A replacement generation that inherits the same black hole must not pin the
/// scope to its last-known-good state forever: it is abandoned after the
/// readiness timeout and another one is started, still make-before-break.
#[tokio::test(start_paused = true)]
async fn a_replacement_that_never_lists_is_retried_without_losing_the_last_good_store() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(3, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    // Generation 1 starts one idle window (plus jitter) from here and never
    // receives a single event: it inherits the same dead connection.
    tokio::time::sleep(PAST_IDLE_WINDOW).await;

    // The readiness timeout is two idle windows, so generation 1 is abandoned
    // and generation 2 started before this sleep ends.
    tokio::time::sleep(PAST_IDLE_WINDOW).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-main"],
        "an abandoned replacement must never blank the scope"
    );

    list(&harness, 2, &["blackbox-tcp-cross", "blackbox-tcp-main"]);
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        harness.visible_names().await,
        vec!["blackbox-tcp-cross", "blackbox-tcp-main"],
        "the retried replacement must recover the scope"
    );

    let _ = shutdown_tx.send(true);
    watcher.await.expect("watcher task");
}

/// Task ownership is unchanged by relisting: the watcher still observes the
/// shutdown watch and returns, including while a replacement is mid-list.
#[tokio::test(start_paused = true)]
async fn watcher_task_still_returns_on_shutdown_mid_relist() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(2, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    tokio::time::sleep(PAST_IDLE_WINDOW).await;
    harness.emit(1, Event::Init);
    tokio::time::sleep(SETTLE).await;

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), watcher)
        .await
        .expect("watcher must observe shutdown while relisting")
        .expect("watcher task");
}

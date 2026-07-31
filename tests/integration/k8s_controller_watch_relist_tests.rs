//! Recovery from a silently stale Kubernetes watch.
//!
//! A kube-rs `watcher` reports an error only when the watch *fails*. A watch
//! that stops delivering without failing never surfaces anything: the task
//! stays alive, the reflector store keeps serving whatever it held when
//! delivery stopped, and every object created from then on is simply absent
//! from every reconcile snapshot. A Gateway API conformance run produced
//! exactly that signature — four TCPRoutes existed in the cluster while the
//! controller reconciled happily against a store that never received them, with
//! no watcher error, restart, or status write for 120s — and
//! `FERRUM_K8S_FULL_SYNC_INTERVAL_SECS` could not help, because it
//! re-reconciles that same stale store rather than re-listing Kubernetes. The
//! artifact does not say where the event stream was lost, so these tests pin
//! the symptom (no event for a whole window) and the recovery, not a cause.
//!
//! These tests drive the production watcher task
//! (`k8s_controller::watcher::run_watcher_generations`) over scripted reflector
//! generations, so the real reflector `Store`, the real `ResourceStoreSet`, and
//! the real `snapshot_all` the reconciler reads are all in the loop. They run on
//! `start_paused` virtual time: the runtime advances to the next pending timer
//! only once every task is idle, so the idle relist fires deterministically
//! instead of racing a wall clock.

use std::time::Duration;

use ferrum_edge::_test_support::{
    K8sWatchScopeForTest, k8s_watch_idle_relist_jitter_millis as jitter_millis,
    k8s_watch_scope_for_test,
};
use kube::runtime::watcher::Event;
use tokio::sync::watch;

const GROUP: &str = "gateway.networking.k8s.io";
const VERSION: &str = "v1alpha2";
/// What the harness composes from `GROUP`/`VERSION`, and what the watcher hashes
/// for the per-scope jitter.
const API_VERSION: &str = "gateway.networking.k8s.io/v1alpha2";
const KIND: &str = "TCPRoute";
const PLURAL: &str = "tcproutes";
const NAMESPACE: &str = "gateway-conformance-infra";
const SCOPE: &str = "namespace:gateway-conformance-infra";
const IDLE_RELIST_SECS: u64 = 60;

/// Long enough to cross the idle window plus its per-scope jitter for ANY
/// jitter value: the offset is bounded by a quarter of the window, so twice the
/// window always crosses the deadline. The jitter carries a per-process random
/// seed, so no test may depend on a particular offset.
const PAST_IDLE_WINDOW: Duration = Duration::from_secs(IDLE_RELIST_SECS * 2);

/// Event cadence for a scope that is deliberately busy. Strictly inside the
/// *minimum* idle deadline: that deadline is `last_event + IDLE_RELIST_SECS +
/// jitter` with `jitter >= 0`, so an event every half-window can never reach it
/// whatever the process seed produced.
const BUSY_EVENT_CADENCE: Duration = Duration::from_secs(IDLE_RELIST_SECS / 2);

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
/// stream and the last update below would never land. The event cadence is
/// strictly inside the minimum idle deadline, so this holds for every jitter
/// value while total elapsed time crosses two whole windows.
#[tokio::test(start_paused = true)]
async fn a_scope_that_keeps_delivering_events_is_never_relisted() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(1, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    for _ in 0..4 {
        tokio::time::sleep(BUSY_EVENT_CADENCE).await;
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

/// A replacement generation that inherits the same stalled path must not pin
/// the scope to its last-known-good state forever: it is abandoned after the
/// readiness timeout and another one is started, still make-before-break.
#[tokio::test(start_paused = true)]
async fn a_replacement_that_never_lists_is_retried_without_losing_the_last_good_store() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (harness, task) = scope(3, IDLE_RELIST_SECS, shutdown_rx);
    let watcher = tokio::spawn(task);

    list(&harness, 0, &["blackbox-tcp-main"]);
    // Generation 1 starts one idle window (plus jitter) from here and never
    // receives a single event: it inherits the same stalled path.
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

/// The per-scope jitter is a bounded offset, never a value a caller may pin.
///
/// It carries a per-process random seed so that control-plane replicas watching
/// the same scopes do not issue the same scope's list in the same instant, so
/// this asserts only what the watcher relies on: it stays inside a quarter of
/// the window (which is what keeps `PAST_IDLE_WINDOW` sufficient), it is zero
/// when relisting is disabled, it is stable within one process, and it survives
/// the largest window the env parser can produce without overflowing.
#[test]
fn idle_relist_jitter_is_bounded_and_stable_within_the_process() {
    let quarter_window_ms = IDLE_RELIST_SECS * 1000 / 4;
    for kind in ["TCPRoute", "HTTPRoute", "ReferenceGrant"] {
        let jitter = jitter_millis(API_VERSION, kind, SCOPE, IDLE_RELIST_SECS);
        assert!(
            jitter < quarter_window_ms,
            "{kind} jitter {jitter}ms must stay inside a quarter of the window \
             ({quarter_window_ms}ms)"
        );
        assert_eq!(
            jitter,
            jitter_millis(API_VERSION, kind, SCOPE, IDLE_RELIST_SECS),
            "a scope's offset must not wander between iterations within one process"
        );
    }

    assert_eq!(
        jitter_millis(API_VERSION, KIND, SCOPE, 0),
        0,
        "a disabled idle relist has no deadline to offset"
    );

    // The env parser clamps the window to 86_400s; the largest admissible
    // window must still produce a bounded offset rather than overflowing the
    // millisecond conversion or the doubling behind the readiness timeout.
    const MAX_WINDOW_SECS: u64 = 86_400;
    assert!(
        jitter_millis(API_VERSION, KIND, SCOPE, MAX_WINDOW_SECS) < MAX_WINDOW_SECS * 1000 / 4,
        "the maximum admissible window must still produce a bounded offset"
    );
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

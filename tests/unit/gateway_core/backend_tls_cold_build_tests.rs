//! Cold backend TLS construction must not run on the Tokio worker.
//!
//! `BackendTlsConfigCache::get_or_build` is the request-path miss path for the
//! direct-H2, gRPC, and HTTP/3 backend pools. These tests pin its contract:
//! the build runs on the bounded TLS source executor rather than the worker
//! polling the request, concurrent misses for one key coalesce onto a single
//! build, and failures stay fail-closed without being cached — including a
//! build that straddles a cache clear (CRL / backend TLS reload). Waiters are
//! bounded by the executor deadline; the build runs under a larger but still
//! bounded background budget, and a late success is cached for the next
//! request.

use ferrum_edge::tls::backend::{BackendTlsConfigCache, TlsError};
use ferrum_edge::tls::source::{
    MaterialError, TLS_SOURCE_BACKGROUND_BUILD_BUDGET_MULTIPLIER, TlsSourceExecutor,
    remaining_tls_source_operation_budget, resolve_on_tls_source_runtime_for_test,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::sync::oneshot;

/// A statically keyed TLS identity (`svidg=static` satisfies the cache's
/// generation-tag contract without a workload SVID).
const STATIC_KEY: &str = "ca=|cert=|key=|sni=|san=|verify=1|svidg=static";

/// Upper bound on how long a parked test build waits for its release. A build
/// that ran on the single Tokio worker would starve the releasing task and
/// surface as this timeout instead of hanging the suite.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

type BuildResult = Result<rustls::ClientConfig, TlsError>;
type TestBuild = Box<dyn FnOnce() -> BuildResult + Send + 'static>;

fn test_executor(max_blocking_concurrency: usize, deadline: Duration) -> TlsSourceExecutor {
    TlsSourceExecutor::new(max_blocking_concurrency, deadline).expect("test executor")
}

fn test_client_config() -> rustls::ClientConfig {
    let provider = Arc::new(ferrum_edge::fips::base_crypto_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
}

fn ok_build() -> TestBuild {
    Box::new(|| -> BuildResult { Ok(test_client_config()) })
}

fn await_release(release: &mpsc::Receiver<()>) -> Result<(), TlsError> {
    release
        .recv_timeout(RELEASE_TIMEOUT)
        .map_err(|_| TlsError::Rustls("test build was never released".to_string()))
}

/// Simulated remote provider wait inside a build: the source needs `latency`
/// and is allowed its per-source budget, capped by what remains of the
/// enclosing executor operation (the same rule real provider resolution uses).
fn slow_remote_source(per_source_budget: Duration, latency: Duration) -> Result<(), TlsError> {
    let allowed = remaining_tls_source_operation_budget(per_source_budget);
    if allowed < latency {
        std::thread::sleep(allowed);
        return Err(TlsError::Rustls(
            "remote source deadline exceeded".to_string(),
        ));
    }
    std::thread::sleep(latency);
    Ok(())
}

/// Wait until a background build has cached `key` and retired its pending
/// entry, bounded by [`RELEASE_TIMEOUT`].
async fn wait_until_cached(cache: &BackendTlsConfigCache, key: &str) {
    tokio::time::timeout(RELEASE_TIMEOUT, async {
        while !cache.contains_key(key) || cache.pending_builds() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the background build must cache its late success");
}

/// Build that reports it started, then parks inside blocking work until the
/// test releases it.
fn parked_build(started: oneshot::Sender<()>, release: mpsc::Receiver<()>) -> TestBuild {
    Box::new(move || -> BuildResult {
        let _ = started.send(());
        await_release(&release)?;
        Ok(test_client_config())
    })
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_cold_build_does_not_stall_the_single_tokio_worker() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let lookup = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    parked_build(started_tx, release_rx)
                })
                .await
        }
    });

    started_rx.await.expect("cold build started");
    // The build is parked inside blocking work. The only Tokio worker must
    // still drive timers and unrelated tasks.
    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::time::sleep(Duration::from_millis(20)),
    )
    .await
    .expect("the single Tokio worker must keep running while a cold TLS build is stalled");
    let heartbeat = tokio::spawn(async { 7_u8 });
    assert_eq!(heartbeat.await.expect("heartbeat task"), 7);

    release_tx.send(()).expect("release the parked build");
    let config = lookup
        .await
        .expect("lookup task")
        .expect("cold build result");
    let cached = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("cached lookup");
    assert!(
        Arc::ptr_eq(&config, &cached),
        "the cold build must be cached"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_cold_misses_share_one_build_off_the_worker() {
    const CALLERS: usize = 16;

    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(4, Duration::from_secs(5));
    let prepares = Arc::new(AtomicUsize::new(0));
    let builds = Arc::new(AtomicUsize::new(0));
    let build_thread = Arc::new(Mutex::new(None));
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(Some(release_rx)));
    let worker_thread = std::thread::current().id();

    let callers = (0..CALLERS).map(|_| {
        let cache = cache.clone();
        let executor = executor.clone();
        let prepares = Arc::clone(&prepares);
        let builds = Arc::clone(&builds);
        let build_thread = Arc::clone(&build_thread);
        let release_rx = Arc::clone(&release_rx);
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    prepares.fetch_add(1, Ordering::SeqCst);
                    let release_rx = release_rx.lock().expect("release lock").take();
                    let build: TestBuild = Box::new(move || -> BuildResult {
                        builds.fetch_add(1, Ordering::SeqCst);
                        *build_thread.lock().expect("build thread lock") =
                            Some(std::thread::current().id());
                        if let Some(release_rx) = release_rx {
                            await_release(&release_rx)?;
                        }
                        Ok(test_client_config())
                    });
                    build
                })
                .await
        }
    });

    let lookups = futures::future::join_all(callers);
    let release = async {
        // Every caller registers on its first poll, before this branch resumes.
        tokio::task::yield_now().await;
        assert_eq!(
            cache.pending_builds(),
            1,
            "all concurrent misses must join one in-flight build"
        );
        release_tx.send(()).expect("release the shared build");
    };
    let (results, ()) = tokio::join!(lookups, release);

    let configs: Vec<_> = results
        .into_iter()
        .map(|result| result.expect("coalesced cold build"))
        .collect();
    assert_eq!(configs.len(), CALLERS);
    assert!(
        configs
            .iter()
            .all(|config| Arc::ptr_eq(config, &configs[0])),
        "every coalesced caller must receive the same Arc"
    );
    assert_eq!(
        prepares.load(Ordering::SeqCst),
        1,
        "only the leader snapshots inputs"
    );
    assert_eq!(
        builds.load(Ordering::SeqCst),
        1,
        "one build, not one per caller"
    );
    let build_thread = build_thread
        .lock()
        .expect("build thread lock")
        .expect("build recorded its thread");
    assert_ne!(
        build_thread, worker_thread,
        "the build must run on the blocking executor, not the Tokio worker"
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.pending_builds(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_cold_build_is_shared_fail_closed_and_not_cached() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let builds = Arc::new(AtomicUsize::new(0));
    let missing_ca = || -> TestBuild {
        Box::new(|| -> BuildResult {
            Err(TlsError::Io {
                kind: "backend CA bundle",
                path: PathBuf::from("/nonexistent/backend-ca.pem"),
                source: std::io::Error::from_raw_os_error(2),
            })
        })
    };

    let lookups = (0..4).map(|_| {
        let cache = cache.clone();
        let executor = executor.clone();
        let builds = Arc::clone(&builds);
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    builds.fetch_add(1, Ordering::SeqCst);
                    missing_ca()
                })
                .await
        }
    });
    let results = futures::future::join_all(lookups).await;

    assert_eq!(
        builds.load(Ordering::SeqCst),
        1,
        "waiters share the leader's failure"
    );
    for result in results {
        match result {
            Err(TlsError::Io { kind, source, .. }) => {
                assert_eq!(kind, "backend CA bundle");
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
                assert_eq!(source.raw_os_error(), Some(2));
            }
            Err(other) => panic!("failure class must be preserved, got {other}"),
            Ok(_) => panic!("a failed build must not produce a config"),
        }
    }
    assert!(cache.is_empty(), "failures are never cached");
    assert_eq!(cache.pending_builds(), 0);

    // No negative cache: the next miss builds again.
    let retry_builds = Arc::clone(&builds);
    let retry = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            retry_builds.fetch_add(1, Ordering::SeqCst);
            missing_ca()
        })
        .await;
    assert!(matches!(retry, Err(TlsError::Io { .. })));
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert!(cache.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn cold_build_straddling_a_clear_answers_callers_without_caching() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let lookup = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    parked_build(started_tx, release_rx)
                })
                .await
        }
    });
    started_rx.await.expect("cold build started");

    // A backend TLS / CRL reload clears the cache while the build is running
    // on inputs snapshotted before the reload.
    cache.clear();
    release_tx.send(()).expect("release the parked build");

    let stale = lookup
        .await
        .expect("lookup task")
        .expect("in-flight callers still get a config");
    assert!(
        !cache.contains_key(STATIC_KEY),
        "a build that straddled a clear must not be cached"
    );

    let fresh = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("fresh build after the clear");
    assert!(cache.contains_key(STATIC_KEY));
    assert!(!Arc::ptr_eq(&stale, &fresh));
}

/// A build slower than the executor deadline (queue time included) fails its
/// waiters closed but keeps running: the late success is cached, callers that
/// arrive meanwhile join the same build instead of starting another, and the
/// next request is a cache hit.
#[tokio::test(flavor = "current_thread")]
async fn slow_cold_build_fails_waiters_closed_then_caches_its_late_success() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(1));
    let prepares = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let leader_prepares = Arc::clone(&prepares);
    let timed_out = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            leader_prepares.fetch_add(1, Ordering::SeqCst);
            parked_build(started_tx, release_rx)
        })
        .await;
    started_rx.await.expect("cold build started");

    let details = match timed_out {
        Err(TlsError::Rustls(details)) => details,
        Err(other) => panic!("a waiter past its deadline must fail closed, got {other}"),
        Ok(_) => panic!("the build was still parked; the waiter cannot have succeeded"),
    };
    assert!(
        details.contains("did not complete"),
        "unexpected deadline diagnostic: {details}"
    );
    assert!(cache.is_empty());
    assert_eq!(
        cache.pending_builds(),
        1,
        "the build outlives its timed-out waiter"
    );

    // A caller arriving while the late build is still running joins it with
    // its own fresh budget rather than starting a second build.
    let joiner_prepares = Arc::clone(&prepares);
    let joiner = async {
        cache
            .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                joiner_prepares.fetch_add(1, Ordering::SeqCst);
                ok_build()
            })
            .await
    };
    let release = async {
        tokio::task::yield_now().await;
        release_tx.send(()).expect("release the parked build");
    };
    let (joined, ()) = tokio::join!(joiner, release);
    let joined = joined.expect("the joiner receives the late success");

    assert_eq!(prepares.load(Ordering::SeqCst), 1, "one build per key");
    assert!(cache.contains_key(STATIC_KEY), "the late success is cached");
    assert_eq!(cache.pending_builds(), 0);
    let hit = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("cache hit");
    assert!(Arc::ptr_eq(&joined, &hit));
}

/// Cancelling the caller that started a build (request deadline, client
/// disconnect) neither aborts the build nor strands the callers that joined it.
#[tokio::test(flavor = "current_thread")]
async fn aborted_leader_does_not_strand_joined_waiters() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let joiner_prepares = Arc::new(AtomicUsize::new(0));

    let leader = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    parked_build(started_tx, release_rx)
                })
                .await
        }
    });
    started_rx.await.expect("cold build started");

    let joiner = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        let joiner_prepares = Arc::clone(&joiner_prepares);
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    joiner_prepares.fetch_add(1, Ordering::SeqCst);
                    ok_build()
                })
                .await
        }
    });
    // Let the joiner register on the in-flight build.
    tokio::task::yield_now().await;
    assert_eq!(cache.pending_builds(), 1);

    leader.abort();
    let aborted = leader.await.expect_err("the leader caller was aborted");
    assert!(aborted.is_cancelled());

    release_tx.send(()).expect("release the parked build");
    let joined = joiner
        .await
        .expect("joiner task")
        .expect("the joiner still receives the build");
    assert_eq!(
        joiner_prepares.load(Ordering::SeqCst),
        0,
        "the joiner must join the in-flight build, not start its own"
    );
    assert_eq!(cache.pending_builds(), 0, "nothing stays pending");
    let hit = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("cache hit");
    assert!(Arc::ptr_eq(&joined, &hit));
}

/// If the build task itself is dropped before it publishes (runtime
/// shutdown), its waiters are answered with a closed failure instead of
/// waiting out their deadline, and the key is free for a fresh build.
#[tokio::test(flavor = "current_thread")]
async fn dropped_build_task_answers_waiters_with_a_closed_failure() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    // The leader, and therefore its spawned build task, run on a separate
    // runtime; shutting that runtime down drops the build task mid-build.
    let build_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("build runtime");
    let _leader = build_runtime.spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    parked_build(started_tx, release_rx)
                })
                .await
        }
    });
    started_rx.await.expect("cold build started");

    let waiter = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
                .await
        }
    });
    tokio::task::yield_now().await;
    assert_eq!(cache.pending_builds(), 1);

    build_runtime.shutdown_background();
    let result = tokio::time::timeout(RELEASE_TIMEOUT, waiter)
        .await
        .expect("the waiter must be answered when the build task is dropped")
        .expect("waiter task");
    // Let the orphaned blocking operation exit.
    let _ = release_tx.send(());

    let details = match result {
        Err(TlsError::Rustls(details)) => details,
        Err(other) => panic!("a dropped build must fail closed, got {other}"),
        Ok(_) => panic!("a dropped build must not produce a config"),
    };
    assert!(
        details.contains("cancelled"),
        "unexpected cancellation diagnostic: {details}"
    );
    assert!(cache.is_empty());
    assert_eq!(cache.pending_builds(), 0);

    cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("a fresh build after the dropped one");
    assert!(cache.contains_key(STATIC_KEY));
}

/// Every executor operation carries one absolute deadline measured from
/// admission, and remote source waits inside it are capped by what remains of
/// it. A bounded operation's deadline is the per-source budget; a
/// run-to-completion (background build) operation gets the larger
/// `TLS_SOURCE_BACKGROUND_BUILD_BUDGET_MULTIPLIER` cap and returns its result
/// even after that cap has passed. The deadline is scoped to the operation.
#[tokio::test(flavor = "current_thread")]
async fn executor_operations_carry_one_absolute_source_budget() {
    let budget = Duration::from_secs(5);
    assert_eq!(remaining_tls_source_operation_budget(budget), budget);

    let executor = test_executor(1, Duration::from_millis(400));
    let (fresh, spent) = executor
        .run_blocking(move || {
            let fresh = remaining_tls_source_operation_budget(budget);
            std::thread::sleep(Duration::from_millis(100));
            let spent = remaining_tls_source_operation_budget(budget);
            Ok::<_, MaterialError>((fresh, spent))
        })
        .await
        .expect("bounded operation");
    assert!(fresh <= Duration::from_millis(400), "{fresh:?}");
    assert!(spent < fresh, "{spent:?} must be less than {fresh:?}");
    assert!(spent <= Duration::from_millis(300), "{spent:?}");

    let per_source = Duration::from_millis(200);
    let background = test_executor(1, per_source);
    let cap = background.background_build_deadline();
    assert_eq!(
        cap,
        per_source * TLS_SOURCE_BACKGROUND_BUILD_BUDGET_MULTIPLIER
    );
    let (fresh, late) = background
        .run_blocking_result_to_completion(move || {
            let fresh = remaining_tls_source_operation_budget(budget);
            std::thread::sleep(cap + Duration::from_millis(100));
            Ok::<_, ()>((fresh, remaining_tls_source_operation_budget(budget)))
        })
        .await
        .expect("run-to-completion operation")
        .expect("late result");
    assert!(fresh <= cap, "{fresh:?}");
    assert!(
        fresh > per_source,
        "the background cap must exceed the per-source budget: {fresh:?}"
    );
    assert_eq!(late, Duration::ZERO, "the operation deadline has passed");

    let after = tokio::task::spawn_blocking(move || remaining_tls_source_operation_budget(budget))
        .await
        .expect("plain blocking task");
    assert_eq!(after, budget, "the deadline is scoped to its operation");
}

/// A backend whose CA, client certificate, and client key each come from a
/// slow remote provider: every source fits the per-source budget `D`, but the
/// three together exceed it. The first request fails closed at `D`, the
/// background build keeps going under its larger cap, and a later request is
/// served from the cache.
#[tokio::test(flavor = "current_thread")]
async fn multi_source_build_past_the_request_budget_is_cached_for_a_later_request() {
    let per_source_budget = Duration::from_millis(400);
    let source_latency = Duration::from_millis(200);
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, per_source_budget);
    assert!(source_latency * 3 > per_source_budget);
    assert!(source_latency * 3 < executor.background_build_deadline());
    let prepares = Arc::new(AtomicUsize::new(0));

    let leader_prepares = Arc::clone(&prepares);
    let first = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            leader_prepares.fetch_add(1, Ordering::SeqCst);
            let build: TestBuild = Box::new(move || -> BuildResult {
                // CA, client certificate, client key: resolved one after
                // another, like the backend TLS builder does.
                for _ in 0..3 {
                    slow_remote_source(per_source_budget, source_latency)?;
                }
                Ok(test_client_config())
            });
            build
        })
        .await;
    let details = match first {
        Err(TlsError::Rustls(details)) => details,
        Err(other) => panic!("the first request must fail closed at its budget, got {other}"),
        Ok(_) => panic!("three sequential sources cannot finish inside one request budget"),
    };
    assert!(
        details.contains("did not complete"),
        "unexpected deadline diagnostic: {details}"
    );

    wait_until_cached(&cache, STATIC_KEY).await;
    let later_prepares = Arc::clone(&prepares);
    cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            later_prepares.fetch_add(1, Ordering::SeqCst);
            ok_build()
        })
        .await
        .expect("a later request hits the cached build");
    assert_eq!(
        prepares.load(Ordering::SeqCst),
        1,
        "the later request is a cache hit, not a rebuild"
    );
}

/// A late success is cached even when every waiter has already given up, so
/// nobody is listening when the build publishes.
#[tokio::test(flavor = "current_thread")]
async fn late_success_is_cached_with_no_waiter_left() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_millis(200));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let timed_out = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            parked_build(started_tx, release_rx)
        })
        .await;
    started_rx.await.expect("cold build started");
    assert!(
        timed_out.is_err(),
        "the only waiter gives up while the build is parked"
    );
    assert!(cache.is_empty());
    assert_eq!(cache.pending_builds(), 1);

    // No caller is waiting on the build any more.
    release_tx.send(()).expect("release the parked build");
    wait_until_cached(&cache, STATIC_KEY).await;

    let rebuilds = Arc::new(AtomicUsize::new(0));
    let hit_rebuilds = Arc::clone(&rebuilds);
    cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            hit_rebuilds.fetch_add(1, Ordering::SeqCst);
            ok_build()
        })
        .await
        .expect("cache hit");
    assert_eq!(rebuilds.load(Ordering::SeqCst), 0);
}

/// A build still queued for an executor slot when a reload clears the cache
/// is skipped once admitted: its result could not be cached, so it must not
/// hold a slot ahead of fresh builds. Its waiters fail closed.
#[tokio::test(flavor = "current_thread")]
async fn queued_build_orphaned_by_a_clear_is_skipped_once_admitted() {
    const OTHER_KEY: &str = "ca=|cert=|key=|sni=other|san=|verify=1|svidg=static";

    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_secs(5));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    // Occupy the only executor slot.
    let occupant = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        async move {
            cache
                .get_or_build_with_executor(&executor, OTHER_KEY.to_string(), move || {
                    parked_build(started_tx, release_rx)
                })
                .await
        }
    });
    started_rx.await.expect("occupying build started");

    let queued_builds = Arc::new(AtomicUsize::new(0));
    let queued = tokio::spawn({
        let cache = cache.clone();
        let executor = executor.clone();
        let queued_builds = Arc::clone(&queued_builds);
        async move {
            cache
                .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
                    let build: TestBuild = Box::new(move || -> BuildResult {
                        queued_builds.fetch_add(1, Ordering::SeqCst);
                        Ok(test_client_config())
                    });
                    build
                })
                .await
        }
    });
    tokio::task::yield_now().await;
    assert_eq!(
        cache.pending_builds(),
        2,
        "the second build is queued behind the first"
    );

    cache.clear();
    release_tx.send(()).expect("release the occupying build");
    occupant
        .await
        .expect("occupant task")
        .expect("the admitted build still answers its callers");

    let result = queued.await.expect("queued task");
    let details = match result {
        Err(TlsError::Rustls(details)) => details,
        Err(other) => panic!("an orphaned build must fail closed, got {other}"),
        Ok(_) => panic!("an orphaned build must not produce a config"),
    };
    assert!(
        details.contains("cancelled by a reload"),
        "unexpected cancellation diagnostic: {details}"
    );
    assert_eq!(
        queued_builds.load(Ordering::SeqCst),
        0,
        "the orphaned build must not run"
    );
    assert!(cache.is_empty());
    assert_eq!(cache.pending_builds(), 0);

    cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), ok_build)
        .await
        .expect("a fresh build after the reload");
    assert!(cache.contains_key(STATIC_KEY));
}

/// Once the enclosing operation's deadline has passed, source resolution
/// fails fast without spawning (or polling) the provider future.
#[tokio::test(flavor = "current_thread")]
async fn exhausted_operation_budget_fails_source_resolution_without_polling() {
    let executor = test_executor(1, Duration::from_millis(50));
    let cap = executor.background_build_deadline();
    let polled = Arc::new(AtomicBool::new(false));
    let provider_polled = Arc::clone(&polled);

    let (result, elapsed) = executor
        .run_blocking_result_to_completion(move || {
            std::thread::sleep(cap + Duration::from_millis(50));
            let started = std::time::Instant::now();
            let result = resolve_on_tls_source_runtime_for_test(async move {
                provider_polled.store(true, Ordering::SeqCst);
                Ok::<_, String>(())
            });
            Ok::<_, ()>((result, started.elapsed()))
        })
        .await
        .expect("run-to-completion operation")
        .expect("operation result");

    let error = result.expect_err("an exhausted budget must fail closed");
    assert!(error.contains("deadline exceeded"), "{error}");
    assert!(
        !polled.load(Ordering::SeqCst),
        "the provider future must not run"
    );
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

/// The direct HTTP/2, gRPC, and reqwest/H3 pool managers must reach the
/// backend TLS cache only through the async single-flight `get_or_build`; the
/// synchronous `get_or_try_build` would run the build on the Tokio worker.
#[test]
fn backend_pool_managers_never_build_tls_synchronously() {
    let sources = [
        (
            "src/proxy/http2_pool.rs",
            include_str!("../../../src/proxy/http2_pool.rs"),
        ),
        (
            "src/proxy/grpc_proxy.rs",
            include_str!("../../../src/proxy/grpc_proxy.rs"),
        ),
        (
            "src/connection_pool.rs",
            include_str!("../../../src/connection_pool.rs"),
        ),
    ];
    for (path, source) in sources {
        // No `(`: a turbofish or function-value use must also trip the guard.
        assert!(
            !source.contains("get_or_try_build"),
            "{path} must not build backend TLS configs synchronously on the Tokio worker"
        );
        assert!(
            source.contains(".get_or_build("),
            "{path} must build cold backend TLS configs through get_or_build"
        );
    }
}

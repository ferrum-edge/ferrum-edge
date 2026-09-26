//! Cold backend TLS construction must not run on the Tokio worker.
//!
//! `BackendTlsConfigCache::get_or_build` is the request-path miss path for the
//! direct-H2, gRPC, and HTTP/3 backend pools. These tests pin its contract:
//! the build runs on the bounded TLS source executor rather than the worker
//! polling the request, concurrent misses for one key coalesce onto a single
//! build, and failures stay fail-closed without being cached — including a
//! build that straddles a cache clear (CRL / backend TLS reload).

use ferrum_edge::tls::backend::{BackendTlsConfigCache, TlsError};
use ferrum_edge::tls::source::TlsSourceExecutor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[tokio::test(flavor = "current_thread")]
async fn cold_build_past_the_executor_deadline_fails_closed() {
    let cache = BackendTlsConfigCache::new();
    let executor = test_executor(1, Duration::from_millis(50));
    let (started_tx, _started_rx) = oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();

    let result = cache
        .get_or_build_with_executor(&executor, STATIC_KEY.to_string(), move || {
            parked_build(started_tx, release_rx)
        })
        .await;
    // Let the abandoned blocking operation finish before the runtime shuts down.
    let _ = release_tx.send(());

    let details = match result {
        Err(TlsError::Rustls(details)) => details,
        Err(other) => panic!("deadline must fail closed as a build error, got {other}"),
        Ok(_) => panic!("a build past the executor deadline must not succeed"),
    };
    assert!(
        details.contains("did not complete"),
        "unexpected deadline diagnostic: {details}"
    );
    assert!(cache.is_empty());
    assert_eq!(cache.pending_builds(), 0);
}

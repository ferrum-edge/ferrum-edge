//! The refreshing AWS credential cache behind
//! `serverless_function` `aws_credentials: default_chain`.
//!
//! The cache is feature-independent: the AWS SDK default chain is only one
//! injected fetcher, so every behavior here runs in the default build.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ferrum_edge::plugins::utils::aws_refreshing_credentials::{
    AwsCredentialFetchFuture, AwsCredentialFetcher, AwsCredentialRefreshTiming,
    AwsCredentialSnapshot, RefreshingAwsCredentials,
};

type FetchPlan = Arc<dyn Fn(u64) -> Result<AwsCredentialSnapshot, String> + Send + Sync>;

/// Give a plan closure its signature so its `Ok` / `Err` types are inferred.
fn plan(
    answer: impl Fn(u64) -> Result<AwsCredentialSnapshot, String> + Send + Sync + 'static,
) -> FetchPlan {
    Arc::new(answer)
}

/// A fetcher whose `n`-th call (1-based) answers `plan(n)` after `delay`.
fn counting_fetcher(delay: Duration, plan: FetchPlan) -> (AwsCredentialFetcher, Arc<AtomicU64>) {
    let calls = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&calls);
    let fetcher: AwsCredentialFetcher = Arc::new(move || -> AwsCredentialFetchFuture {
        let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
        let plan = Arc::clone(&plan);
        Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            plan(call)
        })
    });
    (fetcher, calls)
}

fn snapshot(generation: u64, expires_in: Option<Duration>) -> AwsCredentialSnapshot {
    AwsCredentialSnapshot::new(
        format!("ASIAGENERATION{generation:04}"),
        "fixture-secret",
        Some(format!("fixture-session-token-{generation}")),
        expires_in.map(|lifetime| SystemTime::now() + lifetime),
    )
}

fn timing(refresh_before_expiry: Duration, retry_backoff: Duration) -> AwsCredentialRefreshTiming {
    AwsCredentialRefreshTiming {
        refresh_before_expiry,
        expiry_skew: Duration::ZERO,
        fetch_timeout: Duration::from_secs(5),
        retry_backoff,
    }
}

#[tokio::test]
async fn concurrent_first_use_shares_one_fetch() {
    let (fetcher, calls) = counting_fetcher(
        Duration::from_millis(100),
        plan(|generation| Ok(snapshot(generation, None))),
    );
    let cache = RefreshingAwsCredentials::with_timing(
        fetcher,
        timing(Duration::from_secs(300), Duration::from_secs(5)),
    );

    let results = futures::future::join_all((0..16).map(|_| cache.credentials())).await;

    for result in results {
        let credentials = result.expect("every waiter receives the shared fetch result");
        assert_eq!(credentials.access_key_id(), "ASIAGENERATION0001");
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one fetch for every waiter"
    );
    assert_eq!(cache.fetch_count(), 1);
}

#[tokio::test]
async fn fresh_credentials_are_reused_without_refetching() {
    let (fetcher, calls) = counting_fetcher(
        Duration::ZERO,
        plan(|generation| Ok(snapshot(generation, Some(Duration::from_secs(3600))))),
    );
    let cache = RefreshingAwsCredentials::with_timing(
        fetcher,
        timing(Duration::from_secs(300), Duration::from_secs(5)),
    );

    for _ in 0..8 {
        let credentials = cache.credentials().await.expect("credential");
        assert_eq!(credentials.access_key_id(), "ASIAGENERATION0001");
        assert!(credentials.has_session_token());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn credentials_inside_the_refresh_window_renew_in_the_background() {
    // Every credential expires in 30 minutes and the refresh window is one
    // hour, so each one is due for renewal as soon as it is cached. Every
    // renewal is held until the test releases it, so "the request did not
    // wait" is proven by completing while the provider is still blocked, not
    // by a wall-clock threshold.
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicU64::new(0));
    let fetcher: AwsCredentialFetcher = {
        let release = Arc::clone(&release);
        let calls = Arc::clone(&calls);
        Arc::new(move || -> AwsCredentialFetchFuture {
            let generation = calls.fetch_add(1, Ordering::SeqCst) + 1;
            let release = Arc::clone(&release);
            Box::pin(async move {
                if generation > 1 {
                    release.notified().await;
                }
                Ok::<_, String>(snapshot(generation, Some(Duration::from_secs(1800))))
            })
        })
    };
    let cache = RefreshingAwsCredentials::with_timing(
        fetcher,
        timing(Duration::from_secs(3600), Duration::from_secs(5)),
    );

    let first = cache.credentials().await.expect("first credential");
    assert_eq!(first.access_key_id(), "ASIAGENERATION0001");

    // The renewal this starts stays blocked; the still-valid credential is
    // returned anyway.
    let second = tokio::time::timeout(Duration::from_secs(5), cache.credentials())
        .await
        .expect("a request inside the refresh window must not wait for the refresh")
        .expect("still-valid credential");
    assert_eq!(second.access_key_id(), "ASIAGENERATION0001");

    release.notify_one();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let current = cache.credentials().await.expect("credential");
        if current.access_key_id() == "ASIAGENERATION0002" {
            break;
        }
        assert_eq!(current.access_key_id(), "ASIAGENERATION0001");
        assert!(
            tokio::time::Instant::now() < deadline,
            "the released refresh never published a renewed credential"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(calls.load(Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn expired_credentials_are_refused_when_renewal_fails() {
    let (fetcher, calls) = counting_fetcher(
        Duration::ZERO,
        plan(|generation| {
            if generation == 1 {
                // Long enough that no scheduling stall makes the first answer
                // look expired; the test then waits past it.
                Ok(snapshot(generation, Some(Duration::from_secs(2))))
            } else {
                Err("provider unavailable".to_string())
            }
        }),
    );
    // No refresh window: the credential is fresh until it expires.
    let cache =
        RefreshingAwsCredentials::with_timing(fetcher, timing(Duration::ZERO, Duration::ZERO));

    cache
        .credentials()
        .await
        .expect("the first credential is valid");
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let refused = cache
        .credentials()
        .await
        .expect_err("an expired credential must never be returned");
    assert!(!refused.reason.contains("fixture"), "{}", refused.reason);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "renewal was attempted once"
    );
}

#[tokio::test]
async fn an_already_expired_answer_is_refused() {
    let (fetcher, _calls) = counting_fetcher(
        Duration::ZERO,
        plan(|generation| {
            Ok(AwsCredentialSnapshot::new(
                format!("ASIAGENERATION{generation:04}"),
                "fixture-secret",
                None,
                Some(SystemTime::now() - Duration::from_secs(1)),
            ))
        }),
    );
    let cache =
        RefreshingAwsCredentials::with_timing(fetcher, timing(Duration::ZERO, Duration::ZERO));

    let refused = cache.credentials().await.expect_err("expired on arrival");
    assert!(refused.reason.contains("expired"), "{}", refused.reason);
}

#[tokio::test]
async fn a_failed_fetch_backs_off_instead_of_refetching_per_request() {
    let (fetcher, calls) = counting_fetcher(
        Duration::ZERO,
        plan(|_| Err("provider unavailable".to_string())),
    );
    let cache = RefreshingAwsCredentials::with_timing(
        fetcher,
        timing(Duration::from_secs(300), Duration::from_secs(60)),
    );

    cache.credentials().await.expect_err("provider is down");
    cache
        .credentials()
        .await
        .expect_err("still refused during the backoff");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the backoff must stop a second fetch"
    );
}

#[tokio::test]
async fn unusable_header_credentials_from_the_provider_are_refused() {
    for (key_id, token) in [
        ("ASIA\nINJECTED", None),
        ("", None),
        ("ASIAVALIDKEY", Some("token\r\nx-injected: 1".to_string())),
    ] {
        let fetcher: AwsCredentialFetcher = Arc::new(move || -> AwsCredentialFetchFuture {
            let token = token.clone();
            Box::pin(async move {
                Ok::<_, String>(AwsCredentialSnapshot::new(
                    key_id,
                    "fixture-secret",
                    token,
                    None,
                ))
            })
        });
        let cache =
            RefreshingAwsCredentials::with_timing(fetcher, timing(Duration::ZERO, Duration::ZERO));
        let refused = cache
            .credentials()
            .await
            .expect_err("credentials that cannot form HTTP field values must be refused");
        assert!(!refused.reason.contains("INJECTED"), "{}", refused.reason);
        assert!(!refused.reason.contains("x-injected"), "{}", refused.reason);
    }
}

#[test]
fn snapshot_debug_redacts_secret_material() {
    let rendered = format!(
        "{:?}",
        AwsCredentialSnapshot::new(
            "ASIAVISIBLEKEYID",
            "never-print-this-secret",
            Some("never-print-this-token".to_string()),
            None,
        )
    );
    assert!(rendered.contains("ASIAVISIBLEKEYID"), "{rendered}");
    assert!(!rendered.contains("never-print-this-secret"), "{rendered}");
    assert!(!rendered.contains("never-print-this-token"), "{rendered}");
}

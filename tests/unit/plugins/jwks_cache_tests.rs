use ferrum_edge::_test_support::jwks_discovery_candidate_for_test;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::utils::jwks_cache::{
    JwksRefreshRequirement, cached_reaper_generation, cached_refresh_state, cached_requirement,
    clear_jwks_cache, get_or_create_jwks_store as get_or_create_jwks_store_with_policy,
    render_prometheus, retain_active_requirements, retain_active_uris,
    retire_jwks_store_if_unreferenced,
};
use ferrum_edge::plugins::utils::jwks_store::{
    DEFAULT_JWKS_MAX_STALE_SECONDS, JwksFailureClass, JwksKeyStore, JwksTrustState,
};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, ResponseTemplate};

const RSA_PUBLIC_PEM: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

fn client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn get_or_create_jwks_store(
    uri: &str,
    http_client: &PluginHttpClient,
    refresh_interval: Duration,
) -> Arc<JwksKeyStore> {
    get_or_create_jwks_store_with_policy(
        uri,
        http_client,
        refresh_interval,
        Duration::from_secs(DEFAULT_JWKS_MAX_STALE_SECONDS),
    )
}

pub(super) fn cache_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[tokio::test]
async fn test_same_jwks_uri_reuses_cached_store() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/.well-known/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let first = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    let second = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(30));

    assert!(Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}

#[tokio::test]
async fn shared_store_uses_minimum_interval_and_reconciles_removals() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/interval/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let slow = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert_eq!(
        cached_refresh_state(&uri),
        Some((Duration::from_secs(300), 1))
    );

    let fast = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(30));
    assert!(Arc::ptr_eq(&slow, &fast));
    let (interval, generation_after_fast_consumer) =
        cached_refresh_state(&uri).expect("cache entry");
    assert_eq!(interval, Duration::from_secs(30));
    assert_eq!(generation_after_fast_consumer, 2);

    // Repeating an identical requirement must not create another refresh task.
    let repeated = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(30));
    assert!(Arc::ptr_eq(&fast, &repeated));
    assert_eq!(
        cached_refresh_state(&uri),
        Some((Duration::from_secs(30), generation_after_fast_consumer))
    );

    // Simulate removal of the 30-second consumer from the committed plugin
    // generation. The surviving 300-second requirement takes effect without
    // replacing the key store or dropping its last-good keys.
    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(300), Duration::from_secs(3_600)),
    )]));
    let (interval, generation_after_removal) = cached_refresh_state(&uri).expect("cache entry");
    assert_eq!(interval, Duration::from_secs(300));
    assert_eq!(generation_after_removal, generation_after_fast_consumer + 1);
    let still_shared = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&slow, &still_shared));

    clear_jwks_cache();
}

#[tokio::test]
async fn shared_store_uses_strictest_max_stale_and_relaxes_only_on_reconcile() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/max-stale/jwks.json?token=secret", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let loose = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(300),
        Duration::from_secs(7_200),
    );
    let strict = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(600),
        Duration::from_secs(1_800),
    );
    assert!(Arc::ptr_eq(&loose, &strict));
    assert_eq!(
        cached_requirement(&uri),
        Some(JwksRefreshRequirement::new(
            Duration::from_secs(300),
            Duration::from_secs(1_800),
        ))
    );

    // A longer request cannot relax a live strict consumer. Only exact
    // committed-generation reconciliation may remove the strict requirement.
    let repeated_loose = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(300),
        Duration::from_secs(7_200),
    );
    assert!(Arc::ptr_eq(&strict, &repeated_loose));
    assert_eq!(
        cached_requirement(&uri).map(|requirement| requirement.max_stale),
        Some(Duration::from_secs(1_800))
    );

    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(300), Duration::from_secs(7_200)),
    )]));
    assert_eq!(
        cached_requirement(&uri).map(|requirement| requirement.max_stale),
        Some(Duration::from_secs(7_200))
    );

    let metrics = render_prometheus();
    assert!(metrics.contains("state=\"fresh\""));
    assert!(metrics.contains("state=\"grace\""));
    assert!(metrics.contains("state=\"expired\""));
    assert!(metrics.contains("class=\"empty\""));
    assert!(metrics.contains("class=\"transport\""));
    assert!(!metrics.contains(&uri));
    assert!(!metrics.contains("token=secret"));

    clear_jwks_cache();
}

#[tokio::test]
async fn policy_reconfiguration_forces_refresh_without_resetting_retained_key_age() {
    let (server, uri) = super::jwks_auth_tests::start_jwks_server(RSA_PUBLIC_PEM).await;
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let store = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(3_600),
        Duration::from_secs(3_600),
    );
    super::jwks_auth_tests::wait_for_received_request_count(&server, 1).await;
    let initial_fetch_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !store.has_keys() {
        assert!(
            std::time::Instant::now() < initial_fetch_deadline,
            "initial JWKS response did not populate the shared store"
        );
        tokio::task::yield_now().await;
    }

    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;

    let initial_age = store
        .health_snapshot()
        .last_success_age
        .expect("the initial fetch records key age");
    let (_, generation_before_policy_change) =
        cached_refresh_state(&uri).expect("shared store remains cached");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(899).saturating_sub(initial_age)).await;

    let before_refresh = store.health_snapshot();
    assert_eq!(
        before_refresh.trust_state,
        JwksTrustState::Fresh,
        "the retained snapshot is still nominally fresh under the original policy"
    );
    assert!(
        before_refresh.last_success_age >= Some(Duration::from_secs(899)),
        "the stricter deadline is only one second away"
    );
    let completions_before = store.refresh_completions();

    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(900), Duration::from_secs(900)),
    )]));
    // Keep the virtual 899-second key age, but let the replacement worker's
    // real HTTP request run on a live clock. Driving reqwest and WireMock while
    // Tokio time is paused can turn a valid response into a transport timeout.
    tokio::time::resume();
    let (interval_after_change, generation_after_policy_change) =
        cached_refresh_state(&uri).expect("shared store remains cached");
    assert_eq!(interval_after_change, Duration::from_secs(900));
    assert_eq!(
        generation_after_policy_change,
        generation_before_policy_change + 1,
        "a changed effective policy must replace the shared refresh worker"
    );

    // The replacement worker must contact the endpoint immediately, without
    // waiting for the new interval. Wait on the store's completion notify
    // rather than a wall-clock scheduling bound.
    store
        .wait_for_refresh_completion_after(completions_before)
        .await;
    assert_eq!(
        store.health_snapshot().last_failure,
        Some(JwksFailureClass::Empty),
        "policy reconfiguration must force an immediate JWKS request"
    );
    let request_count = server
        .received_requests()
        .await
        .map(|requests| requests.len())
        .unwrap_or(0);
    assert!(
        request_count >= 1,
        "policy reconfiguration must force an immediate JWKS request"
    );

    let after_failed_refresh = store.health_snapshot();
    assert_eq!(
        after_failed_refresh.last_failure,
        Some(JwksFailureClass::Empty)
    );
    assert!(
        after_failed_refresh.last_success_age >= before_refresh.last_success_age,
        "restarting the worker must not reset the retained snapshot's key age"
    );

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(store.health_snapshot().trust_state, JwksTrustState::Expired);

    tokio::time::resume();
    clear_jwks_cache();
}

#[tokio::test]
async fn test_different_jwks_uris_get_distinct_store_entries() {
    let server = wiremock::MockServer::start().await;
    let uri_a = format!("{}/issuer-a/jwks.json", server.uri());
    let uri_b = format!("{}/issuer-b/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let first = get_or_create_jwks_store(&uri_a, &client(), Duration::from_secs(300));
    let second = get_or_create_jwks_store(&uri_b, &client(), Duration::from_secs(300));

    assert!(!Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}

#[tokio::test]
async fn test_clear_jwks_cache_forces_store_recreation() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/.well-known/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let first = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    clear_jwks_cache();
    let second = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));

    assert!(!Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}

#[tokio::test]
async fn test_retain_active_uris_removes_stale_entries() {
    let server = wiremock::MockServer::start().await;
    let uri_a = format!("{}/issuer-a/jwks.json", server.uri());
    let uri_b = format!("{}/issuer-b/jwks.json", server.uri());
    let uri_c = format!("{}/issuer-c/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let store_a = get_or_create_jwks_store(&uri_a, &client(), Duration::from_secs(300));
    let store_b = get_or_create_jwks_store(&uri_b, &client(), Duration::from_secs(300));
    let store_c = get_or_create_jwks_store(&uri_c, &client(), Duration::from_secs(300));
    let weak_b = Arc::downgrade(&store_b);

    // Keep only A and C — B should be evicted
    let active: HashSet<String> = [uri_a.clone(), uri_c.clone()].into();
    retain_active_uris(&active);

    // A and C should still return the same store instances (cache hit)
    let store_a2 = get_or_create_jwks_store(&uri_a, &client(), Duration::from_secs(300));
    let store_c2 = get_or_create_jwks_store(&uri_c, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&store_a, &store_a2));
    assert!(Arc::ptr_eq(&store_c, &store_c2));

    // B stays refreshable while an old generation still owns it, then is
    // reaped without requiring another retain_active_uris call.
    drop(store_b);
    for _ in 0..20 {
        if weak_b.upgrade().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(weak_b.upgrade().is_none());
    let store_b2 = get_or_create_jwks_store(&uri_b, &client(), Duration::from_secs(300));
    assert_eq!(store_b2.jwks_uri(), uri_b);

    clear_jwks_cache();
}

#[tokio::test]
async fn test_retain_active_uris_empty_set_clears_all() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/.well-known/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();
    let original = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    let weak = Arc::downgrade(&original);

    // Empty active set retires the store, but the external owner keeps its
    // refresh worker alive until that generation drops.
    retain_active_uris(&HashSet::new());
    drop(original);
    for _ in 0..20 {
        if weak.upgrade().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(weak.upgrade().is_none());

    let recreated = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert_eq!(recreated.jwks_uri(), uri);

    clear_jwks_cache();
}

#[tokio::test]
async fn test_retired_store_revival_cancels_pending_reaper() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/.well-known/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();
    let old_generation = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));

    retain_active_uris(&HashSet::new());
    let revived = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&old_generation, &revived));
    drop(old_generation);
    tokio::time::sleep(Duration::from_millis(250)).await;

    let still_cached = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&revived, &still_cached));

    clear_jwks_cache();
}

#[tokio::test]
async fn superseded_store_is_reaped_after_transient_owner_drops() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/superseded/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();
    let in_flight_owner = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    let weak = Arc::downgrade(&in_flight_owner);

    retire_jwks_store_if_unreferenced(&uri);
    drop(in_flight_owner);
    for _ in 0..20 {
        if weak.upgrade().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(weak.upgrade().is_none());

    clear_jwks_cache();
}

#[tokio::test]
async fn cancelled_discovery_candidate_retires_cache_entry_at_acquisition_boundary() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/cancelled-candidate/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let candidate = jwks_discovery_candidate_for_test(&uri, client(), Duration::from_secs(300));
    assert_eq!(cached_reaper_generation(&uri), Some(0));

    let task = tokio::spawn(async move {
        let _candidate = candidate;
        std::future::pending::<()>().await;
    });
    task.abort();
    let error = task
        .await
        .expect_err("aborting the discovery task must cancel it");
    assert!(error.is_cancelled());
    assert!(cached_refresh_state(&uri).is_none());

    clear_jwks_cache();
}

#[tokio::test]
async fn discarded_candidate_does_not_reap_or_poll_active_shared_store() {
    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/active-shared/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let active_store = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(300), Duration::from_secs(3_600)),
    )]));
    assert_eq!(cached_reaper_generation(&uri), Some(0));

    let discarded = jwks_discovery_candidate_for_test(&uri, client(), Duration::from_secs(300));
    drop(discarded);

    assert_eq!(
        cached_reaper_generation(&uri),
        Some(0),
        "discarding a candidate must not schedule a reaper for an active shared store"
    );
    let still_active = get_or_create_jwks_store(&uri, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&active_store, &still_active));

    clear_jwks_cache();
}

#[tokio::test]
async fn active_remote_trust_health_transitions_and_excludes_inactive() {
    use ferrum_edge::plugins::utils::jwks_cache::{
        republish_trust_health, trust_health_snapshot, trust_health_watch_generation_for_test,
    };

    let (server, uri) = super::jwks_auth_tests::start_jwks_server(RSA_PUBLIC_PEM).await;
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let store = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(10),
        Duration::from_secs(30),
    );
    super::jwks_auth_tests::wait_for_received_request_count(&server, 1).await;
    let populated = std::time::Instant::now() + Duration::from_secs(2);
    while !store.has_keys() {
        assert!(
            std::time::Instant::now() < populated,
            "initial JWKS populate"
        );
        tokio::task::yield_now().await;
    }

    // Inactive cache entries must not affect readiness.
    republish_trust_health();
    let inactive = trust_health_snapshot();
    assert!(inactive.ready(tokio::time::Instant::now()));
    assert!(!inactive.degraded(tokio::time::Instant::now()));
    assert_eq!(
        (inactive.fresh, inactive.grace, inactive.expired),
        (0, 0, 0)
    );

    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(10), Duration::from_secs(30)),
    )]));
    let fresh = trust_health_snapshot();
    assert_eq!((fresh.fresh, fresh.grace, fresh.expired), (1, 0, 0));
    assert!(fresh.ready(tokio::time::Instant::now()));
    assert!(!fresh.degraded(tokio::time::Instant::now()));

    let watch_generation = trust_health_watch_generation_for_test();
    for _ in 0..64 {
        republish_trust_health();
    }
    assert_eq!(
        trust_health_watch_generation_for_test(),
        watch_generation,
        "repeated refresh/metrics publications must reuse the one earlier deadline watcher"
    );

    // Prevent background refresh from resetting key age while we advance through
    // grace and expiry. Recovery re-mounts a valid document below.
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(5)).await;
    let between_publications = trust_health_snapshot();
    assert!(
        between_publications.max_age_seconds_fresh >= 5,
        "the O(1) snapshot must project key age between cache publications"
    );
    tokio::time::advance(Duration::from_secs(5)).await;
    // Deadline comparison flips degraded without a client verification attempt.
    let after_grace_deadline = trust_health_snapshot();
    assert!(after_grace_deadline.ready(tokio::time::Instant::now()));
    assert!(after_grace_deadline.degraded(tokio::time::Instant::now()));
    republish_trust_health();
    let grace = trust_health_snapshot();
    assert_eq!((grace.fresh, grace.grace, grace.expired), (0, 1, 0));
    assert!(grace.ready(tokio::time::Instant::now()));
    assert!(grace.degraded(tokio::time::Instant::now()));

    tokio::time::advance(Duration::from_secs(20)).await;
    let after_expiry_deadline = trust_health_snapshot();
    assert!(!after_expiry_deadline.ready(tokio::time::Instant::now()));
    assert!(after_expiry_deadline.degraded(tokio::time::Instant::now()));
    republish_trust_health();
    let expired = trust_health_snapshot();
    assert_eq!((expired.fresh, expired.grace, expired.expired), (0, 0, 1));
    assert!(!expired.ready(tokio::time::Instant::now()));

    // Recovery after a later validated non-empty refresh. Preserve the
    // virtually advanced key age, but run real HTTP traffic on a live clock.
    tokio::time::resume();
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            super::jwks_auth_tests::build_rsa_jwks_from_pem(RSA_PUBLIC_PEM),
        ))
        .mount(&server)
        .await;
    let before = store.refresh_completions();
    let fetched = store.fetch_keys().await;
    assert!(
        fetched.is_ok(),
        "recovery refresh should succeed: {fetched:?}"
    );
    store.wait_for_refresh_completion_after(before).await;
    republish_trust_health();
    let recovered = trust_health_snapshot();
    assert_eq!(
        (recovered.fresh, recovered.grace, recovered.expired),
        (1, 0, 0)
    );
    assert!(recovered.ready(tokio::time::Instant::now()));
    assert!(!recovered.degraded(tokio::time::Instant::now()));

    // Removing the active registration clears remote readiness pressure.
    retain_active_requirements(&HashMap::new());
    let removed = trust_health_snapshot();
    assert_eq!((removed.fresh, removed.grace, removed.expired), (0, 0, 0));
    assert!(removed.ready(tokio::time::Instant::now()));

    clear_jwks_cache();
}

#[tokio::test]
async fn shared_cache_trust_publish_stays_outside_dashmap_guards() {
    // Contract: create / tighten / retain / relax must not invoke
    // republish_trust_health while a DashMap get_mut, entry, or retain guard
    // is held. configure_trust_policy must not call the trust-change hook, and
    // reconfigure_refresh_policy must not republish under those guards — both
    // previously self-deadlocked by re-entering the same shard. Completing
    // these paths without hanging, and observing coherent O(1) trust health
    // without an explicit test-side republish, encodes that publication stays
    // at post-guard cache boundaries (refresh completions still publish).
    use ferrum_edge::plugins::utils::jwks_cache::trust_health_snapshot;

    let (server, uri) = super::jwks_auth_tests::start_jwks_server(RSA_PUBLIC_PEM).await;
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let store = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(60),
        Duration::from_secs(300),
    );
    super::jwks_auth_tests::wait_for_received_request_count(&server, 1).await;
    let populated = std::time::Instant::now() + Duration::from_secs(2);
    while !store.has_keys() {
        assert!(
            std::time::Instant::now() < populated,
            "initial JWKS populate"
        );
        tokio::task::yield_now().await;
    }

    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(60), Duration::from_secs(300)),
    )]));
    let active = trust_health_snapshot();
    assert_eq!((active.fresh, active.grace, active.expired), (1, 0, 0));
    assert!(active.ready(tokio::time::Instant::now()));
    assert!(!active.degraded(tokio::time::Instant::now()));

    // Empty responses keep the forced policy-change refresh from resetting age
    // while still exercising post-guard publish on the get_mut reconfigure path.
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;

    let completions_before = store.refresh_completions();
    let tightened = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(5),
        Duration::from_secs(300),
    );
    assert!(Arc::ptr_eq(&store, &tightened));
    assert_eq!(
        cached_requirement(&uri),
        Some(JwksRefreshRequirement::new(
            Duration::from_secs(5),
            Duration::from_secs(300),
        ))
    );
    store
        .wait_for_refresh_completion_after(completions_before)
        .await;
    let after_tighten = trust_health_snapshot();
    assert_eq!(
        (
            after_tighten.fresh,
            after_tighten.grace,
            after_tighten.expired
        ),
        (0, 1, 0),
        "failed forced refresh must publish grace without a test-side republish"
    );
    assert!(after_tighten.degraded(tokio::time::Instant::now()));

    retain_active_requirements(&HashMap::from([(
        uri.clone(),
        JwksRefreshRequirement::new(Duration::from_secs(60), Duration::from_secs(300)),
    )]));
    assert_eq!(
        cached_requirement(&uri),
        Some(JwksRefreshRequirement::new(
            Duration::from_secs(60),
            Duration::from_secs(300),
        ))
    );
    let after_relax = trust_health_snapshot();
    assert_eq!(
        (after_relax.fresh, after_relax.grace, after_relax.expired),
        (0, 1, 0),
        "retain must republish after its guard so grace remains visible"
    );

    retain_active_requirements(&HashMap::new());
    let removed = trust_health_snapshot();
    assert_eq!((removed.fresh, removed.grace, removed.expired), (0, 0, 0));

    clear_jwks_cache();
}

// ---------------------------------------------------------------------------
// Asynchronously discovered stores (issue #3739 direct/discovery parity)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn late_registered_store_is_active_immediately_and_expires_without_another_reload() {
    use ferrum_edge::plugins::utils::jwks_cache::{
        LateActiveRequirement, republish_trust_health, trust_health_snapshot,
    };

    let (server, uri) = super::jwks_auth_tests::start_jwks_server(RSA_PUBLIC_PEM).await;
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    // A discovery worker resolves a store *after* its generation's publication
    // reconciliation already ran, so the committed requirement map is empty.
    let store = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        Duration::from_secs(10),
        Duration::from_secs(30),
    );
    super::jwks_auth_tests::wait_for_received_request_count(&server, 1).await;
    let populated = std::time::Instant::now() + Duration::from_secs(2);
    while !store.has_keys() {
        assert!(
            std::time::Instant::now() < populated,
            "initial JWKS populate"
        );
        tokio::task::yield_now().await;
    }
    retain_active_requirements(&HashMap::new());
    let before = trust_health_snapshot();
    assert_eq!(
        (before.fresh, before.grace, before.expired),
        (0, 0, 0),
        "a store no committed consumer has claimed must stay out of readiness"
    );

    // The committed owner publishes its contribution. No reload involved.
    let contribution = LateActiveRequirement::register(
        &uri,
        JwksRefreshRequirement::new(Duration::from_secs(10), Duration::from_secs(30)),
    );
    let active = trust_health_snapshot();
    assert_eq!(
        (active.fresh, active.grace, active.expired),
        (1, 0, 0),
        "a committed discovery-backed store must be visible immediately"
    );
    assert_eq!(
        cached_requirement(&uri).expect("cached entry").max_stale,
        Duration::from_secs(30)
    );

    // Its readiness must transition at max-stale with no further publication.
    server.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [] })))
        .mount(&server)
        .await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    let expired = trust_health_snapshot();
    assert!(
        !expired.ready(tokio::time::Instant::now()),
        "a late-registered store must fail readiness at its own max-stale deadline"
    );
    republish_trust_health();
    let expired = trust_health_snapshot();
    assert_eq!((expired.fresh, expired.grace, expired.expired), (0, 0, 1));
    tokio::time::resume();

    // Retiring the owning generation withdraws exactly this contribution.
    drop(contribution);
    let retired = trust_health_snapshot();
    assert_eq!((retired.fresh, retired.grace, retired.expired), (0, 0, 0));
    assert!(retired.ready(tokio::time::Instant::now()));

    drop(store);
    clear_jwks_cache();
}

#[tokio::test]
async fn shared_uri_strictest_arbitration_spans_committed_and_late_consumers() {
    use ferrum_edge::plugins::utils::jwks_cache::LateActiveRequirement;

    let server = wiremock::MockServer::start().await;
    let uri = format!("{}/shared-late/jwks.json", server.uri());
    let _guard = cache_test_lock().lock().await;
    clear_jwks_cache();

    let relaxed = JwksRefreshRequirement::new(Duration::from_secs(600), Duration::from_secs(3_600));
    let strict = JwksRefreshRequirement::new(Duration::from_secs(60), Duration::from_secs(300));

    let _store = get_or_create_jwks_store_with_policy(
        &uri,
        &client(),
        relaxed.refresh_interval,
        relaxed.max_stale,
    );
    retain_active_requirements(&HashMap::from([(uri.clone(), relaxed)]));
    assert_eq!(cached_requirement(&uri), Some(relaxed));

    // A late discovery-backed consumer of the same URI tightens both bounds.
    let strict_contribution = LateActiveRequirement::register(&uri, strict);
    assert_eq!(
        cached_requirement(&uri),
        Some(strict),
        "the strictest active requirement must win across both contributors"
    );

    // A second committed publication that still carries only the relaxed
    // consumer must not relax the store while the strict consumer is live.
    retain_active_requirements(&HashMap::from([(uri.clone(), relaxed)]));
    assert_eq!(cached_requirement(&uri), Some(strict));

    // Relaxation happens only once the stricter consumer is gone.
    drop(strict_contribution);
    assert_eq!(cached_requirement(&uri), Some(relaxed));

    // A late consumer alone keeps the store active after the committed
    // generation drops it.
    let strict_contribution = LateActiveRequirement::register(&uri, strict);
    retain_active_requirements(&HashMap::new());
    assert_eq!(
        cached_requirement(&uri),
        Some(strict),
        "a publication must not deactivate another consumer of the same URI"
    );

    // Re-pointing that consumer at a replacement URI moves only its own
    // contribution; the original URI has no owner left.
    let replacement_uri = format!("{}/shared-late/rotated.json", server.uri());
    let _replacement = get_or_create_jwks_store_with_policy(
        &replacement_uri,
        &client(),
        relaxed.refresh_interval,
        relaxed.max_stale,
    );
    assert_eq!(cached_requirement(&replacement_uri), Some(relaxed));
    strict_contribution.replace(&replacement_uri, strict);
    assert_eq!(
        cached_requirement(&replacement_uri),
        Some(strict),
        "a replaced discovery URI must carry the consumer's exact requirement"
    );

    drop(strict_contribution);
    clear_jwks_cache();
}

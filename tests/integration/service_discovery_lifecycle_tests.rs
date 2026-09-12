//! Service-discovery task lifecycle integration coverage
//! (issues #3717 / #3721 / #3722).
//!
//! Exercises the production supervisor, reconcile keep/replace decisions, and
//! the bounded-staleness expiry policy against the live `LoadBalancerCache`.
//!
//! The discovery health registry is process-global, so every test here runs
//! under one serializing mutex and resets the registry before it starts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ferrum_edge::circuit_breaker::CircuitBreakerCache;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MeshSdConfig, SdProvider, SdStalePolicy,
    ServiceDiscoveryConfig, Upstream, UpstreamTarget, default_namespace,
};
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::dns::DnsCache;
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::load_balancer::LoadBalancerCache;
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::request_epoch::RequestEpochStore;
use ferrum_edge::service_discovery::health;
use ferrum_edge::service_discovery::{
    DiscoverySnapshot, ServiceDiscoverer, ServiceDiscoveryManager,
    spawn_supervised_discovery_task_for_test,
};

/// The health registry and the Prometheus registry are process-global.
static REGISTRY_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn isolated() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = REGISTRY_GUARD.lock().await;
    health::reset_for_test();
    // The publication-preparation hold is process-global too; a test that
    // panicked while holding one must not block the next test's publications.
    // This blanket clear is panic-cleanup at the start of a serialized
    // lifecycle test. Holder Drop uses the generation-scoped clear so a stale
    // holder cannot steal a newer test's slot.
    ferrum_edge::service_discovery::clear_discovery_publication_preparation_hold_for_test();
    guard
}

// ── Fixtures ──────────────────────────────────────────────────────────

fn target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    }
}

fn mesh_sd_config(service_name: &str, poll_interval_seconds: u64) -> ServiceDiscoveryConfig {
    ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: service_name.to_string(),
            namespace: None,
            port: Some(8080),
            poll_interval_seconds,
            topology: Default::default(),
        }),
        default_weight: 1,
        max_stale_seconds: None,
        stale_policy: None,
    }
}

fn upstream_with_sd(
    id: &str,
    static_targets: Vec<UpstreamTarget>,
    sd: Option<ServiceDiscoveryConfig>,
) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        targets: static_targets,
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: sd,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn config_with(upstreams: Vec<Upstream>) -> GatewayConfig {
    GatewayConfig {
        upstreams,
        ..Default::default()
    }
}

fn epoch_store(config: &GatewayConfig) -> Arc<RequestEpochStore> {
    let plugin_cache = PluginCache::new(config).expect("plugin cache");
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let lb_cache = LoadBalancerCache::new(config);
    Arc::new(RequestEpochStore::from_runtime_parts(
        config.clone(),
        &plugin_cache,
        &consumer_index,
        &lb_cache,
    ))
}

fn manager(config: &GatewayConfig) -> ServiceDiscoveryManager {
    ServiceDiscoveryManager::new(
        Arc::new(LoadBalancerCache::new(config)),
        DnsCache::new(Default::default()),
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        PluginHttpClient::default(),
        Some(epoch_store(config)),
    )
}

fn task_key(id: &str) -> String {
    format!("{}|{}", default_namespace(), id)
}

/// Hosts currently installed in the load balancer for `id`.
fn lb_hosts(lb_cache: &LoadBalancerCache, id: &str) -> Vec<String> {
    lb_cache
        .get_upstream(&default_namespace(), id)
        .map(|upstream| {
            upstream
                .targets
                .iter()
                .map(|target| target.host.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// Discoverer under full test control: it can return targets, fail, or panic.
struct ScriptedDiscoverer {
    calls: Arc<AtomicU64>,
    targets: std::sync::Mutex<Vec<UpstreamTarget>>,
    fail: Arc<AtomicBool>,
    hang: Arc<AtomicBool>,
    panic_until_call: u64,
    /// Delay before a scripted panic, so a test can move registry state while
    /// the poller is provably still inside `discover()`.
    panic_delay: std::time::Duration,
}

impl ScriptedDiscoverer {
    fn new(targets: Vec<UpstreamTarget>) -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            targets: std::sync::Mutex::new(targets),
            fail: Arc::new(AtomicBool::new(false)),
            hang: Arc::new(AtomicBool::new(false)),
            panic_until_call: 0,
            panic_delay: std::time::Duration::ZERO,
        }
    }

    #[cfg(panic = "unwind")]
    fn panicking(panic_until_call: u64) -> Self {
        Self {
            panic_until_call,
            ..Self::new(vec![target("recovered.local", 8080)])
        }
    }

    /// Always panics, but only after `panic_delay`.
    #[cfg(panic = "unwind")]
    fn panicking_slowly(panic_delay: std::time::Duration) -> Self {
        Self {
            panic_until_call: u64::MAX,
            panic_delay,
            ..Self::new(Vec::new())
        }
    }
}

#[async_trait::async_trait]
impl ServiceDiscoverer for ScriptedDiscoverer {
    async fn discover(&self) -> Result<DiscoverySnapshot, anyhow::Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call <= self.panic_until_call {
            if !self.panic_delay.is_zero() {
                tokio::time::sleep(self.panic_delay).await;
            }
            panic!("scripted discovery panic on call {call}");
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("scripted discovery failure"));
        }
        if self.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let targets = self.targets.lock().expect("targets lock").clone();
        Ok(DiscoverySnapshot::from_targets(targets))
    }

    fn provider_name(&self) -> &str {
        "scripted"
    }
}

async fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..600 {
        if predicate() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    predicate()
}

// ── #3722: reconcile keeps unchanged tasks ────────────────────────────

#[tokio::test]
async fn reconcile_keeps_unchanged_discovery_tasks() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("keep-me", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("keep-me-too", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);

    let first = health::generation_for_test(&task_key("keep-me")).expect("task registered");
    let second = health::generation_for_test(&task_key("keep-me-too")).expect("task registered");

    // An unrelated reconcile of an identical config must not churn the pollers:
    // restarting them would drop provider cursors and re-hit every registry.
    manager.reconcile(&config, None);

    assert_eq!(
        health::generation_for_test(&task_key("keep-me")),
        Some(first),
        "an unchanged upstream must keep its running task generation"
    );
    assert_eq!(
        health::generation_for_test(&task_key("keep-me-too")),
        Some(second)
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_replaces_only_the_upstream_whose_discovery_config_changed() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("stable", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("churned", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);

    let stable = health::generation_for_test(&task_key("stable")).expect("task registered");
    let churned = health::generation_for_test(&task_key("churned")).expect("task registered");

    let changed = config_with(vec![
        upstream_with_sd("stable", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        // Only the poll interval moves.
        upstream_with_sd("churned", Vec::new(), Some(mesh_sd_config("svc-b", 15))),
    ]);
    manager.reconcile(&changed, None);

    assert_eq!(
        health::generation_for_test(&task_key("stable")),
        Some(stable),
        "an untouched upstream must not be restarted by another upstream's change"
    );
    assert_ne!(
        health::generation_for_test(&task_key("churned")),
        Some(churned),
        "a changed discovery configuration must replace exactly that task"
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_replaces_kubernetes_task_when_address_family_changes() {
    let _guard = isolated().await;
    let sd: ServiceDiscoveryConfig = serde_json::from_value(serde_json::json!({
        "provider": "kubernetes",
        "kubernetes": {"service_name": "api", "address_type": "IPv4"}
    }))
    .unwrap();
    let config = config_with(vec![upstream_with_sd("family", Vec::new(), Some(sd))]);
    let manager = manager(&config);
    manager.start(&config, None);
    let first = health::generation_for_test(&task_key("family")).expect("task registered");
    manager.reconcile(&config, None);
    assert_eq!(
        health::generation_for_test(&task_key("family")),
        Some(first)
    );

    let mut changed = config.clone();
    changed.upstreams[0]
        .service_discovery
        .as_mut()
        .unwrap()
        .kubernetes
        .as_mut()
        .unwrap()
        .address_type = Some(ferrum_edge::config::types::KubernetesAddressType::Ipv6);
    manager.reconcile(&changed, None);
    let replacement = health::generation_for_test(&task_key("family")).expect("replacement task");
    assert_ne!(replacement, first);
    manager.stop();
}

#[tokio::test]
async fn reconcile_replaces_a_task_whose_static_targets_changed() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd(
        "mixed",
        vec![target("static-a.local", 8080)],
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    let manager = manager(&config);
    manager.start(&config, None);
    let before = health::generation_for_test(&task_key("mixed")).expect("task registered");

    // Static targets are merged under every published snapshot, so they are part
    // of the task's material specification.
    let changed = config_with(vec![upstream_with_sd(
        "mixed",
        vec![target("static-b.local", 8080)],
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    manager.reconcile(&changed, None);

    assert_ne!(
        health::generation_for_test(&task_key("mixed")),
        Some(before)
    );

    manager.stop();
}

#[tokio::test]
async fn reconcile_stops_only_the_removed_upstream() {
    let _guard = isolated().await;

    let config = config_with(vec![
        upstream_with_sd("kept", Vec::new(), Some(mesh_sd_config("svc-a", 30))),
        upstream_with_sd("removed", Vec::new(), Some(mesh_sd_config("svc-b", 30))),
    ]);
    let manager = manager(&config);
    manager.start(&config, None);
    let kept = health::generation_for_test(&task_key("kept")).expect("task registered");
    assert!(health::generation_for_test(&task_key("removed")).is_some());

    let reduced = config_with(vec![upstream_with_sd(
        "kept",
        Vec::new(),
        Some(mesh_sd_config("svc-a", 30)),
    )]);
    manager.reconcile(&reduced, None);

    assert_eq!(health::generation_for_test(&task_key("kept")), Some(kept));
    assert!(
        wait_for(|| health::generation_for_test(&task_key("removed")).is_none()).await,
        "a removed upstream's task must be stopped and deregistered"
    );

    manager.stop();
}

// ── #3721: supervision (unwind-only panic recovery; issue #4166) ──────

#[cfg(panic = "unwind")]
#[tokio::test]
async fn a_panicking_poller_is_restarted_and_recovers() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("supervised", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::panicking(1));
    let calls = Arc::clone(&discoverer.calls);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let panics_before = metrics.service_discovery_task_panics_total();
    let restarts_before = metrics.service_discovery_task_restarts_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "supervised",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        1,
    );

    // The first poll panics; the supervisor must restart the poller and the
    // second poll must publish.
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 2).await,
        "supervisor did not restart the poller after a panic"
    );
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.restarts >= 1)
        })
        .await,
        "the restart must be visible in per-upstream health"
    );

    assert!(
        metrics.service_discovery_task_panics_total() > panics_before,
        "a panicking poller must be counted as a panic, not a graceful stop"
    );
    assert!(metrics.service_discovery_task_restarts_total() > restarts_before);

    let status = health::snapshot()
        .upstreams
        .into_iter()
        .find(|u| u.upstream == task.key)
        .expect("task health present");
    assert_ne!(
        status.state, "stopped",
        "a restarted poller must not be reported as stopped"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn a_clean_cancel_is_not_counted_as_a_crash() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("cancelled", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let panics_before = metrics.service_discovery_task_panics_total();
    let restarts_before = metrics.service_discovery_task_restarts_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "cancelled",
        "scripted",
        Arc::new(ScriptedDiscoverer::new(vec![target("a.local", 8080)])),
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        7,
    );

    let _ = task.cancel_tx.send(true);
    task.handle
        .await
        .expect("supervisor exits cleanly on cancel");

    assert_eq!(
        metrics.service_discovery_task_panics_total(),
        panics_before,
        "cancellation must not increment the panic counter"
    );
    assert_eq!(
        metrics.service_discovery_task_restarts_total(),
        restarts_before,
        "cancellation must not increment the restart counter"
    );
}

#[cfg(panic = "unwind")]
#[tokio::test]
async fn a_superseded_generation_neither_restarts_nor_publishes() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("superseded", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::panicking(u64::MAX));
    let calls = Arc::clone(&discoverer.calls);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "superseded",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 1).await,
        "poller never ran"
    );

    // A reconcile registers a newer generation under the same key while the old
    // supervisor is inside its restart backoff.
    health::register_task_for_test(
        &task.key,
        99,
        "scripted",
        health::resolve_staleness(60, SdStalePolicy::Withdraw, 1),
    );

    task.handle
        .await
        .expect("superseded supervisor exits instead of restarting");

    assert_eq!(
        health::generation_for_test(&task.key),
        Some(99),
        "the superseded supervisor must not have overwritten the newer generation"
    );
}

// ── #3721: the publication fence ──────────────────────────────────────
//
// The invariant is stronger than "check ownership before publishing": a bare
// check followed by a publication leaves a window in which a reconcile can
// register the replacement generation, after which the superseded task still
// overwrites the replacement's load-balancer / request-epoch state. These tests
// pin the atomicity of the check and the publication.

fn scripted_staleness() -> health::DiscoveryStaleness {
    health::resolve_staleness(60, SdStalePolicy::Withdraw, 1)
}

/// Spin until `predicate` holds. Used only to hand off between the fence
/// holder and the thread standing in for a reconcile.
fn spin_until(predicate: impl Fn() -> bool) {
    while !predicate() {
        std::thread::yield_now();
    }
}

#[tokio::test]
async fn a_replacement_generation_cannot_register_between_the_fence_check_and_the_publish() {
    let _guard = isolated().await;

    let key = task_key("fenced-publish");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    let entered = Arc::new(AtomicBool::new(false));
    let replacement_started = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));

    let holder = {
        let key = key.clone();
        let entered = Arc::clone(&entered);
        let replacement_started = Arc::clone(&replacement_started);
        let published = Arc::clone(&published);
        std::thread::spawn(move || {
            health::publish_under_fence_for_test(&key, 1, || {
                entered.store(true, Ordering::SeqCst);
                // Hold the fence across the whole window in which a reconcile
                // tries to install the replacement generation.
                spin_until(|| replacement_started.load(Ordering::SeqCst));
                std::thread::sleep(std::time::Duration::from_millis(200));
                published.store(true, Ordering::SeqCst);
            })
            .is_some()
        })
    };

    spin_until(|| entered.load(Ordering::SeqCst));
    replacement_started.store(true, Ordering::SeqCst);
    // Stands in for the reconcile that registers the replacement. It must not
    // be able to complete while the superseded generation is mid-publication.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    assert!(
        published.load(Ordering::SeqCst),
        "a replacement generation registered while the fenced publication was still running; \
         the ownership check and the publication are not atomic"
    );
    assert!(
        holder.join().expect("fence thread"),
        "the fence must admit the generation that still owned the key"
    );
    assert_eq!(health::generation_for_test(&key), Some(2));

    // Past the replacement, the superseded generation is refused outright.
    let ran = Arc::new(AtomicBool::new(false));
    let refused = health::publish_under_fence_for_test(&key, 1, || {
        ran.store(true, Ordering::SeqCst);
    });
    assert!(refused.is_none(), "a superseded generation must be refused");
    assert!(
        !ran.load(Ordering::SeqCst),
        "a superseded generation must not run its publication at all"
    );
}

/// Drive the production apply pipeline bound to a supervised generation.
#[allow(clippy::too_many_arguments)]
async fn apply_under_generation(
    upstream_id: &str,
    lifecycle_key: &str,
    generation: u64,
    discovered: Vec<UpstreamTarget>,
    state: &mut ferrum_edge::_test_support::DiscoveryLoopStateForTest,
    lb_cache: &LoadBalancerCache,
    dns_cache: &DnsCache,
    health_checker: &HealthChecker,
    circuit_breaker_cache: &CircuitBreakerCache,
    cancel_rx: &tokio::sync::watch::Receiver<bool>,
) -> ferrum_edge::_test_support::DiscoveryApplyControlForTest {
    ferrum_edge::_test_support::apply_service_discovery_snapshot_for_generation_for_test(
        &default_namespace(),
        upstream_id,
        "scripted",
        DiscoverySnapshot::from_targets(discovered),
        state,
        lb_cache,
        &None,
        &[],
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        cancel_rx,
        &None,
        dns_cache,
        health_checker,
        circuit_breaker_cache,
        lifecycle_key,
        generation,
    )
    .await
}

#[tokio::test]
async fn a_closed_lifecycle_channel_prevents_discovery_publication() {
    let _guard = isolated().await;

    let static_target = target("static.local", 9000);
    let config = config_with(vec![upstream_with_sd(
        "closed-lifecycle",
        vec![static_target.clone()],
        None,
    )]);
    let lb_cache = LoadBalancerCache::new(&config);
    let dns_cache = DnsCache::new(Default::default());
    let health_checker = HealthChecker::new();

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    drop(cancel_tx);
    let mut canceled_state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();
    let canceled = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
        &default_namespace(),
        "closed-lifecycle",
        "scripted",
        DiscoverySnapshot::from_targets(vec![target("canceled.local", 8080)]),
        &mut canceled_state,
        &lb_cache,
        &None,
        std::slice::from_ref(&static_target),
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        &cancel_rx,
        &None,
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
    )
    .await;
    assert_eq!(
        canceled,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Stop
    );

    let (_live_cancel_tx, live_cancel_rx) = tokio::sync::watch::channel(false);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    drop(shutdown_tx);
    let mut shutdown_state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();
    let shut_down = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
        &default_namespace(),
        "closed-lifecycle",
        "scripted",
        DiscoverySnapshot::from_targets(vec![target("shutdown.local", 8080)]),
        &mut shutdown_state,
        &lb_cache,
        &None,
        std::slice::from_ref(&static_target),
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        &live_cancel_rx,
        &Some(shutdown_rx),
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
    )
    .await;
    assert_eq!(
        shut_down,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Stop
    );

    let hosts = lb_hosts(&lb_cache, "closed-lifecycle");
    assert!(hosts.contains(&"static.local".to_string()));
    assert!(!hosts.contains(&"canceled.local".to_string()));
    assert!(!hosts.contains(&"shutdown.local".to_string()));
}

#[tokio::test]
async fn a_superseded_generation_publishes_no_discovered_snapshot() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("fenced-snapshot", Vec::new(), None)]);
    let lb_cache = LoadBalancerCache::new(&config);
    let dns_cache = DnsCache::new(Default::default());
    let health_checker = HealthChecker::new();
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let key = task_key("fenced-snapshot");

    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());
    let mut state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();

    // Current generation: the fence admits the publication.
    let control = apply_under_generation(
        "fenced-snapshot",
        &key,
        1,
        vec![target("first.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
        &cancel_rx,
    )
    .await;
    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
    );
    assert_eq!(lb_hosts(&lb_cache, "fenced-snapshot"), vec!["first.local"]);

    // A reconcile installs the replacement generation.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    let control = apply_under_generation(
        "fenced-snapshot",
        &key,
        1,
        vec![target("superseded.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
        &cancel_rx,
    )
    .await;

    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Stop,
        "a superseded generation must stop instead of publishing"
    );
    assert_eq!(
        lb_hosts(&lb_cache, "fenced-snapshot"),
        vec!["first.local"],
        "a superseded generation must not overwrite the replacement's load-balancer state"
    );
}

/// Recovery must invalidate the cached coarse aggregate even when the stale
/// window it clears was never claimed by an expiry episode.
///
/// `stale` and `readiness_failing` are derived from the staleness anchor at
/// compute time, not stored, and a task is stale-but-unclaimed for as long as
/// its poller sits mid-publication: the deadline is armed across asynchronous
/// preparation, but preparation that completes first wins that select and the
/// anchor can still cross the bound during the synchronous fenced
/// installation. A coarse recompute driven by any *other*
/// task's lifecycle transition inside that window caches `ready: false`, so the
/// success that ends the window has to refresh it — otherwise `/health` and
/// `/status` keep answering 503 after discovery has fully recovered, with no
/// further transition left to clear it.
#[tokio::test]
async fn recovery_from_an_unclaimed_stale_window_clears_cached_readiness() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("cached-ready", Vec::new(), None)]);
    let lb_cache = LoadBalancerCache::new(&config);
    let dns_cache = DnsCache::new(Default::default());
    let health_checker = HealthChecker::new();
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let key = task_key("cached-ready");

    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());
    let mut state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();

    let control = apply_under_generation(
        "cached-ready",
        &key,
        1,
        vec![target("first.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
        &cancel_rx,
    )
    .await;
    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
    );

    // Age past the 60s bound with no supervisor attached, so nothing claims or
    // withdraws the episode. `age_anchor_for_test` recomputes the coarse
    // aggregate exactly as a concurrent task's transition would, which is what
    // caches the fail-closed verdict.
    assert!(health::age_anchor_for_test(&key, 600));
    assert_eq!(health::coarse_aggregate().stale, 1);
    assert!(
        !health::coarse_aggregate().ready(),
        "an unclaimed stale window under the withdraw policy fails readiness closed"
    );

    // Recovery through the production publication path.
    let control = apply_under_generation(
        "cached-ready",
        &key,
        1,
        vec![target("recovered.local", 8080)],
        &mut state,
        &lb_cache,
        &dns_cache,
        &health_checker,
        &CircuitBreakerCache::default(),
        &cancel_rx,
    )
    .await;
    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
    );

    assert_eq!(
        health::aggregate().stale,
        0,
        "the admitted snapshot advanced the staleness anchor"
    );
    assert!(
        health::coarse_aggregate().ready(),
        "a success that clears an unclaimed stale window must invalidate the cache"
    );
    assert!(
        !health::coarse_aggregate().degraded(),
        "a recovered task must not keep reporting degraded coarse health"
    );
}

#[tokio::test]
async fn a_superseded_generation_publishes_no_staleness_withdrawal() {
    let _guard = isolated().await;

    let key = task_key("fenced-withdrawal");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    // While current, the fenced withdrawal publishes and claims the episode.
    let published = health::publish_withdrawal_under_fence_for_test(&key, 1, || Ok(()))
        .expect("the current generation may withdraw");
    assert!(published.0.is_ok());
    assert!(published.1, "the current generation claims its episode");
    assert_eq!(health::expiry_applied_for_test(&key), Some(true));

    // A second withdrawal in the same episode publishes but does not re-claim,
    // so the operator warning and metric stay one-per-episode.
    let repeat = health::publish_withdrawal_under_fence_for_test(&key, 1, || Ok(()))
        .expect("still the current generation");
    assert!(!repeat.1, "an episode must be claimed exactly once");

    // A reconcile installs the replacement generation.
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    let ran = Arc::new(AtomicBool::new(false));
    let refused = health::publish_withdrawal_under_fence_for_test(&key, 1, || {
        ran.store(true, Ordering::SeqCst);
        Ok(())
    });
    assert!(
        refused.is_none(),
        "a superseded generation must not publish a static-only withdrawal"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the withdrawal publication must not run at all for a superseded generation"
    );
    assert_eq!(
        health::expiry_applied_for_test(&key),
        Some(false),
        "a superseded generation must not consume the replacement's expiry episode"
    );
}

#[tokio::test]
async fn a_replacement_generation_cannot_register_during_a_fenced_withdrawal() {
    let _guard = isolated().await;

    let key = task_key("fenced-withdrawal-race");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    let entered = Arc::new(AtomicBool::new(false));
    let replacement_started = Arc::new(AtomicBool::new(false));
    let published = Arc::new(AtomicBool::new(false));

    let holder = {
        let key = key.clone();
        let entered = Arc::clone(&entered);
        let replacement_started = Arc::clone(&replacement_started);
        let published = Arc::clone(&published);
        std::thread::spawn(move || {
            health::publish_withdrawal_under_fence_for_test(&key, 1, || {
                entered.store(true, Ordering::SeqCst);
                spin_until(|| replacement_started.load(Ordering::SeqCst));
                std::thread::sleep(std::time::Duration::from_millis(200));
                published.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_some()
        })
    };

    spin_until(|| entered.load(Ordering::SeqCst));
    replacement_started.store(true, Ordering::SeqCst);
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    assert!(
        published.load(Ordering::SeqCst),
        "a replacement generation registered while a staleness withdrawal was mid-publication"
    );
    assert!(holder.join().expect("fence thread"));
    assert_eq!(health::generation_for_test(&key), Some(2));
    assert_eq!(
        health::expiry_applied_for_test(&key),
        Some(false),
        "the replacement's fresh entry must not inherit the superseded episode claim"
    );
}

#[tokio::test(start_paused = true)]
async fn a_superseded_supervisor_does_not_withdraw_when_its_staleness_bound_elapses() {
    let _guard = isolated().await;
    let poll_interval = 1;
    let configured_max_stale = 3;
    let resolved_max_stale =
        health::resolve_staleness(configured_max_stale, SdStalePolicy::Withdraw, poll_interval)
            .max_stale
            .expect("a nonzero staleness bound must resolve to a finite duration");

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "superseded-stale",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    // IP literal: publication preparation DNS-warms discovered hostnames, and a
    // `.local` lookup is real I/O. Hosted CI let that warmup outlive the 3s
    // gen-1 bound, so the still-current poller fail-closed withdrew (metric=1)
    // and a later poll republished before this test could supersede.
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        PAUSED_PREPARATION_DISCOVERED_HOST,
        8080,
    )]));
    let hang = Arc::clone(&discoverer.hang);
    let calls = Arc::clone(&discoverer.calls);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "superseded-stale",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        poll_interval,
        configured_max_stale,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for_progress(|| {
            health::snapshot().upstreams.iter().any(|upstream| {
                upstream.upstream == task.key && upstream.last_success_age_seconds.is_some()
            })
        })
        .await,
        "initial discovered snapshot must publish"
    );
    assert!(
        lb_has_host(
            &lb_cache,
            "superseded-stale",
            PAUSED_PREPARATION_DISCOVERED_HOST
        ),
        "initial discovered snapshot must be routable"
    );

    // Park the poller inside discover() so the registry stops answering, then
    // supersede it exactly as a reconcile would — before its resolved staleness
    // bound elapses. A deadline armed before the replacement registered still
    // reaches the expiry path, where the fence must refuse it.
    hang.store(true, Ordering::SeqCst);
    // Advance only the poll interval so the hung discover() samples its deadline
    // while generation 1 still owns the key.
    let poll_advance = std::time::Duration::from_secs(poll_interval);
    tokio::time::advance(poll_advance).await;
    assert!(
        wait_for_progress(|| calls.load(Ordering::SeqCst) >= 2).await,
        "the poller must park inside discover() with its pre-supersession deadline armed"
    );
    health::register_task_for_test(&task.key, 99, "scripted", scripted_staleness());

    // Cross the resolved deadline after accounting for the poll advance. The
    // fence must refuse the deadline armed while generation 1 owned the key.
    let remaining_stale_window = resolved_max_stale - poll_advance;
    let withdrew = wait_for_deadline_action(remaining_stale_window, || {
        metrics.service_discovery_stale_withdrawals_total() > withdrawals_before
            || health::expiry_applied_for_test(&task.key) == Some(true)
            || !lb_has_host(
                &lb_cache,
                "superseded-stale",
                PAUSED_PREPARATION_DISCOVERED_HOST,
            )
    })
    .await;
    assert!(
        !withdrew,
        "a superseded generation must not withdraw after its pre-supersession deadline elapses"
    );

    assert!(
        lb_has_host(
            &lb_cache,
            "superseded-stale",
            PAUSED_PREPARATION_DISCOVERED_HOST
        ),
        "a superseded generation must not withdraw discovered targets"
    );
    assert_eq!(
        health::expiry_applied_for_test(&task.key),
        Some(false),
        "a superseded generation must not claim the replacement's expiry episode"
    );
    assert_eq!(
        metrics.service_discovery_stale_withdrawals_total(),
        withdrawals_before,
        "no withdrawal may be recorded for a superseded generation"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

// ── #3717: bounded staleness ──────────────────────────────────────────

#[tokio::test]
async fn expiry_withdraws_discovered_targets_and_retains_static_targets() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd("stale-mixed", statics.clone(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "stale-mixed",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    // Publish once, then stop answering.
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await,
        "initial snapshot never published"
    );
    fail.store(true, Ordering::SeqCst);

    // Force the staleness anchor past the effective window instead of sleeping.
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.withdrawn)
        })
        .await,
        "expired discovered targets were never withdrawn"
    );

    assert!(metrics.service_discovery_stale_withdrawals_total() > withdrawals_before);

    let aggregate = health::aggregate();
    assert_eq!(aggregate.withdrawn, 1);
    assert!(
        aggregate.degraded(),
        "a withdrawn upstream must degrade coarse health"
    );
    assert!(
        aggregate.ready(),
        "the withdraw policy removes unsafe routes without failing gateway readiness"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn expiry_recovers_and_republishes_without_a_config_reload() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("recovering", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let recoveries_before = metrics.service_discovery_stale_recoveries_total();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "recovering",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));
    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.withdrawn)
        })
        .await,
        "expiry never applied"
    );

    // Registry comes back.
    fail.store(false, Ordering::SeqCst);

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && !u.withdrawn && !u.stale)
        })
        .await,
        "a recovered registry must clear stale/withdrawn state without a reload"
    );
    assert!(metrics.service_discovery_stale_recoveries_total() > recoveries_before);

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn expiry_withdrawal_is_not_blocked_by_a_hung_discovery_call() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("hung-registry", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let calls = Arc::clone(&discoverer.calls);
    let hang = Arc::clone(&discoverer.hang);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "hung-registry",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot().upstreams.iter().any(|upstream| {
                upstream.upstream == task.key && upstream.last_success_age_seconds.is_some()
            })
        })
        .await,
        "initial discovered snapshot must publish"
    );
    hang.store(true, Ordering::SeqCst);
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 2).await,
        "second discovery call must enter the scripted hang"
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|upstream| upstream.upstream == task.key && upstream.withdrawn)
        })
        .await,
        "staleness withdrawal must fire while discovery remains pending"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn failed_expiry_publication_retries_and_fails_readiness_closed() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("withdraw-retry", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let base_store = epoch_store(&config);
    let exhausted_store = Arc::new(
        ferrum_edge::_test_support::request_epoch_store_with_lb_generation_for_test(
            &base_store,
            u64::MAX - 1,
        ),
    );
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "stale-discovered.local",
        8080,
    )]));
    let calls = discoverer.calls.clone();
    let hang = discoverer.hang.clone();

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "withdraw-retry",
        "scripted",
        discoverer,
        lb_cache,
        Some(exhausted_store),
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot().upstreams.iter().any(|upstream| {
                upstream.upstream == task.key && upstream.last_success_age_seconds.is_some()
            })
        })
        .await,
        "initial discovered snapshot must publish before LB generation exhaustion"
    );
    let calls_before_hang = calls.load(Ordering::SeqCst);
    hang.store(true, Ordering::SeqCst);
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) > calls_before_hang).await,
        "the provider must enter a post-snapshot hang before staleness is forced"
    );
    assert!(health::age_anchor_for_test(&task.key, 600));
    assert!(
        wait_for(|| health::expiry_retry_attempts_for_test(&task.key).is_some_and(|n| n >= 2))
            .await,
        "a failed withdrawal publication must be retried with bounded delay"
    );

    let snapshot = health::snapshot();
    let status = snapshot
        .upstreams
        .iter()
        .find(|upstream| upstream.upstream == task.key)
        .expect("task health remains registered");
    assert!(status.stale);
    assert!(!status.withdrawn);
    assert_eq!(status.last_error, Some("publish_failed"));
    assert!(
        !snapshot.aggregate.ready(),
        "withdraw policy must fail readiness while stale targets remain installed"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn fail_readiness_policy_degrades_readiness_until_recovery() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("critical", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "critical",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::FailReadiness,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    assert!(health::aggregate().ready(), "healthy discovery is ready");

    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| !health::aggregate().ready()).await,
        "an expired fail_readiness upstream must fail gateway readiness"
    );

    fail.store(false, Ordering::SeqCst);
    assert!(
        wait_for(|| health::aggregate().ready()).await,
        "readiness must restore after a fresh snapshot"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn retain_policy_keeps_targets_but_still_reports_staleness() {
    let _guard = isolated().await;

    let config = config_with(vec![upstream_with_sd("legacy", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        "discovered.local",
        8080,
    )]));
    let fail = Arc::clone(&discoverer.fail);

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "legacy",
        "scripted",
        discoverer,
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        1,
        3,
        SdStalePolicy::Retain,
        1,
    );

    assert!(
        wait_for(|| {
            health::snapshot()
                .upstreams
                .iter()
                .any(|u| u.upstream == task.key && u.last_success_age_seconds.is_some())
        })
        .await
    );
    fail.store(true, Ordering::SeqCst);
    assert!(health::age_anchor_for_test(&task.key, 600));

    assert!(
        wait_for(|| health::aggregate().stale == 1).await,
        "retain must still report staleness"
    );

    let status = health::snapshot()
        .upstreams
        .into_iter()
        .find(|u| u.upstream == task.key)
        .expect("task health present");
    assert!(
        !status.withdrawn,
        "retain must not withdraw discovered targets"
    );
    assert_eq!(status.policy, "retain");
    assert!(
        health::aggregate().ready(),
        "retain never fails gateway readiness"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

#[tokio::test]
async fn per_upstream_unbounded_retention_falls_back_to_the_bounded_default() {
    let _guard = isolated().await;

    // No unsafe opt-in installed for this process: an upstream asking for
    // unbounded retention must not get it.
    let resolved = health::resolve_upstream_staleness(Some(0), None, 30);

    assert!(
        resolved.staleness.max_stale.is_some(),
        "unbounded retention must not be reachable by editing one upstream"
    );
    assert!(
        resolved.unbounded_request_refused,
        "the refusal must be reported to the caller that starts the task"
    );

    // A valid per-upstream bound reports no refusal, so nothing warns.
    let ordinary = health::resolve_upstream_staleness(Some(120), None, 30);
    assert!(!ordinary.unbounded_request_refused);
    let defaulted = health::resolve_upstream_staleness(None, None, 30);
    assert!(!defaulted.unbounded_request_refused);
}

#[tokio::test]
async fn per_upstream_unbounded_retention_is_honored_under_the_opt_in() {
    let _guard = isolated().await;

    health::override_discovery_staleness_policy_for_test(Some(
        ferrum_edge::config::env_config::DiscoveryStalenessPolicy {
            max_stale_seconds: 300,
            policy: SdStalePolicy::Withdraw,
            allow_unbounded: true,
        },
    ));

    let resolved = health::resolve_upstream_staleness(Some(0), None, 30);
    health::override_discovery_staleness_policy_for_test(None);

    assert_eq!(resolved.staleness.max_stale, None);
    assert!(
        !resolved.unbounded_request_refused,
        "an admitted opt-in is not a refusal and must not warn"
    );
}

// ── #3717 × #3721: expiry must lose to cancellation and shutdown ──────
//
// The staleness timer and the lifecycle signals race by construction: a
// reconcile cancels a task, and the manager registers the replacement, while
// the outgoing task may already be inside its expiry path. A stale generation
// that wins that race installs static-only targets over the routing state its
// replacement is about to own, and consumes the replacement's expiry episode so
// the real withdrawal is never reported. These tests drive the production
// expiry application at an exact point instead of racing a live poller.

/// Probe over the production staleness-expiry path for one generation.
fn expiry_probe(
    upstream_id: &str,
    lb_cache: Arc<LoadBalancerCache>,
    static_targets: Vec<UpstreamTarget>,
    policy: SdStalePolicy,
    generation: u64,
) -> ferrum_edge::service_discovery::StalenessExpiryProbeForTest {
    ferrum_edge::service_discovery::staleness_expiry_probe_for_test(
        &default_namespace(),
        upstream_id,
        "scripted",
        lb_cache,
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        static_targets,
        LoadBalancerAlgorithm::RoundRobin,
        1,
        60,
        policy,
        generation,
        true,
    )
}

/// Install the merged view a poller would have published before it went stale.
fn seed_published_targets(lb_cache: &LoadBalancerCache, upstream_id: &str) {
    lb_cache.update_targets(
        &default_namespace(),
        upstream_id,
        vec![
            target("static.local", 9000),
            target("discovered.local", 8080),
        ],
        LoadBalancerAlgorithm::RoundRobin,
        None,
    );
}

#[tokio::test]
async fn a_canceled_generation_neither_withdraws_nor_claims_its_expiry_episode() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "cancel-vs-expiry",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();
    let expiries_before = metrics.service_discovery_stale_expiries_total();

    let mut probe = expiry_probe(
        "cancel-vs-expiry",
        Arc::clone(&lb_cache),
        statics,
        SdStalePolicy::Withdraw,
        1,
    );
    seed_published_targets(&lb_cache, "cancel-vs-expiry");
    probe.set_installed_discovered(vec![target("discovered.local", 8080)]);

    // A reconcile cancels this task before registering its replacement.
    probe.cancel();

    assert_eq!(
        probe.apply_expiry(),
        ferrum_edge::service_discovery::StalenessExpiryOutcome::Aborted,
        "a canceled task must abort its expiry application, not publish it"
    );
    assert!(
        lb_hosts(&lb_cache, "cancel-vs-expiry").contains(&"discovered.local".to_string()),
        "a canceled task must not install static-only targets over the routing \
         state its replacement is about to own"
    );
    assert_eq!(
        health::expiry_applied_for_test(&probe.key),
        Some(false),
        "a canceled task must not claim the expiry episode"
    );
    assert_eq!(
        health::expiry_retry_attempts_for_test(&probe.key),
        Some(0),
        "an abort is not a publication failure and must not schedule a retry"
    );
    assert_eq!(
        metrics.service_discovery_stale_withdrawals_total(),
        withdrawals_before,
        "an aborted expiry must not record a withdrawal"
    );
    assert_eq!(
        metrics.service_discovery_stale_expiries_total(),
        expiries_before,
        "an aborted expiry must not record an expiry"
    );
}

#[tokio::test]
async fn a_shutting_down_generation_does_not_claim_a_retain_policy_expiry() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "shutdown-vs-expiry",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let expiries_before = metrics.service_discovery_stale_expiries_total();

    // `retain` never touches routing, but claiming its episode is still a
    // lifecycle-owned mutation: a task on its way out must not consume it.
    let mut probe = expiry_probe(
        "shutdown-vs-expiry",
        Arc::clone(&lb_cache),
        statics,
        SdStalePolicy::Retain,
        1,
    );
    seed_published_targets(&lb_cache, "shutdown-vs-expiry");
    probe.shutdown();

    assert_eq!(
        probe.apply_expiry(),
        ferrum_edge::service_discovery::StalenessExpiryOutcome::Aborted,
        "global shutdown must abort the expiry application"
    );
    assert_eq!(
        health::expiry_applied_for_test(&probe.key),
        Some(false),
        "a shutting-down task must not claim the expiry episode"
    );
    assert_eq!(
        metrics.service_discovery_stale_expiries_total(),
        expiries_before
    );

    // Without the lifecycle signal the same probe applies the retain expiry.
    let mut fresh = expiry_probe(
        "shutdown-vs-expiry",
        Arc::clone(&lb_cache),
        Vec::new(),
        SdStalePolicy::Retain,
        2,
    );
    assert_eq!(
        fresh.apply_expiry(),
        ferrum_edge::service_discovery::StalenessExpiryOutcome::Applied
    );
    assert_eq!(health::expiry_applied_for_test(&fresh.key), Some(true));
    assert!(metrics.service_discovery_stale_expiries_total() > expiries_before);
}

#[tokio::test]
async fn a_replaced_generation_reports_supersession_rather_than_publishing() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "replaced-vs-expiry",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));

    let mut probe = expiry_probe(
        "replaced-vs-expiry",
        Arc::clone(&lb_cache),
        statics,
        SdStalePolicy::Withdraw,
        1,
    );
    seed_published_targets(&lb_cache, "replaced-vs-expiry");
    probe.set_installed_discovered(vec![target("discovered.local", 8080)]);

    // The reconcile completed: a replacement generation owns the key.
    health::register_task_for_test(&probe.key, 99, "scripted", scripted_staleness());

    assert_eq!(
        probe.apply_expiry(),
        ferrum_edge::service_discovery::StalenessExpiryOutcome::Superseded,
        "supersession is distinct from an abort and from a publication failure"
    );
    assert!(
        lb_hosts(&lb_cache, "replaced-vs-expiry").contains(&"discovered.local".to_string()),
        "a superseded generation must not overwrite the replacement's routing state"
    );
    assert_eq!(
        health::expiry_applied_for_test(&probe.key),
        Some(false),
        "a superseded task must not consume the replacement's expiry episode"
    );
    assert_eq!(
        health::expiry_retry_attempts_for_test(&probe.key),
        Some(0),
        "supersession must not be retried as a publication failure"
    );
}

#[tokio::test]
async fn a_lifecycle_abort_inside_the_withdrawal_fence_claims_nothing() {
    let _guard = isolated().await;

    let key = task_key("fenced-withdrawal-abort");
    health::register_task_for_test(&key, 1, "scripted", scripted_staleness());

    let entered = Arc::new(AtomicBool::new(false));
    let replacement_started = Arc::new(AtomicBool::new(false));
    let decided = Arc::new(AtomicBool::new(false));

    let holder = {
        let key = key.clone();
        let entered = Arc::clone(&entered);
        let replacement_started = Arc::clone(&replacement_started);
        let decided = Arc::clone(&decided);
        std::thread::spawn(move || {
            health::publish_withdrawal_under_fence_with_abort_for_test(&key, 1, || {
                entered.store(true, Ordering::SeqCst);
                // Hold the fence across the whole window in which a reconcile
                // tries to install the replacement generation, then decide —
                // inside the fence — that the lifecycle signal won.
                spin_until(|| replacement_started.load(Ordering::SeqCst));
                std::thread::sleep(std::time::Duration::from_millis(200));
                decided.store(true, Ordering::SeqCst);
                None
            })
        })
    };

    spin_until(|| entered.load(Ordering::SeqCst));
    replacement_started.store(true, Ordering::SeqCst);
    health::register_task_for_test(&key, 2, "scripted", scripted_staleness());

    assert!(
        decided.load(Ordering::SeqCst),
        "a replacement generation registered while the withdrawal fence was held; \
         the lifecycle check and the routing mutation are not atomic"
    );
    assert_eq!(
        holder.join().expect("fence thread"),
        health::FencedWithdrawalForTest::Aborted,
        "a lifecycle abort inside the fence is neither a publication nor a failure"
    );
    assert_eq!(
        health::expiry_applied_for_test(&key),
        Some(false),
        "an aborted withdrawal must not claim any expiry episode"
    );
}

// ── #3717 × #3721: expiry during supervisor restart backoff ───────────

/// Bounded variant of [`wait_for`]: at most `polls` × 10ms of real or paused
/// time. Under `start_paused` each sleep auto-advances the clock; use
/// [`wait_for_progress`] for scheduling seams and [`wait_for_deadline_action`]
/// for timer-backed production events instead of this helper.
async fn wait_for_within(polls: u32, mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..polls {
        if predicate() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    predicate()
}

/// Wait for a scheduling or state-transition predicate without advancing
/// paused time.
///
/// Hosted mesh-protocols shards (jobs 94564143416 / 94550479399) failed
/// `expiry_withdraws_on_time_while_publication_preparation_is_blocked` and
/// `a_retain_policy_expiry_keeps_a_pending_publication_alive` in ~0.1s:
/// `wait_for_within`'s 10ms sleeps auto-advance ~20s of virtual time while
/// the poller is off the timer wheel (hold watch, or real DNS warmup after
/// release). The production event after release is that the parked waiter
/// continues and publishes — yield until that state is visible.
async fn wait_for_progress(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..10_000 {
        if predicate() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    predicate()
}

/// Advance paused time by the production deadline, then yield until the
/// timer-backed action is visible. Does not keep auto-advancing past that
/// deadline the way [`wait_for_within`] would.
async fn wait_for_deadline_action(
    deadline: std::time::Duration,
    predicate: impl FnMut() -> bool,
) -> bool {
    tokio::task::yield_now().await;
    tokio::time::advance(deadline + std::time::Duration::from_millis(1)).await;
    wait_for_progress(predicate).await
}

#[cfg(panic = "unwind")]
#[tokio::test]
async fn a_crash_looping_poller_still_expires_and_withdraws_during_restart_backoff() {
    let _guard = isolated().await;

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "crash-loop-stale",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    // Every poll panics after a short delay, so the test can move the staleness
    // anchor while the poller is provably still inside `discover()`.
    let discoverer = Arc::new(ScriptedDiscoverer::panicking_slowly(
        std::time::Duration::from_millis(500),
    ));
    let calls = Arc::clone(&discoverer.calls);
    let metrics = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let withdrawals_before = metrics.service_discovery_stale_withdrawals_total();

    // Stand in for the snapshot this upstream published before it went bad.
    seed_published_targets(&lb_cache, "crash-loop-stale");

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "crash-loop-stale",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        1,
        // Long enough that the bound never elapses on its own: only the forced
        // anchor below expires this task.
        600,
        SdStalePolicy::Withdraw,
        1,
    );

    // Two crashes in, the supervisor's next backoff window is seconds long.
    assert!(
        wait_for(|| calls.load(Ordering::SeqCst) >= 3).await,
        "the poller never entered a crash loop"
    );
    // Expire the task while the third poll is still sleeping toward its panic,
    // so the deadline is already elapsed when the supervisor re-arms it at the
    // top of the following backoff window.
    assert!(health::age_anchor_for_test(&task.key, 6000));

    // The supervisor must apply expiry inside that backoff window. Waiting for
    // the next poller generation instead would take the whole (multi-second,
    // and still growing) backoff, and a poller that panics before reaching its
    // own timer would never apply it at all.
    assert!(
        wait_for_within(200, || {
            health::expiry_applied_for_test(&task.key) == Some(true)
        })
        .await,
        "a crash-looping generation must still expire during restart backoff"
    );

    let hosts = lb_hosts(&lb_cache, "crash-loop-stale");
    assert!(
        !hosts.contains(&"discovered.local".to_string()),
        "expired discovered targets must be withdrawn from routing"
    );
    assert!(
        hosts.contains(&"static.local".to_string()),
        "static targets must survive a staleness withdrawal"
    );
    assert!(
        metrics.service_discovery_stale_withdrawals_total() > withdrawals_before,
        "the withdrawal must be recorded exactly as a poller-applied one is"
    );
    assert!(
        health::snapshot()
            .upstreams
            .iter()
            .any(|u| u.upstream == task.key && u.withdrawn),
        "the withdrawal must be visible in per-upstream health"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

// ── #3717: the deadline stays armed across publication preparation ────
//
// Admission is not publication. After a snapshot is admitted the poller still
// has to prepare it — DNS warmup for every discovered hostname — before
// anything becomes routable, and that step is unbounded in principle: a large
// catalog or a slow/unresponsive DNS set can hold it open arbitrarily long.
// While it was unfenced, the *old* dynamic targets stayed routable for exactly
// that long, no matter what `max_stale_seconds` promised.
//
// Real DNS latency is not controllable, so these tests block preparation at an
// exact point instead, and run on a paused clock so the staleness deadline is
// virtual time rather than seconds of real sleeping. Discovered targets in
// this group are IP literals so the post-hold warmup cannot stall on the
// network while virtual time races ahead.

/// RAII wrapper: the hold is process-global, so it must not outlive its test.
/// Drop releases *this* generation only — a stale holder must not clear or
/// release a newer test's hold.
struct PreparationHold(Arc<ferrum_edge::service_discovery::PublicationPreparationHold>);

impl PreparationHold {
    fn install() -> Self {
        Self(ferrum_edge::service_discovery::hold_discovery_publication_preparation_for_test())
    }

    fn inner(&self) -> Arc<ferrum_edge::service_discovery::PublicationPreparationHold> {
        Arc::clone(&self.0)
    }

    fn generation(&self) -> u64 {
        self.0.generation()
    }

    /// How many publication preparations have parked on this hold.
    fn entered(&self) -> u64 {
        self.0.entered()
    }

    fn passed(&self) -> u64 {
        self.0.passed()
    }

    fn is_released(&self) -> bool {
        self.0.is_released()
    }

    fn is_installed(&self) -> bool {
        self.0.is_installed()
    }

    /// Release this generation, wait until parked waiters observe it, then let
    /// Drop clear the slot if we still own it. Required under paused time:
    /// dropping the hold without this handshake lets a sleep-poll auto-advance
    /// to exhaustion while the poller is still parked.
    async fn release_and_observe(self) {
        self.0.release();
        assert!(
            self.0.wait_until_release_observed().await,
            "parked publication preparation must observe this hold generation's release"
        );
    }
}

impl Drop for PreparationHold {
    fn drop(&mut self) {
        self.0.release();
        ferrum_edge::service_discovery::clear_discovery_publication_preparation_hold_generation_for_test(
            self.0.generation(),
        );
    }
}

/// Per-upstream lifecycle detail for `key`, if it is registered.
fn task_status(key: &str) -> Option<health::DiscoveryTaskStatus> {
    health::snapshot()
        .upstreams
        .into_iter()
        .find(|upstream| upstream.upstream == key)
}

/// Whether `host` is currently routable for `upstream_id`.
fn lb_has_host(lb_cache: &LoadBalancerCache, upstream_id: &str, host: &str) -> bool {
    lb_hosts(lb_cache, upstream_id).iter().any(|h| h == host)
}

/// Effective staleness window for the tasks below is `max(5, 3 x poll)`.
const BLOCKED_PREPARATION_POLL_SECONDS: u64 = 1;
const BLOCKED_PREPARATION_MAX_STALE_SECONDS: u64 = 5;
/// TEST-NET-1 literal used by paused-clock preparation tests. Publication
/// preparation DNS-warms every discovered hostname after the test hold; a
/// name lookup is real I/O and cannot complete while `start_paused` auto-
/// advances virtual time, so hosted CI observed the post-release publication
/// waits returning false in ~80ms. An IP takes the literal fast path.
const PAUSED_PREPARATION_DISCOVERED_HOST: &str = "192.0.2.10";
const BLOCKED_PREPARATION_STALE_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(BLOCKED_PREPARATION_MAX_STALE_SECONDS);

/// A withdrawing policy must fail closed on time even though the pending
/// snapshot was already admitted, and must not let that snapshot publish (or
/// commit its cursor) over the withdrawal afterwards.
#[tokio::test(start_paused = true)]
async fn expiry_withdraws_on_time_while_publication_preparation_is_blocked() {
    let _guard = isolated().await;
    let hold = PreparationHold::install();

    let statics = vec![target("static.local", 9000)];
    let config = config_with(vec![upstream_with_sd(
        "blocked-warmup",
        statics.clone(),
        None,
    )]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        PAUSED_PREPARATION_DISCOVERED_HOST,
        8080,
    )]));

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "blocked-warmup",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        statics,
        LoadBalancerAlgorithm::RoundRobin,
        BLOCKED_PREPARATION_POLL_SECONDS,
        BLOCKED_PREPARATION_MAX_STALE_SECONDS,
        SdStalePolicy::Withdraw,
        1,
    );

    // The first admitted snapshot parks in preparation and never publishes.
    assert!(
        wait_for_progress(|| hold.entered() >= 1).await,
        "publication preparation was never reached"
    );
    assert!(
        !lb_has_host(
            &lb_cache,
            "blocked-warmup",
            PAUSED_PREPARATION_DISCOVERED_HOST
        ),
        "an unprepared snapshot must not already be routable"
    );

    // Nothing has ever published, so the anchor is task start and the deadline
    // elapses while preparation is still parked.
    let withdrew = wait_for_deadline_action(BLOCKED_PREPARATION_STALE_DEADLINE, || {
        task_status(&task.key).is_some_and(|status| status.withdrawn)
    })
    .await;
    assert!(
        withdrew,
        "the staleness deadline must withdraw while publication preparation is pending"
    );

    assert_eq!(
        lb_hosts(&lb_cache, "blocked-warmup"),
        vec!["static.local"],
        "the fail-closed withdrawal must leave only static targets installed"
    );
    assert!(
        task_status(&task.key).is_some_and(|status| status.last_success_age_seconds.is_none()),
        "an abandoned snapshot must not advance the staleness anchor"
    );

    // The abandoned snapshot must not surface later either: the next poll
    // interval is already due (missed ticks while parked), so yield until it
    // re-enters preparation. Advance one poll only if the interval has not
    // yet fired.
    if !wait_for_progress(|| hold.entered() >= 2).await {
        tokio::time::advance(std::time::Duration::from_secs(
            BLOCKED_PREPARATION_POLL_SECONDS,
        ))
        .await;
    }
    assert!(
        wait_for_progress(|| hold.entered() >= 2).await,
        "the next poll must re-enter preparation after the withdrawal"
    );
    assert_eq!(
        lb_hosts(&lb_cache, "blocked-warmup"),
        vec!["static.local"],
        "a stale pending snapshot must never publish over the withdrawal"
    );

    // Recovery: release preparation. The parked waiter publishes without a
    // paused-clock sleep poll (which would auto-advance through DNS timeouts
    // and exhaust in ~0.1s on hosted CI).
    let released_at = tokio::time::Instant::now();
    hold.release_and_observe().await;

    let republished = wait_for_progress(|| {
        lb_has_host(
            &lb_cache,
            "blocked-warmup",
            PAUSED_PREPARATION_DISCOVERED_HOST,
        )
    })
    .await;
    assert!(
        republished,
        "a later fresh poll must recover once preparation can complete"
    );
    assert!(
        released_at.elapsed() < std::time::Duration::from_secs(1),
        "recovery after release must complete from the parked waiter, not from paused-clock sleep exhaustion"
    );
    let recovered = wait_for_progress(|| {
        task_status(&task.key).is_some_and(|status| !status.withdrawn && !status.stale)
    })
    .await;
    assert!(recovered, "recovery must clear stale and withdrawn state");

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

/// A reconcile signals exactly this cancel channel before it registers the
/// replacement generation, so a task parked in publication preparation has to
/// observe it promptly instead of waiting out an unbounded warmup.
#[tokio::test(start_paused = true)]
async fn cancellation_stops_a_task_parked_in_publication_preparation() {
    let _guard = isolated().await;
    let hold = PreparationHold::install();

    let config = config_with(vec![upstream_with_sd("canceled-warmup", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        PAUSED_PREPARATION_DISCOVERED_HOST,
        8080,
    )]));

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "canceled-warmup",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        BLOCKED_PREPARATION_POLL_SECONDS,
        // Far beyond this test: cancellation, not expiry, must end the task.
        3600,
        SdStalePolicy::Withdraw,
        1,
    );

    assert!(
        wait_for_progress(|| hold.entered() >= 1).await,
        "publication preparation was never reached"
    );

    let _ = task.cancel_tx.send(true);
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(30), task.handle).await;
    let joined = stopped.expect("a task parked in preparation must stop promptly on cancel");
    assert!(
        joined.is_ok(),
        "the supervisor must exit cleanly, not panic"
    );

    assert!(
        !lb_has_host(
            &lb_cache,
            "canceled-warmup",
            PAUSED_PREPARATION_DISCOVERED_HOST,
        ),
        "a canceled task must not publish the snapshot it was preparing"
    );
}

/// `retain` records the episode without touching routing, so it must not
/// discard the pending publication: the same preparation stays parked and
/// completes once it is released.
#[tokio::test(start_paused = true)]
async fn a_retain_policy_expiry_keeps_a_pending_publication_alive() {
    let _guard = isolated().await;
    let hold = PreparationHold::install();

    let config = config_with(vec![upstream_with_sd("retain-warmup", Vec::new(), None)]);
    let lb_cache = Arc::new(LoadBalancerCache::new(&config));
    let discoverer = Arc::new(ScriptedDiscoverer::new(vec![target(
        PAUSED_PREPARATION_DISCOVERED_HOST,
        8080,
    )]));

    let task = spawn_supervised_discovery_task_for_test(
        &default_namespace(),
        "retain-warmup",
        "scripted",
        discoverer,
        Arc::clone(&lb_cache),
        None,
        Arc::new(HealthChecker::new()),
        Arc::new(CircuitBreakerCache::default()),
        DnsCache::new(Default::default()),
        Vec::new(),
        LoadBalancerAlgorithm::RoundRobin,
        BLOCKED_PREPARATION_POLL_SECONDS,
        BLOCKED_PREPARATION_MAX_STALE_SECONDS,
        SdStalePolicy::Retain,
        1,
    );

    assert!(
        wait_for_progress(|| hold.entered() >= 1).await,
        "publication preparation was never reached"
    );
    let claimed = wait_for_deadline_action(BLOCKED_PREPARATION_STALE_DEADLINE, || {
        health::expiry_applied_for_test(&task.key) == Some(true)
    })
    .await;
    assert!(
        claimed,
        "the retain policy must still claim its expiry episode on time"
    );

    assert!(
        task_status(&task.key).is_some_and(|status| status.stale && !status.withdrawn),
        "retain reports staleness without withdrawing"
    );
    assert_eq!(
        hold.entered(),
        1,
        "retain does not touch routing, so the pending publication must stay \
         parked rather than being discarded and re-prepared"
    );

    let released_at = tokio::time::Instant::now();
    hold.release_and_observe().await;
    let published = wait_for_progress(|| {
        lb_has_host(
            &lb_cache,
            "retain-warmup",
            PAUSED_PREPARATION_DISCOVERED_HOST,
        )
    })
    .await;
    assert!(
        published,
        "the retained pending publication must complete once preparation is released"
    );
    assert!(
        released_at.elapsed() < std::time::Duration::from_secs(1),
        "the retained waiter must publish from the parked preparation, not from paused-clock sleep exhaustion"
    );

    let _ = task.cancel_tx.send(true);
    let _ = task.handle.await;
}

// ── Preparation-hold generation ownership and paused-clock release ────

/// A stale holder whose slot was replaced must not clear or release the newer
/// generation. Hosted shards run other tests in the same process; Drop and the
/// generation-scoped clear have to be no-ops against a slot they no longer own.
#[tokio::test(start_paused = true)]
async fn a_stale_holder_does_not_clear_or_release_a_newer_preparation_hold() {
    let _guard = isolated().await;
    let first = PreparationHold::install();
    let first_generation = first.generation();
    let second = PreparationHold::install();

    assert_ne!(first_generation, second.generation());
    assert!(
        second.is_installed(),
        "installing a replacement must occupy the process-global slot"
    );
    assert!(
        !second.is_released(),
        "replacing the slot must not release the newer generation"
    );

    drop(first);
    assert!(
        second.is_installed(),
        "a stale Drop must not take a newer test's hold"
    );
    assert!(
        !second.is_released(),
        "a stale Drop must not release a newer test's waiters"
    );

    ferrum_edge::service_discovery::clear_discovery_publication_preparation_hold_generation_for_test(
        first_generation,
    );
    assert!(
        second.is_installed(),
        "clearing a stale generation must leave the current hold installed"
    );
    assert!(
        !second.is_released(),
        "clearing a stale generation must not release the current hold"
    );

    second.release_and_observe().await;
}

/// Replacing the process-global hold must unblock waiters parked on the
/// previous generation without releasing the replacement.
#[tokio::test(start_paused = true)]
async fn replacing_a_preparation_hold_releases_the_previous_generation_only() {
    let _guard = isolated().await;
    let first = PreparationHold::install();
    let first_hold = first.inner();
    let parked = tokio::spawn(async move {
        first_hold.park().await;
    });
    assert!(
        wait_for_progress(|| first.entered() >= 1).await,
        "the previous generation never parked"
    );

    let second = PreparationHold::install();
    assert!(
        first.inner().wait_until_release_observed().await,
        "installing a replacement must release waiters parked on the previous generation"
    );
    parked.await.expect("previous waiter");
    assert!(
        first.passed() >= 1,
        "the previous waiter must have observed replacement-release"
    );
    assert!(
        !second.is_released(),
        "the replacement hold must still block"
    );
    assert!(second.is_installed());

    second.release_and_observe().await;
}

/// Under `start_paused`, releasing the owned generation must let a parked
/// waiter observe the flag without relying on a sleep-poll that auto-advances
/// the paused clock to exhaustion. A semaphore close is invisible to the
/// paused clock; this seam keeps the waiter on the timer wheel and handshakes
/// `passed` / `waiting == 0`.
#[tokio::test(start_paused = true)]
async fn releasing_a_preparation_hold_is_observed_under_paused_time() {
    let _guard = isolated().await;
    let hold = PreparationHold::install();
    let parked_hold = hold.inner();
    let parked = tokio::spawn(async move {
        parked_hold.park().await;
    });
    assert!(
        wait_for_progress(|| hold.entered() >= 1).await,
        "the waiter never parked"
    );
    assert_eq!(hold.passed(), 0, "release has not happened yet");

    hold.release_and_observe().await;
    parked.await.expect("parked waiter");
}

// ── #3717: the refused unbounded-retention request is reported once ───

fn mesh_sd_config_requesting_unbounded(
    service_name: &str,
    poll_interval_seconds: u64,
) -> ServiceDiscoveryConfig {
    ServiceDiscoveryConfig {
        max_stale_seconds: Some(0),
        ..mesh_sd_config(service_name, poll_interval_seconds)
    }
}

fn risky_upstream(poll_interval_seconds: u64) -> Upstream {
    upstream_with_sd(
        "risky",
        Vec::new(),
        Some(mesh_sd_config_requesting_unbounded(
            "svc-risky",
            poll_interval_seconds,
        )),
    )
}

fn neighbor_upstream(poll_interval_seconds: u64) -> Upstream {
    upstream_with_sd(
        "neighbor",
        Vec::new(),
        Some(mesh_sd_config("svc-neighbor", poll_interval_seconds)),
    )
}

/// The refusal is reported when a task generation *starts*, not when its spec
/// is rebuilt. Reconcile rebuilds every discovery-backed upstream's spec on
/// every config change, so resolve-time logging repeated the same operator
/// warning for unrelated churn forever. A kept task cannot re-report; a removed
/// and later reintroduced upstream starts a new generation and reports again.
#[tokio::test]
async fn a_refused_unbounded_retention_request_is_bounded_to_one_active_task() {
    let _guard = isolated().await;

    let config = config_with(vec![risky_upstream(30), neighbor_upstream(30)]);
    let manager = manager(&config);
    manager.start(&config, None);

    let risky = health::generation_for_test(&task_key("risky")).expect("task registered");
    assert!(
        task_status(&task_key("risky")).is_some_and(|status| status.max_stale_seconds > 0),
        "a refused unbounded request must run under the bounded default"
    );

    // Unrelated churn (another upstream's poll interval) and repeated identical
    // reconciles must keep the task carrying the refused request, so there is
    // no second active occurrence of the condition to report.
    let churned = config_with(vec![risky_upstream(30), neighbor_upstream(15)]);
    for _ in 0..3 {
        manager.reconcile(&churned, None);
    }
    assert_eq!(
        health::generation_for_test(&task_key("risky")),
        Some(risky),
        "reconcile must keep the unchanged task, so its refusal is reported once"
    );

    // Removing the upstream retires the condition ...
    let without_risky = config_with(vec![neighbor_upstream(15)]);
    manager.reconcile(&without_risky, None);
    assert!(
        wait_for(|| health::generation_for_test(&task_key("risky")).is_none()).await,
        "a removed upstream must retire its discovery task"
    );

    // ... and reintroducing it is a new active occurrence, reported again.
    manager.reconcile(&churned, None);
    let reintroduced = health::generation_for_test(&task_key("risky")).expect("task restarted");
    assert_ne!(
        reintroduced, risky,
        "a reintroduced invalid request must start a new generation"
    );

    manager.stop();
}

/// Issue #4516: circuit-breaker entries must be reclaimed by the
/// service-discovery publish path, not only by a `GatewayConfig` delta.
///
/// Publishes several target generations for one upstream through the exact
/// production admission → publication pipeline, minting a breaker per live
/// target after each publication the way dispatch does. Before the fix the
/// cache grew monotonically with pod churn until it hit its ceiling; now its
/// occupancy tracks the live target set.
#[tokio::test]
async fn service_discovery_target_churn_reclaims_circuit_breaker_entries() {
    let _guard = isolated().await;

    let upstream_id = "breaker-churn";
    let mut config = config_with(vec![upstream_with_sd(upstream_id, Vec::new(), None)]);
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "breaker-churn-proxy",
        "listen_path": "/churn",
        "backend_scheme": "http",
        "backend_host": "unused.local",
        "backend_port": 1,
        "upstream_id": upstream_id,
    }))
    .expect("proxy fixture");
    config.proxies.push(proxy);
    config.normalize_fields();

    let lb_cache = LoadBalancerCache::new(&config);
    let dns_cache = DnsCache::new(Default::default());
    let health_checker = HealthChecker::new();
    let breakers = CircuitBreakerCache::with_max_entries(64);
    let request_epoch = Some(epoch_store(&config));
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let breaker_config = ferrum_edge::config::types::CircuitBreakerConfig::default();

    let mut state = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();
    let ns = default_namespace();

    // Five successive pod generations, two live pods each, no overlap.
    for generation in 0..5u16 {
        let live = vec![
            target(&format!("pod-{}.local", generation * 2), 8080),
            target(&format!("pod-{}.local", generation * 2 + 1), 8080),
        ];

        let control = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
            &ns,
            upstream_id,
            "scripted",
            DiscoverySnapshot::from_targets(live.clone()),
            &mut state,
            &lb_cache,
            &request_epoch,
            &[],
            LoadBalancerAlgorithm::RoundRobin,
            &None,
            &cancel_rx,
            &None,
            &dns_cache,
            &health_checker,
            &breakers,
        )
        .await;
        assert_eq!(
            control,
            ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
        );

        // Dispatch mints one breaker per live target on the next request.
        for live_target in &live {
            breakers.get_or_create(
                &ns,
                "breaker-churn-proxy",
                Some(&ferrum_edge::circuit_breaker::target_key(
                    &live_target.host,
                    live_target.port,
                )),
                &breaker_config,
            );
        }

        assert_eq!(
            breakers.len(),
            live.len(),
            "breaker cache occupancy must track the live target set, not grow with churn \
             (generation {generation})"
        );
    }

    // The final generation's targets are the only ones still resident.
    assert!(
        breakers
            .peek(&ns, "breaker-churn-proxy", Some("pod-8.local:8080"))
            .is_some()
    );
    assert!(
        breakers
            .peek(&ns, "breaker-churn-proxy", Some("pod-0.local:8080"))
            .is_none(),
        "a retired target's breaker must not survive later publications"
    );
    assert_eq!(
        breakers.admission_refused_total(),
        0,
        "reclaimed entries mean the ceiling is never reached in this churn pattern"
    );
}

/// Own the listener and every accepted connection so a failed assertion cannot
/// strand a gateway task in another lifecycle test.
struct PassiveReloadGateway {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for PassiveReloadGateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn passive_reload_gateway(state: ferrum_edge::proxy::ProxyState) -> PassiveReloadGateway {
    let reservation = crate::scaffolding::ports::reserve_port().await.unwrap();
    let url = format!("http://127.0.0.1:{}", reservation.port);
    let listener = reservation.into_listener();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, remote) = accepted.unwrap();
                    let state = state.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |request| {
                            ferrum_edge::proxy::handle_proxy_request(
                                request, state.clone(), remote, false, None, None,
                            )
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    // The fixture owns the bound listener already; the first request is the
    // barrier and cannot reach an unrelated process.
    PassiveReloadGateway { url, task }
}

async fn apply_passive_reload(state: &ferrum_edge::proxy::ProxyState, incremental: bool) {
    use ferrum_edge::config::db_loader::IncrementalResult;
    use ferrum_edge::proxy::ConfigApplyOutcome;

    let mut next = (*state.config.load_full()).clone();
    let filler = next
        .proxies
        .iter_mut()
        .find(|proxy| proxy.id == "filler")
        .unwrap();
    filler.updated_at += chrono::Duration::seconds(1);
    filler.backend_path = Some(format!("/revision-{}", filler.updated_at.timestamp()));
    let outcome = if incremental {
        state
            .apply_incremental(IncrementalResult {
                added_or_modified_proxies: vec![filler.clone()],
                removed_proxy_ids: vec![],
                added_or_modified_consumers: vec![],
                removed_consumer_ids: vec![],
                added_or_modified_plugin_configs: vec![],
                removed_plugin_config_ids: vec![],
                added_or_modified_upstreams: vec![],
                removed_upstream_ids: vec![],
                sequence_cursor: 0,
                poll_timestamp: chrono::Utc::now(),
            })
            .await
    } else {
        state.update_config(next)
    };
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
}

async fn passive_discovery_ejection_survives_reload(incremental: bool) {
    use ferrum_edge::config::types::PassiveHealthCheck;
    use ferrum_edge::proxy::ProxyState;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = isolated().await;
    let good = MockServer::start().await;
    let bad = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("healthy-backend"))
        .mount(&good)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).set_body_string("failing-backend"))
        .mount(&bad)
        .await;
    let good_target = target("127.0.0.1", good.address().port());
    let bad_target = target("127.0.0.1", bad.address().port());
    let bad_key = format!("127.0.0.1:{}", bad.address().port());
    let good_key = format!("127.0.0.1:{}", good.address().port());
    let passive: PassiveHealthCheck = serde_json::from_value(serde_json::json!({
        "unhealthy_status_codes": [503], "unhealthy_threshold": 2,
        "unhealthy_window_seconds": 600, "healthy_after_seconds": 600
    }))
    .unwrap();
    let mut discovered_upstream = upstream_with_sd(
        "reload-discovered",
        vec![],
        Some(
            serde_json::from_value(serde_json::json!({
                "provider": "consul", "consul": {
                    "address": good.uri(), "service_name": "reload", "poll_interval_seconds": 3600
                }
            }))
            .unwrap(),
        ),
    );
    let mut static_upstream = upstream_with_sd(
        "reload-static",
        vec![bad_target.clone(), good_target.clone()],
        None,
    );
    for upstream in [&mut discovered_upstream, &mut static_upstream] {
        upstream.health_checks = Some(
            serde_json::from_value(serde_json::json!({
                "passive": passive
            }))
            .unwrap(),
        );
    }
    let mut config = config_with(vec![discovered_upstream, static_upstream]);
    for (id, upstream_id) in [
        ("discovered", "reload-discovered"),
        ("static", "reload-static"),
        ("partial", "reload-discovered"),
        ("filler", "reload-static"),
    ] {
        config.proxies.push(
            serde_json::from_value(serde_json::json!({
                "id": id, "listen_path": format!("/{id}"), "backend_scheme": "http",
                "backend_host": "127.0.0.1", "backend_port": 1, "upstream_id": upstream_id
            }))
            .unwrap(),
        );
    }
    config.normalize_fields();
    let (state, handles) = ProxyState::new(
        config,
        DnsCache::new(Default::default()),
        ferrum_edge::config::EnvConfig {
            pool_warmup_enabled: false,
            ..Default::default()
        },
        None,
        None,
    )
    .unwrap();
    // Drive the real discovery publication boundary with admitted snapshots.
    // No background provider is started; only unrelated proxy edits are made.
    let request_epoch = Some(Arc::clone(&state.request_epoch));
    let mut discovery = ferrum_edge::_test_support::DiscoveryLoopStateForTest::new();
    let (_cancel, cancel_rx) = tokio::sync::watch::channel(false);
    let publish = |targets| DiscoverySnapshot::from_targets(targets);
    let mut snapshots = vec![
        vec![bad_target.clone(), good_target.clone()],
        vec![good_target.clone()],
        vec![],
    ]
    .into_iter();
    let initial = snapshots.next().unwrap();
    let control = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
        "ferrum",
        "reload-discovered",
        "scripted",
        publish(initial),
        &mut discovery,
        &state.load_balancer_cache,
        &request_epoch,
        &[],
        LoadBalancerAlgorithm::RoundRobin,
        &None,
        &cancel_rx,
        &None,
        &state.dns_cache,
        &state.health_checker,
        &state.circuit_breaker_cache,
    )
    .await;
    assert_eq!(
        control,
        ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
    );
    let gateway = passive_reload_gateway(state.clone()).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let ejected = |proxy: &str| {
        state
            .health_checker
            .passive_health
            .get(&format!("ferrum|{proxy}"))
            .is_some_and(|health| health.unhealthy.contains_key(&bad_key))
    };
    // Real backend 503s cause the ejections, with a static upstream as control.
    for proxy in ["discovered", "static"] {
        for _ in 0..8 {
            let response = client
                .get(format!("{}/{proxy}/check", gateway.url))
                .send()
                .await
                .unwrap();
            assert!([200, 503].contains(&response.status().as_u16()));
            let body = response.text().await.unwrap();
            assert!(["healthy-backend", "failing-backend"].contains(&body.as_str()));
            if ejected(proxy) {
                break;
            }
        }
        assert!(ejected(proxy), "fixture failed to eject {proxy}");
    }
    // A different proxy has not crossed its threshold: its partial history
    // must survive too, not merely the already-unhealthy map.
    state.health_checker.report_response(
        "ferrum",
        "partial",
        "reload-discovered",
        &bad_target,
        503,
        false,
        Some(&passive),
    );
    assert_eq!(
        state
            .health_checker
            .passive_recent_failure_len_for_test("ferrum", "partial", &bad_key),
        1
    );
    let bad_hits = bad.received_requests().await.unwrap().len();
    apply_passive_reload(&state, incremental).await;
    for proxy in ["discovered", "static"] {
        assert!(
            ejected(proxy),
            "reload re-admitted {proxy}'s ejected endpoint"
        );
        for _ in 0..8 {
            let response = client
                .get(format!("{}/{proxy}/check", gateway.url))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.text().await.unwrap(), "healthy-backend");
        }
    }
    assert_eq!(bad.received_requests().await.unwrap().len(), bad_hits);
    assert_eq!(
        state
            .health_checker
            .passive_recent_failure_len_for_test("ferrum", "partial", &bad_key),
        1
    );

    // Actual discovery retirement must remove both ejections and partial
    // history. A subsequent unrelated reload must also reclaim late state for
    // a retired endpoint, including when discovery's installed set is empty.
    for remaining in snapshots {
        let removed = if remaining.is_empty() {
            &good_target
        } else {
            &bad_target
        };
        let removed_key = if remaining.is_empty() {
            &good_key
        } else {
            &bad_key
        };
        let control = ferrum_edge::_test_support::apply_service_discovery_snapshot_for_test(
            "ferrum",
            "reload-discovered",
            "scripted",
            publish(remaining),
            &mut discovery,
            &state.load_balancer_cache,
            &request_epoch,
            &[],
            LoadBalancerAlgorithm::RoundRobin,
            &None,
            &cancel_rx,
            &None,
            &state.dns_cache,
            &state.health_checker,
            &state.circuit_breaker_cache,
        )
        .await;
        assert_eq!(
            control,
            ferrum_edge::_test_support::DiscoveryApplyControlForTest::Continue
        );
        assert!(!ejected("discovered"));
        assert_eq!(
            state.health_checker.passive_recent_failure_len_for_test(
                "ferrum",
                "partial",
                removed_key
            ),
            0
        );
        state.health_checker.report_response(
            "ferrum",
            "partial",
            "reload-discovered",
            removed,
            503,
            false,
            Some(&passive),
        );
        assert_eq!(
            state.health_checker.passive_recent_failure_len_for_test(
                "ferrum",
                "partial",
                removed_key
            ),
            1
        );
        apply_passive_reload(&state, incremental).await;
        assert_eq!(
            state.health_checker.passive_recent_failure_len_for_test(
                "ferrum",
                "partial",
                removed_key
            ),
            0
        );
        assert!(
            ejected("static"),
            "discovery retirement crossed upstream ownership"
        );
    }
    drop(gateway);
    for handle in handles {
        handle.abort();
    }
}

#[tokio::test]
async fn full_reload_preserves_discovered_passive_ejection_and_failure_history() {
    passive_discovery_ejection_survives_reload(false).await;
}

#[tokio::test]
async fn incremental_reload_preserves_discovered_passive_ejection_and_failure_history() {
    passive_discovery_ejection_survives_reload(true).await;
}

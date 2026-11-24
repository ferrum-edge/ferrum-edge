//! Authenticated `/metrics` reads a cached TLS inventory snapshot (#2410).
//!
//! Endpoint-level proof, driven through the real admin listener with a counting
//! fake inventory collector standing in for a certificate/key source or secret
//! provider:
//!
//! 1. Repeated unchanged scrapes do not increase the source fetch count — the
//!    scrape path performs no certificate/key/Kubernetes/secret-manager I/O.
//! 2. A scrape never blocks on the collector: with a deliberately slow provider
//!    in flight, scrapes still return promptly and keep serving the previous
//!    snapshot, and the single-flight guard admits exactly one refresh.
//! 3. The authentication tier is unchanged (`401` without credentials) and the
//!    snapshot's freshness is exported explicitly.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use ferrum_edge::tls::inventory::{
    TlsInventory, TlsInventoryEntry, TlsInventorySource, TlsInventoryState, TlsInventoryUsage,
};
use ferrum_edge::tls::inventory_cache::{self, TlsInventoryCache, TlsInventoryCollector};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const JWT_SECRET: &str = "tls-inventory-snapshot-scrape-test-secret-key";
const JWT_ISSUER: &str = "ferrum-edge-tls-inventory-snapshot-test";
const CERT_ID: &str = "certificate-2410cachedsnapshot";
const SNAPSHOT_TTL: Duration = Duration::from_secs(300);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Every call is a source fetch. A channel can hold collection in flight until
/// the test releases it, with no sleep or assumption about scheduler timing.
struct CountingInventoryCollector {
    cert_id: &'static str,
    fetches: AtomicU64,
    started: tokio::sync::watch::Sender<u64>,
    next_gate: Mutex<Option<mpsc::Receiver<()>>>,
    not_after: DateTime<Utc>,
}

impl CountingInventoryCollector {
    fn new(cert_id: &'static str) -> Self {
        Self {
            cert_id,
            fetches: AtomicU64::new(0),
            started: tokio::sync::watch::channel(0).0,
            next_gate: Mutex::new(None),
            not_after: Utc::now() + ChronoDuration::days(30),
        }
    }

    fn fetches(&self) -> u64 {
        self.fetches.load(Ordering::SeqCst)
    }

    fn block_next_fetch(&self) -> mpsc::Sender<()> {
        let (release, gate) = mpsc::channel();
        *self.next_gate.lock().expect("collector gate") = Some(gate);
        release
    }

    async fn wait_for_fetches(&self, target: u64) {
        let mut started = self.started.subscribe();
        tokio::time::timeout(TEST_TIMEOUT, started.wait_for(|count| *count >= target))
            .await
            .expect("collector must start")
            .expect("collector notification channel");
    }
}

impl TlsInventoryCollector for CountingInventoryCollector {
    fn collect_public_metadata(&self) -> TlsInventory {
        let gate = self.next_gate.lock().expect("collector gate").take();
        let count = self.fetches.fetch_add(1, Ordering::SeqCst) + 1;
        self.started.send_replace(count);
        if let Some(gate) = gate {
            // Dropping the sender on assertion failure also releases the worker.
            let _ = gate.recv();
        }
        TlsInventory {
            entries: vec![TlsInventoryEntry {
                id: self.cert_id.to_string(),
                material_kind: "certificate".to_string(),
                source: TlsInventorySource {
                    kind: "file".to_string(),
                    identifier: "/counting-fake/cert.pem".to_string(),
                    refreshable: true,
                    version: None,
                },
                state: TlsInventoryState::Loaded,
                used_by: vec![TlsInventoryUsage {
                    surface: "frontend_tls".to_string(),
                    role: "server_certificate".to_string(),
                    resource_type: "env".to_string(),
                    resource_id: "runtime".to_string(),
                    field: "FERRUM_FRONTEND_TLS_CERT".to_string(),
                }],
                subject: Some("CN=counting-fake".to_string()),
                issuer: Some("CN=counting-fake".to_string()),
                sans: Vec::new(),
                not_before: Some(Utc::now() - ChronoDuration::days(1)),
                not_after: Some(self.not_after),
                days_until_expiry: Some(30),
                next_update: None,
                days_until_next_update: None,
                fingerprint_sha256: Some("a".repeat(64)),
                certificate_count: Some(1),
                crl_count: None,
                error: None,
            }],
        }
    }

    fn serving_cycle_key(&self) -> Option<usize> {
        Some(self as *const Self as usize)
    }
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "tls-inventory-snapshot-test",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + ChronoDuration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()).unwrap(),
    )
    .expect("encode admin JWT")
}

fn admin_state_with_proxy(proxy_state: ProxyState) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        proxy_state: Some(proxy_state),
        cached_config: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: Some(Arc::new(AtomicBool::new(true))),
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr)
        .await
        .expect("bind admin listener");
    let actual = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    // The listener is already bound and owned; requests can queue before the
    // accept task is first polled. No readiness retry is necessary.
    (format!("http://{actual}"), shutdown_tx)
}

async fn scrape(client: &reqwest::Client, base: &str) -> String {
    let response = client
        .get(format!("{base}/metrics"))
        .bearer_auth(admin_token())
        .send()
        .await
        .expect("authenticated /metrics");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    response.text().await.expect("metrics body")
}

async fn join_refresh(refresh: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(TEST_TIMEOUT, refresh)
        .await
        .expect("refresh must finish")
        .expect("refresh must not panic");
}

async fn refresh(cache: &Arc<TlsInventoryCache>) {
    join_refresh(
        cache
            .schedule_refresh_if_due(SNAPSHOT_TTL)
            .expect("refresh due"),
    )
    .await;
}

fn isolated_proxy_state(cache: Arc<TlsInventoryCache>) -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig::default());
    let (mut proxy_state, _handles) = ProxyState::new(
        GatewayConfig::default(),
        dns_cache,
        EnvConfig::default(),
        None,
        None,
    )
    .expect("proxy state");
    assert!(Arc::ptr_eq(
        &proxy_state.tls_inventory_cache,
        inventory_cache::process_cache(),
    ));
    assert!(Arc::ptr_eq(
        &proxy_state.admin_metrics_registry,
        &ferrum_edge::plugins::prometheus_metrics::global_registry(),
    ));
    proxy_state.tls_inventory_cache = cache;
    proxy_state.admin_metrics_registry = Arc::new(MetricsRegistry::new());
    proxy_state
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_scrapes_read_cached_snapshot_without_refetching_or_blocking() {
    let collector = Arc::new(CountingInventoryCollector::new(CERT_ID));
    let cache = Arc::new(TlsInventoryCache::with_collector(collector.clone()));
    let proxy_state = isolated_proxy_state(cache.clone());
    // Join publication, not merely entry into the collector. Listener startup
    // must retain this cache's fixed collector and already-fresh snapshot.
    refresh(&cache).await;
    let (base, shutdown) = start_admin(admin_state_with_proxy(proxy_state.clone())).await;
    let client = reqwest::Client::builder()
        .timeout(TEST_TIMEOUT)
        .build()
        .expect("client");

    // Phase 0: the auth tier is untouched.
    let unauthenticated = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .expect("unauthenticated /metrics");
    assert_eq!(
        unauthenticated.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "/metrics must stay gated"
    );

    // Phase 1: the bounded background refresh publishes the snapshot; the scrape
    // path renders certificate gauges from it plus explicit freshness.
    assert_eq!(collector.fetches(), 1);
    let cert_label = format!("cert_id=\"{CERT_ID}\"");
    let body = scrape(&client, &base).await;
    assert!(
        body.contains(&cert_label),
        "cached certificate missing:\n{body}"
    );
    assert!(
        body.contains("ferrum_tls_cert_expiry_seconds"),
        "certificate expiry family missing:\n{body}"
    );
    assert!(
        body.contains("ferrum_tls_inventory_snapshot_timestamp_seconds"),
        "snapshot freshness timestamp missing:\n{body}"
    );
    assert!(
        body.contains("ferrum_tls_inventory_snapshot_max_age_seconds"),
        "snapshot freshness bound missing:\n{body}"
    );

    // Phase 2: repeated unchanged scrapes fetch nothing at all.
    let baseline = collector.fetches();
    for _ in 0..6 {
        let repeated = scrape(&client, &base).await;
        assert!(
            repeated.contains(&cert_label),
            "repeated scrape lost the cached certificate gauge:\n{repeated}"
        );
        assert_eq!(
            collector.fetches(),
            baseline,
            "an unchanged scrape must not fetch any TLS source"
        );
    }

    // Phase 3: hold collection in flight until after the scrapes complete.
    // Retain the task handle to prove publication before the next phase.
    let release = collector.block_next_fetch();
    cache.mark_stale();
    let pending = cache
        .schedule_refresh_if_due(SNAPSHOT_TTL)
        .expect("refresh due");
    collector.wait_for_fetches(baseline + 1).await;
    let during = scrape(&client, &base).await;
    assert!(
        during.contains(&cert_label),
        "a scrape during an in-flight refresh must keep serving the previous snapshot:\n{during}"
    );

    for _ in 0..3 {
        let _ = scrape(&client, &base).await;
    }
    assert_eq!(
        collector.fetches(),
        baseline + 1,
        "single-flight must admit exactly one refresh for a stale snapshot"
    );

    // Phase 4: once the slow refresh lands, scrapes are quiet again.
    release.send(()).expect("release collector");
    join_refresh(pending).await;
    assert_eq!(cache.snapshot().expect("published snapshot").generation, 2);
    let settled = collector.fetches();
    for _ in 0..3 {
        let _ = scrape(&client, &base).await;
    }
    assert_eq!(
        collector.fetches(),
        settled,
        "scrapes after a completed refresh must stay fetch-free"
    );

    // Phase 5: an accepted GatewayConfig publication invalidates the snapshot
    // even when no source watcher fired. Config reloads can replace TLS source
    // descriptors themselves, so waiting for the ordinary TTL here would
    // expose stale certificate metadata after a successful reload.
    let release = collector.block_next_fetch();
    assert_eq!(
        proxy_state.update_config(reloaded_config()),
        ConfigApplyOutcome::Applied,
        "the fixture reload must publish before testing cache invalidation"
    );
    assert!(cache.refresh_is_due(SNAPSHOT_TTL));
    let before_reload_refresh = collector.fetches();
    let _ = scrape(&client, &base).await;
    collector.wait_for_fetches(before_reload_refresh + 1).await;
    assert_eq!(collector.fetches(), before_reload_refresh + 1);
    release.send(()).expect("release reload collector");

    let _ = shutdown.send(true);
}

fn reloaded_config() -> GatewayConfig {
    let mut reloaded = GatewayConfig::default();
    reloaded.proxies.push(
        serde_json::from_value(json!({
            "id": "tls-inventory-reload-proxy",
            "namespace": "ferrum",
            "name": "tls-inventory-reload-proxy",
            "hosts": [],
            "listen_path": "/tls-inventory-reload",
            "backend_scheme": "http",
            "backend_host": "backend.example.com",
            "backend_port": 8080,
            "strip_listen_path": true,
            "preserve_host_header": false,
            "backend_connect_timeout_ms": 5000,
            "backend_read_timeout_ms": 30000,
            "backend_write_timeout_ms": 30000,
            "backend_tls_verify_server_cert": true
        }))
        .expect("reload proxy should deserialize"),
    );
    reloaded
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_inventory_fixtures_keep_collectors_snapshots_and_invalidations_isolated() {
    let first = Arc::new(CountingInventoryCollector::new("certificate-first-owner"));
    let second = Arc::new(CountingInventoryCollector::new("certificate-second-owner"));
    let first_cache = Arc::new(TlsInventoryCache::with_collector(first.clone()));
    let second_cache = Arc::new(TlsInventoryCache::with_collector(second.clone()));
    let first_proxy = isolated_proxy_state(first_cache.clone());
    let second_proxy = isolated_proxy_state(second_cache.clone());
    let first_registry = Arc::clone(&first_proxy.admin_metrics_registry);
    let second_registry = Arc::clone(&second_proxy.admin_metrics_registry);
    refresh(&first_cache).await;
    refresh(&second_cache).await;
    let client = reqwest::Client::builder()
        .timeout(TEST_TIMEOUT)
        .build()
        .expect("client");

    let (first_base, first_shutdown) = start_admin(admin_state_with_proxy(first_proxy)).await;
    assert!(scrape(&client, &first_base).await.contains(first.cert_id));
    let release = first.block_next_fetch();
    // A 1 ns TTL is always expired without moving wall clocks and stays inside
    // the positive domain production passes (both call sites gate on ttl > 0).
    let pending = first_cache
        .schedule_refresh_if_due(Duration::from_nanos(1))
        .expect("expired snapshot must refresh");
    first.wait_for_fetches(2).await;

    // Start another listener and publish its config while the first collector
    // is blocked. Neither operation may replace, stale, or refresh the first.
    let (second_base, second_shutdown) =
        start_admin(admin_state_with_proxy(second_proxy.clone())).await;
    assert!(scrape(&client, &second_base).await.contains(second.cert_id));
    // Assert ownership directly as well as through concurrent responses: this
    // catches registry sharing even if the two handlers happen to run serially.
    assert!(!Arc::ptr_eq(&first_registry, &second_registry));
    let first_gauges = first_registry.render();
    let second_gauges = second_registry.render();
    assert!(first_gauges.contains(first.cert_id));
    assert!(!first_gauges.contains(second.cert_id));
    assert!(second_gauges.contains(second.cert_id));
    assert!(!second_gauges.contains(first.cert_id));
    assert_eq!(
        second_proxy.update_config(reloaded_config()),
        ConfigApplyOutcome::Applied
    );
    assert!(second_cache.refresh_is_due(SNAPSHOT_TTL));
    refresh(&second_cache).await;
    assert_eq!(second.fetches(), 2);

    // TLS events and unrelated fixtures still invalidate the production cache.
    // This was enough to force extra counting-collector fetches before #5544.
    inventory_cache::mark_stale();
    assert!(!first_cache.refresh_is_due(SNAPSHOT_TTL));
    assert!(!second_cache.refresh_is_due(SNAPSHOT_TTL));

    for _ in 0..4 {
        let (first_body, second_body) =
            tokio::join!(scrape(&client, &first_base), scrape(&client, &second_base));
        assert!(first_body.contains(first.cert_id));
        assert!(!first_body.contains(second.cert_id));
        assert!(second_body.contains(second.cert_id));
        assert!(!second_body.contains(first.cert_id));
        assert_eq!(first.fetches(), 2);
        assert_eq!(second.fetches(), 2);
    }

    release.send(()).expect("release first collector");
    join_refresh(pending).await;
    inventory_cache::mark_stale();
    let _ = scrape(&client, &first_base).await;
    let _ = scrape(&client, &second_base).await;
    assert_eq!(first.fetches(), 2, "foreign invalidation after publication");
    assert_eq!(second.fetches(), 2);

    let _ = first_shutdown.send(true);
    let _ = second_shutdown.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_inventory_serving_cycles_fence_old_results_and_preserve_mid_refresh_invalidation() {
    let cache = Arc::new(TlsInventoryCache::default());
    let old = Arc::new(CountingInventoryCollector::new("certificate-old-cycle"));
    let next = Arc::new(CountingInventoryCollector::new("certificate-new-cycle"));
    assert!(cache.install_collector(old.clone()));
    refresh(&cache).await;
    let original = cache.snapshot().expect("original snapshot");
    assert!(!cache.replace_collector_for_serving_cycle(old.clone()));
    assert!(Arc::ptr_eq(&original, &cache.snapshot().unwrap()));
    assert!(!cache.refresh_is_due(SNAPSHOT_TTL));

    let release = old.block_next_fetch();
    cache.mark_stale();
    let pending = cache
        .schedule_refresh_if_due(SNAPSHOT_TTL)
        .expect("old refresh");
    old.wait_for_fetches(2).await;
    assert!(cache.replace_collector_for_serving_cycle(next.clone()));
    assert!(cache.snapshot().is_none());
    assert!(cache.schedule_refresh_if_due(SNAPSHOT_TTL).is_none());
    release.send(()).expect("release old collector");
    join_refresh(pending).await;
    assert!(cache.snapshot().is_none(), "old result must remain fenced");

    let release = next.block_next_fetch();
    let pending = cache
        .schedule_refresh_if_due(SNAPSHOT_TTL)
        .expect("new cycle refresh");
    next.wait_for_fetches(1).await;
    cache.mark_stale();
    assert!(cache.schedule_refresh_if_due(SNAPSHOT_TTL).is_none());
    release.send(()).expect("release new collector");
    join_refresh(pending).await;
    let current = cache.snapshot().expect("new snapshot");
    assert_eq!(current.inventory.entries[0].id, next.cert_id);
    assert!(current.generation > original.generation);
    assert!(cache.refresh_is_due(SNAPSHOT_TTL));
    refresh(&cache).await;
    assert_eq!(next.fetches(), 2);
    assert!(!cache.refresh_is_due(SNAPSHOT_TTL));
}

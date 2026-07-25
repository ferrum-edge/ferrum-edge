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
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use ferrum_edge::tls::inventory::{
    TlsInventory, TlsInventoryEntry, TlsInventorySource, TlsInventoryState, TlsInventoryUsage,
};
use ferrum_edge::tls::inventory_cache::{self, TlsInventoryCollector};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const JWT_SECRET: &str = "tls-inventory-snapshot-scrape-test-secret-key";
const JWT_ISSUER: &str = "ferrum-edge-tls-inventory-snapshot-test";
const CERT_ID: &str = "certificate-2410cachedsnapshot";

/// Counting stand-in for a certificate source / secret provider. Every call is a
/// "fetch"; `delay_ms` simulates a slow or unavailable secret manager.
struct CountingInventoryCollector {
    fetches: AtomicU64,
    delay_ms: AtomicU64,
    not_after: DateTime<Utc>,
}

impl CountingInventoryCollector {
    fn new() -> Self {
        Self {
            fetches: AtomicU64::new(0),
            delay_ms: AtomicU64::new(0),
            not_after: Utc::now() + ChronoDuration::days(30),
        }
    }

    fn fetches(&self) -> u64 {
        self.fetches.load(Ordering::SeqCst)
    }

    fn set_delay(&self, delay: Duration) {
        self.delay_ms
            .store(delay.as_millis() as u64, Ordering::SeqCst);
    }
}

impl TlsInventoryCollector for CountingInventoryCollector {
    fn collect_public_metadata(&self) -> TlsInventory {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        let delay_ms = self.delay_ms.load(Ordering::SeqCst);
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        TlsInventory {
            entries: vec![TlsInventoryEntry {
                id: CERT_ID.to_string(),
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
                fingerprint_sha256: Some("a".repeat(64)),
                certificate_count: Some(1),
                crl_count: None,
                error: None,
            }],
        }
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
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
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
        admin_require_namespace_claim: false,
        startup_ready: Some(Arc::new(AtomicBool::new(true))),
        serving_degraded: None,
        serving_listener_failures: None,
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
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr)
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
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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

/// Scrape until `needle` shows up, so the publication that follows the counted
/// fetch cannot race the assertion.
async fn scrape_until_contains(client: &reqwest::Client, base: &str, needle: &str) -> String {
    let mut body = String::new();
    for _ in 0..200 {
        body = scrape(client, base).await;
        if body.contains(needle) {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("'{needle}' never appeared in the metrics exposition:\n{body}");
}

async fn wait_for_fetches(collector: &CountingInventoryCollector, target: u64) {
    for _ in 0..400 {
        if collector.fetches() >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "background TLS inventory refresh never reached {target} fetches (saw {})",
        collector.fetches()
    );
}

/// One test function on purpose: the cached snapshot is process-wide, so the
/// phases below run in a fixed order instead of racing each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_scrapes_read_cached_snapshot_without_refetching_or_blocking() {
    let collector = Arc::new(CountingInventoryCollector::new());
    inventory_cache::pin_collector(collector.clone());
    // Another test in this binary may already have published a snapshot from the
    // production collector; make sure the first admin start refreshes through the
    // counting fake.
    inventory_cache::mark_stale();

    let dns_cache = DnsCache::new(DnsConfig::default());
    let (proxy_state, _handles) = ProxyState::new(
        GatewayConfig::default(),
        dns_cache,
        EnvConfig::default(),
        None,
        None,
    )
    .expect("proxy state");
    let (base, shutdown) = start_admin(admin_state_with_proxy(proxy_state.clone())).await;
    let client = reqwest::Client::new();

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
    wait_for_fetches(&collector, 1).await;
    let cert_label = format!("cert_id=\"{CERT_ID}\"");
    let body = scrape_until_contains(&client, &base, &cert_label).await;
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

    // Phase 3: a slow provider must not slow the scrape. Mark the snapshot stale
    // so the next scrape schedules a refresh, then keep scraping while that
    // refresh sits in the collector's simulated provider latency.
    collector.set_delay(Duration::from_secs(3));
    inventory_cache::mark_stale();
    let scheduling_scrape = Instant::now();
    let during = scrape(&client, &base).await;
    let scheduling_elapsed = scheduling_scrape.elapsed();
    assert!(
        scheduling_elapsed < Duration::from_secs(1),
        "the scrape that scheduled the refresh blocked for {scheduling_elapsed:?}"
    );
    assert!(
        during.contains(&cert_label),
        "a scrape during an in-flight refresh must keep serving the previous snapshot:\n{during}"
    );

    let in_flight = Instant::now();
    for _ in 0..3 {
        let _ = scrape(&client, &base).await;
    }
    let in_flight_elapsed = in_flight.elapsed();
    assert!(
        in_flight_elapsed < Duration::from_secs(1),
        "scrapes blocked on the in-flight provider fetch for {in_flight_elapsed:?}"
    );
    assert_eq!(
        collector.fetches(),
        baseline + 1,
        "single-flight must admit exactly one refresh for a stale snapshot"
    );

    // Phase 4: once the slow refresh lands, scrapes are quiet again.
    collector.set_delay(Duration::ZERO);
    wait_for_fetches(&collector, baseline + 1).await;
    tokio::time::sleep(Duration::from_millis(3_200)).await;
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
    assert_eq!(
        proxy_state.update_config(reloaded),
        ConfigApplyOutcome::Applied,
        "the fixture reload must publish before testing cache invalidation"
    );
    let before_reload_refresh = collector.fetches();
    let _ = scrape(&client, &base).await;
    wait_for_fetches(&collector, before_reload_refresh + 1).await;

    let _ = shutdown.send(true);
}

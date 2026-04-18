//! CP/DP resilience tests: broadcast-channel overflow, multi-CP failover, and
//! `/cluster` admin endpoint behavior.
//!
//! These tests mirror the in-process CP + DP harness from `functional_cp_dp_test.rs`:
//! the CP gRPC server and the DP gRPC client are both spawned as tokio tasks in
//! the test process. That approach is significantly more reliable than
//! orchestrating two separate binary processes over ephemeral ports.
//!
//! Run with:
//!   cargo test --test functional_tests -- --ignored functional_cp_dp_resilience --nocapture
//!
//! Coverage:
//! 1. `test_broadcast_overflow_triggers_full_snapshot_recovery` — CP configured
//!    with a tiny broadcast channel capacity. We rapid-fire more deltas than
//!    the channel can hold, then verify the DP's config converges to the
//!    latest full snapshot (the `BroadcastStream::Lagged` recovery path in
//!    `CpGrpcServer::subscribe` re-sends the current `ArcSwap` config).
//! 2. `test_multi_cp_failover_connects_to_fallback` — DP configured with a
//!    bogus primary + a working fallback; verifies the DP connects to the
//!    fallback within a bounded window and `/cluster` reports `is_primary=false`.
//! 3. `test_primary_retry_reconnects_to_primary` — DP on fallback with a
//!    short `primary_retry_secs`. Once the primary becomes available the
//!    DP reconnects to it and `/cluster` flips to `is_primary=true`.
//! 4. `test_cluster_endpoint_shape_cp_and_dp` — exercises the `/cluster`
//!    JSON shape on both a CP admin listener (lists DP nodes) and a DP
//!    admin listener (reports CP connection state).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    start_admin_listener,
};
use ferrum_edge::config::types::{AuthMode, BackendProtocol, GatewayConfig, Proxy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::grpc::cp_server::{CpGrpcServer, DpNodeRegistry};
use ferrum_edge::grpc::dp_client::{self, DpCpConnectionState};
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use tokio::time::{sleep, timeout};
use tonic::transport::Server;

const ADMIN_JWT_SECRET: &str = "test-admin-secret-key-for-resilience-suite-32";
const GRPC_JWT_SECRET: &str = "test-grpc-secret-cp-dp-resilience-32char!";

/// Build a minimal `EnvConfig` suitable for constructing a DP-side `ProxyState`.
///
/// Copied from `functional_cp_dp_test.rs` because that helper is private to the
/// other test module. Keeping a separate copy avoids cross-file coupling.
fn create_test_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        log_level: "debug".into(),
        admin_jwt_secret: Some(ADMIN_JWT_SECRET.into()),
        db_type: Some("sqlite".into()),
        cp_dp_grpc_jwt_secret: Some(GRPC_JWT_SECRET.into()),
        ..Default::default()
    }
}

fn create_test_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Resilience Proxy {}", id)),
        hosts: vec![],
        listen_path: listen_path.to_string(),
        backend_protocol: BackendProtocol::Http,
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_proxy_state() -> ProxyState {
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: HashMap::new(),
        resolver_addresses: None,
        hosts_file_path: None,
        dns_order: None,
        ttl_override_seconds: None,
        min_ttl_seconds: 5,
        stale_ttl_seconds: 3600,
        error_ttl_seconds: 1,
        max_cache_size: 10_000,
        warmup_concurrency: 500,
        backend_allow_ips: ferrum_edge::config::BackendAllowIps::Both,
        slow_threshold_ms: None,
        refresh_threshold_percent: 90,
        failed_retry_interval_seconds: 10,
    });
    ProxyState::new(
        GatewayConfig::default(),
        dns_cache,
        create_test_env_config(),
        None,
    )
    .expect("ProxyState::new failed")
}

/// Build a CP-scoped admin `AdminState` that exposes `GET /cluster` with the
/// supplied DP node registry.
fn build_cp_admin_state(
    cached_config: Arc<ArcSwap<GatewayConfig>>,
    registry: Arc<DpNodeRegistry>,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ADMIN_JWT_SECRET.to_string(),
            issuer: "ferrum-edge".to_string(),
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }),
        proxy_state: None,
        cached_config: Some(cached_config),
        mode: "cp".into(),
        read_only: false,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: Some(registry),
        cp_connection_state: None,
    }
}

/// Build a DP-scoped admin `AdminState` wired to the supplied
/// `DpCpConnectionState` so `GET /cluster` reflects live connection status.
fn build_dp_admin_state(
    proxy_state: &ProxyState,
    conn_state: Arc<ArcSwap<DpCpConnectionState>>,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: ADMIN_JWT_SECRET.to_string(),
            issuer: "ferrum-edge".to_string(),
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        }),
        proxy_state: Some(proxy_state.clone()),
        cached_config: Some(proxy_state.config.clone()),
        mode: "dp".into(),
        read_only: true,
        startup_ready: None,
        db_available: None,
        admin_restore_max_body_size_mib: 100,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".into(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        cp_connection_state: Some(conn_state),
    }
}

/// Bind the admin listener on an OS-assigned port; returns the base URL.
async fn spawn_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin listener");
    let addr = listener.local_addr().expect("admin addr");
    drop(listener);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let state_clone = state.clone();
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(async move {
        let admin_addr: SocketAddr = addr;
        let _ = start_admin_listener(admin_addr, state_clone, shutdown_rx_clone).await;
    });

    // Give the listener a moment to accept connections.
    sleep(Duration::from_millis(100)).await;

    (format!("http://{}", addr), shutdown_tx)
}

fn generate_admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": "ferrum-edge",
        "sub": "resilience-test",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(ADMIN_JWT_SECRET.as_bytes()),
    )
    .expect("encode admin JWT")
}

async fn admin_get_json(base_url: &str, path: &str) -> Value {
    let token = generate_admin_token();
    let resp = reqwest::Client::new()
        .get(format!("{}{}", base_url, path))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("admin GET failed");
    assert!(
        resp.status().is_success(),
        "admin GET {} returned {}",
        path,
        resp.status()
    );
    resp.json().await.expect("admin JSON parse")
}

/// Start a CP gRPC server on an OS-assigned port. Returns the URL, the
/// broadcast update sender, the shared config pointer, the DP registry, and
/// the server task handle.
async fn spawn_cp(
    initial_config: GatewayConfig,
    broadcast_capacity: usize,
) -> (
    String,
    tokio::sync::broadcast::Sender<ferrum_edge::grpc::proto::ConfigUpdate>,
    Arc<ArcSwap<GatewayConfig>>,
    Arc<DpNodeRegistry>,
    tokio::task::JoinHandle<()>,
) {
    let config_arc = Arc::new(ArcSwap::new(Arc::new(initial_config)));
    let registry = Arc::new(DpNodeRegistry::new());
    let (cp_server, update_tx) = CpGrpcServer::with_channel_capacity_and_registry(
        config_arc.clone(),
        GRPC_JWT_SECRET.to_string(),
        broadcast_capacity,
        registry.clone(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind CP gRPC");
    let addr = listener.local_addr().expect("CP gRPC addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let handle = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(cp_server.into_service())
            .serve_with_incoming(incoming)
            .await;
    });

    // Give the server a moment to enter the accept loop.
    sleep(Duration::from_millis(200)).await;

    (
        format!("http://{}", addr),
        update_tx,
        config_arc,
        registry,
        handle,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — broadcast overflow → full snapshot recovery
// ─────────────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_broadcast_overflow_triggers_full_snapshot_recovery() {
    println!("=== broadcast overflow → full-snapshot recovery test ===");

    // Start the CP with an intentionally tiny broadcast capacity. Any
    // overflow in the DP's receive queue triggers `BroadcastStreamRecvError::Lagged`
    // on the CP side, which `CpGrpcServer::subscribe` recovers from by
    // re-sending a FULL_SNAPSHOT built from the current `ArcSwap` config.
    let initial_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("seed-proxy", "/seed", 4000)],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let (cp_url, update_tx, config_arc, _registry, server_handle) =
        spawn_cp(initial_config, 4).await;

    // Start the DP subscribing. Use the long-running client entry so we
    // exercise the production stream loop (with startup-ready signalling).
    let dp_proxy_state = create_proxy_state();
    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());
    let ps = dp_proxy_state.clone();
    let cp_urls = vec![cp_url.clone()];
    let startup_ready = Arc::new(AtomicBool::new(false));
    let startup_ready_clone = startup_ready.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            cp_urls,
            secret,
            ps,
            Some(shutdown_rx),
            None,
            Some(startup_ready_clone),
            "ferrum".to_string(),
            0,
            None,
        )
        .await;
    });

    // Wait until the DP has processed the initial snapshot (startup_ready flips
    // to true inside the stream loop after the first FULL_SNAPSHOT is applied).
    let startup_deadline = timeout(Duration::from_secs(5), async {
        while !startup_ready.load(Ordering::Relaxed) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        startup_deadline.is_ok(),
        "DP never signalled startup_ready — it did not receive the initial snapshot"
    );
    assert_eq!(
        dp_proxy_state.config.load().proxies.len(),
        1,
        "initial snapshot should have 1 proxy"
    );

    // Rapid-fire 20 config updates, each with a progressively larger proxy
    // list. Even with capacity=4 the DP's live stream will receive the
    // recovery full-snapshot that reflects the final (20th) state. The
    // broadcast channel only queues up to 4 unconsumed updates — slower
    // DPs receive a `FULL_SNAPSHOT` rebuilt from the current `ArcSwap`
    // rather than missed deltas.
    const TOTAL_UPDATES: usize = 20;
    for i in 1..=TOTAL_UPDATES {
        let proxies: Vec<Proxy> = (1..=i)
            .map(|n| create_test_proxy(&format!("proxy-{n}"), &format!("/p{n}"), 4000 + n as u16))
            .collect();
        let updated = GatewayConfig {
            version: format!("v{i}"),
            proxies,
            consumers: vec![],
            plugin_configs: vec![],
            upstreams: vec![],
            loaded_at: Utc::now(),
            known_namespaces: Vec::new(),
        };
        config_arc.store(Arc::new(updated.clone()));
        CpGrpcServer::broadcast_update(&update_tx, &updated);
        // No sleep — we want to overflow the channel.
    }

    // Wait for the DP to converge to the final config.
    let final_expected = TOTAL_UPDATES;
    let converged = timeout(Duration::from_secs(5), async {
        loop {
            let got = dp_proxy_state.config.load().proxies.len();
            if got == final_expected {
                break got;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "DP never converged to final config — saw {} proxies, expected {}",
        dp_proxy_state.config.load().proxies.len(),
        final_expected
    );
    assert_eq!(
        dp_proxy_state.config.load().proxies.len(),
        final_expected,
        "DP must end up with the latest config state (self-healing via full-snapshot recovery)"
    );
    println!(
        "DP converged to {} proxies after broadcasting {} updates through a capacity-4 channel",
        final_expected, TOTAL_UPDATES
    );

    let _ = shutdown_tx.send(true);
    client_handle.abort();
    server_handle.abort();
    println!("=== broadcast overflow test PASSED ===");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — multi-CP failover: primary unreachable → DP connects to fallback
// ─────────────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_cp_failover_connects_to_fallback() {
    println!("=== multi-CP failover test ===");

    // Bogus primary URL (no listener bound) — first connect attempt will fail.
    // We grab an ephemeral port, drop it, so the address is effectively
    // unreachable for the duration of the test.
    let bogus_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bogus");
    let bogus_addr = bogus_listener.local_addr().expect("bogus addr");
    drop(bogus_listener);
    let primary_url = format!("http://{}", bogus_addr);

    // Working fallback CP.
    let fallback_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("fallback-proxy", "/fallback", 4100)],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let (fallback_url, _fallback_tx, _fallback_config_arc, _fallback_registry, fallback_handle) =
        spawn_cp(fallback_config, 16).await;

    // DP with [primary (bogus), fallback (working)].
    let dp_proxy_state = create_proxy_state();
    let conn_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&primary_url),
    )));
    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());
    let ps = dp_proxy_state.clone();
    let conn_state_clone = conn_state.clone();
    let cp_urls = vec![primary_url.clone(), fallback_url.clone()];
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            cp_urls,
            secret,
            ps,
            Some(shutdown_rx),
            None,
            None,
            "ferrum".to_string(),
            0, // disable primary-retry timer for this test
            Some(conn_state_clone),
        )
        .await;
    });

    // Wait for the DP to fail over to the fallback and sync its config.
    // The first connect to the bogus primary fails, backoff jitter applies,
    // then the DP tries the fallback and succeeds. Bound this at ~15s.
    let converged = timeout(Duration::from_secs(15), async {
        loop {
            let snap = conn_state.load();
            let config_ok = dp_proxy_state
                .config
                .load()
                .proxies
                .iter()
                .any(|p| p.id == "fallback-proxy");
            if snap.connected && !snap.is_primary && config_ok {
                break snap.cp_url.clone();
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        converged.is_ok(),
        "DP never connected to the fallback CP (conn_state={:?}, proxies={:?})",
        conn_state.load().cp_url,
        dp_proxy_state
            .config
            .load()
            .proxies
            .iter()
            .map(|p| p.id.clone())
            .collect::<Vec<_>>()
    );
    let cp_url = converged.unwrap();
    assert_eq!(
        cp_url, fallback_url,
        "DP should be connected to the fallback URL"
    );

    let snap = conn_state.load();
    assert!(snap.connected, "cp_connection_state.connected must be true");
    assert!(
        !snap.is_primary,
        "cp_connection_state.is_primary must be false when on fallback"
    );
    println!("DP connected to fallback {} with is_primary=false", cp_url);

    let _ = shutdown_tx.send(true);
    client_handle.abort();
    fallback_handle.abort();
    println!("=== multi-CP failover test PASSED ===");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — primary-retry timer returns traffic to the primary when it recovers
// ─────────────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_primary_retry_reconnects_to_primary() {
    println!("=== primary-retry timer test ===");

    // Bogus primary — unreachable until we bring one up on that exact port.
    // We reserve the port by binding, then drop, to make an initial unreachable
    // primary. Later we bind a real CP on the same port to simulate recovery.
    // Because the port may be stolen between drop and re-bind, we do the
    // rebind inside a retry loop bounded at a few attempts.
    let primary_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind primary probe");
    let primary_addr = primary_probe.local_addr().expect("primary addr");
    drop(primary_probe);
    let primary_url = format!("http://{}", primary_addr);

    // Fallback CP (different port, always up).
    let fallback_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("fallback-only", "/fb", 4200)],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let (fallback_url, _fb_tx, _fb_cfg, _fb_reg, fallback_handle) =
        spawn_cp(fallback_config, 16).await;

    // DP with short primary-retry interval.
    let dp_proxy_state = create_proxy_state();
    let conn_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&primary_url),
    )));
    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());
    let cp_urls = vec![primary_url.clone(), fallback_url.clone()];
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ps = dp_proxy_state.clone();
    let cs = conn_state.clone();
    let client_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            cp_urls,
            secret,
            ps,
            Some(shutdown_rx),
            None,
            None,
            "ferrum".to_string(),
            3, // primary_retry_secs — disconnect from fallback every 3s to retry primary
            Some(cs),
        )
        .await;
    });

    // Phase 1: wait until we're on the fallback.
    let fallback_ok = timeout(Duration::from_secs(20), async {
        loop {
            let snap = conn_state.load();
            if snap.connected && !snap.is_primary && snap.cp_url == fallback_url {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        fallback_ok.is_ok(),
        "DP never connected to fallback; cp_url={}",
        conn_state.load().cp_url
    );
    println!("Phase 1: DP connected to fallback CP");

    // Phase 2: bring a real CP up on the primary's address. Because another
    // process may have reused that port, we accept a small window of rebind
    // attempts; if all fail we skip the recovery assertion.
    let primary_config = GatewayConfig {
        version: "primary-1".to_string(),
        proxies: vec![create_test_proxy("primary-proxy", "/primary", 4300)],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let mut primary_handle_opt: Option<tokio::task::JoinHandle<()>> = None;
    for attempt in 1..=5 {
        match tokio::net::TcpListener::bind(primary_addr).await {
            Ok(listener) => {
                let (cp_server, _tx) = CpGrpcServer::with_channel_capacity_and_registry(
                    Arc::new(ArcSwap::new(Arc::new(primary_config.clone()))),
                    GRPC_JWT_SECRET.to_string(),
                    16,
                    Arc::new(DpNodeRegistry::new()),
                );
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                let h = tokio::spawn(async move {
                    let _ = Server::builder()
                        .add_service(cp_server.into_service())
                        .serve_with_incoming(incoming)
                        .await;
                });
                primary_handle_opt = Some(h);
                break;
            }
            Err(e) => {
                eprintln!(
                    "Primary rebind attempt {attempt}/5 on {primary_addr} failed: {e}; retrying"
                );
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
    if primary_handle_opt.is_none() {
        eprintln!(
            "Could not rebind the primary CP on {} (port lost to another process). \
             Skipping Phase 2 assertions — Phase 1 (fallback) already PASSED.",
            primary_addr
        );
        let _ = shutdown_tx.send(true);
        client_handle.abort();
        fallback_handle.abort();
        return;
    }
    let primary_handle = primary_handle_opt.unwrap();

    // Phase 3: within a bounded window the DP should disconnect from the
    // fallback (primary_retry_secs=3 triggers the retry) and reconnect to
    // the primary. Allow ~12s to absorb retry interval + backoff + reconnect.
    let primary_ok = timeout(Duration::from_secs(15), async {
        loop {
            let snap = conn_state.load();
            let config_ok = dp_proxy_state
                .config
                .load()
                .proxies
                .iter()
                .any(|p| p.id == "primary-proxy");
            if snap.connected && snap.is_primary && snap.cp_url == primary_url && config_ok {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        primary_ok.is_ok(),
        "DP never reconnected to primary. state={{connected={}, is_primary={}, cp_url={}}}, proxies={:?}",
        conn_state.load().connected,
        conn_state.load().is_primary,
        conn_state.load().cp_url,
        dp_proxy_state
            .config
            .load()
            .proxies
            .iter()
            .map(|p| p.id.clone())
            .collect::<Vec<_>>()
    );
    println!("Phase 3: DP reconnected to primary CP (is_primary=true)");

    let _ = shutdown_tx.send(true);
    client_handle.abort();
    primary_handle.abort();
    fallback_handle.abort();
    println!("=== primary-retry test PASSED ===");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — `/cluster` endpoint shape for CP and DP admin listeners
// ─────────────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_cluster_endpoint_shape_cp_and_dp() {
    println!("=== /cluster endpoint shape test ===");

    // Spin up a CP that the DP subscribes to.
    let initial_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![create_test_proxy("cluster-seed", "/seed", 5000)],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let (cp_url, _tx, cached_config_arc, registry, server_handle) =
        spawn_cp(initial_config, 16).await;

    // Spawn CP admin listener with the shared registry.
    let cp_admin_state = build_cp_admin_state(cached_config_arc.clone(), registry.clone());
    let (cp_admin_url, cp_admin_shutdown) = spawn_admin(cp_admin_state).await;

    // Spawn DP: proxy state + connection state, subscribing to CP.
    let dp_proxy_state = create_proxy_state();
    let conn_state = Arc::new(ArcSwap::new(Arc::new(
        DpCpConnectionState::new_disconnected(&cp_url),
    )));
    let dp_admin_state = build_dp_admin_state(&dp_proxy_state, conn_state.clone());
    let (dp_admin_url, dp_admin_shutdown) = spawn_admin(dp_admin_state).await;

    let secret = dp_client::GrpcJwtSecret::new(GRPC_JWT_SECRET.to_string());
    let startup_ready = Arc::new(AtomicBool::new(false));
    let startup_ready_clone = startup_ready.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ps = dp_proxy_state.clone();
    let cs = conn_state.clone();
    let cp_urls = vec![cp_url.clone()];
    let dp_handle = tokio::spawn(async move {
        dp_client::start_dp_client_with_shutdown_and_startup_ready(
            cp_urls,
            secret,
            ps,
            Some(shutdown_rx),
            None,
            Some(startup_ready_clone),
            "ferrum".to_string(),
            0,
            Some(cs),
        )
        .await;
    });

    // Wait for the DP to subscribe and receive its snapshot.
    let sub_ok = timeout(Duration::from_secs(10), async {
        loop {
            if startup_ready.load(Ordering::Relaxed) && !registry.is_empty() {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        sub_ok.is_ok(),
        "DP never subscribed or CP registry never populated"
    );

    // --- CP /cluster ---
    let cp_body = admin_get_json(&cp_admin_url, "/cluster").await;
    assert_eq!(cp_body["mode"], "cp");
    let nodes = cp_body["data_planes"]
        .as_array()
        .expect("data_planes should be an array");
    assert_eq!(nodes.len(), 1, "CP should have exactly 1 DP registered");
    let node = &nodes[0];
    assert!(node["node_id"].is_string(), "node entry must carry node_id");
    assert_eq!(
        node["status"], "online",
        "subscribed DP must appear as online"
    );
    assert_eq!(
        node["namespace"], "ferrum",
        "namespace should be populated from SubscribeRequest"
    );
    assert!(
        node["connected_at"].is_string(),
        "connected_at must be serialized as RFC3339"
    );
    assert!(
        node["last_sync_at"].is_string(),
        "last_sync_at must be serialized as RFC3339"
    );
    println!("CP /cluster shape OK: {}", cp_body);

    // --- DP /cluster ---
    // The DP's connection state is populated asynchronously after the stream
    // is established; poll briefly for `connected=true`.
    let dp_body = timeout(Duration::from_secs(5), async {
        loop {
            let body = admin_get_json(&dp_admin_url, "/cluster").await;
            if body["control_plane"]["status"] == "online" {
                break body;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("DP /cluster never reported online");
    assert_eq!(dp_body["mode"], "dp");
    let cp = &dp_body["control_plane"];
    assert_eq!(cp["url"], cp_url);
    assert_eq!(cp["status"], "online");
    assert_eq!(
        cp["is_primary"], true,
        "single-URL DP must report is_primary=true"
    );
    assert!(
        cp["connected_since"].is_string(),
        "connected_since must be RFC3339 when online"
    );
    println!("DP /cluster shape OK: {}", dp_body);

    let _ = shutdown_tx.send(true);
    let _ = cp_admin_shutdown.send(true);
    let _ = dp_admin_shutdown.send(true);
    dp_handle.abort();
    server_handle.abort();
    println!("=== /cluster endpoint shape test PASSED ===");
}

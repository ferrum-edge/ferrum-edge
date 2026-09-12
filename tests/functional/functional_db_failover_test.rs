//! Functional tests for database failover, config backup bootstrap, and read replica.
//!
//! Verifies three resilience mechanisms in database mode:
//! 1. `FERRUM_DB_FAILOVER_URLS` — gateway tries primary, falls back to comma-
//!    separated failover URLs when primary is unreachable at startup.
//! 2. `FERRUM_DB_CONFIG_BACKUP_PATH` — gateway bootstraps from a read-only
//!    JSON backup file when the DB (and all failover URLs) are unreachable,
//!    so pods can start serving with stale-but-working config.
//! 3. `FERRUM_DB_READ_REPLICA_URL` — eligible admin reads can use a SQL
//!    replica with primary fallback. Runtime config polling always reads the
//!    primary-consistent database view.
//!
//! All tests use SQLite for speed and deterministic behaviour. Unreachable DBs
//! are simulated with `?mode=ro` plus a path that does not exist on disk — sqlx
//! fails to open the file with an explicit error instead of auto-creating it.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_db_failover

use chrono::Utc;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy, default_namespace};
use serde_json::json;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

/// Spawn a minimal HTTP echo backend that returns `200 OK` with a fixed body.
/// Used to verify proxy routing works when the gateway is bootstrapped from a
/// config backup while the DB is unreachable.
///
/// Takes a pre-bound `TcpListener` rather than a port number so the caller can
/// hold the port atomically from allocation through server startup — no
/// bind→drop→rebind race where another process could steal the port.
fn start_static_backend(
    listener: tokio::net::TcpListener,
    body: &'static str,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let body = body.to_string();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                // Consume request line + headers (don't care about contents).
                let mut line = String::new();
                while buf_reader.read_line(&mut line).await.is_ok() {
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                    line.clear();
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    })
}

fn mint_failover_identity(label: &str) -> crate::common::SpawnedGatewayIdentity {
    crate::common::SpawnedGatewayIdentity::mint(label)
}

fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Build the gateway binary. Thin wrapper over the shared
/// [`crate::common::ensure_gateway_built`] so this file's tests share the
/// same `OnceLock` memoization and `FERRUM_SKIP_GATEWAY_BUILD=1` contract as
/// the [`crate::common::TestGateway`] builder.
fn ensure_built() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

async fn wait_for_owned_health(
    child: &mut Child,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> bool {
    crate::common::wait_for_owned_gateway_identity(
        child,
        admin_port,
        identity,
        Duration::from_secs(30),
    )
    .await
    .is_ok()
}

/// Kill the child process and reap its zombie before any retry re-binds ports.
fn kill_child(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn seeded_proxy(id: &str, listen_path: &str, backend_port: u16) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: Some(id.to_string()),
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
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
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

// ============================================================================
// Test 1: Failover URLs at startup
// ============================================================================

/// When the primary DB is unreachable and a failover URL is reachable, the
/// gateway should successfully connect to the failover, run migrations there,
/// serve admin reads, and fail closed for admin writes by default (issue #3001).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_failover_urls_startup() {
    println!("\n=== DB Failover: primary unreachable, failover reachable ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        // Fresh temp dir + ports for each attempt so a stolen port from the
        // previous try doesn't poison this one.
        let temp_dir = TempDir::new().expect("temp dir");
        let failover_db_path: PathBuf = temp_dir.path().join("failover.db");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        // Primary URL points at a path that does not exist. With `?mode=ro`
        // sqlx returns an error instead of auto-creating the file, so the
        // connection attempt definitively fails and triggers failover logic.
        let bogus_primary = "sqlite:/nonexistent/primary-should-not-exist/bogus.db?mode=ro";
        let failover_url = format!("sqlite:{}?mode=rwc", failover_db_path.to_string_lossy());

        let identity = mint_failover_identity("db-failover-urls");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env("FERRUM_DB_FAILOVER_URLS", &failover_url)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        // Gateway is up backed by the failover DB. Reads succeed; writes fail closed.
        let client = reqwest::Client::new();
        let auth = identity.auth_header();

        let health = client
            .get(format!("http://127.0.0.1:{}/health", admin_port))
            .header("Authorization", &auth)
            .send()
            .await
            .expect("health")
            .json::<serde_json::Value>()
            .await
            .expect("health json");
        assert_eq!(
            health["admin_writes_enabled"].as_bool(),
            Some(false),
            "admin writes must fail closed on failover by default"
        );
        assert_eq!(
            health["database"]["failover_topology"]["primary_active"].as_bool(),
            Some(false),
            "health must expose failover topology"
        );

        let list = client
            .get(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .send()
            .await
            .expect("list proxies");
        assert_eq!(list.status(), 200, "GET /proxies should succeed");
        println!("  GET /proxies OK (failover DB in use)");

        let create = client
            .post(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .json(&json!({
                "id": "failover-proxy",
                "listen_path": "/failover",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 9999,
                "strip_listen_path": true,
            }))
            .send()
            .await
            .expect("create proxy");
        assert_eq!(
            create.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "POST /proxies must be 503 on failover without FERRUM_DB_FAILOVER_ALLOW_WRITES, got {}",
            create.status()
        );
        println!("  POST /proxies correctly fail-closed on failover DB");

        // Confirm the failover file actually exists on disk — proves the
        // gateway used failover, not some other fallback.
        assert!(
            failover_db_path.exists(),
            "Failover SQLite file should have been created on disk"
        );

        kill_child(child);
        println!("\n=== DB Failover URLs Test PASSED ===\n");
        return;
    }

    panic!(
        "Failover URLs test failed after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 2: Config backup path bootstrap
// ============================================================================

/// Exercise the public export producer and the real database startup fallback
/// together, including authenticated traffic from the restored consumer.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_config_backup_authenticated_export_roundtrip() {
    use crate::common::TestGateway;

    let temp_dir = TempDir::new().unwrap();
    let backup_path = temp_dir.path().join("administrative-backup.json");
    let backend = crate::scaffolding::ports::reserve_port().await.unwrap();
    let backend_port = backend.port;
    let backend_task = start_static_backend(backend.into_listener(), "export-roundtrip-ok");
    let producer = TestGateway::builder()
        .clear_env()
        .namespace("tenant-a")
        .spawn()
        .await
        .expect("healthy database producer");
    let client = reqwest::Client::new();
    let credentials = json!({
        "keyauth": [{"key": "backup-roundtrip-test-key"}],
        "jwt": [{"secret": "backup-roundtrip-test-secret-at-least-32-chars"}],
        "custom": [{"schema": {"private_key": {"type": "string"}}}]
    });
    for (path, payload) in [
        (
            "/consumers",
            json!({
                "id": "roundtrip-consumer", "username": "roundtrip-user",
                "credentials": credentials
            }),
        ),
        (
            "/plugins/config",
            json!({
                "id": "roundtrip-key-auth", "plugin_name": "key_auth",
                "scope": "global", "enabled": true,
                "config": {"key_location": "header:X-API-Key"}
            }),
        ),
        (
            "/proxies",
            json!({
                "id": "roundtrip-proxy", "listen_path": "/roundtrip",
                "backend_scheme": "http", "backend_host": "127.0.0.1",
                "backend_port": backend_port, "strip_listen_path": true
            }),
        ),
    ] {
        let response = client
            .post(producer.admin_url(path))
            .header("Authorization", producer.auth_header())
            .header("X-Ferrum-Namespace", "tenant-a")
            .json(&payload)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "seed {path}");
    }
    let response = client
        .get(producer.admin_url("/backup"))
        .header("Authorization", producer.auth_header())
        .header("X-Ferrum-Namespace", "tenant-a")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-data-source"], "database");
    let bytes = response.bytes().await.unwrap();
    let exported: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(exported["consumers"][0]["credentials"], credentials);
    assert!(exported.get("api_specs").is_some());
    assert!(exported.get("gateway_trust_bundles").is_some());
    // No envelope stripping or reserialization between the API and the file.
    std::fs::write(&backup_path, bytes).unwrap();
    drop(producer);

    let unavailable_url = format!(
        "sqlite:{}/missing/database.db?mode=ro",
        temp_dir.path().display()
    );
    let fallback = TestGateway::builder()
        .clear_env()
        .namespace("tenant-a")
        .env("FERRUM_DB_URL", &unavailable_url)
        .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "2")
        .env(
            "FERRUM_DB_CONFIG_BACKUP_PATH",
            backup_path.to_string_lossy(),
        )
        .spawn()
        .await
        .expect("boot from the unmodified authenticated export");
    let response = client
        .get(fallback.proxy_url("/roundtrip/hello"))
        .header("X-API-Key", "backup-roundtrip-test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "export-roundtrip-ok");
    let denied = client
        .get(fallback.proxy_url("/roundtrip/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    let health: serde_json::Value = client
        .get(fallback.admin_url("/health"))
        .header("Authorization", fallback.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["admin_writes_enabled"], false);
    let trust: serde_json::Value = client
        .get(fallback.admin_url("/gateway-trust/status"))
        .header("Authorization", fallback.auth_header())
        .header("X-Ferrum-Namespace", "tenant-a")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(trust["authority_unresolved"], true);
    drop(fallback);

    // A malformed runtime section must still reject before serving. The
    // failure must come from backup admission, not unrelated startup settings.
    let mut malformed = exported;
    malformed["consumers"][0]["credentials"]["jwt"] = json!([{
        "secret": "backup-roundtrip-test-secret-at-least-32-chars",
        "private_key": "malformed-credential-canary"
    }]);
    std::fs::write(&backup_path, malformed.to_string()).unwrap();
    let failure = TestGateway::builder()
        .clear_env()
        .namespace("tenant-a")
        .env("FERRUM_DB_URL", unavailable_url)
        .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "2")
        .env(
            "FERRUM_DB_CONFIG_BACKUP_PATH",
            backup_path.to_string_lossy(),
        )
        .spawn_expect_failure(Duration::from_secs(30))
        .await
        .expect("invalid backup must refuse startup");
    let output = failure.combined_output();
    assert!(output.contains("failed consumer validation"));
    assert!(!output.contains("malformed-credential-canary"));

    let healthy = TestGateway::builder()
        .clear_env()
        .namespace("tenant-a")
        .env(
            "FERRUM_DB_CONFIG_BACKUP_PATH",
            backup_path.to_string_lossy(),
        )
        .capture_output()
        .spawn()
        .await
        .expect("invalid backup must not reject a healthy database start");
    let output = healthy
        .wait_for_captured_output(
            |output| output.contains("Configured startup backup is unusable"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert!(output.contains("Configured startup backup is unusable"));
    assert!(!output.contains("malformed-credential-canary"));
    let response = client
        .get(healthy.proxy_url("/roundtrip/hello"))
        .header("X-API-Key", "backup-roundtrip-test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        404,
        "healthy DB config remains authoritative"
    );
    backend_task.abort();
}

/// When the DB is unreachable AND `FERRUM_DB_CONFIG_BACKUP_PATH` points at a
/// valid JSON snapshot, the gateway starts with that snapshot. Proxy routing
/// is served from the in-memory config built from the backup.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_config_backup_bootstrap() {
    println!("\n=== DB Config Backup: unreachable DB + backup JSON ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let backup_path: PathBuf = temp_dir.path().join("backup.json");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        // Bind the backend listener early and pass it directly into the echo
        // task — no drop-and-rebind, so the port is held atomically from
        // allocation through server startup. This eliminates the race where
        // another process could steal the numeric port between drop and rebind.
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend_listener.local_addr().unwrap().port();
        let _backend = start_static_backend(backend_listener, "backup-bootstrap-ok");

        // Write a minimal backup JSON that wires a proxy to the echo backend.
        // `namespace` defaults to "ferrum" via serde, matching the gateway's
        // default FERRUM_NAMESPACE.
        let backup_json = json!({
            "version": "1",
            "proxies": [{
                "id": "boot",
                "listen_path": "/boot",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
            }],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": [],
        });
        std::fs::write(&backup_path, backup_json.to_string()).expect("write backup");

        // Unreachable primary, empty failover list → load_full_config fails →
        // the database mode entry point falls through to load_config_backup().
        let bogus_primary = "sqlite:/nonexistent/bootstrap/bogus.db?mode=ro";

        let identity = mint_failover_identity("db-failover-backup");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        // Note: connecting to the primary DB fails with a short pool timeout,
        // but the backup loader still needs to read and parse the JSON file.
        // Budget plenty of time to avoid timing-out on a slow CI runner.
        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        println!("  Gateway healthy after backup-only bootstrap");

        // The admin API can't issue authenticated CRUD against a dead DB, but
        // the proxy HTTP listener serves routes from the in-memory config
        // built from the backup. Prove the backup proxy actually routes.
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/boot/hello", proxy_port))
            .send()
            .await
            .expect("proxy request");
        assert_eq!(
            resp.status(),
            200,
            "Proxy route from backup config should return 200"
        );
        let body = resp.text().await.unwrap_or_default();
        assert_eq!(
            body, "backup-bootstrap-ok",
            "Proxy should forward to backend defined in backup JSON"
        );
        println!("  Proxy routes via backup-defined proxy (body: {})", body);

        // Health endpoint should also flag the DB-unavailable state: writes
        // are disabled because the primary isn't reachable yet.
        let health = client
            .get(format!("http://127.0.0.1:{}/health", admin_port))
            .header("Authorization", identity.auth_header())
            .send()
            .await
            .expect("health");
        assert_eq!(health.status(), 200);
        let hjson: serde_json::Value = health.json().await.unwrap();
        assert_eq!(
            hjson["admin_writes_enabled"].as_bool(),
            Some(false),
            "admin_writes_enabled must be false while DB is unreachable"
        );
        println!("  Health reports admin_writes_enabled=false (DB still down)");

        kill_child(child);
        println!("\n=== DB Config Backup Bootstrap Test PASSED ===\n");
        return;
    }

    // Exhausted all retries without the gateway becoming healthy. This is a
    // real regression signal — `FERRUM_DB_CONFIG_BACKUP_PATH` bootstrap must
    // bring the proxy HTTP listener up when the primary DB is unreachable,
    // otherwise operators relying on this fallback will find their pods can't
    // serve traffic during a DB outage. Fail the test rather than skipping.
    panic!(
        "Config backup bootstrap did not bring gateway healthy after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 2a: Invalid backup must fail closed (runtime validation)
// ============================================================================

/// When the DB is unreachable AND `FERRUM_DB_CONFIG_BACKUP_PATH` points at a
/// syntactically valid JSON snapshot that violates the rejecting runtime
/// contract (duplicate listen path), startup must fail closed rather than
/// serving the ambiguous backup.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_config_backup_bootstrap_rejects_invalid_runtime_config() {
    println!("\n=== DB Config Backup: unreachable DB + invalid backup JSON ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let backup_path: PathBuf = temp_dir.path().join("backup-invalid.json");

        // Two proxies share the same catch-all listen_path — accepted by JSON
        // deserialize/normalize but rejected by collect_rejecting_runtime_config_errors.
        let backup_json = json!({
            "version": "1",
            "proxies": [
                {
                    "id": "dup-a",
                    "listen_path": "/boot",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                    "strip_listen_path": true,
                },
                {
                    "id": "dup-b",
                    "listen_path": "/boot",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                    "strip_listen_path": true,
                }
            ],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": [],
        });
        std::fs::write(&backup_path, backup_json.to_string()).expect("write backup");

        let bogus_primary = "sqlite:/nonexistent/bootstrap/bogus-invalid-backup.db?mode=ro";
        let identity = mint_failover_identity("db-failover-backup-reject");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            // Both listeners are irrelevant to this pre-serving rejection
            // path. Disabling them avoids introducing a bind/drop/rebind race
            // into a test whose sole success condition is a non-zero exit.
            .env("FERRUM_ADMIN_HTTP_PORT", "0")
            .env("FERRUM_PROXY_HTTP_PORT", "0")
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        // An invalid backup should fail closed with a non-zero status once the
        // unreachable primary pool times out and the backup rejection path
        // runs. If the process keeps running, it accepted the invalid snapshot.
        let deadline = SystemTime::now() + Duration::from_secs(25);
        let mut try_wait_err = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if SystemTime::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Ok(None) => break None,
                Err(e) => {
                    try_wait_err = Some(format!("attempt {}: try_wait failed: {}", attempt, e));
                    break None;
                }
            }
        };

        // stderr is a pipe: reading it while a timed-out child is still alive
        // can block forever waiting for EOF. Terminate and reap first.
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let stderr = child
            .stderr
            .take()
            .map(|mut pipe| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = pipe.read_to_string(&mut buf);
                buf
            })
            .unwrap_or_default();

        match status {
            Some(status) if !status.success() => {
                let lower = stderr.to_lowercase();
                assert!(
                    lower.contains("failed runtime validation")
                        || lower.contains("config backup")
                            && (lower.contains("rejected") || lower.contains("overlapping")),
                    "stderr must mention backup runtime rejection.\nstderr:\n{stderr}"
                );
                println!(
                    "  Gateway failed closed on invalid backup (exit={:?})",
                    status,
                );
                println!("\n=== DB Config Backup Bootstrap Rejection Test PASSED ===\n");
                return;
            }
            Some(status) => {
                last_err = format!(
                    "attempt {}: gateway exited successfully ({:?}) despite invalid backup\nstderr:\n{}",
                    attempt, status, stderr
                );
            }
            None => {
                last_err = try_wait_err.unwrap_or_else(|| {
                    format!(
                        "attempt {}: gateway did not exit after accepting an invalid backup\nstderr:\n{}",
                        attempt, stderr
                    )
                });
            }
        }

        eprintln!("  {}", last_err);
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    panic!(
        "Invalid config backup was not rejected after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 2b-ns: Multi-namespace backup is projected onto FERRUM_NAMESPACE
// ============================================================================

/// An externally provisioned startup backup may be an all-namespace export.
/// The gateway must serve ONLY the namespace it is configured for.
///
/// Success criteria:
/// 1. The gateway starts at all — the file holds two proxies on the same
///    `listen_path` in different namespaces, which the cross-resource
///    validators would reject if they ran over the unfiltered file.
/// 2. The active namespace's route serves, authenticated by the active
///    namespace's consumer credential.
/// 3. The other namespace's credential does NOT authenticate on that route.
/// 4. A route that exists only in the other namespace 404s — its listener and
///    route were never installed.
/// 5. The startup log names no foreign resource and carries no credential.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_config_backup_bootstrap_filters_to_configured_namespace() {
    println!("\n=== DB Config Backup: multi-namespace export, one served namespace ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let backup_path: PathBuf = temp_dir.path().join("backup-multi-namespace.json");
        let log_path: PathBuf = temp_dir.path().join("gateway.stderr");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        // Held atomically from allocation through server startup.
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend_listener.local_addr().unwrap().port();
        let _backend = start_static_backend(backend_listener, "tenant-a-backend");

        // A two-namespace export. `tenant-a` and `tenant-b` deliberately share
        // `/shared`: that collision is legal because listen paths are
        // `(namespace, value)`-scoped, and it is exactly what an unfiltered
        // backup load would reject.
        let backup_json = json!({
            "version": "1",
            "known_namespaces": ["tenant-a", "tenant-b"],
            "proxies": [
                {
                    "id": "a-shared",
                    "namespace": "tenant-a",
                    "listen_path": "/shared",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": backend_port,
                    "strip_listen_path": true,
                    "plugins": [{"plugin_config_id": "a-key-auth"}],
                },
                {
                    "id": "b-shared",
                    "namespace": "tenant-b",
                    "listen_path": "/shared",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                    "strip_listen_path": true,
                },
                {
                    "id": "b-only",
                    "namespace": "tenant-b",
                    "listen_path": "/tenant-b-only",
                    "backend_scheme": "http",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                    "strip_listen_path": true,
                }
            ],
            "consumers": [
                {
                    "id": "alice",
                    "username": "alice",
                    "namespace": "tenant-a",
                    "credentials": {"keyauth": [{"key": "tenant-a-api-key"}]},
                },
                {
                    "id": "bob",
                    "username": "bob",
                    "namespace": "tenant-b",
                    "credentials": {"keyauth": [{"key": "tenant-b-api-key"}]},
                }
            ],
            "upstreams": [],
            "plugin_configs": [
                {
                    "id": "a-key-auth",
                    "namespace": "tenant-a",
                    "plugin_name": "key_auth",
                    "scope": "proxy",
                    "proxy_id": "a-shared",
                    "enabled": true,
                    "config": {"key_location": "header:X-API-Key"},
                },
                {
                    "id": "b-key-auth",
                    "namespace": "tenant-b",
                    "plugin_name": "key_auth",
                    "scope": "proxy",
                    "proxy_id": "b-only",
                    "enabled": true,
                    "config": {"key_location": "header:X-API-Key"},
                }
            ],
        });
        std::fs::write(&backup_path, backup_json.to_string()).expect("write backup");

        let bogus_primary = "sqlite:/nonexistent/bootstrap/bogus-multi-namespace.db?mode=ro";
        let identity = mint_failover_identity("db-failover-backup-namespace");

        let log_file = std::fs::File::create(&log_path).expect("create stderr log");
        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env("FERRUM_NAMESPACE", "tenant-a")
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!(
                "attempt {}: health check did not pass (a multi-namespace backup must \
                 still bootstrap the configured namespace)",
                attempt
            );
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }
        println!("  Gateway healthy from a two-namespace backup export");

        let client = reqwest::Client::new();

        // 1. The active namespace's route serves, with its own credential.
        let ok = client
            .get(format!("http://127.0.0.1:{}/shared/hello", proxy_port))
            .header("X-API-Key", "tenant-a-api-key")
            .send()
            .await
            .expect("tenant-a proxy request");
        assert_eq!(
            ok.status(),
            200,
            "the configured namespace's route must serve from the backup"
        );
        assert_eq!(
            ok.text().await.unwrap_or_default(),
            "tenant-a-backend",
            "the configured namespace's proxy must reach its own backend"
        );

        // 2. The other namespace's consumer credential must not authenticate.
        let foreign = client
            .get(format!("http://127.0.0.1:{}/shared/hello", proxy_port))
            .header("X-API-Key", "tenant-b-api-key")
            .send()
            .await
            .expect("tenant-b credential request");
        assert_eq!(
            foreign.status(),
            401,
            "a consumer from another namespace must not authenticate"
        );

        // 3. A route that exists only in the other namespace was never installed.
        let foreign_route = client
            .get(format!(
                "http://127.0.0.1:{}/tenant-b-only/hello",
                proxy_port
            ))
            .send()
            .await
            .expect("tenant-b-only route request");
        assert_eq!(
            foreign_route.status(),
            404,
            "another namespace's route must not be routable"
        );
        println!("  tenant-b route 404s and tenant-b credential is rejected");

        kill_child(child);

        // 4. The startup log must not disclose the other tenant or any secret.
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        for forbidden in [
            "tenant-a-api-key",
            "tenant-b-api-key",
            "tenant-b",
            "b-only",
            "b-shared",
            "b-key-auth",
            // Short tokens like the foreign username are deliberately omitted:
            // the log embeds a randomly named temporary directory that a
            // 3-character needle could match by chance.
        ] {
            assert!(
                !log.contains(forbidden),
                "startup output disclosed '{}':\n{}",
                forbidden,
                log
            );
        }
        println!("  Startup output names no foreign resource and no credential");

        println!("\n=== DB Config Backup Namespace Filter Test PASSED ===\n");
        return;
    }

    panic!(
        "Multi-namespace backup bootstrap did not serve the configured namespace \
         after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 2b: Backup bootstrap recovers via failover URL (no primary ever up)
// ============================================================================

/// Gateway starts with an unreachable primary and configured failover URLs.
/// The backup file bootstraps the in-memory config, then the polling loop's
/// `try_failover_reconnect()` must probe the failover URL — a primary that
/// stays down must never prevent recovery when a healthy failover is available.
///
/// Success criteria:
/// 1. Gateway starts healthy from backup (same as `test_db_config_backup_bootstrap`).
/// 2. Within the polling window, `db_available` flips to `true` because the
///    failover URL connected and deferred migrations ran on it.
/// 3. Admin writes succeed via the now-connected pool (proves migrations ran —
///    writes would error with "no such table" if migrations were skipped).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_backup_bootstrap_recovers_via_failover_url() {
    println!("\n=== DB Backup Bootstrap: recover via failover URL ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let backup_path: PathBuf = temp_dir.path().join("backup.json");
        let failover_db_path: PathBuf = temp_dir.path().join("failover.db");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        // Minimal backup JSON — we don't need proxy routing to succeed here,
        // only to prove the gateway started and then recovered via failover.
        let backup_json = json!({
            "version": "1",
            "proxies": [],
            "consumers": [],
            "upstreams": [],
            "plugin_configs": [],
        });
        std::fs::write(&backup_path, backup_json.to_string()).expect("write backup");

        // Primary is a non-existent file (mode=ro → sqlx errors instead of
        // auto-creating). Failover is a writable file that sqlx will create
        // on demand when the polling loop retries — proving the recovery path
        // runs migrations on the newly-connected failover DB.
        let bogus_primary = "sqlite:/nonexistent/recovery-test/bogus.db?mode=ro";
        let failover_url = format!("sqlite:{}?mode=rwc", failover_db_path.to_string_lossy());

        let identity = mint_failover_identity("db-failover-recovery");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env("FERRUM_DB_FAILOVER_URLS", &failover_url)
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "1")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        println!("  Gateway healthy after backup-only bootstrap");

        // Poll `/health` until the failover DB is connected. Default fail-closed
        // policy keeps admin_writes_enabled=false while on failover topology
        // (issue #3001); recovery is evidenced by database.status=connected and
        // ready=true, not by writable admin.
        let client = reqwest::Client::new();
        let health_url = format!("http://127.0.0.1:{}/health", admin_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut recovered = false;
        let mut last_health = serde_json::Value::Null;
        let health_auth = identity.auth_header();
        while std::time::Instant::now() < deadline {
            if let Ok(resp) = client
                .get(&health_url)
                .header("Authorization", &health_auth)
                .send()
                .await
                && let Ok(hjson) = resp.json::<serde_json::Value>().await
            {
                last_health = hjson.clone();
                if hjson["ready"].as_bool() == Some(true)
                    && hjson["database"]["status"].as_str() == Some("connected")
                {
                    recovered = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if !recovered {
            last_err = format!(
                "attempt {}: failover reconnect never recovered (last health={})",
                attempt, last_health
            );
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }
        println!("  Health reports database connected (recovered via failover)");
        assert_eq!(
            last_health["admin_writes_enabled"].as_bool(),
            Some(false),
            "admin writes must fail closed on failover topology by default"
        );
        assert_eq!(
            last_health["database"]["failover_topology"]["primary_active"].as_bool(),
            Some(false),
            "health must expose redacted failover topology while failed over"
        );

        // Reads stay available; mutations stay gated. A GET proves the failover
        // schema/migrations path without accepting a write that failback would erase.
        let auth = identity.auth_header();
        let list = client
            .get(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .send()
            .await
            .expect("list proxies after failover recovery");
        assert!(
            list.status().is_success(),
            "GET /proxies should succeed on failover (polling/reads preserved), got {}",
            list.status()
        );
        let create = client
            .post(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .json(&json!({
                "id": "recovery-proxy",
                "listen_path": "/recovered",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 9999,
                "strip_listen_path": true,
            }))
            .send()
            .await
            .expect("create proxy after recovery");
        assert_eq!(
            create.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "POST /proxies must be 503 while on failover without FERRUM_DB_FAILOVER_ALLOW_WRITES"
        );
        println!("  Admin reads succeed and writes fail closed on failover DB");

        assert!(
            failover_db_path.exists(),
            "Failover SQLite file should have been created during recovery"
        );

        kill_child(child);
        println!("\n=== DB Backup Bootstrap → Failover Recovery Test PASSED ===\n");
        return;
    }

    panic!(
        "Backup-bootstrap failover recovery did not complete after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 3: Read replica happy path
// ============================================================================

/// Start the gateway with a reachable primary AND a reachable read replica.
///
/// In production, primary and replica are the same logical database reached
/// via two URLs — the replica sees the primary's schema via streaming
/// replication. To simulate that with SQLite, we point both URLs at the same
/// file: migrations run on the primary URL, creating tables, and the replica
/// URL opens the same file so reads through the replica pool succeed. This
/// exercises the real codepath (replica connect, admin reads can use replica) without
/// needing a multi-database setup.
///
/// The test asserts the gateway comes up healthy, the replica pool connects,
/// and admin writes succeed (writes always target the primary pool).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_read_replica_startup() {
    println!("\n=== DB Read Replica: primary + replica startup ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let db_path = temp_dir.path().join("gateway.db");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        // Primary and replica point at the same SQLite file — replicates real
        // production semantics where both URLs resolve to the same logical DB
        // with shared schema.
        let primary_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        let replica_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

        let identity = mint_failover_identity("db-failover-replica");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &primary_url)
            .env("FERRUM_DB_READ_REPLICA_URL", &replica_url)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        println!("  Gateway healthy with primary + replica configured");

        // Schema should have been created (migrations ran on the primary URL).
        // Replica connected to the same file without re-running migrations.
        assert!(db_path.exists(), "gateway.db should exist after startup");

        let client = reqwest::Client::new();
        let auth = identity.auth_header();

        // Writes always go to primary — exercise that codepath.
        let create = client
            .post(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .json(&json!({
                "id": "replica-test-proxy",
                "listen_path": "/replica-test",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 9999,
                "strip_listen_path": true,
            }))
            .send()
            .await
            .expect("create proxy");
        assert!(
            create.status().is_success(),
            "POST /proxies (→ primary) should succeed, got {}",
            create.status()
        );
        println!("  POST /proxies routes to primary (success)");

        // Health should report normal (admin_writes_enabled=true). The replica
        // connected cleanly so there's no degradation warning.
        let health = client
            .get(format!("http://127.0.0.1:{}/health", admin_port))
            .header("Authorization", &auth)
            .send()
            .await
            .expect("health");
        assert_eq!(health.status(), 200);
        let hjson: serde_json::Value = health.json().await.unwrap();
        assert_eq!(
            hjson["admin_writes_enabled"].as_bool(),
            Some(true),
            "admin_writes_enabled must be true with primary reachable"
        );
        println!("  Health reports admin_writes_enabled=true");

        kill_child(child);
        println!("\n=== DB Read Replica Startup Test PASSED ===\n");
        return;
    }

    // Exhausted all retries without the gateway becoming healthy. A regression
    // in `FERRUM_DB_READ_REPLICA_URL` wiring (e.g., the replica connect call
    // silently blocking startup) should fail the suite, not be swallowed.
    panic!(
        "Read replica startup test did not complete after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Test 4: Authoritative runtime polling ignores stale read replica
// ============================================================================

/// Startup full-load and runtime routing must read the primary-consistent DB
/// view even when a SQL read replica URL is configured.
///
/// This seeds the primary SQLite DB with a route, points the configured
/// "replica" at a separate empty SQLite file, and then starts the gateway.
/// Old replica-backed startup polling would read the empty replica and fail
/// before the proxy listener came up. The admin list call also proves replica
/// query failure falls back to primary for eligible admin reads.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_db_authoritative_startup_uses_primary_when_replica_is_stale() {
    println!("\n=== DB Read Replica: authoritative startup uses primary ===\n");
    ensure_built().expect("Failed to build gateway binary");

    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("temp dir");
        let primary_db_path: PathBuf = temp_dir.path().join("primary.db");
        let replica_db_path: PathBuf = temp_dir.path().join("replica-empty.db");

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend_listener.local_addr().unwrap().port();
        let _backend = start_static_backend(backend_listener, "primary-authoritative-ok");

        let primary_url = format!("sqlite:{}?mode=rwc", primary_db_path.to_string_lossy());
        let replica_url = format!("sqlite:{}?mode=rwc", replica_db_path.to_string_lossy());

        let store = DatabaseStore::connect_with_pool_config(
            "sqlite",
            &primary_url,
            DbPoolConfig::default(),
        )
        .await
        .expect("seed primary DB");
        store
            .create_proxy(&seeded_proxy(
                "authoritative-primary",
                "/primary",
                backend_port,
            ))
            .await
            .expect("insert primary proxy");
        drop(store);

        let identity = mint_failover_identity("db-failover-authoritative");

        let mut cmd = Command::new(binary_path());
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &primary_url)
            .env("FERRUM_DB_READ_REPLICA_URL", &replica_url)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "1")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        identity.apply_to_command(&mut cmd);
        let mut child = cmd.spawn().expect("spawn gateway");

        if !wait_for_owned_health(&mut child, admin_port, &identity).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{}/primary/hello", proxy_port))
            .send()
            .await
            .expect("proxy request");
        assert_eq!(
            resp.status(),
            200,
            "Route seeded only in primary DB should be active at startup"
        );
        let body = resp.text().await.unwrap_or_default();
        assert_eq!(body, "primary-authoritative-ok");

        let auth = identity.auth_header();
        let list = client
            .get(format!("http://127.0.0.1:{}/proxies", admin_port))
            .header("Authorization", &auth)
            .send()
            .await
            .expect("list proxies");
        assert_eq!(
            list.status(),
            200,
            "GET /proxies should fall back to primary when replica has no schema"
        );
        let list_body = list.text().await.unwrap_or_default();
        assert!(
            list_body.contains("authoritative-primary"),
            "GET /proxies should return the primary DB proxy after fallback: {}",
            list_body
        );

        assert!(
            replica_db_path.exists(),
            "Replica SQLite file should have been opened but not used for startup config"
        );

        kill_child(child);
        println!("\n=== DB Authoritative Primary Startup Test PASSED ===\n");
        return;
    }

    panic!(
        "Authoritative primary startup test did not complete after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

//! Functional tests for database failover, config backup bootstrap, and read replica.
//!
//! Verifies three resilience mechanisms in database mode:
//! 1. `FERRUM_DB_FAILOVER_URLS` — gateway tries primary, falls back to comma-
//!    separated failover URLs when primary is unreachable at startup.
//! 2. `FERRUM_DB_CONFIG_BACKUP_PATH` — gateway bootstraps from a read-only
//!    JSON backup file when the DB (and all failover URLs) are unreachable,
//!    so pods can start serving with stale-but-working config.
//! 3. `FERRUM_DB_READ_REPLICA_URL` — polling reads use the replica instead of
//!    the primary. Writes always target the primary via the admin API.
//!
//! All tests use SQLite for speed and deterministic behaviour. Unreachable DBs
//! are simulated with `?mode=ro` plus a path that does not exist on disk — sqlx
//! fails to open the file with an explicit error instead of auto-creating it.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_db_failover

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

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

fn auth_header(jwt_secret: &str, jwt_issuer: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": jwt_issuer,
        "sub": "test-admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let token = encode(&header, &claims, &key).expect("Failed to encode admin JWT");
    format!("Bearer {}", token)
}

fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Build the gateway binary if not already present. Shared across all tests in
/// this file — subsequent invocations are no-ops because cargo handles caching.
fn ensure_built() -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("cargo")
        .args(["build", "--bin", "ferrum-edge"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Failed to build ferrum-edge".into());
    }
    Ok(())
}

async fn wait_for_health(admin_port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = SystemTime::now() + Duration::from_secs(30);
    loop {
        if SystemTime::now() >= deadline {
            return false;
        }
        match reqwest::get(&url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Kill the child process and reap its zombie before any retry re-binds ports.
fn kill_child(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

// ============================================================================
// Test 1: Failover URLs at startup
// ============================================================================

/// When the primary DB is unreachable and a failover URL is reachable, the
/// gateway should successfully connect to the failover, run migrations there,
/// and serve admin API traffic backed by that failover DB.
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

        let jwt_secret = "failover-urls-test-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-failover-test".to_string();

        let child = Command::new(binary_path())
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env("FERRUM_DB_FAILOVER_URLS", &failover_url)
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway");

        if !wait_for_health(admin_port).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        // Gateway is up backed by the failover DB. Verify admin API reads and
        // writes succeed against it.
        let client = reqwest::Client::new();
        let auth = auth_header(&jwt_secret, &jwt_issuer);

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
        assert!(
            create.status().is_success(),
            "POST /proxies should succeed against failover DB, got {}",
            create.status()
        );
        println!("  POST /proxies OK (write succeeded against failover DB)");

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

        let jwt_secret = "backup-bootstrap-test-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-backup-test".to_string();

        let child = Command::new(binary_path())
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway");

        // Note: connecting to the primary DB fails with a short pool timeout,
        // but the backup loader still needs to read and parse the JSON file.
        // Budget plenty of time to avoid timing-out on a slow CI runner.
        if !wait_for_health(admin_port).await {
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

        let jwt_secret = "recovery-test-jwt-secret-ferrum-edge-12345".to_string();
        let jwt_issuer = "ferrum-edge-recovery-test".to_string();

        let child = Command::new(binary_path())
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", bogus_primary)
            .env("FERRUM_DB_FAILOVER_URLS", &failover_url)
            .env(
                "FERRUM_DB_CONFIG_BACKUP_PATH",
                backup_path.to_string_lossy().to_string(),
            )
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "1")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway");

        if !wait_for_health(admin_port).await {
            last_err = format!("attempt {}: health check did not pass", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }

        println!("  Gateway healthy after backup-only bootstrap");

        // Poll `/health` until `admin_writes_enabled=true`. With a 1-second
        // poll interval and a reachable failover, recovery typically happens
        // within 3-5 seconds. Give it up to 20 seconds to be safe on slow CI.
        let client = reqwest::Client::new();
        let health_url = format!("http://127.0.0.1:{}/health", admin_port);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut recovered = false;
        while std::time::Instant::now() < deadline {
            if let Ok(resp) = client.get(&health_url).send().await
                && let Ok(hjson) = resp.json::<serde_json::Value>().await
                && hjson["admin_writes_enabled"].as_bool() == Some(true)
            {
                recovered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        if !recovered {
            last_err = format!("attempt {}: failover reconnect never recovered", attempt);
            eprintln!("  {}", last_err);
            kill_child(child);
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            continue;
        }
        println!("  Health reports admin_writes_enabled=true (recovered via failover)");

        // Sanity check that migrations ran on the failover DB: an admin write
        // would fail with "no such table" if they had been skipped.
        let auth = auth_header(&jwt_secret, &jwt_issuer);
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
        assert!(
            create.status().is_success(),
            "POST /proxies should succeed after failover recovery (migrations must have run), got {}",
            create.status()
        );
        println!("  Admin writes succeed against failover DB (migrations ran on reconnect)");

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
/// exercises the real codepath (replica connect, polling via replica) without
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

        let jwt_secret = "replica-startup-test-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-replica-test".to_string();

        let child = Command::new(binary_path())
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &primary_url)
            .env("FERRUM_DB_READ_REPLICA_URL", &replica_url)
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "3")
            .env("FERRUM_LOG_LEVEL", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway");

        if !wait_for_health(admin_port).await {
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
        let auth = auth_header(&jwt_secret, &jwt_issuer);

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

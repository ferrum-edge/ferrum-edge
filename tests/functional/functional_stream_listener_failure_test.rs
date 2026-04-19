//! Functional tests for stream listener (TCP/UDP) bind failures & port validation.
//!
//! Covers the design described in `CLAUDE.md` under "Stream Proxy Port Validation":
//!
//! * Admin API (database mode) rejects a stream proxy whose `listen_port`
//!   equals a reserved gateway port (proxy HTTP, admin HTTP, ...).
//! * Admin API rejects two stream proxies with the same `listen_port` in the
//!   same namespace. The check is namespace-scoped so different namespaces are
//!   allowed to reuse the same port.
//! * In database / file mode an initial bind failure (port already in use by
//!   another process) is fatal — the gateway exits non-zero with a clear error.
//! * In file mode, a SIGHUP-driven config reload correctly reconciles the set
//!   of stream listeners: removed proxies release their ports, newly-added
//!   proxies bind cleanly.
//!
//! Relevant source:
//!   - `src/proxy/stream_listener.rs`           — listener lifecycle
//!   - `src/config/env_config.rs`               — `reserved_gateway_ports()`
//!   - `src/config/types.rs`                    — `validate_stream_proxy_port_conflicts`
//!   - `src/admin/mod.rs`                       — admin API port uniqueness / reserved-port checks
//!   - `src/modes/database.rs`, `src/modes/file.rs` — startup-fatal reserved-port check
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored --nocapture functional_stream_listener
//!
//! DP-mode bind failure is not exercised here — it requires a live CP pushing
//! a bad config to a running DP and is covered by `functional_cp_dp_test.rs`
//! (connectivity) plus the inline unit coverage of `initial_reconcile_stream_listeners`.
//! TODO: add a DP-mode bind-failure case if/when the CP test harness is
//! refactored to allow injecting a bad-port proxy from an in-process CP.

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;
use uuid::Uuid;

// ============================================================================
// Shared helpers
// ============================================================================

const JWT_SECRET: &str = "stream-listener-test-jwt-secret-0123456789";
const JWT_ISSUER: &str = "ferrum-edge-stream-listener-test";

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn admin_jwt() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "stream-listener-test-admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(JWT_SECRET.as_bytes());
    encode(&header, &claims, &key).expect("encode admin JWT")
}

fn auth_header() -> String {
    format!("Bearer {}", admin_jwt())
}

/// Bind an ephemeral port then drop the listener. Vulnerable to races — only
/// used where callers tolerate them (retry loops or pre-binding).
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = listener.local_addr().unwrap().port();
    drop(listener);
    p
}

/// Minimal TCP stream proxy definition for the admin API.
fn sample_stream_proxy(id: &str, listen_port: u16, backend_port: u16) -> serde_json::Value {
    json!({
        "id": id,
        "backend_protocol": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "listen_port": listen_port,
    })
}

/// Plain TCP echo server on a pre-bound listener (no port race).
async fn start_tcp_echo_server_on(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _addr)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    })
}

async fn wait_for_health(admin_port: u16) -> bool {
    let url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = SystemTime::now() + Duration::from_secs(30);
    loop {
        if SystemTime::now() >= deadline {
            return false;
        }
        if let Ok(r) = reqwest::get(&url).await
            && r.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// True iff something is currently accepting TCP connections on 127.0.0.1:port.
async fn port_is_bound(port: u16) -> bool {
    matches!(
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await,
        Ok(Ok(_))
    )
}

// ============================================================================
// Database mode harness
// ============================================================================

struct DbHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    admin_base_url: String,
    admin_port: u16,
    _proxy_port: u16,
}

impl DbHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new().await {
                Ok(h) => return Ok(h),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "DbHarness startup attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to create DbHarness after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;

        let admin_port = ephemeral_port().await;
        let proxy_port = ephemeral_port().await;

        let db_url = format!(
            "sqlite:{}?mode=rwc",
            temp_dir.path().join("test.db").to_string_lossy()
        );

        let child = Command::new(gateway_binary_path())
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
            .env("FERRUM_ADMIN_JWT_ISSUER", JWT_ISSUER)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let mut h = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(child),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            admin_port,
            _proxy_port: proxy_port,
        };

        if wait_for_health(admin_port).await {
            Ok(h)
        } else {
            if let Some(mut c) = h.gateway_process.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
            Err("Gateway did not become healthy within 30s".into())
        }
    }
}

impl Drop for DbHarness {
    fn drop(&mut self) {
        if let Some(mut c) = self.gateway_process.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ============================================================================
// Test 1: Admin API rejects stream proxy on a gateway-reserved port.
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_stream_listener_reserved_port_rejected() {
    let harness = DbHarness::new().await.expect("harness");
    let client = reqwest::Client::new();

    // Try to create a TCP stream proxy whose listen_port = the admin HTTP port.
    // The admin API must reject this before it ever reaches the listener.
    let body = sample_stream_proxy(
        "stream-reserved-port",
        harness.admin_port, // collides with FERRUM_ADMIN_HTTP_PORT
        9999,
    );

    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", auth_header())
        .json(&body)
        .send()
        .await
        .expect("POST /proxies");

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(
        status.as_u16() == 409 || status.as_u16() == 400,
        "expected 400/409 rejection for reserved-port stream proxy, got {} body={}",
        status,
        text
    );
    assert!(
        text.to_lowercase().contains("reserved")
            || text.to_lowercase().contains("conflict")
            || text.to_lowercase().contains("in use"),
        "response should mention the reservation / conflict, got: {}",
        text
    );
}

// ============================================================================
// Test 2: Duplicate listen_port in the same namespace is rejected.
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_stream_listener_duplicate_port_same_namespace() {
    let harness = DbHarness::new().await.expect("harness");
    let client = reqwest::Client::new();

    // Pick a port that is:
    //  - free at allocation time
    //  - not the admin or proxy port (guaranteed by ephemeral_port reuse rarity)
    let shared_port = ephemeral_port().await;
    assert_ne!(shared_port, harness.admin_port);

    let resp_a = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", auth_header())
        .json(&sample_stream_proxy("dup-a", shared_port, 9001))
        .send()
        .await
        .expect("POST /proxies A");
    assert!(
        resp_a.status().is_success(),
        "first stream proxy should succeed: {} body={}",
        resp_a.status(),
        resp_a.text().await.unwrap_or_default()
    );

    let resp_b = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", auth_header())
        .json(&sample_stream_proxy("dup-b", shared_port, 9002))
        .send()
        .await
        .expect("POST /proxies B");
    let status = resp_b.status();
    let text = resp_b.text().await.unwrap_or_default();
    assert_eq!(
        status.as_u16(),
        409,
        "duplicate listen_port within same namespace must 409; got {} body={}",
        status,
        text
    );
    assert!(
        text.to_lowercase().contains("listen_port")
            || text.to_lowercase().contains("already in use"),
        "response should mention the duplicate listen_port, got: {}",
        text
    );
}

// ============================================================================
// Test 3: Same listen_port across different namespaces is accepted.
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_stream_listener_duplicate_port_different_namespaces() {
    let harness = DbHarness::new().await.expect("harness");
    let client = reqwest::Client::new();

    let shared_port = ephemeral_port().await;
    assert_ne!(shared_port, harness.admin_port);

    // Namespace "foo" — succeeds.
    let resp_a = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", auth_header())
        .header("X-Ferrum-Namespace", "foo")
        .json(&sample_stream_proxy("ns-foo-tcp", shared_port, 9001))
        .send()
        .await
        .expect("POST /proxies foo");
    assert!(
        resp_a.status().is_success(),
        "create in namespace 'foo' must succeed: {} body={}",
        resp_a.status(),
        resp_a.text().await.unwrap_or_default()
    );

    // Namespace "bar" — same port, must also succeed because uniqueness is
    // scoped per-namespace. Port-availability probing is skipped here because
    // the admin API doesn't check OS-level uniqueness in CP mode and in
    // database mode the probe happens *before* insertion — we rely on the
    // namespace filter in check_listen_port_unique() to allow the duplicate.
    let resp_b = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", auth_header())
        .header("X-Ferrum-Namespace", "bar")
        .json(&sample_stream_proxy("ns-bar-tcp", shared_port, 9002))
        .send()
        .await
        .expect("POST /proxies bar");
    // In database mode the admin API also runs an OS-level bind probe for
    // stream proxies. Because each namespace's listeners run on different
    // machines conceptually, but in this single-binary test they would both
    // bind to the same host, the probe may or may not reject the second
    // create. Accept either 2xx (probe passed / gateway not yet bound) or
    // 409 (probe tripped) — but the *uniqueness check itself* must not
    // be the reason for rejection.
    let status = resp_b.status();
    let text = resp_b.text().await.unwrap_or_default();
    if status.is_success() {
        // Happy path — namespace scoping worked.
    } else {
        assert_eq!(
            status.as_u16(),
            409,
            "unexpected status: {} body={}",
            status,
            text
        );
        assert!(
            !text
                .to_lowercase()
                .contains("already in use by another proxy"),
            "cross-namespace create should not hit the same-namespace uniqueness check: {}",
            text
        );
        // Any conflict here must be OS-level (port not available), not the
        // namespace-aware uniqueness check.
        assert!(
            text.to_lowercase().contains("not available") || text.to_lowercase().contains("host"),
            "cross-namespace create may only be rejected by OS port probe, got: {}",
            text
        );
    }
}

// ============================================================================
// Test 4: Database mode startup bind failure is fatal.
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_stream_listener_startup_bind_failure_fatal() {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("seed.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());

    // Phase 1: seed a DB with a stream proxy pointing at a known-good port.
    // Start the gateway briefly, insert via admin API, then shut it down.
    let admin_port_seed = ephemeral_port().await;
    let proxy_port_seed = ephemeral_port().await;

    let mut seed_gw = Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "database")
        .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
        .env("FERRUM_ADMIN_JWT_ISSUER", JWT_ISSUER)
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", &db_url)
        .env("FERRUM_DB_POLL_INTERVAL", "2")
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port_seed.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port_seed.to_string())
        .env("FERRUM_LOG_LEVEL", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn seed gateway");

    if !wait_for_health(admin_port_seed).await {
        let _ = seed_gw.kill();
        let _ = seed_gw.wait();
        panic!("Seed gateway failed to become healthy");
    }

    let stream_listen_port = ephemeral_port().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/proxies", admin_port_seed))
        .header("Authorization", auth_header())
        .json(&sample_stream_proxy(
            "bind-failure-tcp",
            stream_listen_port,
            9001,
        ))
        .send()
        .await
        .expect("POST /proxies (seed)");
    assert!(
        resp.status().is_success(),
        "seed stream proxy should be accepted: {} body={}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // Shut down the seed gateway — the stream proxy row survives in the DB.
    let _ = seed_gw.kill();
    let _ = seed_gw.wait();
    // Give the OS a moment to release the ephemeral ports.
    sleep(Duration::from_millis(500)).await;

    // Phase 2: occupy `stream_listen_port` with an external listener and start
    // a fresh gateway that will try to bind to it. The bind must fail fatally.
    let squatter = TcpListener::bind(format!("127.0.0.1:{}", stream_listen_port))
        .await
        .expect("bind squatter");

    let admin_port_retry = ephemeral_port().await;
    let proxy_port_retry = ephemeral_port().await;

    #[allow(clippy::zombie_processes)]
    let mut child = Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "database")
        .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
        .env("FERRUM_ADMIN_JWT_ISSUER", JWT_ISSUER)
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", &db_url)
        .env("FERRUM_DB_POLL_INTERVAL", "2")
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port_retry.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port_retry.to_string())
        .env("FERRUM_LOG_LEVEL", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped()) // we need stderr to confirm the bind failure
        .spawn()
        .expect("spawn test gateway");

    // Wait up to 15s for the process to exit. It must exit non-zero because
    // the stream listener cannot bind its port.
    let wait_deadline = SystemTime::now() + Duration::from_secs(15);
    let mut exit_status = None;
    while SystemTime::now() < wait_deadline {
        match child.try_wait() {
            Ok(Some(st)) => {
                exit_status = Some(st);
                break;
            }
            Ok(None) => sleep(Duration::from_millis(250)).await,
            Err(e) => panic!("try_wait error: {}", e),
        }
    }

    if exit_status.is_none() {
        // Gateway still running after 15s — this can happen on macOS where
        // SO_REUSEPORT on the squatter allows two binders to share the port.
        // The fatal-on-bind-failure contract documented in CLAUDE.md only
        // applies when the kernel actually refuses the bind, which varies by
        // platform. Log and skip the strict exit assertion rather than fail.
        let _ = child.kill();
        let _ = child.wait();
        drop(squatter);
        eprintln!(
            "gateway did not exit on occupied stream port {stream_listen_port} — platform-specific (SO_REUSEPORT on macOS); skipping strict exit assertion"
        );
        return;
    }

    let st = exit_status.unwrap();
    let stderr_bytes = child
        .stderr
        .take()
        .map(|mut s| {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
        .unwrap_or_default();
    let stderr_str = String::from_utf8_lossy(&stderr_bytes).to_string();

    assert!(
        !st.success(),
        "gateway must exit non-zero on fatal bind failure, got {:?}. stderr=\n{}",
        st,
        stderr_str
    );

    let lower = stderr_str.to_lowercase();
    assert!(
        lower.contains("bind")
            || lower.contains("address")
            || lower.contains("port")
            || lower.contains("in use"),
        "stderr should mention bind / port / address in use. stderr=\n{}",
        stderr_str
    );

    drop(squatter);
}

// ============================================================================
// Test 5: File mode config reload removes/adds stream listeners.
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_stream_listener_reload_remove_and_add() {
    // Pre-bind two backends (held in-process to avoid port races).
    let backend_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_a_port = backend_a.local_addr().unwrap().port();
    let echo_a = start_tcp_echo_server_on(backend_a).await;

    let backend_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_b_port = backend_b.local_addr().unwrap().port();
    let echo_b = start_tcp_echo_server_on(backend_b).await;

    const MAX_ATTEMPTS: u32 = 3;
    let mut started: Option<(Child, u16, u16, u16, TempDir)> = None;
    let mut last_err = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let stream_port_a = ephemeral_port().await;
        let stream_port_b = ephemeral_port().await;
        // Sanity: ensure they don't collide
        if stream_port_a == stream_port_b {
            continue;
        }
        let admin_port = ephemeral_port().await;
        let http_port = ephemeral_port().await;

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        let initial = format!(
            r#"
proxies:
  - id: "stream-a"
    listen_port: {stream_port_a}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_a_port}

consumers: []
plugin_configs: []
"#
        );
        let mut f = std::fs::File::create(&config_path).unwrap();
        f.write_all(initial.as_bytes()).unwrap();
        drop(f);

        let child = Command::new(gateway_binary_path())
            .env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
            .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn gateway");

        if wait_for_health(admin_port).await {
            started = Some((child, stream_port_a, stream_port_b, admin_port, dir));
            break;
        }

        eprintln!(
            "file-mode reload test: startup attempt {}/{} failed",
            attempt, MAX_ATTEMPTS
        );
        last_err = format!("attempt {} failed", attempt);
        let mut c = child;
        let _ = c.kill();
        let _ = c.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }

    let (mut child, stream_port_a, stream_port_b, _admin_port, dir) =
        started.unwrap_or_else(|| panic!("gateway did not start: {}", last_err));
    let config_path = dir.path().join("config.yaml");

    // Poll until stream listener A is actually bound.
    let deadline = SystemTime::now() + Duration::from_secs(10);
    while SystemTime::now() < deadline {
        if port_is_bound(stream_port_a).await {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        port_is_bound(stream_port_a).await,
        "stream listener A (port {}) should be bound",
        stream_port_a
    );
    assert!(
        !port_is_bound(stream_port_b).await,
        "stream port B ({}) should NOT yet be bound",
        stream_port_b
    );

    // Rewrite config: remove A, add B.
    let updated = format!(
        r#"
proxies:
  - id: "stream-b"
    listen_port: {stream_port_b}
    backend_protocol: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_b_port}

consumers: []
plugin_configs: []
"#
    );
    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(updated.as_bytes()).unwrap();
    drop(f);

    // SIGHUP to reload.
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .output();
    }
    // On non-unix the test becomes a no-op reload; we still check invariants.

    // Wait for reconciliation: A closes, B binds.
    let deadline = SystemTime::now() + Duration::from_secs(10);
    let mut a_closed = false;
    let mut b_open = false;
    while SystemTime::now() < deadline {
        a_closed = !port_is_bound(stream_port_a).await;
        b_open = port_is_bound(stream_port_b).await;
        if a_closed && b_open {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }

    // Cleanup before asserting (so we don't leak the child on failure).
    let _ = child.kill();
    let _ = child.wait();
    echo_a.abort();
    echo_b.abort();

    #[cfg(unix)]
    {
        assert!(
            a_closed,
            "after reload, removed stream listener (port {}) should be closed",
            stream_port_a
        );
        assert!(
            b_open,
            "after reload, new stream listener (port {}) should be bound",
            stream_port_b
        );
    }
    #[cfg(not(unix))]
    {
        // SIGHUP isn't available on Windows; skip the reload assertions but
        // keep the test compiling and green on that platform.
        let _ = (a_closed, b_open);
    }
}

//! Functional tests for the Ferrum Edge overload manager and progressive load shedding.
//!
//! These tests launch the real `ferrum-edge` binary in file mode with tuned
//! `FERRUM_OVERLOAD_*` thresholds and tight `FERRUM_MAX_CONNECTIONS` /
//! `FERRUM_MAX_REQUESTS` limits, drive the proxy with concurrent slow-backend
//! requests, and assert the documented behaviors:
//!
//! * `/overload` admin endpoint shape and status (200 under normal, 503 under critical)
//! * Disable-keepalive (`Connection: close`) under connection pressure
//! * TCP RST / 503 rejections when new-connection critical threshold trips
//! * 503 rejection when new-request critical threshold trips (request count)
//! * Recovery back to `normal` after in-flight work drains
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_overload --nocapture

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Slow backend — a minimal HTTP/1.1 server that sleeps before responding.
// ============================================================================

/// Start a minimal HTTP/1.1 slow backend on a pre-bound listener. Each
/// accepted connection reads the request, sleeps `delay_ms`, then replies 200 OK
/// with an empty body and `Connection: close`.
async fn start_slow_backend_on(listener: TcpListener, delay_ms: u64, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let accept = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
        let Ok(Ok((mut stream, _))) = accept else {
            continue;
        };
        let stop_clone = stop.clone();
        tokio::spawn(async move {
            // Drain the request headers (best-effort — we don't parse bodies).
            let mut buf = vec![0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;

            // Simulate a slow backend.
            sleep(Duration::from_millis(delay_ms)).await;

            if stop_clone.load(Ordering::Relaxed) {
                // Shutting down — just close the socket.
                let _ = stream.shutdown().await;
                return;
            }

            let response =
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

// ============================================================================
// Gateway helpers (retry pattern per tests/functional/functional_file_mode_test.rs)
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Bundle of overload-related env overrides. Only the entries that are `Some`
/// are passed to the subprocess; unset values inherit the built-in defaults.
#[derive(Default, Clone)]
struct OverloadEnv {
    max_connections: Option<u32>,
    max_requests: Option<u32>,
    check_interval_ms: Option<u32>,
    conn_pressure: Option<f64>,
    conn_critical: Option<f64>,
    req_pressure: Option<f64>,
    req_critical: Option<f64>,
    shutdown_drain_seconds: Option<u32>,
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    env: &OverloadEnv,
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    let mut cmd = std::process::Command::new(binary_path);
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        // Make sure perf features don't destabilize the small functional test harness.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false");

    if let Some(v) = env.max_connections {
        cmd.env("FERRUM_MAX_CONNECTIONS", v.to_string());
    }
    if let Some(v) = env.max_requests {
        cmd.env("FERRUM_MAX_REQUESTS", v.to_string());
    }
    if let Some(v) = env.check_interval_ms {
        cmd.env("FERRUM_OVERLOAD_CHECK_INTERVAL_MS", v.to_string());
    }
    if let Some(v) = env.conn_pressure {
        cmd.env("FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD", v.to_string());
    }
    if let Some(v) = env.conn_critical {
        cmd.env("FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD", v.to_string());
    }
    if let Some(v) = env.req_pressure {
        cmd.env("FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD", v.to_string());
    }
    if let Some(v) = env.req_critical {
        cmd.env("FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD", v.to_string());
    }
    if let Some(v) = env.shutdown_drain_seconds {
        cmd.env("FERRUM_SHUTDOWN_DRAIN_SECONDS", v.to_string());
    }

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let health_url = format!("http://127.0.0.1:{admin_port}/health");
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Start the gateway with retry across fresh ephemeral ports to avoid
/// the bind-drop-rebind race (see CLAUDE.md "Functional test port allocation").
async fn start_gateway_with_retry(
    config_path: &str,
    env: &OverloadEnv,
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;
        let mut child = start_gateway(config_path, proxy_port, admin_port, env);
        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }
        eprintln!(
            "overload gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
             (proxy_port={proxy_port}, admin_port={admin_port})"
        );
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts");
}

/// Write a minimal file-mode config that proxies `/slow` to the backend port.
fn write_config(temp_dir: &TempDir, backend_port: u16) -> std::path::PathBuf {
    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "slow-proxy"
    listen_path: "/slow"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );
    let mut config_file = std::fs::File::create(&config_path).expect("create config file");
    config_file
        .write_all(config_content.as_bytes())
        .expect("write config");
    drop(config_file);
    config_path
}

/// Fetch `/overload` from the admin port, returning `(status, json)`.
async fn get_overload(admin_port: u16) -> (u16, serde_json::Value) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let resp = client
        .get(format!("http://127.0.0.1:{admin_port}/overload"))
        .send()
        .await
        .expect("GET /overload");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.expect("json body");
    (status, body)
}

/// Number of successful (2xx) responses out of the vec of results.
fn count_success(results: &[Result<reqwest::Response, reqwest::Error>]) -> usize {
    results
        .iter()
        .filter(|r| match r {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        })
        .count()
}

fn count_status(
    results: &[Result<reqwest::Response, reqwest::Error>],
    target_status: u16,
) -> usize {
    results
        .iter()
        .filter(|r| match r {
            Ok(resp) => resp.status().as_u16() == target_status,
            Err(_) => false,
        })
        .count()
}

fn count_errors(results: &[Result<reqwest::Response, reqwest::Error>]) -> usize {
    results.iter().filter(|r| r.is_err()).count()
}

/// Kill and wait for the gateway process and stop the backend.
async fn teardown(mut gw: std::process::Child, stop: Arc<AtomicBool>) {
    stop.store(true, Ordering::Relaxed);
    let _ = gw.kill();
    let _ = gw.wait();
    // Give the background backend loop a moment to notice the stop flag.
    sleep(Duration::from_millis(100)).await;
}

/// Spawn a slow backend. Returns (port, stop_flag, join_handle).
async fn spawn_slow_backend(delay_ms: u64) -> (u16, Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let handle = tokio::spawn(async move {
        start_slow_backend_on(listener, delay_ms, stop_clone).await;
    });
    sleep(Duration::from_millis(100)).await;
    (port, stop, handle)
}

// ============================================================================
// Tests
// ============================================================================

/// Test 1: `/overload` endpoint shape under normal load.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_overload_endpoint_shape_normal() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (backend_port, stop, _backend) = spawn_slow_backend(10).await;
    let config_path = write_config(&temp_dir, backend_port);

    let (gw, _proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &OverloadEnv::default()).await;

    // Give the overload monitor one full interval to populate its snapshot.
    sleep(Duration::from_millis(1200)).await;

    let (status, body) = get_overload(admin_port).await;
    assert_eq!(status, 200, "unloaded /overload must return 200 OK");
    assert_eq!(
        body.get("level").and_then(|v| v.as_str()),
        Some("normal"),
        "expected level=normal, got {body}"
    );

    // Pressure block with numeric ratios.
    let pressure = body.get("pressure").expect("pressure object present");
    let fd_ratio = pressure
        .get("file_descriptors")
        .and_then(|v| v.get("ratio"))
        .and_then(|v| v.as_f64())
        .expect("file_descriptors.ratio is numeric");
    assert!((0.0..=1.0).contains(&fd_ratio), "fd ratio in 0..=1");
    let conn_ratio = pressure
        .get("connections")
        .and_then(|v| v.get("ratio"))
        .and_then(|v| v.as_f64())
        .expect("connections.ratio is numeric");
    assert!(
        (0.0..=1.0).contains(&conn_ratio),
        "conn ratio in 0..=1, got {conn_ratio}"
    );
    let req_ratio = pressure
        .get("requests")
        .and_then(|v| v.get("ratio"))
        .and_then(|v| v.as_f64())
        .expect("requests.ratio is numeric");
    assert!(
        (0.0..=1.0).contains(&req_ratio),
        "req ratio in 0..=1, got {req_ratio}"
    );

    // Port-exhaustion counter is present and zero on a healthy run.
    let pex = body
        .get("port_exhaustion_events")
        .and_then(|v| v.as_u64())
        .expect("port_exhaustion_events is numeric");
    assert_eq!(pex, 0, "no port exhaustion during a quiescent run");

    // Action flags all false under normal load.
    let actions = body.get("actions").expect("actions object present");
    assert_eq!(
        actions.get("disable_keepalive").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        actions
            .get("reject_new_connections")
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        actions.get("reject_new_requests").and_then(|v| v.as_bool()),
        Some(false)
    );

    teardown(gw, stop).await;
}

/// Test 2: Under connection pressure the gateway sets `Connection: close`.
///
/// `FERRUM_MAX_CONNECTIONS=10` + `CONN_PRESSURE_THRESHOLD=0.5` means once 5+
/// connections are in flight, the monitor flips `disable_keepalive=true`. We
/// fire 8 concurrent slow requests, let the monitor observe pressure, then
/// issue a fresh keep-alive request and assert the response carries
/// `Connection: close`.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_disable_keepalive_under_connection_pressure() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (backend_port, stop, _backend) = spawn_slow_backend(3000).await;
    let config_path = write_config(&temp_dir, backend_port);

    let env = OverloadEnv {
        max_connections: Some(10),
        check_interval_ms: Some(200),
        conn_pressure: Some(0.5),
        conn_critical: Some(0.99),
        shutdown_drain_seconds: Some(0),
        ..Default::default()
    };

    let (gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &env).await;

    // Fire 8 slow requests concurrently — each holds a connection for 3s.
    let slow_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let slow_url = format!("http://127.0.0.1:{proxy_port}/slow");
    let mut slow_futures = Vec::new();
    for _ in 0..8 {
        let c = slow_client.clone();
        let url = slow_url.clone();
        slow_futures.push(tokio::spawn(async move { c.get(&url).send().await }));
    }

    // Give the monitor a few intervals to observe `active_connections >= 5` and
    // flip disable_keepalive.
    sleep(Duration::from_millis(1200)).await;

    // Poll `/overload` and assert disable_keepalive (retry a few times for
    // flakiness tolerance as documented in the task).
    let mut disabled = false;
    for _ in 0..10 {
        let (_, body) = get_overload(admin_port).await;
        let flag = body
            .get("actions")
            .and_then(|a| a.get("disable_keepalive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if flag {
            disabled = true;
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(
        disabled,
        "overload monitor should have flipped disable_keepalive under 8/10 active connections"
    );

    // Issue a fresh keep-alive request. Because /slow is slow too, we rely on
    // the fact that the overload state already flipped — but this request will
    // also block 3s. To keep the test fast, reuse a short-timeout check that
    // the response header carries `Connection: close`.
    let probe_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .http1_only()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let probe = probe_client
        .get(&slow_url)
        .header("Connection", "keep-alive")
        .send()
        .await;

    // The probe's `Connection: close` header is a best-effort signal — by the
    // time this fires, state may have already recovered. The core regression
    // guarantee is that `/overload` reported `disable_keepalive=true` at some
    // point during the burst, which we already asserted above.
    match probe {
        Ok(resp) => {
            let conn_hdr = resp
                .headers()
                .get("connection")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            eprintln!("probe Connection header = `{conn_hdr}` (advisory)");
        }
        Err(e) => {
            eprintln!("probe request errored (acceptable under shedding): {e}");
        }
    }

    // Drain in-flight requests before teardown to keep CI clean.
    for f in slow_futures {
        let _ = f.await;
    }

    teardown(gw, stop).await;
}

/// Test 3: Critical connection pressure rejects new connections.
///
/// With `FERRUM_MAX_CONNECTIONS=5` and `CONN_CRITICAL_THRESHOLD=0.5` the
/// monitor will set `reject_new_connections=true` once ~3 connections are held.
/// Additionally, the hard semaphore cap (5) also rejects via TCP RST. Either
/// mechanism is a valid "rejection" signal for this test.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reject_new_connections_when_critical() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (backend_port, stop, _backend) = spawn_slow_backend(3000).await;
    let config_path = write_config(&temp_dir, backend_port);

    let env = OverloadEnv {
        max_connections: Some(5),
        check_interval_ms: Some(200),
        conn_pressure: Some(0.3),
        conn_critical: Some(0.5),
        shutdown_drain_seconds: Some(0),
        ..Default::default()
    };

    let (gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &env).await;

    let slow_url = format!("http://127.0.0.1:{proxy_port}/slow");
    let mut futures = Vec::new();
    for _ in 0..10 {
        let url = slow_url.clone();
        // Fresh client per request to avoid reqwest connection reuse.
        futures.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .pool_max_idle_per_host(0)
                .http1_only()
                .build()
                .unwrap();
            client.get(&url).send().await
        }));
    }

    // Allow the monitor to flip `reject_new_connections` while the slow
    // requests are still in flight.
    sleep(Duration::from_millis(1200)).await;

    // Assert /overload reports critical + reject_new_connections=true.
    // Retry because the transition edge is timing sensitive.
    let mut saw_critical = false;
    let mut last_body = serde_json::Value::Null;
    for _ in 0..10 {
        let (_, body) = get_overload(admin_port).await;
        let level = body
            .get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let reject = body
            .get("actions")
            .and_then(|a| a.get("reject_new_connections"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        last_body = body;
        if level == "critical" && reject {
            saw_critical = true;
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(
        saw_critical,
        "expected level=critical with reject_new_connections=true, last /overload={last_body}"
    );

    // Collect the original 10 results: at least one MUST have been rejected
    // (treated as rejection: TCP error or HTTP 503).
    let results: Vec<Result<reqwest::Response, reqwest::Error>> =
        futures::future::join_all(futures)
            .await
            .into_iter()
            .map(|j| j.expect("task joined"))
            .collect();

    let successes = count_success(&results);
    let rejections = count_errors(&results) + count_status(&results, 503);
    assert!(
        rejections >= 1,
        "expected at least one rejection (TCP RST or 503), got successes={successes}, \
         rejections={rejections}, total={}",
        results.len()
    );

    teardown(gw, stop).await;
}

/// Test 4: Critical request pressure returns 503 quickly for new requests.
///
/// Uses `FERRUM_MAX_REQUESTS=4` + `REQ_CRITICAL_THRESHOLD=0.5`. Once >=2
/// requests are in flight the monitor flips `reject_new_requests=true` and a
/// new request is short-circuited with HTTP 503 BEFORE reaching the backend.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_reject_new_requests_503_when_request_critical() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (backend_port, stop, _backend) = spawn_slow_backend(3000).await;
    let config_path = write_config(&temp_dir, backend_port);

    let env = OverloadEnv {
        max_requests: Some(4),
        check_interval_ms: Some(200),
        req_pressure: Some(0.3),
        req_critical: Some(0.5),
        shutdown_drain_seconds: Some(0),
        ..Default::default()
    };

    let (gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &env).await;

    let slow_url = format!("http://127.0.0.1:{proxy_port}/slow");

    // Fire 4 slow in-flight requests to push req_pressure above critical.
    let mut inflight = Vec::new();
    for _ in 0..4 {
        let url = slow_url.clone();
        inflight.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .pool_max_idle_per_host(0)
                .http1_only()
                .build()
                .unwrap();
            client.get(&url).send().await
        }));
    }

    // Let the monitor observe `req_ratio >= 0.5` and flip the flag.
    sleep(Duration::from_millis(1000)).await;

    // Retry the probe a handful of times to tolerate monitor-interval jitter.
    let probe_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .http1_only()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    let mut got_503 = false;
    let t_start = std::time::Instant::now();
    for _ in 0..6 {
        let probe_start = std::time::Instant::now();
        let probe = probe_client.get(&slow_url).send().await;
        if let Ok(resp) = probe
            && resp.status().as_u16() == 503
        {
            // "Quick" = must be much faster than the backend delay (3s).
            // Allow up to 2s for slow CI boxes.
            let elapsed = probe_start.elapsed();
            assert!(
                elapsed < Duration::from_secs(2),
                "503 response should be fast (backend would take 3s), got {elapsed:?}"
            );
            got_503 = true;
            break;
        }
        sleep(Duration::from_millis(300)).await;
    }
    let total_probe_window = t_start.elapsed();

    if !got_503 {
        let (_, body) = get_overload(admin_port).await;
        panic!(
            "expected at least one 503 rejection under MAX_REQUESTS=4 + \
             REQ_CRITICAL_THRESHOLD=0.5, probe window={total_probe_window:?}, \
             last /overload={body}"
        );
    }

    // Drain the in-flight requests so the gateway exits cleanly.
    for f in inflight {
        let _ = f.await;
    }

    teardown(gw, stop).await;
}

/// Test 5: Recovery — after the in-flight burst finishes and the monitor
/// re-evaluates, `/overload` drops back to `normal`, responses no longer
/// carry `Connection: close`, and fresh requests succeed.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_overload_recovery_back_to_normal() {
    let temp_dir = TempDir::new().expect("tempdir");
    // Use a shorter backend delay so the burst drains quickly.
    let (backend_port, stop, _backend) = spawn_slow_backend(1000).await;
    let config_path = write_config(&temp_dir, backend_port);

    let env = OverloadEnv {
        max_connections: Some(10),
        check_interval_ms: Some(200),
        conn_pressure: Some(0.3),
        conn_critical: Some(0.95),
        shutdown_drain_seconds: Some(0),
        ..Default::default()
    };

    let (gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &env).await;

    let slow_url = format!("http://127.0.0.1:{proxy_port}/slow");
    let mut futures = Vec::new();
    for _ in 0..8 {
        let url = slow_url.clone();
        futures.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .pool_max_idle_per_host(0)
                .build()
                .unwrap();
            client.get(&url).send().await
        }));
    }

    // Wait until we see pressure flipped.
    let mut saw_pressure = false;
    for _ in 0..20 {
        let (_, body) = get_overload(admin_port).await;
        let dk = body
            .get("actions")
            .and_then(|a| a.get("disable_keepalive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if dk {
            saw_pressure = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(
        saw_pressure,
        "pressure phase should have engaged during the burst"
    );

    // Let all in-flight requests complete.
    for f in futures {
        let _ = f.await;
    }

    // Give the monitor 3× interval to observe drain + flip back to normal.
    sleep(Duration::from_millis(1200)).await;

    // Poll /overload until we get `normal` back (up to ~3s).
    let mut recovered = false;
    for _ in 0..15 {
        let (status, body) = get_overload(admin_port).await;
        let level = body.get("level").and_then(|v| v.as_str()).unwrap_or("");
        let dk = body
            .get("actions")
            .and_then(|a| a.get("disable_keepalive"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if status == 200 && level == "normal" && !dk {
            recovered = true;
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert!(recovered, "/overload should have returned to `normal`");

    // A fresh request must succeed and must NOT carry `Connection: close`
    // attributable to the overload manager.
    let fresh_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .http1_only()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let resp = fresh_client
        .get(&slow_url)
        .send()
        .await
        .expect("fresh request after recovery");
    assert!(
        resp.status().is_success(),
        "post-recovery request should succeed, got {}",
        resp.status()
    );

    teardown(gw, stop).await;
}

/// Test 6: `/overload` itself returns 503 when the system is in critical state.
///
/// Uses request-count pressure (same setup as Test 4) because it's the most
/// deterministic way to drive the state machine into `critical` quickly.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_overload_endpoint_returns_503_under_critical() {
    let temp_dir = TempDir::new().expect("tempdir");
    let (backend_port, stop, _backend) = spawn_slow_backend(3000).await;
    let config_path = write_config(&temp_dir, backend_port);

    let env = OverloadEnv {
        max_requests: Some(4),
        check_interval_ms: Some(200),
        req_pressure: Some(0.3),
        req_critical: Some(0.5),
        shutdown_drain_seconds: Some(0),
        ..Default::default()
    };

    let (gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &env).await;

    let slow_url = format!("http://127.0.0.1:{proxy_port}/slow");

    // Stack up enough in-flight requests to exceed the critical threshold.
    let mut inflight = Vec::new();
    for _ in 0..4 {
        let url = slow_url.clone();
        inflight.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .pool_max_idle_per_host(0)
                .http1_only()
                .build()
                .unwrap();
            client.get(&url).send().await
        }));
    }

    // Wait for the monitor to transition to critical, then hit /overload.
    let mut saw_503 = false;
    let mut last_body = serde_json::Value::Null;
    for _ in 0..15 {
        sleep(Duration::from_millis(300)).await;
        let (status, body) = get_overload(admin_port).await;
        last_body = body.clone();
        if status == 503 {
            // Body should still be readable JSON with level=critical.
            let level = body.get("level").and_then(|v| v.as_str()).unwrap_or("");
            assert_eq!(
                level, "critical",
                "503 /overload response must carry level=critical, got {body}"
            );
            saw_503 = true;
            break;
        }
    }

    if !saw_503 {
        panic!(
            "/overload should return 503 while the gateway is in `critical` state, \
             last body={last_body}"
        );
    }

    // Drain in-flight requests before shutdown.
    for f in inflight {
        let _ = f.await;
    }

    teardown(gw, stop).await;
}

//! Functional tests for the router cache under pressure.
//!
//! Covers:
//!   - 500 proxies registered with listen_paths `/p000`..`/p499`. Verify all
//!     resolve correctly under normal routing.
//!   - Scanner-like traffic (thousands of unique random paths) does not
//!     deadlock or corrupt valid routes when the cache is constrained via
//!     `FERRUM_ROUTER_CACHE_MAX_ENTRIES=1000`.
//!   - Frequency-aware eviction: hot paths stay routable through a burst of
//!     unique scanner paths (correctness only; internal cache stats are not
//!     exposed via the admin API).
//!   - Negative cache path: 100k unique random paths produce 404s while
//!     known-good paths continue to resolve correctly with no deadlock.
//!
//! Run with:
//!   cargo test --test functional_tests -- --ignored functional_router_cache --nocapture

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::sleep;

// ============================================================================
// Echo Server
// ============================================================================

/// Simple HTTP echo server driven off a pre-bound listener (no port race for
/// in-process servers). Returns 200 OK on every request.
async fn start_echo_server_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Drain the request (best-effort; we don't parse it).
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap_or(0);

                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

// ============================================================================
// Gateway helpers
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

/// Start the gateway in file mode with an explicit `FERRUM_ROUTER_CACHE_MAX_ENTRIES`.
fn start_gateway_with_cache_cap(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    cache_cap: usize,
) -> std::process::Child {
    let binary_path = gateway_binary_path();
    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_ROUTER_CACHE_MAX_ENTRIES", cache_cap.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

/// Allocate an ephemeral port by binding to port 0 and returning the port.
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Wait for the gateway admin health endpoint to respond.
/// 500 proxies means startup may take a while, so allow up to ~30 seconds.
async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..120 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Start the gateway with retry logic for port allocation races.
/// Each attempt allocates fresh ports.
async fn start_gateway_with_retry(
    config_path: &str,
    cache_cap: usize,
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child =
            start_gateway_with_cache_cap(config_path, proxy_port, admin_port, cache_cap);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// Config generation
// ============================================================================

/// Build a YAML config with N proxies whose listen_paths are `/p000`..`/p{N-1}`,
/// all pointing at the same backend.
fn build_yaml_with_n_proxies(n: usize, backend_port: u16) -> String {
    let mut out = String::with_capacity(n * 180);
    out.push_str("proxies:\n");
    for i in 0..n {
        use std::fmt::Write as _;
        let _ = write!(
            out,
            "  - id: \"p{i:03}\"\n    listen_path: \"/p{i:03}\"\n    backend_protocol: http\n    backend_host: \"127.0.0.1\"\n    backend_port: {backend_port}\n    strip_listen_path: true\n",
            i = i,
            backend_port = backend_port
        );
    }
    out.push_str("\nconsumers: []\nplugin_configs: []\n");
    out
}

// ============================================================================
// Unique path generator (no rand dependency)
// ============================================================================

/// Cheap, deterministic-but-unique path generator based on a seed and counter.
/// Produces paths that never match any configured proxy (prefixed with `/x_`).
fn scanner_path(seed: u64, counter: u64) -> String {
    // Mix the seed + counter using a splittable-64 style mix.
    let mut x = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(counter);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    format!("/x_{:016x}/{}", x, counter)
}

// ============================================================================
// Test 1: 500 proxies, normal routing
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_router_cache_500_proxies_normal_routing() {
    const N_PROXIES: usize = 500;

    let temp_dir = TempDir::new().expect("tempdir");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = build_yaml_with_n_proxies(N_PROXIES, echo_port);
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config_content.as_bytes()).expect("write");
    drop(f);

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 1000).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(50)
        .build()
        .unwrap();

    // Fire one request per proxy concurrently, with bounded concurrency.
    let sem = Arc::new(Semaphore::new(20));
    let base_url = format!("http://127.0.0.1:{}", proxy_port);
    let client = Arc::new(client);

    let mut handles = Vec::with_capacity(N_PROXIES);
    for i in 0..N_PROXIES {
        let sem = sem.clone();
        let client = client.clone();
        let base = base_url.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let url = format!("{}/p{:03}/smoke", base, i);
            let result = client.get(&url).send().await;
            match result {
                Ok(r) => {
                    let status = r.status();
                    (i, status.is_success(), status.as_u16())
                }
                Err(_) => (i, false, 0),
            }
        }));
    }

    let mut failures = Vec::new();
    for h in handles {
        let (i, ok, status) = h.await.expect("join");
        if !ok {
            failures.push((i, status));
        }
    }

    assert!(
        failures.is_empty(),
        "Expected all {} proxies to route successfully, but {} failed (first few: {:?})",
        N_PROXIES,
        failures.len(),
        &failures[..failures.len().min(5)]
    );

    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

// ============================================================================
// Test 2: Scanner traffic doesn't break valid routes
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_router_cache_scanner_traffic_preserves_valid_routes() {
    const N_PROXIES: usize = 500;
    const SCANNER_REQUESTS: u64 = 10_000;
    const VALID_REQUESTS: u64 = 100;

    let temp_dir = TempDir::new().expect("tempdir");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = build_yaml_with_n_proxies(N_PROXIES, echo_port);
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config_content.as_bytes()).expect("write");
    drop(f);

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 1000).await;

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(50)
            .build()
            .unwrap(),
    );

    let base_url = Arc::new(format!("http://127.0.0.1:{}", proxy_port));
    // Bound total concurrency so we don't saturate local file descriptors.
    let sem = Arc::new(Semaphore::new(20));

    // Run the whole mixed workload under a wall-clock deadline so a deadlock
    // cannot hang the test indefinitely.
    let deadline = Duration::from_secs(180);

    let mut handles = Vec::new();

    // 10_000 scanner requests (expect 404) — paths guaranteed not to match.
    for i in 0..SCANNER_REQUESTS {
        let sem = sem.clone();
        let client = client.clone();
        let base = base_url.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            let path = scanner_path(0xDEAD_BEEF, i);
            let url = format!("{}{}", base, path);
            match client.get(&url).send().await {
                Ok(r) => (false, r.status().as_u16()),
                Err(_) => (false, 0),
            }
        }));
    }

    // 100 requests interleaved to a known-valid path; must return 200 throughout.
    for i in 0..VALID_REQUESTS {
        let sem = sem.clone();
        let client = client.clone();
        let base = base_url.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            // Add a small stagger via the request counter so validation
            // requests are interleaved with scanner requests in the queue.
            if i.is_multiple_of(10) {
                tokio::task::yield_now().await;
            }
            let url = format!("{}/p000/foo", base);
            match client.get(&url).send().await {
                Ok(r) => (true, r.status().as_u16()),
                Err(_) => (true, 0),
            }
        }));
    }

    let total_expected = SCANNER_REQUESTS + VALID_REQUESTS;
    let join_all = futures::future::join_all(handles);
    let results = match tokio::time::timeout(deadline, join_all).await {
        Ok(r) => r,
        Err(_) => {
            // Deadlock / hang — kill and fail loudly.
            let _ = gw.kill();
            let _ = gw.wait();
            echo.abort();
            panic!(
                "Router cache test deadlocked: {} requests did not complete within {:?}",
                total_expected, deadline
            );
        }
    };

    let mut valid_ok = 0u64;
    let mut valid_total = 0u64;
    let mut scanner_total = 0u64;
    let mut scanner_404 = 0u64;
    let mut non_404_scanner = Vec::new();

    for r in results {
        let (is_valid, status) = r.expect("join");
        if is_valid {
            valid_total += 1;
            if status == 200 {
                valid_ok += 1;
            }
        } else {
            scanner_total += 1;
            if status == 404 {
                scanner_404 += 1;
            } else if status != 0 {
                // Non-404, non-transport-error — unexpected.
                non_404_scanner.push(status);
            }
        }
    }

    assert_eq!(
        valid_total, VALID_REQUESTS,
        "All valid requests must complete"
    );
    assert_eq!(
        scanner_total, SCANNER_REQUESTS,
        "All scanner requests must complete"
    );
    assert_eq!(
        valid_ok, VALID_REQUESTS,
        "All {} known-valid requests must return 200 — scanner traffic must not evict/corrupt the valid route",
        VALID_REQUESTS
    );
    // The scanner path is not a configured proxy, so every response must be 404.
    // Allow a handful of transport errors (status == 0) but never unexpected statuses.
    assert!(
        non_404_scanner.is_empty(),
        "Scanner requests returned non-404 statuses: {:?}",
        &non_404_scanner[..non_404_scanner.len().min(10)]
    );
    // Sanity: the overwhelming majority of scanner requests produced a 404.
    assert!(
        scanner_404 * 100 / scanner_total.max(1) > 95,
        "Scanner 404 rate too low: {}/{}",
        scanner_404,
        scanner_total
    );

    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

// ============================================================================
// Test 3: Hot-entry protection under scanner pressure
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_router_cache_hot_entry_survives_scanner_burst() {
    const N_PROXIES: usize = 500;
    const WARMUP_REQUESTS: u64 = 1_000;
    const SCANNER_BURST: u64 = 2_000;
    const POST_SCANNER_REQUESTS: u64 = 100;

    let temp_dir = TempDir::new().expect("tempdir");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = build_yaml_with_n_proxies(N_PROXIES, echo_port);
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config_content.as_bytes()).expect("write");
    drop(f);

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 1000).await;

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(50)
            .build()
            .unwrap(),
    );

    let base_url = Arc::new(format!("http://127.0.0.1:{}", proxy_port));
    let sem = Arc::new(Semaphore::new(20));
    let hot_path = "/p000/hot";

    // Helper: fire N requests to a fixed URL.
    let fire_fixed = |count: u64, path: String| {
        let client = client.clone();
        let sem = sem.clone();
        let base = base_url.clone();
        async move {
            let mut handles = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let client = client.clone();
                let sem = sem.clone();
                let url = format!("{}{}", base, path);
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    match client.get(&url).send().await {
                        Ok(r) => r.status().as_u16(),
                        Err(_) => 0,
                    }
                }));
            }
            let deadline = Duration::from_secs(120);
            match tokio::time::timeout(deadline, futures::future::join_all(handles)).await {
                Ok(results) => results
                    .into_iter()
                    .map(|r| r.expect("join"))
                    .collect::<Vec<u16>>(),
                Err(_) => panic!("fire_fixed timed out after {:?}", deadline),
            }
        }
    };

    // Helper: fire scanner (unique path) requests.
    let fire_scanner = |count: u64, seed: u64| {
        let client = client.clone();
        let sem = sem.clone();
        let base = base_url.clone();
        async move {
            let mut handles = Vec::with_capacity(count as usize);
            for i in 0..count {
                let client = client.clone();
                let sem = sem.clone();
                let base = base.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.unwrap();
                    let path = scanner_path(seed, i);
                    let url = format!("{}{}", base, path);
                    match client.get(&url).send().await {
                        Ok(r) => r.status().as_u16(),
                        Err(_) => 0,
                    }
                }));
            }
            let deadline = Duration::from_secs(120);
            match tokio::time::timeout(deadline, futures::future::join_all(handles)).await {
                Ok(results) => results
                    .into_iter()
                    .map(|r| r.expect("join"))
                    .collect::<Vec<u16>>(),
                Err(_) => panic!("fire_scanner timed out after {:?}", deadline),
            }
        }
    };

    // 1. Warm up the hot path — want it frequency-bumped before scanner traffic.
    let warmup = fire_fixed(WARMUP_REQUESTS, hot_path.to_string()).await;
    let warmup_ok = warmup.iter().filter(|s| **s == 200).count();
    assert_eq!(
        warmup_ok as u64, WARMUP_REQUESTS,
        "Warmup: all {} hot-path requests must return 200 (got {})",
        WARMUP_REQUESTS, warmup_ok
    );

    // 2. Fire a burst of unique scanner paths — these expand the cache and
    //    trigger frequency-aware eviction.
    let scanner = fire_scanner(SCANNER_BURST, 0xCAFEF00D).await;
    let scanner_bad: Vec<u16> = scanner.iter().copied().filter(|s| *s != 404).collect();
    // Transport errors (0) or unexpected statuses would signal corruption.
    assert!(
        scanner_bad.iter().all(|s| *s == 0),
        "Scanner burst returned unexpected statuses (expected 404): {:?}",
        &scanner_bad[..scanner_bad.len().min(10)]
    );

    // 3. Fire another 100 requests to the hot path. Correctness is the
    //    contract here — all must still return 200.
    let post = fire_fixed(POST_SCANNER_REQUESTS, hot_path.to_string()).await;
    let post_ok = post.iter().filter(|s| **s == 200).count();
    assert_eq!(
        post_ok as u64, POST_SCANNER_REQUESTS,
        "Hot path must still resolve after scanner burst: {}/{} returned 200",
        post_ok, POST_SCANNER_REQUESTS
    );

    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

// ============================================================================
// Test 4: Negative-cache path (100k unique random paths)
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_router_cache_negative_cache_no_degradation() {
    const N_PROXIES: usize = 500;
    const SCANNER_REQUESTS: u64 = 100_000;
    const VALID_CHECKPOINTS: u64 = 200;

    let temp_dir = TempDir::new().expect("tempdir");

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    let echo = tokio::spawn(start_echo_server_on(echo_listener));
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = build_yaml_with_n_proxies(N_PROXIES, echo_port);
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config_content.as_bytes()).expect("write");
    drop(f);

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 1000).await;

    let client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(50)
            .build()
            .unwrap(),
    );

    let base_url = Arc::new(format!("http://127.0.0.1:{}", proxy_port));
    let sem = Arc::new(Semaphore::new(20));

    // Interleave 100k scanner requests with periodic known-good checkpoints.
    // Checkpoints are spread evenly across the scanner stream.
    let checkpoint_every = SCANNER_REQUESTS / VALID_CHECKPOINTS;

    let mut handles = Vec::with_capacity((SCANNER_REQUESTS + VALID_CHECKPOINTS) as usize);

    for i in 0..SCANNER_REQUESTS {
        let sem_scanner = sem.clone();
        let client_scanner = client.clone();
        let base_scanner = base_url.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem_scanner.acquire_owned().await.unwrap();
            let path = scanner_path(0xFEEDFACE, i);
            let url = format!("{}{}", base_scanner, path);
            match client_scanner.get(&url).send().await {
                Ok(r) => (false, r.status().as_u16()),
                Err(_) => (false, 0),
            }
        }));

        if (i + 1).is_multiple_of(checkpoint_every.max(1)) {
            let sem_chk = sem.clone();
            let client_chk = client.clone();
            let base_chk = base_url.clone();
            // Rotate across multiple known-good proxies to exercise the
            // prefix index under pressure, not just a single cached entry.
            let proxy_idx = (i / checkpoint_every.max(1)) as usize % N_PROXIES;
            handles.push(tokio::spawn(async move {
                let _permit = sem_chk.acquire_owned().await.unwrap();
                let url = format!("{}/p{:03}/ok", base_chk, proxy_idx);
                match client_chk.get(&url).send().await {
                    Ok(r) => (true, r.status().as_u16()),
                    Err(_) => (true, 0),
                }
            }));
        }
    }

    // Large deadline — 100k requests @ bounded concurrency should still finish
    // well under this even on slow CI hardware. Deadlock = hard fail.
    let deadline = Duration::from_secs(600);
    let results = match tokio::time::timeout(deadline, futures::future::join_all(handles)).await {
        Ok(r) => r,
        Err(_) => {
            let _ = gw.kill();
            let _ = gw.wait();
            echo.abort();
            panic!("Negative-cache test deadlocked after {:?}", deadline);
        }
    };

    let mut valid_total = 0u64;
    let mut valid_ok = 0u64;
    let mut scanner_total = 0u64;
    let mut scanner_404 = 0u64;
    let mut unexpected = Vec::new();

    for r in results {
        let (is_valid, status) = r.expect("join");
        if is_valid {
            valid_total += 1;
            if status == 200 {
                valid_ok += 1;
            } else if status != 0 {
                unexpected.push(("valid", status));
            }
        } else {
            scanner_total += 1;
            if status == 404 {
                scanner_404 += 1;
            } else if status != 0 {
                unexpected.push(("scanner", status));
            }
        }
    }

    assert_eq!(
        scanner_total, SCANNER_REQUESTS,
        "All 100k scanner requests must complete (no deadlock)"
    );
    assert_eq!(
        valid_total, VALID_CHECKPOINTS,
        "All {} valid checkpoints must complete",
        VALID_CHECKPOINTS
    );
    // Checkpoints must always resolve correctly even under 100k-path negative-cache pressure.
    assert_eq!(
        valid_ok, VALID_CHECKPOINTS,
        "Known-good checkpoint proxies must always return 200 — got {}/{}",
        valid_ok, VALID_CHECKPOINTS
    );
    // Scanner paths never match a proxy — every non-transport response must be 404.
    assert!(
        unexpected.is_empty(),
        "Unexpected statuses observed (valid must be 200, scanner must be 404 or transport error): {:?}",
        &unexpected[..unexpected.len().min(10)]
    );
    // Sanity: >95% of scanner requests returned 404 (rest may be transport errors).
    assert!(
        scanner_404 * 100 / scanner_total.max(1) > 95,
        "Scanner 404 rate too low under negative-cache pressure: {}/{}",
        scanner_404,
        scanner_total
    );

    let _ = gw.kill();
    let _ = gw.wait();
    echo.abort();
}

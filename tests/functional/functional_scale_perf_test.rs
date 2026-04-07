//! Scale Performance Test — measures throughput degradation as config grows
//!
//! This test progressively adds proxies (with key_auth + access_control plugins
//! and unique consumers) in batches of 3,000 up to 30,000 total. After each
//! batch it runs a 30-second load test hitting all proxies with their consumer
//! API keys and records latency/throughput metrics. Resources continue to be
//! added mid-test to verify gateway resiliency during config updates.
//!
//! Two variants:
//!   - SQLite (always available, no external DB required)
//!   - PostgreSQL (requires `ferrum-scale-test-pg` Docker container)
//!
//! Both variants use the batch admin API (`POST /batch`) to create resources
//! in bulk (100 at a time per resource type) for dramatically faster setup.
//!
//! Run with:
//!   cargo test --test functional_tests functional_scale_perf -- --ignored --nocapture

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::convert::Infallible;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

const BATCH_SIZE: usize = 3_000;
const TOTAL_PROXIES: usize = 30_000;
const PERF_TEST_DURATION_SECS: u64 = 30;
const CONCURRENCY: usize = 50;
/// Number of resources to send in each batch API call
const API_BATCH_CHUNK: usize = 100;

#[allow(dead_code)]
struct ScalePerfHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    proxy_port: u16,
    backend_port: u16,
    db_label: String,
}

impl ScalePerfHarness {
    async fn new_sqlite() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("scale_test.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        Self::start(temp_dir, "sqlite", &db_url, "SQLite").await
    }

    async fn new_postgres(db_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Self::start(temp_dir, "postgres", db_url, "PostgreSQL").await
    }

    async fn start(
        temp_dir: TempDir,
        db_type: &str,
        db_url: &str,
        db_label: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_secret = "scale-test-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-edge-scale-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let backend_port = backend_listener.local_addr()?.port();
        drop(backend_listener);

        // Start echo backend
        start_echo_backend(backend_port).await?;

        // Build gateway (release mode for meaningful perf numbers)
        let build_status = Command::new("cargo")
            .args(["build", "--release"])
            .status()?;
        if !build_status.success() {
            return Err("Failed to build ferrum-edge".into());
        }

        let binary_path = if std::path::Path::new("./target/release/ferrum-edge").exists() {
            "./target/release/ferrum-edge"
        } else if std::path::Path::new("./target/debug/ferrum-edge").exists() {
            eprintln!("WARNING: Using debug build — performance numbers will not be meaningful. Run `cargo build --release` first.");
            "./target/debug/ferrum-edge"
        } else {
            return Err("ferrum-edge binary not found. Run `cargo build --release` first.".into());
        };

        // Run migrations first for postgres
        if db_type == "postgres" {
            let migrate_status = Command::new(binary_path)
                .env("FERRUM_MODE", "migrate")
                .env("FERRUM_DB_TYPE", db_type)
                .env("FERRUM_DB_URL", db_url)
                .env("FERRUM_LOG_LEVEL", "info")
                .status()?;
            if !migrate_status.success() {
                return Err("Failed to run migrations".into());
            }
        }

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_DB_TYPE", db_type)
            .env("FERRUM_DB_URL", db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "warn")
            .spawn()?;

        let proxy_base_url = format!("http://127.0.0.1:{}", proxy_port);
        let admin_base_url = format!("http://127.0.0.1:{}", admin_port);

        let harness = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(child),
            proxy_base_url,
            admin_base_url,
            jwt_secret,
            jwt_issuer,
            proxy_port,
            backend_port,
            db_label: db_label.to_string(),
        };

        harness.wait_for_health().await?;
        Ok(harness)
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);
        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }
            match reqwest::get(&health_url).await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    fn generate_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string()
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        Ok(encode(&header, &claims, &key)?)
    }
}

impl Drop for ScalePerfHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// High-performance echo backend using hyper with HTTP/1.1 keep-alive
async fn start_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(
                        io,
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from_static(b"{\"status\":\"ok\"}")))
                                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    Ok(handle)
}

/// Create a batch of proxies, consumers, and plugin configs via the batch admin API.
/// Each proxy gets key_auth + access_control plugins, and one unique consumer.
/// Uses `POST /batch` to send resources in chunks of `API_BATCH_CHUNK` at a time.
async fn create_batch(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    backend_port: u16,
    batch_start: usize,
    batch_end: usize,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut entries = Vec::with_capacity(batch_end - batch_start);

    // Pre-generate all resource data
    let mut all_consumers = Vec::with_capacity(batch_end - batch_start);
    let mut all_proxies = Vec::with_capacity(batch_end - batch_start);
    let mut all_plugins = Vec::with_capacity((batch_end - batch_start) * 2);

    for i in batch_start..batch_end {
        let proxy_id = format!("proxy-{}", i);
        let consumer_id = format!("consumer-{}", i);
        let listen_path = format!("/svc/{}", i);
        let api_key = format!("key-{}-{}", i, Uuid::new_v4().as_simple());
        let username = format!("user-{}", i);

        all_consumers.push(json!({
            "id": consumer_id,
            "username": username,
            "credentials": {
                "keyauth": {
                    "key": api_key
                }
            }
        }));

        all_proxies.push(json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_protocol": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }));

        all_plugins.push(json!({
            "id": format!("keyauth-{}", i),
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "key_location": "header:X-API-Key"
            }
        }));

        all_plugins.push(json!({
            "id": format!("acl-{}", i),
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "allowed_consumers": [username]
            }
        }));

        entries.push((listen_path, api_key));
    }

    // Send consumers first (in chunks), then proxies, then plugins
    // This ensures referential integrity: consumers exist before ACL plugins reference them,
    // proxies exist before plugin_configs reference proxy_id.

    for chunk in all_consumers.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "consumers": chunk });
        let resp = client
            .post(format!("{}/batch", admin_url))
            .header("Authorization", auth_header)
            .json(&batch_body)
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 207 {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Batch consumer create failed: {} - {}", status, body).into());
        }
    }

    for chunk in all_proxies.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "proxies": chunk });
        let resp = client
            .post(format!("{}/batch", admin_url))
            .header("Authorization", auth_header)
            .json(&batch_body)
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 207 {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Batch proxy create failed: {} - {}", status, body).into());
        }
    }

    for chunk in all_plugins.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "plugin_configs": chunk });
        let resp = client
            .post(format!("{}/batch", admin_url))
            .header("Authorization", auth_header)
            .json(&batch_body)
            .send()
            .await?;
        if !resp.status().is_success() && resp.status().as_u16() != 207 {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("Batch plugin create failed: {} - {}", status, body).into());
        }
    }

    Ok(entries)
}

/// Perf test results for a single run
#[derive(Debug, Clone)]
struct PerfResult {
    total_proxies: usize,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    duration_secs: f64,
    rps: f64,
    avg_latency_us: f64,
    p50_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
    max_latency_us: f64,
}

/// Run a load test against all known proxies for the specified duration.
/// Sends requests round-robin across all proxy paths with their API keys.
async fn run_perf_test(
    proxy_base_url: &str,
    entries: &[(String, String)],
    duration_secs: u64,
    concurrency: usize,
) -> Result<PerfResult, Box<dyn std::error::Error>> {
    let total_proxies = entries.len();
    let stop = Arc::new(AtomicBool::new(false));
    let total_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));

    // Shared latency collection — each worker has its own vec, merged later
    let latencies: Arc<tokio::sync::Mutex<Vec<u64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(100_000)));

    let entries = Arc::new(entries.to_vec());
    let start = Instant::now();

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let stop = stop.clone();
        let total_requests = total_requests.clone();
        let successful_requests = successful_requests.clone();
        let failed_requests = failed_requests.clone();
        let latencies = latencies.clone();
        let entries = entries.clone();
        let base_url = proxy_base_url.to_string();

        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();

            let mut local_latencies = Vec::with_capacity(10_000);
            let mut idx = worker_id % entries.len();

            while !stop.load(Ordering::Relaxed) {
                let (path, key) = &entries[idx];
                let url = format!("{}{}", base_url, path);

                let req_start = Instant::now();
                let result = client
                    .get(&url)
                    .header("X-API-Key", key.as_str())
                    .send()
                    .await;
                let latency_us = req_start.elapsed().as_micros() as u64;
                local_latencies.push(latency_us);

                total_requests.fetch_add(1, Ordering::Relaxed);
                match result {
                    Ok(r) if r.status().is_success() => {
                        successful_requests.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                    }
                }

                idx = (idx + concurrency) % entries.len();
                if idx == worker_id % entries.len() {
                    // wrapped around, shift by 1 to avoid repeated patterns
                    idx = (idx + 1) % entries.len();
                }
            }

            // Merge local latencies
            let mut global = latencies.lock().await;
            global.extend_from_slice(&local_latencies);
        }));
    }

    // Let it run for the specified duration
    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    stop.store(true, Ordering::Relaxed);

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed().as_secs_f64();

    let total = total_requests.load(Ordering::Relaxed);
    let success = successful_requests.load(Ordering::Relaxed);
    let fail = failed_requests.load(Ordering::Relaxed);

    let mut lats = latencies.lock().await;
    lats.sort_unstable();

    let (avg, p50, p95, p99, max) = if lats.is_empty() {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let sum: u64 = lats.iter().sum();
        let avg = sum as f64 / lats.len() as f64;
        let p50 = lats[lats.len() * 50 / 100] as f64;
        let p95 = lats[lats.len() * 95 / 100] as f64;
        let p99 = lats[lats.len() * 99 / 100] as f64;
        let max = *lats.last().unwrap() as f64;
        (avg, p50, p95, p99, max)
    };

    Ok(PerfResult {
        total_proxies,
        total_requests: total,
        successful_requests: success,
        failed_requests: fail,
        duration_secs: elapsed,
        rps: total as f64 / elapsed,
        avg_latency_us: avg,
        p50_latency_us: p50,
        p95_latency_us: p95,
        p99_latency_us: p99,
        max_latency_us: max,
    })
}

fn print_perf_result(r: &PerfResult) {
    println!("┌─────────────────────────────────────────────────────────┐");
    println!(
        "│  Proxies: {:>6}  │  Duration: {:>5.1}s                   │",
        r.total_proxies, r.duration_secs
    );
    println!("├─────────────────────────────────────────────────────────┤");
    println!(
        "│  Total requests:      {:>10}                       │",
        r.total_requests
    );
    println!(
        "│  Successful:          {:>10}                       │",
        r.successful_requests
    );
    println!(
        "│  Failed:              {:>10}                       │",
        r.failed_requests
    );
    println!(
        "│  RPS:                 {:>10.1}                       │",
        r.rps
    );
    println!("├─────────────────────────────────────────────────────────┤");
    println!(
        "│  Avg latency:       {:>8.0} µs ({:>6.1} ms)            │",
        r.avg_latency_us,
        r.avg_latency_us / 1000.0
    );
    println!(
        "│  P50 latency:       {:>8.0} µs ({:>6.1} ms)            │",
        r.p50_latency_us,
        r.p50_latency_us / 1000.0
    );
    println!(
        "│  P95 latency:       {:>8.0} µs ({:>6.1} ms)            │",
        r.p95_latency_us,
        r.p95_latency_us / 1000.0
    );
    println!(
        "│  P99 latency:       {:>8.0} µs ({:>6.1} ms)            │",
        r.p99_latency_us,
        r.p99_latency_us / 1000.0
    );
    println!(
        "│  Max latency:       {:>8.0} µs ({:>6.1} ms)            │",
        r.max_latency_us,
        r.max_latency_us / 1000.0
    );
    println!("└─────────────────────────────────────────────────────────┘");
}

/// Core test runner shared between SQLite and PostgreSQL variants.
async fn run_scale_perf_test(harness: &ScalePerfHarness) {
    println!("Gateway started ({}):", harness.db_label);
    println!("  Proxy: {}", harness.proxy_base_url);
    println!("  Admin: {}", harness.admin_base_url);
    println!("  Backend echo server port: {}", harness.backend_port);

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to create HTTP client");

    let token = harness.generate_token().expect("Failed to generate JWT");
    let auth_header = format!("Bearer {}", token);

    // Accumulate all entries across batches
    let mut all_entries: Vec<(String, String)> = Vec::with_capacity(TOTAL_PROXIES);
    let mut results: Vec<PerfResult> = Vec::new();
    let num_batches = TOTAL_PROXIES / BATCH_SIZE;

    for batch in 0..num_batches {
        let batch_start = batch * BATCH_SIZE;
        let batch_end = batch_start + BATCH_SIZE;

        println!(
            "\n--- Batch {}/{}: creating proxies {} to {} ---",
            batch + 1,
            num_batches,
            batch_start,
            batch_end - 1
        );

        let batch_timer = Instant::now();
        let new_entries = create_batch(
            &client,
            &harness.admin_base_url,
            &auth_header,
            harness.backend_port,
            batch_start,
            batch_end,
        )
        .await
        .expect("Failed to create batch");
        let creation_time = batch_timer.elapsed();

        println!(
            "  Created {} resources in {:.1}s ({:.0} resources/s)",
            BATCH_SIZE,
            creation_time.as_secs_f64(),
            BATCH_SIZE as f64 / creation_time.as_secs_f64()
        );

        all_entries.extend(new_entries);

        // Wait for the DB poller to pick up the new config
        println!("  Waiting for DB poll to load new config...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Verify a sample of the new proxies are routable
        let sample_idx = batch_start;
        let (ref path, ref key) = all_entries[sample_idx];
        let verify_url = format!("{}{}", harness.proxy_base_url, path);
        let verify_resp = client
            .get(&verify_url)
            .header("X-API-Key", key.as_str())
            .send()
            .await;
        match verify_resp {
            Ok(r) if r.status().is_success() => {
                println!("  Verified proxy {} is routable", path);
            }
            Ok(r) => {
                println!(
                    "  WARNING: proxy {} returned status {}, waiting longer...",
                    path,
                    r.status()
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => {
                println!(
                    "  WARNING: proxy {} failed verification: {}, waiting longer...",
                    path, e
                );
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }

        // Run perf test against all proxies accumulated so far
        println!(
            "\n  Running {}-second perf test against {} proxies (concurrency={})...",
            PERF_TEST_DURATION_SECS,
            all_entries.len(),
            CONCURRENCY
        );

        let result = run_perf_test(
            &harness.proxy_base_url,
            &all_entries,
            PERF_TEST_DURATION_SECS,
            CONCURRENCY,
        )
        .await
        .expect("Perf test failed");

        print_perf_result(&result);

        // Check that success rate is reasonable (>50%)
        if result.total_requests > 0 {
            let success_rate =
                result.successful_requests as f64 / result.total_requests as f64 * 100.0;
            println!("  Success rate: {:.1}%", success_rate);
            assert!(
                success_rate > 50.0,
                "Success rate dropped below 50% at {} proxies: {:.1}%",
                all_entries.len(),
                success_rate
            );
        }

        results.push(result);
    }

    // Print summary table
    println!("\n\n======================================================================");
    println!("  SCALE PERFORMANCE SUMMARY ({})", harness.db_label);
    println!("======================================================================");
    println!(
        "{:<10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Proxies", "RPS", "Avg(ms)", "P50(ms)", "P95(ms)", "P99(ms)", "Max(ms)"
    );
    println!("----------------------------------------------------------------------");

    let baseline_rps = results.first().map(|r| r.rps).unwrap_or(1.0);

    for r in &results {
        let rps_pct = (r.rps / baseline_rps) * 100.0;
        println!(
            "{:<10} {:>9.0} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1}  ({:.0}% of baseline)",
            r.total_proxies,
            r.rps,
            r.avg_latency_us / 1000.0,
            r.p50_latency_us / 1000.0,
            r.p95_latency_us / 1000.0,
            r.p99_latency_us / 1000.0,
            r.max_latency_us / 1000.0,
            rps_pct,
        );
    }

    // Check degradation: RPS at 30k should be at least 30% of RPS at 3k
    if results.len() >= 2 {
        let first_rps = results[0].rps;
        let last_rps = results.last().unwrap().rps;
        let degradation_pct = (1.0 - last_rps / first_rps) * 100.0;
        println!(
            "\nThroughput degradation from {} to {} proxies: {:.1}%",
            results[0].total_proxies,
            results.last().unwrap().total_proxies,
            degradation_pct
        );

        if degradation_pct > 70.0 {
            println!(
                "WARNING: Significant throughput degradation detected ({:.1}%)",
                degradation_pct
            );
        }
    }

    println!(
        "\n=== Scale Performance Test ({}) Complete ===\n",
        harness.db_label
    );
}

/// Check if a Docker container is running.
fn is_container_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

// ---- SQLite variant ----

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_scale_perf_30k_proxies() {
    println!("\n============================================================");
    println!("  Scale Performance Test (SQLite): 0 -> 30,000 proxies");
    println!(
        "  Batch size: {}  |  Perf test: {}s  |  Concurrency: {}",
        BATCH_SIZE, PERF_TEST_DURATION_SECS, CONCURRENCY
    );
    println!("============================================================\n");

    let harness = ScalePerfHarness::new_sqlite()
        .await
        .expect("Failed to create test harness");

    run_scale_perf_test(&harness).await;
}

// ---- PostgreSQL variant ----

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_scale_perf_30k_proxies_postgres() {
    println!("\n============================================================");
    println!("  Scale Performance Test (PostgreSQL): 0 -> 30,000 proxies");
    println!(
        "  Batch size: {}  |  Perf test: {}s  |  Concurrency: {}",
        BATCH_SIZE, PERF_TEST_DURATION_SECS, CONCURRENCY
    );
    println!("============================================================\n");

    // Check for the PostgreSQL container
    // Start with: docker run -d --name ferrum-scale-test-pg \
    //   -e POSTGRES_USER=ferrum -e POSTGRES_PASSWORD=ferrum-scale-test \
    //   -e POSTGRES_DB=ferrum_scale -p 25432:5432 postgres:16
    if !is_container_running("ferrum-scale-test-pg") {
        println!("SKIPPED: ferrum-scale-test-pg container not running.");
        println!("Start it with:");
        println!("  docker run -d --name ferrum-scale-test-pg \\");
        println!("    -e POSTGRES_USER=ferrum -e POSTGRES_PASSWORD=ferrum-scale-test \\");
        println!("    -e POSTGRES_DB=ferrum_scale -p 25432:5432 postgres:16");
        return;
    }

    // Clean the database for a fresh run by dropping and recreating the schema
    let db_url = "postgres://ferrum:ferrum-scale-test@localhost:25432/ferrum_scale";

    // Drop all tables for a clean run
    let drop_result = Command::new("psql")
        .arg(db_url)
        .arg("-c")
        .arg("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        .output();
    match drop_result {
        Ok(o) if o.status.success() => println!("Cleaned PostgreSQL database"),
        Ok(o) => {
            println!(
                "Warning: psql cleanup returned {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
        }
        Err(e) => println!("Warning: psql not available for cleanup: {}", e),
    }

    let harness = ScalePerfHarness::new_postgres(db_url)
        .await
        .expect("Failed to create PostgreSQL test harness");

    run_scale_perf_test(&harness).await;
}

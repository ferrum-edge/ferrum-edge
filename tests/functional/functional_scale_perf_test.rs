//! Scale Performance Test — measures throughput degradation as config grows
//!
//! This test progressively adds proxies (with key_auth + access_control plugins
//! and unique consumers) in batches of 3,000 up to 30,000 total. After each
//! batch it runs a 30-second load test hitting all proxies with their consumer
//! API keys and records latency/throughput metrics. Resources continue to be
//! added mid-test to verify gateway resiliency during config updates.
//!
//! Three variants:
//!   - SQLite (always available, no external DB required)
//!   - PostgreSQL (requires `ferrum-scale-test-pg` Docker container)
//!   - MongoDB (requires a `ferrum-scale-test-mongo` Docker container running as
//!     a single-node replica set, plus `FERRUM_MONGO_REPLICA_SET`)
//!
//! All variants use the batch admin API (`POST /batch`) to create resources
//! in bulk (100 at a time per resource type) for dramatically faster setup.
//! `POST /batch` is all-or-nothing (issue #2401), so on MongoDB it needs
//! multi-document transactions and therefore a replica set; a standalone mongod
//! refuses the import with `501`.
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
use std::time::{Duration, Instant};
use tempfile::TempDir;
use uuid::Uuid;

use crate::common::scheduled_scaling::{
    BatchApplyCursor, CONFIG_CONVERGENCE_MAX_WAIT_SECS, LIVE_APPLY_CURSOR_MAX_WAIT_SECS,
    MEASUREMENT_WINDOW_MAX_ATTEMPTS, SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, post_admin_batch,
    scheduled_scaling_admin_jwt_max_ttl_value, wait_for_batch_apply_cursor,
    wait_for_config_convergence,
};

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
    observability_token: String,
    proxy_port: u16,
    backend_port: u16,
    db_label: String,
}

impl ScalePerfHarness {
    async fn new_sqlite() -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new_sqlite().await {
                Ok(harness) => return Ok(harness),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Harness startup attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to create harness after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_new_sqlite() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("scale_test.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        Self::try_start(temp_dir, "sqlite", &db_url, "SQLite", None).await
    }

    async fn new_postgres(db_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new_postgres(db_url).await {
                Ok(harness) => return Ok(harness),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Harness startup attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to create harness after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_new_postgres(db_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Self::try_start(temp_dir, "postgres", db_url, "PostgreSQL", None).await
    }

    async fn new_mongodb(
        db_url: &str,
        mongo_database: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new_mongodb(db_url, mongo_database).await {
                Ok(harness) => return Ok(harness),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Harness startup attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to create harness after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_new_mongodb(
        db_url: &str,
        mongo_database: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Self::try_start(temp_dir, "mongodb", db_url, "MongoDB", Some(mongo_database)).await
    }

    async fn try_start(
        temp_dir: TempDir,
        db_type: &str,
        db_url: &str,
        db_label: &str,
        mongo_database: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let identity = crate::common::SpawnedGatewayIdentity::mint("scale-perf");
        let jwt_secret = identity.jwt_secret.clone();
        let jwt_issuer = identity.jwt_issuer.clone();
        let observability_token = identity.observability_token.clone();

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
            eprintln!(
                "WARNING: Using debug build — performance numbers will not be meaningful. Run `cargo build --release` first."
            );
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

        let mut command = Command::new(binary_path);
        command
            .env("FERRUM_MODE", "database")
            .env(
                "FERRUM_ADMIN_JWT_MAX_TTL",
                scheduled_scaling_admin_jwt_max_ttl_value(),
            )
            .env("FERRUM_DB_TYPE", db_type)
            .env("FERRUM_DB_URL", db_url)
            // Production default. The harness used 2s here for fast convergence,
            // but with deferred provisioning (issue #4139) that cadence keeps
            // the poller in continuous consumer-escalated FULL reloads during
            // creation, and on PostgreSQL the resulting I/O starvation
            // produced 170s COMMITs, sequence-lock pileups, and lease losses
            // (run 32815095730: single-row INSERT 227s, chunk past the 5-min
            // client budget). Wave-end convergence no longer depends on this
            // interval: the blocking `GET /config/apply-status` cursor gate
            // raises an immediate poll wake on demand.
            .env("FERRUM_DB_POLL_INTERVAL", "30")
            // Attribute convergence delays to SQL snapshot loading versus
            // runtime application without enabling per-request info logs.
            .env("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS", "1000")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "warn");
        // MongoDB stores the gateway's config collections in a dedicated data
        // database, independent of the auth DB in the connection URL. SQL
        // backends ignore this var, so it is only set for the MongoDB variant.
        if let Some(database) = mongo_database {
            command.env("FERRUM_MONGO_DATABASE", database);
            // `POST /batch` is all-or-nothing (issue #2401), which on MongoDB
            // needs multi-document transactions — i.e. a replica set. The CI
            // container is initiated as a single-node replica set and exports
            // its name here; a standalone mongod would refuse the batch import
            // with 501 instead of silently applying part of a graph.
            if let Ok(replica_set) = std::env::var("FERRUM_MONGO_REPLICA_SET") {
                command.env("FERRUM_MONGO_REPLICA_SET", replica_set);
            }
        }
        identity.apply_to_command(&mut command);
        let child = command.spawn()?;

        let proxy_base_url = format!("http://127.0.0.1:{}", proxy_port);
        let admin_base_url = format!("http://127.0.0.1:{}", admin_port);

        let mut harness = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(child),
            proxy_base_url,
            admin_base_url,
            jwt_secret,
            jwt_issuer,
            observability_token,
            proxy_port,
            backend_port,
            db_label: db_label.to_string(),
        };

        match harness.wait_for_health().await {
            Ok(()) => Ok(harness),
            Err(e) => {
                if let Some(mut child) = harness.gateway_process.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e)
            }
        }
    }

    async fn wait_for_health(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let admin_port: u16 = self
            .admin_base_url
            .rsplit(':')
            .next()
            .ok_or("admin_base_url missing port")?
            .parse()?;
        let identity = crate::common::SpawnedGatewayIdentity {
            jwt_secret: self.jwt_secret.clone(),
            jwt_issuer: self.jwt_issuer.clone(),
            observability_token: self.observability_token.clone(),
        };
        let child = self
            .gateway_process
            .as_mut()
            .ok_or("gateway process missing")?;
        crate::common::wait_for_owned_gateway_identity(
            child,
            admin_port,
            &identity,
            Duration::from_secs(30),
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn generate_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "role": "admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS))
                .timestamp(),
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
/// Uses `POST /batch?apply=async` to send resources in chunks of
/// `API_BATCH_CHUNK` at a time, and returns the highest covering live-apply
/// cursor it saw so the caller can prove the whole wave live with ONE blocking
/// `GET /config/apply-status` instead of paying one synchronous reload per
/// chunk (issues #4136 / #4139).
async fn create_batch(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    backend_port: u16,
    batch_start: usize,
    batch_end: usize,
) -> Result<(Vec<(String, String)>, Option<BatchApplyCursor>), Box<dyn std::error::Error>> {
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
                "keyauth": [{"key": api_key}]
            }
        }));

        all_proxies.push(json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_scheme": "http",
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

    // `POST /batch?apply=async` is all-or-nothing and succeeds only with the
    // deferred 202 (durably committed, cursor returned). Only the documented
    // all-or-nothing 503s are retried, so repeating the same atomic body
    // cannot accept or compound a partial graph. Cursors are monotone
    // (epoch-major), so keeping the max makes the final cursor cover every
    // chunk in the wave.
    let mut last_cursor: Option<BatchApplyCursor> = None;
    for chunk in all_consumers.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "consumers": chunk });
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &batch_body,
            "Batch consumer create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }

    for chunk in all_proxies.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "proxies": chunk });
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &batch_body,
            "Batch proxy create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }

    for chunk in all_plugins.chunks(API_BATCH_CHUNK) {
        let batch_body = json!({ "plugin_configs": chunk });
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &batch_body,
            "Batch plugin create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }

    Ok((entries, last_cursor))
}

/// Perf test results for a single run
#[derive(Debug, Clone)]
struct PerfResult {
    total_proxies: usize,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    not_found_requests: u64,
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
    let not_found_requests = Arc::new(AtomicU64::new(0));
    let convergence_interruption = Arc::new(tokio::sync::Notify::new());

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
        let not_found_requests = not_found_requests.clone();
        let convergence_interruption = convergence_interruption.clone();
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
                    Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => {
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                        not_found_requests.fetch_add(1, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        convergence_interruption.notify_one();
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

    // A route-miss 404 is the observable data-plane signal that convergence
    // changed after the pre-window gate. End this attempt immediately so its
    // partial traffic can be discarded rather than reported as throughput.
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(duration_secs)) => {}
        _ = convergence_interruption.notified() => {}
    }
    stop.store(true, Ordering::Relaxed);

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }
    let elapsed = start.elapsed().as_secs_f64();

    let total = total_requests.load(Ordering::Relaxed);
    let success = successful_requests.load(Ordering::Relaxed);
    let fail = failed_requests.load(Ordering::Relaxed);
    let not_found = not_found_requests.load(Ordering::Relaxed);

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
        not_found_requests: not_found,
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

/// Sample indices used to prove a freshly created batch has been published.
///
/// Covers the first, middle and last proxy of the new batch plus proxy 0, so a
/// forced full reload that has published only part of the graph — or that has
/// transiently dropped already-published config — cannot be mistaken for
/// convergence.
fn convergence_sample_indices(batch_start: usize, total: usize) -> Vec<usize> {
    let mut indices = vec![
        0,
        batch_start,
        batch_start + (total - batch_start) / 2,
        total - 1,
    ];
    indices.sort_unstable();
    indices.dedup();
    indices
}

async fn wait_for_scale_config_convergence(
    client: &reqwest::Client,
    proxy_base_url: &str,
    entries: &[(String, String)],
    sample_indices: &[usize],
) -> Result<(), String> {
    let sample_labels: Vec<String> = sample_indices
        .iter()
        .map(|&index| entries[index].0.clone())
        .collect();
    println!(
        "  Waiting for config convergence on {} sample proxies (bound {}s)...",
        sample_labels.len(),
        CONFIG_CONVERGENCE_MAX_WAIT_SECS
    );
    let convergence = wait_for_config_convergence("the scale harness", &sample_labels, |i| {
        let index = sample_indices[i];
        let (ref path, ref key) = entries[index];
        let url = format!("{proxy_base_url}{path}");
        let key = key.clone();
        let client = client.clone();
        async move {
            match client.get(&url).header("X-API-Key", key).send().await {
                Ok(response) => Ok(response.status().as_u16()),
                Err(error) => Err(error.to_string()),
            }
        }
    })
    .await?;
    println!(
        "  Config converged after {:.1}s ({} polls)",
        convergence.waited.as_secs_f64(),
        convergence.polls
    );
    Ok(())
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
        let (new_entries, wave_cursor) = create_batch(
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

        // First gate: prove the deferred wave's covering cursor was accepted
        // by the poll loop (issue #4139). Every chunk answered 202 without
        // paying a reload; this single blocking wait is where the wave's one
        // reload is paid, and a `rejected`/`unverifiable` cursor aborts loudly
        // instead of surfacing as mysterious 404s in the probe gate below.
        if let Some(cursor) = wave_cursor {
            println!(
                "  Waiting for live-apply cursor {}:{} (bound {}s)...",
                cursor.epoch, cursor.sequence, LIVE_APPLY_CURSOR_MAX_WAIT_SECS
            );
            let waited = wait_for_batch_apply_cursor(
                &client,
                &harness.admin_base_url,
                &auth_header,
                cursor,
                "the scale harness",
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Scale harness aborted before measuring {} proxies: {}",
                    all_entries.len(),
                    error
                )
            });
            println!("  Live apply converged after {:.1}s", waited.as_secs_f64());
        }

        // Second gate: prove the published config actually routes end to end.
        // Provisioning appends ~12,000 `config_changes` rows, which
        // pushes the poller past `CHANGE_LOG_BATCH_LIMIT` and forces a full
        // reload; measuring inside that reload measures convergence, not
        // routing throughput. Sample across the new batch — not only its first
        // proxy — plus the oldest proxy, so a reload that drops already-published
        // config is caught too.
        let sample_indices = convergence_sample_indices(batch_start, all_entries.len());
        wait_for_scale_config_convergence(
            &client,
            &harness.proxy_base_url,
            &all_entries,
            &sample_indices,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "Scale harness aborted before measuring {} proxies: {}",
                all_entries.len(),
                error
            )
        });

        // Run one complete window against the converged generation. A 404 is
        // the observable route-miss signal that the data plane changed after
        // the gate; discard that partial window, prove convergence again, and
        // allow one bounded restart. Other failures stay in the completed
        // window and remain subject to the success-rate assertion below.
        let mut measurement_attempt = 0u32;
        let result = loop {
            measurement_attempt += 1;
            println!(
                "\n  Running {}-second perf test against {} proxies (concurrency={}, window {}/{})...",
                PERF_TEST_DURATION_SECS,
                all_entries.len(),
                CONCURRENCY,
                measurement_attempt,
                MEASUREMENT_WINDOW_MAX_ATTEMPTS
            );
            let candidate = run_perf_test(
                &harness.proxy_base_url,
                &all_entries,
                PERF_TEST_DURATION_SECS,
                CONCURRENCY,
            )
            .await
            .expect("Perf test failed");
            if candidate.not_found_requests == 0 {
                break candidate;
            }

            println!(
                "  CONVERGENCE EVENT: observed {} route-miss 404 response(s) after {:.1}s; \
                 discarding interrupted measurement window {}/{}",
                candidate.not_found_requests,
                candidate.duration_secs,
                measurement_attempt,
                MEASUREMENT_WINDOW_MAX_ATTEMPTS
            );
            assert!(
                measurement_attempt < MEASUREMENT_WINDOW_MAX_ATTEMPTS,
                "Configuration convergence instability interrupted all {} bounded measurement \
                 windows at {} proxies; no routing-throughput result was recorded",
                MEASUREMENT_WINDOW_MAX_ATTEMPTS,
                all_entries.len()
            );
            wait_for_scale_config_convergence(
                &client,
                &harness.proxy_base_url,
                &all_entries,
                &sample_indices,
            )
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "Scale harness could not restart the measurement at {} proxies: {}",
                    all_entries.len(),
                    error
                )
            });
        };

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

// ---- MongoDB variant ----

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_scale_perf_30k_proxies_mongodb() {
    println!("\n============================================================");
    println!("  Scale Performance Test (MongoDB): 0 -> 30,000 proxies");
    println!(
        "  Batch size: {}  |  Perf test: {}s  |  Concurrency: {}",
        BATCH_SIZE, PERF_TEST_DURATION_SECS, CONCURRENCY
    );
    println!("============================================================\n");

    // Check for the MongoDB container. Resources are provisioned through
    // `POST /batch`, which is all-or-nothing (issue #2401) and therefore needs
    // MongoDB multi-document transactions — i.e. a replica set, not a
    // standalone mongod. `--network host` keeps the member's advertised
    // host:port reachable from this process.
    if !is_container_running("ferrum-scale-test-mongo") {
        println!("SKIPPED: ferrum-scale-test-mongo container not running.");
        println!("Start it with:");
        println!("  docker run -d --name ferrum-scale-test-mongo --network host \\");
        println!("    mongo:7 --replSet rs0 --port 27117 --bind_ip_all");
        println!("  docker exec ferrum-scale-test-mongo mongosh --port 27117 --eval \\");
        println!(
            "    'rs.initiate({{_id: \"rs0\", members: [{{_id: 0, host: \"localhost:27117\"}}]}})'"
        );
        println!("  export FERRUM_MONGO_REPLICA_SET=rs0");
        return;
    }

    // The connection URL points at the container's mapped host port. MongoDB
    // stores the gateway's config collections in FERRUM_MONGO_DATABASE
    // (`ferrum_scale`), independent of the URL path / auth database.
    let db_url = "mongodb://localhost:27117";
    let mongo_database = "ferrum_scale";

    // Clean the database for a fresh run by dropping it inside the container.
    // `mongosh` ships with the mongo:7 image, so we exec it there rather than
    // depending on a host-installed Mongo client.
    let drop_result = Command::new("docker")
        .args([
            "exec",
            "ferrum-scale-test-mongo",
            "mongosh",
            "--quiet",
            "--port",
            "27117",
            "--eval",
            "db.getSiblingDB('ferrum_scale').dropDatabase()",
        ])
        .output();
    match drop_result {
        Ok(o) if o.status.success() => println!("Cleaned MongoDB database"),
        Ok(o) => {
            println!(
                "Warning: mongosh cleanup returned {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
        }
        Err(e) => println!("Warning: docker/mongosh not available for cleanup: {}", e),
    }

    let harness = ScalePerfHarness::new_mongodb(db_url, mongo_database)
        .await
        .expect("Failed to create MongoDB test harness");

    run_scale_perf_test(&harness).await;
}

//! Scale Performance Test — measures throughput degradation as config grows
//!
//! This test progressively adds proxies (with key_auth + access_control plugins
//! and unique consumers) in batches of 3,000 up to 30,000 total. After each
//! batch it runs a 30-second load test (after a discarded warmup) hitting all
//! proxies with their consumer API keys and records latency, throughput, and
//! gateway CPU per request. Each new batch is provisioned through the admin API
//! while the gateway process keeps running, and must converge (hot config swap,
//! no restart) before the next window is measured. Load is not applied while a
//! batch is being provisioned.
//!
//! Set `FERRUM_SCALE_RESULTS_JSON=<path>` to also write every batch result as
//! JSON for publishing.
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

use crate::scaffolding::port_registry::TestSocket;

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
/// Traffic sent before each window and discarded: connections, route caches,
/// and consumer lookups for the new generation are warm when measuring starts.
const PERF_WARMUP_SECS: u64 = 5;
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

/// Spotlight skips directories ending in `.noindex`; indexing the growing
/// SQLite file otherwise competes with the gateway for CPU on macOS.
fn harness_temp_dir() -> std::io::Result<TempDir> {
    tempfile::Builder::new()
        .prefix("ferrum-scale-")
        .suffix(".noindex")
        .tempdir()
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
        let temp_dir = harness_temp_dir()?;
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
        let temp_dir = harness_temp_dir()?;
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
        let temp_dir = harness_temp_dir()?;
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

        let admin_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let backend_port = backend_listener.local_addr()?.port();
        drop(backend_listener);

        // Start echo backend
        start_echo_backend(backend_port).await?;

        // Build gateway (release mode for meaningful perf numbers). Build only
        // the gateway binary, exactly as the documented prebuild does: a plain
        // `cargo build --release` covers a different target set, so it redid
        // the whole fat-LTO release build inside the measured test.
        let build_status = Command::new("cargo")
            .args(["build", "--release", "--bin", "ferrum-edge"])
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
                .arg("run")
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
        command.arg("run");
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
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;
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
    // Per-resource-type admin write time, to localize slow provisioning.
    let phase_timer = Instant::now();
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
    let consumers_secs = phase_timer.elapsed().as_secs_f64();

    let phase_timer = Instant::now();
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
    let proxies_secs = phase_timer.elapsed().as_secs_f64();

    let phase_timer = Instant::now();
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
    println!(
        "  Admin writes: consumers {:.1}s, proxies {:.1}s, plugin configs {:.1}s ({} per request)",
        consumers_secs,
        proxies_secs,
        phase_timer.elapsed().as_secs_f64(),
        API_BATCH_CHUNK
    );

    Ok((entries, last_cursor))
}

/// Perf test results for a single run
#[derive(Debug, Clone, serde::Serialize)]
struct PerfResult {
    total_proxies: usize,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    not_found_requests: u64,
    duration_secs: f64,
    /// Successful requests per second over the measured window.
    rps: f64,
    /// Gateway process CPU time (user + system) consumed during the window.
    gateway_cpu_seconds: Option<f64>,
    avg_latency_us: f64,
    p50_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
    max_latency_us: f64,
}

/// Cumulative user + system CPU seconds of a process (all threads).
fn process_cpu_seconds(pid: u32) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
        let ticks = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        (hz > 0).then(|| ticks / hz as f64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS/BSD: `[[DD-]HH:]MM:SS.ss`, 10 ms resolution.
        let output = Command::new("ps")
            .args(["-o", "cputime=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let raw = String::from_utf8(output.stdout).ok()?;
        let raw = raw.trim();
        let (days, clock) = raw.split_once('-').unwrap_or(("0", raw));
        let mut seconds = 0.0;
        for part in clock.split(':') {
            seconds = seconds * 60.0 + part.parse::<f64>().ok()?;
        }
        Some(seconds + days.parse::<f64>().ok()? * 86_400.0)
    }
}

/// Run a load test against all known proxies: `warmup_secs` of discarded
/// traffic, then a `duration_secs` measured window. Sends requests round-robin
/// across all proxy paths with their API keys. Only requests that complete
/// inside the window count; latency percentiles cover successful requests.
async fn run_perf_test(
    proxy_base_url: &str,
    entries: &[(String, String)],
    warmup_secs: u64,
    duration_secs: u64,
    concurrency: usize,
    gateway_pid: Option<u32>,
) -> Result<PerfResult, Box<dyn std::error::Error>> {
    let total_proxies = entries.len();
    let stop = Arc::new(AtomicBool::new(false));
    let measuring = Arc::new(AtomicBool::new(false));
    let total_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));
    let not_found_requests = Arc::new(AtomicU64::new(0));
    let convergence_interruption = Arc::new(tokio::sync::Notify::new());

    // Shared latency collection — each worker has its own vec, merged later
    let latencies: Arc<tokio::sync::Mutex<Vec<u64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(100_000)));

    let entries = Arc::new(entries.to_vec());

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        let stop = stop.clone();
        let measuring = measuring.clone();
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
                // A request succeeds only once its whole body arrives: headers
                // alone would count a truncated or stalled response as served.
                let result = match client
                    .get(&url)
                    .header("X-API-Key", key.as_str())
                    .send()
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        response.bytes().await.map(|_| status)
                    }
                    Err(error) => Err(error),
                };
                let latency_us = req_start.elapsed().as_micros() as u64;
                // Warmup completions and requests finishing after the window
                // closed are not samples.
                let in_window = measuring.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed);

                match result {
                    Ok(status) if status.is_success() => {
                        if in_window {
                            total_requests.fetch_add(1, Ordering::Relaxed);
                            successful_requests.fetch_add(1, Ordering::Relaxed);
                            local_latencies.push(latency_us);
                        }
                    }
                    Ok(status) if status == reqwest::StatusCode::NOT_FOUND => {
                        // A route miss is a convergence signal in warmup too.
                        total_requests.fetch_add(1, Ordering::Relaxed);
                        failed_requests.fetch_add(1, Ordering::Relaxed);
                        not_found_requests.fetch_add(1, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        convergence_interruption.notify_one();
                    }
                    _ => {
                        if in_window {
                            total_requests.fetch_add(1, Ordering::Relaxed);
                            failed_requests.fetch_add(1, Ordering::Relaxed);
                        }
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
    let interrupted = tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(warmup_secs)) => false,
        _ = convergence_interruption.notified() => true,
    };
    let cpu_start = gateway_pid.and_then(process_cpu_seconds);
    let window_start = Instant::now();
    if !interrupted {
        measuring.store(true, Ordering::Relaxed);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(duration_secs)) => {}
            _ = convergence_interruption.notified() => {}
        }
    }
    stop.store(true, Ordering::Relaxed);
    let elapsed = window_start.elapsed().as_secs_f64();
    let cpu_end = gateway_pid.and_then(process_cpu_seconds);

    // Wait for all workers to finish their in-flight request
    for h in handles {
        let _ = h.await;
    }

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
        rps: if elapsed > 0.0 {
            success as f64 / elapsed
        } else {
            0.0
        },
        gateway_cpu_seconds: cpu_start.zip(cpu_end).map(|(start, end)| end - start),
        avg_latency_us: avg,
        p50_latency_us: p50,
        p95_latency_us: p95,
        p99_latency_us: p99,
        max_latency_us: max,
    })
}

fn gateway_cpu_us_per_request(r: &PerfResult) -> Option<f64> {
    r.gateway_cpu_seconds
        .filter(|_| r.successful_requests > 0)
        .map(|cpu| cpu * 1e6 / r.successful_requests as f64)
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
    if let Some(cpu_us) = gateway_cpu_us_per_request(r) {
        println!(
            "│  Gateway CPU/req:     {:>8.1} µs                       │",
            cpu_us
        );
    }
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
        // Provisioning appends ~12,000 `config_changes` rows, which the
        // poller applies as one large delta; measuring inside that apply
        // measures convergence, not routing throughput. Sample across the new batch — not only its first
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
                "\n  Running {}-second perf test (+{}s warmup) against {} proxies (concurrency={}, window {}/{})...",
                PERF_TEST_DURATION_SECS,
                PERF_WARMUP_SECS,
                all_entries.len(),
                CONCURRENCY,
                measurement_attempt,
                MEASUREMENT_WINDOW_MAX_ATTEMPTS
            );
            let candidate = run_perf_test(
                &harness.proxy_base_url,
                &all_entries,
                PERF_WARMUP_SECS,
                PERF_TEST_DURATION_SECS,
                CONCURRENCY,
                harness.gateway_process.as_ref().map(Child::id),
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
        "{:<10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>12}",
        "Proxies", "RPS", "Avg(ms)", "P50(ms)", "P95(ms)", "P99(ms)", "Max(ms)", "CPU/req(µs)"
    );
    println!("----------------------------------------------------------------------");

    let baseline_rps = results.first().map(|r| r.rps).unwrap_or(1.0);

    for r in &results {
        let rps_pct = (r.rps / baseline_rps) * 100.0;
        let cpu = gateway_cpu_us_per_request(r)
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "n/a".to_string());
        println!(
            "{:<10} {:>9.0} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>12}  ({:.0}% of baseline)",
            r.total_proxies,
            r.rps,
            r.avg_latency_us / 1000.0,
            r.p50_latency_us / 1000.0,
            r.p95_latency_us / 1000.0,
            r.p99_latency_us / 1000.0,
            r.max_latency_us / 1000.0,
            cpu,
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

    if let Ok(path) = std::env::var("FERRUM_SCALE_RESULTS_JSON") {
        write_results_json(&path, &harness.db_label, &results);
    }

    println!(
        "\n=== Scale Performance Test ({}) Complete ===\n",
        harness.db_label
    );
}

/// Machine-readable copy of the batch results with the run's parameters.
fn write_results_json(path: &str, db_label: &str, results: &[PerfResult]) {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string());
    let batches: Vec<_> = results
        .iter()
        .map(|r| {
            let mut value = serde_json::to_value(r).unwrap_or_default();
            value["gateway_cpu_us_per_request"] = json!(gateway_cpu_us_per_request(r));
            value
        })
        .collect();
    let document = json!({
        "test": "tests/functional/functional_scale_perf_test.rs",
        "database": db_label,
        "finished_utc": Utc::now().to_rfc3339(),
        "git_commit": commit,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "batch_size": BATCH_SIZE,
        "total_proxies": TOTAL_PROXIES,
        "warmup_secs": PERF_WARMUP_SECS,
        "window_secs": PERF_TEST_DURATION_SECS,
        "concurrency": CONCURRENCY,
        "batches": batches,
    });
    match serde_json::to_string_pretty(&document) {
        Ok(text) => match std::fs::write(path, text + "\n") {
            Ok(()) => println!("Wrote scale results to {path}"),
            Err(error) => eprintln!("Could not write {path}: {error}"),
        },
        Err(error) => eprintln!("Could not serialize scale results: {error}"),
    }
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
    //   -e POSTGRES_DB=ferrum_scale -p 127.0.0.1:25432:5432 postgres:16
    if !is_container_running("ferrum-scale-test-pg") {
        println!("SKIPPED: ferrum-scale-test-pg container not running.");
        println!("Start it with:");
        println!("  docker run -d --name ferrum-scale-test-pg \\");
        println!("    -e POSTGRES_USER=ferrum -e POSTGRES_PASSWORD=ferrum-scale-test \\");
        println!("    -e POSTGRES_DB=ferrum_scale -p 127.0.0.1:25432:5432 postgres:16");
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
        println!("    mongo:7 --replSet rs0 --port 27117 --bind_ip 127.0.0.1");
        println!("  docker exec ferrum-scale-test-mongo mongosh --port 27117 --eval \\");
        println!(
            "    'rs.initiate({{_id: \"rs0\", members: [{{_id: 0, host: \"127.0.0.1:27117\"}}]}})'"
        );
        println!("  export FERRUM_MONGO_REPLICA_SET=rs0");
        return;
    }

    // The connection URL points at the container's mapped host port. MongoDB
    // stores the gateway's config collections in FERRUM_MONGO_DATABASE
    // (`ferrum_scale`), independent of the URL path / auth database.
    let db_url = "mongodb://127.0.0.1:27117";
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

// ── Reload under load ────────────────────────────────────────────────────────
//
// The scale test above measures steady-state throughput *between* config waves.
// This variant keeps traffic flowing against every already-live proxy while the
// next wave is written through the admin API and hot-applied, and records a
// per-second series of throughput, latency, errors, gateway CPU, and gateway
// RSS. Any non-2xx or transport error from a previously-live proxy fails the
// test: an atomic config swap must never drop or stall routes that already
// exist.

/// Discarded traffic before each wave's steady baseline.
const RELOAD_WARMUP_SECS: u64 = 5;
/// Steady baseline measured immediately before each wave is provisioned.
const RELOAD_STEADY_SECS: u64 = 10;
/// Measured after the new wave is live, still under the same load.
const RELOAD_POST_SECS: u64 = 10;
/// Proxies in each small change applied after every wave. A 12,000-resource
/// wave exceeds the poller's 10,000-row change-log limit and forces a full
/// rebuild. Small changes come in two kinds: with new `key_auth` consumers and
/// proxies-only (new proxies whose plugins admit existing consumers). Both take
/// the incremental path: consumer changes escalate to a full reload only while
/// load-time quarantine is active or a changed consumer carries `hmac_auth`
/// (issue #6060).
const RELOAD_SMALL_CHANGE_PROXIES: usize = 100;
/// Index bases for small-change proxies, clear of every wave's range.
const RELOAD_SMALL_WITH_CONSUMERS_BASE: usize = 1_000_000;
const RELOAD_SMALL_PROXIES_ONLY_BASE: usize = 2_000_000;

/// Create proxies `batch_start..batch_end` with key_auth + access_control that
/// admit existing first-wave consumers (`user-<k>` / `reuse[k]`'s key), so
/// the change carries no consumer rows. Returns the new entries.
async fn create_proxy_only_batch(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    backend_port: u16,
    batch_start: usize,
    batch_end: usize,
    reuse: &[(String, String)],
) -> Result<(Vec<(String, String)>, Option<BatchApplyCursor>), Box<dyn std::error::Error>> {
    let mut entries = Vec::with_capacity(batch_end - batch_start);
    let mut proxies = Vec::with_capacity(batch_end - batch_start);
    let mut plugins = Vec::with_capacity((batch_end - batch_start) * 2);
    for (k, i) in (batch_start..batch_end).enumerate() {
        let (_, api_key) = &reuse[k % reuse.len()];
        let proxy_id = format!("proxy-{i}");
        let listen_path = format!("/svc/{i}");
        proxies.push(json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }));
        plugins.push(json!({
            "id": format!("keyauth-{i}"),
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": { "key_location": "header:X-API-Key" }
        }));
        plugins.push(json!({
            "id": format!("acl-{i}"),
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": { "allowed_consumers": [format!("user-{}", k % reuse.len())] }
        }));
        entries.push((listen_path, api_key.clone()));
    }
    let mut last_cursor: Option<BatchApplyCursor> = None;
    for chunk in proxies.chunks(API_BATCH_CHUNK) {
        let body = json!({ "proxies": chunk });
        let cursor =
            post_admin_batch(client, admin_url, auth_header, &body, "Batch proxy create").await?;
        last_cursor = last_cursor.max(cursor);
    }
    for chunk in plugins.chunks(API_BATCH_CHUNK) {
        let body = json!({ "plugin_configs": chunk });
        let cursor =
            post_admin_batch(client, admin_url, auth_header, &body, "Batch plugin create").await?;
        last_cursor = last_cursor.max(cursor);
    }
    Ok((entries, last_cursor))
}

/// Per-second load bucket. Latency samples are successful requests only.
#[derive(Default)]
struct LoadBucket {
    ok: u64,
    errors: u64,
    not_found: u64,
    latencies_us: Vec<u32>,
}

impl LoadBucket {
    fn absorb(&mut self, other: LoadBucket) {
        self.ok += other.ok;
        self.errors += other.errors;
        self.not_found += other.not_found;
        self.latencies_us.extend(other.latencies_us);
    }
}

/// Closed-loop load against a fixed set of live proxies, bucketed per second
/// from `started`.
struct LiveLoad {
    stop: Arc<AtomicBool>,
    handles: Vec<tokio::task::JoinHandle<Vec<LoadBucket>>>,
}

fn start_live_load(
    proxy_base_url: &str,
    entries: Arc<Vec<(String, String)>>,
    concurrency: usize,
    started: Instant,
) -> LiveLoad {
    let stop = Arc::new(AtomicBool::new(false));
    let handles = (0..concurrency)
        .map(|worker_id| {
            let stop = stop.clone();
            let entries = entries.clone();
            let base_url = proxy_base_url.to_string();
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .pool_max_idle_per_host(10)
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap();
                let mut buckets: Vec<LoadBucket> = Vec::new();
                let mut idx = worker_id % entries.len();
                while !stop.load(Ordering::Relaxed) {
                    let (path, key) = &entries[idx];
                    let req_start = Instant::now();
                    // Success and latency cover the whole body: a reload that
                    // truncates or stalls a response after its headers must
                    // count as an error, not as a served request.
                    let result = match client
                        .get(format!("{base_url}{path}"))
                        .header("X-API-Key", key.as_str())
                        .send()
                        .await
                    {
                        Ok(response) => {
                            let status = response.status();
                            response.bytes().await.map(|_| status)
                        }
                        Err(error) => Err(error),
                    };
                    let latency_us = req_start.elapsed().as_micros().min(u32::MAX as u128) as u32;
                    let second = started.elapsed().as_secs() as usize;
                    if buckets.len() <= second {
                        buckets.resize_with(second + 1, LoadBucket::default);
                    }
                    let bucket = &mut buckets[second];
                    match result {
                        Ok(status) if status.is_success() => {
                            bucket.ok += 1;
                            bucket.latencies_us.push(latency_us);
                        }
                        Ok(status) if status == reqwest::StatusCode::NOT_FOUND => {
                            bucket.errors += 1;
                            bucket.not_found += 1;
                        }
                        _ => bucket.errors += 1,
                    }
                    idx = (idx + concurrency) % entries.len();
                    if idx == worker_id % entries.len() {
                        idx = (idx + 1) % entries.len();
                    }
                }
                buckets
            })
        })
        .collect();
    LiveLoad { stop, handles }
}

impl LiveLoad {
    async fn finish(self) -> Vec<LoadBucket> {
        self.stop.store(true, Ordering::Relaxed);
        let mut merged: Vec<LoadBucket> = Vec::new();
        for handle in self.handles {
            let Ok(buckets) = handle.await else { continue };
            if merged.len() < buckets.len() {
                merged.resize_with(buckets.len(), LoadBucket::default);
            }
            for (slot, bucket) in merged.iter_mut().zip(buckets) {
                slot.absorb(bucket);
            }
        }
        merged
    }
}

/// Resident set size of a process in bytes.
fn process_rss_bytes(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kib * 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let kib: u64 = String::from_utf8(output.stdout).ok()?.trim().parse().ok()?;
        Some(kib * 1024)
    }
}

#[derive(Clone, Copy, serde::Serialize)]
struct ResourceSample {
    t_secs: f64,
    cpu_seconds: Option<f64>,
    rss_bytes: Option<u64>,
    /// This test process (load generator + echo backend): CPU seconds.
    client_cpu_seconds: Option<f64>,
    /// Host 1-minute load average: sustained contention from other processes.
    host_load_1m: Option<f64>,
    /// Host-wide cumulative CPU ticks `(busy, total)` across every core.
    host_cpu_ticks: Option<(u64, u64)>,
}

/// With `FERRUM_RELOAD_WAIT_FOR_QUIET_HOST=1`, wait (up to 10 min) before a
/// change until host-wide CPU over a 3-second window is below 30% of the CPU
/// count, so another build on a shared machine does not land inside the
/// measurement. Busy CPU is measured directly rather than through the 1-minute
/// load average, which still carries the previous change's own load for a
/// minute or two after it ends. Returns the seconds waited.
async fn wait_for_quiet_host() -> f64 {
    if std::env::var("FERRUM_RELOAD_WAIT_FOR_QUIET_HOST").as_deref() != Ok("1") {
        return 0.0;
    }
    let threshold = logical_cpus() * 0.3;
    let started = Instant::now();
    let mut busy = None;
    while started.elapsed() < Duration::from_secs(600) {
        let before = host_cpu_ticks();
        tokio::time::sleep(Duration::from_secs(3)).await;
        busy = before
            .zip(host_cpu_ticks())
            .and_then(|(a, b)| host_busy_cores(a, b));
        match busy {
            Some(cores) if cores >= threshold => {}
            _ => break,
        }
    }
    let waited = started.elapsed().as_secs_f64();
    if waited >= 5.0 {
        println!(
            "  waited {:.0}s for host CPU below {:.1} cores; now {}",
            waited,
            threshold,
            fmt_opt(busy, 1)
        );
    }
    waited
}

fn logical_cpus() -> f64 {
    std::thread::available_parallelism().map_or(1, |n| n.get()) as f64
}

/// Host-wide cumulative CPU ticks `(busy, total)` summed over every core.
fn host_cpu_ticks() -> Option<(u64, u64)> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let fields: Vec<u64> = stat
            .lines()
            .next()?
            .split_whitespace()
            .skip(1)
            .take(8)
            .map(|v| v.parse().ok())
            .collect::<Option<_>>()?;
        // user nice system idle iowait irq softirq steal
        let idle = fields.get(3)? + fields.get(4)?;
        let total: u64 = fields.iter().sum();
        Some((total - idle, total))
    }
    #[cfg(target_os = "macos")]
    {
        // libSystem's host port accessor (`libc` deprecates its binding in
        // favour of the `mach2` crate; this test needs only this one symbol).
        unsafe extern "C" {
            fn mach_host_self() -> libc::mach_port_t;
        }
        static HOST: std::sync::OnceLock<libc::mach_port_t> = std::sync::OnceLock::new();
        // SAFETY: mach_host_self has no preconditions; the port is reused.
        let host = *HOST.get_or_init(|| unsafe { mach_host_self() });
        let mut info = libc::host_cpu_load_info {
            cpu_ticks: [0; libc::CPU_STATE_MAX as usize],
        };
        let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
        // SAFETY: `info` is a host_cpu_load_info and `count` is its size in
        // natural_t units, as HOST_CPU_LOAD_INFO requires.
        let status = unsafe {
            libc::host_statistics(
                host,
                libc::HOST_CPU_LOAD_INFO,
                (&mut info as *mut libc::host_cpu_load_info).cast(),
                &mut count,
            )
        };
        if status != libc::KERN_SUCCESS {
            return None;
        }
        let ticks = info.cpu_ticks.map(u64::from);
        let idle = ticks[libc::CPU_STATE_IDLE as usize];
        let total: u64 = ticks.iter().sum();
        Some((total - idle, total))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Cores busy host-wide between two `host_cpu_ticks` samples.
fn host_busy_cores(before: (u64, u64), after: (u64, u64)) -> Option<f64> {
    let total = after.1.checked_sub(before.1)?;
    let busy = after.0.checked_sub(before.0)?;
    (total > 0).then(|| busy as f64 / total as f64 * logical_cpus())
}

fn host_load_average_1m() -> Option<f64> {
    let mut loads = [0f64; 3];
    // SAFETY: `loads` has room for the three values requested.
    let n = unsafe { libc::getloadavg(loads.as_mut_ptr(), 3) };
    (n >= 1).then_some(loads[0])
}

/// Samples gateway CPU and RSS once per second until stopped.
fn start_resource_sampler(
    pid: u32,
    started: Instant,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Vec<ResourceSample>> {
    tokio::spawn(async move {
        let mut samples = Vec::new();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        while !stop.load(Ordering::Relaxed) {
            tick.tick().await;
            let t_secs = started.elapsed().as_secs_f64();
            let self_pid = std::process::id();
            let (cpu_seconds, rss_bytes, client_cpu_seconds) =
                tokio::task::spawn_blocking(move || {
                    (
                        process_cpu_seconds(pid),
                        process_rss_bytes(pid),
                        process_cpu_seconds(self_pid),
                    )
                })
                .await
                .unwrap_or((None, None, None));
            samples.push(ResourceSample {
                t_secs,
                cpu_seconds,
                rss_bytes,
                client_cpu_seconds,
                host_load_1m: host_load_average_1m(),
                host_cpu_ticks: host_cpu_ticks(),
            });
        }
        samples
    })
}

/// One row of the per-second series.
#[derive(serde::Serialize)]
struct SecondPoint {
    t: usize,
    ok: u64,
    errors: u64,
    p50_us: Option<u32>,
    p99_us: Option<u32>,
    gateway_cpu_cores: Option<f64>,
    gateway_rss_mib: Option<f64>,
    load_generator_cpu_cores: Option<f64>,
    host_load_1m: Option<f64>,
    /// Host busy cores minus the gateway and this test process.
    other_cpu_cores: Option<f64>,
}

#[derive(Debug, Default, Clone, serde::Serialize)]
struct PhaseStats {
    secs: usize,
    rps: f64,
    p50_us: u32,
    p99_us: u32,
    max_us: u32,
    errors: u64,
    not_found: u64,
    worst_second_rps: u64,
    worst_second_p99_us: u32,
    gateway_cpu_cores_mean: Option<f64>,
    gateway_cpu_cores_peak: Option<f64>,
    gateway_rss_mib_peak: Option<f64>,
    /// Highest host 1-minute load average seen in the phase.
    host_load_1m_peak: Option<f64>,
}

fn percentile(sorted: &[u32], q: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

fn cpu_cores_series(samples: &[ResourceSample]) -> Vec<(f64, f64)> {
    cores_series(samples, |s| s.cpu_seconds)
}

fn cores_series(
    samples: &[ResourceSample],
    cpu: impl Fn(&ResourceSample) -> Option<f64>,
) -> Vec<(f64, f64)> {
    samples
        .windows(2)
        .filter_map(|w| {
            let (a, b) = (&w[0], &w[1]);
            let dt = b.t_secs - a.t_secs;
            Some((b.t_secs, (cpu(b)? - cpu(a)?) / dt))
        })
        .collect()
}

/// Stats over whole seconds `[from, to)` of the series.
fn phase_stats(
    buckets: &[LoadBucket],
    samples: &[ResourceSample],
    from: usize,
    to: usize,
) -> PhaseStats {
    let to = to.min(buckets.len());
    let window = buckets.get(from..to).unwrap_or_default();
    if window.is_empty() {
        return PhaseStats::default();
    }
    let mut latencies: Vec<u32> = window
        .iter()
        .flat_map(|b| b.latencies_us.iter().copied())
        .collect();
    latencies.sort_unstable();
    let ok: u64 = window.iter().map(|b| b.ok).sum();
    let worst_second_p99_us = window
        .iter()
        .map(|b| {
            let mut l = b.latencies_us.clone();
            l.sort_unstable();
            percentile(&l, 0.99)
        })
        .max()
        .unwrap_or(0);
    let in_phase = |t: f64| t > from as f64 && t <= to as f64;
    let cores: Vec<f64> = cpu_cores_series(samples)
        .into_iter()
        .filter(|(t, _)| in_phase(*t))
        .map(|(_, c)| c)
        .collect();
    let rss_peak = samples
        .iter()
        .filter(|s| in_phase(s.t_secs))
        .filter_map(|s| s.rss_bytes)
        .max()
        .map(|b| b as f64 / 1_048_576.0);
    PhaseStats {
        secs: window.len(),
        rps: ok as f64 / window.len() as f64,
        p50_us: percentile(&latencies, 0.50),
        p99_us: percentile(&latencies, 0.99),
        max_us: latencies.last().copied().unwrap_or(0),
        errors: window.iter().map(|b| b.errors).sum(),
        not_found: window.iter().map(|b| b.not_found).sum(),
        worst_second_rps: window.iter().map(|b| b.ok).min().unwrap_or(0),
        worst_second_p99_us,
        gateway_cpu_cores_mean: (!cores.is_empty())
            .then(|| cores.iter().sum::<f64>() / cores.len() as f64),
        gateway_cpu_cores_peak: cores.iter().copied().reduce(f64::max),
        gateway_rss_mib_peak: rss_peak,
        host_load_1m_peak: samples
            .iter()
            .filter(|s| in_phase(s.t_secs))
            .filter_map(|s| s.host_load_1m)
            .reduce(f64::max),
    }
}

/// Per-interval CPU used by every other process on the host: host-wide busy
/// cores minus the gateway's and this test process's (load generator + echo
/// backend) over the same one-second interval.
fn other_cpu_series(samples: &[ResourceSample]) -> Vec<(f64, f64)> {
    samples
        .windows(2)
        .filter_map(|w| {
            let (a, b) = (&w[0], &w[1]);
            let dt = b.t_secs - a.t_secs;
            let host = host_busy_cores(a.host_cpu_ticks?, b.host_cpu_ticks?)?;
            let own = (b.cpu_seconds? - a.cpu_seconds?) / dt
                + (b.client_cpu_seconds? - a.client_cpu_seconds?) / dt;
            Some((b.t_secs, (host - own).max(0.0)))
        })
        .collect()
}

fn second_points(buckets: &[LoadBucket], samples: &[ResourceSample]) -> Vec<SecondPoint> {
    let cores = cpu_cores_series(samples);
    let client_cores = cores_series(samples, |s| s.client_cpu_seconds);
    let other_cores = other_cpu_series(samples);
    buckets
        .iter()
        .enumerate()
        .map(|(t, b)| {
            let mut l = b.latencies_us.clone();
            l.sort_unstable();
            let in_second = |s: f64| s > t as f64 && s <= (t + 1) as f64;
            SecondPoint {
                t,
                ok: b.ok,
                errors: b.errors,
                p50_us: (!l.is_empty()).then(|| percentile(&l, 0.50)),
                p99_us: (!l.is_empty()).then(|| percentile(&l, 0.99)),
                gateway_cpu_cores: cores.iter().find(|(s, _)| in_second(*s)).map(|(_, c)| *c),
                gateway_rss_mib: samples
                    .iter()
                    .find(|s| in_second(s.t_secs))
                    .and_then(|s| s.rss_bytes)
                    .map(|b| b as f64 / 1_048_576.0),
                load_generator_cpu_cores: client_cores
                    .iter()
                    .find(|(s, _)| in_second(*s))
                    .map(|(_, c)| *c),
                host_load_1m: samples
                    .iter()
                    .find(|s| in_second(s.t_secs))
                    .and_then(|s| s.host_load_1m),
                other_cpu_cores: other_cores
                    .iter()
                    .find(|(s, _)| in_second(*s))
                    .map(|(_, c)| *c),
            }
        })
        .collect()
}

#[derive(serde::Serialize)]
struct ReloadWaveResult {
    /// `"full"`: 3k proxies + consumers. `"small+consumers"`: 100 proxies +
    /// `key_auth` consumers. `"small-proxies"`: 100 proxies admitting existing
    /// consumers. Both small kinds take the incremental reload path.
    kind: &'static str,
    proxies_before: usize,
    proxies_after: usize,
    /// Admin resources written (consumer + proxy + two plugin configs per proxy).
    resources: usize,
    /// Seconds spent waiting for a quiet host before this change (opt-in).
    quiet_wait_secs: f64,
    /// Cores other processes used during the change window (host busy CPU
    /// minus the gateway and this test process): mean and worst second.
    other_cpu_cores_mean: Option<f64>,
    other_cpu_cores_peak: Option<f64>,
    /// Seconds from load start: write began, write finished, apply confirmed,
    /// new routes probed live.
    write_start_secs: f64,
    write_end_secs: f64,
    applied_secs: f64,
    live_secs: f64,
    steady: PhaseStats,
    /// Admin writes + apply + convergence, under load.
    change: PhaseStats,
    /// Only the reload: from the last admin write to confirmed apply.
    apply: PhaseStats,
    post: PhaseStats,
    series: Vec<SecondPoint>,
}

/// Write one wave, then prove it is applied and routable. Returns the new
/// entries and the (write end, applied, live) instants.
async fn provision_wave(
    harness: &ScalePerfHarness,
    client: &reqwest::Client,
    auth_header: &str,
    all_entries: &mut Vec<(String, String)>,
    batch_start: usize,
    batch_end: usize,
    reuse_consumers: Option<Vec<(String, String)>>,
) -> (Instant, Instant, Instant) {
    let (new_entries, cursor) = match reuse_consumers {
        Some(reuse) => {
            create_proxy_only_batch(
                client,
                &harness.admin_base_url,
                auth_header,
                harness.backend_port,
                batch_start,
                batch_end,
                &reuse,
            )
            .await
        }
        None => {
            create_batch(
                client,
                &harness.admin_base_url,
                auth_header,
                harness.backend_port,
                batch_start,
                batch_end,
            )
            .await
        }
    }
    .expect("Failed to create batch");
    let written = Instant::now();
    if let Some(cursor) = cursor {
        wait_for_batch_apply_cursor(
            client,
            &harness.admin_base_url,
            auth_header,
            cursor,
            "the reload-under-load harness",
        )
        .await
        .unwrap_or_else(|error| panic!("Wave {batch_start}..{batch_end} never applied: {error}"));
    }
    let applied = Instant::now();
    let first_new = all_entries.len();
    all_entries.extend(new_entries);
    let sample_indices = convergence_sample_indices(first_new, all_entries.len());
    wait_for_scale_config_convergence(
        client,
        &harness.proxy_base_url,
        all_entries,
        &sample_indices,
    )
    .await
    .unwrap_or_else(|error| panic!("Wave {batch_start}..{batch_end} never converged: {error}"));
    (written, applied, Instant::now())
}

fn fmt_ms(us: u32) -> String {
    format!("{:.1}", us as f64 / 1000.0)
}

fn fmt_opt(v: Option<f64>, digits: usize) -> String {
    v.map(|v| format!("{v:.digits$}"))
        .unwrap_or_else(|| "n/a".into())
}

/// Hold load on every live proxy while `batch_start..batch_end` is written and
/// applied, and measure steady / change / apply / post phases.
#[allow(clippy::too_many_arguments)]
async fn measure_change_under_load(
    harness: &ScalePerfHarness,
    client: &reqwest::Client,
    auth_header: &str,
    pid: u32,
    all_entries: &mut Vec<(String, String)>,
    kind: &'static str,
    batch_start: usize,
    batch_end: usize,
) -> ReloadWaveResult {
    let reuse_consumers =
        (kind == "small-proxies").then(|| all_entries[..RELOAD_SMALL_CHANGE_PROXIES].to_vec());
    let consumers_per_proxy = if reuse_consumers.is_some() { 0 } else { 1 };
    let quiet_wait_secs = wait_for_quiet_host().await;
    let live = Arc::new(all_entries.clone());
    let proxies_before = live.len();
    println!(
        "\n--- {} change: +{} proxies under load ({} live proxies, concurrency {}) ---",
        kind,
        batch_end - batch_start,
        proxies_before,
        CONCURRENCY
    );
    let started = Instant::now();
    let sampler_stop = Arc::new(AtomicBool::new(false));
    let sampler = start_resource_sampler(pid, started, sampler_stop.clone());
    let load = start_live_load(&harness.proxy_base_url, live, CONCURRENCY, started);

    tokio::time::sleep(Duration::from_secs(RELOAD_WARMUP_SECS + RELOAD_STEADY_SECS)).await;
    let write_start = Instant::now();
    let (written, applied, live_at) = provision_wave(
        harness,
        client,
        auth_header,
        all_entries,
        batch_start,
        batch_end,
        reuse_consumers,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(RELOAD_POST_SECS)).await;
    let buckets = load.finish().await;
    sampler_stop.store(true, Ordering::Relaxed);
    let samples = sampler.await.unwrap_or_default();

    let at = |i: Instant| i.duration_since(started).as_secs_f64();
    let (ws, we, ap, lv) = (at(write_start), at(written), at(applied), at(live_at));
    let steady_from = RELOAD_WARMUP_SECS as usize;
    let steady = phase_stats(&buckets, &samples, steady_from, ws.floor() as usize);
    let change = phase_stats(&buckets, &samples, ws.floor() as usize, lv.ceil() as usize);
    let apply = phase_stats(&buckets, &samples, we.floor() as usize, ap.ceil() as usize);
    let post = phase_stats(
        &buckets,
        &samples,
        lv.ceil() as usize,
        lv.ceil() as usize + RELOAD_POST_SECS as usize - 1,
    );
    println!(
        "  write {:.1}s, apply {:.1}s, live after {:.1}s",
        we - ws,
        ap - we,
        lv - ap
    );
    println!(
        "  {:<8} {:>9} {:>9} {:>8} {:>8} {:>9} {:>7} {:>9} {:>9}",
        "phase", "rps", "worst/s", "p50 ms", "p99 ms", "worst p99", "errors", "cpu peak", "rss MiB"
    );
    for (name, s) in [
        ("steady", &steady),
        ("change", &change),
        ("apply", &apply),
        ("post", &post),
    ] {
        println!(
            "  {:<8} {:>9.0} {:>9} {:>8} {:>8} {:>9} {:>7} {:>9} {:>9}",
            name,
            s.rps,
            s.worst_second_rps,
            fmt_ms(s.p50_us),
            fmt_ms(s.p99_us),
            fmt_ms(s.worst_second_p99_us),
            s.errors,
            fmt_opt(s.gateway_cpu_cores_peak, 2),
            fmt_opt(s.gateway_rss_mib_peak, 0)
        );
    }
    // Other processes' CPU, measured per second over the change window (host
    // busy cores minus this test's gateway and load generator), so both a
    // sustained competing build and a short burst inside the apply are seen.
    let other_cores: Vec<f64> = other_cpu_series(&samples)
        .into_iter()
        .filter(|(t, _)| *t > ws && *t <= lv.ceil())
        .map(|(_, c)| c)
        .collect();
    let other_cpu_cores_mean = (!other_cores.is_empty())
        .then(|| other_cores.iter().sum::<f64>() / other_cores.len() as f64);
    let other_cpu_cores_peak = other_cores.iter().copied().reduce(f64::max);
    println!(
        "  other processes' CPU during the change: mean {} cores, peak {} cores",
        fmt_opt(other_cpu_cores_mean, 1),
        fmt_opt(other_cpu_cores_peak, 1)
    );
    if other_cpu_cores_mean.is_some_and(|c| c > 2.0)
        || other_cpu_cores_peak.is_some_and(|c| c > 4.0)
    {
        println!(
            "  WARNING: other processes used more than 2 cores on average (or 4 in one \
             second) during this change; its numbers are noisy"
        );
    }
    if steady.rps > 0.0 && (change.worst_second_rps as f64) < steady.rps * 0.5 {
        println!("  WARNING: a second during the change ran below 50% of steady RPS");
    }
    if steady.p99_us > 0 && change.worst_second_p99_us > steady.p99_us * 10 {
        println!("  WARNING: a second during the change had p99 above 10x steady p99");
    }
    let total_errors: u64 = buckets.iter().map(|b| b.errors).sum();
    assert_eq!(
        total_errors,
        0,
        "{} request(s) to already-live proxies failed while a {} change of {} proxies \
         was applied at {} proxies ({} route-miss 404s)",
        total_errors,
        kind,
        batch_end - batch_start,
        proxies_before,
        buckets.iter().map(|b| b.not_found).sum::<u64>()
    );
    ReloadWaveResult {
        kind,
        proxies_before,
        proxies_after: all_entries.len(),
        resources: (batch_end - batch_start) * (3 + consumers_per_proxy),
        quiet_wait_secs,
        other_cpu_cores_mean,
        other_cpu_cores_peak,
        write_start_secs: ws,
        write_end_secs: we,
        applied_secs: ap,
        live_secs: lv,
        steady,
        change,
        apply,
        post,
        series: second_points(&buckets, &samples),
    }
}

async fn run_reload_under_load_test(harness: &ScalePerfHarness, total_proxies: usize) {
    let pid = harness
        .gateway_process
        .as_ref()
        .map(Child::id)
        .expect("gateway process");
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(Duration::from_secs(300))
        .build()
        .expect("admin client");
    let token = harness.generate_token().expect("Failed to generate JWT");
    let auth_header = format!("Bearer {token}");
    let mut all_entries: Vec<(String, String)> = Vec::with_capacity(total_proxies);

    println!(
        "\n--- Initial wave: proxies 0 to {} (no load) ---",
        BATCH_SIZE - 1
    );
    provision_wave(
        harness,
        &client,
        &auth_header,
        &mut all_entries,
        0,
        BATCH_SIZE,
        None,
    )
    .await;

    // After the initial wave and after every full wave: one small change with
    // new consumers, then one proxies-only small change; then the next wave.
    let mut waves: Vec<ReloadWaveResult> = Vec::new();
    let mut with_consumers_next = RELOAD_SMALL_WITH_CONSUMERS_BASE;
    let mut proxies_only_next = RELOAD_SMALL_PROXIES_ONLY_BASE;
    let mut batch_start = BATCH_SIZE;
    loop {
        for (kind, next) in [
            ("small+consumers", &mut with_consumers_next),
            ("small-proxies", &mut proxies_only_next),
        ] {
            let end = *next + RELOAD_SMALL_CHANGE_PROXIES;
            waves.push(
                measure_change_under_load(
                    harness,
                    &client,
                    &auth_header,
                    pid,
                    &mut all_entries,
                    kind,
                    *next,
                    end,
                )
                .await,
            );
            *next = end;
            write_reload_results(harness, total_proxies, &waves, false);
        }
        if batch_start >= total_proxies {
            break;
        }
        waves.push(
            measure_change_under_load(
                harness,
                &client,
                &auth_header,
                pid,
                &mut all_entries,
                "full",
                batch_start,
                batch_start + BATCH_SIZE,
            )
            .await,
        );
        write_reload_results(harness, total_proxies, &waves, false);
        batch_start += BATCH_SIZE;
    }

    println!("\n\n======================================================================");
    println!("  RELOAD UNDER LOAD SUMMARY ({})", harness.db_label);
    println!("======================================================================");
    println!(
        "{:<22} {:>7} {:>8} {:>8} {:>8} {:>7} {:>8} {:>7} {:>7} {:>7} {:>7}",
        "Change",
        "live",
        "steady",
        "change",
        "worst/s",
        "p99 ms",
        "worst99",
        "apply s",
        "cpu pk",
        "rss pk",
        "errors"
    );
    for w in &waves {
        println!(
            "{:<22} {:>7} {:>8.0} {:>8.0} {:>8} {:>7} {:>8} {:>7.1} {:>7} {:>7} {:>7}",
            format!("{} +{}", w.kind, w.proxies_after - w.proxies_before),
            w.proxies_before,
            w.steady.rps,
            w.change.rps,
            w.change.worst_second_rps,
            fmt_ms(w.steady.p99_us),
            fmt_ms(w.change.worst_second_p99_us),
            w.applied_secs - w.write_end_secs,
            fmt_opt(w.change.gateway_cpu_cores_peak, 2),
            fmt_opt(w.change.gateway_rss_mib_peak, 0),
            w.change.errors + w.post.errors + w.steady.errors
        );
    }

    write_reload_results(harness, total_proxies, &waves, true);
}

/// Write `FERRUM_RELOAD_RESULTS_JSON` (after every change, so an interrupted run
/// keeps the changes it finished).
fn write_reload_results(
    harness: &ScalePerfHarness,
    total_proxies: usize,
    waves: &[ReloadWaveResult],
    complete: bool,
) {
    let Ok(path) = std::env::var("FERRUM_RELOAD_RESULTS_JSON") else {
        return;
    };
    let document = json!({
        "test": "tests/functional/functional_scale_perf_test.rs::test_scale_reload_under_load",
        "database": harness.db_label,
        "complete": complete,
        "finished_utc": Utc::now().to_rfc3339(),
        "git_commit": Command::new("git").args(["rev-parse", "HEAD"]).output().ok()
            .and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "logical_cpus": std::thread::available_parallelism().map(|n| n.get()).ok(),
        "batch_size": BATCH_SIZE,
        "small_change_proxies": RELOAD_SMALL_CHANGE_PROXIES,
        "total_proxies": total_proxies,
        "concurrency": CONCURRENCY,
        "warmup_secs": RELOAD_WARMUP_SECS,
        "steady_secs": RELOAD_STEADY_SECS,
        "post_secs": RELOAD_POST_SECS,
        "changes": waves,
    });
    let written = std::fs::write(
        &path,
        serde_json::to_string_pretty(&document).unwrap_or_default() + "\n",
    );
    match (written, complete) {
        (Ok(()), true) => println!("Wrote reload results to {path}"),
        (Ok(()), false) => {}
        (Err(error), _) => eprintln!("Could not write {path}: {error}"),
    }
}

/// `FERRUM_SCALE_TOTAL_PROXIES` shortens a local run (a multiple of the batch
/// size, at least two batches); the default is the full 30k.
fn reload_total_proxies() -> usize {
    let total = std::env::var("FERRUM_SCALE_TOTAL_PROXIES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(TOTAL_PROXIES);
    assert!(
        total >= 2 * BATCH_SIZE && total.is_multiple_of(BATCH_SIZE),
        "FERRUM_SCALE_TOTAL_PROXIES must be a multiple of {BATCH_SIZE} and at least {}",
        2 * BATCH_SIZE
    );
    total
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_scale_reload_under_load() {
    let total = reload_total_proxies();
    println!("\n============================================================");
    println!("  Reload Under Load (SQLite): waves of {BATCH_SIZE} up to {total} proxies");
    println!(
        "  Load: {CONCURRENCY} workers on every live proxy | {RELOAD_WARMUP_SECS}s warmup, \
         {RELOAD_STEADY_SECS}s steady, change, {RELOAD_POST_SECS}s post"
    );
    println!("============================================================\n");
    let harness = ScalePerfHarness::new_sqlite()
        .await
        .expect("Failed to create test harness");
    run_reload_under_load_test(&harness, total).await;
}

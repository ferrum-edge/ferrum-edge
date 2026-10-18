//! Comprehensive Load & Stress Test — realistic traffic patterns with mixed auth,
//! varied payload sizes, and mid-flight admin API config updates.
//!
//! This test provisions 10k proxies with 30k plugins (auth + access_control +
//! rate_limiting per proxy) and 10k consumers, then drives sustained traffic
//! with a variety of:
//!
//! - Small JSON payloads (~100 bytes)
//! - Medium JSON payloads (~5 KB)
//! - Large JSON payloads (~50 KB)
//! - XML payloads (~10 KB)
//! - Multipart/form-data file uploads (~100 KB)
//! - GET requests (no body)
//!
//! Auth is exercised via key_auth (header), basic_auth (HMAC), and jwt_auth spread across
//! proxies so all credential types are exercised under load.
//!
//! Mid-test, admin API mutations (create/update/delete proxies) are injected to
//! measure latency impact during config reload.
//!
//! Concurrency ramps from 50 → 100 → 200 → 400 to find the breaking point.
//!
//! **Build**: Uses a release build (`cargo build --release`) for production-realistic numbers.
//! **Backend**: High-throughput hyper-based backend (no simulated latency, instant responses).
//! **Database**: Defaults to PostgreSQL if `ferrum-load-test-pg` container is running,
//!              falls back to SQLite otherwise.
//!
//! Run with:
//!   cargo build --release --bin ferrum-edge
//!   cargo test --test functional_tests test_load_stress_10k_proxies -- --ignored --nocapture

use crate::scaffolding::port_registry::TestSocket;

use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::convert::Infallible;
use std::io::Write;
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use uuid::Uuid;

use crate::common::scheduled_scaling::{
    BatchApplyCursor, CONFIG_CONVERGENCE_MAX_WAIT_SECS, LIVE_APPLY_CURSOR_MAX_WAIT_SECS,
    SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS, post_admin_batch,
    scheduled_scaling_admin_jwt_max_ttl_value, wait_for_batch_apply_cursor,
    wait_for_config_convergence,
};

// --- Configuration constants ---

/// Number of proxies to create (each gets 3 plugins = 30k total plugins)
const NUM_PROXIES: usize = 10_000;
/// Number of consumers to create
const NUM_CONSUMERS: usize = 10_000;
/// Number of open (no-plugin) proxies for baseline measurement
const NUM_OPEN_PROXIES: usize = 1000;
/// Resources per batch API call
const API_BATCH_CHUNK: usize = 100;
/// Duration of each load phase in seconds
const PHASE_DURATION_SECS: u64 = 30;
/// Concurrency levels to ramp through
const CONCURRENCY_LEVELS: &[usize] = &[50, 100, 200, 400];
/// Duration of the mid-flight admin mutation phase
const ADMIN_MUTATION_PHASE_SECS: u64 = 30;
/// Concurrency during admin mutation phase
const ADMIN_MUTATION_CONCURRENCY: usize = 100;

// --- Auth distribution: proxies are split into 3 auth groups ---

/// Proxies 0..3333 use key_auth
const KEY_AUTH_END: usize = NUM_PROXIES / 3;
/// Proxies 3333..6666 use basic_auth
const BASIC_AUTH_END: usize = (NUM_PROXIES * 2) / 3;
// Proxies 6666..10000 use jwt_auth

// --- Payload templates ---

fn small_json_payload() -> String {
    json!({
        "event": "page_view",
        "user_id": 42,
        "timestamp": "2026-03-29T12:00:00Z",
        "metadata": {"page": "/home", "referrer": "google"}
    })
    .to_string()
}

fn medium_json_payload() -> String {
    let items: Vec<serde_json::Value> = (0..50)
        .map(|i| {
            json!({
                "id": i,
                "name": format!("Product {}", i),
                "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore.",
                "price": 19.99 + i as f64,
                "category": if i % 3 == 0 { "electronics" } else if i % 3 == 1 { "clothing" } else { "food" },
                "tags": ["sale", "popular", "new"],
                "inventory": { "warehouse_a": 100 + i, "warehouse_b": 50 + i }
            })
        })
        .collect();
    json!({ "products": items, "page": 1, "total": 500 }).to_string()
}

fn large_json_payload() -> String {
    let records: Vec<serde_json::Value> = (0..200)
        .map(|i| {
            json!({
                "id": format!("rec-{}", i),
                "timestamp": "2026-03-29T12:00:00Z",
                "source": "sensor-array-alpha",
                "measurements": {
                    "temperature": 22.5 + (i as f64 * 0.1),
                    "humidity": 45.0 + (i as f64 * 0.05),
                    "pressure": 1013.25,
                    "wind_speed": 12.3,
                    "wind_direction": "NNW"
                },
                "location": {
                    "latitude": 37.7749 + (i as f64 * 0.001),
                    "longitude": -122.4194 + (i as f64 * 0.001),
                    "altitude_m": 15.0
                },
                "notes": "Automated reading from environmental monitoring station. All values within normal operating parameters. No anomalies detected during this sampling period.",
                "quality_flags": ["validated", "calibrated", "peer_reviewed"],
                "raw_data": format!("{:0>128}", i)
            })
        })
        .collect();
    json!({
        "batch_id": "batch-20260329-001",
        "records": records,
        "metadata": {
            "schema_version": "2.1",
            "encoding": "UTF-8",
            "compression": "none"
        }
    })
    .to_string()
}

fn xml_payload() -> String {
    let mut xml = String::with_capacity(12_000);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<order xmlns=\"urn:example:order:v1\">\n");
    xml.push_str("  <header>\n");
    xml.push_str("    <orderId>ORD-2026-0329-001</orderId>\n");
    xml.push_str("    <customerId>CUST-42</customerId>\n");
    xml.push_str("    <orderDate>2026-03-29</orderDate>\n");
    xml.push_str("    <currency>USD</currency>\n");
    xml.push_str("  </header>\n");
    xml.push_str("  <items>\n");
    for i in 0..40 {
        xml.push_str(&format!(
            "    <item sku=\"SKU-{:04}\" quantity=\"{}\">\n      <name>Widget Type {}</name>\n      <unitPrice>{:.2}</unitPrice>\n      <description>High-quality widget for industrial applications with premium finish and extended warranty coverage.</description>\n    </item>\n",
            i, (i % 5) + 1, i, 9.99 + i as f64
        ));
    }
    xml.push_str("  </items>\n");
    xml.push_str("  <shipping>\n");
    xml.push_str("    <method>express</method>\n");
    xml.push_str("    <address>123 Main St, San Francisco, CA 94105</address>\n");
    xml.push_str("  </shipping>\n");
    xml.push_str("</order>");
    xml
}

fn multipart_file_payload() -> (String, Vec<u8>) {
    let boundary = "----FormBoundary7MA4YWxkTrZu0gW";
    // ~100KB of pseudo-binary data (repeated pattern)
    let file_data: Vec<u8> = (0..100_000u32)
        .map(|i| ((i * 7 + 13) % 256) as u8)
        .collect();
    let file_b64 = base64_encode_simple(&file_data);

    let mut body = Vec::with_capacity(file_data.len() + 1024);
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(
        json!({"filename": "report.bin", "type": "binary", "size": file_data.len()})
            .to_string()
            .as_bytes(),
    );
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.bin\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file_b64.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

    let content_type = format!("multipart/form-data; boundary={}", boundary);
    (content_type, body)
}

/// Simple base64 encoder (avoids adding a dependency)
fn base64_encode_simple(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

// --- High-throughput backend server (hyper-based) ---

/// Handle a single request: read+discard body, return a small JSON response.
/// No simulated latency — measures gateway overhead, not backend time.
async fn handle_backend_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    // Read and discard the full request body (important for POST/PUT with large payloads)
    let body_size = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes().len(),
        Err(_) => 0,
    };

    let response_body = format!(
        r#"{{"status":"ok","method":"{}","path":"{}","body_size":{}}}"#,
        method, path, body_size
    );

    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .header("Connection", "keep-alive")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

/// Start a high-throughput hyper backend on the given port.
/// Returns a JoinHandle that runs until the tokio runtime shuts down.
async fn start_hyper_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let io = TokioIo::new(stream);
            tokio::spawn(async move {
                let conn = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service_fn(handle_backend_request));
                let _ = conn.await;
            });
        }
    });

    Ok(handle)
}

// --- Test harness ---

#[allow(dead_code)]
struct LoadTestHarness {
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
    basic_auth_hmac_secret: String,
    backend_pool_http2: bool,
}

impl LoadTestHarness {
    async fn new_sqlite(enable_http2: bool) -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new_sqlite(enable_http2).await {
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

    async fn try_new_sqlite(enable_http2: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("load_test.db");
        let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
        Self::try_start(temp_dir, "sqlite", &db_url, "SQLite", enable_http2).await
    }

    async fn new_postgres(
        db_url: &str,
        enable_http2: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new_postgres(db_url, enable_http2).await {
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

    async fn try_new_postgres(
        db_url: &str,
        enable_http2: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        Self::try_start(temp_dir, "postgres", db_url, "PostgreSQL", enable_http2).await
    }

    async fn try_start(
        temp_dir: TempDir,
        db_type: &str,
        db_url: &str,
        db_label: &str,
        enable_http2: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let identity = crate::common::SpawnedGatewayIdentity::mint("load-stress");
        let jwt_secret = identity.jwt_secret.clone();
        let jwt_issuer = identity.jwt_issuer.clone();
        let observability_token = identity.observability_token.clone();
        let basic_auth_hmac_secret = "load-test-hmac-secret-54321-0123456789".to_string();

        let admin_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0").await?;
        let backend_port = backend_listener.local_addr()?.port();
        drop(backend_listener);

        // Start high-throughput hyper backend and verify it's listening
        start_hyper_backend(backend_port).await?;
        let echo_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", backend_port)).await {
                Ok(_) => break,
                Err(_) if Instant::now() < echo_deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(e) => return Err(format!("Backend failed to start: {}", e).into()),
            }
        }

        // Prefer release binary for production-realistic numbers
        let binary_path =
            crate::common::locate_binary(true).map_err(|e| -> Box<dyn std::error::Error> { e })?;
        if binary_path.starts_with("./target/release") {
            println!("Using release binary");
        } else {
            println!(
                "WARNING: Using {} — run `cargo build --release --bin ferrum-edge` for accurate perf numbers",
                binary_path.display()
            );
        }

        // Run migrations for postgres
        if db_type == "postgres" {
            let migrate_status = Command::new(&binary_path)
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

        let mut cmd = Command::new(&binary_path);
        cmd.arg("run");
        cmd.env("FERRUM_MODE", "database")
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
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_BASIC_AUTH_HMAC_SECRET", &basic_auth_hmac_secret)
            // Connection pool tuning for high throughput
            .env("FERRUM_POOL_MAX_IDLE_PER_HOST", "1024")
            .env("FERRUM_POOL_IDLE_TIMEOUT_SECONDS", "120")
            .env("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE", "true")
            .env(
                "FERRUM_POOL_ENABLE_HTTP2",
                if enable_http2 { "true" } else { "false" },
            )
            // Frontend HTTP/2 flow control — large trusted-client windows for load testing
            .env("FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE", "8388608")
            .env(
                "FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE",
                "33554432",
            )
            .env("FERRUM_FRONTEND_H2_MAX_FRAME_SIZE", "1048576")
            // Backend HTTP/2 pool flow control tuning
            .env("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE", "8388608")
            .env(
                "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE",
                "33554432",
            )
            .env("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW", "false")
            .env("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE", "65535")
            .env("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS", "1000")
            // Frontend HTTP/3 — large trusted-client windows for load testing
            .env("FERRUM_HTTP3_MAX_STREAMS", "1000")
            .env("FERRUM_HTTP3_STREAM_RECEIVE_WINDOW", "8388608")
            .env("FERRUM_HTTP3_RECEIVE_WINDOW", "33554432")
            .env("FERRUM_HTTP3_SEND_WINDOW", "8388608")
            .env("FERRUM_LOG_LEVEL", "error");
        identity.apply_to_command(&mut cmd);
        let child = cmd.spawn()?;

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
            basic_auth_hmac_secret,
            backend_pool_http2: enable_http2,
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

    fn generate_admin_token(&self) -> Result<String, Box<dyn std::error::Error>> {
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

impl Drop for LoadTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// --- Auth entry types ---

/// Represents a provisioned proxy + consumer pair with the auth info needed to call it.
#[derive(Clone)]
#[allow(clippy::enum_variant_names)]
enum AuthEntry {
    KeyAuth {
        listen_path: String,
        api_key: String,
    },
    BasicAuth {
        listen_path: String,
        username: String,
        password: String,
    },
    JwtAuth {
        listen_path: String,
        consumer_username: String,
        jwt_secret: String,
    },
}

impl AuthEntry {
    fn listen_path(&self) -> &str {
        match self {
            AuthEntry::KeyAuth { listen_path, .. } => listen_path,
            AuthEntry::BasicAuth { listen_path, .. } => listen_path,
            AuthEntry::JwtAuth { listen_path, .. } => listen_path,
        }
    }
}

/// Credential material for one bounded convergence probe.
///
/// The probe future must own everything it uses, so the borrowed `AuthEntry`
/// is projected into this before the request is built.
enum SampleAuth {
    KeyAuth(String),
    BasicAuth(String, String),
    Bearer(String),
}

// --- Consumer JWT generation ---

fn generate_consumer_jwt(username: &str, secret: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "sub": username,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).expect("Failed to encode consumer JWT")
}

// --- Resource provisioning ---

/// Provision all resources: 10k proxies, 10k consumers, 30k plugins, plus open proxies.
/// Returns (auth_entries, open_proxy_paths, covering_live_apply_cursor).
///
/// Every chunk posts with `?apply=async` (issue #4139), so provisioning never
/// pays a synchronous poll-loop reload per chunk; the caller proves the whole
/// graph live with one blocking `GET /config/apply-status` on the returned
/// cursor before its data-plane convergence gates run.
async fn provision_resources(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    backend_port: u16,
) -> Result<(Vec<AuthEntry>, Vec<String>, Option<BatchApplyCursor>), Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    let mut entries: Vec<AuthEntry> = Vec::with_capacity(NUM_PROXIES);
    let mut last_cursor: Option<BatchApplyCursor> = None;

    // We provision in 4 phases to respect referential integrity:
    // Phase 1: Consumers, with their credentials carried inline (batch)
    // Phase 2: Proxies (batch)
    // Phase 3: Plugin configs (batch)
    // Phase 4: Open proxies for the no-plugin baseline (batch)
    //
    // Credentials ride the atomic consumer batch rather than 10,000 separate
    // `PUT /consumers/{id}/credentials/{type}` calls (issue #4116). `POST
    // /batch` runs every consumer through the same
    // `prepare_for_write` -> `hash_consumer_secrets` path the credential
    // endpoint uses, so Basic-auth passwords are hashed identically. The
    // per-consumer path issued 10,000 individual namespace mutations against a
    // deliberately serialized admission critical section, which is what
    // manufactured the transient-contention 503s this harness then reported as
    // a provisioning failure — and it logged those failures to stderr while
    // still returning an `AuthEntry` for a credential that was never
    // persisted, so the measurement ran against consumers that could not
    // authenticate.

    println!(
        "  Phase 1: Creating {} consumers with inline credentials...",
        NUM_CONSUMERS
    );
    let phase_start = Instant::now();
    let mut all_consumers = Vec::with_capacity(NUM_CONSUMERS);
    for i in 0..NUM_CONSUMERS {
        let consumer_id = format!("consumer-{}", i);
        let username = format!("user-{}", i);
        let listen_path = format!("/svc/{}", i);

        let (credentials, entry) = if i < KEY_AUTH_END {
            let api_key = format!("key-{}-{}", i, Uuid::new_v4().as_simple());
            (
                json!({ "keyauth": [{ "key": api_key.clone() }] }),
                AuthEntry::KeyAuth {
                    listen_path,
                    api_key,
                },
            )
        } else if i < BASIC_AUTH_END {
            let password = format!("pass-{}", i);
            (
                json!({ "basicauth": [{ "password": password.clone() }] }),
                AuthEntry::BasicAuth {
                    listen_path,
                    username: username.clone(),
                    password,
                },
            )
        } else {
            let jwt_secret = format!(
                "jwt-secret-padding-1234567890-{}-{}",
                i,
                &Uuid::new_v4().to_string()[..8]
            );
            (
                json!({ "jwt": [{ "secret": jwt_secret.clone() }] }),
                AuthEntry::JwtAuth {
                    listen_path,
                    consumer_username: username.clone(),
                    jwt_secret,
                },
            )
        };

        entries.push(entry);
        all_consumers.push(json!({
            "id": consumer_id,
            "username": username,
            "credentials": credentials,
        }));
    }
    // `POST /batch?apply=async` is all-or-nothing and succeeds only with the
    // deferred 202 (durably committed, cursor returned). Only the documented
    // all-or-nothing 503s are retried, so repeating the same atomic body
    // cannot accept or compound a partial graph.
    for chunk in all_consumers.chunks(API_BATCH_CHUNK) {
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &json!({ "consumers": chunk }),
            "Batch consumer create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }
    println!(
        "    Created {} consumers with credentials in {:.1}s",
        NUM_CONSUMERS,
        phase_start.elapsed().as_secs_f64()
    );

    println!("  Phase 2: Creating {} proxies...", NUM_PROXIES);
    let phase_start = Instant::now();
    let mut all_proxies = Vec::with_capacity(NUM_PROXIES);
    for i in 0..NUM_PROXIES {
        all_proxies.push(json!({
            "id": format!("proxy-{}", i),
            "listen_path": format!("/svc/{}", i),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }));
    }
    for chunk in all_proxies.chunks(API_BATCH_CHUNK) {
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &json!({ "proxies": chunk }),
            "Batch proxy create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }
    println!(
        "    Created {} proxies in {:.1}s",
        NUM_PROXIES,
        phase_start.elapsed().as_secs_f64()
    );

    println!(
        "  Phase 3: Creating {} plugins (3 per proxy)...",
        NUM_PROXIES * 3
    );
    let phase_start = Instant::now();
    let mut all_plugins = Vec::with_capacity(NUM_PROXIES * 3);

    for i in 0..NUM_PROXIES {
        let proxy_id = format!("proxy-{}", i);
        let username = format!("user-{}", i);

        if i < KEY_AUTH_END {
            // key_auth group
            all_plugins.push(json!({
                "id": format!("keyauth-{}", i),
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": proxy_id,
                "enabled": true,
                "config": { "key_location": "header:X-API-Key" }
            }));
        } else if i < BASIC_AUTH_END {
            // basic_auth group
            all_plugins.push(json!({
                "id": format!("basicauth-{}", i),
                "plugin_name": "basic_auth",
                "scope": "proxy",
                "proxy_id": proxy_id,
                "enabled": true,
                "config": {}
            }));
        } else {
            // jwt_auth group
            all_plugins.push(json!({
                "id": format!("jwtauth-{}", i),
                "plugin_name": "jwt_auth",
                "scope": "proxy",
                "proxy_id": proxy_id,
                "enabled": true,
                "config": {
                    "token_lookup": "header:Authorization",
                    "consumer_claim_field": "sub"
                }
            }));
        }

        // access_control for all proxies
        all_plugins.push(json!({
            "id": format!("acl-{}", i),
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": { "allowed_consumers": [username] }
        }));

        // rate_limiting for all proxies (high limit to not block traffic, but exercises the plugin)
        all_plugins.push(json!({
            "id": format!("ratelimit-{}", i),
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "limit_by": "consumer",
                "limits": [{"scope": "default", "requests_per_second": 10000}]
            }
        }));
    }

    for chunk in all_plugins.chunks(API_BATCH_CHUNK) {
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &json!({ "plugin_configs": chunk }),
            "Batch plugin create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }
    println!(
        "    Created {} plugins in {:.1}s",
        all_plugins.len(),
        phase_start.elapsed().as_secs_f64()
    );

    // Phase 4: Open proxies (no plugins) for baseline measurement
    println!(
        "  Phase 4: Creating {} open proxies (no plugins)...",
        NUM_OPEN_PROXIES
    );
    let phase_start = Instant::now();
    let mut open_proxies = Vec::with_capacity(NUM_OPEN_PROXIES);
    let mut open_paths = Vec::with_capacity(NUM_OPEN_PROXIES);
    for i in 0..NUM_OPEN_PROXIES {
        let path = format!("/open/{}", i);
        open_paths.push(path.clone());
        open_proxies.push(json!({
            "id": format!("open-proxy-{}", i),
            "listen_path": path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }));
    }
    for chunk in open_proxies.chunks(API_BATCH_CHUNK) {
        let cursor = post_admin_batch(
            client,
            admin_url,
            auth_header,
            &json!({ "proxies": chunk }),
            "Batch open proxy create",
        )
        .await?;
        last_cursor = last_cursor.max(cursor);
    }
    println!(
        "    Created {} open proxies in {:.1}s",
        NUM_OPEN_PROXIES,
        phase_start.elapsed().as_secs_f64()
    );

    println!(
        "\n  Total provisioning time: {:.1}s",
        total_start.elapsed().as_secs_f64()
    );
    println!(
        "  Resources: {} proxies ({} with plugins + {} open), {} consumers, {} plugins\n",
        NUM_PROXIES + NUM_OPEN_PROXIES,
        NUM_PROXIES,
        NUM_OPEN_PROXIES,
        NUM_CONSUMERS,
        NUM_PROXIES * 3
    );

    Ok((entries, open_paths, last_cursor))
}

// --- Perf result ---

/// What a `PerfResult`'s throughput, latency, and success numbers measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeasurementBoundary {
    /// reqwest phases: latency runs from request start to `send()`
    /// completion (response head received); the response body is never
    /// read, so a body error after a 2xx head is not counted as a failure. Success is a 2xx status. RPS is attempts
    /// (successes and failures) divided by wall time.
    ResponseHead,
    /// wrk phases: wrk's own `Requests/sec` and latency figures; failures are
    /// wrk's non-2xx/3xx responses plus socket errors.
    WrkReported,
}

impl MeasurementBoundary {
    fn rps_label(self) -> &'static str {
        match self {
            MeasurementBoundary::ResponseHead => "Attempt RPS",
            MeasurementBoundary::WrkReported => "wrk Requests/sec",
        }
    }

    fn latency_label(self) -> &'static str {
        match self {
            MeasurementBoundary::ResponseHead => {
                "Response-head latency (send() completion; body not read)"
            }
            MeasurementBoundary::WrkReported => "wrk-reported latency",
        }
    }

    fn success_label(self) -> &'static str {
        match self {
            MeasurementBoundary::ResponseHead => "2xx-status success rate",
            MeasurementBoundary::WrkReported => {
                "wrk success rate (non-2xx/3xx + socket errors fail)"
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PerfResult {
    label: String,
    concurrency: usize,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    duration_secs: f64,
    rps: f64,
    avg_latency_us: f64,
    p50_latency_us: f64,
    p95_latency_us: f64,
    p99_latency_us: f64,
    p999_latency_us: f64,
    max_latency_us: f64,
    boundary: MeasurementBoundary,
}

fn print_perf_result(r: &PerfResult) {
    println!("┌──────────────────────────────────────────────────────────────────┐");
    println!("│  {}  (concurrency={})", r.label, r.concurrency);
    println!("├──────────────────────────────────────────────────────────────────┤");
    println!(
        "│  Duration: {:.1}s  |  Total: {}  |  OK: {}  |  Fail: {}",
        r.duration_secs, r.total_requests, r.successful_requests, r.failed_requests
    );
    println!(
        "│  {}: {:.0}  |  {}: {:.1}%",
        r.boundary.rps_label(),
        r.rps,
        r.boundary.success_label(),
        if r.total_requests > 0 {
            r.successful_requests as f64 / r.total_requests as f64 * 100.0
        } else {
            0.0
        }
    );
    println!("├──────────────────────────────────────────────────────────────────┤");
    println!("│  {}", r.boundary.latency_label());
    println!(
        "│  Avg: {:>8.1}ms  P50: {:>7.1}ms  P95: {:>7.1}ms",
        r.avg_latency_us / 1000.0,
        r.p50_latency_us / 1000.0,
        r.p95_latency_us / 1000.0,
    );
    println!(
        "│  P99: {:>7.1}ms  P99.9: {:>7.1}ms  Max: {:>7.1}ms",
        r.p99_latency_us / 1000.0,
        r.p999_latency_us / 1000.0,
        r.max_latency_us / 1000.0,
    );
    println!("└──────────────────────────────────────────────────────────────────┘");
}

// --- Load test runner ---

/// Payload type distribution for traffic mixing
#[derive(Clone, Copy)]
enum PayloadType {
    None,       // GET, no body
    SmallJson,  // ~100 bytes
    MediumJson, // ~5 KB
    LargeJson,  // ~50 KB
    Xml,        // ~10 KB
    Multipart,  // ~100 KB
}

/// Run a load test with mixed payloads and auth types.
async fn run_load_phase(
    label: &str,
    proxy_base_url: &str,
    entries: &[AuthEntry],
    duration_secs: u64,
    concurrency: usize,
) -> Result<PerfResult, Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let total_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));
    let latencies: Arc<tokio::sync::Mutex<Vec<u64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(200_000)));

    let entries = Arc::new(entries.to_vec());

    // Pre-generate payloads (shared across workers)
    let small_json = Arc::new(small_json_payload());
    let medium_json = Arc::new(medium_json_payload());
    let large_json = Arc::new(large_json_payload());
    let xml = Arc::new(xml_payload());
    let (multipart_ct, multipart_body) = multipart_file_payload();
    let multipart_ct = Arc::new(multipart_ct);
    let multipart_body = Arc::new(multipart_body);

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
        let small_json = small_json.clone();
        let medium_json = medium_json.clone();
        let large_json = large_json.clone();
        let xml = xml.clone();
        let multipart_ct = multipart_ct.clone();
        let multipart_body = multipart_body.clone();

        handles.push(tokio::spawn(async move {
            // Per-worker client: each worker maintains its own persistent connection
            // to avoid pool lock contention. Keep-alive is on by default in reqwest.
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(2)
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_keepalive(Duration::from_secs(60))
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();

            let mut local_latencies = Vec::with_capacity(10_000);
            let mut idx = worker_id % entries.len();
            let mut request_counter: u64 = 0;

            while !stop.load(Ordering::Relaxed) {
                let entry = &entries[idx];
                let url = format!("{}{}", base_url, entry.listen_path());

                // Cycle through payload types based on request counter
                let payload_type = match request_counter % 6 {
                    0 => PayloadType::None,
                    1 => PayloadType::SmallJson,
                    2 => PayloadType::MediumJson,
                    3 => PayloadType::LargeJson,
                    4 => PayloadType::Xml,
                    5 => PayloadType::Multipart,
                    _ => PayloadType::None,
                };

                let req_start = Instant::now();

                let result = match entry {
                    AuthEntry::KeyAuth { api_key, .. } => {
                        let req = match payload_type {
                            PayloadType::None => {
                                client.get(&url).header("X-API-Key", api_key.as_str())
                            }
                            PayloadType::SmallJson => client
                                .post(&url)
                                .header("X-API-Key", api_key.as_str())
                                .header("Content-Type", "application/json")
                                .body(small_json.as_str().to_owned()),
                            PayloadType::MediumJson => client
                                .post(&url)
                                .header("X-API-Key", api_key.as_str())
                                .header("Content-Type", "application/json")
                                .body(medium_json.as_str().to_owned()),
                            PayloadType::LargeJson => client
                                .post(&url)
                                .header("X-API-Key", api_key.as_str())
                                .header("Content-Type", "application/json")
                                .body(large_json.as_str().to_owned()),
                            PayloadType::Xml => client
                                .post(&url)
                                .header("X-API-Key", api_key.as_str())
                                .header("Content-Type", "application/xml")
                                .body(xml.as_str().to_owned()),
                            PayloadType::Multipart => client
                                .post(&url)
                                .header("X-API-Key", api_key.as_str())
                                .header("Content-Type", multipart_ct.as_str())
                                .body(multipart_body.as_ref().clone()),
                        };
                        req.send().await
                    }
                    AuthEntry::BasicAuth {
                        username, password, ..
                    } => {
                        let req = match payload_type {
                            PayloadType::None => {
                                client.get(&url).basic_auth(username, Some(password))
                            }
                            PayloadType::SmallJson => client
                                .post(&url)
                                .basic_auth(username, Some(password))
                                .header("Content-Type", "application/json")
                                .body(small_json.as_str().to_owned()),
                            PayloadType::MediumJson => client
                                .post(&url)
                                .basic_auth(username, Some(password))
                                .header("Content-Type", "application/json")
                                .body(medium_json.as_str().to_owned()),
                            PayloadType::LargeJson => client
                                .post(&url)
                                .basic_auth(username, Some(password))
                                .header("Content-Type", "application/json")
                                .body(large_json.as_str().to_owned()),
                            PayloadType::Xml => client
                                .post(&url)
                                .basic_auth(username, Some(password))
                                .header("Content-Type", "application/xml")
                                .body(xml.as_str().to_owned()),
                            PayloadType::Multipart => client
                                .post(&url)
                                .basic_auth(username, Some(password))
                                .header("Content-Type", multipart_ct.as_str())
                                .body(multipart_body.as_ref().clone()),
                        };
                        req.send().await
                    }
                    AuthEntry::JwtAuth {
                        consumer_username,
                        jwt_secret,
                        ..
                    } => {
                        let token = generate_consumer_jwt(consumer_username, jwt_secret);
                        let bearer = format!("Bearer {}", token);
                        let req = match payload_type {
                            PayloadType::None => client.get(&url).header("Authorization", &bearer),
                            PayloadType::SmallJson => client
                                .post(&url)
                                .header("Authorization", &bearer)
                                .header("Content-Type", "application/json")
                                .body(small_json.as_str().to_owned()),
                            PayloadType::MediumJson => client
                                .post(&url)
                                .header("Authorization", &bearer)
                                .header("Content-Type", "application/json")
                                .body(medium_json.as_str().to_owned()),
                            PayloadType::LargeJson => client
                                .post(&url)
                                .header("Authorization", &bearer)
                                .header("Content-Type", "application/json")
                                .body(large_json.as_str().to_owned()),
                            PayloadType::Xml => client
                                .post(&url)
                                .header("Authorization", &bearer)
                                .header("Content-Type", "application/xml")
                                .body(xml.as_str().to_owned()),
                            PayloadType::Multipart => client
                                .post(&url)
                                .header("Authorization", &bearer)
                                .header("Content-Type", multipart_ct.as_str())
                                .body(multipart_body.as_ref().clone()),
                        };
                        req.send().await
                    }
                };

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

                request_counter += 1;
                idx = (idx + concurrency) % entries.len();
                if idx == worker_id % entries.len() {
                    idx = (idx + 1) % entries.len();
                }
            }

            // Merge local latencies
            let mut global = latencies.lock().await;
            global.extend_from_slice(&local_latencies);
        }));
    }

    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    stop.store(true, Ordering::Relaxed);

    // A worker that panicked (for example on client construction) did not
    // participate; propagate it instead of reporting a partial phase.
    for h in handles {
        h.await?;
    }
    let elapsed = start.elapsed().as_secs_f64();

    let total = total_requests.load(Ordering::Relaxed);
    let success = successful_requests.load(Ordering::Relaxed);
    let fail = failed_requests.load(Ordering::Relaxed);

    let mut lats = latencies.lock().await;
    lats.sort_unstable();

    let (avg, p50, p95, p99, p999, max) = if lats.is_empty() {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let sum: u64 = lats.iter().sum();
        let len = lats.len();
        (
            sum as f64 / len as f64,
            lats[len * 50 / 100] as f64,
            lats[len * 95 / 100] as f64,
            lats[len * 99 / 100] as f64,
            lats[len.saturating_mul(999) / 1000] as f64,
            *lats.last().unwrap() as f64,
        )
    };

    Ok(PerfResult {
        label: label.to_string(),
        concurrency,
        total_requests: total,
        successful_requests: success,
        failed_requests: fail,
        duration_secs: elapsed,
        rps: total as f64 / elapsed,
        avg_latency_us: avg,
        p50_latency_us: p50,
        p95_latency_us: p95,
        p99_latency_us: p99,
        p999_latency_us: p999,
        max_latency_us: max,
        boundary: MeasurementBoundary::ResponseHead,
    })
}

// --- No-plugin baseline load runner ---

/// Run a load test against open proxies (no auth, no plugins) to measure pure proxy overhead.
async fn run_open_proxy_phase(
    label: &str,
    proxy_base_url: &str,
    open_paths: &[String],
    duration_secs: u64,
    concurrency: usize,
) -> Result<PerfResult, Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));
    let total_requests = Arc::new(AtomicU64::new(0));
    let successful_requests = Arc::new(AtomicU64::new(0));
    let failed_requests = Arc::new(AtomicU64::new(0));
    let latencies: Arc<tokio::sync::Mutex<Vec<u64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(200_000)));

    let paths = Arc::new(open_paths.to_vec());

    // Pre-generate payloads (shared across workers)
    let small_json = Arc::new(small_json_payload());
    let medium_json = Arc::new(medium_json_payload());
    let large_json = Arc::new(large_json_payload());
    let xml = Arc::new(xml_payload());
    let (multipart_ct, multipart_body) = multipart_file_payload();
    let multipart_ct = Arc::new(multipart_ct);
    let multipart_body = Arc::new(multipart_body);

    let start = Instant::now();
    let mut handles = Vec::with_capacity(concurrency);

    for worker_id in 0..concurrency {
        let stop = stop.clone();
        let total_requests = total_requests.clone();
        let successful_requests = successful_requests.clone();
        let failed_requests = failed_requests.clone();
        let latencies = latencies.clone();
        let paths = paths.clone();
        let base_url = proxy_base_url.to_string();
        let small_json = small_json.clone();
        let medium_json = medium_json.clone();
        let large_json = large_json.clone();
        let xml = xml.clone();
        let multipart_ct = multipart_ct.clone();
        let multipart_body = multipart_body.clone();

        handles.push(tokio::spawn(async move {
            // Per-worker client with persistent connection
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(2)
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_keepalive(Duration::from_secs(60))
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();

            let mut local_latencies = Vec::with_capacity(10_000);
            let mut idx = worker_id % paths.len();
            let mut request_counter: u64 = 0;

            while !stop.load(Ordering::Relaxed) {
                let url = format!("{}{}", base_url, paths[idx]);

                // Same payload mix as the authed phases
                let payload_type = match request_counter % 6 {
                    0 => PayloadType::None,
                    1 => PayloadType::SmallJson,
                    2 => PayloadType::MediumJson,
                    3 => PayloadType::LargeJson,
                    4 => PayloadType::Xml,
                    5 => PayloadType::Multipart,
                    _ => PayloadType::None,
                };

                let req_start = Instant::now();

                let result = match payload_type {
                    PayloadType::None => client.get(&url).send().await,
                    PayloadType::SmallJson => {
                        client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(small_json.as_str().to_owned())
                            .send()
                            .await
                    }
                    PayloadType::MediumJson => {
                        client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(medium_json.as_str().to_owned())
                            .send()
                            .await
                    }
                    PayloadType::LargeJson => {
                        client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(large_json.as_str().to_owned())
                            .send()
                            .await
                    }
                    PayloadType::Xml => {
                        client
                            .post(&url)
                            .header("Content-Type", "application/xml")
                            .body(xml.as_str().to_owned())
                            .send()
                            .await
                    }
                    PayloadType::Multipart => {
                        client
                            .post(&url)
                            .header("Content-Type", multipart_ct.as_str())
                            .body(multipart_body.as_ref().clone())
                            .send()
                            .await
                    }
                };

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

                request_counter += 1;
                idx = (idx + 1) % paths.len();
            }

            // Merge local latencies
            let mut global = latencies.lock().await;
            global.extend_from_slice(&local_latencies);
        }));
    }

    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    stop.store(true, Ordering::Relaxed);

    // A worker that panicked (for example on client construction) did not
    // participate; propagate it instead of reporting a partial phase.
    for h in handles {
        h.await?;
    }
    let elapsed = start.elapsed().as_secs_f64();

    let total = total_requests.load(Ordering::Relaxed);
    let success = successful_requests.load(Ordering::Relaxed);
    let fail = failed_requests.load(Ordering::Relaxed);

    let mut lats = latencies.lock().await;
    lats.sort_unstable();

    let (avg, p50, p95, p99, p999, max) = if lats.is_empty() {
        (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    } else {
        let sum: u64 = lats.iter().sum();
        let len = lats.len();
        (
            sum as f64 / len as f64,
            lats[len * 50 / 100] as f64,
            lats[len * 95 / 100] as f64,
            lats[len * 99 / 100] as f64,
            lats[len.saturating_mul(999) / 1000] as f64,
            *lats.last().unwrap() as f64,
        )
    };

    Ok(PerfResult {
        label: label.to_string(),
        concurrency,
        total_requests: total,
        successful_requests: success,
        failed_requests: fail,
        duration_secs: elapsed,
        rps: total as f64 / elapsed,
        avg_latency_us: avg,
        p50_latency_us: p50,
        p95_latency_us: p95,
        p99_latency_us: p99,
        p999_latency_us: p999,
        max_latency_us: max,
        boundary: MeasurementBoundary::ResponseHead,
    })
}

// --- Admin mutation phase ---

/// One admin write issued by the mutation phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationOp {
    CreateProxy,
    CreatePlugin,
    UpdateProxy,
    DeletePlugin,
    DeleteProxy,
}

impl MutationOp {
    const ALL: [MutationOp; 5] = [
        MutationOp::CreateProxy,
        MutationOp::CreatePlugin,
        MutationOp::UpdateProxy,
        MutationOp::DeletePlugin,
        MutationOp::DeleteProxy,
    ];

    fn label(self) -> &'static str {
        match self {
            MutationOp::CreateProxy => "create_proxy",
            MutationOp::CreatePlugin => "create_plugin",
            MutationOp::UpdateProxy => "update_proxy",
            MutationOp::DeletePlugin => "delete_plugin",
            MutationOp::DeleteProxy => "delete_proxy",
        }
    }

    /// Documented success status for this write without `?apply=async`
    /// (`openapi.yaml`). The default `apply=sync` contract answers 2xx only
    /// after a covering `config_changes` generation is live on the gateway,
    /// so an accepted write is also bounded (client timeout) evidence that
    /// the change was applied.
    fn expected_status(self) -> u16 {
        match self {
            MutationOp::CreateProxy | MutationOp::CreatePlugin => 201,
            MutationOp::UpdateProxy => 200,
            MutationOp::DeletePlugin | MutationOp::DeleteProxy => 204,
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Classification of one admin write against its documented success status.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MutationOutcome {
    Accepted,
    /// The admin API answered with a status other than the documented one.
    Rejected(u16),
    /// No HTTP response was received (connect, timeout, or I/O error).
    TransportFailed,
}

fn classify_mutation(op: MutationOp, result: &Result<u16, String>) -> MutationOutcome {
    match result {
        Ok(status) if *status == op.expected_status() => MutationOutcome::Accepted,
        Ok(status) => MutationOutcome::Rejected(*status),
        Err(_) => MutationOutcome::TransportFailed,
    }
}

/// Maximum rejected/transport-failed diagnostics retained for the report.
const MUTATION_DIAGNOSTIC_LIMIT: usize = 10;
/// Maximum response-body bytes quoted in one rejection diagnostic.
const MUTATION_BODY_EXCERPT_CHARS: usize = 200;

#[derive(Debug, Default, Clone)]
struct MutationOpStats {
    attempted: u64,
    accepted: u64,
    rejected: u64,
    transport_failed: u64,
    /// Latencies of accepted writes only.
    accepted_latencies_us: Vec<u64>,
}

/// Typed outcome of the admin mutation phase. Only writes answered with their
/// documented success status count as accepted.
#[derive(Debug, Default, Clone)]
struct MutationStats {
    per_op: [MutationOpStats; 5],
    cycles_attempted: u64,
    /// Cycles in which all five writes were accepted.
    cycles_accepted: u64,
    diagnostics: Vec<String>,
    diagnostics_dropped: u64,
}

impl MutationStats {
    /// Record one write and return whether it was accepted. `detail` is a
    /// response-body excerpt (rejections) or empty.
    fn record(
        &mut self,
        op: MutationOp,
        cycle: u64,
        result: &Result<u16, String>,
        latency_us: u64,
        detail: &str,
    ) -> bool {
        let stats = &mut self.per_op[op.index()];
        stats.attempted += 1;
        let diagnostic = match classify_mutation(op, result) {
            MutationOutcome::Accepted => {
                stats.accepted += 1;
                stats.accepted_latencies_us.push(latency_us);
                return true;
            }
            MutationOutcome::Rejected(status) => {
                stats.rejected += 1;
                format!(
                    "{} (cycle {}): HTTP {} (expected {}) {}",
                    op.label(),
                    cycle,
                    status,
                    op.expected_status(),
                    detail
                )
            }
            MutationOutcome::TransportFailed => {
                stats.transport_failed += 1;
                let error = result.as_ref().err().map(String::as_str).unwrap_or("");
                format!(
                    "{} (cycle {}): transport error: {}",
                    op.label(),
                    cycle,
                    error
                )
            }
        };
        if self.diagnostics.len() < MUTATION_DIAGNOSTIC_LIMIT {
            self.diagnostics.push(diagnostic.trim_end().to_string());
        } else {
            self.diagnostics_dropped += 1;
        }
        false
    }

    fn record_cycle(&mut self, all_accepted: bool) {
        self.cycles_attempted += 1;
        if all_accepted {
            self.cycles_accepted += 1;
        }
    }

    fn attempted(&self) -> u64 {
        self.per_op.iter().map(|s| s.attempted).sum()
    }

    fn accepted(&self) -> u64 {
        self.per_op.iter().map(|s| s.accepted).sum()
    }

    fn rejected(&self) -> u64 {
        self.per_op.iter().map(|s| s.rejected).sum()
    }

    fn transport_failed(&self) -> u64 {
        self.per_op.iter().map(|s| s.transport_failed).sum()
    }

    fn summary(&self) -> String {
        let mut out = format!(
            "  Admin mutations: attempted={} accepted={} rejected={} transport_failed={} | cycles: attempted={} fully_accepted={}\n",
            self.attempted(),
            self.accepted(),
            self.rejected(),
            self.transport_failed(),
            self.cycles_attempted,
            self.cycles_accepted,
        );
        for op in MutationOp::ALL {
            let stats = &self.per_op[op.index()];
            if stats.attempted == 0 {
                continue;
            }
            out.push_str(&format!(
                "    {} (expect {}): attempted={} accepted={} rejected={} transport_failed={}",
                op.label(),
                op.expected_status(),
                stats.attempted,
                stats.accepted,
                stats.rejected,
                stats.transport_failed,
            ));
            let lats = &stats.accepted_latencies_us;
            if let Some(max) = lats.iter().max() {
                let avg = lats.iter().sum::<u64>() as f64 / lats.len() as f64;
                out.push_str(&format!(
                    ", accepted avg={:.1}ms max={:.1}ms",
                    avg / 1000.0,
                    *max as f64 / 1000.0,
                ));
            }
            out.push('\n');
        }
        for diagnostic in &self.diagnostics {
            out.push_str(&format!("    ! {}\n", diagnostic));
        }
        if self.diagnostics_dropped > 0 {
            out.push_str(&format!(
                "    ! ... {} further failures not shown\n",
                self.diagnostics_dropped
            ));
        }
        out
    }

    /// The phase certifies a reload workload only when at least one complete
    /// create/update/delete cycle was accepted and accepted writes are a
    /// majority of attempts (the same >50% floor as the traffic gate).
    fn verdict(&self) -> Result<(), String> {
        if self.cycles_accepted == 0 {
            return Err(format!(
                "no admin mutation cycle had all five writes accepted ({} cycles attempted)",
                self.cycles_attempted
            ));
        }
        let attempted = self.attempted();
        let accepted = self.accepted();
        if accepted.saturating_mul(2) <= attempted {
            return Err(format!(
                "only {} of {} admin mutations were accepted (rejected={}, transport_failed={})",
                accepted,
                attempted,
                self.rejected(),
                self.transport_failed()
            ));
        }
        Ok(())
    }
}

/// Send one admin write, classify it, and record it. Latency stops when the
/// response head (or transport error) arrives; a rejection's body is read
/// afterwards only for the diagnostic excerpt.
async fn perform_admin_mutation(
    stats: &mut MutationStats,
    op: MutationOp,
    cycle: u64,
    request: reqwest::RequestBuilder,
) -> bool {
    let start = Instant::now();
    let response = request.send().await;
    let latency_us = start.elapsed().as_micros() as u64;
    let (result, detail) = match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let detail = if status == op.expected_status() {
                String::new()
            } else {
                match response.text().await {
                    Ok(body) => body.chars().take(MUTATION_BODY_EXCERPT_CHARS).collect(),
                    Err(error) => format!("<body unavailable: {}>", error),
                }
            };
            (Ok(status), detail)
        }
        Err(error) => (Err(error.to_string()), String::new()),
    };
    stats.record(op, cycle, &result, latency_us, &detail)
}

/// Run traffic + admin mutations concurrently to measure latency impact.
/// Returns (traffic_result, mutation_stats).
async fn run_admin_mutation_phase(
    proxy_base_url: &str,
    admin_url: &str,
    admin_auth: &str,
    entries: &[AuthEntry],
    backend_port: u16,
    duration_secs: u64,
    concurrency: usize,
) -> Result<(PerfResult, MutationStats), Box<dyn std::error::Error>> {
    let stop = Arc::new(AtomicBool::new(false));

    // Admin mutation task: create, update, delete proxies/plugins during traffic
    let admin_stop = stop.clone();
    let admin_url_owned = admin_url.to_string();
    let admin_auth_owned = admin_auth.to_string();

    let admin_handle = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let mut stats = MutationStats::default();
        let mut cycle = 0u64;

        while !admin_stop.load(Ordering::Relaxed) {
            // Create a temporary proxy
            let temp_id = format!("temp-proxy-{}", cycle);
            let temp_path = format!("/temp/{}", cycle);
            let mut all_accepted = true;

            all_accepted &= perform_admin_mutation(
                &mut stats,
                MutationOp::CreateProxy,
                cycle,
                client
                    .post(format!("{}/proxies", admin_url_owned))
                    .header("Authorization", &admin_auth_owned)
                    .json(&json!({
                        "id": &temp_id,
                        "listen_path": &temp_path,
                        "backend_scheme": "http",
                        "backend_host": "127.0.0.1",
                        "backend_port": backend_port,
                        "strip_listen_path": true,
                    })),
            )
            .await;

            // Add a plugin to it
            all_accepted &= perform_admin_mutation(
                &mut stats,
                MutationOp::CreatePlugin,
                cycle,
                client
                    .post(format!("{}/plugins/config", admin_url_owned))
                    .header("Authorization", &admin_auth_owned)
                    .json(&json!({
                        "id": format!("temp-plugin-{}", cycle),
                        "plugin_name": "cors",
                        "scope": "proxy",
                        "proxy_id": &temp_id,
                        "enabled": true,
                        "config": {
                            "allowed_origins": ["*"],
                            "allowed_methods": ["GET", "POST"]
                        }
                    })),
            )
            .await;

            // Update an existing proxy (change backend timeout)
            let update_idx = (cycle as usize) % NUM_PROXIES;
            all_accepted &= perform_admin_mutation(
                &mut stats,
                MutationOp::UpdateProxy,
                cycle,
                client
                    .put(format!("{}/proxies/proxy-{}", admin_url_owned, update_idx))
                    .header("Authorization", &admin_auth_owned)
                    .json(&json!({
                        "id": format!("proxy-{}", update_idx),
                        "listen_path": format!("/svc/{}", update_idx),
                        "backend_scheme": "http",
                        "backend_host": "127.0.0.1",
                        "backend_port": backend_port,
                        "strip_listen_path": true,
                        "backend_connect_timeout_ms": 6000,
                    })),
            )
            .await;

            // Delete the temporary plugin and proxy
            all_accepted &= perform_admin_mutation(
                &mut stats,
                MutationOp::DeletePlugin,
                cycle,
                client
                    .delete(format!(
                        "{}/plugins/config/temp-plugin-{}?expected_proxy_ids={}",
                        admin_url_owned, cycle, temp_id
                    ))
                    .header("Authorization", &admin_auth_owned),
            )
            .await;

            all_accepted &= perform_admin_mutation(
                &mut stats,
                MutationOp::DeleteProxy,
                cycle,
                client
                    .delete(format!("{}/proxies/{}", admin_url_owned, temp_id))
                    .header("Authorization", &admin_auth_owned),
            )
            .await;

            stats.record_cycle(all_accepted);
            cycle += 1;

            // Small pause between mutation cycles
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        stats
    });

    // Run traffic concurrently
    let traffic_result = run_load_phase(
        "Admin Mutations + Traffic",
        proxy_base_url,
        entries,
        duration_secs,
        concurrency,
    )
    .await?;

    stop.store(true, Ordering::Relaxed);
    let mutation_stats = admin_handle.await?;

    Ok((traffic_result, mutation_stats))
}

// --- Core test runner ---

/// Run label for the backend-pool setting. The setting only permits HTTP/2
/// where the backend supports it; the embedded backend is plaintext
/// HTTP/1.1-only (`http1::Builder`, `backend_scheme: http`), so neither run
/// is an observed HTTP/1.1-versus-HTTP/2 backend comparison.
fn pool_setting_label(enable_http2: bool) -> &'static str {
    if enable_http2 {
        "FERRUM_POOL_ENABLE_HTTP2=true, backend: plaintext HTTP/1.1"
    } else {
        "FERRUM_POOL_ENABLE_HTTP2=false, backend: plaintext HTTP/1.1"
    }
}

async fn run_load_stress_test(harness: &LoadTestHarness) {
    let pool_proto = pool_setting_label(harness.backend_pool_http2);
    println!("Gateway started ({}, {}):", harness.db_label, pool_proto);
    println!("  Proxy: {}", harness.proxy_base_url);
    println!("  Admin: {}", harness.admin_base_url);
    println!("  Backend (hyper): 127.0.0.1:{}", harness.backend_port);

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(20)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");

    let token = harness
        .generate_admin_token()
        .expect("Failed to generate JWT");
    let auth_header = format!("Bearer {}", token);

    // --- Provision resources ---
    println!("\n=== Provisioning Resources ===");
    let (entries, open_paths, provision_cursor) = provision_resources(
        &client,
        &harness.admin_base_url,
        &auth_header,
        harness.backend_port,
    )
    .await
    .expect("Failed to provision resources");

    // First gate: prove the deferred graph's covering cursor was accepted by
    // the poll loop (issue #4139). Every chunk answered 202 without paying a
    // reload; this single blocking wait is where the graph's one reload is
    // paid, and a rejected/unverifiable cursor aborts loudly instead of
    // surfacing as mysterious 404s in the probe gates below.
    if let Some(cursor) = provision_cursor {
        println!(
            "\nWaiting for live-apply cursor {}:{} (bound {}s)...",
            cursor.epoch, cursor.sequence, LIVE_APPLY_CURSOR_MAX_WAIT_SECS
        );
        let waited = wait_for_batch_apply_cursor(
            &client,
            &harness.admin_base_url,
            &auth_header,
            cursor,
            "the load harness",
        )
        .await
        .unwrap_or_else(|error| panic!("Load harness aborted before measuring: {error}"));
        println!("Live apply converged after {:.1}s", waited.as_secs_f64());
    }

    // Gate every measurement on the gateway having actually published the
    // provisioned graph. Provisioning appends tens of thousands of
    // `config_changes` rows, which the poller applies as a large delta (or,
    // past `CHANGE_LOG_MAX_ROWS`, a full reload); a load phase started inside
    // that apply measures convergence, not proxy throughput. Both
    // safety valves are correct, so the harness waits them out under an
    // explicit bound instead of sleeping a fixed interval and measuring anyway.
    println!("\nWaiting for config convergence before measuring...");
    let sample_indices = [0, KEY_AUTH_END, BASIC_AUTH_END, NUM_PROXIES - 1];
    let sample_labels: Vec<String> = sample_indices
        .iter()
        .map(|&index| entries[index].listen_path().to_string())
        .collect();
    let convergence = wait_for_config_convergence("the load harness", &sample_labels, |i| {
        let entry = &entries[sample_indices[i]];
        let url = format!("{}{}", harness.proxy_base_url, entry.listen_path());
        let client = client.clone();
        let auth = match entry {
            AuthEntry::KeyAuth { api_key, .. } => SampleAuth::KeyAuth(api_key.clone()),
            AuthEntry::BasicAuth {
                username, password, ..
            } => SampleAuth::BasicAuth(username.clone(), password.clone()),
            AuthEntry::JwtAuth {
                consumer_username,
                jwt_secret,
                ..
            } => SampleAuth::Bearer(generate_consumer_jwt(consumer_username, jwt_secret)),
        };
        async move {
            let request = client.get(&url);
            let request = match auth {
                SampleAuth::KeyAuth(key) => request.header("X-API-Key", key),
                SampleAuth::BasicAuth(username, password) => {
                    request.basic_auth(username, Some(password))
                }
                SampleAuth::Bearer(token) => {
                    request.header("Authorization", format!("Bearer {}", token))
                }
            };
            match request.send().await {
                Ok(response) => Ok(response.status().as_u16()),
                Err(error) => Err(error.to_string()),
            }
        }
    })
    .await
    .unwrap_or_else(|error| {
        panic!(
            "Load harness aborted before measuring {} proxies: {}",
            NUM_PROXIES + NUM_OPEN_PROXIES,
            error
        )
    });
    println!(
        "  Config converged after {:.1}s ({} polls, bound {}s)",
        convergence.waited.as_secs_f64(),
        convergence.polls,
        CONFIG_CONVERGENCE_MAX_WAIT_SECS
    );

    // Open proxies are provisioned last, so they are the tail of the change
    // log: Phase 2's no-plugin baseline gets its own bounded gate rather than
    // inheriting the authenticated set's verdict.
    let open_sample_indices = [0usize, open_paths.len() - 1];
    let open_sample_labels: Vec<String> = open_sample_indices
        .iter()
        .map(|&index| open_paths[index].clone())
        .collect();
    let open_convergence = wait_for_config_convergence(
        "the load harness open-proxy baseline",
        &open_sample_labels,
        |i| {
            let path = &open_paths[open_sample_indices[i]];
            let url = format!("{}{}", harness.proxy_base_url, path);
            let client = client.clone();
            async move {
                match client.get(&url).send().await {
                    Ok(response) => Ok(response.status().as_u16()),
                    Err(error) => Err(error.to_string()),
                }
            }
        },
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "Load harness aborted before measuring {} open proxies: {}",
            NUM_OPEN_PROXIES, error
        )
    });
    println!(
        "  Open-proxy config converged after {:.1}s ({} polls)",
        open_convergence.waited.as_secs_f64(),
        open_convergence.polls
    );

    // --- Phase 1: Ramp concurrency ---
    println!("\n=== Phase 1: Concurrency Ramp (mixed payloads, mixed auth) ===");
    let mut all_results: Vec<PerfResult> = Vec::new();

    for &conc in CONCURRENCY_LEVELS {
        println!(
            "\n  Running {}s load test at concurrency={} ...",
            PHASE_DURATION_SECS, conc
        );
        let result = run_load_phase(
            &format!("Ramp c={}", conc),
            &harness.proxy_base_url,
            &entries,
            PHASE_DURATION_SECS,
            conc,
        )
        .await
        .expect("Load phase failed");

        print_perf_result(&result);
        all_results.push(result);
    }

    // --- Phase 2: No-plugin baseline (pure proxy overhead) ---
    println!("\n=== Phase 2: No-Plugin Baseline (pure proxy overhead) ===");
    let mut open_results: Vec<PerfResult> = Vec::new();

    for &conc in CONCURRENCY_LEVELS {
        println!(
            "\n  Running {}s open-proxy test at concurrency={} ...",
            PHASE_DURATION_SECS, conc
        );
        let result = run_open_proxy_phase(
            &format!("No-plugin c={}", conc),
            &harness.proxy_base_url,
            &open_paths,
            PHASE_DURATION_SECS,
            conc,
        )
        .await
        .expect("Open proxy phase failed");

        print_perf_result(&result);
        open_results.push(result);
    }

    // --- Phase 3: Admin mutations under load ---
    println!("\n=== Phase 3: Admin Mutations Under Load ===");
    println!(
        "  Running {}s with concurrent admin API create/update/delete...",
        ADMIN_MUTATION_PHASE_SECS
    );

    let (mutation_result, mutation_stats) = run_admin_mutation_phase(
        &harness.proxy_base_url,
        &harness.admin_base_url,
        &auth_header,
        &entries,
        harness.backend_port,
        ADMIN_MUTATION_PHASE_SECS,
        ADMIN_MUTATION_CONCURRENCY,
    )
    .await
    .expect("Admin mutation phase failed");

    print_perf_result(&mutation_result);
    println!("\n{}", mutation_stats.summary());

    // Compare mutation phase latency to baseline (same concurrency without mutations)
    let baseline = all_results
        .iter()
        .find(|r| r.concurrency == ADMIN_MUTATION_CONCURRENCY);
    if let Some(baseline) = baseline {
        let p99_increase = if baseline.p99_latency_us > 0.0 {
            ((mutation_result.p99_latency_us - baseline.p99_latency_us) / baseline.p99_latency_us)
                * 100.0
        } else {
            0.0
        };
        println!(
            "  P99 latency impact from admin mutations: {:+.1}%  ({:.1}ms -> {:.1}ms)",
            p99_increase,
            baseline.p99_latency_us / 1000.0,
            mutation_result.p99_latency_us / 1000.0,
        );

        let rps_change = if baseline.rps > 0.0 {
            ((mutation_result.rps - baseline.rps) / baseline.rps) * 100.0
        } else {
            0.0
        };
        println!(
            "  RPS impact from admin mutations: {:+.1}%  ({:.0} -> {:.0})",
            rps_change, baseline.rps, mutation_result.rps,
        );
    }

    // --- Phase 4: wrk comparison (if available) ---
    // Once wrk is available every attempted phase must produce a result: a
    // failed invocation or unparseable output is recorded here and fails the
    // final gate instead of silently dropping out of the comparison.
    let mut wrk_results: Vec<PerfResult> = Vec::new();
    let mut wrk_failures: Vec<String> = Vec::new();

    if is_wrk_available() {
        println!("\n=== Phase 4: wrk Comparison (native C load generator) ===");

        // Collect a subset of key_auth paths and keys for wrk Lua script (use first 100)
        let wrk_sample_size = 100.min(KEY_AUTH_END);
        let mut wrk_paths = Vec::with_capacity(wrk_sample_size);
        let mut wrk_keys = Vec::with_capacity(wrk_sample_size);
        for entry in entries.iter().take(wrk_sample_size) {
            if let AuthEntry::KeyAuth {
                listen_path,
                api_key,
            } = entry
            {
                wrk_paths.push(listen_path.clone());
                wrk_keys.push(api_key.clone());
            }
        }

        // Write Lua script to temp file
        let lua_content = generate_wrk_keyauth_lua(&wrk_paths, &wrk_keys);
        let lua_path = harness._temp_dir.path().join("wrk_keyauth.lua");
        {
            let mut f = std::fs::File::create(&lua_path).expect("Failed to create wrk Lua script");
            f.write_all(lua_content.as_bytes())
                .expect("Failed to write wrk Lua script");
        }
        let lua_path_str = lua_path.to_string_lossy().to_string();

        let wrk_duration = PHASE_DURATION_SECS;

        for &(threads, connections, label_suffix) in &[
            (4, 50, "c=50"),
            (4, 100, "c=100"),
            (8, 200, "c=200"),
            (8, 400, "c=400"),
        ] {
            // wrk: key_auth (with plugins)
            println!(
                "\n  Running wrk {}s key_auth test at {} ...",
                wrk_duration, label_suffix
            );
            let label = format!("wrk key_auth {}", label_suffix);
            match run_wrk_phase(
                &label,
                &harness.proxy_base_url,
                Some(&lua_path_str),
                wrk_duration,
                threads,
                connections,
            )
            .await
            {
                Ok(r) => {
                    print_perf_result(&r);
                    wrk_results.push(r);
                }
                Err(error) => {
                    println!("  {} produced no result: {}", label, error);
                    wrk_failures.push(format!("{}: {}", label, error));
                }
            }

            // wrk: no-plugin (open proxy)
            let open_url = format!("{}/open/0", harness.proxy_base_url);
            println!(
                "\n  Running wrk {}s no-plugin test at {} ...",
                wrk_duration, label_suffix
            );
            let label = format!("wrk no-plugin {}", label_suffix);
            match run_wrk_phase(&label, &open_url, None, wrk_duration, threads, connections).await {
                Ok(r) => {
                    print_perf_result(&r);
                    wrk_results.push(r);
                }
                Err(error) => {
                    println!("  {} produced no result: {}", label, error);
                    wrk_failures.push(format!("{}: {}", label, error));
                }
            }
        }
    } else {
        println!("\n=== Phase 4: wrk Comparison SKIPPED (wrk not installed) ===");
        println!("  Install wrk for a native C load generator comparison:");
        println!("    macOS: brew install wrk");
        println!("    Ubuntu: sudo apt-get install wrk");
    }

    // --- Summary ---
    let all_combined: Vec<&PerfResult> = all_results
        .iter()
        .chain(open_results.iter())
        .chain(std::iter::once(&mutation_result))
        .chain(wrk_results.iter())
        .collect();

    let pool_proto = pool_setting_label(harness.backend_pool_http2);

    println!("\n\n======================================================================");
    println!(
        "  LOAD & STRESS TEST SUMMARY ({}, {})",
        harness.db_label, pool_proto
    );
    println!(
        "  {} proxies ({} with plugins + {} open) | {} consumers | {} plugins",
        NUM_PROXIES + NUM_OPEN_PROXIES,
        NUM_PROXIES,
        NUM_OPEN_PROXIES,
        NUM_CONSUMERS,
        NUM_PROXIES * 3
    );
    println!(
        "  Auth: key_auth ({}) + basic_auth ({}) + jwt_auth ({})",
        KEY_AUTH_END,
        BASIC_AUTH_END - KEY_AUTH_END,
        NUM_PROXIES - BASIC_AUTH_END
    );
    println!("  Payloads: GET, small JSON, medium JSON, large JSON, XML, multipart");
    println!(
        "  reqwest rows: RPS = attempts / wall time; latency = response head (send() completion, body not read); OK% = 2xx status"
    );
    println!(
        "  wrk rows: wrk-reported Requests/sec and latency; OK% excludes non-2xx/3xx and socket errors"
    );
    println!("======================================================================");
    println!(
        "{:<28} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7}",
        "Phase", "Conc", "RPS", "Avg(ms)", "P50(ms)", "P95(ms)", "P99(ms)", "Max(ms)", "OK%"
    );
    println!("----------------------------------------------------------------------");

    // Print with-plugin ramp results
    for r in &all_results {
        let success_pct = if r.total_requests > 0 {
            r.successful_requests as f64 / r.total_requests as f64 * 100.0
        } else {
            0.0
        };
        println!(
            "{:<28} {:>5} {:>8.0} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>6.1}%",
            r.label,
            r.concurrency,
            r.rps,
            r.avg_latency_us / 1000.0,
            r.p50_latency_us / 1000.0,
            r.p95_latency_us / 1000.0,
            r.p99_latency_us / 1000.0,
            r.max_latency_us / 1000.0,
            success_pct,
        );
    }

    println!("----------------------------------------------------------------------");

    // Print no-plugin baseline results
    for r in &open_results {
        let success_pct = if r.total_requests > 0 {
            r.successful_requests as f64 / r.total_requests as f64 * 100.0
        } else {
            0.0
        };
        println!(
            "{:<28} {:>5} {:>8.0} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>6.1}%",
            r.label,
            r.concurrency,
            r.rps,
            r.avg_latency_us / 1000.0,
            r.p50_latency_us / 1000.0,
            r.p95_latency_us / 1000.0,
            r.p99_latency_us / 1000.0,
            r.max_latency_us / 1000.0,
            success_pct,
        );
    }

    println!("----------------------------------------------------------------------");

    // Print admin mutation result
    {
        let r = &mutation_result;
        let success_pct = if r.total_requests > 0 {
            r.successful_requests as f64 / r.total_requests as f64 * 100.0
        } else {
            0.0
        };
        println!(
            "{:<28} {:>5} {:>8.0} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>6.1}%",
            r.label,
            r.concurrency,
            r.rps,
            r.avg_latency_us / 1000.0,
            r.p50_latency_us / 1000.0,
            r.p95_latency_us / 1000.0,
            r.p99_latency_us / 1000.0,
            r.max_latency_us / 1000.0,
            success_pct,
        );
    }

    // Print wrk results if any
    if !wrk_results.is_empty() {
        println!("----------------------------------------------------------------------");
        for r in &wrk_results {
            let success_pct = if r.total_requests > 0 {
                r.successful_requests as f64 / r.total_requests as f64 * 100.0
            } else {
                0.0
            };
            println!(
                "{:<28} {:>5} {:>8.0} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>6.1}%",
                r.label,
                r.concurrency,
                r.rps,
                r.avg_latency_us / 1000.0,
                r.p50_latency_us / 1000.0,
                r.p95_latency_us / 1000.0,
                r.p99_latency_us / 1000.0,
                r.max_latency_us / 1000.0,
                success_pct,
            );
        }

        // Compare wrk vs reqwest at same concurrency
        println!("\n--- wrk vs reqwest Client Comparison ---");
        for wr in &wrk_results {
            // Find matching reqwest result
            let reqwest_result = if wr.label.contains("no-plugin") {
                open_results
                    .iter()
                    .find(|r| r.concurrency == wr.concurrency)
            } else {
                all_results.iter().find(|r| r.concurrency == wr.concurrency)
            };
            if let Some(rr) = reqwest_result {
                let rps_diff = if rr.rps > 0.0 {
                    ((wr.rps - rr.rps) / rr.rps) * 100.0
                } else {
                    0.0
                };
                println!(
                    "  {:<24}  reqwest: {:>8.0} attempt RPS  |  wrk: {:>8.0} RPS  ({:+.1}%)",
                    wr.label, rr.rps, wr.rps, rps_diff,
                );
            }
        }
    }

    // --- Plugin overhead analysis ---
    println!(
        "\n--- Plugin Overhead (with-plugins vs no-plugin at same concurrency; attempt RPS, response-head P99) ---"
    );
    for r_with in &all_results {
        if let Some(r_open) = open_results
            .iter()
            .find(|o| o.concurrency == r_with.concurrency)
        {
            let rps_overhead = if r_open.rps > 0.0 {
                ((r_open.rps - r_with.rps) / r_open.rps) * 100.0
            } else {
                0.0
            };
            let p99_overhead = if r_open.p99_latency_us > 0.0 {
                ((r_with.p99_latency_us - r_open.p99_latency_us) / r_open.p99_latency_us) * 100.0
            } else {
                0.0
            };
            println!(
                "  c={:<4}  RPS: {:.0} -> {:.0} ({:+.1}%)  |  P99: {:.1}ms -> {:.1}ms ({:+.1}%)",
                r_with.concurrency,
                r_open.rps,
                r_with.rps,
                -rps_overhead,
                r_open.p99_latency_us / 1000.0,
                r_with.p99_latency_us / 1000.0,
                p99_overhead,
            );
        }
    }

    // Identify where latency becomes concerning
    println!("\n--- Latency Analysis ---");
    for r in &all_combined {
        if r.p99_latency_us > 100_000.0 {
            println!(
                "  WARNING: P99 > 100ms at concurrency={}: {:.1}ms ({})",
                r.concurrency,
                r.p99_latency_us / 1000.0,
                r.label
            );
        }
        if r.p95_latency_us > 50_000.0 {
            println!(
                "  WARNING: P95 > 50ms at concurrency={}: {:.1}ms ({})",
                r.concurrency,
                r.p95_latency_us / 1000.0,
                r.label
            );
        }
        let success_pct = if r.total_requests > 0 {
            r.successful_requests as f64 / r.total_requests as f64 * 100.0
        } else {
            0.0
        };
        if success_pct < 95.0 {
            println!(
                "  WARNING: Success rate < 95% at concurrency={}: {:.1}% ({})",
                r.concurrency, success_pct, r.label
            );
        }
    }

    // Final gate: every phase that ran must report requests with a success
    // rate above 50%, every attempted wrk phase must have produced a result,
    // and the admin mutation phase must have accepted a reload workload.
    let mut gate_failures = phase_gate_failures(&all_combined, &wrk_failures);
    if let Err(error) = mutation_stats.verdict() {
        gate_failures.push(format!("admin mutation phase: {}", error));
    }
    assert!(
        gate_failures.is_empty(),
        "Load & stress gate failed ({}):\n  {}",
        harness.db_label,
        gate_failures.join("\n  ")
    );

    println!(
        "\n=== Load & Stress Test ({}) Complete ===\n",
        harness.db_label
    );
}

/// Collect final-gate failures: a phase that ran but reported no requests, a
/// phase at or below a 50% success rate, and every attempted phase that
/// produced no result (`missing`).
fn phase_gate_failures(results: &[&PerfResult], missing: &[String]) -> Vec<String> {
    let mut failures = Vec::new();
    for r in results {
        if r.total_requests == 0 {
            failures.push(format!(
                "phase '{}' at concurrency={} reported no requests",
                r.label, r.concurrency
            ));
            continue;
        }
        let success_rate = r.successful_requests as f64 / r.total_requests as f64 * 100.0;
        if success_rate <= 50.0 {
            failures.push(format!(
                "success rate at or below 50% in phase '{}' at concurrency={}: {:.1}%",
                r.label, r.concurrency, success_rate
            ));
        }
    }
    for missing in missing {
        failures.push(format!("attempted phase produced no result: {}", missing));
    }
    failures
}

// --- wrk comparison phase ---

/// Check if wrk is available on the system.
fn is_wrk_available() -> bool {
    // wrk --version exits with code 1 but still outputs version info
    let output = Command::new("wrk")
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match output {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            combined.contains("wrk")
        }
        Err(_) => false,
    }
}

/// Parse wrk latency output (e.g. "  50%   4.12ms" or "  Latency   5.23ms   2.10ms  43.21ms  85.00%")
/// Returns (rps, avg_us, p50_us, p99_us, max_us, total_requests, errors)
fn parse_wrk_output(output: &str) -> Option<(f64, f64, f64, f64, f64, u64, u64)> {
    let mut rps = 0.0f64;
    let mut avg_us = 0.0f64;
    let mut p50_us = 0.0f64;
    let mut p99_us = 0.0f64;
    let mut max_us = 0.0f64;
    let mut total_requests = 0u64;
    let mut errors = 0u64;

    for line in output.lines() {
        let line = line.trim();

        // "Requests/sec:  12345.67"
        if line.starts_with("Requests/sec:")
            && let Some(val) = line.split_whitespace().nth(1)
        {
            rps = val.parse().unwrap_or(0.0);
        }

        // "    Latency     5.23ms    2.10ms   43.21ms   85.00%"
        if line.starts_with("Latency") && !line.contains("Distribution") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                avg_us = parse_wrk_duration(parts[1]);
                max_us = parse_wrk_duration(parts[3]);
            }
        }

        // "  12345 requests in 30.00s, 2.34MB read"
        if line.contains("requests in")
            && let Some(val) = line.split_whitespace().next()
        {
            total_requests = val.parse().unwrap_or(0);
        }

        // "  Non-2xx or 3xx responses: 123"
        if line.contains("Non-2xx")
            && let Some(val) = line.split(':').nth(1)
        {
            errors = val.trim().parse().unwrap_or(0);
        }

        // Socket errors
        if line.starts_with("Socket errors:") {
            // "Socket errors: connect 0, read 0, write 0, timeout 5"
            for part in line.split(',') {
                if let Some(val) = part.split_whitespace().last() {
                    errors += val.parse::<u64>().unwrap_or(0);
                }
            }
        }

        // Latency distribution: "  50%   4.12ms"
        if line.ends_with("ms") || line.ends_with("us") || line.ends_with('s') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if parts[0] == "50%" {
                    p50_us = parse_wrk_duration(parts[1]);
                } else if parts[0] == "99%" {
                    p99_us = parse_wrk_duration(parts[1]);
                }
            }
        }
    }

    if total_requests > 0 {
        Some((rps, avg_us, p50_us, p99_us, max_us, total_requests, errors))
    } else {
        None
    }
}

/// Parse wrk duration string like "4.12ms", "123.45us", "1.23s" to microseconds.
fn parse_wrk_duration(s: &str) -> f64 {
    if let Some(v) = s.strip_suffix("ms") {
        v.parse::<f64>().unwrap_or(0.0) * 1000.0
    } else if let Some(v) = s.strip_suffix("us") {
        v.parse::<f64>().unwrap_or(0.0)
    } else if let Some(v) = s.strip_suffix('s') {
        v.parse::<f64>().unwrap_or(0.0) * 1_000_000.0
    } else {
        0.0
    }
}

/// Build a `PerfResult` from combined wrk stdout/stderr. Output without a
/// positive `N requests in` total is an error, not an omitted phase.
fn wrk_result_from_output(
    label: &str,
    connections: usize,
    duration_secs: u64,
    output: &str,
) -> Result<PerfResult, String> {
    let (rps, avg_us, p50_us, p99_us, max_us, total, errors) = parse_wrk_output(output)
        .ok_or_else(|| {
            format!(
                "wrk output had no positive request total:\n{}",
                output.trim_end()
            )
        })?;
    Ok(PerfResult {
        label: label.to_string(),
        concurrency: connections,
        total_requests: total,
        successful_requests: total.saturating_sub(errors),
        failed_requests: errors,
        duration_secs: duration_secs as f64,
        rps,
        avg_latency_us: avg_us,
        p50_latency_us: p50_us,
        p95_latency_us: 0.0, // wrk --latency only shows 50/75/90/99
        p99_latency_us: p99_us,
        p999_latency_us: 0.0,
        max_latency_us: max_us,
        boundary: MeasurementBoundary::WrkReported,
    })
}

/// Run wrk against a target URL with an optional Lua script.
/// Returns a PerfResult comparable to the reqwest-based phases, or an error
/// when wrk could not be invoked, its worker task failed, or its output had
/// no positive request total.
/// Uses spawn_blocking to avoid blocking the tokio runtime (the hyper backend
/// runs on the same runtime and must keep accepting connections).
async fn run_wrk_phase(
    label: &str,
    target_url: &str,
    lua_script_path: Option<&str>,
    duration_secs: u64,
    threads: usize,
    connections: usize,
) -> Result<PerfResult, String> {
    let label = label.to_string();
    let target_url = target_url.to_string();
    let lua_script_path = lua_script_path.map(|s| s.to_string());

    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new("wrk");
        cmd.arg(format!("-t{}", threads))
            .arg(format!("-c{}", connections))
            .arg(format!("-d{}s", duration_secs))
            .arg("--latency");

        if let Some(ref script) = lua_script_path {
            cmd.arg("-s").arg(script);
        }

        cmd.arg(&target_url);

        let out = cmd
            .output()
            .map_err(|e| format!("failed to run wrk: {}", e))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let combined = format!("{}\n{}", stdout, stderr);
        wrk_result_from_output(&label, connections, duration_secs, &combined)
    })
    .await
    .map_err(|e| format!("wrk worker task failed: {}", e))?
}

/// Generate a Lua script for wrk that sets an API key header and cycles through paths.
fn generate_wrk_keyauth_lua(paths: &[String], api_keys: &[String]) -> String {
    // Build arrays of paths and keys in Lua
    let mut lua = String::with_capacity(2048);
    lua.push_str("-- Auto-generated wrk script for key_auth load testing\n");
    lua.push_str("local paths = {\n");
    for p in paths {
        lua.push_str(&format!("  \"{}\",\n", p));
    }
    lua.push_str("}\n");
    lua.push_str("local keys = {\n");
    for k in api_keys {
        lua.push_str(&format!("  \"{}\",\n", k));
    }
    lua.push_str("}\n\n");
    lua.push_str("local idx = 1\n");
    lua.push_str("local total = #paths\n\n");
    lua.push_str("request = function()\n");
    lua.push_str("  local path = paths[idx]\n");
    lua.push_str("  local key = keys[idx]\n");
    lua.push_str("  idx = (idx % total) + 1\n");
    lua.push_str("  wrk.headers[\"X-API-Key\"] = key\n");
    lua.push_str("  return wrk.format(\"GET\", path)\n");
    lua.push_str("end\n");
    lua
}

// --- Docker helper ---

fn is_container_running(name: &str) -> bool {
    // Use a timeout to avoid hanging when Docker daemon is unresponsive
    let child = Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", name])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    match child {
        Ok(child) => {
            // Wait up to 5 seconds for the docker command to complete
            let start = Instant::now();
            let mut child = child;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        if !status.success() {
                            return false;
                        }
                        let output =
                            child
                                .wait_with_output()
                                .unwrap_or_else(|_| std::process::Output {
                                    status,
                                    stdout: Vec::new(),
                                    stderr: Vec::new(),
                                });
                        return String::from_utf8_lossy(&output.stdout).trim() == "true";
                    }
                    Ok(None) => {
                        if start.elapsed() > Duration::from_secs(5) {
                            let _ = child.kill();
                            let _ = child.wait();
                            println!(
                                "Docker inspect timed out after 5s — daemon may not be running"
                            );
                            return false;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(_) => return false,
                }
            }
        }
        Err(_) => false,
    }
}

fn clean_postgres_database(_db_url: &str) {
    // Use docker exec to clean the database — doesn't require psql on the host
    let drop_result = Command::new("docker")
        .args([
            "exec",
            "ferrum-load-test-pg",
            "psql",
            "-U",
            "ferrum",
            "-d",
            "ferrum_load",
            "-c",
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        ])
        .output();
    match drop_result {
        Ok(o) if o.status.success() => println!("Cleaned PostgreSQL database"),
        Ok(o) => println!(
            "Warning: psql cleanup returned {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => println!("Warning: docker exec for cleanup failed: {}", e),
    }
}

// ---- Single test: PostgreSQL-first with SQLite fallback, runs FERRUM_POOL_ENABLE_HTTP2=false then true ----

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_load_stress_10k_proxies() {
    // Try PostgreSQL first, fall back to SQLite
    let pg_db_url = "postgres://ferrum:ferrum-load-test@localhost:25433/ferrum_load";
    let use_postgres = is_container_running("ferrum-load-test-pg");

    let db_label = if use_postgres { "PostgreSQL" } else { "SQLite" };

    println!("\n============================================================");
    println!(
        "  Load & Stress Test ({}): 10k proxies, 30k plugins",
        db_label
    );
    println!(
        "  Concurrency ramp: {:?}  |  Phase: {}s",
        CONCURRENCY_LEVELS, PHASE_DURATION_SECS
    );
    println!(
        "  Backend pool settings: FERRUM_POOL_ENABLE_HTTP2=false then true (backend is plaintext HTTP/1.1 in both)"
    );
    if !use_postgres {
        println!("  (PostgreSQL not available — using SQLite fallback)");
        println!("  For PostgreSQL, run:");
        println!("    docker run -d --name ferrum-load-test-pg \\");
        println!("      -e POSTGRES_USER=ferrum -e POSTGRES_PASSWORD=ferrum-load-test \\");
        println!("      -e POSTGRES_DB=ferrum_load -p 127.0.0.1:25433:5432 postgres:16");
    }
    println!("============================================================\n");

    // Build release binary if not already built
    println!("Building release binary...");
    let build_status = Command::new("cargo")
        .args(["build", "--release", "--bin", "ferrum-edge"])
        .status()
        .expect("Failed to run cargo build");
    if !build_status.success() {
        panic!("Failed to build ferrum-edge in release mode");
    }
    println!("Release binary ready.\n");

    // --- Run 1: FERRUM_POOL_ENABLE_HTTP2=false ---
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  RUN 1: FERRUM_POOL_ENABLE_HTTP2=false                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    {
        let harness = if use_postgres {
            clean_postgres_database(pg_db_url);
            LoadTestHarness::new_postgres(pg_db_url, false)
                .await
                .expect("Failed to create PostgreSQL test harness")
        } else {
            LoadTestHarness::new_sqlite(false)
                .await
                .expect("Failed to create SQLite test harness")
        };

        run_load_stress_test(&harness).await;
    }
    // harness dropped here — gateway process killed

    // --- Run 2: FERRUM_POOL_ENABLE_HTTP2=true ---
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║  RUN 2: FERRUM_POOL_ENABLE_HTTP2=true                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    {
        let harness = if use_postgres {
            clean_postgres_database(pg_db_url);
            LoadTestHarness::new_postgres(pg_db_url, true)
                .await
                .expect("Failed to create PostgreSQL test harness")
        } else {
            LoadTestHarness::new_sqlite(true)
                .await
                .expect("Failed to create SQLite test harness")
        };

        run_load_stress_test(&harness).await;
    }
}

// ---- Harness accounting tests (not ignored; no gateway required) ----

fn perf_result(label: &str, total: u64, success: u64) -> PerfResult {
    PerfResult {
        label: label.to_string(),
        concurrency: 50,
        total_requests: total,
        successful_requests: success,
        failed_requests: total - success,
        duration_secs: 30.0,
        rps: total as f64 / 30.0,
        avg_latency_us: 0.0,
        p50_latency_us: 0.0,
        p95_latency_us: 0.0,
        p99_latency_us: 0.0,
        p999_latency_us: 0.0,
        max_latency_us: 0.0,
        boundary: MeasurementBoundary::ResponseHead,
    }
}

fn record_full_cycle(stats: &mut MutationStats, cycle: u64) {
    let mut all_accepted = true;
    for op in MutationOp::ALL {
        all_accepted &= stats.record(op, cycle, &Ok(op.expected_status()), 1_000, "");
    }
    stats.record_cycle(all_accepted);
}

#[test]
fn load_stress_mutation_classification_requires_the_documented_status() {
    for op in MutationOp::ALL {
        assert_eq!(
            classify_mutation(op, &Ok(op.expected_status())),
            MutationOutcome::Accepted,
            "{}",
            op.label()
        );
        for status in [401u16, 404, 409, 500, 503] {
            assert_eq!(
                classify_mutation(op, &Ok(status)),
                MutationOutcome::Rejected(status),
                "{} answered {}",
                op.label(),
                status
            );
        }
        assert_eq!(
            classify_mutation(op, &Err("connection reset".to_string())),
            MutationOutcome::TransportFailed,
            "{}",
            op.label()
        );
    }
    // A deferred 202 does not claim the generation is live, and a 2xx other
    // than the documented one is not that write's success contract.
    assert_eq!(
        classify_mutation(MutationOp::CreateProxy, &Ok(202)),
        MutationOutcome::Rejected(202)
    );
    assert_eq!(
        classify_mutation(MutationOp::DeleteProxy, &Ok(200)),
        MutationOutcome::Rejected(200)
    );
}

#[test]
fn load_stress_rejected_and_transport_failed_mutations_are_not_accepted() {
    let mut stats = MutationStats::default();
    record_full_cycle(&mut stats, 0);

    // Later cycles: admin writes rejected and both DELETEs fail in transport.
    for cycle in 1..=3 {
        let mut all_accepted = true;
        all_accepted &= stats.record(
            MutationOp::CreateProxy,
            cycle,
            &Ok(401),
            500,
            "unauthorized",
        );
        all_accepted &= stats.record(MutationOp::CreatePlugin, cycle, &Ok(409), 500, "conflict");
        all_accepted &= stats.record(MutationOp::UpdateProxy, cycle, &Ok(500), 500, "");
        all_accepted &= stats.record(
            MutationOp::DeletePlugin,
            cycle,
            &Err("operation timed out".to_string()),
            30_000_000,
            "",
        );
        all_accepted &= stats.record(
            MutationOp::DeleteProxy,
            cycle,
            &Err("connection refused".to_string()),
            10,
            "",
        );
        stats.record_cycle(all_accepted);
    }

    assert_eq!(stats.attempted(), 20);
    assert_eq!(stats.accepted(), 5);
    assert_eq!(stats.rejected(), 9);
    assert_eq!(stats.transport_failed(), 6);
    assert_eq!(stats.cycles_attempted, 4);
    assert_eq!(stats.cycles_accepted, 1);
    for op in MutationOp::ALL {
        // Only the first cycle's accepted latency is retained per operation.
        assert_eq!(stats.per_op[op.index()].accepted_latencies_us, vec![1_000]);
    }
    assert_eq!(stats.diagnostics.len(), MUTATION_DIAGNOSTIC_LIMIT);
    assert_eq!(
        stats.diagnostics_dropped,
        15 - MUTATION_DIAGNOSTIC_LIMIT as u64
    );
    assert!(stats.diagnostics[0].contains("create_proxy (cycle 1): HTTP 401 (expected 201)"));
    assert!(stats.diagnostics[3].contains("delete_plugin (cycle 1): transport error"));

    let error = stats.verdict().expect_err("a rejected majority must fail");
    assert!(error.contains("only 5 of 20"), "{error}");
    let summary = stats.summary();
    assert!(summary.contains("attempted=20 accepted=5 rejected=9 transport_failed=6"));
    assert!(!summary.contains("completed"), "{summary}");
}

#[test]
fn load_stress_mutation_verdict_requires_an_accepted_cycle() {
    // No success at all.
    let mut none = MutationStats::default();
    for cycle in 0..4 {
        let mut all_accepted = true;
        for op in MutationOp::ALL {
            all_accepted &= none.record(op, cycle, &Ok(500), 1, "");
        }
        none.record_cycle(all_accepted);
    }
    assert_eq!(none.accepted(), 0);
    assert!(none.verdict().is_err());

    // No phase activity at all.
    assert!(MutationStats::default().verdict().is_err());

    // A majority of writes accepted but every cycle loses its deletes: no
    // complete create/update/delete cycle was applied.
    let mut partial = MutationStats::default();
    for cycle in 0..4 {
        let mut all_accepted = true;
        for op in MutationOp::ALL {
            let result = match op {
                MutationOp::DeleteProxy => Err("connection reset".to_string()),
                _ => Ok(op.expected_status()),
            };
            all_accepted &= partial.record(op, cycle, &result, 1, "");
        }
        partial.record_cycle(all_accepted);
    }
    assert_eq!(partial.accepted(), 16);
    let error = partial.verdict().expect_err("no complete cycle");
    assert!(error.contains("no admin mutation cycle"), "{error}");

    let mut healthy = MutationStats::default();
    for cycle in 0..3 {
        record_full_cycle(&mut healthy, cycle);
    }
    assert_eq!(healthy.verdict(), Ok(()));
}

const WRK_SAMPLE_OUTPUT: &str = "Running 30s test @ http://127.0.0.1:8000/open/0
  4 threads and 50 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.25ms  500.00us  20.00ms   90.00%
    Req/Sec    10.00k     1.00k   12.00k    70.00%
  Latency Distribution
     50%    1.00ms
     75%    1.50ms
     90%    2.00ms
     99%    3.00ms
  1200000 requests in 30.00s, 150.00MB read
  Non-2xx or 3xx responses: 100
Requests/sec:  40000.00
Transfer/sec:      5.00MB
";

#[test]
fn load_stress_wrk_output_with_positive_total_yields_a_result() {
    let result = wrk_result_from_output("wrk no-plugin c=50", 50, 30, WRK_SAMPLE_OUTPUT)
        .expect("positive request total");
    assert_eq!(result.total_requests, 1_200_000);
    assert_eq!(result.failed_requests, 100);
    assert_eq!(result.successful_requests, 1_199_900);
    assert_eq!(result.concurrency, 50);
    assert!((result.rps - 40_000.0).abs() < 1e-6, "{}", result.rps);
    assert_eq!(result.boundary, MeasurementBoundary::WrkReported);
}

#[test]
fn load_stress_wrk_output_without_positive_total_is_an_error() {
    let zero = WRK_SAMPLE_OUTPUT.replace("1200000 requests in", "0 requests in");
    let malformed = WRK_SAMPLE_OUTPUT.replace("1200000 requests in", "lots requests in");
    let absent = WRK_SAMPLE_OUTPUT.replace("  1200000 requests in 30.00s, 150.00MB read\n", "");
    for (name, output) in [
        ("zero", zero.as_str()),
        ("malformed", malformed.as_str()),
        ("absent", absent.as_str()),
        ("empty", ""),
        (
            "invocation error text",
            "unable to connect to 127.0.0.1:8000 Connection refused",
        ),
    ] {
        let error = wrk_result_from_output("wrk key_auth c=50", 50, 30, output).expect_err(name);
        assert!(
            error.contains("no positive request total"),
            "{name}: {error}"
        );
    }
}

#[test]
fn load_stress_phase_gate_fails_closed() {
    let healthy = perf_result("Ramp c=50", 1_000, 1_000);
    let barely = perf_result("Ramp c=100", 1_000, 501);
    assert!(phase_gate_failures(&[&healthy, &barely], &[]).is_empty());

    let half = perf_result("Ramp c=200", 1_000, 500);
    let below = perf_result("No-plugin c=50", 1_000, 100);
    let empty = perf_result("No-plugin c=100", 0, 0);
    let failures = phase_gate_failures(&[&healthy, &half, &below, &empty], &[]);
    assert_eq!(failures.len(), 3, "{failures:?}");
    assert!(failures[0].contains("'Ramp c=200'"), "{failures:?}");
    assert!(failures[1].contains("'No-plugin c=50'"), "{failures:?}");
    assert!(failures[2].contains("reported no requests"), "{failures:?}");

    // An attempted wrk phase that produced no result fails even when every
    // retained phase is healthy.
    let missing = ["wrk key_auth c=400: failed to run wrk: not found".to_string()];
    let failures = phase_gate_failures(&[&healthy], &missing);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("wrk key_auth c=400"), "{failures:?}");
}

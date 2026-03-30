//! Functional Tests for Circuit Breaker and Retry Logic (E2E)
//!
//! Tests that were previously only covered by unit tests:
//! - Circuit breaker opens after consecutive failures, then half-opens and recovers
//! - Retry logic retries on connect failure and retryable status codes
//! - Retry respects max_retries and retryable_methods
//!
//! Uses database mode with SQLite. A controllable backend simulates failures.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_circuit_breaker

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Harness (same pattern as other functional tests)
// ============================================================================

struct CbRetryTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
}

impl CbRetryTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-cb-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-gateway-cb-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let db_url = format!(
            "sqlite:{}?mode=rwc",
            temp_dir.path().join("test.db").to_string_lossy()
        );

        // Build the gateway binary if not already built
        let build_status = Command::new("cargo")
            .args(["build", "--bin", "ferrum-gateway"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !build_status.success() {
            return Err("Failed to build ferrum-gateway".into());
        }

        let binary_path = if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
            "./target/debug/ferrum-gateway"
        } else {
            "./target/release/ferrum-gateway"
        };

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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

    fn auth_header(&self) -> String {
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
        let token = encode(&header, &claims, &key).unwrap();
        format!("Bearer {}", token)
    }
}

impl Drop for CbRetryTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A controllable backend: returns configurable status codes.
/// `fail_flag` = true → returns 500; false → returns 200.
/// Also tracks request count for verification.
async fn start_controllable_backend(
    port: u16,
    fail_flag: Arc<AtomicBool>,
    request_count: Arc<AtomicU32>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let fail = fail_flag.clone();
            let count = request_count.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                // Read request line
                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                // Read headers
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }

                count.fetch_add(1, Ordering::SeqCst);

                let (status, body) = if fail.load(Ordering::SeqCst) {
                    (
                        "500 Internal Server Error",
                        r#"{"error":"backend failure"}"#,
                    )
                } else {
                    ("200 OK", r#"{"status":"ok"}"#)
                };

                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

// ============================================================================
// Circuit Breaker Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_circuit_breaker_opens_and_recovers() {
    let harness = CbRetryTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    let fail_flag = Arc::new(AtomicBool::new(false));
    let request_count = Arc::new(AtomicU32::new(0));
    let _backend =
        start_controllable_backend(backend_port, fail_flag.clone(), request_count.clone())
            .await
            .unwrap();

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create proxy with circuit breaker: opens after 3 failures, 3s timeout
    let proxy_data = json!({
        "id": "proxy-cb",
        "listen_path": "/cb",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "circuit_breaker": {
            "failure_threshold": 3,
            "timeout_seconds": 3,
            "success_threshold": 1,
            "failure_status_codes": [500, 502, 503]
        }
    });

    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create proxy");

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Phase 1: Verify normal operation
    let resp = client
        .get(format!("{}/cb/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Should work normally initially"
    );

    // Phase 2: Start failing backend
    fail_flag.store(true, Ordering::SeqCst);

    // Send failures to trip the circuit breaker (need 3+ failures)
    for i in 1..=5 {
        let resp = client
            .get(format!("{}/cb/test", harness.proxy_base_url))
            .send()
            .await
            .unwrap();
        println!("Failure request {}: status={}", i, resp.status().as_u16());
    }

    // Phase 3: Circuit should be open — requests should be rejected immediately (503)
    // without reaching the backend
    let count_before = request_count.load(Ordering::SeqCst);
    let resp = client
        .get(format!("{}/cb/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();
    let count_after = request_count.load(Ordering::SeqCst);

    // When circuit is open, gateway returns 503 without forwarding to backend
    assert_eq!(
        resp.status().as_u16(),
        503,
        "Circuit breaker should return 503 when open"
    );
    assert_eq!(
        count_before, count_after,
        "No request should reach backend when circuit is open"
    );

    // Phase 4: Fix backend and wait for recovery timeout (3s + margin)
    fail_flag.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Phase 5: After recovery timeout, circuit should be half-open — allow one request
    let resp = client
        .get(format!("{}/cb/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Circuit should recover after timeout and successful probe"
    );
}

// ============================================================================
// Retry Logic Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_retry_on_backend_failure() {
    let harness = CbRetryTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    // Backend always fails with 502
    let fail_flag = Arc::new(AtomicBool::new(true));
    let request_count = Arc::new(AtomicU32::new(0));
    let _backend =
        start_controllable_backend(backend_port, fail_flag.clone(), request_count.clone())
            .await
            .unwrap();

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create proxy with retry: max 2 retries on 500
    let proxy_data = json!({
        "id": "proxy-retry",
        "listen_path": "/retry",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "retry": {
            "max_retries": 2,
            "retryable_status_codes": [500, 502, 503],
            "retryable_methods": ["GET", "HEAD"],
            "backoff_strategy": "fixed",
            "backoff_base_ms": 100
        }
    });

    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create proxy");

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Reset counter
    request_count.store(0, Ordering::SeqCst);

    // Send a GET — backend always returns 500, should be retried
    let resp = client
        .get(format!("{}/retry/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();

    // Should get 500 (all retries failed)
    assert_eq!(
        resp.status().as_u16(),
        500,
        "Should return 500 after all retries exhausted"
    );

    // Backend should have received original + 2 retries = 3 requests
    let total_requests = request_count.load(Ordering::SeqCst);
    assert_eq!(
        total_requests, 3,
        "Backend should receive 1 original + 2 retries = 3 requests, got {}",
        total_requests
    );
}

#[tokio::test]
#[ignore]
async fn test_retry_succeeds_on_second_attempt() {
    let harness = CbRetryTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);

    // Start with failing backend
    let fail_flag = Arc::new(AtomicBool::new(true));
    let request_count = Arc::new(AtomicU32::new(0));
    let _backend =
        start_controllable_backend(backend_port, fail_flag.clone(), request_count.clone())
            .await
            .unwrap();

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    let proxy_data = json!({
        "id": "proxy-retry-recover",
        "listen_path": "/retry-recover",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "retry": {
            "max_retries": 3,
            "retryable_status_codes": [500],
            "retryable_methods": ["GET"],
            "backoff_strategy": "fixed",
            "backoff_base_ms": 200
        }
    });

    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    tokio::time::sleep(Duration::from_secs(3)).await;

    // Fix backend after a short delay (during retry window)
    request_count.store(0, Ordering::SeqCst);
    let fail_clone = fail_flag.clone();
    tokio::spawn(async move {
        // After 300ms (one retry), fix the backend
        tokio::time::sleep(Duration::from_millis(300)).await;
        fail_clone.store(false, Ordering::SeqCst);
    });

    let resp = client
        .get(format!("{}/retry-recover/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();

    // Should eventually succeed because backend recovers during retry
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Should succeed after backend recovers during retry, got {}",
        resp.status()
    );

    let total = request_count.load(Ordering::SeqCst);
    assert!(
        total >= 2,
        "Should have made at least 2 requests (original + retry), got {}",
        total
    );
}

// ============================================================================
// Retry + Connect Failure Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_retry_on_connect_failure() {
    let harness = CbRetryTestHarness::new()
        .await
        .expect("Failed to create harness");

    // Use a port where nothing is listening to simulate connect failure
    let dead_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    };

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    let proxy_data = json!({
        "id": "proxy-retry-connect",
        "listen_path": "/retry-connect",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": dead_port,
        "strip_listen_path": true,
        "retry": {
            "max_retries": 2,
            "retry_on_connect_failure": true,
            "retryable_methods": ["GET"],
            "backoff_strategy": "fixed",
            "backoff_base_ms": 100
        }
    });

    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    tokio::time::sleep(Duration::from_secs(3)).await;

    let start = std::time::Instant::now();
    let resp = client
        .get(format!("{}/retry-connect/test", harness.proxy_base_url))
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    // Should fail with 502/503 (backend unreachable after retries)
    assert!(
        resp.status().as_u16() >= 500,
        "Should return 5xx when backend unreachable: got {}",
        resp.status()
    );

    // Should have taken at least 200ms (2 retries * 100ms backoff)
    assert!(
        elapsed >= Duration::from_millis(150),
        "Should have waited for retries, elapsed: {:?}",
        elapsed
    );
}

//! Functional Tests for Circuit Breaker and Retry Logic (E2E)
//!
//! Tests that were previously only covered by unit tests:
//! - Circuit breaker opens after consecutive failures, then half-opens and recovers
//! - Retry logic retries on connect failure and retryable status codes
//! - Retry respects max_retries and retryable_methods
//!
//! Uses database mode with SQLite via the shared `TestGateway` harness. A
//! controllable backend simulates failures.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_circuit_breaker

use crate::common::TestGateway;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ============================================================================
// Controllable backend (specific to these tests — the shared echo helpers
// return fixed responses; circuit-breaker/retry coverage needs a backend
// that can toggle between 200 and 500 at runtime and count requests).
// Listener is held inside the spawned task (no bind-drop-rebind race).
// ============================================================================

async fn start_controllable_backend(
    fail_flag: Arc<AtomicBool>,
    request_count: Arc<AtomicU32>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let fail = fail_flag.clone();
            let count = request_count.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

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
    (port, handle)
}

async fn spawn_gateway() -> TestGateway {
    TestGateway::builder()
        .mode_database_sqlite()
        .log_level("debug")
        .db_poll_interval_seconds(2)
        .spawn()
        .await
        .expect("start gateway")
}

async fn wait_for_proxy_route(
    client: &reqwest::Client,
    url: String,
    timeout: Duration,
) -> reqwest::Response {
    let deadline = Instant::now() + timeout;
    let mut last_status = None;
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().as_u16() != 404 => return resp,
            Ok(resp) => {
                last_status = Some(resp.status());
            }
            Err(err) => {
                eprintln!("waiting for proxy route {url}: {err}");
            }
        }

        assert!(
            Instant::now() < deadline,
            "proxy route {url} did not load before timeout; last status: {:?}",
            last_status
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ============================================================================
// Circuit Breaker Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_circuit_breaker_opens_and_recovers() {
    let fail_flag = Arc::new(AtomicBool::new(false));
    let request_count = Arc::new(AtomicU32::new(0));
    let (backend_port, _backend) =
        start_controllable_backend(fail_flag.clone(), request_count.clone()).await;

    let gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();

    // Create proxy with circuit breaker: opens after 3 failures, 3s timeout
    let proxy_data = json!({
        "id": "proxy-cb",
        "listen_path": "/cb",
        "backend_scheme": "http",
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
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create proxy");

    // Phase 1: Verify normal operation
    let resp = wait_for_proxy_route(
        &client,
        gateway.proxy_url("/cb/test"),
        Duration::from_secs(10),
    )
    .await;
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
            .get(gateway.proxy_url("/cb/test"))
            .send()
            .await
            .unwrap();
        println!("Failure request {}: status={}", i, resp.status().as_u16());
    }

    // Phase 3: Circuit should be open — requests should be rejected immediately (503)
    // without reaching the backend
    let count_before = request_count.load(Ordering::SeqCst);
    let resp = client
        .get(gateway.proxy_url("/cb/test"))
        .send()
        .await
        .unwrap();
    let count_after = request_count.load(Ordering::SeqCst);

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
        .get(gateway.proxy_url("/cb/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Circuit should recover after timeout and successful probe"
    );
}

#[tokio::test]
#[ignore]
async fn stalled_buffered_upload_releases_half_open_probe_neutrally() {
    let fail_flag = Arc::new(AtomicBool::new(false));
    let request_count = Arc::new(AtomicU32::new(0));
    let (backend_port, _backend) =
        start_controllable_backend(fail_flag.clone(), request_count).await;

    let gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();
    let proxy_id = "proxy-cb-stalled-buffer";
    let proxy_data = json!({
        "id": proxy_id,
        "listen_path": "/cb-stalled-buffer",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_read_timeout_ms": 100,
        "retry": {
            "max_retries": 1,
            "retry_on_connect_failure": true,
            "retryable_methods": ["POST"]
        },
        "circuit_breaker": {
            "failure_threshold": 1,
            "timeout_seconds": 1,
            "success_threshold": 2,
            "half_open_max_requests": 1,
            "failure_status_codes": [500]
        }
    });

    let create = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success(), "Failed to create proxy");

    let ready = wait_for_proxy_route(
        &client,
        gateway.proxy_url("/cb-stalled-buffer/test"),
        Duration::from_secs(10),
    )
    .await;
    assert_eq!(ready.status().as_u16(), 200);

    fail_flag.store(true, Ordering::SeqCst);
    let trip = client
        .get(gateway.proxy_url("/cb-stalled-buffer/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(trip.status().as_u16(), 500);
    let open = client
        .get(gateway.proxy_url("/cb-stalled-buffer/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(open.status().as_u16(), 503);

    fail_flag.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;

    // A retry-enabled POST reaches proxy_to_backend's buffered Streaming
    // catch-all after claiming the sole HALF_OPEN probe slot. Send only one of
    // ten promised bytes so the real collector, not a helper-only unit test,
    // must enforce backend_read_timeout_ms.
    let mut stalled = tokio::net::TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .unwrap();
    stalled
        .write_all(
            b"POST /cb-stalled-buffer/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut response))
        .await
        .expect("stalled upload should receive a bounded response")
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "stalled buffered upload should receive 408, got: {response}"
    );

    let status: serde_json::Value = client
        .get(gateway.admin_url("/admin/metrics"))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let breaker = status["circuit_breakers"]
        .as_array()
        .and_then(|breakers| {
            breakers
                .iter()
                .find(|breaker| breaker["proxy_id"] == proxy_id)
        })
        .expect("circuit breaker status entry");
    assert_eq!(
        breaker["state"], "half_open",
        "client upload timeout must neither heal nor reopen the breaker"
    );

    // Immediate backend success proves the timeout released the only probe
    // slot; a leaked slot would make this request a 503.
    let next_probe = client
        .get(gateway.proxy_url("/cb-stalled-buffer/test"))
        .send()
        .await
        .unwrap();
    assert_eq!(next_probe.status().as_u16(), 200);
}

// ============================================================================
// Retry Logic Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_retry_on_backend_failure() {
    // Backend always fails with 500
    let fail_flag = Arc::new(AtomicBool::new(true));
    let request_count = Arc::new(AtomicU32::new(0));
    let (backend_port, _backend) =
        start_controllable_backend(fail_flag.clone(), request_count.clone()).await;

    let gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();

    // Create proxy with retry: max 2 retries on 500
    let proxy_data = json!({
        "id": "proxy-retry",
        "listen_path": "/retry",
        "backend_scheme": "http",
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
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create proxy");

    let _ = wait_for_proxy_route(
        &client,
        gateway.proxy_url("/retry/test"),
        Duration::from_secs(10),
    )
    .await;

    request_count.store(0, Ordering::SeqCst);

    let resp = client
        .get(gateway.proxy_url("/retry/test"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status().as_u16(),
        500,
        "Should return 500 after all retries exhausted"
    );

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
    let fail_flag = Arc::new(AtomicBool::new(true));
    let request_count = Arc::new(AtomicU32::new(0));
    let (backend_port, _backend) =
        start_controllable_backend(fail_flag.clone(), request_count.clone()).await;

    let gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();

    let proxy_data = json!({
        "id": "proxy-retry-recover",
        "listen_path": "/retry-recover",
        "backend_scheme": "http",
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
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let _ = wait_for_proxy_route(
        &client,
        gateway.proxy_url("/retry-recover/test"),
        Duration::from_secs(10),
    )
    .await;

    // Fix backend after a short delay (during retry window)
    request_count.store(0, Ordering::SeqCst);
    let fail_clone = fail_flag.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        fail_clone.store(false, Ordering::SeqCst);
    });

    let resp = client
        .get(gateway.proxy_url("/retry-recover/test"))
        .send()
        .await
        .unwrap();

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
    // Use a port where nothing is listening to simulate connect failure.
    let dead_port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    };

    let gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();

    let proxy_data = json!({
        "id": "proxy-retry-connect",
        "listen_path": "/retry-connect",
        "backend_scheme": "http",
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
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&proxy_data)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let _ = wait_for_proxy_route(
        &client,
        gateway.proxy_url("/retry-connect/test"),
        Duration::from_secs(10),
    )
    .await;

    let start = std::time::Instant::now();
    let resp = client
        .get(gateway.proxy_url("/retry-connect/test"))
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert!(
        resp.status().as_u16() >= 500,
        "Should return 5xx when backend unreachable: got {}",
        resp.status()
    );

    assert!(
        elapsed >= Duration::from_millis(150),
        "Should have waited for retries, elapsed: {:?}",
        elapsed
    );
}

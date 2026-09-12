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
use crate::scaffolding::ports::reserve_refused_tcp_port;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

/// Database-mode admin writes are observed by the proxy through the poller.
/// Ten seconds proved too tight when the hosted application shard ran 578
/// tests concurrently; keep the wait bounded but allow scheduler contention.
const PROXY_ROUTE_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(30);

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
        .capture_output()
        .spawn()
        .await
        .expect("start gateway")
}

async fn wait_for_proxy_route(
    client: &reqwest::Client,
    gateway: &mut TestGateway,
    path: &str,
    timeout: Duration,
) -> reqwest::Response {
    let url = gateway.proxy_url(path);
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

        if !gateway.is_running() {
            panic!(
                "gateway exited while waiting for proxy route {url}; last status: \
                 {last_status:?}\n--- captured gateway output ---\n{}",
                gateway.diagnostic_captured_output()
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "proxy route {url} did not load within {timeout:?}; last status: \
                 {last_status:?}\n--- captured gateway output ---\n{}",
                gateway.diagnostic_captured_output()
            );
        }
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

    let mut gateway = spawn_gateway().await;
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
        &mut gateway,
        "/cb/test",
        PROXY_ROUTE_PROPAGATION_TIMEOUT,
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
        resp.headers()
            .get("x-gateway-error")
            .and_then(|v| v.to_str().ok()),
        Some("circuit_breaker_open"),
        "open-breaker 503 must be distinguishable from a backend 5xx"
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

    let mut gateway = spawn_gateway().await;
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
        &mut gateway,
        "/cb-stalled-buffer/test",
        PROXY_ROUTE_PROPAGATION_TIMEOUT,
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

    let mut gateway = spawn_gateway().await;
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
        &mut gateway,
        "/retry/test",
        PROXY_ROUTE_PROPAGATION_TIMEOUT,
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

    let mut gateway = spawn_gateway().await;
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
        &mut gateway,
        "/retry-recover/test",
        PROXY_ROUTE_PROPAGATION_TIMEOUT,
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
    // Bound-but-not-listening port: kernel ECONNREFUSED and parallel tests
    // cannot steal the port while this reservation is held.
    let dead_port_reservation = reserve_refused_tcp_port().expect("reserve refused backend port");
    let dead_port = dead_port_reservation.port;

    let mut gateway = spawn_gateway().await;
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
        &mut gateway,
        "/retry-connect/test",
        PROXY_ROUTE_PROPAGATION_TIMEOUT,
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

    let _keep_dead_port = dead_port_reservation;
}

// ============================================================================
// Client abort during a HALF_OPEN probe (GHSA-4cq4-3f3f-mq76)
//
// A probe slot used to be released only by the explicit `record_*` call sites
// on each dispatch path. A client that disconnects while its probe is still in
// flight runs none of them — the transport drops the whole service future — so
// the packed breaker state stayed `(HALF_OPEN, count = 1)`. Nothing times out
// of HALF_OPEN, so the gateway then shed EVERY later request to that backend
// with `503 circuit_breaker_open` for the rest of the process lifetime, healthy
// backend or not. The window is widest exactly when the backend is slow, which
// is when a client is most likely to give up.
//
// Both tests below fail against the pre-fix gateway — the recovery request
// stays 503 until the poll deadline — and pass once every dispatch path owns
// its probe slot through the shared RAII guard.
// ============================================================================

/// Backend that can fail on demand, stall before answering, and complete a real
/// WebSocket upgrade, plus the handles a test drives it with.
struct ProbeBackend {
    port: u16,
    fail: Arc<AtomicBool>,
    delay_ms: Arc<AtomicU64>,
    /// Incremented as soon as a request head is read — BEFORE the stall — so a
    /// test can tell "the probe reached the backend" from "the probe is still
    /// being routed".
    requests: Arc<AtomicU32>,
    _task: tokio::task::JoinHandle<()>,
}

async fn start_probe_backend() -> ProbeBackend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fail = Arc::new(AtomicBool::new(false));
    let delay_ms = Arc::new(AtomicU64::new(0));
    let requests = Arc::new(AtomicU32::new(0));

    let task_fail = Arc::clone(&fail);
    let task_delay = Arc::clone(&delay_ms);
    let task_requests = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let fail = Arc::clone(&task_fail);
            let delay = Arc::clone(&task_delay);
            let requests = Arc::clone(&task_requests);
            tokio::spawn(async move {
                serve_probe_connection(socket, fail, delay, requests).await;
            });
        }
    });

    ProbeBackend {
        port,
        fail,
        delay_ms,
        requests,
        _task: task,
    }
}

async fn serve_probe_connection(
    socket: tokio::net::TcpStream,
    fail: Arc<AtomicBool>,
    delay: Arc<AtomicU64>,
    requests: Arc<AtomicU32>,
) {
    use tokio::io::AsyncBufReadExt;

    let (reader, mut writer) = socket.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }

    let mut websocket_key: Option<String> = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("sec-websocket-key")
        {
            websocket_key = Some(value.trim().to_string());
        }
    }

    requests.fetch_add(1, Ordering::SeqCst);
    let delay_ms = delay.load(Ordering::SeqCst);
    if delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    if let Some(key) = websocket_key {
        let accept = derive_accept_key(key.as_bytes());
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        let _ = writer.write_all(response.as_bytes()).await;
        // Hold the upgraded carrier open until the peer goes away.
        let mut drain = Vec::new();
        let _ = reader.read_to_end(&mut drain).await;
        return;
    }

    let (status, body) = if fail.load(Ordering::SeqCst) {
        ("500 Internal Server Error", r#"{"error":"failed"}"#)
    } else {
        ("200 OK", r#"{"status":"ok"}"#)
    };
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.write_all(response.as_bytes()).await;
}

fn probe_abort_proxy(proxy_id: &str, listen_path: &str, backend_port: u16) -> serde_json::Value {
    json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
        // The client abort must beat every gateway-side deadline: a backend
        // read timeout would settle the breaker itself and prove nothing about
        // the dropped-future path.
        "backend_read_timeout_ms": 60000,
        "circuit_breaker": {
            "failure_threshold": 1,
            "timeout_seconds": 1,
            "success_threshold": 1,
            "half_open_max_requests": 1,
            "failure_status_codes": [500]
        }
    })
}

/// Trip the proxy's breaker to OPEN and wait out its 1s recovery timeout,
/// leaving it HALF_OPEN with its single probe slot free.
async fn drive_breaker_to_half_open(
    client: &reqwest::Client,
    gateway: &TestGateway,
    path: &str,
    fail: &Arc<AtomicBool>,
) {
    fail.store(true, Ordering::SeqCst);
    let url = gateway.proxy_url(path);
    let tripped = client.get(&url).send().await.unwrap();
    assert_eq!(
        tripped.status().as_u16(),
        500,
        "the tripping request must reach the failing backend"
    );
    let shed = client.get(&url).send().await.unwrap();
    assert_eq!(
        shed.status().as_u16(),
        503,
        "the breaker must be OPEN after its failure threshold"
    );
    fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;
}

/// The named proxy's breaker state as the admin metrics report it.
async fn breaker_state(client: &reqwest::Client, gateway: &TestGateway, proxy_id: &str) -> String {
    let metrics: serde_json::Value = client
        .get(gateway.admin_url("/admin/metrics"))
        .header("Authorization", gateway.auth_header())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let breakers = metrics["circuit_breakers"]
        .as_array()
        .expect("admin metrics must carry a circuit_breakers array")
        .clone();
    let entry = breakers
        .iter()
        .find(|breaker| breaker["proxy_id"] == proxy_id)
        .unwrap_or_else(|| panic!("no circuit-breaker entry for {proxy_id}"));
    entry["state"]
        .as_str()
        .expect("circuit-breaker state must be a string")
        .to_string()
}

/// Wait until the backend observes one more request than `baseline`, proving
/// the probe is genuinely in flight rather than still being routed.
async fn wait_for_backend_request(requests: &Arc<AtomicU32>, baseline: u32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while requests.load(Ordering::SeqCst) == baseline {
        assert!(
            Instant::now() < deadline,
            "{what} never reached the backend"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Poll until the proxy answers 200 again. Only a 503 is tolerated while
/// waiting: a leaked probe slot is exactly what keeps that 503 coming, so the
/// deadline expiring is the pre-fix failure.
async fn wait_for_probe_admission(client: &reqwest::Client, gateway: &TestGateway, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let url = gateway.proxy_url(path);
    loop {
        let status = client.get(&url).send().await.unwrap().status().as_u16();
        if status == 200 {
            return;
        }
        assert_eq!(status, 503, "unexpected status while waiting for a probe");
        assert!(
            Instant::now() < deadline,
            "the aborted HALF_OPEN probe leaked its slot: the breaker still sheds every \
             request to a healthy backend with 503 circuit_breaker_open"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Send `request` on a raw connection, wait for the backend to receive it, then
/// abort the client with an RST so the gateway sees the disconnect at once.
async fn abort_probe_after_backend_receives(
    gateway: &TestGateway,
    backend: &ProbeBackend,
    request: &[u8],
    what: &str,
) {
    backend.delay_ms.store(10_000, Ordering::SeqCst);
    let baseline = backend.requests.load(Ordering::SeqCst);
    let addr = ("127.0.0.1", gateway.proxy_port);
    let mut aborted = tokio::net::TcpStream::connect(addr).await.unwrap();
    aborted.write_all(request).await.unwrap();
    wait_for_backend_request(&backend.requests, baseline, what).await;
    // RST rather than a lingering FIN: a half-closed socket can sit in the
    // kernel long enough to make the assertions below race the abort.
    // `SO_LINGER = 0` is exactly the RST this test needs and the socket is
    // dropped on the next line, so the blocking-drop caveat behind the
    // deprecation does not apply here.
    #[allow(deprecated)]
    let _ = aborted.set_linger(Some(Duration::ZERO));
    drop(aborted);
    backend.delay_ms.store(0, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test]
#[ignore]
async fn http1_client_abort_during_a_half_open_probe_releases_the_slot() {
    let backend = start_probe_backend().await;
    let mut gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();
    let proxy_id = "proxy-cb-h1-abort";
    let path = "/cb-h1-abort/test";

    let create = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&probe_abort_proxy(proxy_id, "/cb-h1-abort", backend.port))
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success(), "Failed to create proxy");

    let ready =
        wait_for_proxy_route(&client, &mut gateway, path, PROXY_ROUTE_PROPAGATION_TIMEOUT).await;
    assert_eq!(ready.status().as_u16(), 200);

    drive_breaker_to_half_open(&client, &gateway, path, &backend.fail).await;

    // Claim the single probe slot with a request the backend will sit on, then
    // abort the client before any response header is written.
    let request = b"GET /cb-h1-abort/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
    abort_probe_after_backend_receives(&gateway, &backend, request, "the HALF_OPEN probe").await;

    assert_eq!(
        breaker_state(&client, &gateway, proxy_id).await,
        "half_open",
        "a client disconnect is neither a backend success nor a backend failure, so \
         releasing its probe slot must leave breaker health exactly where it was"
    );

    wait_for_probe_admission(&client, &gateway, path).await;
}

#[tokio::test]
#[ignore]
async fn websocket_client_abort_during_a_half_open_probe_releases_the_slot() {
    let backend = start_probe_backend().await;
    let mut gateway = spawn_gateway().await;
    let client = reqwest::Client::new();
    let auth = gateway.auth_header();
    let proxy_id = "proxy-cb-ws-abort";
    let path = "/cb-ws-abort/test";

    let create = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&probe_abort_proxy(proxy_id, "/cb-ws-abort", backend.port))
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success(), "Failed to create proxy");

    let ready =
        wait_for_proxy_route(&client, &mut gateway, path, PROXY_ROUTE_PROPAGATION_TIMEOUT).await;
    assert_eq!(ready.status().as_u16(), 200);

    drive_breaker_to_half_open(&client, &gateway, path, &backend.fail).await;

    // WebSocket is a runtime flavor of the same HTTP proxy, so this upgrade
    // claims the same single probe slot the plain requests above used. It is
    // aborted while the dedicated WebSocket handler still awaits the backend
    // handshake — before the successful-upgrade hop records its success.
    let request = b"GET /cb-ws-abort/test HTTP/1.1\r\n\
                    Host: localhost\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                    Sec-WebSocket-Version: 13\r\n\r\n";
    let what = "the HALF_OPEN WebSocket probe";
    abort_probe_after_backend_receives(&gateway, &backend, request, what).await;

    assert_eq!(
        breaker_state(&client, &gateway, proxy_id).await,
        "half_open",
        "an abandoned WebSocket upgrade must return its probe slot without moving \
         breaker health"
    );

    wait_for_probe_admission(&client, &gateway, path).await;
}

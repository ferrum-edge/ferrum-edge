//! Functional Tests for Admin Observability Endpoints (E2E)
//!
//! Exercises admin endpoints that surface operational state:
//! - `/cluster` — CP/DP connection status (database mode returns informational)
//! - `/metrics/runtime` — JWT-authenticated combined runtime JSON
//! - `/overload` — coarse `{level}` unauthenticated, full snapshot with auth, 503 under request-critical load
//! - `/metrics` — gated by default (401), 200 with admin JWT; `/live` always minimal+unauthenticated
//! - `/namespaces` — distinct sorted namespaces (JWT required)
//! - `/restore` — body-size limit (413) and malformed JSON (400)
//! - JWT auth required on `/cluster`, `/metrics/runtime`, `/namespaces`, `/metrics`, and detailed `/overload`
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_admin_observability --nocapture

use crate::common::TestGateway;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// File-mode slow backend (specific to the /overload 503 test — simulates a
// backend slow enough to pin FERRUM_MAX_REQUESTS above the critical threshold).
// ============================================================================

/// Start a minimal HTTP/1.1 slow backend on a pre-bound listener. Sleeps
/// `delay_ms` before replying 200 OK with Connection: close.
async fn start_slow_backend_on(listener: TcpListener, delay_ms: u64, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        let accept = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
        let Ok(Ok((mut stream, _))) = accept else {
            continue;
        };
        let stop_clone = stop.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            sleep(Duration::from_millis(delay_ms)).await;
            if stop_clone.load(Ordering::Relaxed) {
                let _ = stream.shutdown().await;
                return;
            }
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

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

fn file_config_yaml(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "slow-proxy"
    listen_path: "/slow"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    )
}

// ============================================================================
// Tests
// ============================================================================

/// Test 1: `/cluster` endpoint in database mode — returns 200 + informational JSON.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cluster_endpoint_database_mode() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/cluster", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .send()
        .await
        .expect("GET /cluster failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "/cluster in database mode should return 200"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON body");
    assert_eq!(
        body.get("mode").and_then(|v| v.as_str()),
        Some("database"),
        "mode field should be 'database', got {body}"
    );
    assert!(
        body.get("data_planes").is_none(),
        "database mode should not include data_planes list"
    );
    assert!(
        body.get("message").is_some(),
        "database mode should include an informational message"
    );
}

/// Test 2: `/overload` tiering — unauthenticated callers get a coarse, LB-safe
/// `{level}` with NO resource internals; authenticated callers get the full
/// pressure/counter snapshot.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_overload_endpoint_tiered_auth() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // --- Unauthenticated: coarse {level} only, 200 under normal load ---
    let resp = client
        .get(format!("{}/overload", harness.admin_base_url))
        .send()
        .await
        .expect("GET /overload (unauth) failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/overload under normal load should return 200"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON body");
    assert!(
        body.get("level").and_then(|v| v.as_str()).is_some(),
        "coarse /overload must still expose `level`: {body}"
    );
    for leaked in [
        "active_connections",
        "active_requests",
        "port_exhaustion_events",
        "pressure",
        "actions",
        "stream_listeners",
    ] {
        assert!(
            body.get(leaked).is_none(),
            "unauthenticated /overload must not expose `{leaked}`: {body}"
        );
    }

    // --- Authenticated: full pressure/counter snapshot ---
    let resp = client
        .get(format!("{}/overload", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .send()
        .await
        .expect("GET /overload (auth) failed");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON body");
    assert!(
        body.get("active_connections")
            .and_then(|v| v.as_u64())
            .is_some(),
        "active_connections numeric field missing (auth): {body}"
    );
    assert!(
        body.get("active_requests")
            .and_then(|v| v.as_u64())
            .is_some(),
        "active_requests numeric field missing (auth): {body}"
    );
    assert!(
        body.get("port_exhaustion_events")
            .and_then(|v| v.as_u64())
            .is_some(),
        "port_exhaustion_events numeric field missing (auth): {body}"
    );
    let pressure = body
        .get("pressure")
        .expect("pressure object present (auth, fd/conn/req)");
    for sub in ["file_descriptors", "connections", "requests"] {
        assert!(
            pressure
                .get(sub)
                .and_then(|v| v.get("ratio"))
                .and_then(|v| v.as_f64())
                .is_some(),
            "pressure.{sub}.ratio missing (auth): {body}"
        );
    }
}

/// Test 2b: `/metrics` is gated by default (401), succeeds with an admin JWT;
/// `/live` is always unauthenticated and minimal.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_metrics_gated_and_live_minimal() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // /metrics without a credential → 401.
    let resp = client
        .get(format!("{}/metrics", harness.admin_base_url))
        .send()
        .await
        .expect("GET /metrics (unauth) failed");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "/metrics must require auth by default"
    );

    // /metrics with a valid admin JWT → 200 Prometheus text.
    let resp = client
        .get(format!("{}/metrics", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .send()
        .await
        .expect("GET /metrics (auth) failed");
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap_or_default();
    assert!(
        text.contains("ferrum_"),
        "expected Prometheus metrics output, got: {}",
        &text[..text.len().min(200)]
    );
    for family in [
        "ferrum_log_sink_healthy",
        "ferrum_log_sink_accepted_records_total",
        "ferrum_log_sink_dropped_records_total",
        "ferrum_log_sink_io_failures_total",
        "ferrum_log_sink_shutdown_timeouts_total",
        "ferrum_log_sink_shutdown_incomplete_records_total",
    ] {
        assert!(text.contains(family), "missing {family}: {text}");
    }
    for sink in ["stdout", "stderr"] {
        assert!(
            text.contains(&format!("ferrum_log_sink_healthy{{sink=\"{sink}\"}}")),
            "missing distinct {sink} sink metrics: {text}"
        );
    }

    // /health keeps sink internals in the authenticated detail tier.
    let unauth_health: serde_json::Value = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("GET /health (unauth) failed")
        .json()
        .await
        .expect("health JSON");
    assert!(unauth_health.get("logging").is_none(), "{unauth_health}");
    let auth_health: serde_json::Value = client
        .get(format!("{}/health", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .send()
        .await
        .expect("GET /health (auth) failed")
        .json()
        .await
        .expect("health JSON");
    assert!(
        auth_health["logging"]["stdout"].is_object(),
        "{auth_health}"
    );
    assert!(
        auth_health["logging"]["stderr"].is_object(),
        "{auth_health}"
    );

    // /live is always unauthenticated and minimal.
    let resp = client
        .get(format!("{}/live", harness.admin_base_url))
        .send()
        .await
        .expect("GET /live failed");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("live JSON");
    assert_eq!(body, serde_json::json!({"status": "ok"}));
}

/// Test 3: `/overload` returns 503 under request-critical load.
///
/// Config: `FERRUM_MAX_REQUESTS=4`, `FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD=0.5`
/// (critical when >= 2 in-flight requests), short monitor interval. We fire 6
/// concurrent slow requests at a 3s backend and poll `/overload` during the
/// burst — expecting a 503 response at some point.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_overload_returns_503_under_request_critical() {
    let (backend_port, stop, _backend) = spawn_slow_backend(3000).await;

    // req_critical=0.5 with max_requests=4 => critical when active_requests >= 2.
    let gw = TestGateway::builder()
        .mode_file(file_config_yaml(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_REQUESTS", "4")
        .env("FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD", "0.25")
        .env("FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD", "0.5")
        .env("FERRUM_OVERLOAD_CHECK_INTERVAL_MS", "200")
        .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", "1")
        .capture_output()
        .spawn()
        .await
        .expect("spawn file-mode gateway");
    let proxy_port = gw.proxy_port;
    let admin_port = gw.admin_port;

    // Fire 6 concurrent slow requests in the background.
    let mut join_handles = Vec::new();
    for _ in 0..6 {
        let port = proxy_port;
        join_handles.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();
            let _ = client
                .get(format!("http://127.0.0.1:{port}/slow"))
                .send()
                .await;
        }));
    }

    // Poll /overload for up to ~4 seconds looking for 503.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let overload_url = format!("http://127.0.0.1:{admin_port}/overload");

    let mut saw_503 = false;
    let mut last_status: u16 = 0;
    let mut last_body: serde_json::Value = serde_json::Value::Null;
    for _ in 0..20 {
        sleep(Duration::from_millis(200)).await;
        let resp = match client.get(&overload_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Read status BEFORE consuming body (so we can assert both).
        last_status = resp.status().as_u16();
        last_body = resp.json().await.unwrap_or(serde_json::Value::Null);
        if last_status == 503 {
            saw_503 = true;
            // Verify body is readable JSON at critical level.
            assert_eq!(
                last_body.get("level").and_then(|v| v.as_str()),
                Some("critical"),
                "expected level=critical when /overload returns 503, got {last_body}"
            );
            break;
        }
    }

    // Let in-flight requests complete so the drop runs cleanly.
    for h in join_handles {
        let _ = h.await;
    }

    // Teardown. TestGateway's Drop kills the gateway; we still need to stop
    // the backend task so its listener releases.
    stop.store(true, Ordering::Relaxed);
    drop(gw);
    sleep(Duration::from_millis(100)).await;

    assert!(
        saw_503,
        "expected /overload to return 503 at some point during burst \
         (last status={last_status}, last body={last_body})"
    );
}

/// Test 4: `/namespaces` returns distinct namespaces sorted (JWT required).
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_namespaces_distinct_sorted() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create 3 proxies in 3 different namespaces.
    for (ns, path) in [
        ("zeta", "/zeta"),
        ("alpha", "/alpha"),
        ("middle", "/middle"),
    ] {
        let proxy = json!({
            "id": format!("obs-proxy-{ns}"),
            "listen_path": path,
            "backend_scheme": "http",
            "backend_host": "localhost",
            "backend_port": 9999,
            "strip_listen_path": true,
        });
        let resp = client
            .post(format!("{}/proxies", harness.admin_base_url))
            .header("Authorization", &auth)
            .header("X-Ferrum-Namespace", ns)
            .json(&proxy)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "Failed to create proxy in namespace {ns}: {}",
            resp.status()
        );
    }

    // Give the poller a moment to observe the new namespaces.
    sleep(Duration::from_millis(500)).await;

    let resp = client
        .get(format!("{}/namespaces", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("GET /namespaces failed");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.expect("JSON body");
    let arr = body["data"].as_array().expect("namespaces data array");

    let names: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Must contain all three (plus possibly default "ferrum") in sorted order.
    for ns in ["alpha", "middle", "zeta"] {
        assert!(
            names.iter().any(|n| n == ns),
            "namespace {ns} missing from response: {names:?}"
        );
    }
    // Subsequence "alpha","middle","zeta" must appear in sorted order.
    let idx_alpha = names.iter().position(|n| n == "alpha").unwrap();
    let idx_middle = names.iter().position(|n| n == "middle").unwrap();
    let idx_zeta = names.iter().position(|n| n == "zeta").unwrap();
    assert!(
        idx_alpha < idx_middle && idx_middle < idx_zeta,
        "namespaces should appear in sorted order, got {names:?}"
    );
}

/// Test 5: `/namespaces` requires JWT auth.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_namespaces_requires_jwt() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // No Authorization header.
    let resp = client
        .get(format!("{}/namespaces", harness.admin_base_url))
        .send()
        .await
        .expect("GET /namespaces failed");
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/namespaces without auth should be 401 or 403, got {status}"
    );

    // Invalid token.
    let resp = client
        .get(format!("{}/namespaces", harness.admin_base_url))
        .header("Authorization", "Bearer bogus-token-value")
        .send()
        .await
        .expect("GET /namespaces failed");
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/namespaces with invalid token should be 401 or 403, got {status}"
    );
}

/// Test 6: `/cluster` requires JWT auth.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cluster_requires_jwt() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/cluster", harness.admin_base_url))
        .send()
        .await
        .expect("GET /cluster failed");
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/cluster without auth should be 401 or 403, got {status}"
    );

    let resp = client
        .get(format!("{}/cluster", harness.admin_base_url))
        .header("Authorization", "Bearer not-a-valid-token")
        .send()
        .await
        .expect("GET /cluster failed");
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/cluster with invalid token should be 401 or 403, got {status}"
    );
}

/// Test 7: `/metrics/runtime` requires JWT auth and returns a live system sample.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_runtime_metrics_endpoint_requires_jwt_and_returns_system_json() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .env("FERRUM_METRICS_SYSTEM_SAMPLE_INTERVAL_MS", "100")
        .env("FERRUM_METRICS_RUNTIME_CACHE_MS", "0")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let unauth = client
        .get(format!("{}/metrics/runtime", harness.admin_base_url))
        .send()
        .await
        .expect("GET /metrics/runtime without auth failed");
    let status = unauth.status().as_u16();
    assert!(
        status == 401 || status == 403,
        "/metrics/runtime without auth should be 401 or 403, got {status}"
    );

    let mut last_body = serde_json::Value::Null;
    for _ in 0..20 {
        sleep(Duration::from_millis(100)).await;
        let resp = client
            .get(format!("{}/metrics/runtime", harness.admin_base_url))
            .header("Authorization", harness.auth_header())
            .send()
            .await
            .expect("GET /metrics/runtime with auth failed");
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.expect("runtime metrics JSON");
        if body["system"]["memory"]["rss_bytes"].as_u64().unwrap_or(0) > 0 {
            last_body = body;
            break;
        }
        last_body = body;
    }

    assert_eq!(last_body["mode"].as_str(), Some("database"));
    assert!(last_body["timestamp"].as_str().is_some(), "{last_body}");
    assert!(
        last_body["system"]["sampled_at_unix_ms"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "{last_body}"
    );
    assert!(
        last_body["system"]["cpu"]["cpu_count"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "{last_body}"
    );
    assert!(
        last_body["system"]["memory"]["rss_bytes"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "system sampler did not populate RSS within 2s: {last_body}"
    );
    assert!(last_body["http"]["status_codes"]["totals"].is_object());
    assert!(last_body["logs"]["sinks"]["stdout"].is_object());
    assert!(last_body["logs"]["sinks"]["stderr"].is_object());
    assert_eq!(last_body["overload"]["level"].as_str(), Some("normal"));
}

/// Test 8: `/restore` body-size limit — POST a 2 MiB body with a 1 MiB limit → 413.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_restore_body_size_limit() {
    // FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB=1
    let harness = TestGateway::builder()
        .log_level("warn")
        .env("FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB", "1")
        .spawn()
        .await
        .expect("Failed to create harness with restore limit");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();

    // Build a 2 MiB body (above the 1 MiB cap). We include one padding field
    // to make this valid JSON shape-wise, though the size check fires before
    // parsing.
    let padding = "a".repeat(2 * 1024 * 1024);
    let body = format!(r#"{{"proxies":[],"pad":"{padding}"}}"#);
    assert!(body.len() > 1024 * 1024, "test body must exceed 1 MiB");

    // Gateway enforces the size cap by returning 413 PAYLOAD_TOO_LARGE and
    // closing the connection. Two outcomes are observable from the client:
    //
    //   1. The gateway reads + buffers up to 1 MiB, sends 413, then closes.
    //      If the client managed to flush the rest of the 2 MiB body into
    //      the socket before the close lands, it sees the 413 cleanly.
    //
    //   2. The client is still writing the body when the connection is
    //      closed. macOS surfaces this as ECONNRESET in `BodyWrite`. Newer
    //      reqwest / hyper-util raise that as a `Request` error rather than
    //      silently completing. This is a race against TCP send/receive
    //      buffer pressure (~128 KiB on macOS by default), so under
    //      parallel test load the connection-reset path is the common one.
    //
    // Both outcomes prove the gateway enforced the cap — accept either.
    match client
        .post(format!("{}/restore?confirm=true", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(resp) => assert_eq!(
            resp.status().as_u16(),
            413,
            "2 MiB body under 1 MiB limit should return 413 PAYLOAD_TOO_LARGE \
             when the response races back before the connection close"
        ),
        Err(err) => {
            // First, confirm this is the gateway-closed-mid-body class of
            // error (not e.g. a connect failure that would mean the gateway
            // never saw the request in the first place). Walk the source
            // chain to find an `io::Error` and match on `ErrorKind` —
            // that's a stable surface across reqwest / hyper-util patch
            // releases; stringifying `Debug` would silently bypass real
            // bugs the moment those crates reword their errors.
            let mut io_kind: Option<std::io::ErrorKind> = None;
            let mut cur: Option<&dyn std::error::Error> = Some(&err);
            while let Some(e) = cur {
                if let Some(io) = e.downcast_ref::<std::io::Error>() {
                    io_kind = Some(io.kind());
                    break;
                }
                cur = e.source();
            }
            assert!(
                matches!(
                    io_kind,
                    Some(
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    )
                ),
                "expected gateway-closed-mid-body io::Error \
                 (ConnectionReset / BrokenPipe / ConnectionAborted / UnexpectedEof) \
                 after enforcing the size cap, got: {err:?}"
            );

            // Second, prove the gateway is still alive and serving — a
            // listener crash / panic mid-test would surface the same
            // ECONNRESET above without ever exercising the size cap. By
            // following up with `/health` (unauthenticated, no body) we
            // distinguish "gateway closed our oversize upload" (passing,
            // /health responds 200) from "gateway died" (failing, /health
            // returns a transport error of its own).
            let health_resp = client
                .get(format!("{}/health", harness.admin_base_url))
                .send()
                .await
                .expect(
                    "/health request after oversize POST failed — \
                         this means the earlier ECONNRESET was not the \
                         size-cap path: the gateway is no longer serving",
                );
            assert_eq!(
                health_resp.status().as_u16(),
                200,
                "gateway must remain healthy after rejecting the \
                 oversized restore body — got {} from /health",
                health_resp.status()
            );

            // Third, prove the cap is `/restore`-specific (not a generic
            // listener problem) by sending a small valid restore body and
            // requiring the response to be anything *other* than 413
            // PAYLOAD_TOO_LARGE. If the gateway is misconfigured and the
            // size cap is firing on every body, this catches it.
            let small_body = r#"{"proxies":[],"consumers":[],"plugins":[]}"#;
            let small_resp = client
                .post(format!("{}/restore?confirm=true", harness.admin_base_url))
                .header("Authorization", harness.auth_header())
                .header("Content-Type", "application/json")
                .body(small_body)
                .send()
                .await
                .expect("small /restore POST after oversize failure errored");
            assert_ne!(
                small_resp.status().as_u16(),
                413,
                "small (<1 MiB) body must not hit the size cap — \
                 got 413 from /restore for a {}-byte body",
                small_body.len()
            );
        }
    }
}

/// Test 9: `/restore` with malformed JSON → 400 with parse error in body.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_restore_malformed_json() {
    let harness = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // Small body (well under 1 MiB default), intentionally malformed.
    let body = "{not valid json";
    let resp = client
        .post(format!("{}/restore?confirm=true", harness.admin_base_url))
        .header("Authorization", harness.auth_header())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("POST /restore failed");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "malformed JSON should return 400"
    );
    let text = resp.text().await.unwrap_or_default();
    let body_json: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| json!({"error": text.clone()}));
    let err_msg = body_json
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        err_msg.to_lowercase().contains("invalid json")
            || err_msg.to_lowercase().contains("parse")
            || err_msg.to_lowercase().contains("expected"),
        "error message should mention JSON parse failure, got: {err_msg}"
    );
}

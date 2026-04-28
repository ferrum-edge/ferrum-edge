//! Phase-8 functional gap-fill tests for the retry policy.
//!
//! Exercises retry-policy semantics that the existing
//! `functional_circuit_breaker_retry_test` does not cover:
//!
//! * `retry_on_methods` enforcement (POST must NOT replay even on
//!   connection-level failures when only GET is in the retry list).
//! * H3 capability-registry interaction with the per-target dispatch
//!   contract: same-target retries stay on the protocol the attempt
//!   started with; load-balancer rotation to a different target
//!   recomputes the dispatch decision against the registry so a
//!   mixed-capability upstream (target A speaks H3, target B speaks
//!   H1) correctly switches transports across attempts.
//! * Streaming-body requests are NOT replayed by the retry loop (the
//!   Codex P1 fix; previously a same-request fallback could double-
//!   fire the body).
//! * `max_retries: 0` disables retries even with `retry_on_connect_failure`
//!   enabled.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_retry \
//!     -- --ignored --nocapture
//! ```

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    H3Step, H3TlsConfig, ScriptedH3Backend, ScriptedTcpBackend, ScriptedTlsBackend, TcpStep,
    TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, reserve_udp_port};
use serde_json::json;
use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

// ────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────────────

/// Mirror of the helper in `functional_capability_registry_test`. Reserve
/// a TCP listener and a UDP socket on the same port; used by tests that
/// need both an H3 + TCP+TLS backend behind a single `backend_port`.
async fn reserve_colocated_tcp_udp()
-> Result<(TcpListener, UdpSocket, u16), Box<dyn std::error::Error + Send + Sync>> {
    for attempt in 0..10 {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let port = tcp.local_addr()?.port();
        match StdUdpSocket::bind(("127.0.0.1", port)) {
            Ok(std_udp) => {
                std_udp.set_nonblocking(true)?;
                let udp = UdpSocket::from_std(std_udp)?;
                return Ok((tcp, udp, port));
            }
            Err(e) => {
                drop(tcp);
                if attempt == 9 {
                    return Err(format!("udp bind at shared port failed: {e}").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    Err("exhausted colocated TCP/UDP reservation retries".into())
}

/// Frontend cert+key files in a leaked scratch dir.
fn write_frontend_certs(scratch: &std::path::Path, ca_name: &str) -> (String, String) {
    let ca = TestCa::new(ca_name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// File-mode YAML for one HTTP proxy with an explicit retry policy.
fn http_with_retry(port: u16, retry: serde_json::Value) -> String {
    let config = json!({
        "proxies": [{
            "id": "phase8-retry",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "retry": retry,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// File-mode YAML for one HTTPS proxy with an explicit retry policy.
fn https_with_retry(port: u16, retry: serde_json::Value) -> String {
    let config = json!({
        "proxies": [{
            "id": "phase8-retry-h3",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "retry": retry,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — `retry_on_methods` enforcement.
// ────────────────────────────────────────────────────────────────────────────
//
// Backend script: every accepted connection sends a TCP RST. Retry policy
// allows up to 3 retries on connect failure for ANY method, but
// `retryable_methods` is `["GET"]`. Because the failure is a connection
// reset BEFORE the response is parsed, ferrum-edge classifies it as
// `connection_error = true` — the retry condition that ignores method
// (the gateway considers connection-level failures safe to retry across
// any method, see `should_retry()` in `src/retry.rs`).
//
// To assert *method-scoped* retry, we use a different fixture: backend
// returns 502 (HTTP-level failure, not connection-level), with
// `retryable_status_codes = [502]` and `retryable_methods = ["GET"]`.
// Then POST sees a single attempt while GET sees max_retries+1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_respects_retry_on_methods() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;

    // Each connection: read request, return 502 with body. The
    // RepeatEachConnection mode (default for ScriptedTcpBackend) replays
    // the script for every retry attempt.
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        .step(TcpStep::Write(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\nConnection: close\r\n\r\n502"
                .to_vec(),
        ))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn backend");

    // Retry: up to 3 attempts, only on GET, only for status 502.
    let yaml = http_with_retry(
        backend_port,
        json!({
            "max_retries": 3,
            "retryable_status_codes": [502],
            "retryable_methods": ["GET"],
            "retry_on_connect_failure": false,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Disable pool warmup probes so the backend's accepted-
        // connection counter reflects only request-driven traffic.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    // Capture any pre-test connections (should be 0; defensive).
    let baseline = backend.accepted_connections();

    // POST — must NOT retry (method not in `retryable_methods`).
    let _post_resp = client
        .request(reqwest::Method::POST, &harness.proxy_url("/api/x"))
        .body(b"hello".to_vec())
        .send()
        .await
        .expect("post resp");
    let post_total = backend.accepted_connections();
    let post_count = post_total - baseline;

    // GET — must retry up to 3 times (4 total attempts).
    let _get_resp = client
        .get(&harness.proxy_url("/api/y"))
        .await
        .expect("get resp");
    // Allow the backend to finish accepting all retry attempts.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let total_count = backend.accepted_connections();
    let get_count = total_count - post_total;

    assert_eq!(
        post_count, 1,
        "POST must NOT retry (got {post_count} attempts) — retryable_methods=[GET] (baseline={baseline}, post_total={post_total})"
    );
    // max_retries=3 → 1 initial + 3 retries = exactly 4 attempts. A
    // weaker `>= 4` would silently allow a regression where the gateway
    // retried beyond the configured cap (e.g., 5+ attempts), defeating
    // the retry-limit contract this test protects.
    assert_eq!(
        get_count, 4,
        "GET must retry exactly max_retries=3 times (1 initial + 3 retries = 4 attempts); \
         got {get_count}. Anything other than 4 means either the retry loop short-circuited \
         (< 4) or exceeded the cap (> 4). post_total={post_total}, total_count={total_count}."
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — Post-H3-downgrade requests route via the cross-protocol bridge.
// ────────────────────────────────────────────────────────────────────────────
//
// IMPORTANT: this test does NOT assert that within-request retry replays
// over the bridge. ferrum-edge intentionally does not silently fall
// through to reqwest after an H3 transport failure inside the same
// request — the dispatch decision is made once per request, so all
// in-request retry attempts use the native H3 pool. The 502 from the
// first request is therefore the expected, documented behavior (see
// CLAUDE.md "Single-protocol-per-request contract" and the sibling
// test `retry_attempts_within_same_request_stay_on_h3_pool` below).
// The retry-policy field is configured here only so the gateway
// exercises the H3 retry loop; the configured `max_retries` is
// exhausted at the H3 layer.
//
// Setup: H3-capable backend on UDP that closes the connection on the
// first stream. The TCP+TLS side answers OK. Retry policy is configured
// so the gateway runs its retry loop (and we observe that retry alone
// does NOT change dispatch).
//
// Assertions:
//   * The first request observably went to H3 (the H3 backend recorded
//     stream activity), proving dispatch took the native pool.
//   * The first request returns a 5xx — proving the in-request retry
//     loop did NOT magically fall back to the bridge.
//   * After the registry downgrade fires, a SECOND request routes via
//     the cross-protocol bridge → TCP backend → 200.
//
// If `mark_h3_unsupported`/registry-downgrade or post-downgrade routing
// regresses, this test fails. If retry replay across pools were ever
// added (a behavior change), the first-request assertion would catch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn post_h3_downgrade_subsequent_requests_route_via_cross_protocol_bridge() {
    let ca = TestCa::new("phase8-retry-h3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side answers OK for the bridge fallback.
    let tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbridge".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 backend accepts the first stream, then closes the connection.
    let h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::CloseConnectionWithCode(0x10c)) // H3_REQUEST_CANCELLED
        .spawn()
        .expect("spawn h3");

    // Frontend HTTPS port for the H3 client. We enable HTTP/3 on the
    // gateway and let it send H3 to the H3 backend.
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (cert_path, key_path) = write_frontend_certs(scratch.path(), "phase8-retry-gw");
    Box::leak(Box::new(scratch));

    let yaml = https_with_retry(
        backend_port,
        json!({
            "max_retries": 2,
            "retry_on_connect_failure": true,
            "retryable_methods": ["GET"],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    // Wait for the warmup probe to populate the registry with h3=Supported.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await {
            let entries = body["entries"].as_array().cloned().unwrap_or_default();
            if let Some(e) = entries.first()
                && e["plain_http"]["h3"].as_str() == Some("supported")
            {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // H3 client request 1: dispatched to the native H3 pool. The H3
    // backend cancels the stream, the gateway's retry loop exhausts at
    // the H3 layer (within-request fallback to the bridge is
    // intentionally not supported), and the response is a 5xx.
    let client = Http3Client::insecure().expect("h3 client");
    let url1 = format!("https://127.0.0.1:{https_port}/api/retry-1");
    let first = client.get(&url1).await.expect("h3 first request");
    assert!(
        first.status.as_u16() >= 500 && first.status.as_u16() < 600,
        "first request should fail at the H3 layer (no within-request bridge fallback); got {first:?}"
    );

    // The H3 backend MUST have observed the first request — otherwise
    // dispatch never went through the native pool and this whole test
    // is meaningless. This catches a regression where dispatch silently
    // routes to the bridge on the first request.
    let h3_streams_after_first = h3_backend.received_requests().await.len();
    assert!(
        h3_streams_after_first >= 1,
        "first request should have hit the native H3 pool; H3 backend saw {h3_streams_after_first} streams"
    );

    // Wait for the registry downgrade to land.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await {
            let entries = body["entries"].as_array().cloned().unwrap_or_default();
            if let Some(e) = entries.first()
                && e["plain_http"]["h3"].as_str() == Some("unsupported")
            {
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Second request: registry says h3=Unsupported → must route through
    // the cross-protocol bridge → TCP backend → 200.
    let url2 = format!("https://127.0.0.1:{https_port}/api/retry-2");
    let second = client.get(&url2).await.expect("h3 second request");
    assert_eq!(
        second.status.as_u16(),
        200,
        "second request must route via bridge after downgrade; got {second:?}"
    );

    // The TCP backend (the bridge) must have served at least one
    // connection — proves subsequent requests went through reqwest.
    let bridge_count = tcp_backend.accepted_connections();
    assert!(
        bridge_count >= 1,
        "expected the TCP+TLS bridge backend to handle at least one request after downgrade; got {bridge_count}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — Streaming POST request bodies are NOT replayed by the retry
// loop.
// ────────────────────────────────────────────────────────────────────────────
//
// The Codex P1 fix ensures that body replay only happens via the
// configured retry policy, never via same-request fallback. This test
// drives a POST with a streaming body (no Content-Length, chunked
// encoding) where the first attempt closes the connection mid-body —
// the retry loop must NOT re-buffer and replay the body, because
// streaming bodies have already been consumed.
//
// We accept either of two outcomes:
//   1. The gateway returns 502 / 500 / 504 — the gateway noticed the
//      streaming body cannot be replayed and gave up after the first
//      attempt.
//   2. The gateway returns 200 — only possible if the gateway buffered
//      the body up front.
//
// What we ASSERT is that the backend received exactly one POST body
// upload — not two — regardless of which path the gateway took. This
// is the Codex P1 regression guarantee.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_does_not_replay_streaming_request_body() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;

    // Backend: read request prelude, then RST. ReadUntil on \r\n\r\n
    // captures the headers; the body bytes that follow are recorded
    // via implicit consumption when the gateway writes them. We use
    // `Reset` to force the gateway's retry loop to consider the failure
    // a connection-level error.
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        // Read enough body bytes to absorb whatever the client sends
        // before the script closes — keeps the wire-state observable.
        .step(TcpStep::Sleep(Duration::from_millis(100)))
        .step(TcpStep::Reset)
        .spawn()
        .expect("spawn backend");

    let yaml = http_with_retry(
        backend_port,
        json!({
            "max_retries": 3,
            "retry_on_connect_failure": true,
            "retryable_methods": ["POST"],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Disable warmup so the backend's count is purely request-driven.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    // Capture any baseline accepted connections.
    let baseline = backend.accepted_connections();

    // Build a streaming POST body via reqwest's Stream wrapper. The
    // body is a single 1KB chunk that the client streams to the
    // gateway.
    let raw_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let body_bytes: Vec<u8> = vec![b'x'; 1024];

    // Use reqwest's stream() + futures::stream::once to make this a
    // real streaming body (Transfer-Encoding: chunked).
    use futures_util::stream;
    let stream =
        stream::once(
            async move { Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(body_bytes)) },
        );
    let body = reqwest::Body::wrap_stream(stream);

    let url = harness.proxy_url("/api/stream");
    let resp = raw_client.post(&url).body(body).send().await;
    eprintln!("test3 resp: {resp:?}");

    // Allow the backend to finish counting.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let total = backend.accepted_connections();
    let attempts = total - baseline;
    // The Codex P1 invariant has TWO halves:
    //   * `attempts >= 1` — the gateway DID reach the backend at least
    //     once. Without this floor, a routing/startup regression that
    //     never forwards the request would silently pass `<= 1`.
    //   * `attempts <= 1` — the gateway did NOT replay a streaming
    //     body. Replaying a streaming POST body is the actual bug
    //     this test was added to catch (Codex P1).
    // Together they mean: exactly one attempt, no replay.
    assert_eq!(
        attempts, 1,
        "streaming POST must reach the backend exactly once — no replay AND no \
         missing attempt. Got {attempts} attempts (baseline={baseline}, total={total}). \
         attempts==0 would mean the request never reached the backend; attempts>1 \
         means the gateway replayed a streaming body."
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test — `retry_on_connect_failure` honors pre-wire transport failures even
// when `retryable_methods=[]` AND `retryable_status_codes=[]`.
// ────────────────────────────────────────────────────────────────────────────
//
// This is the contract the unified `connection_error` classification was
// introduced to protect: any failure that classifies as pre-wire transport
// (`request_reached_wire(error_class) == false`) MUST trigger
// `retry_on_connect_failure` regardless of method/status allowlists. The
// previous code derived `connection_error` from
// `e.is_connect() || e.is_timeout()` at the reqwest sites, which mostly
// agreed with the new contract for connect-class failures but was
// inconsistent across the H3, gRPC, and direct-H2 paths. The new contract
// funnels every dispatcher through the same `request_reached_wire` boundary.
//
// Setup: bind a TCP listener, drop it BEFORE starting the gateway, then
// point the gateway at that port. The kernel returns ECONNREFUSED on every
// connect attempt — the cleanest possible pre-wire transport failure
// (DnsLookupError / TlsError / handshake races are all unambiguous
// `request_reached_wire == false` cases too, but ECONNREFUSED is the
// least timing-sensitive). reqwest classifies it as
// `ErrorClass::ConnectionRefused`, which `request_reached_wire` maps to
// `false`, so `connection_error=true` and `retry_on_connect_failure` must
// fire.
//
// We count attempts by tallying the gateway's `"Backend request failed"`
// log lines (one per attempt) — `accepted_connections()` doesn't apply
// here because nothing accepts.
//
// We use POST as the strictest case — any classification leak that demoted
// the failure to `connection_error=false` would route the retry decision
// through `retryable_methods`, which is `[]`, and the retry would not fire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_on_connect_failure_fires_with_empty_methods_and_statuses() {
    // Reserve a port and immediately release it. The kernel will refuse
    // every subsequent connect attempt to that port (assuming nothing
    // else binds it in the meantime — vanishingly unlikely on the
    // localhost-loopback address space the harness uses).
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    drop(reservation);

    let yaml = http_with_retry(
        backend_port,
        json!({
            "max_retries": 3,
            "retry_on_connect_failure": true,
            // Zero allowlist on BOTH method and status. This is what
            // operators set when they want ONLY connect-failure retry —
            // explicitly opting out of method/status replay so POST
            // stays safely non-idempotent on application-level errors.
            "retryable_methods": [],
            "retryable_status_codes": [],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        // Disable pool warmup so it doesn't probe the dead backend at
        // startup and skew the log count.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");

    // POST is the strictest case — `retryable_methods=[]` would normally
    // forbid replay. The retry-on-connect-failure path applies regardless
    // because connect-refused is a pre-wire transport class.
    let resp = client
        .request(reqwest::Method::POST, &harness.proxy_url("/api/x"))
        .body(b"hello".to_vec())
        .send()
        .await
        .expect("post request");
    assert_eq!(
        resp.status().as_u16(),
        502,
        "gateway must return 502 after exhausting retries; got {resp:?}"
    );

    // Give the gateway time to flush its log after the final retry attempt.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Each retry attempt logs `"Backend request failed"` (initial) or
    // `"Backend retry request failed"` — count both. With max_retries=3,
    // we expect 4 lines total: 1 initial + 3 retries. Anything other
    // than 4 means the retry boundary regressed.
    let combined = harness.captured_combined().expect("captured logs");
    let attempts = combined
        .lines()
        .filter(|l| {
            l.contains("Backend request failed") || l.contains("Backend retry request failed")
        })
        .count();

    if attempts != 4 {
        eprintln!(
            "--- gateway logs (matching backend-failure lines) ---\n{}",
            combined
                .lines()
                .filter(|l| l.contains("Backend request failed")
                    || l.contains("Backend retry request failed"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    // 1 initial + 3 retries = 4 attempts, full stop. Any classification
    // leak that demoted the connect-refused failure to
    // `connection_error=false` would short-circuit the retry (because
    // `retryable_methods=[]` rejects POST replay) and we'd see exactly
    // 1 attempt. The reverse — attempts > 4 — would mean the retry loop
    // exceeded `max_retries`, also a regression.
    assert_eq!(
        attempts, 4,
        "retry_on_connect_failure must fire on pre-wire transport failures \
         even when retryable_methods=[] and retryable_status_codes=[]; \
         expected 4 attempts (1 initial + max_retries=3), got {attempts}. \
         attempts==1 means the unified boundary regressed — connect-refused \
         was misclassified as connection_error=false and fell through to \
         method/status retry, which the empty allowlist disables."
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — `max_retries: 0` disables retries entirely.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_max_retries_zero_means_no_retry() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;

    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Reset)
        .spawn()
        .expect("spawn backend");

    let yaml = http_with_retry(
        backend_port,
        json!({
            "max_retries": 0,
            "retry_on_connect_failure": true,
            "retryable_methods": ["GET", "POST"],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Disable pool warmup so the only connection the backend sees
        // is the one driven by our request — not a probe.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    // Pre-test: capture the warmup count (should be 0 with warmup off,
    // but be conservative).
    let baseline = backend.accepted_connections();

    let client = harness.http_client().expect("client");
    let _resp = client.get(&harness.proxy_url("/api/none")).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let post_request = backend.accepted_connections();
    let attempts = post_request - baseline;
    assert_eq!(
        attempts, 1,
        "max_retries=0 must mean exactly one attempt; got {attempts} (baseline={baseline}, post={post_request})"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — Within-request retries stay on the H3 pool.
// ────────────────────────────────────────────────────────────────────────────
//
// Sibling of `post_h3_downgrade_subsequent_requests_route_via_cross_protocol_bridge`.
// That test asserts the next-REQUEST contract; this one pins the
// same-request contract: once a request dispatches via the native H3
// pool, every retry attempt for that request stays on H3, even after
// `mark_h3_unsupported` downgrades the cached capability.
//
// Industry practice (Envoy, NGINX, HAProxy, Cloudflare, GFE) is that
// retries within a single request stay on the same transport — the
// failed transport attempt may already have flushed headers / body
// before the error surfaced, so cross-protocol replay would bypass
// `proxy.retry.retry_on_methods` and risk duplicating non-idempotent
// requests. Capability downgrade fires on the first H3 transport
// failure, but it routes the NEXT request, not this one.
//
// Setup:
//   * H3 backend that accepts the stream and immediately sends
//     `RESET_STREAM(0x10c)`. The "reset" substring in the gateway's
//     classifier produces `ConnectionReset` (`connection_error=true`),
//     which trips `retry_on_connect_failure` so the retry loop fires.
//   * TCP+TLS backend on the same port that would answer 200 OK if hit
//     by the cross-protocol bridge. Pre-fix behavior would route
//     iteration 1+ via reqwest → this backend; post-fix it never gets a
//     connection during the first request.
//
// Retry policy: `max_retries: 2`, `retry_on_connect_failure: true`,
// `retryable_methods: ["GET"]` — guarantees both retries fire.
//
// Assertions:
//   * Response is 5xx — proves the retry loop never silently fell
//     through to reqwest (which would have returned 200 from the TCP+TLS
//     backend).
//   * The H3 backend recorded ≥ 1 request — proves dispatch went
//     through the native H3 pool. (We avoid a strict `== 3` here; the
//     intra-pool reconnect path can short-circuit a retry attempt
//     before opening a backend stream when the cached connection is
//     invalidated mid-attempt. The contract this test pins is "no
//     mid-request bridge fallback", not "exactly N backend streams".)
//   * The TCP+TLS bridge backend saw 0 connections during the first
//     request — the load-bearing assertion. Pre-fix would route
//     iteration 1+ via reqwest after `mark_h3_unsupported` fires,
//     producing ≥ 1 connection here. Post-fix it stays at 0.
//   * Registry shows `h3 = unsupported` after the request — proves the
//     downgrade hook still fires (it just doesn't affect the in-flight
//     request).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_attempts_within_same_request_stay_on_h3_pool() {
    let ca = TestCa::new("retry-h3-same-request").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // Bridge fallback target — answers 200 OK if reqwest ever routes
    // here mid-request. We pre-load enough script copies that any
    // accidental cross-protocol replay would observably succeed (the
    // assertion below is `accepted_connections() == 0`, so this is
    // belt-and-braces).
    let tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbridge".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 backend: every accepted connection accepts the stream, then
    // closes the connection with H3_REQUEST_CANCELLED. The script runs
    // fresh per accepted connection, so each gateway-level retry that
    // establishes a new QUIC connection sees the same post-wire H3
    // transport failure. Use an explicit non-graceful close rather than
    // RESET_STREAM: on Linux the scripted connection's eventual
    // H3_NO_ERROR teardown can race ahead of the reset at recv_response.
    let h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::CloseConnectionWithCode(0x10c))
        .spawn()
        .expect("spawn h3");

    // Retry policy that DEFINITELY fires on connection-class failures.
    // The H3 application close is a transport-class failure after the
    // request reached the wire; GET is explicitly retryable, so
    // `should_retry` returns true for the configured `max_retries: 2`.
    let yaml = https_with_retry(
        backend_port,
        json!({
            "max_retries": 2,
            "retry_on_connect_failure": true,
            "retryable_methods": ["GET"],
        }),
    );

    // Plain HTTP frontend — gateway dispatches to the HTTPS backend via
    // the native H3 pool because the registry will classify
    // `h3 = supported` after the warmup probe completes the QUIC
    // handshake (the H3 script's stream-level RST never fires during
    // warmup since warmup doesn't open a stream).
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_TLS_NO_VERIFY", "true")
        // Warmup must populate the registry before the first request,
        // otherwise the request would land while h3 is still Unknown
        // and dispatch via reqwest — bypassing the code path under
        // test.
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    // Wait for warmup to mark h3 = supported. Without this gate the
    // request races the probe and may land before classification, in
    // which case reqwest serves it and the test no longer exercises
    // the H3 retry path.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut classified_h3 = false;
    while std::time::Instant::now() < deadline {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await {
            let entries = body["entries"].as_array().cloned().unwrap_or_default();
            if let Some(e) = entries.first()
                && e["plain_http"]["h3"].as_str() == Some("supported")
            {
                classified_h3 = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        classified_h3,
        "warmup probe should have classified h3 = supported before the request fires; \
         without this the test does not exercise the H3 retry path"
    );

    // Capture baselines (warmup already opened a QUIC connection on the
    // H3 backend, so the counters are not zero).
    let h3_streams_baseline = h3_backend.received_requests().await.len();
    let bridge_baseline = tcp_backend.accepted_connections();

    // The single request that drives the retry loop. With the new
    // contract, all 3 attempts (initial + 2 retries) must hit H3 — none
    // are allowed to fall through to the bridge mid-request.
    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/single-h3"))
        .await
        .expect("send request");

    assert!(
        resp.status.as_u16() >= 500 && resp.status.as_u16() < 600,
        "request must end in 5xx — every retry attempt failed at the H3 layer; \
         a 200 here means a retry leaked into the cross-protocol bridge. \
         got: {resp:?}"
    );

    // Allow any in-flight backend bookkeeping to settle before reading
    // the counters.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let h3_streams_after = h3_backend.received_requests().await.len();
    let bridge_after = tcp_backend.accepted_connections();
    let h3_streams = h3_streams_after - h3_streams_baseline;
    let bridge_hits = bridge_after - bridge_baseline;

    // Load-bearing assertion: the bridge backend MUST NOT have served
    // any traffic during this single request. Pre-fix, after the first
    // H3 attempt failed and `mark_h3_unsupported` fired, the per-
    // iteration `tried_h3` re-check would see Unsupported and route
    // iteration 1 (and iteration 2) via reqwest → this backend would
    // record at least one connection. Post-fix, `request_was_h3` is
    // captured once before the loop and stays true for all retries.
    assert_eq!(
        bridge_hits, 0,
        "TCP+TLS bridge backend must see ZERO connections during a request that \
         dispatched via H3 — a non-zero value means a retry crossed protocols \
         mid-request, which the same-request contract forbids. \
         (h3 streams during request: {h3_streams}, bridge connections: {bridge_hits})"
    );

    // Sanity: the H3 backend must have observed at least the initial
    // dispatch. Without this floor a routing regression that never
    // dispatched via H3 would silently pass the bridge=0 check.
    assert!(
        h3_streams >= 1,
        "H3 backend should have served at least the initial dispatch; got {h3_streams} \
         streams during request — possible regression that skipped the native pool entirely"
    );

    // The downgrade hook should have fired on the H3 transport failure
    // — assert it landed so the NEXT request would route via reqwest.
    // (This is the contract the sibling test
    // `post_h3_downgrade_subsequent_requests_route_via_cross_protocol_bridge`
    // verifies end-to-end; here we just confirm the hook ran.)
    let downgrade_deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut downgrade_observed = false;
    while std::time::Instant::now() < downgrade_deadline {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await {
            let entries = body["entries"].as_array().cloned().unwrap_or_default();
            if let Some(e) = entries.first()
                && e["plain_http"]["h3"].as_str() == Some("unsupported")
            {
                downgrade_observed = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        downgrade_observed,
        "after an H3 transport failure the registry must downgrade h3 to unsupported \
         so the NEXT request routes via reqwest — without this the lifecycle is broken"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 6 — Mixed-capability upstream: LB rotation across targets recomputes
// the dispatch decision per-target.
// ────────────────────────────────────────────────────────────────────────────
//
// Companion to `retry_attempts_within_same_request_stay_on_h3_pool`.
// That sibling pins SAME-TARGET retries (must stay on the same
// protocol). This one pins CROSS-TARGET rotation: when the LB picks a
// different target on retry, the gateway must consult the registry
// for that target's actual capability and switch protocols if needed.
//
// Without per-target recomputation a snapshot taken from the initial
// target leaks across the rotation — e.g. a reqwest-only target A
// picked first locks `current_dispatch_h3 = false` for every retry,
// so a rotation to H3-only target B forces `proxy_to_backend_retry`
// (reqwest) against a backend with no TCP listener and 502 forever.
// This is the regression Codex flagged on c6e1a5c.
//
// Setup (round-robin LB, two targets):
//   * Target A (TCP+TLS only, NO QUIC listener):
//       — Returns HTTP/1 502 to every request → trips
//         `retryable_status_codes: [502]`.
//       — `h3 = Unknown`/`Unsupported` in the registry (UDP probe
//         finds nothing on A's port).
//   * Target B (UDP only, NO TCP listener):
//       — H3 backend that accepts the stream and immediately RSTs it.
//       — `h3 = Supported` in the registry (warmup probe completes the
//         handshake before the script's first stream interaction).
//
// We deliberately use a stream-RST H3 backend on B (rather than a
// successful response) to avoid a Linux-only race in the gateway's
// buffered H3 read path: `do_request` loops on `recv_data().await?`
// until the stream signals end-of-body, but on Linux the backend's
// post-response CONNECTION_CLOSE batches into the same network burst
// as the body's fin marker, surfacing as `ApplicationClose: H3_NO_ERROR`
// before the gateway sees end-of-body. That's a real classifier issue
// (tracked separately) — but for *this* test, a stream RST is the
// canonical "rotation reached H3 backend" signal and doesn't depend on
// the gateway successfully reading a clean response.
//
// Retry policy: `max_retries: 1`, `retryable_status_codes: [502]`,
// `retryable_methods: ["GET"]`. A's HTTP/1 502 trips the retry; B's H3
// stream RST returns the gateway-synthesized 502 either way (with or
// without the per-target recompute fix), so the response status alone
// doesn't distinguish pre-fix from post-fix.
//
// What DOES distinguish: which backend processed the retry.
//   * Pre-fix (snapshot from A locks `dispatch_h3 = false`): retry uses
//     reqwest against B's nonexistent TCP listener → connect refused.
//     B's H3 backend records ZERO streams.
//   * Post-fix (per-target recompute flips `dispatch_h3 = true` for B):
//     retry uses the H3 native pool against B → backend's AcceptStream
//     resolves and records ONE stream → script RSTs → gateway 502.
//     B's H3 backend records >= 1 streams.
//
// Assertions:
//   * `b_h3_streams >= 1` — load-bearing: proves the rotation hit the
//     H3 pool. Pre-fix, this is 0. Post-fix, this is ≥ 1.
//   * `a_tcp_hits >= 1` — proves the initial dispatch went to A
//     (otherwise the test never exercised the recompute path).
//
// We don't assert on the response status / body. The H3 pool's internal
// retry-cached-then-create-new chain can produce different terminal
// errors depending on timing (the underlying classifier issue), so any
// 5xx response is acceptable here as long as the H3 backend was hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn retry_rotation_across_mixed_capability_targets_recomputes_dispatch() {
    let ca = TestCa::new("retry-mixed-capability").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    // Target A — TCP+TLS only (no UDP listener). Returns HTTP/1 502
    // for every request so the gateway retries via
    // `retryable_status_codes`.
    let target_a_reservation = reserve_port().await.expect("reserve target A port");
    let target_a_port = target_a_reservation.port;
    let target_a_tcp_backend = ScriptedTlsBackend::builder(
        target_a_reservation.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 5\r\nConnection: close\r\n\r\nA-502".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn target A tls");

    // Target B — H3 only (no TCP listener). The script accepts the
    // gateway's stream, then RSTs it. We only need the backend to
    // RECORD that it received a stream — `b_h3_streams >= 1` is the
    // assertion; the gateway-side response is allowed to be any 5xx.
    //
    // Use `reserve_udp_port` (which holds the UDP socket through the
    // hand-off into `ScriptedH3Backend`) rather than reserving a TCP
    // port and dropping it before binding UDP — `CLAUDE.md`'s "Port
    // allocation MUST retry: bind-drop-rebind races" rule applies to
    // UDP too.
    let target_b_reservation = reserve_udp_port().await.expect("reserve target B udp port");
    let target_b_port = target_b_reservation.port;
    let target_b_udp = target_b_reservation.into_socket();
    let target_b_h3 = ScriptedH3Backend::builder(target_b_udp, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::SendStreamReset(0x10c))
        .spawn()
        .expect("spawn target B h3");

    // Proxy with a load-balanced upstream containing both targets.
    let yaml_value = json!({
        "proxies": [{
            "id": "phase8-mixed-capability",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": target_a_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "upstream_id": "mixed-capability-upstream",
            "retry": {
                "max_retries": 1,
                "retryable_status_codes": [502],
                "retryable_methods": ["GET"],
            },
        }],
        "consumers": [],
        "upstreams": [{
            "id": "mixed-capability-upstream",
            "name": "mixed-capability-upstream",
            "algorithm": "round_robin",
            "targets": [
                { "host": "127.0.0.1", "port": target_a_port, "weight": 1 },
                { "host": "127.0.0.1", "port": target_b_port, "weight": 1 },
            ],
        }],
        "plugin_configs": [],
    });
    let yaml = serde_yaml::to_string(&yaml_value).expect("yaml serialize");

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_TLS_NO_VERIFY", "true")
        // Warmup must populate the registry so A is h3-not-supported
        // and B is h3-Supported BEFORE the request fires. Without this
        // gate the request races the probe and may land while both
        // targets are still Unknown.
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    // Wait for warmup to classify B as h3=Supported. A's classification
    // is allowed to be either Unknown (UDP probe timeout) or Unsupported
    // — both map to `supports_native_http3_backend = false`.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut both_classified = false;
    let mut last_snapshot = serde_json::Value::Null;
    while std::time::Instant::now() < deadline {
        if let Ok(body) = harness.get_admin_json("/backend-capabilities").await {
            last_snapshot = body.clone();
            let entries = body["entries"].as_array().cloned().unwrap_or_default();
            let mut a_not_supported = false;
            let mut b_supported = false;
            for e in &entries {
                let key = e["key"].as_str().unwrap_or("");
                // Key shape: `scheme|host|port|dns|ca|cert|key|verify`
                let port: u16 = key
                    .split('|')
                    .nth(2)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let h3 = e["plain_http"]["h3"].as_str();
                if port == target_a_port && matches!(h3, Some("unsupported") | Some("unknown")) {
                    a_not_supported = true;
                }
                if port == target_b_port && h3 == Some("supported") {
                    b_supported = true;
                }
            }
            if a_not_supported && b_supported {
                both_classified = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(
        both_classified,
        "warmup must classify A=h3-(unsupported|unknown) AND B=h3-supported before the \
         request fires; without this the test does not exercise the per-target recompute \
         path. target_a_port={target_a_port} target_b_port={target_b_port} \
         last_snapshot={last_snapshot:#}"
    );

    let a_tcp_baseline = target_a_tcp_backend.accepted_connections();
    let b_h3_streams_baseline = target_b_h3.received_requests().await.len();

    // Single request. Round-robin selects A first (rr_counter starts
    // at 0 → index 0 → A). Initial attempt: dispatch_h3=false (A is
    // h3-not-supported) → reqwest → A returns 502 → retry fires on
    // status code. LB rotates to B (excluding A). Per-target
    // recompute: B is h3=Supported → current_dispatch_h3 flips to
    // true → H3 to B → backend records the stream then RSTs.
    let client = harness.http_client().expect("client");
    let resp = match client.get(&harness.proxy_url("/api/mixed")).await {
        Ok(r) => r,
        Err(e) => {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("send request failed: {e}\n=== gateway logs ===\n{logs}");
        }
    };

    // Allow target B's stream counter to settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let a_tcp_after = target_a_tcp_backend.accepted_connections();
    let b_h3_streams_after = target_b_h3.received_requests().await.len();
    let a_tcp_hits = a_tcp_after - a_tcp_baseline;
    let b_h3_streams = b_h3_streams_after - b_h3_streams_baseline;

    // Load-bearing assertion: the H3 backend on B must have recorded
    // at least one stream — proving the LB rotation flipped
    // `current_dispatch_h3` to true for the new target. Pre-fix (Codex
    // P1 on c6e1a5c) the initial-target snapshot from A's
    // classification (false) would force reqwest against B's
    // nonexistent TCP listener → connect refused → b_h3_streams stays
    // at 0.
    if b_h3_streams == 0 {
        let logs = harness.captured_combined().unwrap_or_default();
        let body = resp.body_text();
        panic!(
            "target B's H3 backend must record at least one stream from the retry rotation; \
             got {b_h3_streams}. b_h3_streams_baseline={b_h3_streams_baseline}, \
             b_h3_streams_after={b_h3_streams_after}. This means the rotation either \
             never happened or routed via reqwest (which would have failed to connect to \
             B's nonexistent TCP listener) — the regression Codex P1 flagged on c6e1a5c. \
             status={} body={body:?} a_tcp_hits={a_tcp_hits}\n\
             === gateway logs ===\n{logs}",
            resp.status.as_u16()
        );
    }
    assert!(
        a_tcp_hits >= 1,
        "target A's TCP backend must record at least the initial-attempt connection; \
         got {a_tcp_hits}. Without this, the initial dispatch never actually went \
         to A — the test is meaningless because the recompute path wasn't exercised."
    );
}

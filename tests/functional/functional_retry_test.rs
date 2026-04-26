//! Phase-8 functional gap-fill tests for the retry policy.
//!
//! Exercises retry-policy semantics that the existing
//! `functional_circuit_breaker_retry_test` does not cover:
//!
//! * `retry_on_methods` enforcement (POST must NOT replay even on
//!   connection-level failures when only GET is in the retry list).
//! * Retry-loop interaction with the H3 capability registry — first
//!   attempt over native H3 fails, second attempt routes via the
//!   cross-protocol bridge (reqwest path).
//! * Streaming-body requests are NOT replayed by the retry loop (the
//!   recent Codex P1 fix; previously a same-request fallback could
//!   double-fire the body).
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
use crate::scaffolding::ports::reserve_port;
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
// CLAUDE.md "No same-request reqwest fallback after H3 failure"). The
// retry-policy field is configured here only so the gateway exercises
// the H3 retry loop; the configured `max_retries` is exhausted at the
// H3 layer.
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

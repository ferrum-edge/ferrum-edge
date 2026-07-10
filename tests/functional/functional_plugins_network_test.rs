//! Phase-8 functional tests for plugin behavior under backend stress.
//!
//! Each test verifies that a plugin runs correctly even when the backend
//! is misbehaving — slow, refusing connections, or closing mid-stream.
//! These are gap-fill tests for the rate-limiting / mirror / compression /
//! response-caching plugins; they exercise the integration between the
//! plugin lifecycle and the backend dispatch path.
//! Round-2 adds response-body transformation under truncation/trickle and
//! verifies reset/stalled mirror targets remain isolated from the primary.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_plugins_network \
//!     -- --ignored --nocapture
//! ```

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// Build a file-mode YAML config from a single proxy + plugin set.
fn yaml_with_plugin(
    backend_port: u16,
    plugin_id: &str,
    plugin_name: &str,
    plugin_config: Value,
) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "phase8-plugin",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 1000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": plugin_id,
            "plugin_name": plugin_name,
            "scope": "global",
            "enabled": true,
            "config": plugin_config,
        }],
    });
    serde_yaml::to_string(&config).expect("yaml")
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — Rate limiting survives a slow backend.
// ────────────────────────────────────────────────────────────────────────────
//
// The `rate_limiting` plugin runs at the `authorize` phase, *before* the
// backend dispatch. So even with a slow backend, the plugin should
// correctly reject requests above its limit.
//
// Setup:
//   * `requests_per_minute = 5` rate limit.
//   * Slow backend that holds each request for ~500ms.
//   * Drive 10 concurrent requests.
//
// Expected: at least 5 succeed (the limit), at least 1 is rejected with
// 429. The exact split is not deterministic (rate-limiter window state
// can change between the start of the test burst), but the rate
// limiter must NOT silently let everything through, regardless of
// backend latency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn rate_limiting_survives_slow_backend() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;

    // Trickle a 200 response with a small delay between header and end —
    // simulates ~500ms backend latency.
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::Sleep(Duration::from_millis(500)))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let yaml = yaml_with_plugin(
        backend_port,
        "rl",
        "rate_limiting",
        json!({
            "limit_by": "ip",
            "limits": [{"scope": "default", "requests_per_minute": 5}],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    // Fire 10 concurrent requests against the same client IP. The rate
    // limiter buckets by source IP, so all share the same window.
    let proxy_url = harness.proxy_url("/api/x");
    let mut tasks = Vec::with_capacity(10);
    for _ in 0..10 {
        let url = proxy_url.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .pool_max_idle_per_host(0)
                .build()
                .expect("client");
            client.get(&url).send().await.map(|r| r.status().as_u16())
        }));
    }

    // Collect EVERY task outcome — a dropped task error would let a
    // partial-failure run satisfy the >=1/<=5 status checks below
    // without actually exercising the rate-limiter contract. Failures
    // and panics are surfaced explicitly.
    let mut statuses: Vec<u16> = Vec::with_capacity(10);
    let mut request_errors: Vec<String> = Vec::new();
    for (i, t) in tasks.into_iter().enumerate() {
        match t.await {
            Ok(Ok(s)) => statuses.push(s),
            Ok(Err(e)) => request_errors.push(format!("task {i}: reqwest error: {e}")),
            Err(e) => request_errors.push(format!("task {i}: join error: {e}")),
        }
    }
    assert!(
        request_errors.is_empty(),
        "rate-limit test expects every concurrent request to complete with an HTTP \
         status (200 or 429); got {} task error(s) which would let a partial-failure \
         run pass the count assertions vacuously: {:?}",
        request_errors.len(),
        request_errors
    );
    assert_eq!(
        statuses.len(),
        10,
        "expected all 10 concurrent requests to produce a status; got {}: statuses={statuses:?}",
        statuses.len()
    );
    let oks = statuses.iter().filter(|s| **s == 200).count();
    let rate_limited = statuses.iter().filter(|s| **s == 429).count();
    eprintln!(
        "rate_limiting_survives_slow_backend: statuses={statuses:?} oks={oks} rl={rate_limited}"
    );
    // Every status must be either 200 (passed rate limit + reached
    // backend) or 429 (rejected by rate limit). Anything else (e.g.,
    // 502 from a flaky backend) means the test isn't measuring what
    // it claims to measure.
    let unexpected: Vec<u16> = statuses
        .iter()
        .copied()
        .filter(|s| *s != 200 && *s != 429)
        .collect();
    assert!(
        unexpected.is_empty(),
        "expected only 200 / 429 statuses; got unexpected: {unexpected:?}; statuses={statuses:?}"
    );
    // Both halves of the rate-limiter contract must hold — without the
    // 200 floor, a broken plugin that rejects every request would also
    // pass.
    assert!(
        rate_limited >= 1,
        "expected at least one 429; statuses={statuses:?}"
    );
    assert!(
        oks >= 1,
        "expected at least one 200 — a plugin that 429s every request would pass with only the 429 assertion; \
         statuses={statuses:?}"
    );
    // Window timing variance can let a few extra requests through, but
    // the upper bound is the configured limit. With requests_per_minute=5
    // and a single test burst within one minute, the 200 count must not
    // exceed the limit, otherwise the rate limiter is leaking.
    assert!(
        oks <= 5,
        "expected oks <= 5 (requests_per_minute limit); got {oks}; \
         statuses={statuses:?}"
    );
    let _ = backend.accepted_connections();
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — `request_mirror` fires even when the primary backend errors.
// ────────────────────────────────────────────────────────────────────────────
//
// Setup:
//   * Primary backend that always responds 502 (simulates a broken
//     primary). Drives the response through ferrum-edge.
//   * Mirror backend that responds 200.
//   * `request_mirror` plugin configured with `percentage: 100` to send
//     every request to the mirror.
//
// Expected:
//   * The client sees the primary's status (502).
//   * The mirror backend receives the request — mirror is fire-and-
//     forget, so a primary failure must NOT block it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_fires_even_when_primary_502s() {
    // Primary: always returns 502.
    let primary_res = reserve_port().await.expect("primary port");
    let primary_port = primary_res.port;
    let _primary = ScriptedHttp1Backend::builder(primary_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 502,
            reason: "Bad Gateway".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "3".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"BAD".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn primary");

    // Mirror: always returns 200, records every request.
    let mirror_res = reserve_port().await.expect("mirror port");
    let mirror_port = mirror_res.port;
    let mirror = ScriptedHttp1Backend::builder(mirror_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"echo".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn mirror");

    let yaml = yaml_with_plugin(
        primary_port,
        "rm",
        "request_mirror",
        json!({
            "mirror_host": "127.0.0.1",
            "mirror_port": mirror_port,
            "mirror_protocol": "http",
            "percentage": 100.0,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/mirror"))
        .await
        .expect("response");
    // Client sees the primary (502).
    assert_eq!(
        resp.status.as_u16(),
        502,
        "client should see primary's 502, got {resp:?}"
    );

    // Allow mirror task to fire (request_mirror is fire-and-forget on
    // a tokio task — typically completes within ~50ms on loopback).
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mirror_count = mirror.accepted_connections();
    assert!(
        mirror_count >= 1,
        "mirror should have received at least one request even though primary 502'd; \
         got {mirror_count}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_stall_scripted_backend_never_delays_primary() {
    let primary_res = reserve_port().await.expect("primary port");
    let primary_port = primary_res.port;
    let primary = ScriptedHttp1Backend::builder(primary_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn primary");

    let mirror_res = reserve_port().await.expect("mirror port");
    let mirror_port = mirror_res.port;
    let mirror = ScriptedHttp1Backend::builder(mirror_res.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::Sleep(Duration::from_secs(30)))
        .spawn()
        .expect("spawn stalled mirror");

    let yaml = yaml_with_plugin(
        primary_port,
        "request-mirror-stall",
        "request_mirror",
        json!({
            "mirror_host": "127.0.0.1",
            "mirror_port": mirror_port,
            "mirror_protocol": "http",
            "percentage": 100.0,
        }),
    );
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client.get(&harness.proxy_url("/api/mirror-stall")),
    )
    .await
    .expect("stalled mirror blocked the primary response")
    .expect("primary response");

    assert_eq!(response.status.as_u16(), 200, "response={response:?}");
    assert_eq!(response.body_text(), "ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stalled mirror delayed the fire-and-forget primary path"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !mirror.received_requests().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("stalled mirror never received the copied request");
    assert_eq!(primary.received_requests().await.len(), 1);
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — `compression` handles mid-stream backend close without
// corrupting output.
// ────────────────────────────────────────────────────────────────────────────
//
// Setup:
//   * Backend announces a Content-Length but closes after writing only
//     part of the body.
//   * `compression` plugin with `gzip` enabled.
//   * Client sends `Accept-Encoding: gzip`.
//
// Expected: the client either:
//   * Sees a clean truncation: response body validates as gzip with all
//     emitted bytes (no garbage), OR
//   * Sees a clean error response (502 or similar) — the gateway noticed
//     the mid-stream failure before forwarding garbage.
//
// What we MUST NOT see: half-encoded bytes that fail gzip decoding.
//
// Since the actual content-encoding handling depends on whether the
// gateway buffers or streams, we assert the weaker but load-bearing
// invariant: if the response body is non-empty, it must either decode
// cleanly via flate2 OR the gateway must have signaled the error via a
// non-200 status.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn compression_handles_mid_stream_backend_close_without_corrupting_output() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;

    // 2KB payload, but backend closes mid-body after 256 bytes. The
    // backend's response is large enough to cross the
    // `min_content_length: 256` compression threshold.
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::CloseMidBody {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Length".into(), "2048".into()),
                ("Content-Type".into(), "text/plain".into()),
            ],
            body_prefix: vec![b'A'; 256],
            reset: false,
        })
        .spawn()
        .expect("spawn backend");

    let yaml = yaml_with_plugin(
        backend_port,
        "cmp",
        "compression",
        json!({
            "algorithms": ["gzip"],
            "min_content_length": 100,
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    // Don't decompress automatically — we want to inspect raw bytes.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(0)
        .no_gzip()
        .no_brotli()
        .build()
        .expect("client");
    let url = harness.proxy_url("/api/cmp");
    let resp = client
        .get(&url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let content_encoding = r
                .headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let bytes = r.bytes().await.unwrap_or_default();
            eprintln!(
                "test3: status={status} content-encoding={content_encoding:?} body_len={}",
                bytes.len()
            );
            // The gateway either:
            //   1. Errored cleanly (>= 500), in which case we don't need
            //      to validate gzip (a body might be a plain error message).
            //   2. Returned 200 with gzip — the body must decode cleanly.
            //   3. Returned 200 plain (no compression because the response
            //      truncated mid-stream and the gateway abandoned the
            //      compression attempt) — accept this too.
            if status >= 500 {
                return; // pass: clean error
            }
            if content_encoding.as_deref() == Some("gzip") {
                // Empty gzip body with content-encoding: gzip is a
                // contradiction — the gateway claimed compressed output
                // but produced nothing. That's a corruption signal we
                // explicitly want to catch, not silently accept.
                assert!(
                    !bytes.is_empty(),
                    "gateway emitted `content-encoding: gzip` with an empty body; \
                     this is a regression — either omit the header or send a \
                     valid (possibly truncated) gzip stream"
                );
                // Try to decode; partial truncation should still be a
                // valid gzip stream up to the truncation point — gzip
                // is a streaming format.
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
                let mut decoded = Vec::new();
                let decode_result = decoder.read_to_end(&mut decoded);
                eprintln!(
                    "test3 gzip decode result: {:?}, decoded_len={}",
                    decode_result,
                    decoded.len()
                );
                // Truncated gzip streams typically fail at the trailer
                // check but still produce valid prefix bytes before the
                // error. We require decoded bytes to be non-empty (a
                // malformed stream that produces zero output before
                // erroring is the corruption case the reviewer flagged
                // — without this check, `decoded.iter().all(...)` would
                // pass vacuously).
                assert!(
                    !decoded.is_empty(),
                    "gzip decoder produced zero output bytes from a non-empty \
                     gzip body ({} bytes in); decode_result={decode_result:?}. \
                     This means the gateway emitted bytes that the gzip decoder \
                     could not interpret as ANY valid prefix — output corruption.",
                    bytes.len()
                );
                // And every decoded byte must come from the backend's
                // 'A' payload — anything else is corruption.
                let non_a = decoded.iter().filter(|b| **b != b'A').count();
                assert_eq!(
                    non_a,
                    0,
                    "expected only valid 'A' bytes in decoded gzip stream; \
                     got {non_a} non-A bytes out of {} decoded; decode_result={decode_result:?}",
                    decoded.len()
                );
            } else {
                // Uncompressed body — the gateway abandoned compression
                // due to truncation. Accept any prefix of 'A' bytes.
                assert!(
                    bytes.iter().all(|b| *b == b'A'),
                    "expected only valid 'A' bytes in plain body; got non-A bytes"
                );
            }
        }
        Err(e) => {
            // Reqwest surfaced the truncation as an error. That's also
            // acceptable — the client got a clear failure signal rather
            // than corrupted data.
            eprintln!("test3: reqwest error (acceptable): {e}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn response_transformer_never_emits_corrupt_json_for_truncated_or_trickled_body() {
    const TRUNCATED_JSON_PREFIX: &[u8] = br#"{"status":"pending"#;
    const TRICKLED_JSON: &[u8] = br#"{"status":"ready"}"#;

    for behavior in ["close-mid-body", "trickle-body"] {
        let reservation = reserve_port().await.expect("reserve port");
        let backend_port = reservation.port;
        let backend = match behavior {
            "close-mid-body" => ScriptedHttp1Backend::builder(reservation.into_listener())
                .step(HttpStep::CloseMidBody {
                    status: 200,
                    reason: "OK".into(),
                    headers: vec![
                        ("Content-Length".into(), "64".into()),
                        ("Content-Type".into(), "application/json".into()),
                    ],
                    body_prefix: TRUNCATED_JSON_PREFIX.to_vec(),
                    reset: true,
                })
                .spawn()
                .expect("spawn close-mid-body backend"),
            "trickle-body" => ScriptedHttp1Backend::builder(reservation.into_listener())
                .step(HttpStep::TrickleBody {
                    status: 200,
                    reason: "OK".into(),
                    headers: vec![
                        ("Content-Length".into(), TRICKLED_JSON.len().to_string()),
                        ("Content-Type".into(), "application/json".into()),
                        ("Connection".into(), "close".into()),
                    ],
                    body: TRICKLED_JSON.to_vec(),
                    chunk_size: 5,
                    pause: Duration::from_millis(75),
                })
                .spawn()
                .expect("spawn trickle backend"),
            _ => unreachable!(),
        };

        let yaml = yaml_with_plugin(
            backend_port,
            "response-transformer-network",
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "gateway",
                    "value": "ferrum",
                }],
            }),
        );
        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(yaml)
            .pool_warmup_enabled(false)
            .spawn()
            .await
            .expect("spawn gateway");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .pool_max_idle_per_host(0)
            .build()
            .expect("client");

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .get(harness.proxy_url(&format!("/api/{behavior}")))
                .send(),
        )
        .await
        .unwrap_or_else(|_| panic!("{behavior} response exceeded the outer timeout"));

        match outcome {
            Err(_) if behavior == "close-mid-body" => {}
            Err(error) => panic!("{behavior} unexpectedly failed before response: {error}"),
            Ok(response) => {
                let status = response.status();
                let response_is_json = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.starts_with("application/json"));
                let body = tokio::time::timeout(Duration::from_secs(4), response.bytes()).await;
                match body {
                    Err(_) => panic!("{behavior} body read exceeded the outer timeout"),
                    Ok(Err(_)) if behavior == "close-mid-body" => {}
                    Ok(Err(error)) => panic!("{behavior} body read failed: {error}"),
                    Ok(Ok(bytes)) if status.is_server_error() => {
                        assert_eq!(
                            behavior, "close-mid-body",
                            "only the truncated case may cleanly fail as 5xx"
                        );
                        assert!(
                            !bytes.is_empty(),
                            "clean 5xx must carry an explicit error body"
                        );
                        assert!(
                            !bytes
                                .windows(TRUNCATED_JSON_PREFIX.len())
                                .any(|window| window == TRUNCATED_JSON_PREFIX),
                            "clean 5xx must not forward the backend's truncated JSON prefix; bytes={bytes:?}"
                        );
                        if response_is_json {
                            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_else(
                                |error| {
                                    panic!(
                                        "clean JSON 5xx carried invalid JSON: {error}; bytes={bytes:?}"
                                    )
                                },
                            );
                        }
                    }
                    Ok(Ok(bytes)) => {
                        assert_eq!(status.as_u16(), 200, "behavior={behavior}");
                        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{behavior} returned corrupt JSON after response_transformer: \
                                     {error}; bytes={bytes:?}"
                                )
                            });
                        if behavior == "trickle-body" {
                            assert_eq!(
                                parsed["status"],
                                json!("ready"),
                                "response_transformer must preserve the trickled object"
                            );
                            assert_eq!(
                                parsed["gateway"],
                                json!("ferrum"),
                                "response_transformer must mutate the trickled object"
                            );
                        }
                    }
                }
            }
        }

        assert!(
            !backend.received_requests().await.is_empty(),
            "{behavior} backend did not receive the gateway request"
        );
    }
}

async fn assert_misbehaving_mirror_does_not_delay_primary(behavior: &'static str) {
    let primary_reservation = reserve_port().await.expect("primary port");
    let primary_port = primary_reservation.port;
    let primary = ScriptedHttp1Backend::builder(primary_reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn primary");

    let mirror_reservation = reserve_port().await.expect("mirror port");
    let mirror_port = mirror_reservation.port;
    let mirror = match behavior {
        "reset" => ScriptedHttp1Backend::builder(mirror_reservation.into_listener())
            .step(HttpStep::CloseMidBody {
                status: 200,
                reason: "OK".into(),
                headers: vec![("Content-Length".into(), "32".into())],
                body_prefix: b"partial".to_vec(),
                reset: true,
            })
            .spawn()
            .expect("spawn reset mirror"),
        "stall" => ScriptedHttp1Backend::builder(mirror_reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::Sleep(Duration::from_secs(30)))
            .spawn()
            .expect("spawn stalled mirror"),
        _ => unreachable!(),
    };

    let yaml = yaml_with_plugin(
        primary_port,
        "request-mirror-network",
        "request_mirror",
        json!({
            "mirror_host": "127.0.0.1",
            "mirror_port": mirror_port,
            "mirror_protocol": "http",
            "percentage": 100.0,
        }),
    );
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let client = harness.http_client().expect("client");
    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client.get(&harness.proxy_url(&format!("/api/mirror-{behavior}"))),
    )
    .await
    .unwrap_or_else(|_| panic!("{behavior} mirror blocked the primary response"))
    .expect("primary response");
    assert_eq!(response.status.as_u16(), 200, "response={response:?}");
    assert_eq!(response.body_text(), "ok");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{behavior} mirror delayed the fire-and-forget primary path"
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !mirror.received_requests().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{behavior} mirror never received the copied request"));
    assert_eq!(primary.received_requests().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_reset_never_delays_primary_response() {
    assert_misbehaving_mirror_does_not_delay_primary("reset").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn request_mirror_stall_never_delays_primary_response() {
    assert_misbehaving_mirror_does_not_delay_primary("stall").await;
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — `response_caching` does not cache 5xx from a failed backend.
// ────────────────────────────────────────────────────────────────────────────
//
// `response_caching` defaults `cacheable_status_codes = [200, 301, 404]`.
// 502 is not in the cacheable set, so the gateway must NOT poison the
// cache when a backend returns one. We verify by alternating responses
// across the request stream and proving the cache only stores
// successful (200) responses.
//
// Approach: a custom backend that returns 502 every request. We then
// flip a flag and the backend starts returning 200. Subsequent requests
// must observe the 200 — proving no 502 was cached during the failure
// window. The flag uses an atomic so the response choice is
// deterministic per-request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn response_caching_does_not_cache_5xx_from_failed_backends() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let serve_200 = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU32::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let serve_200_task = serve_200.clone();
    let counter_task = counter.clone();
    let bg = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            counter_task.fetch_add(1, Ordering::SeqCst);
            let serve = serve_200_task.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
                let resp = if serve.load(Ordering::SeqCst) {
                    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok!"
                } else {
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\nConnection: close\r\n\r\n502"
                };
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });

    let yaml = yaml_with_plugin(
        backend_port,
        "rc",
        "response_caching",
        json!({
            "ttl_seconds": 60,
            "max_entries": 100,
            "cacheable_methods": ["GET"],
            "cacheable_status_codes": [200, 301, 404],
        }),
    );
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("warn")
        // Disable pool warmup so the request count we observe matches
        // user-driven traffic.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let url = harness.proxy_url("/api/cache-key");

    // Phase A — backend serves 502.
    let r1 = client.get(&url).await.expect("r1");
    assert_eq!(
        r1.status.as_u16(),
        502,
        "phase A: backend should return 502; got {r1:?}"
    );

    // Wait briefly to ensure the gateway's caching middleware has
    // observed the response.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Phase B — flip backend to serve 200.
    serve_200.store(true, Ordering::SeqCst);

    // The next request MUST hit the backend (the 502 was not cached).
    let r2 = client.get(&url).await.expect("r2");
    assert_eq!(
        r2.status.as_u16(),
        200,
        "phase B: post-flip request must reflect 200 from backend, NOT a cached 502; got {r2:?}"
    );
    assert_eq!(r2.body_text(), "ok!");

    // Counter must have advanced beyond r1 — proves r2 reached the
    // backend (i.e., the cache did not return a stale 502).
    let n_after_r2 = counter.load(Ordering::SeqCst);
    assert!(
        n_after_r2 >= 2,
        "backend must have served at least 2 requests across r1+r2; got {n_after_r2}"
    );

    // Optional: a third request should now be cached (the 200 IS
    // cacheable). Counter should not advance.
    let _r3 = client.get(&url).await.expect("r3");
    let final_count = counter.load(Ordering::SeqCst);
    eprintln!("final backend count after 3rd request: {final_count}");

    // Cleanup background task.
    bg.abort();
    let _ = bg.await;

    let _ = Instant::now();
}

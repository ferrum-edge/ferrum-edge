//! Live traffic-path acceptance for the DestinationRule
//! `connectionPool.http.http2MaxRequests` destination-wide active-request
//! breaker (issue #3775), native gRPC leg.
//!
//! gRPC is where a permit released at response headers is most visibly wrong: a
//! server-streaming or long-lived bidi RPC occupies backend capacity for its
//! whole lifetime, which is exactly the workload Istio's field exists to bound.
//! Both tests park the backend AFTER it has already sent response headers and a
//! response message, so the only way a second RPC can be shed is if the permit
//! is still held at that point.
//!
//! Covers: unary and streaming RPCs draw on the SAME destination budget;
//! saturation is shaped as gRPC `UNAVAILABLE` (14) and as the gRPC-Web
//! browser equivalent; the permit is released at trailers, and on a client
//! cancellation/reset of a live stream.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_destination_active_requests_grpc -- --ignored --nocapture`

use super::destination_active_requests_helpers::{
    NS, UPSTREAM_ID, assert_projected_active_request_cap, prepare_for_assertions, start_gateway,
    wait_until,
};
use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
use crate::scaffolding::clients::{GrpcClient, GrpcResponse};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use ferrum_edge::config::types::GatewayConfig;
use serde_json::json;
use std::time::Duration;
use tokio::time::{sleep, timeout};

const SETTLE: Duration = Duration::from_millis(400);
const HOLD_WAIT: Duration = Duration::from_secs(20);
const GRPC_UNAVAILABLE: u32 = 14;
const HOLD_PATH: &str = "/grpc.Destination/Hold";
const PROBE_PATH: &str = "/grpc.Destination/Probe";

// ───────────────────────────────────────────────────────────────────────────
// 1. Unary — the permit survives response headers AND the response message,
//    and is released only at trailers. Saturation is UNAVAILABLE / gRPC-Web.
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_grpc_unary_holds_until_trailers() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_grpc_unary_holds_until_trailers_inner());
}

async fn functional_destination_active_requests_grpc_unary_holds_until_trailers_inner() {
    let reservation = reserve_port().await.expect("reserve gRPC backend port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .connection_scripts([
            // Connection 0 stays open after trailers so a pooled follow-up can
            // reuse it. A one-shot script would close ~100ms after status and
            // the gateway's gRPC pool would surface that as `Backend unavailable`
            // — which is not a still-held destination permit.
            {
                let mut steps = vec![
                    GrpcStep::AcceptRpc(MatchRpc::any()),
                    GrpcStep::SendInitialHeaders,
                    GrpcStep::RespondMessage(Bytes::from_static(b"held")),
                    GrpcStep::AwaitTestSignal,
                    GrpcStep::RespondStatus {
                        code: 0,
                        message: "",
                    },
                ];
                steps.extend(grpc_ok_unary_steps());
                steps
            },
            // Fresh dials (if the pool opens another connection) succeed too.
            grpc_ok_unary_steps(),
        ])
        .spawn()
        .expect("spawn scripted gRPC backend");

    let config = grpc_destination_config(backend_port);
    let prepared = prepare_for_assertions(config.clone());
    assert_projected_active_request_cap(&prepared, "dest-active-grpc", backend_port, Some(1));
    assert_projected_active_request_cap(&prepared, "dest-active-grpc-web", backend_port, Some(1));

    let gateway = start_gateway(config, false).await.expect("start gateway");
    let port = gateway.http_port;

    let hold = tokio::spawn(async move {
        GrpcClient::h2c(format!("127.0.0.1:{port}"))
            .unary(HOLD_PATH, Bytes::from_static(b"req"))
            .await
            .expect("held unary RPC")
    });
    let parked = || backend.awaiting_test_signal() >= 1;
    wait_until(HOLD_WAIT, "the gRPC backend to park pre-trailer", parked).await;
    assert_eq!(
        backend.received_stream_count(),
        1,
        "exactly one backend RPC must be live"
    );

    // A second native gRPC RPC is shed as UNAVAILABLE, before any dial.
    let probe = grpc_unary(port, PROBE_PATH).await;
    assert_shed_as_unavailable(&probe, "second native gRPC RPC");

    // The gRPC-Web route on the same logical destination shares the budget and
    // is shed in the browser-facing shape.
    assert_grpc_web_shed(port).await;

    sleep(SETTLE).await;
    assert_eq!(
        backend.received_stream_count(),
        1,
        "a shed RPC must not open a backend stream"
    );
    assert_eq!(
        backend.accepted_connections(),
        1,
        "a shed RPC must not dial the backend"
    );

    backend.release_test_signal();
    let held = hold.await.expect("held RPC task");
    assert_eq!(
        held.grpc_status(),
        Some(0),
        "the held unary RPC must complete OK"
    );
    wait_until(
        HOLD_WAIT,
        "the held connection to arm the post-trailer acceptor",
        || backend.acceptors_waiting() >= 1,
    )
    .await;

    // Trailers ended the exchange; the permit must be back. The follow-up
    // must actually reach the backend (not merely stop returning 503).
    let after = grpc_unary(port, PROBE_PATH).await;
    assert_eq!(
        after.effective_grpc_status(),
        0,
        "the destination permit must be released at gRPC trailers; response={after:?}"
    );
    assert!(
        backend.received_stream_count() >= 2,
        "the post-release RPC must have reached the backend"
    );

    gateway.shutdown().await;
    drop(backend);
}

// ───────────────────────────────────────────────────────────────────────────
// 2. Streaming — a long-lived RPC holds the same budget, and a client-side
//    cancellation/reset releases it.
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_grpc_streaming_release_on_cancel() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_grpc_streaming_release_on_cancel_inner());
}

async fn functional_destination_active_requests_grpc_streaming_release_on_cancel_inner() {
    let reservation = reserve_port().await.expect("reserve gRPC backend port");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .connection_scripts([
            // Connection 0: park after the response has begun, then wait for
            // the gateway to RST this stream when the client cancels, and keep
            // the connection reusable for the post-cancel RPC. Parking on
            // AwaitTestSignal until teardown left the pooled connection unable
            // to accept a follow-up stream.
            {
                let mut steps = vec![
                    GrpcStep::AcceptStreamingRpc(MatchRpc::any()),
                    GrpcStep::SendInitialHeaders,
                    GrpcStep::RespondMessage(Bytes::from_static(b"chunk")),
                    GrpcStep::AwaitTestSignal,
                    GrpcStep::ExpectReset(Duration::from_secs(20)),
                ];
                steps.extend(grpc_ok_unary_steps());
                steps
            },
            grpc_ok_unary_steps(),
        ])
        .spawn()
        .expect("spawn scripted gRPC backend");

    let gateway = start_gateway(grpc_destination_config(backend_port), false)
        .await
        .expect("start gateway");
    let port = gateway.http_port;

    let hold = tokio::spawn(async move {
        GrpcClient::h2c(format!("127.0.0.1:{port}"))
            .bidi_with_headers(HOLD_PATH, Bytes::from_static(b"req"), &[])
            .await
    });
    let parked = || backend.awaiting_test_signal() >= 1;
    wait_until(HOLD_WAIT, "the gRPC stream to park mid-response", parked).await;

    let probe = grpc_unary(port, PROBE_PATH).await;
    assert_shed_as_unavailable(&probe, "RPC issued while a stream is live");
    sleep(SETTLE).await;
    assert_eq!(
        backend.received_stream_count(),
        1,
        "the shed RPC must not have opened a backend stream"
    );

    // Client cancels the live stream: aborting the task now also aborts the
    // h2 connection driver, so the gateway observes a reset. Release the
    // park so the script can witness that RST and arm the next acceptor;
    // the follow-up must then reach the backend, not merely stop shedding.
    hold.abort();
    backend.release_test_signal();
    wait_until(
        HOLD_WAIT,
        "the gateway to RST the cancelled backend stream",
        || backend.stream_reset_count() >= 1,
    )
    .await;
    wait_until(
        HOLD_WAIT,
        "the held connection to arm the post-cancel acceptor",
        || backend.acceptors_waiting() >= 1,
    )
    .await;

    let after = grpc_unary(port, PROBE_PATH).await;
    assert_eq!(
        after.effective_grpc_status(),
        0,
        "a cancelled streaming RPC must release its destination permit; response={after:?}"
    );
    assert!(
        backend.received_stream_count() >= 2,
        "the post-cancel RPC must have reached the backend"
    );

    gateway.shutdown().await;
    drop(backend);
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

async fn grpc_unary(gateway_port: u16, path: &str) -> GrpcResponse {
    timeout(
        Duration::from_secs(20),
        GrpcClient::h2c(format!("127.0.0.1:{gateway_port}"))
            .unary(path, Bytes::from_static(b"req")),
    )
    .await
    .unwrap_or_else(|_| panic!("gRPC {path} timed out"))
    .unwrap_or_else(|err| panic!("gRPC {path} failed: {err}"))
}

fn grpc_ok_unary_steps() -> Vec<GrpcStep> {
    vec![
        GrpcStep::AcceptRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"ok")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ]
}

fn assert_shed_as_unavailable(response: &GrpcResponse, what: &str) {
    assert_eq!(
        response.effective_grpc_status(),
        GRPC_UNAVAILABLE,
        "{what} must be shed as gRPC UNAVAILABLE; response={response:?}"
    );
}

/// gRPC-Web saturation must reach the browser as a gRPC-Web response carrying
/// `grpc-status: 14`, not as a bare HTTP error a browser client cannot read.
async fn assert_grpc_web_shed(gateway_port: u16) {
    let mut body = Vec::with_capacity(8);
    body.push(0u8);
    body.extend_from_slice(&3u32.to_be_bytes());
    body.extend_from_slice(b"req");

    let response = timeout(
        Duration::from_secs(20),
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("grpc-web client")
            .post(format!(
                "http://127.0.0.1:{gateway_port}/grpcweb.Destination/Probe"
            ))
            .header("content-type", "application/grpc-web+proto")
            .body(body)
            .send(),
    )
    .await
    .expect("gRPC-Web probe timed out")
    .expect("gRPC-Web probe");

    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let header_status = response
        .headers()
        .get("grpc-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u32>().ok());
    let bytes = response.bytes().await.expect("gRPC-Web body");

    assert!(
        content_type.starts_with("application/grpc-web"),
        "a saturated gRPC-Web request must stay gRPC-Web shaped; status={status} \
         content-type={content_type}"
    );

    let trailer_status = grpc_web_frames(&bytes)
        .into_iter()
        .find_map(|(flag, payload)| (flag & 0x80 != 0).then_some(payload))
        .map(|payload| String::from_utf8_lossy(payload).into_owned())
        .and_then(|text| parse_grpc_status(&text));

    let observed = trailer_status.or(header_status);
    assert_eq!(
        observed,
        Some(GRPC_UNAVAILABLE),
        "gRPC-Web saturation must carry grpc-status 14; status={status} \
         content-type={content_type} body={bytes:?}"
    );
}

fn grpc_web_frames(body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut frames = Vec::new();
    let mut remaining = body;
    while remaining.len() >= 5 {
        let flag = remaining[0];
        let len =
            u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]) as usize;
        if remaining.len() < 5 + len {
            break;
        }
        frames.push((flag, &remaining[5..5 + len]));
        remaining = &remaining[5 + len..];
    }
    frames
}

fn parse_grpc_status(trailer_text: &str) -> Option<u32> {
    trailer_text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("grpc-status")
            .then(|| value.trim().parse::<u32>().ok())
            .flatten()
    })
}

/// One logical destination reached by a native-gRPC route and a gRPC-Web route.
/// Both carry `http2MaxRequests: 1`, so a live RPC on either must saturate both.
fn grpc_destination_config(backend_port: u16) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "dest-active-grpc",
                "namespace": NS,
                "listen_path": "/grpc.Destination",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": false,
                "upstream_id": UPSTREAM_ID
            },
            {
                "id": "dest-active-grpc-web",
                "namespace": NS,
                "listen_path": "/grpcweb.Destination",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": false,
                "upstream_id": UPSTREAM_ID,
                "plugins": [{"plugin_config_id": "dest-active-grpc-web-plugin"}]
            }
        ],
        "upstreams": [{
            "id": UPSTREAM_ID,
            "namespace": NS,
            "name": UPSTREAM_ID,
            "algorithm": "round_robin",
            "targets": [{
                "host": "127.0.0.1",
                "port": backend_port,
                "weight": 1
            }]
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "dest-active-grpc-web-plugin",
            "plugin_name": "grpc_web",
            "scope": "proxy",
            "proxy_id": "dest-active-grpc-web",
            "enabled": true,
            "config": {}
        }],
        "mesh": {
            "destination_rules": [{
                "name": "dest-active-grpc-dr",
                "namespace": NS,
                "host": UPSTREAM_ID,
                "traffic_policy": {
                    "connection_pool_http": {
                        "http2_max_requests": 1
                    }
                }
            }]
        }
    }))
    .expect("gRPC destination config is valid")
}

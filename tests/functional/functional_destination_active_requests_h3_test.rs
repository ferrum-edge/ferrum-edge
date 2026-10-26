//! Live traffic-path acceptance for the DestinationRule
//! `connectionPool.http.http2MaxRequests` destination-wide active-request
//! breaker (issue #3775), HTTP/3 front-end leg.
//!
//! The H3→HTTP bridge takes its backend-admission permit through the same
//! funnel as the HTTP/1.1 and HTTP/2 paths
//! (`run_h3_backend_admission_or_send_reject` →
//! `run_backend_admission_plugins`), and the permit is owned by the relay that
//! streams the response back over QUIC. These tests prove that on the wire:
//! an H3 request that is holding a backend exchange keeps the destination
//! budget, the next H3 request is shed before any backend dial, and the budget
//! comes back when the relay ends — both on a clean completion and when the
//! client cancels one multiplexed stream without closing the QUIC connection
//! (response-direction STOP_SENDING, or request-upload RESET_STREAM while
//! backend headers are still held).
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_destination_active_requests_h3 -- --ignored --nocapture`

use super::destination_active_requests_helpers::{
    HoldBehavior, HoldingHttp1Backend, NS, OVERFLOW_BODY, UPSTREAM_ID,
    assert_projected_active_request_cap, prepare_for_assertions, start_gateway,
};
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Connection, Http3Response};

use ferrum_edge::config::types::GatewayConfig;
use http::StatusCode;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::time::sleep;

const SETTLE: Duration = Duration::from_millis(400);

#[ignore]
#[test]
fn functional_destination_active_requests_h3_sheds_and_releases_on_relay_end() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_h3_sheds_and_releases_on_relay_end_inner(),
    );
}

async fn functional_destination_active_requests_h3_sheds_and_releases_on_relay_end_inner() {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let config = h3_destination_config(backend.port);
    let prepared = prepare_for_assertions(config.clone());
    assert_projected_active_request_cap(&prepared, "dest-active-h3", backend.port, Some(1));

    let gateway = start_gateway(config, true).await.expect("start h3 gateway");
    let https_port = gateway.https_port;

    // First H3 request: reaches the backend and parks there, so the relay — and
    // with it the destination permit — stays alive.
    let hold_client = Http3Client::insecure().expect("hold h3 client");
    let hold_url = format!("https://localhost:{https_port}/h3/hold");
    let hold = tokio::spawn(async move { retry_h3_get(&hold_client, &hold_url).await });
    backend.wait_for_hits(1, Duration::from_secs(20)).await;

    let probe_client = Http3Client::insecure().expect("probe h3 client");
    let shed = retry_h3_get(
        &probe_client,
        &format!("https://localhost:{https_port}/h3/shed"),
    )
    .await;
    assert_eq!(
        shed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a second H3 request must be shed by the destination breaker: {shed:?}"
    );
    assert_eq!(
        shed.body_text(),
        OVERFLOW_BODY,
        "the H3 shed must carry the documented destination-overflow body"
    );
    backend.assert_hits_eq(1, SETTLE).await;

    backend.release();
    let held = hold.await.expect("held H3 task");
    assert_eq!(held.status, StatusCode::OK, "held H3 request must complete");
    assert_eq!(held.body_text(), "ok");

    let after = retry_h3_get(
        &probe_client,
        &format!("https://localhost:{https_port}/h3/after"),
    )
    .await;
    assert_eq!(
        after.status,
        StatusCode::OK,
        "the destination permit must be released when the H3 relay ends: {after:?}"
    );
    backend.assert_hits_eq(2, SETTLE).await;

    gateway.shutdown().await;
    backend.shutdown().await;
}

#[ignore]
#[test]
fn functional_destination_active_requests_h3_release_on_client_cancellation() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_h3_release_on_client_cancellation_inner());
}

async fn functional_destination_active_requests_h3_release_on_client_cancellation_inner() {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let gateway = start_gateway(h3_destination_config(backend.port), true)
        .await
        .expect("start h3 gateway");
    let https_port = gateway.https_port;

    let hold_client = Http3Client::insecure().expect("hold h3 client");
    let hold_url = format!("https://localhost:{https_port}/h3/hold");
    let mut session = connect_h3_session(&hold_client, &hold_url).await;
    let mut hold_stream = open_finished_hold_stream(&mut session, &hold_url).await;
    backend.wait_for_hits(1, Duration::from_secs(20)).await;

    let probe_client = Http3Client::insecure().expect("probe h3 client");
    let shed = retry_h3_get(
        &probe_client,
        &format!("https://localhost:{https_port}/h3/shed"),
    )
    .await;
    assert_eq!(
        shed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the destination must be saturated before the cancellation: {shed:?}"
    );
    backend.assert_hits_eq(1, SETTLE).await;

    // Cancel only this stream's response direction (peer STOP_SENDING on the
    // gateway send half). The session (and its QUIC connection) stays open so a
    // follow-up on the same connection cannot be explained by CONNECTION_CLOSE.
    hold_stream.cancel_response_download();
    drop(hold_stream);

    let after_url = format!("https://localhost:{https_port}/h3/after-cancel");
    let after =
        tokio::spawn(
            async move { retry_h3_session_until_admitted(&mut session, &after_url).await },
        );
    // Reaching the fixture at all proves the permit was released while the
    // first backend exchange is still held. If only whole-connection close
    // were observed, this request would stay shed at 503 and never increment
    // hits.
    backend.wait_for_hits(2, Duration::from_secs(25)).await;

    backend.release();
    let after = after.await.expect("post-cancel H3 task");
    assert_eq!(
        after.status,
        StatusCode::OK,
        "an H3 request admitted after a per-stream cancellation must complete: {after:?}"
    );
    assert_ne!(
        after.body_text(),
        OVERFLOW_BODY,
        "the post-cancellation request must not be a destination shed"
    );

    gateway.shutdown().await;
    backend.shutdown().await;
}

#[ignore]
#[test]
fn functional_destination_active_requests_h3_release_on_streaming_upload_cancellation() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_h3_release_on_streaming_upload_cancellation_inner(),
    );
}

async fn functional_destination_active_requests_h3_release_on_streaming_upload_cancellation_inner()
{
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let gateway = start_gateway(h3_destination_config(backend.port), true)
        .await
        .expect("start h3 gateway");
    let https_port = gateway.https_port;

    let hold_client = Http3Client::insecure().expect("hold h3 client");
    let hold_url = format!("https://localhost:{https_port}/h3/hold");
    let mut session = connect_h3_session(&hold_client, &hold_url).await;
    let mut hold_stream = open_streaming_hold_stream(&mut session, &hold_url).await;
    hold_stream
        .send_data(bytes::Bytes::from_static(b"partial-upload"))
        .await
        .expect("send streaming hold body");
    backend.wait_for_hits(1, Duration::from_secs(20)).await;

    let probe_client = Http3Client::insecure().expect("probe h3 client");
    let shed = retry_h3_get(
        &probe_client,
        &format!("https://localhost:{https_port}/h3/shed"),
    )
    .await;
    assert_eq!(
        shed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the destination must be saturated before streaming cancellation: {shed:?}"
    );
    backend.assert_hits_eq(1, SETTLE).await;

    // Cancel only this stream's response direction (peer STOP_SENDING on the
    // gateway send half) while a streaming upload is still open. A separate
    // test covers request-upload RESET_STREAM / recv_data() error.
    hold_stream.cancel_response_download();
    drop(hold_stream);

    let after_url = format!("https://localhost:{https_port}/h3/after-cancel");
    let after =
        tokio::spawn(
            async move { retry_h3_session_until_admitted(&mut session, &after_url).await },
        );
    backend.wait_for_hits(2, Duration::from_secs(25)).await;

    backend.release();
    let after = after.await.expect("post-cancel streaming H3 task");
    assert_eq!(
        after.status,
        StatusCode::OK,
        "an H3 request admitted after streaming-upload cancellation must complete: {after:?}"
    );
    assert_ne!(
        after.body_text(),
        OVERFLOW_BODY,
        "the post-cancellation request must not be a destination shed"
    );

    gateway.shutdown().await;
    backend.shutdown().await;
}

#[ignore]
#[test]
fn functional_destination_active_requests_h3_release_on_streaming_request_reset() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_h3_release_on_streaming_request_reset_inner(),
    );
}

async fn functional_destination_active_requests_h3_release_on_streaming_request_reset_inner() {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let gateway = start_gateway(h3_destination_config(backend.port), true)
        .await
        .expect("start h3 gateway");
    let https_port = gateway.https_port;

    let hold_client = Http3Client::insecure().expect("hold h3 client");
    let hold_url = format!("https://localhost:{https_port}/h3/hold");
    let mut session = connect_h3_session(&hold_client, &hold_url).await;
    let mut hold_stream = open_streaming_hold_stream(&mut session, &hold_url).await;
    hold_stream
        .send_data(bytes::Bytes::from_static(b"partial-upload"))
        .await
        .expect("send streaming hold body");
    backend.wait_for_hits(1, Duration::from_secs(20)).await;

    let probe_client = Http3Client::insecure().expect("probe h3 client");
    let shed = retry_h3_get(
        &probe_client,
        &format!("https://localhost:{https_port}/h3/shed"),
    )
    .await;
    assert_eq!(
        shed.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the destination must be saturated before request-upload reset: {shed:?}"
    );
    backend.assert_hits_eq(1, SETTLE).await;

    // Reset only the request-upload direction (gateway recv_data() error /
    // reader_peer_reset). Keep the stream alive so Drop cannot also STOP_SENDING
    // the response half and take the already-covered path. The session stays
    // open so a follow-up cannot be explained by CONNECTION_CLOSE.
    hold_stream.cancel_request_upload();

    let after_url = format!("https://localhost:{https_port}/h3/after-reset");
    let after =
        tokio::spawn(
            async move { retry_h3_session_until_admitted(&mut session, &after_url).await },
        );
    // Reaching the fixture before backend.release() proves the permit was
    // released by the upload reset, not by waiting for the held backend.
    backend.wait_for_hits(2, Duration::from_secs(25)).await;

    backend.release();
    let after = after.await.expect("post-reset streaming H3 task");
    assert_eq!(
        after.status,
        StatusCode::OK,
        "an H3 request admitted after request-upload reset must complete: {after:?}"
    );
    assert_ne!(
        after.body_text(),
        OVERFLOW_BODY,
        "the post-reset request must not be a destination shed"
    );
    drop(hold_stream);

    gateway.shutdown().await;
    backend.shutdown().await;
}

async fn retry_h3_get(client: &Http3Client, url: &str) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_err = None;
    loop {
        match client.get(url).await {
            Ok(response) => return response,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!(
                "H3 request to {url} did not complete; last startup error={last_err:?}; final error={err}"
            ),
        }
    }
}

async fn retry_h3_session_until_admitted(
    session: &mut Http3Connection,
    url: &str,
) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut last_status = None;
    let mut last_err = None;
    loop {
        match session.get(url).await {
            Ok(response)
                if response.status == StatusCode::SERVICE_UNAVAILABLE
                    && response.body_text() == OVERFLOW_BODY
                    && Instant::now() < deadline =>
            {
                last_status = Some(response.status);
                last_err = None;
                sleep(Duration::from_millis(100)).await;
            }
            Ok(response) => return response,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!(
                "H3 session request to {url} did not complete; last shed status={last_status:?}; last error={last_err:?}; final error={err}"
            ),
        }
    }
}

async fn connect_h3_session(client: &Http3Client, url: &str) -> Http3Connection {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_err = None;
    loop {
        match client.connect(url).await {
            Ok(session) => return session,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!(
                "H3 session to {url} did not connect; last startup error={last_err:?}; final error={err}"
            ),
        }
    }
}

async fn open_finished_hold_stream(
    session: &mut Http3Connection,
    url: &str,
) -> crate::scaffolding::clients::Http3ConnectionStream {
    open_hold_stream(session, url, true).await
}

async fn open_streaming_hold_stream(
    session: &mut Http3Connection,
    url: &str,
) -> crate::scaffolding::clients::Http3ConnectionStream {
    let options = GetOptions::default().method(http::Method::POST);
    open_hold_stream_with_options(session, url, options, false).await
}

async fn open_hold_stream(
    session: &mut Http3Connection,
    url: &str,
    finish_body: bool,
) -> crate::scaffolding::clients::Http3ConnectionStream {
    open_hold_stream_with_options(session, url, GetOptions::default(), finish_body).await
}

async fn open_hold_stream_with_options(
    session: &mut Http3Connection,
    url: &str,
    options: GetOptions,
    finish_body: bool,
) -> crate::scaffolding::clients::Http3ConnectionStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_err = None;
    loop {
        match session.open_stream(url, options.clone(), finish_body).await {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!(
                "H3 hold stream to {url} did not open; last startup error={last_err:?}; final error={err}"
            ),
        }
    }
}

fn h3_destination_config(backend_port: u16) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "dest-active-h3",
            "namespace": NS,
            "listen_path": "/h3",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "upstream_id": UPSTREAM_ID,
            "pool_enable_http2": false
        }],
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
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "dest-active-h3-dr",
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
    .expect("h3 destination config is valid")
}

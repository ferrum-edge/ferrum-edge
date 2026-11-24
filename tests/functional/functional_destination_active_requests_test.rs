//! Live traffic-path acceptance for the DestinationRule
//! `connectionPool.http.http2MaxRequests` destination-wide **active-request**
//! breaker (issue #3775), HTTP/1.1 and HTTP/2 legs.
//!
//! Istio defines the field as "maximum number of active requests to a
//! destination, applicable to both HTTP1.1 and HTTP2". These tests hold a real
//! backend exchange open on a real in-process gateway and assert the
//! consequences an operator actually depends on:
//!
//! * a held exchange keeps its permit for the WHOLE exchange (not until
//!   response headers), so a second request to the same logical destination is
//!   shed with the documented `503` body;
//! * the shed happens BEFORE any backend dial — the fixture's request counter
//!   never moves;
//! * an HTTP/1.1 hold and an HTTP/2 attempt to the same logical destination
//!   share ONE budget, and a second client connection does not mint a second
//!   allowance;
//! * every terminal path releases: body EOF, client disconnect / task
//!   cancellation, backend error, and read timeout;
//! * lanes are keyed by logical policy identity, so two Services that resolve
//!   to the same address do not interfere, a sequential retry drops and
//!   reacquires, and a shed poisons neither the circuit breaker nor passive
//!   health.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_destination_active_requests -- --ignored --nocapture`

use super::destination_active_requests_helpers::{
    HoldBehavior, HoldingHttp1Backend, NS, OVERFLOW_BODY, SIBLING_UPSTREAM_ID,
    StatusScriptHttp1Backend, UPSTREAM_ID, assert_projected_active_request_cap,
    prepare_for_assertions, start_gateway, wait_until,
};
use crate::scaffolding::backends::{H2Step, MatchHeaders, ScriptedH2Backend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::ports::reserve_port;

use ferrum_edge::config::types::GatewayConfig;
use http::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::timeout;

const SETTLE: Duration = Duration::from_millis(400);
const HIT_WAIT: Duration = Duration::from_secs(15);
const HOLD_WAIT: Duration = Duration::from_secs(20);

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        // One connection per request: a per-client-connection allowance would
        // be indistinguishable from a destination-wide one on a pooled client.
        .pool_max_idle_per_host(0)
        .build()
        .expect("http client")
}

async fn get(client: &reqwest::Client, port: u16, path: &str) -> (StatusCode, String) {
    let response = timeout(
        Duration::from_secs(20),
        client.get(format!("http://127.0.0.1:{port}{path}")).send(),
    )
    .await
    .unwrap_or_else(|_| panic!("GET {path} timed out"))
    .unwrap_or_else(|err| panic!("GET {path} failed: {err}"));
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    (status, body)
}

fn assert_destination_shed(status: StatusCode, body: &str, what: &str) {
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{what} must be shed by the destination active-request breaker; body={body}"
    );
    assert_eq!(
        body, OVERFLOW_BODY,
        "{what} must carry the documented destination-overflow body"
    );
}

fn assert_not_destination_shed(body: &str, what: &str) {
    assert_ne!(
        body, OVERFLOW_BODY,
        "{what} must not be a destination active-request shed"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 1. HTTP/1.1 — saturation, no-dial shed, logical-identity isolation, EOF release
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_http1_sheds_before_dispatch_and_releases_on_eof() {
    crate::common::in_process_gateway_runtime(4).block_on(functional_destination_active_requests_http1_sheds_before_dispatch_and_releases_on_eof_inner());
}

async fn functional_destination_active_requests_http1_sheds_before_dispatch_and_releases_on_eof_inner()
 {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let config = two_destination_config(backend.port, None);

    // Setup gate: the DestinationRule budget must be on the primary lane only,
    // so a traffic failure below cannot be a silent translation failure.
    let prepared = prepare_for_assertions(config.clone());
    assert_projected_active_request_cap(&prepared, "dest-active-primary", backend.port, Some(1));
    assert_projected_active_request_cap(&prepared, "dest-active-sibling", backend.port, None);

    let gateway = start_gateway(config, false).await.expect("start gateway");
    let port = gateway.http_port;

    // Hold one exchange at the backend. The gateway has sent the request and is
    // waiting for a response, so exactly one destination permit is live.
    let hold_client = client();
    let hold = tokio::spawn({
        let hold_client = hold_client.clone();
        async move { get(&hold_client, port, "/primary/hold").await }
    });
    backend.wait_for_hits(1, Duration::from_secs(15)).await;

    // Second request to the same logical destination, on its own client
    // connection: shed with the documented body, and never dialed.
    let probe = client();
    let (status, body) = get(&probe, port, "/primary/shed").await;
    assert_destination_shed(status, &body, "second concurrent request");
    backend.assert_hits_eq(1, SETTLE).await;

    // A DIFFERENT logical destination whose endpoints are the SAME address must
    // keep its own budget: it reaches the backend while the primary is
    // saturated. This is the "keyed by logical identity, not by resolved
    // host/IP" contract.
    let sibling_client = client();
    let sibling = tokio::spawn({
        let sibling_client = sibling_client.clone();
        async move { get(&sibling_client, port, "/sibling/ok").await }
    });
    backend.wait_for_hits(2, Duration::from_secs(15)).await;

    // Release: both held exchanges complete, and the primary permit drops at
    // body EOF.
    backend.release();
    let (held_status, held_body) = hold.await.expect("held request task");
    assert_eq!(held_status, StatusCode::OK, "held request must complete");
    assert_eq!(held_body, "ok");
    let (sibling_status, _) = sibling.await.expect("sibling request task");
    assert_eq!(
        sibling_status,
        StatusCode::OK,
        "sibling destination must not be shed by the primary destination's budget"
    );

    let (after_status, after_body) = get(&probe, port, "/primary/after").await;
    assert_eq!(
        after_status,
        StatusCode::OK,
        "destination permit must be released at response-body EOF; body={after_body}"
    );
    backend.assert_hits_eq(3, SETTLE).await;

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 2. HTTP/1.1 — client disconnect / task cancellation releases the permit
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_release_on_client_disconnect() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_release_on_client_disconnect_inner());
}

async fn functional_destination_active_requests_release_on_client_disconnect_inner() {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let gateway = start_gateway(two_destination_config(backend.port, None), false)
        .await
        .expect("start gateway");
    let port = gateway.http_port;

    // Hold one exchange, then confirm the destination really is saturated
    // before cancelling — otherwise a later admission would prove nothing.
    let hold_client = client();
    let hold = tokio::spawn({
        let hold_client = hold_client.clone();
        async move { get(&hold_client, port, "/primary/hold").await }
    });
    backend.wait_for_hits(1, Duration::from_secs(15)).await;
    let probe = client();
    let (status, body) = get(&probe, port, "/primary/shed").await;
    assert_destination_shed(status, &body, "request while the first is held");
    backend.assert_hits_eq(1, SETTLE).await;

    // Client goes away mid-exchange: abort the in-flight task, then wait until
    // Tokio has actually dropped that future before probing admission again.
    // Without the join, a busy runtime can leave the task's cloned client (and
    // therefore its connection) alive while the follow-up request races it.
    // The backend never answered, so the ONLY way the budget frees is the RAII
    // permit riding the cancelled response body.
    hold.abort();
    let cancelled = hold
        .await
        .expect_err("held request task must be cancelled before the release probe");
    assert!(
        cancelled.is_cancelled(),
        "held request task must end by cancellation: {cancelled}"
    );
    drop(hold_client);

    let after = tokio::spawn({
        let probe = probe.clone();
        async move { get(&probe, port, "/primary/after-disconnect").await }
    });
    // Admission is observable at the backend even though the fixture still
    // holds the exchange: reaching it at all proves the permit was released.
    backend.wait_for_hits(2, Duration::from_secs(20)).await;

    backend.release();
    let (after_status, after_body) = after.await.expect("post-disconnect task");
    assert_eq!(
        after_status,
        StatusCode::OK,
        "a request admitted after a client disconnect must complete; body={after_body}"
    );
    assert_not_destination_shed(&after_body, "post-disconnect request");

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 3. HTTP/1.1 — backend error / socket drop releases the permit
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_release_on_backend_error() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_release_on_backend_error_inner());
}

async fn functional_destination_active_requests_release_on_backend_error_inner() {
    let behavior = HoldBehavior::DropConnection;
    let backend = HoldingHttp1Backend::spawn(behavior).await;
    // Every exchange fails at the backend immediately, so a leaked permit would
    // wedge the destination at the first failure.
    backend.release();
    let gateway = start_gateway(two_destination_config(backend.port, None), false)
        .await
        .expect("start gateway");
    let port = gateway.http_port;
    let probe = client();

    for attempt in 1..=3 {
        let (status, body) = get(&probe, port, "/primary/error").await;
        assert!(
            status.is_server_error(),
            "attempt {attempt} must surface the backend failure, got {status}"
        );
        assert_not_destination_shed(
            &body,
            &format!("attempt {attempt} after a backend-side failure"),
        );
        backend.assert_hits_eq(attempt, SETTLE).await;
    }

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 4. HTTP/1.1 — backend read timeout releases the permit
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_release_on_backend_timeout() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_release_on_backend_timeout_inner());
}

async fn functional_destination_active_requests_release_on_backend_timeout_inner() {
    // The fixture NEVER releases, so every exchange ends at the gateway's own
    // read timeout — the deadline terminal path.
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    let gateway = start_gateway(
        two_destination_config(backend.port, Some(json!({"backend_read_timeout_ms": 700}))),
        false,
    )
    .await
    .expect("start gateway");
    let port = gateway.http_port;
    let probe = client();

    for attempt in 1..=3 {
        let (status, body) = get(&probe, port, "/primary/timeout").await;
        assert!(
            status.is_server_error(),
            "attempt {attempt} must surface the backend read timeout, got {status}"
        );
        assert_not_destination_shed(&body, &format!("attempt {attempt} after a read timeout"));
        backend.wait_for_hits(attempt, HIT_WAIT).await;
    }
    backend.assert_hits_eq(3, SETTLE).await;

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 5. A sequential retry drops and reacquires — it never double-charges
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_sequential_retry_reacquires_the_permit() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_sequential_retry_reacquires_the_permit_inner(),
    );
}

async fn functional_destination_active_requests_sequential_retry_reacquires_the_permit_inner() {
    // First attempt 503 (retryable), second attempt 200. With a cap of one, a
    // retry that failed to release the previous attempt's permit would be shed
    // by its own predecessor and the client would see the overflow body.
    let backend = StatusScriptHttp1Backend::spawn(&[503, 200]).await;
    let gateway = start_gateway(
        two_destination_config(
            backend.port,
            Some(json!({
                "retry": {
                    "max_retries": 1,
                    "retryable_status_codes": [503],
                    "retryable_methods": ["GET"],
                    "retry_on_connect_failure": false
                }
            })),
        ),
        false,
    )
    .await
    .expect("start gateway");

    let (status, body) = get(&client(), gateway.http_port, "/primary/retry").await;
    assert_not_destination_shed(&body, "retried request");
    assert_eq!(
        status,
        StatusCode::OK,
        "a sequential retry must reacquire its own destination permit; body={body}"
    );
    assert_eq!(
        backend.hits(),
        2,
        "the retry must have reached the backend a second time"
    );

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 6. A shed is backend-neutral: no dial, no health/breaker feedback
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_shed_is_backend_neutral() {
    crate::common::in_process_gateway_runtime(4)
        .block_on(functional_destination_active_requests_shed_is_backend_neutral_inner());
}

async fn functional_destination_active_requests_shed_is_backend_neutral_inner() {
    let backend = HoldingHttp1Backend::spawn(HoldBehavior::RespondOk).await;
    // A breaker that trips on ONE 503 and passive health that ejects on ONE
    // 503: if the shed were recorded as a backend outcome, the follow-up
    // request would be short-circuited or the target ejected and would never
    // reach the fixture.
    let config = two_destination_config(
        backend.port,
        Some(json!({
            "circuit_breaker": {
                "failure_threshold": 1,
                "success_threshold": 1,
                "timeout_seconds": 60,
                "failure_status_codes": [500, 502, 503, 504],
                "half_open_max_requests": 1,
                "trip_on_connection_errors": true
            }
        })),
    );
    let config = with_passive_health(config);
    let gateway = start_gateway(config, false).await.expect("start gateway");
    let port = gateway.http_port;

    let hold_client = client();
    let hold = tokio::spawn({
        let hold_client = hold_client.clone();
        async move { get(&hold_client, port, "/primary/hold").await }
    });
    backend.wait_for_hits(1, Duration::from_secs(15)).await;

    let probe = client();
    for attempt in 1..=3 {
        let (status, body) = get(&probe, port, "/primary/shed").await;
        assert_destination_shed(status, &body, &format!("shed attempt {attempt}"));
    }
    backend.assert_hits_eq(1, SETTLE).await;

    backend.release();
    let (held_status, _) = hold.await.expect("held task");
    assert_eq!(held_status, StatusCode::OK);

    let (after_status, after_body) = get(&probe, port, "/primary/after").await;
    assert_eq!(
        after_status,
        StatusCode::OK,
        "three sheds must not trip the circuit breaker or eject the target; body={after_body}"
    );
    backend.assert_hits_eq(2, SETTLE).await;

    gateway.shutdown().await;
    backend.shutdown().await;
}

// ───────────────────────────────────────────────────────────────────────────
// 7. HTTP/2 — the same destination budget, shared with an HTTP/1.1 route
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_http2_shares_one_destination_budget() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_http2_shares_one_destination_budget_inner(),
    );
}

async fn functional_destination_active_requests_http2_shares_one_destination_budget_inner() {
    let ca = TestCa::new("destination-active-h2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("h2 backend port");
    let backend_port = reservation.port;

    // Response HEADERS are sent immediately and the stream is then parked, so
    // the exchange is live long after the client has seen `200`. A permit
    // released at response headers would let the next request through here.
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::AwaitTestSignal)
        .step(H2Step::RespondData {
            data: bytes::Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2 tls backend");

    let gateway = start_gateway(http2_lane_config(backend_port), false)
        .await
        .expect("start gateway");
    let port = gateway.http_port;

    let hold_client = client();
    let hold = tokio::spawn({
        let hold_client = hold_client.clone();
        async move { get(&hold_client, port, "/h2/hold").await }
    });
    let parked = || backend.awaiting_test_signal() >= 1;
    wait_until(HOLD_WAIT, "the H2 backend to park a stream", parked).await;
    let streams_while_held = backend.received_stream_count();
    let connections_while_held = backend.accepted_connections();
    assert_eq!(
        streams_while_held, 1,
        "exactly one backend stream must be live while the exchange is held"
    );

    // A second HTTP/2 request on its own client connection: shed. A
    // per-connection stream allowance (the pre-#3775 behavior) would have
    // admitted it on a fresh connection.
    let probe = client();
    let (status, body) = get(&probe, port, "/h2/shed").await;
    assert_destination_shed(status, &body, "second HTTP/2 request");

    // An HTTP/1.1-dispatch route on the SAME logical destination shares the
    // budget: the request is shed before any dial, so the H1-only route never
    // has to reach the H2-only fixture.
    let (h1_status, h1_body) = get(&probe, port, "/h1/shed").await;
    assert_destination_shed(h1_status, &h1_body, "HTTP/1.1 request sharing the lane");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        backend.received_stream_count(),
        streams_while_held,
        "a shed request must not open a backend stream"
    );
    assert_eq!(
        backend.accepted_connections(),
        connections_while_held,
        "a shed request must not dial the backend"
    );

    backend.release_test_signal();
    let (held_status, held_body) = hold.await.expect("held H2 task");
    assert_eq!(held_status, StatusCode::OK, "held H2 request must complete");
    assert_eq!(held_body, "ok");

    let (after_status, after_body) = get(&probe, port, "/h2/after").await;
    assert_eq!(
        after_status,
        StatusCode::OK,
        "the permit must release at HTTP/2 body end-of-stream; body={after_body}"
    );
    assert!(
        backend.received_stream_count() >= 2,
        "the post-release request must have reached the backend over HTTP/2"
    );
    backend.assert_no_matcher_mismatches().await;

    gateway.shutdown().await;
    drop(backend);
}

// ───────────────────────────────────────────────────────────────────────────
// 8. Reqwest/ALPN HTTP/2 dispatch consumes the same budget
// ───────────────────────────────────────────────────────────────────────────

#[ignore]
#[test]
fn functional_destination_active_requests_reqwest_alpn_http2_consumes_the_budget() {
    crate::common::in_process_gateway_runtime(4).block_on(
        functional_destination_active_requests_reqwest_alpn_http2_consumes_the_budget_inner(),
    );
}

async fn functional_destination_active_requests_reqwest_alpn_http2_consumes_the_budget_inner() {
    let ca = TestCa::new("destination-active-reqwest-h2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("h2 backend port");
    let backend_port = reservation.port;

    // ALPN advertises `h2` only, so the exchange below can only complete if the
    // gateway's shared reqwest client negotiated HTTP/2 — the dispatch fork the
    // issue calls out as previously uncovered by the direct-H2 builder knob.
    let backend = ScriptedH2Backend::builder_tls(reservation.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::AwaitTestSignal)
        .step(H2Step::RespondData {
            data: bytes::Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2 tls backend");

    let gateway = start_gateway(reqwest_http2_lane_config(backend_port), false)
        .await
        .expect("start gateway");
    let port = gateway.http_port;

    let hold_client = client();
    let hold = tokio::spawn({
        let hold_client = hold_client.clone();
        async move { get(&hold_client, port, "/reqwest-h2/hold").await }
    });
    let parked = || backend.awaiting_test_signal() >= 1;
    wait_until(HOLD_WAIT, "the reqwest H2 backend to park", parked).await;

    let probe = client();
    let (status, body) = get(&probe, port, "/reqwest-h2/shed").await;
    assert_destination_shed(status, &body, "second reqwest/ALPN HTTP/2 request");
    let streams_while_held = backend.received_stream_count();
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        backend.received_stream_count(),
        streams_while_held,
        "a shed request must not open a backend stream"
    );

    backend.release_test_signal();
    let (held_status, held_body) = hold.await.expect("held reqwest H2 task");
    assert_eq!(held_status, StatusCode::OK);
    assert_eq!(held_body, "ok");

    let (after_status, after_body) = get(&probe, port, "/reqwest-h2/after").await;
    assert_eq!(
        after_status,
        StatusCode::OK,
        "the permit must release when the reqwest H2 body ends; body={after_body}"
    );
    backend.assert_no_matcher_mismatches().await;

    gateway.shutdown().await;
    drop(backend);
}

// ───────────────────────────────────────────────────────────────────────────
// Configs
// ───────────────────────────────────────────────────────────────────────────

/// Two logical destinations that resolve to the SAME backend address. Only the
/// primary carries `http2MaxRequests: 1`.
///
/// `primary_extra` is merged into the primary proxy so individual tests can add
/// a retry policy, circuit breaker, or read timeout without another builder.
fn two_destination_config(backend_port: u16, primary_extra: Option<Value>) -> GatewayConfig {
    let mut primary = json!({
        "id": "dest-active-primary",
        "namespace": NS,
        "listen_path": "/primary",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "upstream_id": UPSTREAM_ID,
        "pool_enable_http2": false
    });
    if let Some(Value::Object(extra)) = primary_extra {
        let primary_obj = primary.as_object_mut().expect("primary proxy object");
        for (key, value) in extra {
            primary_obj.insert(key, value);
        }
    }

    serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            primary,
            {
                "id": "dest-active-sibling",
                "namespace": NS,
                "listen_path": "/sibling",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "upstream_id": SIBLING_UPSTREAM_ID,
                "pool_enable_http2": false
            }
        ],
        "upstreams": [
            upstream_json(UPSTREAM_ID, backend_port),
            upstream_json(SIBLING_UPSTREAM_ID, backend_port)
        ],
        "consumers": [],
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "dest-active-dr",
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
    .expect("two-destination config is valid")
}

/// One HTTPS destination reached by two routes: an HTTP/2-capable one and an
/// HTTP/1.1-only one. `h2UpgradePolicy: UPGRADE` is the neighbouring transport
/// control and must not itself change the budget.
fn http2_lane_config(backend_port: u16) -> GatewayConfig {
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "dest-active-h2",
                "namespace": NS,
                "listen_path": "/h2",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "upstream_id": UPSTREAM_ID,
                "pool_enable_http2": true
            },
            {
                "id": "dest-active-h2-h1-lane",
                "namespace": NS,
                "listen_path": "/h1",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "upstream_id": UPSTREAM_ID,
                "pool_enable_http2": false
            }
        ],
        "upstreams": [upstream_json(UPSTREAM_ID, backend_port)],
        "consumers": [],
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "dest-active-h2-dr",
                "namespace": NS,
                "host": UPSTREAM_ID,
                "traffic_policy": {
                    "connection_pool_http": {
                        "http2_max_requests": 1,
                        "h2_upgrade_policy": "UPGRADE"
                    }
                }
            }]
        }
    }))
    .expect("http2 lane config is valid");
    trust_fixture_certificates(&mut config);
    config
}

/// A route whose retry policy retains the request body, which forces dispatch
/// onto the shared reqwest client instead of the direct HTTP/2 pool
/// (`can_use_direct_http2_pool`). The backend still speaks HTTP/2 only.
fn reqwest_http2_lane_config(backend_port: u16) -> GatewayConfig {
    let mut config: GatewayConfig = serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "dest-active-reqwest-h2",
            "namespace": NS,
            "listen_path": "/reqwest-h2",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "upstream_id": UPSTREAM_ID,
            "pool_enable_http2": true,
            "retry": {
                "max_retries": 1,
                "retryable_status_codes": [502],
                "retryable_methods": ["GET"],
                "retry_on_connect_failure": false
            }
        }],
        "upstreams": [upstream_json(UPSTREAM_ID, backend_port)],
        "consumers": [],
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "dest-active-reqwest-h2-dr",
                "namespace": NS,
                "host": UPSTREAM_ID,
                "traffic_policy": {
                    "connection_pool_http": {
                        "http2_max_requests": 1,
                        "h2_upgrade_policy": "UPGRADE"
                    }
                }
            }]
        }
    }))
    .expect("reqwest http2 lane config is valid");
    trust_fixture_certificates(&mut config);
    config
}

fn upstream_json(id: &str, backend_port: u16) -> Value {
    json!({
        "id": id,
        "namespace": NS,
        "name": id,
        "algorithm": "round_robin",
        "targets": [{
            "host": "127.0.0.1",
            "port": backend_port,
            "weight": 1
        }]
    })
}

/// Passive health that would eject the only target after a single `503`, used
/// to prove a shed never reaches passive-health accounting.
fn with_passive_health(config: GatewayConfig) -> GatewayConfig {
    let mut config = config;
    for upstream in &mut config.upstreams {
        upstream.health_checks = serde_json::from_value(json!({
            "passive": {
                "unhealthy_status_codes": [500, 502, 503, 504],
                "unhealthy_threshold": 1,
                "unhealthy_window_seconds": 60
            }
        }))
        .expect("passive health config is valid");
    }
    config
}

/// These synthetic backend certificates are trusted by this fixture only;
/// production TLS defaults remain fail-closed.
fn trust_fixture_certificates(config: &mut GatewayConfig) {
    for upstream in &mut config.upstreams {
        upstream.backend_tls_verify_server_cert = false;
    }
    for proxy in &mut config.proxies {
        proxy.backend_tls_verify_server_cert = false;
    }
}

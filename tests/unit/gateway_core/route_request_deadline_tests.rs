//! Proxy-core contract for a route rule's total request deadline
//! (`mesh_route_dispatch` `request_timeout_ms`, Gateway API
//! `HTTPRoute.rules[].timeouts.request`, #5646).
//!
//! These run on a paused Tokio clock, so the deadline arithmetic is exact and
//! no wall-clock window can flake. They pin:
//!
//! * the attempt wrapper: a spent budget refuses an attempt WITHOUT polling it,
//!   an in-flight attempt is cancelled (dropped) at the deadline, and no
//!   deadline leaves the attempt unbounded;
//! * health attribution: only an attempt the backend actually held is charged
//!   to it — expiry during gateway/client-side work is health-neutral;
//! * framing: the route cut keeps a known response length exact, so it cannot
//!   silently turn a `Content-Length` response into a chunked one;
//! * native HTTP/3: the relays read the same deadlines, answer an expiry before
//!   the response head with proxy core's exact terminal and attribution, bound
//!   the committed body by the earlier of the total deadline and the attempt
//!   budget, and cut it with `H3_REQUEST_CANCELLED`; and HTTP/3 stays
//!   advertised (`Alt-Svc`) where a timed rule is served.
//!
//! Data-plane behavior through the real gateway is covered by
//! `tests/integration/k8s_controller_gateway_status_tests.rs` and, over native
//! HTTP/3, by `tests/functional/functional_h3_local_policy_test.rs` (the bridge
//! to an HTTP/1.1 backend) and `tests/functional/scripted_backend_h3_tests.rs`
//! (the native HTTP/3 backend pool).

use bytes::Bytes;
use ferrum_edge::_test_support::{
    H3AuthorizedHeadersWrite, H3AuthorizedWrite, attribute_streaming_headers_deadline_for_test,
    await_authorized_response_write_for_test,
    await_authorized_response_write_with_route_sleep_for_test,
    await_offered_response_write_for_test, await_route_request_deadline_for_test,
    h3_plain_bridge_backend_request_for_test, h3_route_attempt_bounds_for_test,
    h3_route_deadline_reset_code_for_test, h3_route_deadline_terminal_for_test,
    h3_route_deadlines_armed_for_test, proxy_body_streaming_for_test,
    proxy_body_with_client_grpc_deadline_for_test, proxy_body_with_route_request_deadline_for_test,
    route_deadline_expiry_response_for_test, route_request_deadline_outcome_for_test,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, Proxy};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthTermination, StreamAuthTerminationLatch,
};
use ferrum_edge::proxy::body::ProxyBodyError;
use ferrum_edge::retry::{ErrorClass, ResponseBody};
use http_body::{Body, Frame, SizeHint};
use serde_json::{Value, json};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

// ── The attempt wrapper ─────────────────────────────────────────────────────

/// Sets its flag when dropped, standing in for the admission permits, upload,
/// and pooled stream a cancelled backend attempt must release.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn a_spent_budget_refuses_the_attempt_without_polling_it() {
    let polled = Arc::new(AtomicBool::new(false));
    let attempt = {
        let polled = Arc::clone(&polled);
        std::future::poll_fn(move |_| {
            polled.store(true, Ordering::SeqCst);
            Poll::Ready("dispatched")
        })
    };
    // Exactly at the deadline counts as spent: the paused clock cannot move
    // between arming and the first poll.
    let deadline = Instant::now();

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Err("not_started"));
    assert!(
        !polled.load(Ordering::SeqCst),
        "a spent budget must refuse the attempt before it does any work"
    );
}

#[tokio::test(start_paused = true)]
async fn an_in_flight_attempt_is_cancelled_at_the_deadline() {
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(Arc::clone(&dropped));
    let attempt = async move {
        let _guard = guard;
        std::future::pending::<&'static str>().await
    };
    let started = Instant::now();
    let deadline = started + Duration::from_millis(700);

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Err("in_flight"));
    let elapsed = Instant::now().duration_since(started);
    assert!(
        elapsed >= Duration::from_millis(700) && elapsed < Duration::from_millis(710),
        "the attempt must be cancelled at the deadline, not before or long after: {elapsed:?}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "cancelling the attempt must drop it, releasing what it held"
    );
}

#[tokio::test(start_paused = true)]
async fn an_attempt_that_answers_first_is_returned_unchanged() {
    let attempt = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "answered"
    };
    let deadline = Instant::now() + Duration::from_millis(700);

    let outcome = await_route_request_deadline_for_test(Some(deadline), attempt).await;

    assert_eq!(outcome, Ok("answered"));
}

#[tokio::test(start_paused = true)]
async fn no_deadline_leaves_the_attempt_unbounded() {
    let attempt = async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "answered"
    };

    let outcome = await_route_request_deadline_for_test(None, attempt).await;

    assert_eq!(outcome, Ok("answered"));
}

// ── Health attribution ──────────────────────────────────────────────────────

#[test]
fn only_an_attempt_the_backend_held_is_charged_to_it() {
    // `(in_flight, handed_to_backend)` -> `(logged phase, dispatch class)`.
    let outcome = route_request_deadline_outcome_for_test;
    let neutral = ("before_dispatch", ErrorClass::DispatchPolicyRejected);
    // The budget was spent before the attempt started: nothing was dialed.
    assert_eq!(outcome(false, false), neutral);
    assert_eq!(outcome(false, true), neutral);
    // Cancelled while the gateway was still collecting a stalled client
    // upload, running request-body hooks, resolving DNS, or waiting for
    // admission: the backend was never asked, so nothing is charged to it.
    assert_eq!(outcome(true, false), neutral);
    // Cancelled while the backend held the request: a backend-health signal.
    assert_eq!(
        outcome(true, true),
        ("dispatch", ErrorClass::ReadWriteTimeout)
    );
}

// ── Response framing ────────────────────────────────────────────────────────

/// A streaming response whose length is known (a backend `Content-Length`)
/// and whose frames have not arrived yet.
struct KnownLengthBody {
    len: u64,
}

impl Body for KnownLengthBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}

#[tokio::test]
async fn a_route_deadline_keeps_a_known_response_length_exact() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let body = proxy_body_streaming_for_test(Box::pin(KnownLengthBody { len: 4_096 }));
    assert_eq!(body.size_hint().exact(), Some(4_096));

    // Hyper rebuilds the stripped `Content-Length` from an exact hint. The
    // route terminal only ever ends the body with an error, so the length
    // stays advertised and a cut reads as a short body, never as a response
    // silently re-framed as chunked.
    let body = proxy_body_with_route_request_deadline_for_test(body, deadline);
    assert_eq!(body.size_hint().exact(), Some(4_096));

    // Contrast: the gRPC deadline may substitute a terminal frame, so it still
    // withholds the hint.
    let grpc = proxy_body_streaming_for_test(Box::pin(KnownLengthBody { len: 4_096 }));
    let grpc = proxy_body_with_client_grpc_deadline_for_test(grpc, deadline, None);
    assert_eq!(grpc.size_hint().exact(), None);
}

// ── Native HTTP/3 ───────────────────────────────────────────────────────────

#[test]
fn native_http3_reads_a_plain_requests_route_deadlines_and_never_a_grpc_ones() {
    let armed = h3_route_deadlines_armed_for_test;
    assert_eq!(
        armed(Some(500), Some(200), false),
        (true, Some(Duration::from_millis(200)))
    );
    // `0s` disables either bound, exactly as in proxy core.
    assert_eq!(armed(Some(0), Some(0), false), (false, None));
    assert_eq!(armed(None, None, false), (false, None));
    // A gRPC-flavored request folds both into its RPC deadline, which the
    // native HTTP/3 gRPC relays enforce, so the plain relays see neither.
    assert_eq!(armed(Some(500), Some(200), true), (false, None));
}

#[test]
fn native_http3_answers_a_route_expiry_before_the_head_like_proxy_core() {
    let route_timeout = r#"{"error":"Request timeout"}"#;
    // Spent before the attempt started: nothing was dialed, so it is neutral.
    assert_eq!(
        h3_route_deadline_terminal_for_test("not_started"),
        (
            504,
            route_timeout,
            ErrorClass::DispatchPolicyRejected,
            Some("before_dispatch".to_string()),
            true,
        )
    );
    // Expired while the backend held the attempt: charged to that backend.
    assert_eq!(
        h3_route_deadline_terminal_for_test("in_flight"),
        (
            504,
            route_timeout,
            ErrorClass::ReadWriteTimeout,
            Some("dispatch".to_string()),
            true,
        )
    );
    // An attempt budget is the ordinary, retryable backend timeout: charged,
    // with no route phase because the transaction is not spent.
    assert_eq!(
        h3_route_deadline_terminal_for_test("attempt_budget"),
        (
            504,
            r#"{"error":"Backend timeout"}"#,
            ErrorClass::ReadWriteTimeout,
            None,
            true,
        )
    );

    // Byte-for-byte proxy core's terminal for the same expiry. Every native
    // HTTP/3 attempt is handed to the backend from its first poll.
    for expiry in ["not_started", "in_flight", "attempt_budget"] {
        let (status, body, class, phase, _) = h3_route_deadline_terminal_for_test(expiry);
        let (core, core_phase) = route_deadline_expiry_response_for_test(expiry, true);
        assert_eq!(status, core.status_code, "{expiry}");
        assert_eq!(Some(class), core.error_class, "{expiry}");
        assert_eq!(phase.as_deref(), core_phase, "{expiry}");
        assert!(!core.connection_error, "{expiry}");
        match core.body {
            ResponseBody::Buffered(bytes) => assert_eq!(&bytes[..], body.as_bytes(), "{expiry}"),
            _ => panic!("proxy core's route terminal must be buffered"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn native_http3_bounds_the_committed_body_by_the_earlier_deadline() {
    let bounds = h3_route_attempt_bounds_for_test;
    let started = Instant::now();
    let total = started + Duration::from_millis(1_000);
    let budget = Duration::from_millis(300);
    let attempt_deadline = started + budget;

    // A fresh attempt budget starts now, and the committed body is cut at the
    // earlier of it and the total deadline.
    let (fresh, body, budget_expired, _) =
        bounds(Some(total), Some(budget), Some(attempt_deadline));
    assert_eq!(fresh, Some(attempt_deadline));
    assert_eq!(body, Some(attempt_deadline));
    assert!(!budget_expired);
    let (_, body, _, _) = bounds(Some(total), None, None);
    assert_eq!(body, Some(total));

    // The attempt budget alone has expired: the retryable backend timeout.
    tokio::time::advance(budget).await;
    let (_, _, budget_expired, expiry) = bounds(Some(total), Some(budget), Some(attempt_deadline));
    assert!(budget_expired);
    assert_eq!(expiry, "attempt_budget");

    // Once the total deadline has elapsed it wins, so the spent transaction
    // is never retried.
    tokio::time::advance(Duration::from_millis(700)).await;
    let (_, _, budget_expired, expiry) = bounds(Some(total), Some(budget), Some(attempt_deadline));
    assert!(!budget_expired);
    assert_eq!(expiry, "in_flight");

    // A rule without timeouts arms nothing.
    let (fresh, body, budget_expired, _) = bounds(None, None, None);
    assert_eq!((fresh, body, budget_expired), (None, None, false));
}

#[test]
fn native_http3_cuts_a_committed_body_with_h3_request_cancelled() {
    // RFC 9114 §8.1: H3_REQUEST_CANCELLED, never a clean FIN.
    assert_eq!(h3_route_deadline_reset_code_for_test(), 0x010c);
}

/// Every native HTTP/3 relay that writes a plain response body carries the
/// route deadline arm, and every trailer-finish site handles its expiry; the
/// retired refusal no longer exists.
#[test]
fn native_http3_relays_enforce_the_route_deadline() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    assert_eq!(
        server
            .matches("optional_sleep_elapsed(route_body_sleep.as_mut())")
            .count(),
        3,
        "the inline, refined, and buffered-request native relays must cut on the route deadline"
    );
    assert_eq!(
        server
            .matches("Err(H3TrailerFinishError::RouteDeadline) =>")
            .count(),
        3,
        "every trailer-finish site must cut on the route deadline"
    );
    assert_eq!(
        bridge
            .matches("optional_sleep_elapsed(route_body_sleep.as_mut())")
            .count(),
        2,
        "both cross-protocol plain relays must cut on the route deadline"
    );
    assert!(
        !server.contains("not supported over HTTP/3"),
        "the native HTTP/3 refusal of timed routes must stay retired"
    );
}

// ── A client that stops reading (PR #5741) ─────────────────────────────────

/// A downstream write the client never grants QUIC flow control for.
fn parked_client_write() -> std::future::Pending<Result<(), &'static str>> {
    std::future::pending()
}

/// A client that stops reading parks every relay write in QUIC flow control,
/// so the relay never returns to its own route deadline arm. The shared write
/// seam races the route body deadline itself: the parked write is cut exactly
/// at the deadline, and a route expiry is not an authorization termination.
#[tokio::test(start_paused = true)]
async fn a_parked_h3_response_write_is_cut_at_the_route_deadline() {
    let started = Instant::now();
    let route_deadline = started + Duration::from_millis(300);
    let latch = StreamAuthTerminationLatch::default();

    let outcome = await_authorized_response_write_for_test(
        None,
        Some(route_deadline),
        &latch,
        parked_client_write(),
    )
    .await;

    assert_eq!(outcome, H3AuthorizedWrite::RouteDeadlineExceeded);
    assert_eq!(Instant::now() - started, Duration::from_millis(300));
    assert_eq!(
        latch.observed(),
        None,
        "a route cut must not record an authorization termination"
    );
}

/// An already-elapsed route deadline never polls the write, so no frame can
/// reach the client after the route budget is spent.
#[tokio::test(start_paused = true)]
async fn an_elapsed_route_deadline_never_polls_the_response_write() {
    let polled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let write = std::future::poll_fn(move |_cx| {
        flag.store(true, Ordering::SeqCst);
        Poll::Ready(Ok::<(), &'static str>(()))
    });
    let latch = StreamAuthTerminationLatch::default();

    let outcome =
        await_authorized_response_write_for_test(None, Some(Instant::now()), &latch, write).await;

    assert_eq!(outcome, H3AuthorizedWrite::RouteDeadlineExceeded);
    assert!(!polled.load(Ordering::SeqCst));
}

/// The seam races the EARLIER of the authorization plan and the route
/// deadline, attributes the winner from the captured instants, and gives an
/// exact tie to authorization, as every composed bound does.
#[tokio::test(start_paused = true)]
async fn the_response_write_seam_attributes_the_earlier_of_authorization_and_route() {
    let started = Instant::now();
    let plan = |at| StreamAuthDeadline {
        at,
        termination: StreamAuthTermination::CredentialExpired,
    };

    // The route deadline is earlier: a route cut, the latch untouched.
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_response_write_for_test(
        Some(plan(started + Duration::from_secs(5))),
        Some(started + Duration::from_secs(1)),
        &latch,
        parked_client_write(),
    )
    .await;
    assert_eq!(outcome, H3AuthorizedWrite::RouteDeadlineExceeded);
    assert_eq!(Instant::now() - started, Duration::from_secs(1));
    assert_eq!(latch.observed(), None);

    // Authorization is earlier: the authorization terminal, recorded once.
    let started = Instant::now();
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_response_write_for_test(
        Some(plan(started + Duration::from_secs(1))),
        Some(started + Duration::from_secs(5)),
        &latch,
        parked_client_write(),
    )
    .await;
    assert_eq!(
        outcome,
        H3AuthorizedWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(Instant::now() - started, Duration::from_secs(1));
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );

    // An exact tie goes to authorization.
    let started = Instant::now();
    let tie = started + Duration::from_secs(1);
    let latch = StreamAuthTerminationLatch::default();
    let outcome = await_authorized_response_write_for_test(
        Some(plan(tie)),
        Some(tie),
        &latch,
        parked_client_write(),
    )
    .await;
    assert_eq!(
        outcome,
        H3AuthorizedWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
    );
}

/// Without a route deadline or an authorization plan the write is awaited
/// straight through; a ready write lands and a failed one is a disconnect.
#[tokio::test(start_paused = true)]
async fn an_unbounded_response_write_passes_straight_through() {
    let latch = StreamAuthTerminationLatch::default();
    let written = await_authorized_response_write_for_test(
        None,
        None,
        &latch,
        std::future::ready(Ok::<(), &'static str>(())),
    )
    .await;
    assert_eq!(written, H3AuthorizedWrite::Written);
    let failed = await_authorized_response_write_for_test(
        None,
        None,
        &latch,
        std::future::ready(Err::<(), &'static str>("reset")),
    )
    .await;
    assert_eq!(failed, H3AuthorizedWrite::ClientWriteFailed);
}

/// Every write of a relay races the relay's one pinned route timer (#5745)
/// instead of registering a fresh timer per frame: writes before the deadline
/// land, a parked write is cut exactly at it, and a write offered after it is
/// never polled. The seam borrows the timer without resetting it, so the
/// relay's own route arm keeps the same absolute instant.
#[tokio::test(start_paused = true)]
async fn every_relay_write_races_the_relays_pinned_route_timer() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let route_sleep = Some(tokio::time::sleep_until(deadline));
    tokio::pin!(route_sleep);
    let latch = StreamAuthTerminationLatch::default();

    for _ in 0..3 {
        let outcome = await_authorized_response_write_with_route_sleep_for_test(
            None,
            route_sleep.as_mut(),
            &latch,
            std::future::ready(Ok::<(), &'static str>(())),
        )
        .await;
        assert_eq!(outcome, H3AuthorizedWrite::Written);
    }

    let outcome = await_authorized_response_write_with_route_sleep_for_test(
        None,
        route_sleep.as_mut(),
        &latch,
        parked_client_write(),
    )
    .await;
    assert_eq!(outcome, H3AuthorizedWrite::RouteDeadlineExceeded);
    assert_eq!(Instant::now(), deadline);
    assert_eq!(latch.observed(), None);

    let polled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&polled);
    let late_write = std::future::poll_fn(move |_cx| {
        flag.store(true, Ordering::SeqCst);
        Poll::Ready(Ok::<(), &'static str>(()))
    });
    let outcome = await_authorized_response_write_with_route_sleep_for_test(
        None,
        route_sleep.as_mut(),
        &latch,
        late_write,
    )
    .await;
    assert_eq!(outcome, H3AuthorizedWrite::RouteDeadlineExceeded);
    assert!(!polled.load(Ordering::SeqCst));

    let timer = route_sleep
        .as_mut()
        .as_pin_mut()
        .expect("the relay's route timer");
    assert_eq!(
        timer.deadline(),
        deadline,
        "the seam must not reset the timer"
    );
    assert!(timer.is_elapsed());
}

/// An earlier authorization plan still owns a write raced against the pinned
/// route timer, and an exact tie still goes to authorization.
#[tokio::test(start_paused = true)]
async fn the_pinned_route_timer_keeps_authorization_first() {
    let started = Instant::now();
    let plan = |at| StreamAuthDeadline {
        at,
        termination: StreamAuthTermination::CredentialExpired,
    };
    let one = started + Duration::from_secs(1);
    let five = started + Duration::from_secs(5);
    for (auth_at, route_at) in [(one, five), (one, one)] {
        let route_sleep = Some(tokio::time::sleep_until(route_at));
        tokio::pin!(route_sleep);
        let latch = StreamAuthTerminationLatch::default();
        let outcome = await_authorized_response_write_with_route_sleep_for_test(
            Some(plan(auth_at)),
            route_sleep.as_mut(),
            &latch,
            parked_client_write(),
        )
        .await;
        assert_eq!(
            outcome,
            H3AuthorizedWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired)
        );
        assert_eq!(
            latch.observed(),
            Some(StreamAuthTermination::CredentialExpired)
        );
    }
}

/// A response HEADERS write the deadline cancels after its first poll has
/// already handed its frame to the H3 send half (#5745), so the bridge must
/// reset the stream rather than write a second HEADERS; one refused before its
/// first poll has not, and a terminal HEADERS is still legal after it.
#[tokio::test(start_paused = true)]
async fn a_cancelled_head_write_reports_whether_it_reached_the_send_half() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let (expired, offered) =
        await_offered_response_write_for_test(Some(deadline), parked_client_write()).await;
    assert!(expired, "the parked head write must lose to the deadline");
    assert!(
        offered,
        "the parked head write was offered before it was cancelled"
    );

    let (expired, offered) =
        await_offered_response_write_for_test(Some(Instant::now()), parked_client_write()).await;
    assert!(expired);
    assert!(!offered, "an elapsed deadline must not poll the write");

    // The paused clock auto-advanced to `deadline` while the first write was
    // parked, so a write that lands in time needs a deadline still ahead.
    let deadline = Instant::now() + Duration::from_secs(1);
    let ready = std::future::ready(Ok::<(), &'static str>(()));
    let (expired, offered) = await_offered_response_write_for_test(Some(deadline), ready).await;
    assert!(!expired, "a write that lands before its deadline is not cut");
    assert!(offered);
}

/// A native streaming HEADERS write that outlives its bound is the route's cut
/// unless a client RPC deadline was strictly earlier; every other outcome is
/// left alone.
#[test]
fn a_parked_streaming_headers_write_is_attributed_to_the_route_deadline() {
    let attribute = attribute_streaming_headers_deadline_for_test;
    let protocol = H3AuthorizedHeadersWrite::ProtocolDeadlineExceeded;
    let route_cut = H3AuthorizedHeadersWrite::RouteDeadlineExceeded;
    let now = Instant::now();
    let later = now + Duration::from_secs(1);

    assert_eq!(attribute(protocol, None, Some(now)), route_cut);
    assert_eq!(attribute(protocol, Some(later), Some(now)), route_cut);
    assert_eq!(attribute(protocol, Some(now), Some(now)), route_cut);
    assert_eq!(attribute(protocol, Some(now), Some(later)), protocol);
    assert_eq!(attribute(protocol, Some(now), None), protocol);
    for outcome in [
        H3AuthorizedHeadersWrite::Written,
        H3AuthorizedHeadersWrite::ClientWriteFailed,
        H3AuthorizedHeadersWrite::AuthorizationExpired(StreamAuthTermination::CredentialExpired),
    ] {
        assert_eq!(attribute(outcome, None, Some(now)), outcome);
    }
}

/// A native route cut resets with `H3_REQUEST_CANCELLED` BEFORE
/// `abort_committed()`: the first reset code is the one on the wire, so the
/// committed guard's own reset would otherwise replace the route cut's code.
fn assert_route_cancel_precedes_abort(arm: &str, what: &str) {
    let cancel = arm
        .find("cancel_response_stream(")
        .unwrap_or_else(|| panic!("{what}: no H3_REQUEST_CANCELLED reset"));
    let abort = arm
        .find("abort_committed()")
        .unwrap_or_else(|| panic!("{what}: no committed reset"));
    assert!(
        cancel < abort,
        "{what}: H3_REQUEST_CANCELLED must be sent before abort_committed()"
    );
}

/// The source of each match arm that starts with `arm`, up to the next
/// variant of the same enum.
fn match_arms<'a>(source: &'a str, arm: &str, next_variant: &str) -> Vec<&'a str> {
    let mut arms = Vec::new();
    for rest in source.split(arm).skip(1) {
        arms.push(rest.split(next_variant).next().unwrap_or_default());
    }
    arms
}

/// Every write seam of every streaming relay races the route body deadline,
/// not only the relay's idle `select!` arm (PR #5741): HEADERS, DATA,
/// trailers, and FIN, on the native HTTP/3 relays and the bridge. A route
/// expiry there is the relay's own route cut: `H3_REQUEST_CANCELLED`, the
/// `read_write_timeout` body class, and health-neutral accounting.
#[test]
fn native_http3_route_deadline_races_every_parked_client_write() {
    let server = include_str!("../../../src/http3/server.rs");
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");

    // DATA / trailers / FIN: the shared seam, called with the route deadline.
    for (file, source, seams) in [("server", server, 4), ("cross_protocol", bridge, 2)] {
        let calls: Vec<&str> = source
            .split("stream_util::await_authorized_response_write(\n")
            .skip(1)
            .collect();
        assert_eq!(
            calls.len(),
            seams,
            "http3/{file}.rs: update the H3 write-seam parity table"
        );
        for call in calls {
            let args = call.split(".await").next().unwrap_or_default();
            assert!(
                args.contains("route_body_sleep.as_mut(),"),
                "http3/{file}.rs: a write seam does not race the relay's pinned route timer"
            );
        }
        let cuts = match_arms(
            source,
            "H3AuthorizedWrite::RouteDeadlineExceeded =>",
            "H3AuthorizedWrite::",
        );
        assert_eq!(
            cuts.len(),
            seams,
            "http3/{file}.rs: every write seam must handle a route expiry"
        );
        for arm in cuts {
            assert!(
                arm.contains("cancel_response_stream(")
                    || arm.contains("H3TrailerFinishError::RouteDeadline"),
                "http3/{file}.rs: a route expiry on a parked write must cut with \
                 H3_REQUEST_CANCELLED"
            );
            assert!(
                arm.contains("route_deadline_cut = true")
                    || arm.contains("H3TrailerFinishError::RouteDeadline"),
                "http3/{file}.rs: a route expiry on a parked write must stay health-neutral"
            );
            if file == "server" && !arm.contains("H3TrailerFinishError::RouteDeadline") {
                assert_route_cancel_precedes_abort(arm, "http3/server.rs write seam");
            }
        }
    }

    // The trailer/FIN seam reports its route expiry to the relay, which cuts.
    let trailer_cuts = match_arms(
        server,
        "Err(H3TrailerFinishError::RouteDeadline) =>",
        "Err(H3TrailerFinishError::",
    );
    assert_eq!(
        trailer_cuts.len(),
        3,
        "every native relay must cut a trailer/FIN route expiry"
    );
    for arm in trailer_cuts {
        assert!(arm.contains("route_deadline_cut = true"));
        assert_route_cancel_precedes_abort(arm, "http3/server.rs trailer/FIN route cut");
    }

    // Native streaming HEADERS: the shared commit helper, with the route
    // deadline, and a route cut on its expiry.
    let commits: Vec<&str> = server
        .split("commit_authorized_streaming_response_headers(\n")
        .skip(1)
        .collect();
    assert_eq!(commits.len(), 3, "update the HEADERS parity table");
    for commit in commits {
        let args = commit.split(".await").next().unwrap_or_default();
        assert!(args.contains("route_body_deadline,"));
    }
    let header_arms = match_arms(
        server,
        "H3AuthorizedHeadersWrite::RouteDeadlineExceeded =>",
        "H3AuthorizedHeadersWrite::",
    );
    let header_cuts = header_arms
        .iter()
        .filter(|arm| arm.contains("cancel_response_stream("))
        .filter(|arm| arm.contains("route_deadline_cut"))
        .count();
    assert_eq!(
        header_cuts, 3,
        "every native HEADERS route expiry must be a route cut"
    );
    for arm in &header_arms {
        if arm.contains("cancel_response_stream(") {
            assert_route_cancel_precedes_abort(arm, "http3/server.rs HEADERS route cut");
        }
    }

    // Bridge streaming HEADERS: the route deadline is composed into the write
    // bound, and its expiry is the route cut, not the gRPC-Web deadline
    // terminal.
    let dispatch = plain_bridge_dispatch();
    let compose = dispatch
        .find("plain_write_bound = crate::proxy::auth_lifetime::ComposedAuthBound::compose(")
        .expect("the bridge recomposes its HEADERS bound");
    let head_write = dispatch
        .find("send_response_headers(stream, &ctx.method, status, &response_headers)")
        .expect("bridge streaming HEADERS write");
    let head_cut = dispatch
        .find("cut_plain_response_head_at_route_deadline(")
        .expect("bridge HEADERS route cut");
    let grpc_web_terminal = dispatch[head_write..]
        .find("write_plain_grpc_web_client_deadline_without_hooks(")
        .map(|at| head_write + at)
        .expect("gRPC-Web HEADERS deadline terminal");
    assert!(compose < head_write && head_write < head_cut && head_cut < grpc_web_terminal);
    assert!(dispatch[compose..head_write].contains("route_body_deadline"));
    let helper = bridge
        .split("fn cut_plain_response_head_at_route_deadline<S>(")
        .nth(1)
        .expect("bridge HEADERS route cut helper")
        .split("\n}\n")
        .next()
        .unwrap_or_default();
    assert!(helper.contains("cancel_response_stream(stream)"));
    assert!(helper.contains("Some(ErrorClass::DispatchPolicyRejected)"));
    assert!(helper.contains("body_error_class: Some(ErrorClass::ReadWriteTimeout)"));
    assert!(helper.contains("client_disconnected: false"));
}

/// The bridge's buffered writer settles the backend exchange BEFORE its first
/// downstream write, as the native HTTP/3 buffered writer does (PR #5741): the
/// backend outcome and admission are recorded, with the backend's own
/// classification, and the least-connections count is released, so a client
/// that parks the HEADERS or body write in QUIC flow control cannot hold the
/// backend admission permit. No client terminal after it records again.
#[test]
fn the_bridge_buffered_writer_settles_the_backend_before_the_client_write() {
    let buffered = plain_bridge_dispatch()
        .split("if should_buffer_response {")
        .nth(1)
        .expect("bridge buffered writer")
        .split("// Only a live reqwest body can be streamed.")
        .next()
        .expect("bounded bridge buffered writer");
    let first_write = buffered
        .find("send_response_headers_with_framing(")
        .expect("bridge buffered HEADERS write");
    let (before_write, after_write) = buffered.split_at(first_write);

    let outcome = before_write
        .rfind("record_backend_outcome_no_conn_end(")
        .expect("the backend outcome is settled before the client write");
    let admission = before_write
        .rfind("record_cross_protocol_backend_admission_outcome(")
        .expect("admission is settled before the client write");
    let guard = before_write
        .rfind("drop(lb_connection_guard.take());")
        .expect("the least-connections count is released before the client write");
    assert!(outcome < admission && admission < guard);

    // The backend's own classification: passive health takes the served
    // status, the limiter the original backend status, and neither a
    // client-side class.
    let args = |at: usize| before_write[at..].split(");").next().unwrap_or_default();
    let outcome_args = args(outcome);
    assert!(outcome_args.contains("response_status,"));
    assert!(outcome_args.contains("terminal_connection_error,"));
    assert!(outcome_args.contains("terminal_error_class,"));
    assert!(!outcome_args.contains("ErrorClass::"));
    let admission_args = args(admission);
    assert!(admission_args.contains("status,"));
    assert!(!admission_args.contains("response_status"));
    assert!(admission_args.contains("terminal_connection_error,"));
    assert!(admission_args.contains("terminal_error_class,"));
    assert!(!admission_args.contains("ErrorClass::"));

    for record in [
        "record_backend_outcome_no_conn_end(",
        "record_cross_protocol_backend_admission_outcome(",
        "record_cross_protocol_header_write_disconnect(",
        "record_plain_grpc_web_client_deadline_after_backend_response(",
        "backend_admission_permits",
        "lb_connection_guard",
    ] {
        assert!(
            !after_write.contains(record),
            "the buffered client write must not settle the backend again: {record}"
        );
    }
}

/// The cross-protocol HTTP/3 → gRPC bridge re-arms the matched rule's attempt
/// budget for each retry exactly as proxy core's gRPC loop does: charged after
/// every attempt, ended before backoff, and begun before the next attempt.
#[test]
fn native_http3_grpc_bridge_rearms_the_attempt_budget_per_retry() {
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let dispatch = bridge
        .split("async fn dispatch_grpc<S>(")
        .nth(1)
        .expect("dispatch_grpc")
        .split("pub(crate) fn boxed_dispatch_grpc_streaming<'a>(")
        .next()
        .expect("bounded dispatch_grpc");
    let charge = "crate::proxy::charge_grpc_route_attempt_budget_expiry(ctx, &mut result);";
    let first_attempt = dispatch
        .find("proxy_grpc_request_from_bytes(")
        .expect("initial attempt");
    let first_charge = dispatch.find(charge).expect("initial attempt charge");
    assert!(first_attempt < first_charge);

    let retry = &dispatch[first_charge + charge.len()..];
    let retry = &retry[retry.find("if grpc_has_retry").expect("retry loop")..];
    let end = retry
        .find("ctx.end_grpc_route_attempt();")
        .expect("attempt budget ends before backoff");
    let backoff = retry.find("retry_delay(").expect("retry backoff");
    let begin = retry
        .find("ctx.begin_grpc_route_attempt();")
        .expect("fresh budget for the retry");
    let retry_attempt = retry
        .find("proxy_grpc_request_from_bytes(")
        .expect("retry attempt");
    let retry_charge = retry.find(charge).expect("retry attempt charge");
    assert!(end < backoff, "backoff must be bounded by the total alone");
    assert!(backoff < begin && begin < retry_attempt && retry_attempt < retry_charge);

    let streaming = bridge
        .split("pub(crate) async fn dispatch_grpc_streaming(")
        .nth(1)
        .expect("dispatch_grpc_streaming");
    let open = streaming
        .find("proxy_grpc_request_streaming_channel(")
        .expect("streaming attempt");
    let streaming_charge = streaming.find(charge).expect("streaming attempt charge");
    assert!(open < streaming_charge);
}

/// The plain HTTP/3 bridge's source between `dispatch_plain` and
/// `dispatch_grpc`.
fn plain_bridge_dispatch() -> &'static str {
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    bridge
        .split("async fn dispatch_plain<S>(")
        .nth(1)
        .expect("dispatch_plain")
        .split("async fn dispatch_grpc<S>(")
        .next()
        .expect("bounded dispatch_plain")
}

/// A gRPC-Web pass-through call on the plain HTTP/3 bridge carries the matched
/// rule's attempt budget in its RPC deadline. The bridge re-arms it exactly as
/// proxy core does: ended before every retry backoff, begun again at every
/// retry attempt's handoff, and an expiry after the handoff charged to the
/// backend.
#[test]
fn native_http3_plain_bridge_rearms_a_grpc_web_attempt_budget_per_retry() {
    let dispatch = plain_bridge_dispatch();
    let backoff = "let delay = crate::retry::retry_delay(retry_config, attempt);";
    let backoffs: Vec<usize> = dispatch.match_indices(backoff).map(|m| m.0).collect();
    assert_eq!(backoffs.len(), 3, "the mesh and both reqwest retry arms");
    for at in backoffs {
        let end = dispatch[..at]
            .rfind("end_plain_route_attempt(")
            .expect("a retry backoff must end the attempt budget first");
        assert!(
            at - end < 800,
            "every retry backoff must be bounded by the total alone"
        );
    }
    assert_eq!(
        dispatch.matches("begin_plain_route_attempt(").count(),
        2,
        "both the mesh and the reqwest attempt restart the budget at the handoff"
    );
    assert_eq!(
        dispatch.matches("if attempt > 0 {\n").count(),
        2,
        "the first attempt keeps the budget armed when the rule was selected"
    );
    assert_eq!(
        dispatch
            .matches("record_plain_grpc_web_deadline_after_handoff(")
            .count(),
        3,
        "the header wait, the streamed upload, and buffered collection charge a budget expiry"
    );
    assert!(
        dispatch.contains("crate::proxy::charge_generic_grpc_route_attempt_budget_expiry("),
        "a mesh attempt's budget expiry is charged as proxy core charges its mesh retry"
    );
    assert!(
        dispatch.contains(
            "let (mut grpc_web_deadline_at, mut plain_write_bound, mut plain_local_bound) ="
        ),
        "the bridge's bounds must be re-derivable per attempt"
    );
}

/// `after_proxy` runs once per plain-bridge response around a charged gRPC-Web
/// budget expiry (#5744). An expiry before the response head decorates the
/// charged terminal with `after_proxy`; one after `after_proxy` decorated the
/// head carries that head's decorations instead, and the terminal writer then
/// runs only the committed observers (an authorization expiry still takes the
/// charged runner, which polls no hook).
#[test]
fn native_http3_plain_bridge_runs_after_proxy_once_around_a_charged_expiry() {
    let dispatch = plain_bridge_dispatch();
    let after_proxy = dispatch
        .find("run_after_proxy_hooks(plugins, ctx, status, &mut response_headers)")
        .expect("the bridge's after_proxy phase");
    let terminals: Vec<usize> = dispatch
        .match_indices("return write_plain_grpc_web_deadline_after_handoff(")
        .map(|m| m.0)
        .collect();
    assert_eq!(terminals.len(), 3);
    for at in terminals {
        let args = dispatch[at..].split(".await").next().unwrap_or_default();
        let decorated = args.contains("charged,\n") && args.contains("Some(&response_headers),");
        assert_eq!(
            decorated,
            at > after_proxy,
            "only the post-head charged terminal carries the decorated head"
        );
    }

    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let writer = bridge
        .split("async fn write_final_body_reject<S>(")
        .nth(1)
        .expect("write_final_body_reject")
        .split("let http_status = StatusCode::from_u16(parts.status_code)")
        .next()
        .expect("the writer's hook phase");
    assert_eq!(
        writer.matches("after_proxy_hooks_to_").count(),
        2,
        "exactly the standard and the charged after_proxy runners"
    );
    let charged_runner = writer
        .find("} else if hooks == FinalRejectHooks::ChargedBackendDeadline")
        .expect("the charged runner branch");
    assert!(
        writer[charged_runner..].contains("|| ctx.authorization_termination().is_some()"),
        "after a decorated head only an authorization expiry runs after_proxy again"
    );
}

/// A plain-bridge response HEADERS write the deadline cancelled after h3 took
/// its frame is never followed by a second HEADERS (#5745): h3-quinn would fail
/// that write with a connection-level error and close every sibling stream.
/// Both head writes report whether they were offered, and both deadline
/// terminals that write HEADERS reset the stream instead once one was.
#[test]
fn native_http3_plain_bridge_resets_after_an_offered_head_write() {
    let dispatch = plain_bridge_dispatch();
    assert_eq!(
        dispatch
            .matches("stream_util::await_offered_response_write_before_deadline(")
            .count(),
        3,
        "the buffered and the streaming response HEADERS writes, and the buffered body write"
    );
    for terminal in [
        "return write_plain_authorization_expired_terminal(",
        "write_plain_grpc_web_client_deadline_without_hooks(",
    ] {
        let guarded: Vec<bool> = dispatch
            .match_indices(terminal)
            .filter_map(|(at, _)| {
                let head = dispatch[..at].rfind("let (head_write, head_offered) =")?;
                Some(dispatch[head..at].contains("if head_offered {"))
            })
            .collect();
        assert_eq!(
            guarded,
            vec![true, true],
            "`{terminal}` after a head write must first reset an offered head"
        );
    }
}

/// The plain bridge's gRPC-Web client deadline terminal is never appended
/// after a body write the deadline cut after h3 took a frame (#5745): h3-quinn
/// would fail that DATA write with a connection-level error and close every
/// sibling stream. The buffered body write reports whether it was offered, the
/// streaming relays report whether they were cancelled inside a write, and the
/// terminal resets the stream in either case.
#[test]
fn native_http3_plain_bridge_resets_after_a_cut_grpc_web_body_write() {
    let dispatch = plain_bridge_dispatch();
    let buffered = dispatch
        .find("let (body_write, body_offered) =")
        .expect("the buffered body write reports whether it was offered");
    let buffered_terminal = dispatch
        .find("append_plain_grpc_web_client_deadline(stream, ctx, body_offered)")
        .expect("the buffered terminal is told whether the body write was offered");
    assert!(buffered < buffered_terminal);
    let streaming_terminal =
        "append_plain_grpc_web_client_deadline(stream, ctx, response_write_in_flight)";
    assert!(
        dispatch.contains(streaming_terminal),
        "the streaming terminal is told whether the relay was inside a write"
    );
    assert_eq!(
        dispatch.matches("&mut response_write_in_flight,").count(),
        2,
        "both streaming relays report an in-flight write"
    );

    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    assert_eq!(
        bridge
            .matches("stream_util::track_response_write_in_flight(")
            .count(),
        2,
        "every write of both streaming relays is tracked"
    );
    let append = bridge
        .split("async fn append_plain_grpc_web_client_deadline<S>(")
        .nth(1)
        .expect("append_plain_grpc_web_client_deadline")
        .split("\n}\n")
        .next()
        .expect("bounded append_plain_grpc_web_client_deadline");
    let reset = append
        .find("if write_in_flight {")
        .expect("a cut write resets the stream");
    let data = append
        .find("stream.send_data(")
        .expect("the appended terminal");
    assert!(reset < data, "the reset must come before any appended DATA");
    let cut = &append[reset..data];
    assert!(
        cut.contains("abort_response_stream(stream);"),
        "a cut write must be answered with a reset"
    );
    let logged = cut
        .find("insert_grpc_error_metadata(")
        .expect("a cut write still logs DEADLINE_EXCEEDED");
    assert!(
        logged < cut.find("abort_response_stream(stream);").unwrap(),
        "the transaction log records the deadline before the reset"
    );
}

/// A gRPC-Web deadline that cancels an offered response head resets the stream
/// and still records `grpc_status=4` for the transaction log, as the native
/// gRPC head-write abort does.
#[test]
fn native_http3_plain_bridge_logs_the_deadline_for_a_reset_grpc_web_head() {
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let reset = bridge
        .split("fn reset_offered_plain_grpc_web_deadline_head<S>(")
        .nth(1)
        .expect("reset_offered_plain_grpc_web_deadline_head")
        .split("\n}\n")
        .next()
        .expect("bounded reset_offered_plain_grpc_web_deadline_head");
    let logged = reset
        .find("insert_grpc_error_metadata(")
        .expect("the reset records the deadline");
    let head_reset = reset
        .find("reset_offered_plain_head(")
        .expect("the offered head is reset");
    assert!(
        logged < head_reset,
        "the transaction log records the deadline before the reset"
    );
    let recorded = &reset[logged..head_reset];
    assert!(
        recorded.contains("grpc_proxy::grpc_status::DEADLINE_EXCEEDED,")
            && recorded.contains("GATEWAY_DEADLINE_EXCEEDED_MESSAGE,"),
        "the recorded terminal is the gateway's DEADLINE_EXCEEDED"
    );
}

/// A relay write cancelled from outside after its first poll stays marked in
/// flight, so the caller resets instead of appending (#5745); a write that
/// finished, successfully or not, is not in flight.
#[tokio::test(start_paused = true)]
async fn a_relay_write_cut_mid_flight_stays_marked_in_flight() {
    use ferrum_edge::_test_support::track_response_write_in_flight_for_test;

    let mut in_flight = false;
    let cut = tokio::time::timeout(
        Duration::from_secs(1),
        track_response_write_in_flight_for_test(&mut in_flight, parked_client_write()),
    )
    .await;
    assert!(cut.is_err(), "the parked write must be cut from outside");
    assert!(in_flight, "the cut write was inside the send half");

    let mut in_flight = false;
    let ready = std::future::ready(Ok::<(), &'static str>(()));
    let landed = track_response_write_in_flight_for_test(&mut in_flight, ready).await;
    assert_eq!(landed, Ok(()));
    assert!(!in_flight, "a finished write is no longer in flight");

    let mut in_flight = false;
    let failed = std::future::ready(Err::<(), &'static str>("client gone"));
    let failed = track_response_write_in_flight_for_test(&mut in_flight, failed).await;
    assert_eq!(failed, Err("client gone"));
    assert!(!in_flight, "a failed write is no longer in flight");
}

/// The H3 bridge's mesh-egress arm ends a charged gRPC-Web attempt budget
/// before the shared response pipeline, as proxy core does (#5744): the
/// dispatch bounds are re-derived without it, so neither `after_proxy` nor the
/// response write reads the spent budget as the gateway's own deadline.
#[test]
fn native_http3_plain_bridge_mesh_arm_ends_a_charged_attempt_budget() {
    let dispatch = plain_bridge_dispatch();
    let charge = dispatch
        .find("if crate::proxy::charge_generic_grpc_route_attempt_budget_expiry(")
        .expect("the mesh arm acts on whether it charged");
    let retry = dispatch[charge..]
        .find("crate::retry::should_retry(")
        .map(|offset| charge + offset)
        .expect("the mesh arm's retry decision");
    let charged = &dispatch[charge..retry];
    assert!(
        charged.contains("(grpc_web_deadline_at, plain_write_bound, _) =")
            && charged.contains("end_plain_route_attempt("),
        "a charged mesh expiry must end the attempt budget and re-derive the bounds"
    );
    assert!(
        charged.contains("ctx.end_charged_grpc_route_attempt();"),
        "a charged mesh expiry must mark the charged terminal for the shared pipeline"
    );
}

/// A route timeout `504` handed to the plain bridge's shared response pipeline
/// (the mesh arm) mints no session affinity, as on the native path and in proxy
/// core.
#[test]
fn native_http3_plain_bridge_mints_no_affinity_on_a_route_timeout() {
    let dispatch = plain_bridge_dispatch();
    let served = dispatch
        .find("let sticky_served_target = if crate::http3::route_deadline::total_expiry_recorded(")
        .expect("served target gated on the route timeout");
    let reissue = dispatch
        .find("sticky_cookie_reissue_target(")
        .expect("sticky reissue");
    let inject = dispatch
        .find("inject_sticky_cookie_with_deadline_provenance(")
        .expect("sticky injection");
    assert!(served < reissue && reissue < inject);
    let reissue_call = &dispatch[reissue..inject];
    assert!(
        reissue_call.contains("sticky_served_target,")
            && !reissue_call.contains("current_target.as_deref(),"),
        "the reissue must name the gated served target"
    );
}

/// A deferred `before_proxy` pass can re-publish route overrides, so the
/// native HTTP/3 handler re-arms the rule's deadlines after the rebind exactly
/// as proxy core does.
#[test]
fn native_http3_rearms_route_deadlines_after_the_deferred_rebind() {
    let server = include_str!("../../../src/http3/server.rs");
    let arm = "ctx.arm_route_request_deadline(matches!(http_flavor, HttpFlavor::Grpc));";
    assert_eq!(server.matches(arm).count(), 2);
    let rebind = server
        .find("routing_proxy = ctx\n            .apply_route_overrides_with_upstreams(")
        .expect("deferred rebind");
    let rearm = server.rfind(arm).expect("re-arm");
    assert!(
        rebind < rearm,
        "the second arm must follow the deferred rebind"
    );
    assert!(
        !server[rebind..rearm].contains("let destination_rebound"),
        "the re-arm must run right after the overrides are re-applied"
    );
}

/// A route timeout raised while buffering an HTTP/3 upload is logged under its
/// own rejection phase, never a gRPC deadline label.
#[test]
fn native_http3_logs_an_upload_route_timeout_under_its_own_phase() {
    let server = include_str!("../../../src/http3/server.rs");
    assert!(
        server.contains("const H3_ROUTE_UPLOAD_TIMEOUT_REJECTION_PHASE: &str =")
            && server.contains("\"route_request_timeout_h3_upload\";"),
        "a route upload timeout has its own rejection phase"
    );
    let finalize = server
        .split("async fn finalize_h3_upload_deadline_rejection(")
        .nth(1)
        .expect("upload deadline finalizer");
    let route_arm = finalize
        .split("None if route_timeout => {")
        .nth(1)
        .expect("route timeout arm")
        .split("Some(termination) => {")
        .next()
        .expect("bounded route timeout arm");
    assert!(
        route_arm.contains("H3_ROUTE_UPLOAD_TIMEOUT_REJECTION_PHASE,"),
        "the route timeout arm must log its own phase"
    );
    assert!(
        !route_arm.contains("(rejection_phase,"),
        "the caller's gRPC deadline label must not name a route timeout"
    );
}

// ── HTTP/3 advertisement (`Alt-Svc`) ────────────────────────────────────────

// Gateway listener ports clear of every default gateway/admin port.
const TIMED_PORT: u16 = 18_443;
const OTHER_PORT: u16 = 18_444;

fn proxy(id: &str, listen_port: Option<u16>) -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    proxy.listen_port = listen_port;
    proxy
}

fn dispatch_plugin(scope: &str, proxy_id: Option<&str>, rule: Value) -> PluginConfig {
    serde_json::from_value(json!({
        "id": "route-dispatch",
        "plugin_name": "mesh_route_dispatch",
        "scope": scope,
        "proxy_id": proxy_id,
        "config": {"rules": [rule]}
    }))
    .expect("plugin fixture")
}

fn timed_rule() -> Value {
    json!({
        "match": {},
        "destination": {"backend_host": "v1.svc", "backend_port": 8080},
        "request_timeout_ms": 500,
        "attempt_timeout_ms": 200
    })
}

fn config(proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        proxies,
        plugin_configs,
        ..GatewayConfig::default()
    }
}

#[tokio::test]
async fn the_gateway_advertises_http3_where_a_timed_rule_is_served() {
    use ferrum_edge::config::env_config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

    let env_config = EnvConfig {
        enable_http3: true,
        ..Default::default()
    };
    let https_port = env_config.proxy_https_port;
    let timed = config(
        vec![proxy("api", None)],
        vec![dispatch_plugin("proxy", Some("api"), timed_rule())],
    );
    let (state, _) = ProxyState::new(
        timed,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("test proxy state should build");

    // Native HTTP/3 enforces both route timeouts, so a timed rule no longer
    // costs the origin its HTTP/3 advertisement.
    assert!(state.alt_svc_for_frontend_port(Some(https_port)).is_some());
    assert!(state.alt_svc_for_frontend_port(None).is_some());

    // A timed rule scoped to one Gateway listener keeps that listener's
    // advertisement, as well as its sibling's and the global port's.
    let mut scoped = state.config.load_full().as_ref().clone();
    scoped.proxies[0].listen_port = Some(TIMED_PORT);
    scoped.proxies.push(proxy("web", Some(OTHER_PORT)));
    assert_eq!(state.update_config(scoped), ConfigApplyOutcome::Applied);
    state.publish_gateway_h3_alt_svc(&[TIMED_PORT, OTHER_PORT]);
    assert!(state.alt_svc_for_frontend_port(Some(TIMED_PORT)).is_some());
    assert!(state.alt_svc_for_frontend_port(Some(OTHER_PORT)).is_some());
    assert!(state.alt_svc_for_frontend_port(Some(https_port)).is_some());

    // A global instance, which can select its timed rule on any route, does
    // not withhold it either.
    let mut global = state.config.load_full().as_ref().clone();
    global.plugin_configs = vec![dispatch_plugin("global", None, timed_rule())];
    assert_eq!(state.update_config(global), ConfigApplyOutcome::Applied);
    assert!(state.alt_svc_for_frontend_port(Some(TIMED_PORT)).is_some());
    assert!(state.alt_svc_for_frontend_port(None).is_some());
}

// ── gRPC-Web budget forwarding on the plain bridge (#5734) ─────────────────

/// The backend request the HTTP/3 plain bridge builds for one attempt.
fn plain_bridge_request(
    proxy_headers: &[(&str, &str)],
    grpc_deadline_at: Option<Instant>,
) -> reqwest::Request {
    use ferrum_edge::config::env_config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::ProxyState;

    let (state, _) = ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        EnvConfig::default(),
        None,
        None,
    )
    .expect("test proxy state should build");
    let proxy: Proxy = serde_json::from_value(json!({
        "backend_host": "backend.example",
        "backend_port": 443
    }))
    .expect("proxy fixture");
    let headers: std::collections::HashMap<String, String> = proxy_headers
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    h3_plain_bridge_backend_request_for_test(
        &state,
        &proxy,
        &headers,
        "https://backend.example/echo.Echo/Call",
        grpc_deadline_at,
    )
    .expect("request should build")
}

fn grpc_timeout_values(request: &reqwest::Request) -> Vec<&[u8]> {
    request
        .headers()
        .get_all("grpc-timeout")
        .iter()
        .map(|value| value.as_bytes())
        .collect()
}

/// A gRPC-Web pass-through attempt tells the backend its remaining RPC budget
/// in `grpc-timeout`, replacing the client's relative value with a single
/// header, as proxy core's reqwest dispatch does.
#[tokio::test(start_paused = true)]
async fn the_plain_bridge_replaces_grpc_timeout_with_the_remaining_budget() {
    let deadline = Instant::now() + Duration::from_millis(5000);
    let request = plain_bridge_request(
        &[
            ("content-type", "application/grpc-web+proto"),
            ("grpc-timeout", "30S"),
        ],
        Some(deadline),
    );
    assert_eq!(
        grpc_timeout_values(&request),
        vec![&b"5000m"[..]],
        "the backend must be told the remaining budget once, not the client's 30S"
    );
}

/// Without an RPC deadline (a plain request) the client's `grpc-timeout`,
/// like every other forwarded header, passes through untouched.
#[tokio::test]
async fn the_plain_bridge_forwards_a_client_grpc_timeout_without_a_deadline() {
    let request = plain_bridge_request(&[("grpc-timeout", "30S")], None);
    assert_eq!(grpc_timeout_values(&request), vec![&b"30S"[..]]);
}

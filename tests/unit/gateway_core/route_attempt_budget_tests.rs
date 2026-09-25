//! Proxy-core contract for a route rule's per-attempt total budget
//! (`mesh_route_dispatch` `attempt_timeout_ms`, Gateway API
//! `HTTPRoute.rules[].timeouts.backendRequest`, #5646).
//!
//! These run on a paused Tokio clock, so the budget arithmetic is exact and no
//! wall-clock window can flake. They pin:
//!
//! * where the budget starts: an initial attempt at its handoff to the backend
//!   (never during gateway- or client-side work), a retry attempt on its first
//!   poll;
//! * that an expired budget cancels only the attempt, as a retryable
//!   backend-timeout `504`, while the total `request` deadline still wins
//!   whenever it is not later;
//! * that every attempt gets a fresh budget;
//! * that the committed attempt's budget cuts a still-streaming body.
//!
//! Data-plane behavior through the real gateway is covered by
//! `tests/integration/k8s_controller_gateway_status_tests.rs`.

use bytes::Bytes;
use ferrum_edge::_test_support::{
    await_route_attempt_budget_for_test, proxy_body_streaming_for_test,
    proxy_body_with_route_request_deadline_for_test, route_deadline_expiry_response_for_test,
};
use ferrum_edge::config::types::{BackoffStrategy, RetryConfig};
use ferrum_edge::proxy::body::ProxyBodyError;
use ferrum_edge::retry::{ErrorClass, ResponseBody, should_retry};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

const BUDGET: Duration = Duration::from_millis(300);

/// Sets its flag when dropped, standing in for the admission permits, upload,
/// and pooled stream a cancelled backend attempt must release.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// ── Where the budget starts ─────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn a_retry_attempt_budget_starts_on_its_first_poll() {
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(Arc::clone(&dropped));
    let attempt = async move {
        let _guard = guard;
        std::future::pending::<&'static str>().await
    };
    let started = Instant::now();

    let (outcome, armed) = await_route_attempt_budget_for_test(None, BUDGET, None, attempt).await;

    assert_eq!(outcome, Err("attempt_budget"));
    assert_eq!(armed, Some(started + BUDGET));
    assert_eq!(Instant::now().duration_since(started), BUDGET);
    assert!(
        dropped.load(Ordering::SeqCst),
        "cancelling the attempt must drop it, releasing what it held"
    );
}

#[tokio::test(start_paused = true)]
async fn an_initial_attempt_budget_starts_only_at_the_handoff() {
    let handed_to_backend = AtomicBool::new(false);
    // Gateway- and client-side work (a stalled upload being buffered, DNS,
    // admission) takes 500ms before the attempt reaches the backend, which
    // then never answers.
    let attempt = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        handed_to_backend.store(true, Ordering::Relaxed);
        std::future::pending::<&'static str>().await
    };
    let started = Instant::now();

    let (outcome, armed) =
        await_route_attempt_budget_for_test(None, BUDGET, Some(&handed_to_backend), attempt).await;

    // The 500ms before the handoff are not charged to the attempt's budget.
    let handoff = started + Duration::from_millis(500);
    assert_eq!(outcome, Err("attempt_budget"));
    assert_eq!(armed, Some(handoff + BUDGET));
    assert_eq!(Instant::now(), handoff + BUDGET);
}

#[tokio::test(start_paused = true)]
async fn an_attempt_handed_over_and_answered_in_one_poll_still_arms_its_budget() {
    let handed_to_backend = AtomicBool::new(false);
    // A backend that answers the head within the same poll as the handoff: the
    // wrapper never sees the attempt pending, yet the committed attempt's
    // streaming body must still be bounded by the budget.
    let attempt = async {
        handed_to_backend.store(true, Ordering::Relaxed);
        "head"
    };
    let started = Instant::now();

    let (outcome, armed) =
        await_route_attempt_budget_for_test(None, BUDGET, Some(&handed_to_backend), attempt).await;

    assert_eq!(outcome, Ok("head"));
    assert_eq!(armed, Some(started + BUDGET));
}

#[tokio::test(start_paused = true)]
async fn an_attempt_that_never_reaches_a_backend_runs_no_budget() {
    let handed_to_backend = AtomicBool::new(false);
    // Longer than the budget, but answered by the gateway itself (an egress
    // refusal, an admission rejection) without ever handing over.
    let attempt = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        "refused"
    };

    let (outcome, armed) =
        await_route_attempt_budget_for_test(None, BUDGET, Some(&handed_to_backend), attempt).await;

    assert_eq!(outcome, Ok("refused"));
    assert_eq!(armed, None);
}

#[tokio::test(start_paused = true)]
async fn an_attempt_that_answers_inside_its_budget_is_returned_unchanged() {
    let attempt = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "answered"
    };
    let started = Instant::now();

    let (outcome, armed) = await_route_attempt_budget_for_test(None, BUDGET, None, attempt).await;

    assert_eq!(outcome, Ok("answered"));
    // The instant still bounds the answered attempt's streaming body.
    assert_eq!(armed, Some(started + BUDGET));
}

// ── Budget versus the total request deadline ────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_earlier_attempt_budget_ends_only_the_attempt() {
    let started = Instant::now();
    let total = started + Duration::from_secs(1);
    let attempt = std::future::pending::<&'static str>();

    let (outcome, _) =
        await_route_attempt_budget_for_test(Some(total), BUDGET, None, attempt).await;

    assert_eq!(outcome, Err("attempt_budget"));
    assert_eq!(Instant::now(), started + BUDGET);
}

#[tokio::test(start_paused = true)]
async fn the_total_deadline_wins_when_it_is_not_later_than_the_budget() {
    for total_after in [Duration::from_millis(200), BUDGET] {
        let started = Instant::now();
        let total = started + total_after;
        let attempt = std::future::pending::<&'static str>();

        let (outcome, _) =
            await_route_attempt_budget_for_test(Some(total), BUDGET, None, attempt).await;

        // A spent transaction is never retried, so the total deadline's
        // expiry is reported even when both end at the same instant.
        assert_eq!(outcome, Err("in_flight"), "{total_after:?}");
        assert_eq!(Instant::now(), started + total_after);
    }
}

#[tokio::test(start_paused = true)]
async fn a_spent_total_deadline_refuses_the_attempt_before_its_budget_starts() {
    let polled = Arc::new(AtomicBool::new(false));
    let attempt = {
        let polled = Arc::clone(&polled);
        std::future::poll_fn(move |_| {
            polled.store(true, Ordering::SeqCst);
            Poll::Ready("dispatched")
        })
    };

    let (outcome, armed) =
        await_route_attempt_budget_for_test(Some(Instant::now()), BUDGET, None, attempt).await;

    assert_eq!(outcome, Err("not_started"));
    assert_eq!(armed, None);
    assert!(!polled.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn every_attempt_gets_a_fresh_budget() {
    let request_started = Instant::now();
    let (first, _) = await_route_attempt_budget_for_test(
        None,
        BUDGET,
        None,
        std::future::pending::<&'static str>(),
    )
    .await;
    assert_eq!(first, Err("attempt_budget"));

    // Retry backoff, then a retry that answers 250ms after it starts: past
    // the first attempt's budget, and past a budget anchored at the request,
    // but inside its own.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let retry_started = Instant::now();
    let retry = async {
        tokio::time::sleep(Duration::from_millis(250)).await;
        "answered"
    };
    let (second, armed) = await_route_attempt_budget_for_test(None, BUDGET, None, retry).await;

    assert_eq!(second, Ok("answered"));
    assert_eq!(armed, Some(retry_started + BUDGET));
    assert!(Instant::now() > request_started + BUDGET);
}

// ── The terminal an expiry produces ─────────────────────────────────────────

fn buffered(body: &ResponseBody) -> &[u8] {
    match body {
        ResponseBody::Buffered(bytes) => bytes.as_ref(),
        _ => panic!("a route deadline answer is gateway-authored and buffered"),
    }
}

#[test]
fn an_attempt_budget_expiry_is_a_retryable_backend_timeout() {
    let (response, phase) = route_deadline_expiry_response_for_test("attempt_budget", true);
    assert_eq!(response.status_code, 504);
    assert_eq!(buffered(&response.body), br#"{"error":"Backend timeout"}"#);
    assert_eq!(response.error_class, Some(ErrorClass::ReadWriteTimeout));
    assert!(!response.connection_error);
    // No route phase: the transaction is not spent, so the retry planner's
    // loop guard does not stop on it.
    assert_eq!(phase, None);

    let retry = RetryConfig {
        max_retries: 2,
        retryable_status_codes: vec![504],
        retryable_methods: vec!["GET".to_string()],
        backoff: BackoffStrategy::Fixed { delay_ms: 10 },
        retry_on_connect_failure: true,
    };
    assert!(should_retry(&retry, "GET", &response, 0));
    // Replay safety is unchanged: a `POST` that reached the backend is not
    // replayed, and a `504` the rule does not list is not retried.
    assert!(!should_retry(&retry, "POST", &response, 0));
    let unlisted = RetryConfig {
        retryable_status_codes: vec![503],
        ..retry
    };
    assert!(!should_retry(&unlisted, "GET", &response, 0));
}

#[test]
fn a_total_deadline_expiry_still_ends_the_transaction() {
    let (response, phase) = route_deadline_expiry_response_for_test("in_flight", true);
    assert_eq!(response.status_code, 504);
    assert_eq!(buffered(&response.body), br#"{"error":"Request timeout"}"#);
    assert_eq!(phase, Some("dispatch"));

    let (response, phase) = route_deadline_expiry_response_for_test("not_started", false);
    assert_eq!(buffered(&response.body), br#"{"error":"Request timeout"}"#);
    assert_eq!(
        response.error_class,
        Some(ErrorClass::DispatchPolicyRejected)
    );
    assert_eq!(phase, Some("before_dispatch"));
}

// ── The committed attempt's body ────────────────────────────────────────────

/// A backend body that keeps answering: one byte every 100ms, so no idle gap
/// ever trips a per-frame read bound.
struct TrickleBody {
    remaining: usize,
    pause: Pin<Box<tokio::time::Sleep>>,
}

impl TrickleBody {
    fn new(frames: usize) -> Self {
        Self {
            remaining: frames,
            pause: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
        }
    }
}

impl Body for TrickleBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        std::task::ready!(self.pause.as_mut().poll(cx));
        self.remaining -= 1;
        let next = Instant::now() + Duration::from_millis(100);
        self.pause.as_mut().reset(next);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"x")))))
    }
}

#[tokio::test(start_paused = true)]
async fn the_committed_attempt_budget_cuts_a_trickling_body() {
    let started = Instant::now();
    // The attempt was handed over at `started`; its head arrived at once.
    let armed = started + Duration::from_millis(350);
    let body = proxy_body_streaming_for_test(Box::pin(TrickleBody::new(20)));
    let mut body = Box::pin(proxy_body_with_route_request_deadline_for_test(body, armed));

    let mut data_frames = 0;
    let terminal = loop {
        match body.frame().await {
            Some(Ok(frame)) if frame.is_data() => data_frames += 1,
            Some(Ok(_)) => {}
            Some(Err(error)) => break Some(error),
            None => break None,
        }
    };

    assert!(
        terminal.is_some(),
        "a body the budget cuts must end with an error, never a clean end of stream"
    );
    assert!(
        (3..20).contains(&data_frames),
        "the bytes that arrived inside the budget are forwarded: {data_frames}"
    );
    assert_eq!(Instant::now(), armed);
}

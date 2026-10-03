//! Backend connection checkout and request handoff are held to the admitted
//! request's authorization lifetime (GHSA-xcg4-wj3x-gjj2).
//!
//! A pooled HTTP/1.1 (or direct-H2) dispatch acquires its connection before it
//! hands the request over, and hyper enqueues the request on the connection
//! task synchronously, before any deadline wrapper around the response future
//! is first polled. These paused-clock tests drive the production composer,
//! checkout bound, and fail-closed handoff gate with a controlled checkout
//! future and a fake send adapter, and prove:
//!
//! * expiry during a stalled checkout cancels the checkout at the
//!   authorization instant and nothing is ever enqueued;
//! * a bound that elapses after the checkout completed refuses the handoff
//!   without calling the send adapter;
//! * the idle-race replay checkout is held to the same absolute instant as
//!   the first;
//! * the earlier deadline keeps its attribution, however late the wait is
//!   observed, and an authorization tie is the authorization decision;
//! * an already-elapsed bound never polls the checkout at all.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum_edge::_test_support::{
    BackendHandoffBoundSourceForTest, BackendHandoffGateOutcomeForTest,
    attribute_dispatch_phase_bound_for_test, await_backend_checkout_bound_for_test,
    backend_handoff_gate_for_test, compose_backend_handoff_bound_for_test,
    compose_dispatch_phase_bound_for_test, direct_h2_handoff_gate_for_test,
};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
};

type Plan = (
    StreamAuthDeadline,
    StreamAuthProtocolFamily,
    ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch,
);

fn plan_after(after: Duration) -> Plan {
    (
        StreamAuthDeadline {
            at: tokio::time::Instant::now() + after,
            termination: StreamAuthTermination::CredentialExpired,
        },
        StreamAuthProtocolFamily::Http,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    )
}

/// A checkout that never completes, records whether it was ever polled, and
/// records when it is dropped (cancelled).
struct StalledCheckout {
    polled: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Future for StalledCheckout {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.polled.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

impl Drop for StalledCheckout {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn stalled_checkout() -> (StalledCheckout, Arc<AtomicBool>, Arc<AtomicBool>) {
    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    (
        StalledCheckout {
            polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped),
        },
        polled,
        dropped,
    )
}

#[tokio::test(start_paused = true)]
async fn expiry_during_a_stalled_checkout_cancels_it_and_enqueues_nothing() {
    let start = tokio::time::Instant::now();
    // The direct HTTP/1.1 shape: a far response-header read bound, no client
    // RPC deadline, and a credential that expires mid-checkout.
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound =
        compose_backend_handoff_bound_for_test(Some(start + Duration::from_secs(30)), &dispatch);
    assert_eq!(bound.at(), Some(start + Duration::from_millis(100)));
    assert_eq!(
        bound.source(),
        BackendHandoffBoundSourceForTest::Authorization
    );

    let (checkout, polled, dropped) = stalled_checkout();
    let outcome = await_backend_checkout_bound_for_test(&bound, checkout).await;

    assert_eq!(
        outcome,
        Err(BackendHandoffBoundSourceForTest::Authorization),
        "a stalled checkout must end at the authorization deadline, not the read bound"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100),
        "the checkout is cancelled at the authorization instant exactly"
    );
    assert!(polled.load(Ordering::SeqCst));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the stalled checkout future must be dropped (cancelled) when the bound fires"
    );
    // The dispatch returns from the checkout arm and never reaches the
    // handoff, so nothing is enqueued: the backend sees zero requests.
    // Attributed to the gateway's own security decision, exactly once.
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&dispatch, Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn a_bound_that_elapses_after_checkout_refuses_the_handoff_before_enqueue() {
    let plan = plan_after(Duration::from_millis(100));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);

    // The checkout completes well inside the bound...
    let connection = await_backend_checkout_bound_for_test(&bound, async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        "connection"
    })
    .await;
    assert_eq!(connection, Ok("connection"));

    // ...and the gate still lets the handoff through while time remains.
    let enqueued = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let outcome = backend_handoff_gate_for_test(
        &bound,
        "connection",
        |_| {
            released.fetch_add(1, Ordering::SeqCst);
        },
        |lease| {
            enqueued.fetch_add(1, Ordering::SeqCst);
            lease
        },
    );
    assert_eq!(
        outcome,
        BackendHandoffGateOutcomeForTest::Enqueued("connection")
    );
    assert_eq!(enqueued.load(Ordering::SeqCst), 1);
    assert_eq!(released.load(Ordering::SeqCst), 0);

    // Time passes between a completed checkout and the handoff (request head
    // assembly, pump binding). Once the bound has elapsed, the gate refuses
    // WITHOUT calling the send adapter, so nothing reaches the connection
    // driver, and the untouched lease goes back to its release path.
    tokio::time::advance(Duration::from_millis(60)).await;
    let refused = backend_handoff_gate_for_test(
        &bound,
        "connection",
        |_| {
            released.fetch_add(1, Ordering::SeqCst);
        },
        |lease| {
            enqueued.fetch_add(1, Ordering::SeqCst);
            lease
        },
    );
    assert_eq!(
        refused,
        BackendHandoffGateOutcomeForTest::Refused(BackendHandoffBoundSourceForTest::Authorization),
        "an exact-deadline handoff is refused: the gate is inclusive"
    );
    assert_eq!(
        enqueued.load(Ordering::SeqCst),
        1,
        "a refused handoff must never reach the send adapter"
    );
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "the refused lease is released exactly once"
    );
}

#[tokio::test(start_paused = true)]
async fn the_replay_checkout_is_held_to_the_same_absolute_instant() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    // Composed ONCE per dispatch, as production does before the first checkout.
    let bound =
        compose_backend_handoff_bound_for_test(Some(start + Duration::from_secs(5)), &dispatch);

    // First checkout: a reused idle connection, handed out after 30ms.
    let first = await_backend_checkout_bound_for_test(&bound, async {
        tokio::time::sleep(Duration::from_millis(30)).await;
    })
    .await;
    assert_eq!(first, Ok(()));

    // The idle-race replay dials a fresh connection that stalls. It must end
    // at the ORIGINAL authorization instant, not 100ms after the replay began.
    let (replay, _, dropped) = stalled_checkout();
    let replay_outcome = await_backend_checkout_bound_for_test(&bound, replay).await;
    assert_eq!(
        replay_outcome,
        Err(BackendHandoffBoundSourceForTest::Authorization)
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100),
        "a replay must not re-arm the authorization lifetime"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn an_earlier_response_header_bound_keeps_its_attribution_under_late_observation() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(200));
    let latch = plan.2.clone();
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound =
        compose_backend_handoff_bound_for_test(Some(start + Duration::from_millis(50)), &dispatch);
    assert_eq!(
        bound.source(),
        BackendHandoffBoundSourceForTest::ResponseHeader
    );

    // The dispatch is not polled until after BOTH instants have passed.
    tokio::time::advance(Duration::from_millis(500)).await;
    let (checkout, polled, _) = stalled_checkout();
    let outcome = await_backend_checkout_bound_for_test(&bound, checkout).await;
    assert_eq!(
        outcome,
        Err(BackendHandoffBoundSourceForTest::ResponseHeader),
        "the strictly earlier operator bound keeps its own terminal"
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an already-elapsed bound must refuse without polling the checkout"
    );
    assert_eq!(
        backend_handoff_gate_for_test(&bound, (), drop, |()| ()),
        BackendHandoffGateOutcomeForTest::Refused(BackendHandoffBoundSourceForTest::ResponseHeader)
    );
    assert_eq!(latch.observed(), None, "no authorization expiry is latched");
}

#[tokio::test(start_paused = true)]
async fn an_earlier_authorization_bound_wins_over_a_later_response_header_bound() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(50));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound =
        compose_backend_handoff_bound_for_test(Some(start + Duration::from_millis(200)), &dispatch);
    tokio::time::advance(Duration::from_millis(500)).await;
    let (checkout, polled, _) = stalled_checkout();
    assert_eq!(
        await_backend_checkout_bound_for_test(&bound, checkout).await,
        Err(BackendHandoffBoundSourceForTest::Authorization),
        "late observation must not hand an authorization expiry to the backend's 504"
    );
    assert!(!polled.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn an_earlier_client_rpc_deadline_keeps_its_attribution() {
    let plan = plan_after(Duration::from_millis(200));
    let latch = plan.2.clone();
    // The client RPC deadline (`grpc-timeout`) is the protocol side of the
    // composed dispatch bound on the direct HTTP/1.1 and direct-H2 paths.
    let dispatch = compose_dispatch_phase_bound_for_test(Some(50), Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    let (checkout, _, _) = stalled_checkout();
    assert_eq!(
        await_backend_checkout_bound_for_test(&bound, checkout).await,
        Err(BackendHandoffBoundSourceForTest::PhaseProtocol)
    );
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&dispatch, Some(&plan)),
        None
    );
    assert_eq!(latch.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn ties_are_decided_by_composition() {
    let start = tokio::time::Instant::now();
    let at = start + Duration::from_millis(100);

    // Authorization ties the response-header bound: the response-header bound
    // (a `504`), exactly as the reqwest dispatch's nested waits attribute it,
    // so `FERRUM_POOL_HTTP1_DIRECT` cannot change the terminal at the boundary.
    let plan = plan_after(Duration::from_millis(100));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(Some(at), &dispatch);
    assert_eq!(bound.at(), Some(at));
    assert_eq!(
        bound.source(),
        BackendHandoffBoundSourceForTest::ResponseHeader
    );
    // Without a response-header bound (Unix, HBONE, direct-H2), the
    // authorization lifetime still wins a tie with the protocol bound.
    let tied = compose_dispatch_phase_bound_for_test(Some(100), Some(&plan));
    assert_eq!(
        compose_backend_handoff_bound_for_test(None, &tied).source(),
        BackendHandoffBoundSourceForTest::Authorization
    );

    // The client RPC deadline ties the response-header bound: the header
    // bound, as the nested waits this composition replaced ordered them.
    let unauthenticated = compose_dispatch_phase_bound_for_test(Some(100), None);
    let bound = compose_backend_handoff_bound_for_test(Some(at), &unauthenticated);
    assert_eq!(bound.at(), Some(at));
    assert_eq!(
        bound.source(),
        BackendHandoffBoundSourceForTest::ResponseHeader
    );
}

#[tokio::test(start_paused = true)]
async fn an_unbounded_unauthenticated_checkout_is_never_cut_short() {
    let dispatch = compose_dispatch_phase_bound_for_test(None, None);
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    assert_eq!(bound.at(), None);

    let connection = await_backend_checkout_bound_for_test(&bound, async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "connection"
    })
    .await;
    assert_eq!(connection, Ok("connection"));
    assert_eq!(
        backend_handoff_gate_for_test(&bound, "lease", drop, |_| "sent"),
        BackendHandoffGateOutcomeForTest::Enqueued("sent")
    );
}

#[tokio::test(start_paused = true)]
async fn an_already_expired_credential_never_starts_a_checkout() {
    let plan = plan_after(Duration::from_millis(10));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    tokio::time::advance(Duration::from_millis(10)).await;

    let (checkout, polled, dropped) = stalled_checkout();
    assert_eq!(
        await_backend_checkout_bound_for_test(&bound, checkout).await,
        Err(BackendHandoffBoundSourceForTest::Authorization)
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "cancellation wins before admission: an elapsed bound never polls the checkout"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_ready_checkout_completes_without_waiting_on_the_bound() {
    // The hot path: a pooled connection is ready on the first poll. The bound
    // still has time left, so the checkout completes at once — it is polled
    // BEFORE any timer is armed — and the handoff proceeds.
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_secs(30));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    let checkout = await_backend_checkout_bound_for_test(&bound, std::future::ready("pooled"));
    assert_eq!(checkout.await, Ok("pooled"));
    assert_eq!(tokio::time::Instant::now(), start);
    assert_eq!(
        backend_handoff_gate_for_test(&bound, "pooled", drop, |lease| lease),
        BackendHandoffGateOutcomeForTest::Enqueued("pooled")
    );
}

#[tokio::test(start_paused = true)]
async fn a_checkout_ready_at_the_instant_is_refused_by_the_handoff_gate() {
    // The checkout is polled before the timer on every wake, so a connection
    // that becomes ready at exactly the authorization instant is handed back.
    // The synchronous handoff gate is the backstop: it refuses that lease
    // before anything is enqueued and releases it untouched.
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    let checkout = await_backend_checkout_bound_for_test(&bound, async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        "dialed"
    })
    .await;
    assert_eq!(checkout, Ok("dialed"));
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100)
    );

    let released = Arc::new(AtomicUsize::new(0));
    let enqueued = Arc::new(AtomicUsize::new(0));
    let outcome = backend_handoff_gate_for_test(
        &bound,
        "dialed",
        |_| {
            released.fetch_add(1, Ordering::SeqCst);
        },
        |_| {
            enqueued.fetch_add(1, Ordering::SeqCst);
        },
    );
    assert_eq!(
        outcome,
        BackendHandoffGateOutcomeForTest::Refused(BackendHandoffBoundSourceForTest::Authorization)
    );
    assert_eq!(enqueued.load(Ordering::SeqCst), 0, "nothing is enqueued");
    assert_eq!(released.load(Ordering::SeqCst), 1, "the lease is released");
    assert_eq!(
        attribute_dispatch_phase_bound_for_test(&dispatch, Some(&plan)),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn the_replay_checkout_ready_after_the_instant_is_refused_by_the_same_gate() {
    // The idle-race replay: the first checkout completed inside the bound, the
    // replay dial completes only after the ORIGINAL authorization instant. The
    // replay is held to that same instant, so its handoff is refused.
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
    let first = await_backend_checkout_bound_for_test(&bound, std::future::ready("reused")).await;
    assert_eq!(first, Ok("reused"));
    tokio::time::advance(Duration::from_millis(60)).await;

    let (replay, _, dropped) = stalled_checkout();
    assert_eq!(
        await_backend_checkout_bound_for_test(&bound, replay).await,
        Err(BackendHandoffBoundSourceForTest::Authorization)
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100),
        "the replay ends at the original instant, 40ms after it began"
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        backend_handoff_gate_for_test(&bound, "replayed", drop, |lease| lease),
        BackendHandoffGateOutcomeForTest::Refused(BackendHandoffBoundSourceForTest::Authorization)
    );
}

// --- The direct-H2 handoff gate (`proxy_to_backend_http2`) ------------------

#[tokio::test(start_paused = true)]
async fn the_direct_h2_gate_lets_a_live_request_through() {
    assert_eq!(direct_h2_handoff_gate_for_test(None, None), None);
    let plan = plan_after(Duration::from_secs(1));
    let client_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(2));
    assert_eq!(
        direct_h2_handoff_gate_for_test(client_deadline, Some(&plan)),
        None
    );
    assert_eq!(plan.2.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn the_direct_h2_gate_refuses_an_expired_credential_before_send_request() {
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();
    tokio::time::advance(Duration::from_millis(100)).await;
    let refusal = direct_h2_handoff_gate_for_test(None, Some(&plan));
    let (source, status, grpc_status) = refusal.expect("an expired plan is refused");
    assert_eq!(source, BackendHandoffBoundSourceForTest::Authorization);
    assert_eq!(status, 401, "the health-neutral authorization placeholder");
    assert_eq!(grpc_status, None);
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the expiry is latched exactly once for the request"
    );
}

#[tokio::test(start_paused = true)]
async fn the_direct_h2_gate_keeps_an_earlier_client_deadline_attribution() {
    let plan = plan_after(Duration::from_millis(500));
    let latch = plan.2.clone();
    let client_deadline = Some(tokio::time::Instant::now() + Duration::from_millis(50));
    tokio::time::advance(Duration::from_secs(1)).await;
    let refusal = direct_h2_handoff_gate_for_test(client_deadline, Some(&plan));
    let (source, status, grpc_status) = refusal.expect("an elapsed client deadline is refused");
    assert_eq!(source, BackendHandoffBoundSourceForTest::PhaseProtocol);
    assert_eq!(status, 200, "gRPC deadline errors ride HTTP 200");
    assert_eq!(grpc_status.as_deref(), Some("4"), "DEADLINE_EXCEEDED");
    assert_eq!(latch.observed(), None, "nothing is latched");
}

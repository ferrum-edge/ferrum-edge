//! Native gRPC dispatch is held to the admitted request's authorization
//! lifetime until the backend response head arrives (GHSA-xcg4-wj3x-gjj2,
//! native gRPC sibling; part of #5990).
//!
//! `proxy_grpc_request_core`, and the fully-streamed dispatch beside it,
//! acquires a sender, hands the request to hyper, and then waits for the
//! response headers. hyper enqueues the request on the connection task on the
//! first poll of the send future, synchronously, before any wait on the
//! response is polled. These paused-clock tests drive the production dispatch
//! bounds, handoff gate, and header-wait bound with controlled futures and a
//! fake send adapter, and prove:
//!
//! * expiry during a stalled sender acquisition ends it at the authorization
//!   instant, and nothing is ever enqueued;
//! * a bound that elapses after the acquisition refuses the handoff without
//!   calling the send adapter;
//! * the response-header wait ends at the authorization instant when the
//!   credential expires first, and keeps its own protocol terminal otherwise;
//! * the earlier deadline keeps its attribution however late the dispatch is
//!   observed, and an authorization expiry is latched once and is
//!   health-neutral;
//! * a retry composes the same absolute instants and cannot re-arm them;
//! * an already-available sender completes without waiting on the bound;
//! * an unauthenticated dispatch is unbounded.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum_edge::_test_support::{
    await_native_grpc_acquisition_for_test, await_native_grpc_header_wait_for_test,
    compose_native_grpc_dispatch_bounds_for_test, native_grpc_handoff_gate_for_test,
};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
};
use ferrum_edge::proxy::grpc_proxy::{GrpcProxyError, GrpcTimeoutKind};
use ferrum_edge::retry::{ErrorClass, classify_grpc_proxy_error};

/// The `ClientDeadlineExceeded` message for a client RPC deadline that
/// elapsed during the sender acquisition.
const ACQUISITION_DEADLINE_MESSAGE: &str =
    "gRPC deadline exceeded during backend connection acquisition";

/// The `ClientDeadlineExceeded` message for a client RPC deadline that had
/// elapsed when the handoff gate ran.
const HANDOFF_DEADLINE_MESSAGE: &str =
    "gRPC deadline exceeded before the request was handed to the backend";

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
        StreamAuthProtocolFamily::Grpc,
        ferrum_edge::proxy::auth_lifetime::StreamAuthTerminationLatch::default(),
    )
}

/// A sender acquisition (or response-header wait) that never completes,
/// records whether it was ever polled, and records when it is dropped.
struct Stalled {
    polled: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl Future for Stalled {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.polled.store(true, Ordering::SeqCst);
        Poll::Pending
    }
}

impl Drop for Stalled {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn stalled() -> (Stalled, Arc<AtomicBool>, Arc<AtomicBool>) {
    let polled = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    (
        Stalled {
            polled: Arc::clone(&polled),
            dropped: Arc::clone(&dropped),
        },
        polled,
        dropped,
    )
}

/// The termination class of a dispatch that the health-neutral authorization
/// error ended BEFORE its request was handed to the connection, or `None` for
/// any other outcome.
fn expired_class<T>(outcome: Result<T, GrpcProxyError>) -> Option<StreamAuthTermination> {
    match outcome {
        Err(GrpcProxyError::AuthorizationExpired {
            termination,
            handed_to_backend: false,
        }) => Some(termination),
        _ => None,
    }
}

/// The termination class of a dispatch that the authorization error ended
/// AFTER its request passed the handoff gate (the response-header wait).
fn expired_after_handoff<T>(outcome: Result<T, GrpcProxyError>) -> Option<StreamAuthTermination> {
    match outcome {
        Err(GrpcProxyError::AuthorizationExpired {
            termination,
            handed_to_backend: true,
        }) => Some(termination),
        _ => None,
    }
}

#[tokio::test(start_paused = true)]
async fn expiry_during_a_stalled_sender_acquisition_ends_it_and_enqueues_nothing() {
    let start = tokio::time::Instant::now();
    // No client `grpc-timeout`: before the fix only the pool's own connect
    // budget bounded the acquisition.
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();
    let bounds = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));

    let (acquisition, polled, dropped) = stalled();
    let outcome = await_native_grpc_acquisition_for_test(&bounds, Some(&plan), acquisition).await;

    assert_eq!(
        expired_class(outcome),
        Some(StreamAuthTermination::CredentialExpired),
        "a stalled acquisition must end with the health-neutral authorization error"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100),
        "the acquisition is cancelled at the authorization instant exactly"
    );
    assert!(polled.load(Ordering::SeqCst));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the stalled acquisition must be dropped (cancelled) when the bound fires"
    );
    // The dispatch returns from the acquisition and never reaches the handoff,
    // so nothing is enqueued: the backend sees zero requests. The expiry is
    // latched exactly once for the request.
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_client_deadline_keeps_its_pre_wire_deadline_terminal() {
    let plan = plan_after(Duration::from_millis(200));
    let latch = plan.2.clone();
    let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(50), Some(&plan));

    let (acquisition, _, dropped) = stalled();
    let outcome = await_native_grpc_acquisition_for_test(&bounds, Some(&plan), acquisition).await;

    assert!(
        matches!(
            &outcome,
            Err(GrpcProxyError::ClientDeadlineExceeded(message))
                if message == ACQUISITION_DEADLINE_MESSAGE
        ),
        "an earlier client RPC deadline keeps its own pre-wire terminal; got {outcome:?}"
    );
    assert!(dropped.load(Ordering::SeqCst));
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(latch.observed(), None, "no authorization expiry is latched");
}

#[tokio::test(start_paused = true)]
async fn an_already_expired_credential_never_starts_an_acquisition() {
    // The credential is the earlier bound. The dispatch is not polled until
    // both instants have passed, and it must still be attributed to the
    // credential, never to the later client deadline.
    let plan = plan_after(Duration::from_millis(50));
    let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(200), Some(&plan));
    tokio::time::advance(Duration::from_millis(500)).await;

    let (acquisition, polled, dropped) = stalled();
    let outcome = await_native_grpc_acquisition_for_test(&bounds, Some(&plan), acquisition).await;

    assert_eq!(
        expired_class(outcome),
        Some(StreamAuthTermination::CredentialExpired),
        "late observation must not hand an authorization expiry to the client deadline"
    );
    assert!(
        !polled.load(Ordering::SeqCst),
        "an elapsed bound must refuse without polling the acquisition"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_bound_that_elapses_after_acquisition_refuses_the_handoff_before_enqueue() {
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();
    let bounds = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));

    // The sender is acquired well inside the bound...
    let sender = await_native_grpc_acquisition_for_test(&bounds, Some(&plan), async {
        tokio::time::sleep(Duration::from_millis(40)).await;
        "sender"
    })
    .await;
    assert!(matches!(sender, Ok("sender")));

    // ...and the gate lets the handoff through while time remains.
    let enqueued = AtomicUsize::new(0);
    let admitted = native_grpc_handoff_gate_for_test(&bounds, Some(&plan), || {
        enqueued.fetch_add(1, Ordering::SeqCst);
    });
    assert!(admitted.is_ok());
    assert_eq!(enqueued.load(Ordering::SeqCst), 1);

    // Time passes between the acquisition and the handoff (request assembly,
    // pump arming). Once the bound has elapsed, the gate refuses WITHOUT
    // calling the send adapter, so nothing reaches the connection.
    tokio::time::advance(Duration::from_millis(60)).await;
    let refused = native_grpc_handoff_gate_for_test(&bounds, Some(&plan), || {
        enqueued.fetch_add(1, Ordering::SeqCst);
    });
    assert_eq!(
        expired_class(refused),
        Some(StreamAuthTermination::CredentialExpired),
        "an exact-deadline handoff is refused: the gate is inclusive"
    );
    assert_eq!(
        enqueued.load(Ordering::SeqCst),
        1,
        "a refused handoff must never reach the send adapter"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn the_handoff_gate_refuses_an_elapsed_client_deadline_as_pre_wire() {
    let plan = plan_after(Duration::from_millis(200));
    let latch = plan.2.clone();
    let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(50), Some(&plan));
    tokio::time::advance(Duration::from_millis(50)).await;

    let enqueued = AtomicUsize::new(0);
    let refused = native_grpc_handoff_gate_for_test(&bounds, Some(&plan), || {
        enqueued.fetch_add(1, Ordering::SeqCst);
    });
    assert!(
        matches!(
            &refused,
            Err(GrpcProxyError::ClientDeadlineExceeded(message))
                if message == HANDOFF_DEADLINE_MESSAGE
        ),
        "a client deadline that elapsed before the handoff is refused pre-wire; got {refused:?}"
    );
    assert_eq!(enqueued.load(Ordering::SeqCst), 0);
    assert_eq!(latch.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn the_response_header_wait_ends_at_the_authorization_instant() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));
    let latch = plan.2.clone();

    // The wait's own operator read bound is far later than the credential.
    let (wait, polled, dropped) = stalled();
    let outcome =
        await_native_grpc_header_wait_for_test(Some(30_000), Some(&plan), async { Ok(wait.await) })
            .await;

    assert_eq!(
        expired_after_handoff(outcome),
        Some(StreamAuthTermination::CredentialExpired),
        "a backend that withholds its response head cannot outlive the credential"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100)
    );
    assert!(polled.load(Ordering::SeqCst));
    assert!(
        dropped.load(Ordering::SeqCst),
        "the header wait (and the request it carries) must be dropped at the bound"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn an_earlier_header_wait_bound_keeps_its_own_terminal() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(200));
    let latch = plan.2.clone();

    // The protocol shape itself: the operator read timeout ends the wait with
    // its own typed backend timeout.
    let outcome = await_native_grpc_header_wait_for_test(Some(50), Some(&plan), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Err::<(), _>(GrpcProxyError::BackendTimeout {
            kind: GrpcTimeoutKind::Read,
            message: "Read timeout after 50ms".to_string(),
        })
    })
    .await;

    assert!(
        matches!(&outcome, Err(GrpcProxyError::BackendTimeout { .. })),
        "the strictly earlier read bound keeps its own terminal; got {outcome:?}"
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(50)
    );
    tokio::time::advance(Duration::from_millis(500)).await;
    assert_eq!(latch.observed(), None, "no authorization expiry is latched");
}

#[tokio::test(start_paused = true)]
async fn a_retry_attempt_is_held_to_the_same_absolute_instant() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));

    // The first attempt acquires a sender after 60ms (and then fails
    // pre-wire, which is what sends the dispatch into a retry).
    let first = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));
    let attempt = await_native_grpc_acquisition_for_test(&first, Some(&plan), async {
        tokio::time::sleep(Duration::from_millis(60)).await;
    })
    .await;
    assert!(attempt.is_ok());

    // The retry composes its bounds again from the SAME receipt-anchored plan,
    // exactly as each production attempt does. Its stalled acquisition must
    // end at the ORIGINAL authorization instant, not 100ms after the retry.
    let retry = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));
    let (acquisition, _, dropped) = stalled();
    let outcome = await_native_grpc_acquisition_for_test(&retry, Some(&plan), acquisition).await;

    assert_eq!(
        expired_class(outcome),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(100),
        "a retry must not re-arm the authorization lifetime"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn an_available_sender_completes_without_waiting_on_the_bound() {
    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(100));
    let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(50), Some(&plan));

    // A pooled sender that is ready on its first poll.
    let polls = AtomicUsize::new(0);
    let pooled = std::future::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready("pooled")
    });
    let sender = await_native_grpc_acquisition_for_test(&bounds, Some(&plan), pooled).await;

    assert!(matches!(sender, Ok("pooled")));
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(tokio::time::Instant::now(), start);
}

/// A pooled sender that is ready on its first poll must complete without
/// arming any timer: the authenticated success path takes no timer-wheel lock.
/// The runtime here has NO time driver, so constructing or polling any timer
/// panics. A combinator that arms its bound before polling the acquisition
/// (`await_deadline_first`, `timeout_at`) fails this test.
#[test]
fn a_ready_sender_never_arms_a_timer() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime without a time driver");
    let sender = runtime.block_on(async {
        let plan = plan_after(Duration::from_secs(60));
        let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(30_000), Some(&plan));
        let pooled = std::future::ready("pooled");
        await_native_grpc_acquisition_for_test(&bounds, Some(&plan), pooled).await
    });
    assert!(matches!(sender, Ok("pooled")));
}

#[tokio::test(start_paused = true)]
async fn unauthenticated_dispatch_is_never_cut_short() {
    let bounds = compose_native_grpc_dispatch_bounds_for_test(None, None);
    let sender = await_native_grpc_acquisition_for_test(&bounds, None, async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        "sender"
    })
    .await;
    assert!(matches!(sender, Ok("sender")));
    let sent = native_grpc_handoff_gate_for_test(&bounds, None, || "sent");
    assert!(matches!(sent, Ok("sent")));
    let headers = await_native_grpc_header_wait_for_test(None, None, async {
        tokio::time::sleep(Duration::from_secs(3_600)).await;
        Ok("headers")
    })
    .await;
    assert!(matches!(headers, Ok("headers")));
}

#[test]
fn an_authorization_expiry_is_health_neutral_and_never_a_deadline() {
    let expired = GrpcProxyError::AuthorizationExpired {
        termination: StreamAuthTermination::CredentialExpired,
        handed_to_backend: false,
    };
    // `ClientDisconnect` is never retried and trains no backend health, the
    // same class the H1/H2 authorization placeholder carries.
    assert_eq!(
        classify_grpc_proxy_error(&expired),
        ErrorClass::ClientDisconnect
    );
    assert_eq!(expired.to_string(), "credential expired");
    let lifetime = GrpcProxyError::AuthorizationExpired {
        termination: StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        handed_to_backend: true,
    };
    assert_eq!(
        classify_grpc_proxy_error(&lifetime),
        ErrorClass::ClientDisconnect
    );
    assert_eq!(
        lifetime.to_string(),
        "authenticated stream lifetime reached"
    );
}

// --- Wiring guards ------------------------------------------------------------
//
// The dispatch functions need a live backend and a real hyper connection to
// drive, so these assertions keep the WIRING of the bounds proven above from
// silently regressing. The live proof is in
// `tests/functional/functional_h1_h2_auth_lifetime_test.rs`.

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const GRPC_PROXY_SOURCE: &str = include_str!("../../../src/proxy/grpc_proxy.rs");

/// The slice of `source` from the first `start` to the next `end` after it.
fn source_region<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("missing region start {start:?}"))
        .split(end)
        .next()
        .unwrap_or_else(|| panic!("missing region end {end:?}"))
}

/// Code outside `//` comments with every whitespace character removed, so a
/// structural scan depends neither on prose nor on how rustfmt wraps a call.
fn compact_code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Byte offset of `pattern` in `haystack`, or a failure naming it.
fn offset_of(haystack: &str, pattern: &str) -> usize {
    haystack
        .find(pattern)
        .unwrap_or_else(|| panic!("missing {pattern:?}"))
}

#[test]
fn both_native_grpc_dispatches_bound_acquisition_handoff_and_header_wait() {
    let dispatches = [
        (
            "buffered",
            "pub(crate) async fn proxy_grpc_request_core(",
            "// Extract response status and headers through the shared collector",
            "protocol_header_wait",
        ),
        (
            "fully-streamed",
            "async fn proxy_grpc_streaming_dispatch(",
            "// Check if the request body already exceeded the limit before response",
            "protocol_send_wait",
        ),
    ];
    for (label, start, end, wait) in dispatches {
        let code = compact_code(source_region(GRPC_PROXY_SOURCE, start, end));
        let composed = offset_of(&code, "letdispatch_bounds=GrpcDispatchBounds::compose(");
        let acquired = offset_of(
            &code,
            "dispatch_bounds.acquire(auth,transport.get_sender(proxy))",
        );
        assert!(
            composed < acquired,
            "{label}: the authorization lifetime must be composed before the sender is acquired"
        );
        assert_eq!(
            code.matches("transport.get_sender(proxy)").count(),
            1,
            "{label}: the only sender acquisition must be the bounded one"
        );
        // hyper enqueues the request as soon as `send_request` is called. The
        // handoff gate is the first statement of the future that owns the
        // send, and the send future is built immediately after it, so the gate
        // is ahead of the enqueue whether or not the adapter is lazy.
        let gate = offset_of(
            &code,
            &format!("let{wait}=async{{dispatch_bounds.admit_handoff(auth)?;"),
        );
        let gated_send = format!(
            "{wait}=async{{dispatch_bounds.admit_handoff(auth)?;letsend_fut=sender.send_request("
        );
        assert!(
            acquired < gate && code.contains(&gated_send),
            "{label}: the send future must be built immediately after the handoff gate"
        );
        assert_eq!(
            code.matches(".send_request(").count(),
            1,
            "{label}: the only request handoff must be the gated one"
        );
        let wrapped = format!("under_authorization(header_auth_bound,auth,{wait})");
        assert!(
            code.contains(&wrapped),
            "{label}: the response-header wait must be held to the authorization bound"
        );
    }
}

#[test]
fn native_grpc_reuses_the_shared_poll_before_timer_combinators() {
    // The acquisition goes through the shared backend checkout combinator,
    // whose structural guard (in `stream_auth_lifetime_tests.rs`) pins
    // precheck -> poll -> timer. The header wait goes through the shared
    // expiry-first wait, which polls the bound first on every wake: no handoff
    // gate follows it, so an exact-deadline tie must go to the bound.
    let acquire = compact_code(source_region(
        GRPC_PROXY_SOURCE,
        "pub(crate) fn acquire<F>(",
        "pub(crate) fn admit_handoff(",
    ));
    assert!(
        acquire.contains("super::await_backend_handoff_bound(self.handoff,acquisition)"),
        "the sender acquisition must reuse the shared poll-before-timer combinator"
    );
    let header_wait = compact_code(source_region(
        GRPC_PROXY_SOURCE,
        "pub(crate) fn grpc_header_wait_under_authorization<F, T>(",
        "\n}\n",
    ));
    assert!(
        header_wait.contains("crate::plugins::await_deadline_first(bound.at,wait)"),
        "the response-header wait must reuse the shared expiry-first wait"
    );
    for duplicate in [
        "sleep_until(",
        "pin_project!",
        "timeout_at(deadline,transport",
    ] {
        assert!(
            !compact_code(GRPC_PROXY_SOURCE).contains(duplicate),
            "native gRPC must not carry its own bound combinator ({duplicate})"
        );
    }
}

#[test]
fn every_native_grpc_dispatch_call_carries_the_authorization_plan() {
    let mut calls = 0;
    for callee in [
        "grpc_proxy::proxy_grpc_request_core(",
        "grpc_proxy::proxy_grpc_request_streaming(",
        "grpc_proxy::proxy_grpc_request_from_bytes(",
    ] {
        for (index, _) in PROXY_SOURCE.match_indices(callee) {
            // A quoted mention is an inline test's marker, not a call.
            if PROXY_SOURCE[..index].ends_with('"') {
                continue;
            }
            let args = PROXY_SOURCE[index..]
                .split("tokio::pin!(attempt)")
                .next()
                .expect("bounded dispatch call");
            assert!(
                args.contains("grpc_buffered_upload_auth_deadline.as_ref(),"),
                "every native gRPC dispatch, retry included, must carry the request's \
                 authorization plan: {args}"
            );
            calls += 1;
        }
    }
    assert_eq!(
        calls, 4,
        "the split, mixed, fully-streamed, and retry dispatches"
    );
}

#[test]
fn a_native_grpc_authorization_expiry_gets_the_fixed_terminal() {
    let arm = source_region(
        PROXY_SOURCE,
        "Err(GrpcProxyError::AuthorizationExpired { termination, .. }) => {",
        "Err(e) => {",
    );
    let code = compact_code(arm);
    assert!(
        code.contains("boxed_finalize_authorization_expired_rejection("),
        "the expiry is answered by the fixed pre-commitment terminal (grpc-status: 16)"
    );
    assert!(
        code.contains("drop(backend_admission_permits.take());")
            && !code.contains("record_backend_outcome(")
            && !code.contains("record_grpc_backend_dispatch_outcome("),
        "the gateway's own decision trains no backend admission or health outcome"
    );
}

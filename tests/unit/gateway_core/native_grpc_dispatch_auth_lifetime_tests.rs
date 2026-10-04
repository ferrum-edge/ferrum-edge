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
    let start_at = source
        .find(start)
        .unwrap_or_else(|| panic!("missing region start {start:?}"));
    let tail = &source[start_at + start.len()..];
    let end_at = tail
        .find(end)
        .unwrap_or_else(|| panic!("missing region end {end:?}"));
    &tail[..end_at]
}

/// Code outside `//` comments with every whitespace character removed, so a
/// structural scan depends neither on prose nor on how rustfmt wraps a call
/// or inserts an optional trailing argument comma.
fn compact_code(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace(",)", ")")
}

/// Match a complete group in compact source, ignoring delimiters in strings.
/// These focused source regions use ordinary strings, not raw or char literals.
pub(super) fn source_group(source: &str, open_at: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let close = match *bytes.get(open_at)? {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut at = open_at + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => at = source_string_end(bytes, at)?,
            b'(' | b'[' | b'{' => at = source_group(source, at)?.1,
            b')' | b']' | b'}' => {
                return (bytes[at] == close).then_some((&source[open_at + 1..at], at + 1));
            }
            _ => at += 1,
        }
    }
    None
}

fn source_string_end(bytes: &[u8], quote_at: usize) -> Option<usize> {
    let mut at = quote_at + 1;
    while at < bytes.len() {
        match bytes[at] {
            b'"' => return Some(at + 1),
            b'\\' => at += 2,
            _ => at += 1,
        }
    }
    None
}

/// Require a whole statement at this scope, never a nested or assigned fragment.
pub(super) fn direct_source_statement(body: &str, statement: &str) -> bool {
    let bytes = body.as_bytes();
    let mut at = 0;
    let mut boundary = true;
    while at < bytes.len() {
        if boundary && body[at..].starts_with(statement) {
            return true;
        }
        match bytes[at] {
            b'"' => {
                let Some(end) = source_string_end(bytes, at) else {
                    return false;
                };
                boundary = false;
                at = end;
            }
            b'(' | b'[' | b'{' => {
                let Some((_, end)) = source_group(body, at) else {
                    return false;
                };
                boundary = bytes[at] == b'{';
                at = end;
            }
            b';' => {
                boundary = true;
                at += 1;
            }
            _ => {
                boundary = false;
                at += 1;
            }
        }
    }
    false
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
        let wrapped =
            format!("under_authorization(header_auth_bound,auth,&handed_to_backend,{wait})");
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
        "pub(crate) fn acquire<F, T, E>(",
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

#[tokio::test(start_paused = true)]
async fn a_completed_connect_error_after_expiry_cannot_bypass_the_acquisition_bound() {
    use ferrum_edge::_test_support::await_native_grpc_acquisition_result_for_test;

    let plan = plan_after(Duration::from_millis(50));
    let bounds = compose_native_grpc_dispatch_bounds_for_test(Some(200), Some(&plan));
    let connect_failed = AtomicBool::new(false);
    let acquisition = std::future::poll_fn(|_| {
        if connect_failed.load(Ordering::Relaxed) {
            Poll::Ready(Err::<(), _>(GrpcProxyError::BackendTimeout {
                kind: GrpcTimeoutKind::Connect,
                message: "later connection failure".to_string(),
            }))
        } else {
            Poll::Pending
        }
    });
    let mut attempt = Box::pin(await_native_grpc_acquisition_result_for_test(
        &bounds,
        Some(&plan),
        acquisition,
    ));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(attempt.as_mut().poll(&mut cx).is_pending());
    // No repoll between expiry and the later connection error becoming ready.
    tokio::time::advance(Duration::from_millis(300)).await;
    connect_failed.store(true, Ordering::Relaxed);
    let error = attempt.await.unwrap_err();
    assert!(matches!(
        error,
        GrpcProxyError::AuthorizationExpired {
            handed_to_backend: false,
            ..
        }
    ));
    assert_eq!(
        classify_grpc_proxy_error(&error),
        ErrorClass::ClientDisconnect
    );
    assert!(
        !plan
            .2
            .record_once(StreamAuthTermination::CredentialExpired, plan.1)
    );
    // A retry would compose the same elapsed instant and never poll a dial.
    let retried = AtomicBool::new(false);
    let result = await_native_grpc_acquisition_result_for_test(&bounds, Some(&plan), async {
        retried.store(true, Ordering::Relaxed);
        Ok::<_, GrpcProxyError>(())
    })
    .await;
    assert!(result.is_err());
    assert!(!retried.load(Ordering::Relaxed));
}

#[tokio::test(start_paused = true)]
async fn an_unpolled_header_wrapper_refuses_before_the_actual_handoff() {
    use ferrum_edge::_test_support::native_grpc_header_wait_with_handoff_for_test;

    let plan = plan_after(Duration::from_millis(50));
    let bounds = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));
    let handed = AtomicBool::new(false);
    let backend_requests = AtomicUsize::new(0);
    let headers =
        native_grpc_header_wait_with_handoff_for_test(None, Some(&plan), &handed, async {
            native_grpc_handoff_gate_for_test(&bounds, Some(&plan), || {
                backend_requests.fetch_add(1, Ordering::Relaxed);
                handed.store(true, Ordering::Relaxed);
            })?;
            Ok::<_, GrpcProxyError>(())
        });
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(matches!(
        headers.await,
        Err(GrpcProxyError::AuthorizationExpired {
            handed_to_backend: false,
            ..
        })
    ));
    assert_eq!(backend_requests.load(Ordering::Relaxed), 0);
    assert!(!handed.load(Ordering::Relaxed));
}

#[tokio::test(start_paused = true)]
async fn expiry_after_actual_handoff_retains_post_wire_attribution() {
    use ferrum_edge::_test_support::native_grpc_header_wait_with_handoff_for_test;

    let plan = plan_after(Duration::from_millis(50));
    let bounds = compose_native_grpc_dispatch_bounds_for_test(None, Some(&plan));
    let handed = AtomicBool::new(false);
    let backend_requests = AtomicUsize::new(0);
    let mut headers = Box::pin(native_grpc_header_wait_with_handoff_for_test(
        None,
        Some(&plan),
        &handed,
        async {
            native_grpc_handoff_gate_for_test(&bounds, Some(&plan), || {
                backend_requests.fetch_add(1, Ordering::Relaxed);
                handed.store(true, Ordering::Relaxed);
            })?;
            std::future::pending::<Result<(), GrpcProxyError>>().await
        },
    ));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(headers.as_mut().poll(&mut cx).is_pending());
    assert_eq!(backend_requests.load(Ordering::Relaxed), 1);
    tokio::time::advance(Duration::from_millis(50)).await;
    assert!(matches!(
        headers.await,
        Err(GrpcProxyError::AuthorizationExpired {
            handed_to_backend: true,
            ..
        })
    ));
    assert_eq!(backend_requests.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn buffered_grpc_collection_is_cancelled_at_the_dispatch_authorization_instant() {
    // Body collection uses the same production wrapper as the header wait,
    // after the actual handoff has been recorded, without rearming the plan.
    let plan = plan_after(Duration::from_millis(100));
    tokio::time::advance(Duration::from_millis(60)).await;
    let (collect, polled, dropped) = stalled();
    let result =
        await_native_grpc_header_wait_for_test(None, Some(&plan), async { Ok(collect.await) })
            .await;
    assert_eq!(
        expired_after_handoff(result),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(polled.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert!(
        !plan
            .2
            .record_once(StreamAuthTermination::CredentialExpired, plan.1)
    );
}

#[tokio::test(start_paused = true)]
async fn sidecar_readiness_error_after_expiry_keeps_the_captured_source() {
    use ferrum_edge::_test_support::{
        BackendHandoffBoundSourceForTest, await_backend_checkout_result_for_test,
        compose_backend_handoff_bound_for_test, compose_dispatch_phase_bound_for_test,
    };

    let plan = plan_after(Duration::from_millis(50));
    let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
    let bound = compose_backend_handoff_bound_for_test(
        Some(tokio::time::Instant::now() + Duration::from_millis(200)),
        &dispatch,
    );
    let ready = AtomicBool::new(false);
    let readiness = std::future::poll_fn(|_| {
        if ready.load(Ordering::Relaxed) {
            Poll::Ready(Err::<(), _>("connection failed"))
        } else {
            Poll::Pending
        }
    });
    let mut wait = Box::pin(await_backend_checkout_result_for_test(&bound, readiness));
    let waker = futures_util::task::noop_waker();
    assert!(
        wait.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    tokio::time::advance(Duration::from_millis(300)).await;
    ready.store(true, Ordering::Relaxed);
    assert_eq!(
        wait.await,
        Err(BackendHandoffBoundSourceForTest::Authorization)
    );
}

#[tokio::test(start_paused = true)]
async fn native_h3_acquisition_and_resumed_send_never_outlive_the_plan() {
    use ferrum_edge::_test_support::{
        await_native_h3_checkout_for_test, await_native_h3_dispatch_for_test,
    };

    let plan = plan_after(Duration::from_millis(50));
    let start = tokio::time::Instant::now();
    let result = await_native_h3_checkout_for_test(None, Some(&plan), async {
        std::future::pending::<Result<(), anyhow::Error>>().await
    })
    .await;
    assert_eq!(
        result,
        Err((Some(StreamAuthTermination::CredentialExpired), false, false))
    );
    assert_eq!(
        tokio::time::Instant::now(),
        start + Duration::from_millis(50)
    );

    let plan = plan_after(Duration::from_millis(50));
    let stream_credit = AtomicBool::new(false);
    let backend_requests = AtomicUsize::new(0);
    let send = std::future::poll_fn(|_| {
        if stream_credit.load(Ordering::Relaxed) {
            backend_requests.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok::<_, ferrum_edge::http3::client::H3PoolError>(()))
        } else {
            Poll::Pending
        }
    });
    let mut wait = Box::pin(await_native_h3_dispatch_for_test(
        None,
        Some(&plan),
        false,
        send,
    ));
    let waker = futures_util::task::noop_waker();
    assert!(
        wait.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    tokio::time::advance(Duration::from_millis(100)).await;
    stream_credit.store(true, Ordering::Relaxed);
    assert_eq!(
        wait.await,
        Err((Some(StreamAuthTermination::CredentialExpired), false, false))
    );
    assert_eq!(backend_requests.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn native_h3_header_expiry_is_post_wire_and_an_earlier_read_bound_stays_read() {
    use ferrum_edge::_test_support::await_native_h3_dispatch_for_test;

    let plan = plan_after(Duration::from_millis(50));
    let result = await_native_h3_dispatch_for_test(None, Some(&plan), true, async {
        std::future::pending::<Result<(), ferrum_edge::http3::client::H3PoolError>>().await
    })
    .await;
    assert_eq!(
        result,
        Err((Some(StreamAuthTermination::CredentialExpired), true, false))
    );

    let plan = plan_after(Duration::from_millis(200));
    let protocol_at = tokio::time::Instant::now() + Duration::from_millis(50);
    let result = await_native_h3_dispatch_for_test(Some(protocol_at), Some(&plan), true, async {
        std::future::pending::<Result<(), ferrum_edge::http3::client::H3PoolError>>().await
    })
    .await;
    assert_eq!(result, Err((None, true, false)));
    assert_eq!(plan.2.observed(), None);
}

#[test]
fn all_grouped_paths_carry_the_authorization_plan_to_their_actual_boundaries() {
    let buffered = source_region(
        GRPC_PROXY_SOURCE,
        "// Collection has its own operator phase budget",
        "// Hand the charge to the retained allocation",
    );
    assert!(compact_code(buffered).contains("grpc_header_wait_under_authorization("));
    let native = source_region(
        PROXY_SOURCE,
        "Ok(GrpcResponseKind::Buffered(grpc_resp)) => {",
        "Err(GrpcProxyError::AuthorizationExpired",
    );
    assert!(native.contains("authorization_expired_grpc_precommit"));
    let sidecar = source_region(
        PROXY_SOURCE,
        "async fn proxy_to_backend_mesh_mtls(",
        "/// Post-ready Sidecar dispatch",
    );
    assert_eq!(sidecar.matches("await_backend_handoff_result(").count(), 3);
    let sidecar_send = source_region(
        PROXY_SOURCE,
        "async fn proxy_to_backend_mesh_mtls_after_ready(",
        "let send_result =",
    );
    assert!(
        offset_of(sidecar_send, "handoff_bound.elapsed()")
            < offset_of(sidecar_send, "sender.send_request(backend_req)")
    );
    let bridge = include_str!("../../../src/http3/cross_protocol.rs");
    let streamed_bridge = source_region(
        bridge,
        "pub(crate) async fn dispatch_grpc_streaming(",
        "async fn apply_buffered_plain_plugin_reject(",
    );
    assert!(streamed_bridge.contains("pump_bound.deadline()"));
    assert!(streamed_bridge.contains("grpc_auth.as_ref(),"));
    let pool = include_str!("../../../src/http3/client.rs");
    assert!(pool.contains("await_backend_dispatch_bound(bound, work)"));
    assert!(pool.contains("await_backend_handoff_result(bound, checkout)"));
}

#[test]
fn ready_sidecar_and_native_h3_phases_never_arm_timers() {
    use ferrum_edge::_test_support::{
        await_backend_checkout_result_for_test, await_native_h3_checkout_for_test,
        await_native_h3_dispatch_for_test, compose_backend_handoff_bound_for_test,
        compose_dispatch_phase_bound_for_test,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime without a time driver");
    runtime.block_on(async {
        let plan = plan_after(Duration::from_secs(60));
        let dispatch = compose_dispatch_phase_bound_for_test(None, Some(&plan));
        let bound = compose_backend_handoff_bound_for_test(None, &dispatch);
        let sidecar = await_backend_checkout_result_for_test(
            &bound,
            std::future::ready(Ok::<_, ()>("ready")),
        )
        .await;
        assert_eq!(sidecar, Ok(Ok("ready")));
        let h3 = await_native_h3_checkout_for_test(
            None,
            Some(&plan),
            std::future::ready(Ok::<_, anyhow::Error>("pooled")),
        )
        .await;
        assert_eq!(h3, Ok("pooled"));
        let sent = await_native_h3_dispatch_for_test(
            None,
            Some(&plan),
            false,
            std::future::ready(Ok::<_, ferrum_edge::http3::client::H3PoolError>("sent")),
        )
        .await;
        assert_eq!(sent, Ok("sent"));
    });
}

#[tokio::test(start_paused = true)]
async fn native_h3_late_checkout_errors_preserve_the_captured_client_winner() {
    use ferrum_edge::_test_support::await_native_h3_checkout_for_test;

    let plan = plan_after(Duration::from_millis(200));
    let client_at = tokio::time::Instant::now() + Duration::from_millis(50);
    let failed = AtomicBool::new(false);
    let checkout = std::future::poll_fn(|_| {
        if failed.load(Ordering::Relaxed) {
            Poll::Ready(Err::<(), _>(anyhow::anyhow!("later connect failure")))
        } else {
            Poll::Pending
        }
    });
    let mut wait = Box::pin(await_native_h3_checkout_for_test(
        Some(client_at),
        Some(&plan),
        checkout,
    ));
    let waker = futures_util::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(Duration::from_millis(300)).await;
    failed.store(true, Ordering::Relaxed);
    assert_eq!(wait.await, Err((None, false, true)));
    assert_eq!(plan.2.observed(), None);
}

#[tokio::test(start_paused = true)]
async fn late_sidecar_readiness_wake_preserves_connect_before_client_winner() {
    use ferrum_edge::_test_support::{
        BackendHandoffBoundSourceForTest, await_backend_checkout_result_for_test,
        compose_backend_handoff_bound_for_test, compose_dispatch_phase_bound_for_test,
        sidecar_readiness_connect_terminal_for_test,
    };

    let start = tokio::time::Instant::now();
    let plan = plan_after(Duration::from_millis(200));
    let dispatch = compose_dispatch_phase_bound_for_test(Some(100), Some(&plan));
    assert!(!dispatch.authorization_wins());
    let bound =
        compose_backend_handoff_bound_for_test(Some(start + Duration::from_millis(50)), &dispatch);
    let ready = AtomicBool::new(false);
    let readiness = std::future::poll_fn(|_| {
        if ready.load(Ordering::Relaxed) {
            Poll::Ready(Err::<(), _>("late readiness error"))
        } else {
            Poll::Pending
        }
    });
    let mut wait = Box::pin(await_backend_checkout_result_for_test(&bound, readiness));
    let waker = futures_util::task::noop_waker();
    assert!(
        wait.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    tokio::time::advance(Duration::from_millis(300)).await;
    ready.store(true, Ordering::Relaxed);
    assert_eq!(
        wait.await,
        Err(BackendHandoffBoundSourceForTest::ResponseHeader)
    );
    assert_eq!(
        sidecar_readiness_connect_terminal_for_test(),
        (200, Some("14".into()), false)
    );
    assert_eq!(plan.2.observed(), None, "later authorization did not win");
}

#[test]
fn authorization_placeholders_keep_actual_handoff_separate_from_neutral_health() {
    use ferrum_edge::_test_support::authorization_dispatch_provenance_for_test;

    assert_eq!(
        authorization_dispatch_provenance_for_test(false),
        (false, false, Some(ErrorClass::ClientDisconnect), "pre_wire")
    );
    assert_eq!(
        authorization_dispatch_provenance_for_test(true),
        (false, true, Some(ErrorClass::ClientDisconnect), "ambiguous")
    );
    let proxy = include_str!("../../../src/proxy/mod.rs");
    assert!(
        !proxy.contains(
            "record_backend_dispatch_outcome(result.error_class, !result.connection_error)"
        )
    );
    let compact_proxy = compact_code(proxy);
    assert!(
        compact_proxy.contains(
            "authorization_expired_dispatch_placeholder(resolved_ip,e.request_on_wire())"
        )
    );
}

#[test]
fn every_plain_h3_frontend_pool_route_carries_the_captured_plan() {
    let server = include_str!("../../../src/http3/server.rs");
    assert!(!server.contains(".request_streaming("));
    assert!(!server.contains(".request_with_target_streaming("));
    assert!(!server.contains(".request_streaming_body("));
    assert!(!server.contains(".request_with_target_streaming_body("));
    assert!(server.contains(".request_streaming_body_under_authorization("));
    assert!(server.contains(".request_with_target_streaming_body_under_authorization("));
    assert_eq!(
        server.matches("let attempt = proxy_to_backend_h3(").count(),
        3
    );
    for call in server.split("let attempt = proxy_to_backend_h3(").skip(1) {
        assert!(call.split_once(");").unwrap().0.contains("auth,"));
    }
}

/// Drive the actual cold-checkout composer after its creator published the
/// post-DNS connect instant. No repoll occurs until every deadline has elapsed.
#[tokio::test(start_paused = true)]
async fn native_h3_cold_checkout_retains_earliest_connect_client_or_authorization_winner() {
    use ferrum_edge::_test_support::error_class_is_health_neutral_for_test;
    use ferrum_edge::http3::client::await_h3_connection_checkout_for_test;
    use std::sync::OnceLock;

    for (connect_ms, client_ms, auth_ms, expected_auth, expected_client) in [
        (40, 80, 100, false, false),
        (40, 100, 80, false, false),
        (80, 40, 100, false, true),
        (80, 100, 40, true, false),
        (40, 100, 40, true, false),
        (40, 40, 100, false, true),
        (80, 40, 40, true, false),
        (40, 40, 40, true, false),
    ] {
        let started = tokio::time::Instant::now();
        let plan = plan_after(Duration::from_millis(auth_ms));
        let connect_at = OnceLock::new();
        let polls = AtomicUsize::new(0);
        let late_error_ready = AtomicBool::new(false);
        let checkout = futures_util::future::poll_fn(|_| {
            polls.fetch_add(1, Ordering::Relaxed);
            let _ = connect_at.set(started + Duration::from_millis(connect_ms));
            if late_error_ready.load(Ordering::Relaxed) {
                Poll::Ready(Err::<(), _>(anyhow::anyhow!("late transport error")))
            } else {
                Poll::Pending
            }
        });
        let mut wait = Box::pin(await_h3_connection_checkout_for_test(
            Some(started + Duration::from_millis(client_ms)),
            Some(&plan),
            &connect_at,
            checkout,
        ));
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert_eq!(polls.load(Ordering::Relaxed), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        late_error_ready.store(true, Ordering::Relaxed);
        let (termination, request_on_wire, client_expired, class) = wait
            .await
            .expect_err("the captured earliest bound must win");
        assert_eq!(
            termination,
            expected_auth.then_some(StreamAuthTermination::CredentialExpired)
        );
        assert!(
            !request_on_wire,
            "cold acquisition never sends request HEADERS"
        );
        assert_eq!(client_expired, expected_client);
        assert_eq!(
            class,
            if expected_auth || expected_client {
                ErrorClass::ClientDisconnect
            } else {
                ErrorClass::ConnectionTimeout
            }
        );
        assert_eq!(plan.2.observed(), termination);
        assert_eq!(
            error_class_is_health_neutral_for_test(class),
            expected_auth || expected_client
        );
    }
}

/// The production H3 pool publishes one typed failure, then the coalesced
/// waiter remains unpolled until all of its own deadlines have elapsed.
#[tokio::test(start_paused = true)]
async fn native_h3_coalesced_creation_late_wake_keeps_shared_failure_and_own_lifetime() {
    use ferrum_edge::_test_support::error_class_is_health_neutral_for_test;
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::http3::client::Http3ConnectionPool;
    use std::io::ErrorKind::{ConnectionRefused, TimedOut};
    use std::sync::OnceLock;

    for (connect_ms, publish_ms, client_ms, auth_ms, kind, expected_auth, expected_client) in [
        (40, 40, 100, 80, TimedOut, false, false),
        (40, 40, 80, 100, TimedOut, false, false),
        (40, 40, 100, 40, TimedOut, true, false),
        (40, 40, 40, 100, TimedOut, false, true),
        (40, 40, 40, 40, TimedOut, true, false),
        (40, 40, 100, 30, TimedOut, true, false),
        (40, 40, 30, 100, TimedOut, false, true),
        (20, 40, 100, 30, TimedOut, false, false),
        (80, 20, 100, 40, ConnectionRefused, false, false),
        (80, 40, 100, 30, ConnectionRefused, true, false),
    ] {
        let pool = Http3ConnectionPool::new(
            Arc::new(EnvConfig::default()),
            DnsCache::new(DnsConfig::default()),
        );
        let started = tokio::time::Instant::now();
        let creator_plan = plan_after(Duration::from_millis(200));
        let waiter_plan = plan_after(Duration::from_millis(auth_ms));
        let creator_connect_at = OnceLock::new();
        let waiter_connect_at = OnceLock::new();
        let ready = AtomicBool::new(false);
        let creator_polls = AtomicUsize::new(0);
        let waiter_creates = AtomicUsize::new(0);
        // The typed io class must survive the misleading TLS text as well as
        // the pool fan-out; the waiter must not manufacture its own context.
        let message = "creator TLS handshake failure before HEADERS";
        let failure = std::future::poll_fn(|_| {
            creator_polls.fetch_add(1, Ordering::Relaxed);
            let _ = creator_connect_at.set(started + Duration::from_millis(connect_ms));
            if ready.load(Ordering::Relaxed) {
                Poll::Ready(std::io::Error::new(kind, message).into())
            } else {
                Poll::Pending
            }
        });
        let mut creator = Box::pin(pool.await_coalesced_connection_failure_for_test(
            "coalesced-cold-checkout".to_string(),
            None,
            Some(&creator_plan),
            &creator_connect_at,
            failure,
        ));
        let mut waiter = Box::pin(pool.await_coalesced_connection_failure_for_test(
            "coalesced-cold-checkout".to_string(),
            Some(started + Duration::from_millis(client_ms)),
            Some(&waiter_plan),
            &waiter_connect_at,
            async {
                waiter_creates.fetch_add(1, Ordering::Relaxed);
                anyhow::anyhow!("coalesced waiter must not create another connection")
            },
        ));
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(creator.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        assert_eq!(creator_polls.load(Ordering::Relaxed), 1);
        assert_eq!(waiter_creates.load(Ordering::Relaxed), 0);

        tokio::time::advance(Duration::from_millis(publish_ms)).await;
        ready.store(true, Ordering::Relaxed);
        let (creator_error, creator_message) = creator.await.unwrap_err();
        let transport_class = match kind {
            TimedOut => ErrorClass::ConnectionTimeout,
            _ => ErrorClass::ConnectionRefused,
        };
        assert_eq!(creator_error, (None, false, false, transport_class));
        assert_eq!(creator_message, message);
        assert_eq!(creator_plan.2.observed(), None);
        assert_eq!(creator_polls.load(Ordering::Relaxed), 2);

        tokio::time::advance(Duration::from_secs(1)).await;
        let (waiter_error, waiter_message) = waiter.await.unwrap_err();
        let termination = expected_auth.then_some(StreamAuthTermination::CredentialExpired);
        let lifetime_wins = expected_auth || expected_client;
        assert_eq!(
            waiter_error,
            (
                termination,
                false,
                expected_client,
                if lifetime_wins {
                    ErrorClass::ClientDisconnect
                } else {
                    transport_class
                },
            )
        );
        if !lifetime_wins {
            assert_eq!(waiter_message, message);
        }
        assert_eq!(waiter_plan.2.observed(), termination);
        if let Some(termination) = termination {
            let recorded_again = waiter_plan.2.record_once(termination, waiter_plan.1);
            assert!(!recorded_again);
        }
        assert_eq!(
            error_class_is_health_neutral_for_test(waiter_error.3),
            lifetime_wins
        );
        assert!(waiter_connect_at.get().is_none());
        assert_eq!(waiter_creates.load(Ordering::Relaxed), 0);
        assert_eq!(pool.pool_size(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_coalesced_waiter_does_not_inherit_creator_authorization_terminal() {
    use ferrum_edge::_test_support::error_class_is_health_neutral_for_test;
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::http3::client::Http3ConnectionPool;
    use std::sync::OnceLock;

    let pool = Http3ConnectionPool::new(
        Arc::new(EnvConfig::default()),
        DnsCache::new(DnsConfig::default()),
    );
    let started = tokio::time::Instant::now();
    let creator_plan = plan_after(Duration::from_millis(20));
    let waiter_plan = plan_after(Duration::from_millis(80));
    let creator_connect_at = OnceLock::new();
    let waiter_connect_at = OnceLock::new();
    let ready = AtomicBool::new(false);
    let waiter_creates = AtomicUsize::new(0);
    let message = "creator transport connect timeout";
    let failure = std::future::poll_fn(|_| {
        let _ = creator_connect_at.set(started + Duration::from_millis(40));
        if ready.load(Ordering::Relaxed) {
            Poll::Ready(std::io::Error::new(std::io::ErrorKind::TimedOut, message).into())
        } else {
            Poll::Pending
        }
    });
    let mut creator = Box::pin(pool.await_coalesced_connection_failure_for_test(
        "creator-auth-isolation".to_string(),
        None,
        Some(&creator_plan),
        &creator_connect_at,
        failure,
    ));
    let mut waiter = Box::pin(pool.await_coalesced_connection_failure_for_test(
        "creator-auth-isolation".to_string(),
        None,
        Some(&waiter_plan),
        &waiter_connect_at,
        async {
            waiter_creates.fetch_add(1, Ordering::Relaxed);
            anyhow::anyhow!("waiter must consume the shared transport failure")
        },
    ));
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(creator.as_mut().poll(&mut cx).is_pending());
    assert!(waiter.as_mut().poll(&mut cx).is_pending());

    tokio::time::advance(Duration::from_millis(40)).await;
    ready.store(true, Ordering::Relaxed);
    let (creator_error, _) = creator.await.unwrap_err();
    assert_eq!(
        creator_error,
        (
            Some(StreamAuthTermination::CredentialExpired),
            false,
            false,
            ErrorClass::ClientDisconnect,
        )
    );
    assert!(error_class_is_health_neutral_for_test(creator_error.3));

    tokio::time::advance(Duration::from_secs(1)).await;
    let (waiter_error, waiter_message) = waiter.await.unwrap_err();
    assert_eq!(
        waiter_error,
        (None, false, false, ErrorClass::ConnectionTimeout)
    );
    assert_eq!(waiter_message, message);
    assert_eq!(waiter_plan.2.observed(), None);
    assert!(waiter_connect_at.get().is_none());
    assert_eq!(waiter_creates.load(Ordering::Relaxed), 0);
    assert_eq!(
        creator_plan.2.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

/// Exercise the ready-dial-first timeout in production connect_candidates,
/// then the actual H3 typed adapter and GenericPool/Http3PoolManager fan-out.
/// The creator resumes after both bounds; the waiter resumes still later.
#[tokio::test(start_paused = true)]
async fn native_h3_candidate_failure_captures_transport_winner_before_pool_publication() {
    use ferrum_edge::_test_support::error_class_is_health_neutral_for_test;
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::dns::{CandidateConnectError, DnsCache, DnsConfig, connect_candidates};
    use ferrum_edge::http3::client::{
        Http3ConnectionPool, h3_connection_checkout_metadata_for_test,
    };
    use std::io::ErrorKind;
    use std::sync::OnceLock;

    // connect, publication, creator client/auth, waiter client/auth (ms).
    for (connect_ms, publish_ms, creator_client_ms, creator_auth_ms, client_ms, auth_ms) in [
        (40, 100, 120, 80, 120, 80),
        (40, 100, 80, 120, 80, 120),
        (40, 100, 120, 40, 120, 80),
        (40, 100, 40, 120, 120, 80),
        (40, 100, 120, 80, 120, 40),
        (40, 100, 120, 80, 40, 120),
        (40, 100, 120, 40, 40, 40),
        (40, 100, 120, 20, 120, 80),
        (40, 100, 120, 80, 120, 20),
        (40, 100, 20, 120, 120, 80),
        (40, 100, 120, 80, 20, 120),
        (40, 40, 120, 80, 120, 80),
        (80, 20, 120, 60, 120, 40),
    ] {
        let dns = DnsCache::new(DnsConfig::default());
        let candidates = dns
            .resolve_candidates("127.0.0.1", None, None)
            .await
            .unwrap();
        let pool = Http3ConnectionPool::new(Arc::new(EnvConfig::default()), dns);
        let idle_state = pool.creation_state_for_test();
        assert_eq!(idle_state.0, 0);
        let started = tokio::time::Instant::now();
        let creator_plan = plan_after(Duration::from_millis(creator_auth_ms));
        let waiter_plan = plan_after(Duration::from_millis(auth_ms));
        let creator_connect_at = OnceLock::new();
        let waiter_connect_at = OnceLock::new();
        let ready = AtomicBool::new(false);
        let dial_polls = AtomicUsize::new(0);
        let waiter_creates = AtomicUsize::new(0);
        let (dial_guard, _, dropped) = stalled();
        // The context deliberately looks like TLS; only the genuine typed
        // source, or the captured operator timeout, may decide the class.
        let message = "creator TLS handshake failure before HEADERS";
        let failure = async {
            let _dial_guard = dial_guard;
            let budget = Duration::from_millis(connect_ms);
            creator_connect_at.set(started + budget).unwrap();
            let result = connect_candidates(&candidates, 443, budget, |_| {
                std::future::poll_fn(|_| {
                    dial_polls.fetch_add(1, Ordering::Relaxed);
                    if ready.load(Ordering::Relaxed) {
                        Poll::Ready(Err::<(), _>(std::io::Error::new(
                            ErrorKind::ConnectionRefused,
                            "typed dial refusal",
                        )))
                    } else {
                        Poll::Pending
                    }
                })
            })
            .await;
            match result {
                Err(CandidateConnectError::Failed { source, .. }) => {
                    anyhow::Error::new(source).context(message)
                }
                _ => panic!("the ready non-timeout dial must beat Tokio's elapsed timer"),
            }
        };
        let mut creator = Box::pin(pool.await_coalesced_connection_error_for_test(
            "candidate-failure-publication".to_string(),
            Some(started + Duration::from_millis(creator_client_ms)),
            Some(&creator_plan),
            &creator_connect_at,
            failure,
        ));
        let mut waiter = Box::pin(pool.await_coalesced_connection_error_for_test(
            "candidate-failure-publication".to_string(),
            Some(started + Duration::from_millis(client_ms)),
            Some(&waiter_plan),
            &waiter_connect_at,
            async {
                waiter_creates.fetch_add(1, Ordering::Relaxed);
                anyhow::anyhow!("waiter must consume the shared transport winner")
            },
        ));
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(creator.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        assert_eq!(pool.creation_state_for_test().0, 1);
        assert_eq!(dial_polls.load(Ordering::Relaxed), 1);
        assert!(!dropped.load(Ordering::SeqCst));

        tokio::time::advance(Duration::from_millis(publish_ms)).await;
        ready.store(true, Ordering::Relaxed);
        let creator_error = creator.await.unwrap_err();
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(dial_polls.load(Ordering::Relaxed), 2);
        assert_eq!(pool.creation_state_for_test(), idle_state);
        tokio::time::advance(Duration::from_secs(1)).await;
        let waiter_error = waiter.await.unwrap_err();

        let failure_ms = connect_ms.min(publish_ms);
        let transport_class = if publish_ms >= connect_ms {
            ErrorClass::ConnectionTimeout
        } else {
            ErrorClass::ConnectionRefused
        };
        for (error, plan, client_ms, auth_ms) in [
            (
                &creator_error,
                &creator_plan,
                creator_client_ms,
                creator_auth_ms,
            ),
            (&waiter_error, &waiter_plan, client_ms, auth_ms),
        ] {
            let expected_auth = auth_ms <= client_ms && auth_ms <= failure_ms;
            let expected_client = client_ms < auth_ms && client_ms <= failure_ms;
            let termination = expected_auth.then_some(StreamAuthTermination::CredentialExpired);
            let lifetime_wins = expected_auth || expected_client;
            let (authorization_expiry, on_wire, client_expired, class) =
                h3_connection_checkout_metadata_for_test(error);
            assert_eq!(authorization_expiry, termination);
            assert_eq!(client_expired, expected_client);
            assert!(!on_wire);
            assert_eq!(
                class,
                if lifetime_wins {
                    ErrorClass::ClientDisconnect
                } else {
                    transport_class
                }
            );
            let health_neutral = error_class_is_health_neutral_for_test(class);
            assert_eq!(health_neutral, lifetime_wins);
            assert_eq!(plan.2.observed(), termination);
            if let Some(termination) = termination {
                assert!(!plan.2.record_once(termination, plan.1));
            }
            if !lifetime_wins {
                assert_eq!(error.to_string(), message);
            }
        }
        let creator_metadata = h3_connection_checkout_metadata_for_test(&creator_error);
        if creator_metadata.0.is_none() && !creator_metadata.2 {
            let mut source: Option<&(dyn std::error::Error + 'static)> =
                Some(creator_error.as_ref());
            let mut typed_kind = None;
            while let Some(error) = source {
                if let Some(io) = error.downcast_ref::<std::io::Error>() {
                    typed_kind = Some(io.kind());
                    break;
                }
                source = error.source();
            }
            assert_eq!(
                typed_kind,
                Some(if publish_ms >= connect_ms {
                    ErrorKind::TimedOut
                } else {
                    ErrorKind::ConnectionRefused
                })
            );
        }
        assert!(waiter_connect_at.get().is_none());
        assert_eq!(waiter_creates.load(Ordering::Relaxed), 0);
        assert_eq!(pool.pool_size(), 0);
        assert_eq!(pool.creation_state_for_test(), idle_state);
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_cancelled_creation_releases_resources_and_waiter_elects_independently() {
    use ferrum_edge::_test_support::error_class_is_health_neutral_for_test;
    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::http3::client::{
        Http3ConnectionPool, classify_http3_error, h3_connection_checkout_metadata_for_test,
    };
    use std::sync::OnceLock;

    for expire_creator in [false, true] {
        let pool = Http3ConnectionPool::new(
            Arc::new(EnvConfig::default()),
            DnsCache::new(DnsConfig::default()),
        );
        let idle_state = pool.creation_state_for_test();
        let started = tokio::time::Instant::now();
        let creator_plan = plan_after(Duration::from_millis(20));
        let waiter_plan = plan_after(Duration::from_millis(80));
        let creator_connect_at = OnceLock::new();
        let waiter_connect_at = OnceLock::new();
        let waiter_creates = AtomicUsize::new(0);
        let (dial, polled, dropped) = stalled();
        let mut creator = Box::pin(pool.await_coalesced_connection_error_for_test(
            "cancelled-cold-creation".to_string(),
            None,
            Some(&creator_plan),
            &creator_connect_at,
            async {
                creator_connect_at
                    .set(started + Duration::from_millis(40))
                    .unwrap();
                dial.await;
                anyhow::anyhow!("cancelled dial must never finish")
            },
        ));
        let mut waiter = Box::pin(pool.await_coalesced_connection_error_for_test(
            "cancelled-cold-creation".to_string(),
            None,
            Some(&waiter_plan),
            &waiter_connect_at,
            async {
                waiter_creates.fetch_add(1, Ordering::Relaxed);
                waiter_connect_at
                    .set(started + Duration::from_millis(60))
                    .unwrap();
                std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "fresh waiter dial")
                    .into()
            },
        ));
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(creator.as_mut().poll(&mut cx).is_pending());
        assert!(waiter.as_mut().poll(&mut cx).is_pending());
        assert!(polled.load(Ordering::SeqCst));
        assert_eq!(waiter_creates.load(Ordering::Relaxed), 0);
        assert_eq!(pool.creation_state_for_test().0, 1);

        if expire_creator {
            tokio::time::advance(Duration::from_millis(20)).await;
            let error = creator.await.unwrap_err();
            let termination = StreamAuthTermination::CredentialExpired;
            assert_eq!(
                h3_connection_checkout_metadata_for_test(&error),
                (
                    Some(termination),
                    false,
                    false,
                    ErrorClass::ClientDisconnect
                )
            );
            assert!(!error.request_on_wire());
            assert!(error_class_is_health_neutral_for_test(
                ErrorClass::ClientDisconnect
            ));
            assert!(!creator_plan.2.record_once(termination, creator_plan.1));
        } else {
            drop(creator);
            assert_eq!(creator_plan.2.observed(), None);
        }
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(pool.creation_state_for_test(), idle_state);

        let error = waiter.await.unwrap_err();
        assert_eq!(
            h3_connection_checkout_metadata_for_test(&error),
            (None, false, false, ErrorClass::ConnectionRefused)
        );
        assert!(!error.request_on_wire());
        assert_eq!(
            classify_http3_error(error.as_ref()),
            ErrorClass::ConnectionRefused
        );
        assert_eq!(error.to_string(), "fresh waiter dial");
        assert_eq!(waiter_plan.2.observed(), None);
        assert_eq!(waiter_creates.load(Ordering::Relaxed), 1);
        assert_eq!(pool.creation_state_for_test(), idle_state);
        assert_eq!(pool.pool_size(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_cold_checkout_success_after_expiry_cannot_handoff_headers() {
    use ferrum_edge::_test_support::await_native_h3_dispatch_for_test;
    use ferrum_edge::http3::client::await_h3_connection_checkout_for_test;
    use std::sync::OnceLock;

    let plan = plan_after(Duration::from_millis(50));
    let connect_at = OnceLock::new();
    let ready = AtomicBool::new(false);
    let checkout = std::future::poll_fn(|_| {
        if ready.load(Ordering::Relaxed) {
            Poll::Ready(Ok::<(), anyhow::Error>(()))
        } else {
            Poll::Pending
        }
    });
    let mut wait = Box::pin(await_h3_connection_checkout_for_test(
        None,
        Some(&plan),
        &connect_at,
        checkout,
    ));
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(Duration::from_millis(100)).await;
    ready.store(true, Ordering::Relaxed);
    wait.await.unwrap();

    let backend_headers = AtomicUsize::new(0);
    let send = std::future::poll_fn(|_| {
        backend_headers.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok::<(), ferrum_edge::http3::client::H3PoolError>(()))
    });
    assert_eq!(
        await_native_h3_dispatch_for_test(None, Some(&plan), false, send).await,
        Err((Some(StreamAuthTermination::CredentialExpired), false, false))
    );
    assert_eq!(backend_headers.load(Ordering::Relaxed), 0);
    assert_eq!(
        plan.2.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn generic_grpc_late_attempt_clock_cannot_replace_authorization_or_actual_handoff() {
    use ferrum_edge::_test_support::{
        request_upload_auth_deadline_for_test, set_request_credential_deadline_for_test,
    };
    use ferrum_edge::plugins::RequestContext;
    use ferrum_edge::proxy::authorization_dispatch_test_support::{
        authorization_response, charge_route_attempt, log_metadata,
    };
    use std::collections::HashMap;

    for request_on_wire in [false, true] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/pkg.Svc/Call".to_string(),
        );
        ctx.headers
            .insert("content-type".to_string(), "application/grpc".to_string());
        ctx.authenticated_identity = Some("accepted-principal".to_string());
        set_request_credential_deadline_for_test(
            &mut ctx,
            Some(tokio::time::Instant::now() + Duration::from_millis(40)),
        );
        ctx.route_override_attempt_timeout_ms = Some(80);
        ctx.arm_route_request_deadline(true);
        let plan = request_upload_auth_deadline_for_test(&ctx, 900).expect("admitted plan");
        assert_eq!(plan.1, StreamAuthProtocolFamily::Grpc);
        let result = ferrum_edge::_test_support::await_native_h3_dispatch_for_test(
            ctx.grpc_deadline_at(),
            Some(&plan),
            request_on_wire,
            std::future::pending::<Result<(), ferrum_edge::http3::client::H3PoolError>>(),
        )
        .await;
        assert_eq!(
            result,
            Err((
                Some(StreamAuthTermination::CredentialExpired),
                request_on_wire,
                false,
            ))
        );
        // The dispatch already chose authorization. A delayed caller now sees
        // the later route-attempt instant too, and a preparation marker is true.
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut response = authorization_response(request_on_wire);
        let headers = HashMap::from([("content-type".to_string(), "application/grpc".to_string())]);
        assert!(!charge_route_attempt(&ctx, &headers, true, &mut response));
        assert_eq!(response.status_code, 401);
        assert_eq!(response.request_on_wire, request_on_wire);
        assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));
        assert!(!response.connection_error);
        let metadata = log_metadata(&ctx);
        assert_eq!(
            metadata
                .get(ferrum_edge::proxy::auth_lifetime::STREAM_AUTH_TERMINATION_METADATA_KEY)
                .map(String::as_str),
            Some("credential_expired")
        );
        assert!(
            !plan
                .2
                .record_once(StreamAuthTermination::CredentialExpired, plan.1)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn generic_grpc_charges_only_its_deadline_terminal_after_observable_handoff() {
    use ferrum_edge::_test_support::{
        request_upload_auth_deadline_for_test, set_request_credential_deadline_for_test,
    };
    use ferrum_edge::plugins::RequestContext;
    use ferrum_edge::proxy::authorization_dispatch_test_support::{
        authorization_response, charge_route_attempt, client_deadline_response,
    };
    use std::collections::HashMap;

    for content_type in [
        "application/grpc",
        "application/grpc-web+proto",
        "application/grpc-web-text+proto",
    ] {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "POST".to_string(),
            "/pkg.Svc/Call".to_string(),
        );
        ctx.authenticated_identity = Some("accepted-principal".to_string());
        set_request_credential_deadline_for_test(
            &mut ctx,
            Some(tokio::time::Instant::now() + Duration::from_millis(80)),
        );
        let plan = request_upload_auth_deadline_for_test(&ctx, 900).expect("admitted plan");
        ctx.route_override_attempt_timeout_ms = Some(40);
        ctx.arm_route_request_deadline(true);
        let headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
        let mut response = client_deadline_response(&ctx, &headers, false);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            plan.2
                .record_once(StreamAuthTermination::CredentialExpired, plan.1)
        );
        assert!(!charge_route_attempt(&ctx, &headers, true, &mut response));
        assert!(!response.request_on_wire);
        assert_eq!(response.error_class, Some(ErrorClass::ClientDisconnect));

        let mut cancellation = authorization_response(true);
        cancellation.status_code = 502;
        assert!(!charge_route_attempt(
            &ctx,
            &headers,
            true,
            &mut cancellation
        ));
        assert_eq!(cancellation.error_class, Some(ErrorClass::ClientDisconnect));

        let mut response = client_deadline_response(&ctx, &headers, true);
        assert!(charge_route_attempt(&ctx, &headers, true, &mut response));
        assert_eq!(response.error_class, Some(ErrorClass::ReadWriteTimeout));
        assert!(response.request_on_wire);
    }
}

#[test]
fn native_h3_grpc_failure_carrier_keeps_handoff_separate_from_neutral_health() {
    use ferrum_edge::http3::server::h3_grpc_authorization_failure_provenance_for_test;

    assert_eq!(
        h3_grpc_authorization_failure_provenance_for_test(false),
        (false, false, ErrorClass::ClientDisconnect, "pre_wire")
    );
    assert_eq!(
        h3_grpc_authorization_failure_provenance_for_test(true),
        (true, false, ErrorClass::ClientDisconnect, "ambiguous")
    );
    let server = include_str!("../../../src/http3/server.rs");
    let recorder = source_region(
        server,
        "async fn record_failed_h3_grpc_dispatch(",
        "/// Sole owner of the native-H3 gRPC request-upload pump",
    );
    assert!(recorder.contains("record_h3_grpc_dispatch_attempt(ctx, &failure)"));
    assert!(!recorder.contains("request_reached_wire("));
}

const H3_CANDIDATE_HANDSHAKES: &str = concat!(
    "letendpoint=self.get_shared_endpoint(addr.is_ipv6()).await?;",
    "letconnection=endpoint.connect_with(client_config,addr,tls_server_name)?",
    ".await.map_err(|e|anyhow::anyhow!(\"QUICconnectionfailed:{}\",e))?;",
    "letquic_conn=connection.clone();letmutbuilder=h3::client::builder();",
    "builder.max_field_section_size(h3_backend_response_max_field_section_size)",
    ".max_buffered_frame_len(h3_max_buffered_frame_len);",
    "let(mutdriver,send_request)=",
    "boxed_h3_future(||builder.build(h3_quinn::Connection::new(connection)))",
    ".await.map_err(|e|anyhow::anyhow!(\"HTTP/3handshakefailed:{}\",e))?;"
);

const H3_CANDIDATE_AWAIT: &str = concat!(
    ".await.map_err(|error|matcherror{",
    "crate::dns::CandidateConnectError::TimedOut{..}=>{",
    "h3_backend_connect_timeout(proxy,host,port,\"HTTP/3\")}",
    "crate::dns::CandidateConnectError::Failed{source,..}=>source,})?;"
);

fn h3_cold_connect_has_bounded_candidate(constructor: &str) -> bool {
    let compact = compact_code(constructor);
    let Some(open_at) = compact.find('{') else {
        return false;
    };
    let Some((body, _)) = source_group(&compact, open_at) else {
        return false;
    };
    let dns = concat!(
        "letcandidates=resolve_backend_addrs_cached(host,&self.dns_cache,",
        "proxy.dns_override.as_deref(),proxy.dns_cache_ttl_seconds).await?;"
    );
    let arm = concat!(
        "letconnect_timeout=Duration::from_millis(proxy.backend_connect_timeout_ms);",
        "ifletSome(connect_at)=connect_at{",
        "let_=connect_at.set(tokio::time::Instant::now()+connect_timeout);}"
    );
    let call = "let(pooled,addr)=crate::dns::connect_candidates(";
    let Some(call_at) = body.find(call) else {
        return false;
    };
    let Some((args, _)) = source_group(body, call_at + call.len() - 1) else {
        return false;
    };
    let args_prefix = "&candidates,port,connect_timeout,|addr|";
    if !args.starts_with(args_prefix) {
        return false;
    }
    let Some((closure, end)) = source_group(args, args_prefix.len()) else {
        return false;
    };
    if end != args.len() {
        return false;
    }
    let child_prefix = concat!(
        "letclient_config=client_config.clone();letconn_slot=conn_slot.clone();",
        "boxed_h3_future(||asyncmove"
    );
    if !closure.starts_with(child_prefix) {
        return false;
    }
    let Some((child, end)) = source_group(closure, child_prefix.len()) else {
        return false;
    };
    if &closure[end..] != ")" {
        return false;
    }
    let Some(driver) = child.strip_prefix(H3_CANDIDATE_HANDSHAKES) else {
        return false;
    };
    if !driver.starts_with("tokio::spawn(") {
        return false;
    }
    let Some((_, end)) = source_group(driver, "tokio::spawn".len()) else {
        return false;
    };
    if &driver[end..] != ";Ok(H3PooledConnection::new(send_request,quic_conn))" {
        return false;
    }
    let candidate = format!("{call}{args}){H3_CANDIDATE_AWAIT}");
    direct_source_statement(body, dns)
        && direct_source_statement(body, arm)
        && direct_source_statement(body, &candidate)
        && body.matches("resolve_backend_addrs_cached(").count() == 1
        && body.matches("crate::dns::connect_candidates(").count() == 1
        && body.find(dns).is_some_and(|at| {
            body.find(arm).is_some_and(|arm_at| {
                at + dns.len() <= arm_at && arm_at + arm.len() <= call_at
            })
        })
}

#[test]
fn native_h3_cold_connect_bound_keeps_dns_outside_and_quic_h3_readiness_inside() {
    let client = include_str!("../../../src/http3/client.rs");
    for (start, end) in [
        (
            "async fn create_connection(",
            "async fn create_connection_to_target(",
        ),
        (
            "async fn create_connection_to_target(",
            "fn boxed_do_request<'a>(",
        ),
    ] {
        let constructor = source_region(client, start, end);
        let compact = compact_code(constructor);
        let dns = compact
            .find("resolve_backend_addrs_cached(")
            .expect("DNS resolution");
        let connect = compact
            .find("connect_at.set(")
            .expect("captured connect instant");
        let candidate = compact
            .find("crate::dns::connect_candidates(")
            .expect("dial scope");
        let boxed_candidate = compact
            .find("boxed_h3_future(||asyncmove{")
            .expect("boxed authorization-bounded candidate future");
        let quic = compact.find(".connect_with(").expect("QUIC/TLS handshake");
        let h3 = compact
            .find("boxed_h3_future(||builder.build(h3_quinn::Connection::new(connection)))")
            .expect("boxed H3 readiness future");
        assert!(
            dns < connect
                && connect < candidate
                && candidate < boxed_candidate
                && boxed_candidate < quic
                && quic < h3,
            concat!(
                "DNS must precede the authorization envelope, which must contain ",
                "candidate QUIC and H3 readiness: {constructor}"
            ),
            constructor = constructor
        );
        assert!(compact[dns..connect].contains(".await?;"));
        assert!(
            h3_cold_connect_has_bounded_candidate(constructor),
            "the actual boxed candidate must await QUIC/TLS and boxed H3 readiness, \
             propagate both errors, and return its pooled connection: {constructor}"
        );
    }
    assert!(client.contains("#[inline(never)]\nfn boxed_h3_future<F>("));
    let factory = source_region(client, "fn boxed_h3_future<F>(", "\n}\n");
    assert!(factory.contains("Box::pin(construct())"));
    assert!(!factory.contains("async"));
    for creator in [
        "async fn create_or_get_proxy_sender_with_connect_deadline(",
        "async fn create_or_get_target_sender_with_connect_deadline(",
    ] {
        let body = source_region(client, creator, "\n    }\n");
        assert!(body.contains("boxed_h3_future(|| {"));
        assert!(body.contains("self.create_or_get_sender(key, connect_at, create).await"));
    }
    assert_eq!(
        client
            .matches("match await_h3_connection_checkout(auth, &connect_at, create,")
            .count(),
        8
    );
}

#[test]
fn the_h3_cold_connect_source_guard_rejects_candidate_scope_and_completion_bypasses() {
    let client = include_str!("../../../src/http3/client.rs");
    for (start, end) in [
        (
            "async fn create_connection(",
            "async fn create_connection_to_target(",
        ),
        (
            "async fn create_connection_to_target(",
            "fn boxed_do_request<'a>(",
        ),
    ] {
        let constructor = compact_code(source_region(client, start, end));
        assert!(h3_cold_connect_has_bounded_candidate(&constructor));
        for (label, from, to) in [
            (
                "unbounded candidate timeout",
                "connect_candidates(&candidates,port,connect_timeout,",
                "connect_candidates(&candidates,port,Duration::ZERO,",
            ),
            (
                "QUIC future not awaited",
                ".await.map_err(|e|anyhow::anyhow!(\"QUICconnectionfailed:{}\",e))?;",
                ";",
            ),
            (
                "QUIC error not propagated",
                ".connect_with(client_config,addr,tls_server_name)?",
                ".connect_with(client_config,addr,tls_server_name)",
            ),
            (
                "H3 future not boxed",
                "boxed_h3_future(||builder.build(h3_quinn::Connection::new(connection)))",
                "builder.build(h3_quinn::Connection::new(connection))",
            ),
            (
                "H3 future not awaited",
                ".await.map_err(|e|anyhow::anyhow!(\"HTTP/3handshakefailed:{}\",e))?;",
                ";",
            ),
            (
                "H3 error not propagated",
                ".await.map_err(|e|anyhow::anyhow!(\"HTTP/3handshakefailed:{}\",e))?;",
                ".await;",
            ),
            (
                "pooled connection not returned",
                "Ok(H3PooledConnection::new(send_request,quic_conn))",
                "let_=Ok(H3PooledConnection::new(send_request,quic_conn));",
            ),
            (
                "candidate result ignored",
                "let(pooled,addr)=crate::dns::connect_candidates(",
                "let_=crate::dns::connect_candidates(",
            ),
        ] {
            assert!(constructor.contains(from), "mutation must change {label}");
            let mutated = constructor.replacen(from, to, 1);
            assert!(
                !h3_cold_connect_has_bounded_candidate(&mutated),
                "{start}: the source guard must reject {label}"
            );
        }

        // Preserve QUIC-before-H3 order while relocating readiness beyond the
        // complete candidate call. A constructor-wide ordering scan accepts it.
        let readiness = H3_CANDIDATE_HANDSHAKES
            .split("letquic_conn=")
            .nth(1)
            .expect("H3 setup suffix");
        let readiness = format!("letquic_conn={readiness}");
        let without_readiness = constructor.replacen(&readiness, "", 1);
        let moved = without_readiness.replacen(
            H3_CANDIDATE_AWAIT,
            &format!("{H3_CANDIDATE_AWAIT}{readiness}"),
            1,
        );
        assert_ne!(moved, constructor);
        assert!(!h3_cold_connect_has_bounded_candidate(&moved));

        let dns = concat!(
            "letcandidates=resolve_backend_addrs_cached(host,&self.dns_cache,",
            "proxy.dns_override.as_deref(),proxy.dns_cache_ttl_seconds).await?;"
        );
        let without_dns = constructor.replacen(dns, "", 1);
        let moved = without_dns.replacen(
            "boxed_h3_future(||asyncmove{",
            &format!("boxed_h3_future(||asyncmove{{{dns}"),
            1,
        );
        assert_ne!(moved, constructor);
        assert!(!h3_cold_connect_has_bounded_candidate(&moved));
    }
}

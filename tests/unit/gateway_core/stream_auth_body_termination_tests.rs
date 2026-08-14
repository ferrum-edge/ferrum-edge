//! Protocol-correct termination of an admitted response body when the
//! authorization lifetime elapses (issue #3815).
//!
//! Covers: `UNAUTHENTICATED` trailers before any response DATA, deterministic
//! reset after DATA (never a fabricated successful status), the bounded
//! gRPC-Web trailer frame, upstream cancellation, non-extension by activity,
//! earliest-deadline-wins against a client `grpc-timeout`, and the unbounded
//! (unauthenticated) baseline.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    GRPC_FRAME_TRAILER, parse_grpc_frames, proxy_body_into_grpc_web_streaming_for_test,
    proxy_body_streaming_for_test, proxy_body_with_authorization_deadline_and_closer_for_test,
    proxy_body_with_authorization_deadline_for_test, proxy_body_with_client_grpc_deadline_for_test,
};
use ferrum_edge::proxy::auth_lifetime::{
    AuthorizationConnectionCloser, StreamAuthDeadline, StreamAuthProtocolFamily,
    StreamAuthTermination, StreamAuthTerminationLatch,
};
use ferrum_edge::proxy::body::ProxyBodyError;
use futures_util::stream;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};

/// A body that yields the queued frames and then stalls forever, recording how
/// often it was polled and whether it was dropped. Stands in for a backend
/// stream that would keep producing indefinitely.
struct ProbeBody {
    frames: VecDeque<Frame<Bytes>>,
    polls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl http_body::Body for ProbeBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        match self.frames.pop_front() {
            Some(frame) => std::task::Poll::Ready(Some(Ok(frame))),
            None => std::task::Poll::Pending,
        }
    }
}

impl Drop for ProbeBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn elapsed_deadline(termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("one second before now is representable"),
        termination,
    }
}

fn future_deadline(after: Duration, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    }
}

fn pending_body() -> ferrum_edge::proxy::ProxyBody {
    proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::pending::<
        Result<Frame<Bytes>, ProxyBodyError>,
    >())))
}

/// Give the current-thread runtime a scheduling turn so the gateway-owned pump
/// task can run — or, once its body has been dropped, be reaped.
///
/// This is NOT a timing sleep: no wall-clock or virtual time passes. The
/// client-visible terminal is decided synchronously by whichever observer claims
/// the shared bound; RELEASING the upstream is the pump's own work, which the
/// runtime performs when that task is next scheduled.
async fn pump_scheduling_turn() {
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
}

// --- Before response commitment --------------------------------------------

#[tokio::test]
async fn expiry_before_response_data_emits_unauthenticated_grpc_trailers() {
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
        None,
    );

    let frame = body
        .frame()
        .await
        .expect("the deadline must produce a terminal frame")
        .expect("terminal frame must be readable");
    let trailers = frame
        .trailers_ref()
        .expect("native gRPC terminates with HTTP trailers");
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert_eq!(
        trailers.get("grpc-message").unwrap().to_str().unwrap(),
        "credential expired"
    );
    assert!(Body::is_end_stream(&body));
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn the_max_lifetime_class_carries_its_own_bounded_message() {
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
        None,
        // Native gRPC: the only flavor for which `grpc-status` trailers are a
        // legal terminal.
        StreamAuthProtocolFamily::Grpc,
        None,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert_eq!(
        trailers.get("grpc-message").unwrap().to_str().unwrap(),
        "authenticated stream lifetime reached"
    );
}

#[tokio::test]
async fn grpc_web_expiry_emits_the_equivalent_bounded_trailer_frame() {
    let body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        Some("application/grpc-web+proto"),
        StreamAuthProtocolFamily::GrpcWeb,
        None,
    );
    let mut body =
        proxy_body_into_grpc_web_streaming_for_test(body, "application/grpc-web+proto", 200, None);

    let frame = body.frame().await.unwrap().unwrap();
    let data = frame
        .data_ref()
        .expect("gRPC-Web carries terminal metadata as DATA");
    let frames = parse_grpc_frames(data);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
    let rendered = String::from_utf8_lossy(&frames[0].1).to_ascii_lowercase();
    assert!(
        rendered.contains("grpc-status: 16"),
        "expected UNAUTHENTICATED, got {rendered:?}"
    );
    assert!(Body::is_end_stream(&body));
}

#[tokio::test]
async fn plain_http_expiry_before_data_never_fabricates_grpc_trailers() {
    // The generic H1/H2/H3-downstream funnel carries chunked HTTP and SSE, not
    // just gRPC. An ordinary HTTP response has NO terminal status metadata, so
    // the only protocol-correct termination is a deterministic end of the body
    // as an error (resetting H2/H3, terminating an H1 chunked/SSE body) — never
    // synthesized `grpc-status` trailers for a client that never spoke gRPC,
    // and never a clean EOF that would look like a complete response.
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    );

    let message = match body
        .frame()
        .await
        .expect("the deadline must terminate the body")
    {
        Ok(frame) => panic!(
            "plain HTTP must not fabricate gRPC terminal metadata; got trailers={:?} data={:?}",
            frame.trailers_ref(),
            frame.data_ref()
        ),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("authenticated stream terminated"),
        "unexpected terminal message: {message}"
    );
    // Redacted: no expiry value, identity, claim, or provider detail.
    assert!(!message.chars().any(|c| c.is_ascii_digit()));
    assert!(Body::is_end_stream(&body));
    assert!(body.frame().await.is_none(), "no second completion");
}

#[tokio::test]
async fn a_grpc_web_stream_without_a_content_type_does_not_fall_back_to_native_trailers() {
    // Defensive: gRPC-Web's only legal terminal is the bounded body-framed
    // trailer frame. With no content type to build one, terminate the stream
    // rather than emitting native trailers a gRPC-Web client cannot read.
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::GrpcWeb,
        None,
    );

    assert!(
        body.frame()
            .await
            .expect("the deadline must terminate the body")
            .is_err()
    );
}

#[tokio::test]
async fn the_shared_latch_records_exactly_one_termination_per_request() {
    // The request-upload body and the response body race the same absolute
    // plan on a bidirectional stream. The latch is what makes the pair record
    // one termination for the stream instead of two.
    // The family here is incidental to the latch contract; `GrpcWeb` keeps
    // this test's counter increments clear of the delta assertions other tests
    // in this binary make on the `http` / `stream_udp` families.
    let latch = StreamAuthTerminationLatch::default();
    assert_eq!(latch.observed(), None);
    assert!(
        latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::GrpcWeb
        ),
        "the first direction to fire owns the termination"
    );
    assert!(
        !latch.record_once(
            StreamAuthTermination::CredentialExpired,
            StreamAuthProtocolFamily::GrpcWeb
        ),
        "the opposite direction must not count a second termination"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    // A cloned handle is the same latch.
    let cloned = latch.clone();
    assert!(!cloned.record_once(
        StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        StreamAuthProtocolFamily::Grpc
    ));
    assert_eq!(
        cloned.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the first class wins; a later firing cannot restate it"
    );
}

// --- After response commitment ---------------------------------------------

#[tokio::test]
async fn expiry_after_response_data_resets_instead_of_fabricating_a_status() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let inner = ProbeBody {
        frames: VecDeque::from(vec![Frame::data(Bytes::from_static(b"event: tick\n\n"))]),
        polls: Arc::clone(&polls),
        dropped: Arc::clone(&dropped),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_millis(60),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    );

    // One SSE event is committed downstream.
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(
        first.data_ref().unwrap().as_ref(),
        b"event: tick\n\n".as_slice()
    );

    // The deadline then fires. A complete message boundary cannot be proven, so
    // the body ends with a transport error — never a successful terminal status.
    let message = match body
        .frame()
        .await
        .expect("the deadline must terminate the body")
    {
        Ok(_) => panic!(
            "post-commitment expiry must not fabricate a successful terminal status or frame"
        ),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("authorization") || message.contains("credential expired"),
        "unexpected terminal message: {message}"
    );
    // Bounded and redacted: no expiry value, identity, or provider detail.
    assert!(!message.chars().any(|c| c.is_ascii_digit()));

    assert!(Body::is_end_stream(&body));
    assert!(
        dropped.load(Ordering::SeqCst),
        "upstream work must be cancelled when the deadline fires"
    );
}

#[tokio::test]
async fn the_upstream_body_is_dropped_exactly_once_at_expiry() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let inner = ProbeBody {
        frames: VecDeque::new(),
        polls: Arc::clone(&polls),
        dropped: Arc::clone(&dropped),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
        None,
    );

    let _terminal = body.frame().await.unwrap().unwrap();
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "an already-elapsed deadline is checked before the inner body is polled"
    );
    pump_scheduling_turn().await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "claiming the bound cancels the gateway-owned pump, whose drop releases the upstream"
    );
    // Draining again must not produce a second completion.
    assert!(body.frame().await.is_none());
    assert!(body.frame().await.is_none());
}

// --- Non-extension and composition -----------------------------------------

#[tokio::test(start_paused = true)]
async fn continuous_activity_never_extends_the_authorization_deadline() {
    // A backend that always has another frame ready never yields a `Pending`
    // inner poll, so an idle-style timer would never fire. The absolute deadline
    // is checked on EVERY poll and must still fire.
    let frames: VecDeque<Frame<Bytes>> = (0..1_000)
        .map(|_| Frame::data(Bytes::from_static(b"data: x\n\n")))
        .collect();
    let inner = ProbeBody {
        frames,
        polls: Arc::new(AtomicUsize::new(0)),
        dropped: Arc::new(AtomicBool::new(false)),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    );

    for _ in 0..5 {
        let frame = body.frame().await.unwrap().unwrap();
        assert!(frame.data_ref().is_some());
    }

    tokio::time::advance(Duration::from_secs(31)).await;

    let terminal = body.frame().await.unwrap();
    assert!(
        terminal.is_err(),
        "a continuously active stream must still be terminated at its deadline"
    );
}

#[tokio::test]
async fn an_unexpired_deadline_passes_frames_through_untouched() {
    let inner = StreamBody::new(stream::iter(vec![
        Ok::<_, ProxyBodyError>(Frame::data(Bytes::from_static(b"one"))),
        Ok(Frame::data(Bytes::from_static(b"two"))),
    ]));
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_secs(3_600),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    );

    assert_eq!(
        body.frame()
            .await
            .unwrap()
            .unwrap()
            .data_ref()
            .unwrap()
            .as_ref(),
        b"one".as_slice()
    );
    assert_eq!(
        body.frame()
            .await
            .unwrap()
            .unwrap()
            .data_ref()
            .unwrap()
            .as_ref(),
        b"two".as_slice()
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn an_earlier_client_grpc_timeout_wins_over_a_later_credential_deadline() {
    // The client deadline is installed first (inner), the authorization deadline
    // second (outer), exactly as the response funnels stack them. The earlier of
    // the two must decide the terminal status, and only one completion may occur.
    let body = proxy_body_with_client_grpc_deadline_for_test(
        pending_body(),
        tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
        None,
    );
    let mut body = proxy_body_with_authorization_deadline_for_test(
        body,
        future_deadline(
            Duration::from_secs(3_600),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Grpc,
        None,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().expect("trailers");
    assert_eq!(
        trailers.get("grpc-status").unwrap().to_str().unwrap(),
        "4",
        "the earlier client grpc-timeout must decide the terminal status"
    );
    assert!(body.frame().await.is_none(), "no second completion");
}

#[tokio::test]
async fn an_earlier_credential_deadline_wins_over_a_later_client_grpc_timeout() {
    let body = proxy_body_with_client_grpc_deadline_for_test(
        pending_body(),
        tokio::time::Instant::now() + Duration::from_secs(3_600),
        None,
    );
    let mut body = proxy_body_with_authorization_deadline_for_test(
        body,
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
        None,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().expect("trailers");
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert!(body.frame().await.is_none(), "no second completion");
}

// --- Buffered and unbounded baselines --------------------------------------

#[tokio::test]
async fn a_buffered_body_is_already_committed_and_is_returned_unchanged() {
    use ferrum_edge::proxy::ProxyBody;

    let mut body = proxy_body_with_authorization_deadline_for_test(
        ProxyBody::from_string("hello"),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    );

    let frame = body.frame().await.unwrap().unwrap();
    assert_eq!(frame.data_ref().unwrap().as_ref(), b"hello".as_slice());
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn a_body_with_no_authorization_deadline_streams_to_completion() {
    let inner = StreamBody::new(stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
        Bytes::from_static(b"public"),
    ))]));
    let mut body = proxy_body_streaming_for_test(Box::pin(inner));

    assert_eq!(
        body.frame()
            .await
            .unwrap()
            .unwrap()
            .data_ref()
            .unwrap()
            .as_ref(),
        b"public".as_slice()
    );
    assert!(body.frame().await.is_none());
}

// --- The gateway-owned response watchdog (issue #3815) ----------------------
//
// `TotalDeadlineBody` fires only when hyper POLLS the response body, and hyper
// does not poll it while its HTTP/2 pipe is parked on `poll_capacity` (a client
// advertising a zero initial window, or simply withholding `WINDOW_UPDATE`) or
// its HTTP/1.1 connection is parked flushing a socket the client stopped
// reading. Both are client-controlled. These cover the two gateway-owned
// mechanisms that make the deadline enforceable anyway.

fn probe_body(
    polls: &Arc<AtomicUsize>,
    dropped: &Arc<AtomicBool>,
) -> ferrum_edge::proxy::ProxyBody {
    proxy_body_streaming_for_test(Box::pin(ProbeBody {
        frames: VecDeque::new(),
        polls: Arc::clone(polls),
        dropped: Arc::clone(dropped),
    }))
}

#[tokio::test(start_paused = true)]
async fn the_watchdog_releases_the_upstream_while_the_transport_polls_nothing() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let fired = Arc::new(AtomicBool::new(false));
    let latch = StreamAuthTerminationLatch::default();
    let body = ferrum_edge::_test_support::authorization_cancellable_body_for_test(
        probe_body(&polls, &dropped),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        StreamAuthProtocolFamily::GrpcWeb,
        latch.clone(),
        Arc::clone(&fired),
        None,
    );
    assert!(!body.upstream_released());

    // Nothing polls the body — the whole point of the watchdog.
    tokio::time::sleep(Duration::from_secs(6)).await;

    assert!(
        polls.load(Ordering::SeqCst) >= 1,
        "the GATEWAY owns and polls the upstream now, so progress does not depend on the          transport polling this body — which it never did here, exactly as a zero-credit          HTTP/2 client forces"
    );
    assert!(
        body.upstream_released(),
        "the gateway must release the backend body from its own task"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the backend body must be DROPPED — releasing the upstream stream, its pooled \
         connection, and every guard rooted in it — not merely detached"
    );
    assert!(
        fired.load(Ordering::Acquire),
        "the shared flag is what classifies the eventual ProxyBody drop as a health-neutral \
         authorization termination rather than a client disconnect"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
}

#[tokio::test(start_paused = true)]
async fn a_downstream_that_never_drains_the_terminal_is_closed_at_the_transport() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let _body =
        ferrum_edge::_test_support::proxy_body_with_authorization_deadline_and_closer_for_test(
            probe_body(&polls, &dropped),
            future_deadline(
                Duration::from_secs(5),
                StreamAuthTermination::CredentialExpired,
            ),
            StreamAuthProtocolFamily::Http,
            Some(latch.clone()),
            closer.clone(),
        );

    // Upstream release happens AT the deadline, before any grace.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "the backend body must be released at the deadline, not at the end of the grace"
    );
    assert!(
        !closer.close_requested(),
        "the downstream still has its bounded grace to drain the terminal"
    );

    tokio::time::sleep(grace + Duration::from_secs(1)).await;
    assert!(
        closer.close_requested(),
        "a downstream that never drains the terminal must have its connection closed, or the \
         request guard, per-IP guard, admission permits, and load-balancer accounting held by \
         the response body are retained at the client's discretion"
    );

    // Exactly one termination for the stream, whichever mechanism settled it.
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(!latch.record_once(
        StreamAuthTermination::CredentialExpired,
        StreamAuthProtocolFamily::Http
    ));
    assert!(
        polls.load(Ordering::SeqCst) >= 1,
        "the gateway-owned pump is what made progress; no poll of the CLIENT-VISIBLE body          was needed to reach either outcome"
    );
}

#[tokio::test(start_paused = true)]
async fn a_drained_terminal_never_costs_the_client_its_connection() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body =
        ferrum_edge::_test_support::proxy_body_with_authorization_deadline_and_closer_for_test(
            pending_body(),
            future_deadline(
                Duration::from_secs(2),
                StreamAuthTermination::CredentialExpired,
            ),
            StreamAuthProtocolFamily::Http,
            Some(latch.clone()),
            closer.clone(),
        );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let terminal = body
        .frame()
        .await
        .expect("the elapsed deadline must produce a terminal");
    assert!(
        terminal.is_err(),
        "an ordinary HTTP/SSE response has no terminal metadata, so it ends with a transport \
         error rather than a clean, complete-looking end of body"
    );
    drop(body);

    tokio::time::sleep(grace * 2 + Duration::from_secs(1)).await;
    assert!(
        !closer.close_requested(),
        "a client that drained the terminal must keep its connection: the transport close is a \
         last resort, not the normal path"
    );
}

// --- The gateway-owned response pump: terminal-winner authority -------------
//
// The upstream body is owned by ONE task, which decides in ONE biased `select!`
// whether this response completed or expired. There is no shared mutex on the
// response path and no check-then-act window in which a watchdog can count a
// response that had already finished, or in which a finishing poll can escape a
// deadline that had already elapsed.

/// A body that yields a ready DATA frame forever. Stands in for a backend that
/// keeps producing while the client stops reading, which is what fills the
/// pump's bounded channel.
struct FloodBody {
    dropped: Arc<AtomicBool>,
}

impl http_body::Body for FloodBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"flood")))))
    }
}

impl Drop for FloodBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn pump_body(
    inner: ferrum_edge::proxy::ProxyBody,
    deadline: StreamAuthDeadline,
    latch: &StreamAuthTerminationLatch,
    fired: &Arc<AtomicBool>,
    closer: Option<AuthorizationConnectionCloser>,
) -> ferrum_edge::proxy::response_watchdog::AuthorizationCancellableBody {
    ferrum_edge::_test_support::authorization_cancellable_body_for_test(
        inner,
        deadline,
        StreamAuthProtocolFamily::Http,
        latch.clone(),
        Arc::clone(fired),
        closer,
    )
}

#[tokio::test(start_paused = true)]
async fn a_response_that_completed_before_the_deadline_is_never_counted_or_closed() {
    let latch = StreamAuthTerminationLatch::default();
    let fired = Arc::new(AtomicBool::new(false));
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body = pump_body(
        proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::iter(vec![Ok::<
            _,
            ProxyBodyError,
        >(
            Frame::data(Bytes::from_static(b"complete")),
        )])))),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &fired,
        Some(closer.clone()),
    );

    // Drained to a clean end of stream WELL before the deadline.
    assert_eq!(
        body.frame()
            .await
            .expect("one data frame")
            .expect("frame is not an error")
            .data_ref()
            .expect("data frame")
            .as_ref(),
        b"complete".as_slice()
    );
    assert!(
        body.frame().await.is_none(),
        "a clean upstream EOF must stay a clean end of stream, never a synthesized error"
    );

    tokio::time::sleep(Duration::from_secs(10) + grace).await;
    assert_eq!(
        latch.observed(),
        None,
        "a response that completed before the deadline is NOT an authorization termination, \
         however long the transport then holds the finished body"
    );
    assert!(
        !fired.load(Ordering::Acquire),
        "the classification flag must stay clear for a completed response"
    );
    assert!(
        !closer.close_requested(),
        "a completed response must never cost the client its connection"
    );
}

#[tokio::test(start_paused = true)]
async fn an_upstream_error_immediately_before_the_deadline_stays_an_error() {
    let latch = StreamAuthTerminationLatch::default();
    let fired = Arc::new(AtomicBool::new(false));
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body =
        pump_body(
            proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::iter(vec![Err::<
                Frame<Bytes>,
                ProxyBodyError,
            >(
                Box::new(std::io::Error::other("backend failed")) as ProxyBodyError,
            )])))),
            future_deadline(
                Duration::from_secs(5),
                StreamAuthTermination::CredentialExpired,
            ),
            &latch,
            &fired,
            Some(closer.clone()),
        );

    let terminal = body.frame().await.expect("a terminal frame");
    let error = terminal.expect_err("an upstream error must stay an error");
    assert!(
        error.to_string().contains("backend failed"),
        "the upstream error must be delivered verbatim, never collapsed into a clean EOF or \
         replaced by the authorization terminal"
    );
    assert!(body.frame().await.is_none());

    tokio::time::sleep(Duration::from_secs(10) + grace).await;
    assert_eq!(
        latch.observed(),
        None,
        "a backend failure before the deadline is not an authorization termination"
    );
    assert!(!fired.load(Ordering::Acquire));
    assert!(!closer.close_requested());
}

#[tokio::test(start_paused = true)]
async fn at_the_exact_deadline_the_security_bound_wins_over_a_ready_frame() {
    let latch = StreamAuthTerminationLatch::default();
    let fired = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    // `at` is exactly now: the expiry timer and the ready upstream frame become
    // eligible in the SAME poll. The biased select must resolve that tie to the
    // security decision, deterministically, every time.
    let mut body = pump_body(
        proxy_body_streaming_for_test(Box::pin(FloodBody {
            dropped: Arc::clone(&dropped),
        })),
        StreamAuthDeadline {
            at: tokio::time::Instant::now(),
            termination: StreamAuthTermination::CredentialExpired,
        },
        &latch,
        &fired,
        None,
    );

    let terminal = body.frame().await.expect("a terminal");
    assert!(
        terminal.is_err(),
        "a tie at the exact deadline must terminate, never deliver the simultaneously ready \
         protected frame"
    );
    // Claimed and accounted by this very poll, with the pump not yet scheduled.
    assert!(fired.load(Ordering::Acquire));
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );

    pump_scheduling_turn().await;
    assert!(
        body.upstream_released(),
        "the upstream must be released at the tie, not after one more frame"
    );
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_full_channel_cannot_postpone_the_deadline() {
    let latch = StreamAuthTerminationLatch::default();
    let fired = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let body = pump_body(
        proxy_body_streaming_for_test(Box::pin(FloodBody {
            dropped: Arc::clone(&dropped),
        })),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::AuthenticatedStreamMaxLifetime,
        ),
        &latch,
        &fired,
        None,
    );

    // A backend producing without pause plus a downstream that never reads
    // fills the pump's one-frame channel immediately and parks it on `reserve`.
    // Backpressure may delay delivery; it may never delay enforcement.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        body.upstream_released(),
        "the deadline arm must win over a full channel"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the flooding backend body must be dropped at the deadline"
    );
    assert!(fired.load(Ordering::Acquire));
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::AuthenticatedStreamMaxLifetime)
    );
}

#[tokio::test(start_paused = true)]
async fn dropping_the_response_body_cancels_the_pump_and_releases_the_upstream() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let fired = Arc::new(AtomicBool::new(false));
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let body = pump_body(
        probe_body(&polls, &dropped),
        future_deadline(
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &fired,
        Some(closer.clone()),
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !dropped.load(Ordering::SeqCst),
        "the pump owns the upstream while the body lives"
    );

    drop(body);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "cancellation must terminate the pump and RELEASE the upstream — no detached producer \
         may survive the response body"
    );

    tokio::time::sleep(grace * 2 + Duration::from_secs(1)).await;
    assert_eq!(
        latch.observed(),
        None,
        "a cancelled body is a client disconnect, not an authorization termination"
    );
    assert!(!fired.load(Ordering::Acquire));
    assert!(
        !closer.close_requested(),
        "a connection whose body was already dropped needs no transport close"
    );
}

// --- The pump is the SOLE terminal winner -----------------------------------
//
// These exercise the FULL wrapped body — the client-visible `ProxyBody` the
// dispatch funnels actually build, protocol terminal adapter included — rather
// than the pump in isolation, and they deliberately let the pump reach its own
// terminal WITHOUT draining it downstream. That is the backpressure shape the
// contract has to survive: hyper does not poll a response body while its HTTP/2
// pipe is parked on `poll_capacity` or its HTTP/1.1 connection is parked
// flushing a socket the client stopped reading, so a response that completed
// well before the deadline can easily not be polled until well after it. An
// adapter with an authorization timer of its own would overwrite that completed
// terminal, count the stream, and close the connection.

/// A body the gateway funnel would build for an ordinary authenticated HTTP or
/// SSE response: the wrapped `ProxyBody`, with the transport close signal the
/// connection handlers install.
fn wrapped_body(
    inner: ferrum_edge::proxy::ProxyBody,
    deadline: StreamAuthDeadline,
    latch: &StreamAuthTerminationLatch,
    closer: &AuthorizationConnectionCloser,
) -> ferrum_edge::proxy::ProxyBody {
    proxy_body_with_authorization_deadline_and_closer_for_test(
        inner,
        deadline,
        StreamAuthProtocolFamily::Http,
        Some(latch.clone()),
        closer.clone(),
    )
}

fn stream_of(frames: Vec<Result<Frame<Bytes>, ProxyBodyError>>) -> ferrum_edge::proxy::ProxyBody {
    proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::iter(frames))))
}

#[tokio::test(start_paused = true)]
async fn a_clean_eof_reached_before_the_deadline_survives_a_downstream_that_polls_after_it() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body = wrapped_body(
        stream_of(Vec::new()),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &closer,
    );

    // The pump reaches the upstream's clean end of stream and queues its
    // terminal here, with the downstream polling NOTHING.
    tokio::time::sleep(Duration::from_secs(1)).await;
    // The transport stays parked well past the deadline and its grace.
    tokio::time::sleep(Duration::from_secs(10) + grace).await;

    assert!(
        body.frame().await.is_none(),
        "the terminal the pump decided BEFORE the deadline must win; a clean end of stream may \
         not be overwritten by an authorization terminal just because the transport was parked \
         past the deadline"
    );
    assert_eq!(
        latch.observed(),
        None,
        "a response that completed before the deadline is not an authorization termination, so \
         nothing may be latched or counted for it"
    );
    assert!(
        !closer.close_requested(),
        "a completed response must never cost the client its connection"
    );
}

#[tokio::test(start_paused = true)]
async fn a_drained_frame_then_a_pre_deadline_eof_still_ends_cleanly_after_the_deadline() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body = wrapped_body(
        stream_of(vec![Ok(Frame::data(Bytes::from_static(b"payload")))]),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &closer,
    );

    // One frame is delivered, which frees the pump's single-slot channel; the
    // pump then reads the upstream's clean EOF and queues it.
    assert_eq!(
        body.frame()
            .await
            .expect("one data frame")
            .expect("frame is not an error")
            .data_ref()
            .expect("data frame")
            .as_ref(),
        b"payload".as_slice()
    );
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Now the client stops reading entirely — the parked-transport case — and
    // does not poll again until long after the deadline and its grace.
    tokio::time::sleep(Duration::from_secs(10) + grace).await;

    assert!(
        body.frame().await.is_none(),
        "the queued clean end of stream must still be the terminal the client observes"
    );
    assert_eq!(latch.observed(), None);
    assert!(!closer.close_requested());
}

#[tokio::test(start_paused = true)]
async fn an_upstream_error_reached_before_the_deadline_survives_a_late_downstream_poll() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body = wrapped_body(
        stream_of(vec![Err(
            Box::new(std::io::Error::other("backend failed")) as ProxyBodyError
        )]),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &closer,
    );

    tokio::time::sleep(Duration::from_secs(1)).await;
    tokio::time::sleep(Duration::from_secs(10) + grace).await;

    let error = body
        .frame()
        .await
        .expect("a terminal frame")
        .expect_err("an upstream error must stay an error");
    assert!(
        error.to_string().contains("backend failed"),
        "the backend failure the pump decided before the deadline must reach the client \
         verbatim, never be replaced by the authorization terminal: {error}"
    );
    assert_eq!(
        latch.observed(),
        None,
        "a backend failure before the deadline is not an authorization termination"
    );
    assert!(!closer.close_requested());
}

#[tokio::test(start_paused = true)]
async fn a_response_still_in_flight_at_the_deadline_is_still_terminated_for_a_parked_client() {
    // The complement of the three above: deferring the decision to the pump
    // must not weaken enforcement. Nothing here ever completes, the downstream
    // never polls before the deadline, and the termination must still be
    // latched and the connection still closed.
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let grace = ferrum_edge::_test_support::authorization_transport_close_grace();
    let mut body = wrapped_body(
        pending_body(),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &closer,
    );

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the gateway-owned pump must still enforce the deadline off-poll"
    );

    tokio::time::sleep(grace + Duration::from_secs(1)).await;
    assert!(
        closer.close_requested(),
        "a downstream that never drains the terminal must still lose its connection"
    );

    let error = body
        .frame()
        .await
        .expect("a terminal frame")
        .expect_err("an expired stream must end with an error, never a clean EOF");
    assert!(
        error.to_string().contains("credential expired"),
        "the client-visible terminal must still be the fixed authorization message: {error}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_exact_deadline_still_resolves_to_the_security_decision_through_the_full_body() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut body = wrapped_body(
        proxy_body_streaming_for_test(Box::pin(FloodBody {
            dropped: Arc::clone(&dropped),
        })),
        StreamAuthDeadline {
            at: tokio::time::Instant::now(),
            termination: StreamAuthTermination::CredentialExpired,
        },
        &latch,
        &closer,
    );

    let terminal = body.frame().await.expect("a terminal");
    assert!(
        terminal.is_err(),
        "a tie at the exact deadline must terminate, never deliver the simultaneously ready \
         protected frame"
    );
    // Claimed synchronously by this poll, so the accounting is settled before
    // the pump has been scheduled even once.
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    pump_scheduling_turn().await;
    assert!(dropped.load(Ordering::SeqCst));
}

// --- One winner, decided by a CAS (issue #3815) ------------------------------
//
// The gateway-owned pump and the protocol adapter that wraps it are two
// independently scheduled observers of ONE response, and which of them settles
// it may not depend on the runtime's scheduling order. These drive the
// interleaving directly — an explicit claim, a manual poll with no scheduling
// turn, a frame parked in the pump's channel across the bound — instead of
// racing two tasks, so each window is exercised on every run.

type TerminalOwner = ferrum_edge::_test_support::AuthorizationTerminalOwnerForTest;
type TerminalOwnership = ferrum_edge::_test_support::AuthorizationTerminalOwnershipForTest;

/// Poll the client-visible body exactly once with a no-op waker, WITHOUT giving
/// the runtime a chance to schedule the gateway-owned pump.
fn poll_once<B>(body: &mut B) -> std::task::Poll<Option<Result<Frame<Bytes>, ProxyBodyError>>>
where
    B: Body<Data = Bytes, Error = ProxyBodyError> + Unpin,
{
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    std::pin::Pin::new(body).poll_frame(&mut cx)
}

#[tokio::test(start_paused = true)]
async fn a_poll_that_reaches_the_bound_claims_it_with_no_timer_having_run() {
    let owner = TerminalOwner::new(tokio::time::Instant::now() + Duration::from_secs(5));
    assert_eq!(owner.observe(), TerminalOwnership::Open);
    assert!(!owner.expiry_claimed());

    // Exactly AT the bound: the observing poll itself settles it. No task ran,
    // no timer fired, no channel closed — which is what keeps enforcement off
    // the runtime's scheduling order.
    tokio::time::advance(Duration::from_secs(5)).await;
    assert_eq!(owner.observe(), TerminalOwnership::AuthorizationExpiry);
    assert!(owner.expiry_claimed());
}

#[tokio::test(start_paused = true)]
async fn a_completion_claimed_before_the_bound_survives_an_arbitrarily_late_observation() {
    let owner = TerminalOwner::new(tokio::time::Instant::now() + Duration::from_secs(5));
    assert!(owner.claim_inner_completion());

    // The transport is parked on flow control for ten minutes. The response
    // still completed, so nothing may reclassify it.
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(owner.observe(), TerminalOwnership::InnerCompletion);
    assert!(!owner.expiry_claimed());
    assert_eq!(
        owner.claim_authorization_expiry(),
        TerminalOwnership::InnerCompletion,
        "the first claim is final; a later deadline arm cannot take the response back"
    );
}

#[tokio::test(start_paused = true)]
async fn a_completion_reached_at_or_after_the_bound_is_refused_fail_closed() {
    let owner = TerminalOwner::new(tokio::time::Instant::now() + Duration::from_secs(5));
    tokio::time::advance(Duration::from_secs(5)).await;

    assert!(
        !owner.claim_inner_completion(),
        "the upstream's own terminal is claimable only while the credential is still \
         authorized — a tokio timer that has not fired yet may not widen that window"
    );
    assert_eq!(
        owner.observe(),
        TerminalOwnership::AuthorizationExpiry,
        "a refused completion settles the response as an expiry, not as unclaimed"
    );
}

#[tokio::test(start_paused = true)]
async fn only_the_first_claim_of_the_bound_counts() {
    let owner = TerminalOwner::new(tokio::time::Instant::now() + Duration::from_secs(5));
    tokio::time::advance(Duration::from_secs(6)).await;

    assert_eq!(
        owner.claim_authorization_expiry(),
        TerminalOwnership::AuthorizationExpiry
    );
    assert_eq!(
        owner.claim_authorization_expiry(),
        TerminalOwnership::AuthorizationExpiry,
        "re-claiming is idempotent, so the pump's deadline arm and an adapter poll may \
         both run it"
    );
    assert!(!owner.claim_inner_completion());
}

#[tokio::test]
async fn a_poll_after_the_bound_settles_the_protocol_terminal_without_the_pump() {
    // NOTHING has been awaited since this body was built, so the gateway-owned
    // pump task has provably not been polled even once. This is the exact
    // interleaving a "did the pump decide?" boolean cannot survive: the observer
    // is at/after the bound and the pump has not spoken.
    let latch = StreamAuthTerminationLatch::default();
    let mut body = Box::pin(proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
        Some(latch.clone()),
    ));

    let frame = match poll_once(&mut body) {
        std::task::Poll::Ready(Some(Ok(frame))) => frame,
        _ => panic!("the bound must settle in this very poll, never park on the pump"),
    };
    let trailers = frame
        .trailers_ref()
        .expect("native gRPC terminates with HTTP trailers");
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired),
        "the claiming observer records the bounded class itself"
    );
}

#[tokio::test]
async fn the_client_never_sees_the_pumps_generic_released_upstream_message() {
    // Ordinary HTTP/SSE has no terminal metadata, so the terminal is an error —
    // but it must be the FIXED authorization message, not the pump's internal
    // released-upstream one, which is what a lost check-then-act race delivered.
    let mut body = Box::pin(proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Http,
        None,
    ));

    let error = match poll_once(&mut body) {
        std::task::Poll::Ready(Some(Err(error))) => error.to_string(),
        _ => panic!("an expired HTTP/SSE response must end with a transport error"),
    };
    assert!(
        error.contains("credential expired"),
        "the client-visible terminal must be the fixed authorization message: {error}"
    );
    assert!(
        !error.contains("upstream released"),
        "the pump's internal released-upstream terminal must never reach a client: {error}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_frame_queued_before_the_bound_is_never_delivered_after_it() {
    let latch = StreamAuthTerminationLatch::default();
    let closer = AuthorizationConnectionCloser::new();
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    // One protected frame, then a backend that never produces again. The pump
    // reads that frame while the credential is still authorized and parks it in
    // its one-slot channel, because the downstream is not reading.
    let mut body = wrapped_body(
        proxy_body_streaming_for_test(Box::pin(ProbeBody {
            frames: VecDeque::from(vec![Frame::data(Bytes::from_static(b"protected"))]),
            polls: Arc::clone(&polls),
            dropped: Arc::clone(&dropped),
        })),
        future_deadline(
            Duration::from_secs(5),
            StreamAuthTermination::CredentialExpired,
        ),
        &latch,
        &closer,
    );

    // The pump queues the frame here, with the transport polling nothing...
    tokio::time::sleep(Duration::from_secs(1)).await;
    // ...and the bound then elapses with that protected frame still queued.
    tokio::time::sleep(Duration::from_secs(5)).await;

    let error = body
        .frame()
        .await
        .expect("a terminal")
        .expect_err("the queued protected frame must not be delivered");
    assert!(
        error.to_string().contains("credential expired"),
        "a frame queued before the bound must lose to the authorization terminal: {error}"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the upstream is released at the bound, not after the queued frame drains"
    );
    assert_eq!(
        latch.observed(),
        Some(StreamAuthTermination::CredentialExpired)
    );
    assert!(body.frame().await.is_none(), "no second completion");
}

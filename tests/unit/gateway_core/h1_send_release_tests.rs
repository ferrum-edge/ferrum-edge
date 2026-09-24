//! Regressions for the HTTP/1.1 sender release (issue #5720).
//!
//! The HBONE inner HTTP/1.1 pool and the Unix-socket backend pool hold the
//! connection's only `SendRequest` while they await the response. A request
//! published by tokio's two-step channel send just after the connection task
//! drained its queue and exited is never dequeued, and its callback only fires
//! when the last sender drops — so, held, it waits for
//! `backend_read_timeout_ms`, or forever when that is `0`.
//!
//! The race sits between two instructions inside tokio's
//! `UnboundedSender::send`, so no public API can schedule it. These tests build
//! the state it leaves behind directly, mirroring the vendored hyper-util
//! regressions for #5714: a queued request whose callback fires only when the
//! connection handle drops, on a connection whose dispatcher has stopped
//! reading. They poll by hand with no timers and no threads. The last two
//! tests pin the real hyper behaviour the watch relies on. That both dispatch
//! call sites use it is pinned in `shared_invariant_parity_tests.rs`.

use bytes::Bytes;
use ferrum_edge::proxy::h1_send_release::await_h1_response_or_release;
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use tokio::sync::oneshot;

type Callback = oneshot::Sender<Result<&'static str, &'static str>>;

/// What hyper's `Envelope::drop` reports: a canceled error that hands the
/// unsent request back.
const CANCELED_UNSENT: &str = "canceled: connection closed, request returned";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DispatchState {
    /// Serving, or about to serve; has not asked for more work.
    Busy,
    /// Asked for another request after the queued one was published.
    Wanting,
    /// Closed its queue, or is gone.
    Closed,
}

/// The dispatcher side of hyper's `want` handshake.
struct Dispatcher {
    state: DispatchState,
    waker: Option<Waker>,
    polls: usize,
}

type SharedDispatcher = Arc<Mutex<Dispatcher>>;

fn set_state(dispatcher: &SharedDispatcher, state: DispatchState) {
    let waker = {
        let mut dispatcher = dispatcher.lock().unwrap();
        dispatcher.state = state;
        dispatcher.waker.take()
    };
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn readiness_polls(dispatcher: &SharedDispatcher) -> usize {
    dispatcher.lock().unwrap().polls
}

/// The pooled lease: it owns the only sender of the request queue, and so the
/// stranded envelope in it. Dropping it drops the queue, and the envelope fails
/// its callback with the unsent request, as hyper's `Envelope::drop` does.
struct Lease {
    dispatcher: SharedDispatcher,
    stranded: Option<Callback>,
    drops: Arc<AtomicUsize>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(callback) = self.stranded.take() {
            let _ = callback.send(Err(CANCELED_UNSENT));
        }
    }
}

/// `SendRequest::poll_ready` as the dispatch maps it.
fn poll_lease(lease: &mut Lease, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
    let mut dispatcher = lease.dispatcher.lock().unwrap();
    dispatcher.polls += 1;
    match dispatcher.state {
        DispatchState::Busy => {
            dispatcher.waker = Some(cx.waker().clone());
            Poll::Pending
        }
        DispatchState::Wanting => Poll::Ready(Ok(())),
        DispatchState::Closed => Poll::Ready(Err(())),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Published into the queue after the dispatcher's last drain.
    Stranded,
    /// Dequeued by the dispatcher, which owns its callback.
    InFlight,
}

struct Fixture {
    dispatcher: SharedDispatcher,
    drops: Arc<AtomicUsize>,
    lease: Lease,
    response: oneshot::Receiver<Result<&'static str, &'static str>>,
    /// `Some` for an in-flight request: the dispatcher's end of the callback.
    in_flight: Option<Callback>,
}

fn fixture(state: DispatchState, placement: Placement) -> Fixture {
    let dispatcher = Arc::new(Mutex::new(Dispatcher {
        state,
        waker: None,
        polls: 0,
    }));
    let drops = Arc::new(AtomicUsize::new(0));
    let (callback, response) = oneshot::channel();
    let (stranded, in_flight) = match placement {
        Placement::Stranded => (Some(callback), None),
        Placement::InFlight => (None, Some(callback)),
    };
    Fixture {
        lease: Lease {
            dispatcher: Arc::clone(&dispatcher),
            stranded,
            drops: Arc::clone(&drops),
        },
        dispatcher,
        drops,
        response,
        in_flight,
    }
}

/// The response future the dispatch awaits.
async fn sent(
    response: oneshot::Receiver<Result<&'static str, &'static str>>,
) -> Result<&'static str, &'static str> {
    response.await.unwrap_or(Err("callback dropped"))
}

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A future polled by hand, recording whether it was woken since its last poll.
struct Task<F: Future> {
    future: Pin<Box<F>>,
    wakes: Arc<WakeCount>,
    waker: Waker,
    seen: usize,
}

impl<F: Future> Task<F> {
    fn new(future: F) -> Self {
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        Task {
            future: Box::pin(future),
            waker: Waker::from(Arc::clone(&wakes)),
            wakes,
            seen: 0,
        }
    }

    fn poll(&mut self) -> Poll<F::Output> {
        self.seen = self.wakes.0.load(Ordering::SeqCst);
        let mut cx = Context::from_waker(&self.waker);
        self.future.as_mut().poll(&mut cx)
    }

    fn is_woken(&self) -> bool {
        self.wakes.0.load(Ordering::SeqCst) > self.seen
    }
}

#[test]
fn stranded_request_without_release_never_resolves() {
    // The bug: the dispatch holds the only sender, so the envelope that missed
    // the dispatcher's drain is never dropped and nothing wakes the request.
    let f = fixture(DispatchState::Busy, Placement::Stranded);
    let mut task = Task::new(sent(f.response));
    assert!(task.poll().is_pending());
    set_state(&f.dispatcher, DispatchState::Closed);
    assert!(!task.is_woken());
    assert!(task.poll().is_pending());
    drop(f.lease);
    assert!(task.is_woken());
    assert_eq!(task.poll(), Poll::Ready(Err(CANCELED_UNSENT)));
}

#[test]
fn stranded_request_resolves_as_unsent_when_dispatcher_closes() {
    let f = fixture(DispatchState::Busy, Placement::Stranded);
    let drops = Arc::clone(&f.drops);
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    assert!(task.poll().is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 0);

    // The dispatcher closes its queue without having seen the request.
    set_state(&f.dispatcher, DispatchState::Closed);
    assert!(task.is_woken());
    match task.poll() {
        Poll::Ready((Err(err), None)) => assert_eq!(err, CANCELED_UNSENT),
        Poll::Ready((result, lease)) => {
            panic!("unexpected {result:?}, lease held: {}", lease.is_some())
        }
        Poll::Pending => panic!("stranded request still pending after the close"),
    }
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn stranded_request_on_already_closed_connection_resolves_on_first_poll() {
    let f = fixture(DispatchState::Closed, Placement::Stranded);
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    assert!(matches!(
        task.poll(),
        Poll::Ready((Err(CANCELED_UNSENT), None))
    ));
}

#[test]
fn response_delivered_before_close_wins_and_keeps_the_lease() {
    let mut f = fixture(DispatchState::Closed, Placement::InFlight);
    let drops = Arc::clone(&f.drops);
    let _ = f.in_flight.take().unwrap().send(Ok("response"));
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    match task.poll() {
        Poll::Ready((Ok("response"), Some(lease))) => drop(lease),
        _ => panic!("expected the delivered response with the lease held"),
    }
    // The response was polled first, so the closed connection was never
    // consulted and the lease went back to the caller rather than being dropped.
    assert_eq!(readiness_polls(&f.dispatcher), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn in_flight_request_keeps_the_lease_until_its_response() {
    let mut f = fixture(DispatchState::Busy, Placement::InFlight);
    let drops = Arc::clone(&f.drops);
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    assert!(task.poll().is_pending());
    assert!(task.poll().is_pending());
    let _ = f.in_flight.take().unwrap().send(Ok("response"));
    assert!(task.is_woken());
    assert!(matches!(
        task.poll(),
        Poll::Ready((Ok("response"), Some(_)))
    ));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn wanting_dispatcher_ends_the_watch() {
    // The dispatcher asked for more work after the request was published, so it
    // saw the request; a later close is its to report, not a strand.
    let mut f = fixture(DispatchState::Wanting, Placement::InFlight);
    let drops = Arc::clone(&f.drops);
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    assert!(task.poll().is_pending());
    set_state(&f.dispatcher, DispatchState::Closed);
    assert!(task.poll().is_pending());
    assert_eq!(readiness_polls(&f.dispatcher), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    // A post-wire failure comes back with the lease still held, so the caller
    // classifies it exactly as before.
    let _ = f.in_flight.take().unwrap().send(Err("connection reset"));
    assert!(matches!(
        task.poll(),
        Poll::Ready((Err("connection reset"), Some(_)))
    ));
}

#[test]
fn release_happens_once_and_leaves_an_in_flight_request_to_its_dispatcher() {
    // The dispatcher is gone while its callback is still on the way to the
    // request. Releasing the lease must not fabricate a handback, and must not
    // run twice.
    let mut f = fixture(DispatchState::Busy, Placement::InFlight);
    let drops = Arc::clone(&f.drops);
    let mut task = Task::new(await_h1_response_or_release(
        sent(f.response),
        f.lease,
        poll_lease,
    ));
    assert!(task.poll().is_pending());
    set_state(&f.dispatcher, DispatchState::Closed);
    assert!(task.poll().is_pending());
    assert!(task.poll().is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    // One readiness poll while busy, one that saw the close, none after.
    assert_eq!(readiness_polls(&f.dispatcher), 2);
    let _ = f.in_flight.take().unwrap().send(Err("dispatch gone"));
    assert!(matches!(
        task.poll(),
        Poll::Ready((Err("dispatch gone"), None))
    ));
}

type H1Sender = hyper::client::conn::http1::SendRequest<Empty<Bytes>>;

/// `SendRequest::poll_ready` exactly as both dispatch sites map it.
fn poll_sender(sender: &mut H1Sender, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
    sender.poll_ready(cx).map_err(|_| ())
}

/// A real hyper HTTP/1.1 request queued on a connection whose task is dropped
/// comes back canceled WITH the request, which is the handback both dispatch
/// sites turn into a replay (reused lease) or a pre-wire `ConnectionPoolError`
/// (fresh lease). A sender that survives reports its connection closed.
#[tokio::test]
async fn hyper_http1_queued_request_on_a_dropped_connection_comes_back_unsent() {
    let (client_io, _server_io) = tokio::io::duplex(1024);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
            .await
            .expect("handshake");
    let sent = sender.try_send_request(hyper::Request::new(Empty::new()));
    // The connection task never ran, so the request is queued, not dequeued.
    drop(connection);

    let (result, lease) = await_h1_response_or_release(sent, sender, poll_sender).await;
    let mut err = match result {
        Ok(_) => panic!("a request on a dropped connection must fail"),
        Err(err) => err,
    };
    assert!(err.take_message().is_some(), "request not handed back");
    assert!(err.into_error().is_canceled());
    if let Some(mut sender) = lease {
        let ready = std::future::poll_fn(|cx| Poll::Ready(sender.poll_ready(cx))).await;
        assert!(matches!(ready, Poll::Ready(Err(_))));
        assert!(sender.is_closed());
    }
}

/// The watch's trigger on the path the issue names: the backend closes an idle
/// keep-alive connection, the connection task ends, and the sender's readiness
/// poll reports the closure.
#[tokio::test]
async fn hyper_http1_sender_reports_closed_after_the_peer_closes_an_idle_connection() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client_io))
            .await
            .expect("handshake");
    let driver = tokio::spawn(connection);
    drop(server_io);
    let _ = driver.await.expect("connection task join");

    let ready = std::future::poll_fn(|cx| Poll::Ready(sender.poll_ready(cx))).await;
    assert!(
        matches!(ready, Poll::Ready(Err(_))),
        "a closed connection must not be ready"
    );
    assert!(sender.is_closed());
}

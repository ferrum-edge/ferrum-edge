//! Gateway-owned request-upload lifecycle for authenticated H1/H2 dispatch
//! (issues #3815 / #3816).
//!
//! # Why a pump exists at all
//!
//! Every H1/H2 backend transport hands the client request body to a hyper
//! client and lets hyper's own connection task drive it. For HTTP/2 that task
//! is `PipeToSendStream`, which **reserves and awaits stream send capacity
//! before it polls the body**. Two consequences follow, and both defeat a
//! body-adapter-only bound:
//!
//! * A pipe parked in `poll_capacity` is not polling the body, so no signal
//!   delivered *through* the body — a cancellation channel, a `Sleep` armed
//!   inside the adapter — can be observed until flow-control credit, a reset,
//!   or a connection close arrives.
//! * Once the response head resolves, hyper's own cancellation sender is gone,
//!   so the detached pipe can keep owning the inbound `Incoming` (and, with it,
//!   the request/session accounting rooted in that body) indefinitely.
//!
//! The equivalent detachment exists on HTTP/1.1 pooled clients (mesh mTLS,
//! HBONE's inner client, the Unix-socket pool) and inside reqwest, whose
//! connection task owns the body the same way and parks on socket writability
//! or on H2 capacity when it negotiates HTTP/2.
//!
//! # What this module guarantees
//!
//! The pump moves the inbound `hyper::body::Incoming` into a **gateway-owned
//! task** and hands the transport a bounded channel receiver instead. The task
//! selects, biased, over three things on every iteration:
//!
//! 1. an explicit cancellation signal from the dispatcher,
//! 2. the admitted stream's absolute authorization deadline,
//! 3. the next unit of work (channel capacity, then one source frame).
//!
//! Because arms 1 and 2 are polled by the gateway's own task, they fire **even
//! while the backend transport is parked on flow control and is not polling the
//! body at all**. When either fires the task publishes a terminal state, drops
//! its channel sender, and drops the `Incoming`. From that instant the gateway
//! neither owns nor polls the client body.
//!
//! The dispatcher holds an [`UploadPumpJoin`], whose
//! [`cancel_and_join`](UploadPumpJoin::cancel_and_join) is an actual join: it
//! resolves only after the task has published its outcome, which it does after
//! dropping the source. [`UploadPumpSource`] additionally aborts the task when
//! it is dropped, so no pump can outlive the body the transport owns.
//!
//! # Enforceable boundary
//!
//! Frames the pump handed to the transport *before* expiry may still be sitting
//! in that transport's own buffers and may reach the wire afterwards — the
//! gateway does not own those bytes and makes no claim about them. What is
//! enforced is narrower and exact: after the deadline the gateway polls no
//! further client body, hands the transport no further client byte, discards
//! anything still queued inside the pump channel, and terminates the transport
//! body with an error rather than a clean end-of-stream, so a backend can never
//! mistake a truncated upload for a complete one.
//!
//! # Cost
//!
//! One task and one capacity-1 channel per **authenticated** streaming upload.
//! Unauthenticated requests never construct a pump: `UploadSource::Direct`
//! keeps the previous zero-overhead path. Frames move by `Bytes` handle, so no
//! per-chunk copy or allocation is introduced.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::Frame;

use crate::proxy::RequestAuthLifetimePlan;
use crate::proxy::body::BoxError;

/// In-flight frame budget of the bridge channel.
///
/// One queued frame plus the one the pump is holding a permit for. The pump
/// reserves capacity *before* it polls the source, so a transport that stops
/// draining stops the pump within one frame — the backpressure the transport
/// used to apply directly to `Incoming` is preserved rather than replaced by
/// buffering.
const UPLOAD_PUMP_CHANNEL_CAPACITY: usize = 1;

const PUMP_RUNNING: u8 = 0;
const PUMP_COMPLETED: u8 = 1;
const PUMP_SOURCE_ERROR: u8 = 2;
const PUMP_CANCELLED: u8 = 3;
const PUMP_AUTHORIZATION_EXPIRED: u8 = 4;
const PUMP_CONSUMER_GONE: u8 = 5;

/// Terminal state of one gateway-owned upload pump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadPumpOutcome {
    /// The client body reached a clean end of stream and every frame was
    /// handed to the transport.
    Completed,
    /// The client body yielded a transport or protocol error.
    SourceError,
    /// The dispatcher cancelled the upload (a dispatch-phase bound fired, or
    /// the handler is returning and is releasing the upload).
    Cancelled,
    /// The admitted stream's authorization lifetime elapsed. Already latched
    /// and counted exactly once for the request.
    AuthorizationExpired,
    /// The transport dropped the bridge receiver, so there is nobody left to
    /// forward to.
    ConsumerGone,
}

const fn outcome_code(outcome: UploadPumpOutcome) -> u8 {
    match outcome {
        UploadPumpOutcome::Completed => PUMP_COMPLETED,
        UploadPumpOutcome::SourceError => PUMP_SOURCE_ERROR,
        UploadPumpOutcome::Cancelled => PUMP_CANCELLED,
        UploadPumpOutcome::AuthorizationExpired => PUMP_AUTHORIZATION_EXPIRED,
        UploadPumpOutcome::ConsumerGone => PUMP_CONSUMER_GONE,
    }
}

const fn code_outcome(code: u8) -> Option<UploadPumpOutcome> {
    match code {
        PUMP_COMPLETED => Some(UploadPumpOutcome::Completed),
        PUMP_SOURCE_ERROR => Some(UploadPumpOutcome::SourceError),
        PUMP_CANCELLED => Some(UploadPumpOutcome::Cancelled),
        PUMP_AUTHORIZATION_EXPIRED => Some(UploadPumpOutcome::AuthorizationExpired),
        PUMP_CONSUMER_GONE => Some(UploadPumpOutcome::ConsumerGone),
        _ => None,
    }
}

/// Fixed, redacted termination message handed to the backend transport.
///
/// A compiled-in literal from a closed set: no expiry instant, claim, subject,
/// certificate field, route, or provider detail can reach it.
pub(crate) const fn upload_pump_error_message(outcome: UploadPumpOutcome) -> &'static str {
    match outcome {
        UploadPumpOutcome::AuthorizationExpired => {
            "request upload terminated: authenticated stream authorization lifetime elapsed"
        }
        UploadPumpOutcome::Cancelled => "request upload terminated: cancelled by the gateway",
        UploadPumpOutcome::SourceError => "request upload terminated: client body stream error",
        UploadPumpOutcome::ConsumerGone => "request upload terminated: backend upload was released",
        // Never surfaced as an error; present so the mapping is total.
        UploadPumpOutcome::Completed => "request upload completed",
    }
}

/// Aborts the pump task when the transport-side body is dropped, so a pump can
/// never outlive the body it feeds.
///
/// The abort is synchronous and lands before the task can be polled again, so
/// the task itself never observes the closed bridge channel and never publishes
/// a terminal of its own. The terminal is therefore published HERE, before the
/// abort: releasing the transport body IS the "consumer went away" outcome, and
/// recording it is what lets a dispatcher joining this pump distinguish it from
/// a task that simply died. `RUNNING` is the only state it may overwrite, so a
/// pump that already settled keeps its own outcome.
struct AbortPumpOnDrop {
    handle: tokio::task::JoinHandle<()>,
    terminal: Arc<AtomicU8>,
}

impl Drop for AbortPumpOnDrop {
    fn drop(&mut self) {
        let _ = self.terminal.compare_exchange(
            PUMP_RUNNING,
            PUMP_CONSUMER_GONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.handle.abort();
    }
}

/// Transport-side half of the pump: an `http_body`-shaped view over the bridge
/// channel, installed inside the gateway's own request-body adapters.
pub struct UploadPumpSource {
    receiver: tokio::sync::mpsc::Receiver<Frame<Bytes>>,
    terminal: Arc<AtomicU8>,
    /// Held only for its `Drop`.
    _abort: AbortPumpOnDrop,
    /// Size hint snapshotted from the client body before it moved into the
    /// pump, so `Content-Length` framing survives the bridge unchanged.
    initial_hint: http_body::SizeHint,
    delivered: u64,
    ended: bool,
    reported_error: bool,
}

impl UploadPumpSource {
    pub(crate) fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        if self.ended || self.reported_error {
            return Poll::Ready(None);
        }
        // A non-clean terminal is checked BEFORE the queue: a frame the pump
        // read from the client before the deadline but has not yet handed to
        // the transport is discarded rather than forwarded afterwards.
        if let Some(outcome) = code_outcome(self.terminal.load(Ordering::Acquire))
            && outcome != UploadPumpOutcome::Completed
        {
            self.reported_error = true;
            return Poll::Ready(Some(Err(upload_pump_error_message(outcome).into())));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.delivered = self.delivered.saturating_add(data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // The pump publishes its terminal state before dropping the
                // sender, so a closed channel always has an authoritative
                // outcome to read. An absent one means the task was aborted
                // mid-flight; fail closed with an error so the backend resets
                // the stream instead of accepting a truncated upload as
                // complete.
                match code_outcome(self.terminal.load(Ordering::Acquire)) {
                    Some(UploadPumpOutcome::Completed) => {
                        self.ended = true;
                        Poll::Ready(None)
                    }
                    Some(other) => {
                        self.reported_error = true;
                        Poll::Ready(Some(Err(upload_pump_error_message(other).into())))
                    }
                    None => {
                        self.reported_error = true;
                        let message = upload_pump_error_message(UploadPumpOutcome::ConsumerGone);
                        Poll::Ready(Some(Err(message.into())))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) fn is_end_stream(&self) -> bool {
        self.ended
    }

    /// The client body's own hint, less what has already crossed the bridge.
    ///
    /// Hyper derives request framing (and, on HTTP/1.1, `Content-Length` vs
    /// chunked) from this, so the bridge must not degrade a known length into
    /// an unknown one.
    pub(crate) fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        hint.set_lower(self.initial_hint.lower().saturating_sub(self.delivered));
        if let Some(upper) = self.initial_hint.upper() {
            hint.set_upper(upper.saturating_sub(self.delivered));
        }
        hint
    }
}

/// Dispatcher-side half of the pump: the join point.
pub(crate) struct UploadPumpJoin {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<UploadPumpOutcome>>,
    /// Shared with the pump task and with [`UploadPumpSource`]'s abort guard.
    /// Read only as a FALLBACK, when the task published no outcome of its own
    /// because it was aborted — which is exactly what releasing the transport
    /// body does.
    terminal: Arc<AtomicU8>,
    cancel_on_drop: bool,
}

impl UploadPumpJoin {
    /// Ask the pump to stop if this handle is dropped without an explicit
    /// join.
    ///
    /// Used by dispatchers whose upload lifecycle is scoped to the handler
    /// (direct-H2): every residual early return then still releases the inbound
    /// client body promptly, even where an `.await` join is not reachable.
    /// Dispatchers whose upload legitimately outlives the handler — the
    /// streaming-response transports, where the transport owns the body and the
    /// [`UploadPumpSource`] abort guard bounds the task — must NOT arm this.
    #[must_use]
    pub(crate) fn cancel_on_drop(mut self) -> Self {
        self.cancel_on_drop = true;
        self
    }

    /// Signal cancellation without waiting.
    pub(crate) fn cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }

    /// Wait for the pump to finish on its own, without cancelling it.
    ///
    /// Same guarantee as [`cancel_and_join`](Self::cancel_and_join) once it
    /// resolves; used where the terminal is expected to come from the pump's
    /// own absolute authorization bound rather than from the dispatcher.
    #[allow(dead_code)]
    pub(crate) async fn join(mut self) -> Option<UploadPumpOutcome> {
        // Release the cancellation channel first so the pump does not treat
        // this handle's eventual drop as a teardown request.
        self.cancel = None;
        self.cancel_on_drop = false;
        self.await_outcome().await
    }

    /// Cancel the pump and wait for it to finish.
    ///
    /// Resolves only after the task has published its terminal state, which it
    /// does *after* dropping the client body — so once this returns, the
    /// gateway provably owns and polls no part of the inbound upload. Every
    /// wait inside the pump sits in a `select!` with the cancellation arm, so
    /// this join is bounded by the pump's own scheduling, not by the backend's
    /// flow-control window.
    pub(crate) async fn cancel_and_join(mut self) -> Option<UploadPumpOutcome> {
        self.cancel();
        self.await_outcome().await
    }

    /// The pump's terminal state: its own published outcome when it ran to a
    /// terminal, otherwise the shared one.
    ///
    /// A `oneshot` `Err` means the task was aborted (its `finished` sender
    /// dropped with it), which also implies the client body was dropped. That
    /// happens on exactly one path — the transport released
    /// [`UploadPumpSource`] — and its abort guard publishes
    /// [`UploadPumpOutcome::ConsumerGone`] before aborting, so the join point
    /// reports why rather than collapsing it into "no outcome".
    async fn await_outcome(&mut self) -> Option<UploadPumpOutcome> {
        let finished = self.finished.take()?;
        match finished.await {
            Ok(outcome) => Some(outcome),
            Err(_) => code_outcome(self.terminal.load(Ordering::Acquire)),
        }
    }
}

impl Drop for UploadPumpJoin {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancel();
        }
    }
}

/// Move a client request body into a gateway-owned pump task.
///
/// The caller must have established that the body is not already at end of
/// stream; an empty upload needs no pump and keeps the direct path.
///
/// Generic over the source body so the pump can be proven end to end against a
/// deliberately non-draining consumer in a unit test — `hyper::body::Incoming`
/// cannot be constructed outside a live connection.
pub(crate) fn spawn_upload_pump<B>(
    body: B,
    plan: &RequestAuthLifetimePlan,
) -> (UploadPumpSource, UploadPumpJoin)
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send,
{
    let initial_hint = http_body::Body::size_hint(&body);
    let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_PUMP_CHANNEL_CAPACITY);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let terminal = Arc::new(AtomicU8::new(PUMP_RUNNING));
    let task_terminal = Arc::clone(&terminal);
    let (deadline, family, latch) = plan.clone();
    let handle = tokio::spawn(async move {
        let outcome = run_upload_pump(
            body,
            sender,
            cancel_rx,
            deadline,
            family,
            latch,
            task_terminal,
        )
        .await;
        let _ = finished_tx.send(outcome);
    });
    (
        UploadPumpSource {
            receiver,
            terminal: Arc::clone(&terminal),
            _abort: AbortPumpOnDrop {
                handle,
                terminal: Arc::clone(&terminal),
            },
            initial_hint,
            delivered: 0,
            ended: false,
            reported_error: false,
        },
        UploadPumpJoin {
            cancel: Some(cancel_tx),
            finished: Some(finished_rx),
            terminal,
            cancel_on_drop: false,
        },
    )
}

/// Wait for an explicit cancellation.
///
/// A *dropped* sender is not a cancellation — it means the dispatcher released
/// the upload deliberately — so it disarms the channel and this future then
/// stays pending forever instead of firing a spurious teardown. Cancel-safe:
/// dropping it mid-poll loses nothing.
async fn cancel_requested(cancel: &mut Option<tokio::sync::oneshot::Receiver<()>>) {
    loop {
        let signalled = match cancel.as_mut() {
            Some(receiver) => await_cancel_signal(receiver).await,
            None => {
                // Disarmed: no cancellation can ever arrive, so this arm must
                // stay pending for the rest of the relay. `pending::<Infallible>()`
                // has an uninhabited output, so the empty match expresses "this
                // await never resolves" as a type, not as a proxy-path panic.
                match std::future::pending::<std::convert::Infallible>().await {}
            }
        };
        if signalled.is_ok() {
            return;
        }
        *cancel = None;
    }
}

/// Await a borrowed `oneshot::Receiver` without consuming it.
async fn await_cancel_signal(
    receiver: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), tokio::sync::oneshot::error::RecvError> {
    std::future::poll_fn(|cx| std::future::Future::poll(Pin::new(&mut *receiver), cx)).await
}

#[allow(clippy::too_many_arguments)]
async fn run_upload_pump<B>(
    mut body: B,
    sender: tokio::sync::mpsc::Sender<Frame<Bytes>>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    deadline: crate::proxy::auth_lifetime::StreamAuthDeadline,
    family: crate::proxy::auth_lifetime::StreamAuthProtocolFamily,
    latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    terminal: Arc<AtomicU8>,
) -> UploadPumpOutcome
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    let mut cancel = Some(cancel_rx);
    // Absolute and armed once. Relayed DATA, gRPC messages, and trailers never
    // refresh it, and it is owned by THIS task, so it fires regardless of what
    // the backend transport is doing.
    let mut expiry = Box::pin(tokio::time::sleep_until(deadline.at));
    let outcome = loop {
        // Reserve capacity BEFORE reading the client, so a transport that
        // stops draining stops the read rather than filling a buffer.
        let permit = tokio::select! {
            biased;
            () = cancel_requested(&mut cancel) => break UploadPumpOutcome::Cancelled,
            () = &mut expiry => {
                latch.record_once(deadline.termination, family);
                break UploadPumpOutcome::AuthorizationExpired;
            }
            reserved = sender.reserve() => match reserved {
                Ok(permit) => permit,
                Err(_) => break UploadPumpOutcome::ConsumerGone,
            },
        };
        let frame = tokio::select! {
            biased;
            () = cancel_requested(&mut cancel) => break UploadPumpOutcome::Cancelled,
            () = &mut expiry => {
                latch.record_once(deadline.termination, family);
                break UploadPumpOutcome::AuthorizationExpired;
            }
            frame = http_body_util::BodyExt::frame(&mut body) => frame,
        };
        match frame {
            None => break UploadPumpOutcome::Completed,
            Some(Ok(frame)) => permit.send(frame),
            Some(Err(_)) => break UploadPumpOutcome::SourceError,
        }
    };
    // Publish BEFORE the sender drops: the transport side reads this exactly
    // when `poll_recv` observes the closed channel, and the channel close is
    // the synchronisation edge for this release store.
    terminal.store(outcome_code(outcome), Ordering::Release);
    drop(sender);
    // Explicit, and the whole point of this module: the gateway stops owning
    // the inbound client body here, whatever the backend transport is doing.
    drop(body);
    outcome
}

/// The bridge's in-flight frame budget, exposed so a test can prove it is
/// bounded rather than a buffer. Reached through `crate::_test_support`.
#[allow(dead_code)]
pub(crate) const fn upload_pump_channel_capacity() -> usize {
    UPLOAD_PUMP_CHANNEL_CAPACITY
}

//! Gateway-owned request-upload lifecycle for H1/H2 dispatch (issues #3815 /
//! #3816 / #4055).
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
//! selects, biased, over four things on every iteration:
//!
//! 1. an explicit cancellation signal from the dispatcher,
//! 2. the admitted stream's absolute authorization deadline (when present),
//! 3. `backend_write_timeout_ms` idle while waiting for the transport to
//!    consume the previous frame (`sender.reserve()`),
//! 4. the next unit of work (channel capacity, then one source frame).
//!
//! Because arms 1–3 are polled by the gateway's own task, they fire **even
//! while the backend transport is parked on flow control and is not polling the
//! body at all**. When any of them fires the task publishes a terminal state,
//! drops its channel sender, and drops the `Incoming`. From that instant the
//! gateway neither owns nor polls the client body.
//!
//! The write idle arm is reset at the start of each `reserve()` wait and is
//! not polled while waiting on the client body, so a slow-but-progressing
//! upload stays alive and a stalled client is not misread as a backend write
//! stall. `backend_write_timeout_ms == 0` leaves that arm unarmed.
//!
//! # When the write watermark starts (issue #4074)
//!
//! The pump is installed BEFORE the transport has a connection: reqwest has not
//! resolved DNS, opened a socket, or finished a TLS handshake, and the pooled
//! hyper dispatchers have not checked out a sender yet. Arming
//! `backend_write_timeout_ms` at spawn therefore charged connection
//! acquisition to a per-direction *write* policy: with a write timeout shorter
//! than `backend_connect_timeout_ms`, a slow dial ended as a post-wire
//! `ReadWriteTimeout` and suppressed the pre-wire connect retry the failure
//! actually warranted.
//!
//! The watermark is now armed by the FIRST transport poll of
//! [`UploadPumpSource`] — the first moment a transport is provably consuming
//! this request body, which on every H1/H2 client happens only after the
//! connection exists and the request head has been written. An authorization
//! lifetime is unaffected: it is absolute, receipt-anchored, and armed at spawn
//! as before. Native gRPC keeps its explicit dispatcher-owned arm
//! ([`UploadPumpJoin::arm_write_watermark`]), which it fires after
//! `get_sender()` and immediately before `send_request()`.
//!
//! Consequence, deliberately: while no transport has polled the body, no write
//! watermark can fire. That window is exactly the connect phase, which
//! `backend_connect_timeout_ms` already bounds.
//!
//! Once the transport has consumed, the watermark must also survive a *clean*
//! source end (issue #4411). A never-read origin still lets the local TCP send
//! buffer absorb a small-or-medium POST; hyper then observes end-of-stream and
//! may immediately drop an exact-length body, aborting the pump before it can
//! publish a response holdover. The terminal bridge frame now carries its
//! source-end marker, so transport consumption records the holdover in shared
//! join state before that drop. The holdover is refreshed only by genuine
//! consume progress and keeps `backend_write_timeout_ms` on the header wait
//! without treating "we queued a frame" as progress.
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
//! One task and one capacity-1 channel per streaming upload that carries an
//! authorization plan **or** a live `backend_write_timeout_ms`. Uploads with
//! neither keep `UploadSource::Direct` (no task, no channel, no timer). Frames
//! move by `Bytes` handle, so no per-chunk copy or allocation is introduced.
//!
//! A fully BUFFERED upload pays the same one task + one channel when
//! `backend_write_timeout_ms` is live, and nothing at all when it is `0`; see
//! [`spawn_buffered_upload_pump`]. Its frames are refcounted `Bytes::split_to`
//! slices of the collected buffer, so it copies nothing either.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

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
const PUMP_WRITE_TIMEOUT: u8 = 6;

/// Shared response-holdover state for one live backend write watermark.
///
/// The transport can consume the terminal body frame and immediately drop its
/// [`UploadPumpSource`] before the pump task is scheduled again. Keeping both
/// facts here lets the join observe that consume without depending on the task
/// surviving the source's abort guard (issue #4411).
struct UploadPumpWriteState {
    armed: AtomicBool,
    eos_consumed: AtomicBool,
    changed: tokio::sync::Notify,
}

impl UploadPumpWriteState {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            eos_consumed: AtomicBool::new(false),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn arm(&self) {
        if !self.armed.swap(true, Ordering::AcqRel) {
            self.changed.notify_one();
        }
    }

    fn record_eos_consumed(&self) {
        if !self.eos_consumed.swap(true, Ordering::AcqRel) {
            self.changed.notify_one();
        }
    }

    fn holdover_ready(&self) -> bool {
        self.armed.load(Ordering::Acquire) && self.eos_consumed.load(Ordering::Acquire)
    }
}

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
    /// The transport stopped consuming request-body frames for
    /// `backend_write_timeout_ms`. Surfaced as `io::ErrorKind::TimedOut` so
    /// `classify_body_error` / `classify_reqwest_error` map it to
    /// `ReadWriteTimeout`.
    WriteTimeout,
}

const fn outcome_code(outcome: UploadPumpOutcome) -> u8 {
    match outcome {
        UploadPumpOutcome::Completed => PUMP_COMPLETED,
        UploadPumpOutcome::SourceError => PUMP_SOURCE_ERROR,
        UploadPumpOutcome::Cancelled => PUMP_CANCELLED,
        UploadPumpOutcome::AuthorizationExpired => PUMP_AUTHORIZATION_EXPIRED,
        UploadPumpOutcome::ConsumerGone => PUMP_CONSUMER_GONE,
        UploadPumpOutcome::WriteTimeout => PUMP_WRITE_TIMEOUT,
    }
}

const fn code_outcome(code: u8) -> Option<UploadPumpOutcome> {
    match code {
        PUMP_COMPLETED => Some(UploadPumpOutcome::Completed),
        PUMP_SOURCE_ERROR => Some(UploadPumpOutcome::SourceError),
        PUMP_CANCELLED => Some(UploadPumpOutcome::Cancelled),
        PUMP_AUTHORIZATION_EXPIRED => Some(UploadPumpOutcome::AuthorizationExpired),
        PUMP_CONSUMER_GONE => Some(UploadPumpOutcome::ConsumerGone),
        PUMP_WRITE_TIMEOUT => Some(UploadPumpOutcome::WriteTimeout),
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
        UploadPumpOutcome::WriteTimeout => {
            "request upload terminated: backend request body write timeout"
        }
        // Never surfaced as an error; present so the mapping is total.
        UploadPumpOutcome::Completed => "request upload completed",
    }
}

/// Transport-side error for a non-clean pump terminal.
///
/// Write-timeout uses a typed `io::ErrorKind::TimedOut` so the existing
/// `classify_body_error` / `classify_reqwest_error` walks map it to
/// `ReadWriteTimeout` without a second string heuristic. Other terminals keep
/// the redacted literal.
fn pump_terminal_error(outcome: UploadPumpOutcome) -> BoxError {
    let message = upload_pump_error_message(outcome);
    if outcome == UploadPumpOutcome::WriteTimeout {
        Box::new(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
    } else {
        message.into()
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

/// One frame on the bounded bridge plus whether it ended the source body.
///
/// Hyper may use an exact size hint to drop a request body immediately after
/// polling its last DATA frame, without polling once more for `None`. Carrying
/// the source terminal bit with that frame lets the transport publish genuine
/// terminal consumption before such a drop can abort the pump task.
struct PumpedUploadFrame {
    frame: Frame<Bytes>,
    source_ended: bool,
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
    receiver: tokio::sync::mpsc::Receiver<PumpedUploadFrame>,
    terminal: Arc<AtomicU8>,
    /// Held only for its `Drop`.
    _abort: AbortPumpOnDrop,
    /// Size hint snapshotted from the client body before it moved into the
    /// pump, so `Content-Length` framing survives the bridge unchanged.
    initial_hint: http_body::SizeHint,
    /// Arms `backend_write_timeout_ms` on the FIRST transport poll (issue
    /// #4074). Present only for a pump whose write watermark is
    /// consumer-armed; the native-gRPC deferred pump hands this sender to its
    /// dispatcher instead, and a pump with no write bound has none at all.
    write_start: Option<tokio::sync::oneshot::Sender<()>>,
    write_state: Option<Arc<UploadPumpWriteState>>,
    delivered: u64,
    ended: bool,
    reported_error: bool,
}

impl UploadPumpSource {
    /// Poll one bridged frame.
    ///
    /// Terminal contract (issue #4074, finding L1). This body is **fused after
    /// a terminal**: a non-clean pump outcome is reported as `Some(Err(_))`
    /// exactly ONCE, and every subsequent poll returns `Ready(None)`. Repeating
    /// the error would spin a consumer that polls past an error, and every
    /// transport that matters stops at the first one (hyper's HTTP/1 dispatcher
    /// aborts the connection; `PipeToSendStream` sends `RST_STREAM`).
    ///
    /// The fuse is deliberately NOT a clean end of stream in the eyes of the
    /// framing layer: [`is_end_stream`](Self::is_end_stream) stays `false` and
    /// [`size_hint`](Self::size_hint) keeps advertising the residual bytes that
    /// never crossed the bridge, so a truncated upload can never present itself
    /// as a complete one to a consumer that inspects the body's end state.
    pub(crate) fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // The first transport poll is the first proof that a transport is
        // consuming THIS body: the connection exists and the request head is
        // written. Arming here — rather than at spawn — is what keeps DNS /
        // TCP / TLS connection acquisition off a per-direction write policy
        // (issue #4074).
        if let Some(write_start) = self.write_start.take() {
            if let Some(write_state) = self.write_state.as_ref() {
                write_state.arm();
            }
            let _ = write_start.send(());
        }
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
            return Poll::Ready(Some(Err(pump_terminal_error(outcome))));
        }
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(pumped)) => {
                let PumpedUploadFrame {
                    frame,
                    source_ended,
                } = pumped;
                if source_ended {
                    match self.terminal.compare_exchange(
                        PUMP_RUNNING,
                        PUMP_COMPLETED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) | Err(PUMP_COMPLETED) => {
                            if let Some(write_state) = self.write_state.as_ref() {
                                write_state.record_eos_consumed();
                            }
                            self.ended = true;
                        }
                        Err(code) => {
                            self.reported_error = true;
                            let outcome =
                                code_outcome(code).unwrap_or(UploadPumpOutcome::ConsumerGone);
                            return Poll::Ready(Some(Err(pump_terminal_error(outcome))));
                        }
                    }
                }
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
                        if let Some(write_state) = self.write_state.as_ref() {
                            write_state.record_eos_consumed();
                        }
                        self.ended = true;
                        Poll::Ready(None)
                    }
                    Some(other) => {
                        self.reported_error = true;
                        Poll::Ready(Some(Err(pump_terminal_error(other))))
                    }
                    None => {
                        self.reported_error = true;
                        Poll::Ready(Some(Err(pump_terminal_error(
                            UploadPumpOutcome::ConsumerGone,
                        ))))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// `true` only after a CLEAN end of stream.
    ///
    /// A pump that ended on a non-clean terminal stays `false` forever, even
    /// once [`poll_frame`](Self::poll_frame) has fused: the upload did not
    /// complete, and saying otherwise would let a backend treat a truncated
    /// request as a whole one.
    pub(crate) fn is_end_stream(&self) -> bool {
        self.ended
    }

    /// The client body's own hint, less what has already crossed the bridge.
    ///
    /// Hyper derives request framing (and, on HTTP/1.1, `Content-Length` vs
    /// chunked) from this, so the bridge must not degrade a known length into
    /// an unknown one.
    ///
    /// After a non-clean terminal the residual is deliberately NOT collapsed to
    /// zero: the remaining bytes were never handed over, and reporting them as
    /// delivered would describe a truncated upload as a complete one.
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
    /// Arms a write watermark the DISPATCHER owns, once it has acquired a
    /// backend sender. `None` for a consumer-armed pump (the ordinary case,
    /// where the transport's first body poll arms it) and for a pump with no
    /// write bound at all.
    write_start: Option<tokio::sync::oneshot::Sender<()>>,
    finished: Option<tokio::sync::oneshot::Receiver<UploadPumpOutcome>>,
    /// Fires ONLY for [`UploadPumpOutcome::WriteTimeout`], and only after the
    /// task has published its terminal and dropped the client body. Every
    /// other terminal drops the sender instead, which
    /// [`backend_write_watermark_expired`](UploadPumpJoin::backend_write_watermark_expired)
    /// turns into "never" rather than a spurious wake.
    write_timeout: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Records transport consumption of clean EOS independently of the pump
    /// task, so the source's abort guard cannot drop the response holdover.
    write_state: Option<Arc<UploadPumpWriteState>>,
    /// Set when [`write_state`](Self::write_state) reports both an armed
    /// watermark and consumed EOS, then slept with `sleep_until` so a dropped
    /// header-wait race can resume the same idle rather than losing the bound.
    eos_holdover_deadline: Option<tokio::time::Instant>,
    write_timeout_ms: u64,
    /// Shared with the pump task and with [`UploadPumpSource`]'s abort guard.
    /// Read only as a FALLBACK, when the task published no outcome of its own
    /// because it was aborted — which is exactly what releasing the transport
    /// body does.
    terminal: Arc<AtomicU8>,
    cancel_on_drop: bool,
}

impl UploadPumpJoin {
    /// Start a deliberately deferred backend-write watermark.
    ///
    /// Native gRPC must install its pump before pool acquisition when an
    /// authorization lifetime owns the client upload, but connection
    /// acquisition is not backend-body writing. Its dispatcher calls this
    /// after `get_sender()` and immediately before `send_request()`, so a slow
    /// dial cannot be misreported as `ReadWriteTimeout`.
    pub(crate) fn arm_write_watermark(&mut self) {
        if let Some(write_start) = self.write_start.take() {
            if let Some(write_state) = self.write_state.as_ref() {
                write_state.arm();
            }
            let _ = write_start.send(());
        }
    }

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

    /// Resolve when — and only when — the pump ends on the backend write
    /// watermark (`backend_write_timeout_ms`, issue #4055).
    ///
    /// This exists because the pump's terminal reaches the backend transport
    /// only through the transport BODY, and every transport that matters is
    /// parked outside a body poll exactly when a backend stops reading: hyper's
    /// HTTP/2 pipe sits in `poll_capacity`, an HTTP/1.1 connection task sits on
    /// socket writability, and reqwest's connection task does either. A
    /// dispatcher that waits only on the response head would therefore run past
    /// the write watermark and end on whatever later bound happens to be
    /// configured. Racing this future against that wait is what makes the
    /// watermark client-visible at the watermark.
    ///
    /// Cancel-safe, and non-consuming: the `finished` channel is untouched, so
    /// a caller that loses this race can still [`cancel_and_join`] and read the
    /// typed terminal. Any other terminal — and a pump with no write bound at
    /// all — drops the sender, which this turns into a future that stays
    /// pending forever, so a `select!` arm built on it cannot fire spuriously.
    ///
    /// [`cancel_and_join`]: Self::cancel_and_join
    pub(crate) async fn backend_write_watermark_expired(&mut self) {
        tokio::select! {
            biased;
            () = write_timeout_fired(&mut self.write_timeout) => {}
            () = eos_holdover_elapsed(
                self.write_state.as_deref(),
                &mut self.eos_holdover_deadline,
                self.write_timeout_ms,
            ) => {}
        }
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
    plan: Option<&RequestAuthLifetimePlan>,
    write_timeout_ms: u64,
) -> (UploadPumpSource, UploadPumpJoin)
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send,
{
    spawn_upload_pump_with_write_start(body, plan, write_timeout_ms, WriteWatermarkArm::Consumer)
}

/// Move a client request body into a pump whose authorization lifetime starts
/// immediately but whose backend-write watermark starts only when the
/// dispatcher explicitly arms it — rather than on the transport's first body
/// poll, which is the default (issue #4074).
///
/// This split is required by native gRPC: authorization must continue to own
/// and bound the frontend upload during pool acquisition, while
/// `backend_write_timeout_ms` must not count that connect phase as backend
/// write inactivity.
pub(crate) fn spawn_upload_pump_with_deferred_write<B>(
    body: B,
    plan: Option<&RequestAuthLifetimePlan>,
    write_timeout_ms: u64,
) -> (UploadPumpSource, UploadPumpJoin)
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send,
{
    spawn_upload_pump_with_write_start(body, plan, write_timeout_ms, WriteWatermarkArm::Dispatcher)
}

/// Who starts `backend_write_timeout_ms` for one pump (issue #4074).
///
/// Never "at spawn": the pump is installed before the transport has a
/// connection, so charging DNS / TCP / TLS acquisition to a write policy would
/// misclassify a slow dial as a post-wire `ReadWriteTimeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteWatermarkArm {
    /// The transport's FIRST poll of [`UploadPumpSource`] arms it. Used by
    /// every reqwest and pooled-hyper upload, whose dispatchers hold no
    /// "sender acquired" seam of their own.
    Consumer,
    /// The dispatcher arms it explicitly through
    /// [`UploadPumpJoin::arm_write_watermark`], after `get_sender()` and
    /// immediately before `send_request()`. Used by native gRPC.
    Dispatcher,
}

fn spawn_upload_pump_with_write_start<B>(
    body: B,
    plan: Option<&RequestAuthLifetimePlan>,
    write_timeout_ms: u64,
    arm: WriteWatermarkArm,
) -> (UploadPumpSource, UploadPumpJoin)
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Send,
{
    let initial_hint = http_body::Body::size_hint(&body);
    let (sender, receiver) = tokio::sync::mpsc::channel(UPLOAD_PUMP_CHANNEL_CAPACITY);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let (write_timeout_tx, write_timeout_rx) = tokio::sync::oneshot::channel();
    // One arm channel, one owner. A pump with no write bound creates neither
    // that channel nor shared holdover state, so `write_configured` and the arm
    // condition can never disagree.
    let (dispatcher_write_start, consumer_write_start, write_start_rx) = if write_timeout_ms == 0 {
        (None, None, None)
    } else {
        let (tx, rx) = tokio::sync::oneshot::channel();
        match arm {
            WriteWatermarkArm::Dispatcher => (Some(tx), None, Some(rx)),
            WriteWatermarkArm::Consumer => (None, Some(tx), Some(rx)),
        }
    };
    let write_state = if write_timeout_ms == 0 {
        None
    } else {
        Some(Arc::new(UploadPumpWriteState::new()))
    };
    let terminal = Arc::new(AtomicU8::new(PUMP_RUNNING));
    let task_terminal = Arc::clone(&terminal);
    let plan = plan.cloned();
    let handle = tokio::spawn(async move {
        let outcome = run_upload_pump(UploadPumpTask {
            body,
            sender,
            cancel_rx,
            plan,
            write_timeout_ms,
            write_start_rx,
            terminal: task_terminal,
            write_timeout_tx,
        })
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
            write_start: consumer_write_start,
            write_state: write_state.as_ref().map(Arc::clone),
            delivered: 0,
            ended: false,
            reported_error: false,
        },
        UploadPumpJoin {
            cancel: Some(cancel_tx),
            write_start: dispatcher_write_start,
            finished: Some(finished_rx),
            write_timeout: Some(write_timeout_rx),
            write_state,
            eos_holdover_deadline: None,
            write_timeout_ms,
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
            Some(receiver) => await_oneshot_signal(receiver).await,
            None => {
                // Disarmed: no cancellation can ever arrive, so this arm must
                // stay pending for the rest of the relay. `pending::<Infallible>()`
                // has an uninhabited output, so the empty match expresses "this
                // await never resolves" as a type — and, unlike `never()`, it
                // types as this arm's `Result` — not as a proxy-path panic.
                match std::future::pending::<std::convert::Infallible>().await {}
            }
        };
        if signalled.is_ok() {
            return;
        }
        *cancel = None;
    }
}

/// A future that never resolves, expressed as a type rather than as a
/// proxy-path panic: `pending::<Infallible>()` has an uninhabited output, so
/// the empty match is the "this await never returns" proof.
async fn never() {
    match std::future::pending::<std::convert::Infallible>().await {}
}

/// Await a borrowed `oneshot::Receiver<()>` without consuming it.
///
/// Shared by the cancellation arm and the write-watermark arm: both need to
/// poll their channel repeatedly across `select!` iterations while keeping the
/// receiver so a later `Err` can disarm it.
async fn await_oneshot_signal(
    receiver: &mut tokio::sync::oneshot::Receiver<()>,
) -> Result<(), tokio::sync::oneshot::error::RecvError> {
    std::future::poll_fn(|cx| std::future::Future::poll(Pin::new(&mut *receiver), cx)).await
}

/// Wait for the pump task's in-flight write-idle expiry.
///
/// A dropped sender is some other terminal: disarm and stay pending so this
/// arm cannot fire spuriously. Cancel-safe.
async fn write_timeout_fired(write_timeout: &mut Option<tokio::sync::oneshot::Receiver<()>>) {
    loop {
        match write_timeout.as_mut() {
            Some(receiver) => {
                if await_oneshot_signal(receiver).await.is_ok() {
                    return;
                }
                *write_timeout = None;
            }
            None => never().await,
        }
    }
}

/// After the source is exhausted, idle `write_timeout_ms` so the header wait
/// still observes `backend_write_timeout_ms` when the kernel absorbed the
/// body (issue #4411).
///
/// Shared state starts this idle only after the write watermark is armed AND
/// the transport consumes clean EOS, so connection acquisition stays off the
/// write clock. Recording those events independently also handles native gRPC,
/// whose dispatcher can arm after the terminal body state is observable in a
/// synthetic probe even though production arms before `send_request()`.
///
/// Cancel-safe: the deadline is stored on the join before any sleep, so a
/// `select!` that loses the header-wait race (or a probe that observes
/// dormancy) resumes the same idle instead of dropping the bound.
async fn eos_holdover_elapsed(
    write_state: Option<&UploadPumpWriteState>,
    eos_holdover_deadline: &mut Option<tokio::time::Instant>,
    write_timeout_ms: u64,
) {
    let Some(write_state) = write_state else {
        never().await;
        return;
    };
    loop {
        if let Some(at) = *eos_holdover_deadline {
            tokio::time::sleep_until(at).await;
            *eos_holdover_deadline = None;
            return;
        }
        let changed = write_state.changed.notified();
        if write_state.holdover_ready() {
            if write_timeout_ms == 0 {
                never().await;
            } else {
                let deadline = tokio::time::Instant::now()
                    .checked_add(Duration::from_millis(write_timeout_ms));
                match deadline {
                    Some(at) => *eos_holdover_deadline = Some(at),
                    // Instant overflow: fail closed; the bound has elapsed as
                    // far as this join can represent.
                    None => return,
                }
            }
        } else {
            changed.await;
        }
    }
}

/// State moved into the gateway-owned upload task.
///
/// Keeping the task controls together makes their shared lifecycle explicit:
/// every sender is consumed by exactly one pump invocation and every terminal
/// path publishes through the corresponding terminal and watermark channels.
struct UploadPumpTask<B> {
    body: B,
    sender: tokio::sync::mpsc::Sender<PumpedUploadFrame>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    plan: Option<RequestAuthLifetimePlan>,
    write_timeout_ms: u64,
    write_start_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    terminal: Arc<AtomicU8>,
    write_timeout_tx: tokio::sync::oneshot::Sender<()>,
}

async fn run_upload_pump<B>(task: UploadPumpTask<B>) -> UploadPumpOutcome
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    let UploadPumpTask {
        mut body,
        sender,
        cancel_rx,
        plan,
        write_timeout_ms,
        write_start_rx: mut write_start,
        terminal,
        write_timeout_tx,
    } = task;
    let mut sender = Some(sender);
    let mut cancel = Some(cancel_rx);
    // Absolute and armed once when a credential admitted the stream. Relayed
    // DATA, gRPC messages, and trailers never refresh it, and it is owned by
    // THIS task, so it fires regardless of what the backend transport is doing.
    let auth_armed = plan.is_some();
    let mut expiry = Box::pin(tokio::time::sleep_until(
        plan.as_ref()
            .map(|(deadline, _, _)| deadline.at)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86_400)),
    ));
    // Per-reserve idle bound. Reset at the start of each capacity wait so a
    // slow-but-progressing upload keeps the watermark fresh. Not polled while
    // waiting on the client body: that stall is not a backend write stall.
    // `write_start` is `Some` for exactly the pumps that have a write bound
    // (issue #4074), so the watermark is dormant until whoever owns that sender
    // fires it — the transport's first body poll, or the gRPC dispatcher after
    // `get_sender()`. A pump with `write_timeout_ms == 0` has neither.
    let write_configured = write_timeout_ms > 0;
    let mut write_armed = false;
    // No `.max(1)` floor: `write_configured` already proves the value is
    // nonzero, and the timer is allocated only when the bound exists, so a pump
    // installed purely for an authorization lifetime carries no write timer
    // (issue #4074).
    let write_idle_dur = Duration::from_millis(write_timeout_ms);
    let mut write_idle = write_configured.then(|| Box::pin(tokio::time::sleep(write_idle_dur)));
    let outcome = 'pump: loop {
        // Reserve capacity BEFORE reading the client, so a transport that
        // stops draining stops the read rather than filling a buffer.
        if write_armed
            && let Some(idle) = write_idle.as_mut()
            && let Some(at) = tokio::time::Instant::now().checked_add(write_idle_dur)
        {
            idle.as_mut().reset(at);
        }
        let Some(sender_ref) = sender.as_ref() else {
            // Sender is taken only on the clean-EOS path, which already
            // broke `'pump`. Remaining `None` is a type-level remainder.
            break 'pump UploadPumpOutcome::Completed;
        };
        let permit = tokio::select! {
            biased;
            () = cancel_requested(&mut cancel) => break 'pump UploadPumpOutcome::Cancelled,
            () = &mut expiry, if auth_armed => {
                if let Some((deadline, family, latch)) = plan.as_ref() {
                    latch.record_once(deadline.termination, *family);
                }
                break 'pump UploadPumpOutcome::AuthorizationExpired;
            }
            () = signal_requested(&mut write_start), if write_configured && !write_armed => {
                write_armed = true;
                continue 'pump;
            }
            () = write_idle_elapsed(&mut write_idle), if write_armed => {
                break 'pump UploadPumpOutcome::WriteTimeout;
            }
            reserved = sender_ref.reserve() => match reserved {
                Ok(permit) => permit,
                Err(_) => break 'pump UploadPumpOutcome::ConsumerGone,
            },
        };
        let frame = 'frame: loop {
            break tokio::select! {
                biased;
                () = cancel_requested(&mut cancel) => break 'pump UploadPumpOutcome::Cancelled,
                () = &mut expiry, if auth_armed => {
                    if let Some((deadline, family, latch)) = plan.as_ref() {
                        latch.record_once(deadline.termination, *family);
                    }
                    break 'pump UploadPumpOutcome::AuthorizationExpired;
                }
                () = signal_requested(&mut write_start), if write_configured && !write_armed => {
                    write_armed = true;
                    continue 'frame;
                }
                frame = http_body_util::BodyExt::frame(&mut body) => frame,
            };
        };
        // `permit` borrows `sender` through `sender_ref`, and its binding scope
        // is this whole loop body, so its `Drop` would keep that borrow live
        // past the end-of-stream handling below, which needs `&mut sender` for
        // `take()`. Release it explicitly on the path that does not send —
        // the reserved slot goes back unused, exactly as it did when the arm
        // simply fell out of scope — and settle the match to a plain `bool` so
        // the permit is moved or dropped on every path.
        let source_exhausted = match frame {
            None => {
                drop(permit);
                true
            }
            Some(Ok(frame)) => {
                let source_ended = http_body::Body::is_end_stream(&body);
                permit.send(PumpedUploadFrame {
                    frame,
                    source_ended,
                });
                false
            }
            Some(Err(_)) => break 'pump UploadPumpOutcome::SourceError,
        };
        if !source_exhausted {
            continue 'pump;
        }
        // Last frame is already on the bridge. Publish clean BODY completion
        // before closing the sender, so the transport can never observe a
        // closed bridge while the terminal is still RUNNING. This is a
        // write-once transition: cancellation or authorization expiry while
        // this task waits to arm the RESPONSE holdover must not retroactively
        // turn a delivered body into a transport error.
        let _ = terminal.compare_exchange(
            PUMP_RUNNING,
            PUMP_COMPLETED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        // Close the sender so the transport observes that clean end-of-stream
        // and can read response headers. A terminal frame already carried the
        // source-end marker; consuming it recorded the join's holdover before
        // the transport could drop this source and abort the task. A body that
        // ended without a terminal frame records the same fact when the source
        // observes this closed bridge.
        drop(sender.take());
        break 'pump UploadPumpOutcome::Completed;
    };
    // Publish BEFORE the sender drops: the transport side reads this exactly
    // when `poll_recv` observes the closed channel, and the channel close is
    // the synchronisation edge for this release transition. Clean BODY
    // completion was already published before its sender closed, so a later
    // RESPONSE-wait cancellation or authorization expiry cannot overwrite it.
    let terminal_published = terminal
        .compare_exchange(
            PUMP_RUNNING,
            outcome_code(outcome),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok();
    drop(sender);
    // Explicit, and the whole point of this module: the gateway stops owning
    // the inbound client body here, whatever the backend transport is doing.
    drop(body);
    // Published LAST, so a dispatcher woken by this signal already observes
    // the terminal state, the closed bridge, and a released client body. Only
    // a write watermark that won terminal publication fires this signal; every
    // other terminal drops the sender.
    if outcome == UploadPumpOutcome::WriteTimeout && terminal_published {
        let _ = write_timeout_tx.send(());
    }
    outcome
}

/// Await the write-idle timer, which exists only when the operator configured
/// `backend_write_timeout_ms` (issue #4074).
///
/// `None` never resolves, expressed as a type rather than as a proxy-path
/// panic. Cancel-safe: `Sleep` is, and the pinned box is re-borrowed each
/// `select!` iteration.
async fn write_idle_elapsed(sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match sleep.as_mut() {
        Some(sleep) => sleep.as_mut().await,
        None => match std::future::pending::<std::convert::Infallible>().await {},
    }
}

/// Wait for a one-shot control signal, treating a dropped sender as a
/// permanently disarmed control rather than as a spurious event.
async fn signal_requested(signal: &mut Option<tokio::sync::oneshot::Receiver<()>>) {
    loop {
        let signalled = match signal.as_mut() {
            Some(receiver) => await_oneshot_signal(receiver).await,
            None => match std::future::pending::<std::convert::Infallible>().await {},
        };
        if signalled.is_ok() {
            return;
        }
        *signal = None;
    }
}

/// The bridge's in-flight frame budget, exposed so a test can prove it is
/// bounded rather than a buffer. Reached through `crate::_test_support`.
#[allow(dead_code)]
pub(crate) const fn upload_pump_channel_capacity() -> usize {
    UPLOAD_PUMP_CHANNEL_CAPACITY
}

// -- Buffered uploads ---------------------------------------------------------

/// Frame size the bridge slices a fully buffered upload into.
///
/// The pump's write-idle arm sits on `sender.reserve()`, so the watermark stays
/// coupled to transport consumption only while frames remain to hand over. A
/// single giant frame would let hyper "consume" the whole upload in one pull —
/// completing the pump — while not one byte had reached the wire, which is the
/// opposite of what `backend_write_timeout_ms` promises. Slicing keeps the
/// bridge's backpressure tied to the transport until the last byte has actually
/// been taken.
///
/// 64 KiB matches hyper's own write granularity, bounds the in-flight budget at
/// two frames (this one plus the queued one), and costs no copy: `split_to`
/// hands out a refcounted view of the same allocation.
const BUFFERED_UPLOAD_FRAME_BYTES: usize = 64 * 1024;

/// Zero-copy chunked view over a fully collected request body, plus the
/// optional validated terminal trailers frame that follows it.
///
/// Exists only as the pump's *source*: it turns one `Bytes` into a bounded
/// sequence of refcounted slices so the pump has something to be backpressured
/// on. The size hint stays exact, so `Content-Length` framing is identical to
/// handing the transport the reusable `Bytes` directly.
///
/// `trailers` is only ever populated from the gRPC-Web plugin's validated
/// staging representation (the same source `ReplayableRequestBody` accepts),
/// and is emitted strictly AFTER the last DATA slice, so the replayable
/// mesh/HBONE/Unix paths keep their existing frame ordering across the bridge.
struct BufferedUploadFrames {
    remaining: Bytes,
    trailers: Option<http::HeaderMap>,
}

impl http_body::Body for BufferedUploadFrames {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.remaining.is_empty() {
            let take = this.remaining.len().min(BUFFERED_UPLOAD_FRAME_BYTES);
            return Poll::Ready(Some(Ok(Frame::data(this.remaining.split_to(take)))));
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.remaining.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // Trailers carry no DATA bytes, so the declared length is exactly the
        // DATA still to cross the bridge.
        http_body::SizeHint::with_exact(self.remaining.len() as u64)
    }
}

/// Transport-side body for a pumped BUFFERED upload.
///
/// The streaming dispatch paths reach [`UploadPumpSource`] through
/// `SizeLimitedIncoming` / `CountingIncoming`, which also own byte counting,
/// the request-size ceiling, and gRPC message counting. A buffered upload has
/// already been counted, limited, and message-counted before it got here, so
/// this wrapper adds nothing but the `http_body::Body` shape the transport
/// needs.
pub struct PumpedUploadBody {
    source: UploadPumpSource,
}

impl PumpedUploadBody {
    /// Hand this body to reqwest.
    ///
    /// `reqwest::Body::wrap` preserves `size_hint()`, so hyper still derives an
    /// exact `Content-Length` from the buffered length.
    pub(crate) fn into_reqwest_body(self) -> reqwest::Body {
        reqwest::Body::wrap(self)
    }
}

impl http_body::Body for PumpedUploadBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.get_mut().source.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.source.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.source.size_hint()
    }
}

/// Install the gateway-owned backend write watermark on a fully buffered
/// upload (issue #4055).
///
/// `Err(bytes)` hands the caller its `Bytes` back untouched, which is the
/// allocation-, task-, and timer-free path the buffered dispatch used before:
/// taken when `backend_write_timeout_ms == 0` (the operator opt-out) or when
/// the upload is empty (nothing to write, and the request must stay
/// end-of-stream at headers).
pub(crate) fn spawn_buffered_upload_pump(
    body: Bytes,
    write_timeout_ms: u64,
) -> Result<(PumpedUploadBody, UploadPumpJoin), Bytes> {
    if write_timeout_ms == 0 || body.is_empty() {
        return Err(body);
    }
    let (source, join) = spawn_upload_pump(
        BufferedUploadFrames {
            remaining: body,
            trailers: None,
        },
        // No authorization plan: a buffered upload was already collected under
        // `collect_request_body_under_authorization`, and the response-header
        // wait still composes the admitted stream's deadline through
        // `compose_dispatch_phase_auth_bound`. Arming a second, pump-owned
        // expiry here would reorder that precedence.
        None,
        write_timeout_ms,
    );
    Ok((PumpedUploadBody { source }, join))
}

/// The buffered bridge's frame size, exposed so a test can prove the source is
/// sliced rather than handed over whole. Reached through `crate::_test_support`.
#[allow(dead_code)]
pub(crate) const fn buffered_upload_frame_bytes() -> usize {
    BUFFERED_UPLOAD_FRAME_BYTES
}

/// Install the gateway-owned backend write watermark on a REPLAYABLE upload —
/// the buffered/body-policy/retry-replay bodies the specialized HBONE, mesh
/// mTLS, and Unix HTTP transports dispatch (issue #4055).
///
/// Same contract as [`spawn_buffered_upload_pump`], with two differences that
/// the replayable paths need:
///
/// * the validated terminal trailers frame rides the bridge after the last
///   DATA slice, so gRPC-Web terminal metadata is preserved in order, and
/// * an upload with NO data but non-empty trailers still gets a pump: a
///   trailers frame is transport work, so treating it as "nothing to write"
///   would silently reopen the same watermark bypass for it.
///
/// `Err((data, trailers))` hands the inputs back untouched, which is the
/// allocation-, task-, and timer-free path these dispatches used before: taken
/// when `backend_write_timeout_ms == 0` (the operator opt-out) or when there is
/// neither DATA nor trailers to write (the request must stay end-of-stream at
/// headers).
///
/// No authorization plan is armed here for the same reason as the buffered
/// pump: these bodies were already collected under
/// `collect_request_body_under_authorization`, and the response-header wait
/// still composes the admitted stream's deadline through
/// `compose_dispatch_phase_auth_bound`.
// Keeping the fallback tuple inline is deliberate: this is the allocation-free
// operator opt-out path, so boxing the HeaderMap merely to shrink Result would
// add an allocation to the exact path this API promises leaves untouched.
#[allow(clippy::type_complexity, clippy::result_large_err)]
pub(crate) fn spawn_replayable_upload_pump(
    data: Bytes,
    trailers: Option<http::HeaderMap>,
    write_timeout_ms: u64,
) -> Result<(UploadPumpSource, UploadPumpJoin), (Bytes, Option<http::HeaderMap>)> {
    if write_timeout_ms == 0 || (data.is_empty() && trailers.is_none()) {
        return Err((data, trailers));
    }
    Ok(spawn_upload_pump(
        BufferedUploadFrames {
            remaining: data,
            trailers,
        },
        None,
        write_timeout_ms,
    ))
}

/// [`spawn_replayable_upload_pump`] with a write watermark that the native
/// gRPC dispatcher arms only after it has acquired a backend sender.
// See `spawn_replayable_upload_pump`: the large fallback stays inline so the
// disabled-watermark path remains allocation-free.
#[allow(clippy::type_complexity, clippy::result_large_err)]
pub(crate) fn spawn_replayable_upload_pump_with_deferred_write(
    data: Bytes,
    trailers: Option<http::HeaderMap>,
    write_timeout_ms: u64,
) -> Result<(UploadPumpSource, UploadPumpJoin), (Bytes, Option<http::HeaderMap>)> {
    if write_timeout_ms == 0 || (data.is_empty() && trailers.is_none()) {
        return Err((data, trailers));
    }
    Ok(spawn_upload_pump_with_deferred_write(
        BufferedUploadFrames {
            remaining: data,
            trailers,
        },
        None,
        write_timeout_ms,
    ))
}

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
//! future** and hands the transport a bounded channel receiver instead. The
//! pump selects, biased, over four things on every iteration:
//!
//! 1. an explicit cancellation signal from the dispatcher,
//! 2. the admitted stream's absolute authorization deadline (when present),
//! 3. `backend_write_timeout_ms` idle while waiting for the transport to
//!    consume the previous frame (`sender.reserve()`),
//! 4. the next unit of work (channel capacity, then one source frame).
//!
//! Because arms 1–3 are polled by the gateway — never by the backend
//! transport — they fire **even while that transport is parked on flow control
//! and is not polling the body at all**. When any of them fires the pump
//! publishes a terminal state, drops its channel sender, and drops the
//! `Incoming`. From that instant the gateway neither owns nor polls the client
//! body.
//!
//! # Who polls the pump (issue #5505)
//!
//! The pump is one boxed future, and the gateway drives it in one of two ways:
//!
//! * **Inline, from the dispatcher's own task.** A pump whose only owner-side
//!   bound is `backend_write_timeout_ms` is polled by
//!   [`UploadPumpJoin::backend_write_watermark_expired`], the arm every
//!   dispatcher already races against its response-header wait
//!   (`await_upload_write_watermark_first`). The write watermark cannot arm
//!   before a transport's first body poll, and every transport first polls the
//!   body inside that race, so nothing the pump enforces can become due while
//!   no one is polling it. An ordinary request/response upload finishes here:
//!   no task is spawned and no cross-task hop is paid per frame.
//! * **Detached, on its own task.** A pump that carries an authorization
//!   lifetime is detached at install: that deadline is absolute and armed
//!   immediately, and the dispatcher may still be inside a pre-dispatch wait
//!   (pool acquisition, admission) that polls nothing else. An inline pump is
//!   detached when the race that was polling it ends before the pump has
//!   resolved — the response head arrived first, a NACK replay is about to
//!   replace it, or the join is dropped — so from then on it behaves exactly
//!   as the always-spawned pump did, post-EOS drain watch included. A pump
//!   that has already resolved is never detached. A pump with nothing to
//!   enforce at all (no plan, `backend_write_timeout_ms = 0`) is also
//!   detached at install: no watermark race will ever poll it, so inline it
//!   would relay nothing. Production never installs one, but the contract of
//!   the join does not depend on that.
//!
//! Both modes run the same loop and publish the same terminals; the mode only
//! decides which task polls it.
//!
//! The write idle arm is reset at the start of each `reserve()` wait and is
//! not polled while waiting on the client body, so a slow-but-progressing
//! upload stays alive and a stalled client is not misread as a backend write
//! stall. `backend_write_timeout_ms == 0` leaves that arm unarmed.
//!
//! # Buffered uploads take the direct route (issue #5505)
//!
//! A fully buffered upload has nothing to relay: every byte is already in
//! memory, and the gateway owns no client body it must keep polling. Bridging
//! it through the channel anyway had a cost the profile made visible — the
//! first transport poll found an empty bridge, so hyper flushed the request
//! head alone and wrote the body in a second TLS record and a second
//! `writev`, and every frame paid a channel hop. Such an upload is therefore
//! handed to the transport as a **direct source** ([`UploadFrames::Direct`]):
//! the transport takes refcounted slices of the buffer synchronously, so the
//! head and body leave in one write, and records each take in a shared
//! [`DirectUploadProgress`]. A **watcher** ([`run_direct_upload_watch`]) —
//! the same boxed future the join point drives, in the same two modes —
//! enforces the same terminals from that record: `backend_write_timeout_ms`
//! of transport idleness ends the upload with `WriteTimeout`, the
//! dispatcher's cancellation with `Cancelled`, a released body with
//! `ConsumerGone`, and the last frame taken with `Completed`, followed by the
//! same post-EOS drain judgment. What the watermark measures is unchanged:
//! time since the transport last took a frame while frames remained.
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
//! The dispatcher holds an [`UploadPumpJoin`], whose
//! [`cancel_and_join`](UploadPumpJoin::cancel_and_join) is an actual join: it
//! resolves only after the pump has published its outcome, which it does after
//! dropping the source. Dropping [`UploadPumpSource`] closes the bridge, which
//! the pump observes on its next poll whatever else it is waiting on, so no
//! pump can outlive the body the transport owns.
//!
//! # Enforceable boundary
//!
//! Frames the pump handed to the transport *before* expiry may still be sitting
//! in that transport's own buffers and may reach the wire afterwards — the
//! gateway does not own those bytes and makes no claim about them. What is
//! enforced is narrower and exact: after the deadline the gateway polls no
//! further client body, hands the transport no further client byte, discards
//! anything still queued inside the pump channel (a direct source has no
//! queue; its remaining slices are simply never handed over), and terminates
//! the transport body with an error rather than a clean end-of-stream, so a
//! backend can never mistake a truncated upload for a complete one.
//!
//! # Cost
//!
//! One boxed future, one capacity-1 channel, and two control `oneshot`s per
//! streaming upload that carries an authorization plan **or** a live
//! `backend_write_timeout_ms`; the timers live inside the future. A task is
//! spawned only for the detached mode above. Uploads with neither bound keep
//! `UploadSource::Direct` (no future, no channel, no timer). Frames move by
//! `Bytes` handle, so no per-chunk copy or allocation is introduced.
//!
//! A fully BUFFERED upload under a live `backend_write_timeout_ms` pays one
//! boxed watcher, one shared progress record, and the two control `oneshot`s
//! — no channel, no relay, no per-frame hop — and nothing at all when the
//! bound is `0`; see [`spawn_buffered_upload_pump`]. Its frames are refcounted
//! `Bytes::split_to` slices of the collected buffer, so it copies nothing
//! either.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;

use crate::proxy::backend_send_queue::diagnostics as drain_diagnostics;
use crate::proxy::backend_send_queue::{
    BackendSocketHandle, BackendSocketSlot, await_send_queue_stall,
};
use crate::proxy::body::BoxError;
use crate::proxy::{RequestAuthLifetimePlan, optional_sleep_elapsed};

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
/// Transient marker, never an outcome: the transport released the body only
/// after taking every declared byte (issue #4411). Set by
/// [`UploadPumpSource`]'s `Drop` in place of `PUMP_CONSUMER_GONE`, read by the
/// pump when the bridge closes, and overwritten by the pump's own terminal.
/// `code_outcome` maps it to `None` like any unknown code.
const PUMP_CONSUMER_DONE: u8 = 7;

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

/// Records that the transport released the body it was fed, so a pump can
/// never outlive that body.
///
/// Dropping [`UploadPumpSource`] drops the bridge receiver, and the pump
/// observes the closed bridge on its very next poll: `sender.reserve()` fails
/// while it waits for capacity, and a dedicated `sender.closed()` arm fires
/// while it waits on the client body (see `run_upload_pump`). The pump then
/// publishes its own terminal and drops the client body — whichever task is
/// driving it, and however the transport's own connection task is parked. A
/// direct source has no bridge; its `Drop` tells the watcher the same thing
/// through [`DirectUploadProgress::consumer_left`].
///
/// The terminal is ALSO recorded here, before the receiver drops, for the
/// pump to read when it sees the closed bridge: releasing the transport body
/// IS the "consumer went away" outcome. `RUNNING` is the only state it may
/// overwrite, so a pump that already settled keeps its own outcome — a pump
/// that has published a terminal has, by construction, already dropped the
/// client body and the bridge sender, and the only work it can still be doing
/// is the post-EOS send-queue drain watch (issue #4411), which is
/// self-bounding: it ends on a drained queue, an unanswerable socket, a
/// cancellation, or the write watermark.
///
/// The state check alone is not enough: hyper's HTTP/1 length-delimited
/// encoder ends the message on its OWN eof — the moment the last declared byte
/// is written — and drops the body without polling it for the trailing end of
/// stream. That drop can land before the pump has read the client's end of
/// stream and published `Completed`, so [`UploadPumpSource`]'s `Drop`
/// suppresses this marker when every byte the client declared has already
/// crossed the bridge: such a transport is done consuming, not gone.
struct ReleasePumpOnDrop {
    terminal: Arc<AtomicU8>,
    /// Set by [`UploadPumpSource`]'s `Drop` when the transport released the
    /// body only after taking every declared byte.
    suppressed: bool,
}

impl Drop for ReleasePumpOnDrop {
    fn drop(&mut self) {
        if self.suppressed {
            return;
        }
        let _ = self.terminal.compare_exchange(
            PUMP_RUNNING,
            PUMP_CONSUMER_GONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

/// Where the transport-side body takes its frames from.
enum UploadFrames {
    /// Relayed by the pump over the bridge channel: a streaming client body
    /// the gateway must keep owning and polling.
    Bridged(tokio::sync::mpsc::Receiver<Frame<Bytes>>),
    /// A fully buffered upload, sliced on demand and handed over synchronously
    /// (issue #5505). Nothing is relayed: the transport takes refcounted
    /// slices of the collected buffer straight from this body, and reports
    /// each take to the watcher through `progress`.
    Direct {
        frames: BufferedUploadFrames,
        progress: Arc<DirectUploadProgress>,
    },
}

/// Transport-side half of the pump: an `http_body`-shaped view over the bridge
/// channel — or over the buffered upload itself — installed inside the
/// gateway's own request-body adapters.
pub struct UploadPumpSource {
    frames: UploadFrames,
    terminal: Arc<AtomicU8>,
    /// Held only for its `Drop`.
    _release: ReleasePumpOnDrop,
    /// Size hint snapshotted from the client body before it moved into the
    /// pump, so `Content-Length` framing survives the bridge unchanged.
    initial_hint: http_body::SizeHint,
    /// Arms `backend_write_timeout_ms` on the FIRST transport poll (issue
    /// #4074). Present only for a pump whose write watermark is
    /// consumer-armed; the native-gRPC deferred pump hands this sender to its
    /// dispatcher instead, and a pump with no write bound has none at all.
    write_start: Option<tokio::sync::oneshot::Sender<()>>,
    delivered: u64,
    ended: bool,
    reported_error: bool,
}

impl Drop for UploadPumpSource {
    fn drop(&mut self) {
        // A transport that releases the body only after taking every byte the
        // client declared has finished consuming it, not abandoned it: hyper's
        // HTTP/1 length-delimited encoder does exactly this without polling
        // for the trailing end of stream. The pump is then at most one
        // iteration from publishing `Completed` — and, for a live
        // `backend_write_timeout_ms`, it still owns the post-EOS send-queue
        // drain judgment (issue #4411). Marking the consumer gone here would
        // end that bound on precisely the uploads it exists for: the ones the
        // peer's kernel absorbed whole and never read. A body released early
        // — fewer bytes delivered than declared, or no declared length at all
        // — keeps the marker, exactly as before.
        let done = self.ended || self.initial_hint.exact() == Some(self.delivered);
        if done {
            self._release.suppressed = true;
            // Tell the pump WHY its bridge is about to close, so a closed
            // channel reads as completion rather than as a consumer that went
            // away. `RUNNING` only: a pump that already settled keeps its own
            // outcome, and the pump overwrites this marker with its terminal.
            let _ = self.terminal.compare_exchange(
                PUMP_RUNNING,
                PUMP_CONSUMER_DONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        // A direct source has no bridge whose close the watcher could observe,
        // so the release is reported to it explicitly, with the same verdict.
        if let UploadFrames::Direct { progress, .. } = &self.frames {
            progress.consumer_left(done);
        }
    }
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
            let _ = write_start.send(());
        }
        // Every poll of a direct source — including one that finds nothing
        // left — is proof the transport is consuming it right now, which is
        // what the write watermark measures idleness from.
        if let UploadFrames::Direct { progress, .. } = &self.frames {
            progress.polled();
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
        match &mut self.frames {
            UploadFrames::Direct { frames, progress } => match frames.next_frame() {
                Some(frame) => {
                    if let Some(data) = frame.data_ref() {
                        self.delivered = self.delivered.saturating_add(data.len() as u64);
                    }
                    if frames.is_end_stream() {
                        progress.consumer_took_last_frame();
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                None => {
                    self.ended = true;
                    progress.consumer_took_last_frame();
                    Poll::Ready(None)
                }
            },
            UploadFrames::Bridged(receiver) => match receiver.poll_recv(cx) {
                Poll::Ready(Some(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        self.delivered = self.delivered.saturating_add(data.len() as u64);
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(None) => {
                    // The pump publishes its terminal state before dropping the
                    // sender, so a closed channel always has an authoritative
                    // outcome to read. An absent one means the pump future was
                    // dropped mid-flight without reaching a terminal; fail
                    // closed with an error so the backend resets the stream
                    // instead of accepting a truncated upload as complete.
                    match code_outcome(self.terminal.load(Ordering::Acquire)) {
                        Some(UploadPumpOutcome::Completed) => {
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
            },
        }
    }

    /// `true` only after a CLEAN end of stream.
    ///
    /// A pump that ended on a non-clean terminal stays `false` forever, even
    /// once [`poll_frame`](Self::poll_frame) has fused: the upload did not
    /// complete, and saying otherwise would let a backend treat a truncated
    /// request as a whole one.
    ///
    /// A direct source is also at its end once the transport has taken its
    /// last frame — nothing of the upload remains unhanded — so an HTTP/2
    /// transport can flag `END_STREAM` on that DATA frame instead of sending
    /// an empty one, exactly as it did for the reusable `Bytes` body before
    /// the watermark was installed on buffered uploads.
    pub(crate) fn is_end_stream(&self) -> bool {
        self.ended
            || match &self.frames {
                UploadFrames::Direct { frames, .. } => frames.is_end_stream(),
                UploadFrames::Bridged(_) => false,
            }
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

/// The pump future, boxed once at install and polled to completion by exactly
/// one task at a time.
type PumpFuture = Pin<Box<dyn Future<Output = UploadPumpOutcome> + Send + 'static>>;

/// Which task is polling one pump (issue #5505). See the module docs, "Who
/// polls the pump".
enum PumpDriver {
    /// Polled from the dispatcher's task by
    /// [`UploadPumpJoin::backend_write_watermark_expired`] and
    /// [`UploadPumpJoin::join`] / [`UploadPumpJoin::cancel_and_join`]. No task
    /// exists for it yet.
    Inline(PumpFuture),
    /// Running on its own task; its outcome arrives over this channel.
    Detached(tokio::sync::oneshot::Receiver<UploadPumpOutcome>),
    /// Reached a terminal; retained until the join point reads it.
    Finished(UploadPumpOutcome),
    /// The join point has already reported the outcome.
    Consumed,
}

/// Dispatcher-side half of the pump: the join point.
pub(crate) struct UploadPumpJoin {
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    /// Arms a write watermark the DISPATCHER owns, once it has acquired a
    /// backend sender. `None` for a consumer-armed pump (the ordinary case,
    /// where the transport's first body poll arms it) and for a pump with no
    /// write bound at all.
    write_start: Option<tokio::sync::oneshot::Sender<()>>,
    driver: PumpDriver,
    /// [`backend_write_watermark_expired`](UploadPumpJoin::backend_write_watermark_expired)
    /// fires exactly once per pump; afterwards it is "never".
    write_timeout_reported: bool,
    /// Shared with the pump and with [`UploadPumpSource`]'s release guard.
    /// Read only as a FALLBACK, when a detached task published no outcome of
    /// its own (its runtime shut down under it).
    terminal: Arc<AtomicU8>,
    /// Where the dispatcher publishes the backend socket this upload is being
    /// written to, so the pump can bound the POST-EOS send-queue drain
    /// (issue #4411). Empty for a transport that cannot expose a socket, which
    /// leaves that bound disarmed.
    socket: BackendSocketSlot,
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
            let _ = write_start.send(());
        }
    }

    /// Publish the backend socket this upload is being written to, so
    /// `backend_write_timeout_ms` also bounds the post-EOS drain of the local
    /// send queue (issue #4411).
    ///
    /// Call immediately before `send_request` — strictly before any body frame
    /// can cross the bridge — so the pump either observes the socket for the
    /// whole drain or observes none at all. Write-once: a replayed attempt
    /// installs a fresh pump, so a second binding on the same pump is ignored
    /// rather than silently re-pointing a live watch at another connection.
    ///
    /// `None` is the ordinary case for a transport whose socket the gateway
    /// does not own (HBONE's tunnelled inner client): the drain bound stays
    /// disarmed and `backend_read_timeout_ms` governs, as before. The bundled
    /// HTTP client reaches the same slot from the other side — see
    /// [`backend_socket_slot`](Self::backend_socket_slot).
    pub(crate) fn bind_backend_socket(&mut self, socket: Option<Arc<BackendSocketHandle>>) {
        if let Some(socket) = socket {
            let _ = self.socket.set(socket);
        }
    }

    /// The same write-once slot, for a dispatcher that cannot hand over a
    /// socket itself and must let the transport publish one (issue #4411).
    ///
    /// The bundled HTTP client never gives the gateway its `TcpStream`; its
    /// connector reports a newly dialed socket through the vendored
    /// connection-admission hook instead. `await_upload_write_watermark_first`
    /// arms this slot as a task-local around the dispatch future so that hook
    /// has somewhere to publish. Write-once semantics are unchanged: a
    /// dispatcher that also calls [`bind_backend_socket`](Self::bind_backend_socket)
    /// wins, and a second dial in the same scope is ignored.
    pub(crate) fn backend_socket_slot(&self) -> BackendSocketSlot {
        Arc::clone(&self.socket)
    }

    /// Ask the pump to stop if this handle is dropped without an explicit
    /// join.
    ///
    /// Used by dispatchers whose upload lifecycle is scoped to the handler
    /// (direct-H2): every residual early return then still releases the inbound
    /// client body promptly, even where an `.await` join is not reachable.
    /// Dispatchers whose upload legitimately outlives the handler — the
    /// streaming-response transports, where the transport owns the body and
    /// releasing the [`UploadPumpSource`] ends the pump — must NOT arm this.
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
    /// Resolves only after the pump has published its terminal state, which it
    /// does *after* dropping the client body — so once this returns, the
    /// gateway provably owns and polls no part of the inbound upload. Every
    /// wait inside the pump sits in a `select!` with the cancellation arm, so
    /// this join is bounded by the pump's own scheduling, not by the backend's
    /// flow-control window. An inline pump is finished right here, on the
    /// caller's task; a detached one is joined over its channel.
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
    /// For an inline pump this arm IS the pump's driver (issue #5505): every
    /// poll of it advances the relay, and the relay's own wakers — the client
    /// body, the bridge, the timers — wake the task that owns the `select!`.
    /// The watermark cannot arm before the transport's first body poll, and no
    /// transport takes that poll before its dispatcher enters this race, so
    /// nothing the pump enforces can fall due while no one is polling it.
    ///
    /// Cancel-safe, and non-consuming: the pump stays where it is, so a caller
    /// that loses this race can still [`cancel_and_join`] and read the typed
    /// terminal. Any other terminal — and a pump with no write bound at all —
    /// turns this into a future that stays pending forever, so a `select!` arm
    /// built on it cannot fire spuriously. It resolves only after the pump has
    /// published its terminal and dropped the client body.
    ///
    /// [`cancel_and_join`]: Self::cancel_and_join
    pub(crate) async fn backend_write_watermark_expired(&mut self) {
        if !self.write_timeout_reported
            && self.drive_to_terminal().await == Some(UploadPumpOutcome::WriteTimeout)
        {
            self.write_timeout_reported = true;
            return;
        }
        never().await
    }

    /// Hand an inline pump to its own task if the caller is about to stop
    /// polling it before it has resolved (issue #5505).
    ///
    /// Called by `await_upload_write_watermark_first` when its race ends, and
    /// by `Drop`. Whatever the pump is still doing — relaying frames because
    /// the backend answered before consuming the upload, parked on backend
    /// flow control, not yet having observed a bridge the transport just
    /// released, or watching the post-EOS send-queue drain (issue #4411) — it
    /// continues on its own task exactly as the always-spawned pump did, so a
    /// dispatcher that races the watermark again later (direct-H2's upload
    /// completion wait) or joins it still observes the same terminals. A pump
    /// that has already resolved is never spawned.
    ///
    /// "Already resolved" is judged by one more poll, not by the last one the
    /// race happened to make: the event that ends most pumps — the transport
    /// taking the last frame, or releasing the body — happens inside the
    /// dispatch future's own poll, and if that same poll also produced the
    /// response head the race ended before the pump could observe it. Polling
    /// it once here lets it publish `Completed` in place instead of paying a
    /// task to do so a moment later.
    pub(crate) fn detach_if_live(&mut self) {
        if self.settle_inline() {
            return;
        }
        self.detach(&drain_diagnostics::PUMP_DETACHED_LIVE);
    }

    /// Give an inline pump one poll, without a task, and record its terminal
    /// if that poll reaches it. `true` when it did.
    ///
    /// A pump that has just been told to cancel settles this way by
    /// construction: every wait in the relay is a `biased` `select!` whose
    /// first arm is the cancellation. A pump whose consumer has just finished
    /// with it or released it settles the same way; one still relaying, or
    /// parked on flow control, reports `Pending` and is detached instead.
    ///
    /// Polled through a no-op waker on purpose: if the pump does settle, no
    /// wake is owed to anyone; if it does not, the task it is handed to
    /// re-registers every waker on its own first poll. Requires a runtime, as
    /// the relay's timers do; outside one the caller detaches instead, which
    /// knows how to drop the pump.
    fn settle_inline(&mut self) -> bool {
        if tokio::runtime::Handle::try_current().is_err() {
            return false;
        }
        let PumpDriver::Inline(pump) = &mut self.driver else {
            return false;
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match pump.as_mut().poll(&mut cx) {
            Poll::Ready(outcome) => {
                self.driver = PumpDriver::Finished(outcome);
                true
            }
            Poll::Pending => false,
        }
    }

    /// Which task is driving this pump right now: `Some(false)` inline on the
    /// dispatcher's, `Some(true)` on one of its own, `None` once it has
    /// reached its terminal. Reached through `crate::_test_support`.
    #[allow(dead_code)]
    pub(crate) fn runs_on_own_task(&self) -> Option<bool> {
        match self.driver {
            PumpDriver::Inline(_) => Some(false),
            PumpDriver::Detached(_) => Some(true),
            PumpDriver::Finished(_) | PumpDriver::Consumed => None,
        }
    }

    /// Move an inline pump onto its own task. No-op for every other driver.
    fn detach(&mut self, counter: &drain_diagnostics::Counter) {
        if !matches!(self.driver, PumpDriver::Inline(_)) {
            return;
        }
        let PumpDriver::Inline(pump) = std::mem::replace(&mut self.driver, PumpDriver::Consumed)
        else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
                handle.spawn(async move {
                    let _ = finished_tx.send(pump.await);
                });
                self.driver = PumpDriver::Detached(finished_rx);
                drain_diagnostics::bump(counter);
            }
            Err(_) => {
                // No runtime can poll it: dropping the future drops the client
                // body and the bridge sender at once. Publish the terminal the
                // transport side will read, so the release is reported as a
                // cancellation rather than as an absent outcome.
                let _ = self.terminal.compare_exchange(
                    PUMP_RUNNING,
                    outcome_code(UploadPumpOutcome::Cancelled),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                drop(pump);
                self.driver = PumpDriver::Finished(
                    code_outcome(self.terminal.load(Ordering::Acquire))
                        .unwrap_or(UploadPumpOutcome::Cancelled),
                );
            }
        }
    }

    /// Drive the pump to its terminal on the caller's task (inline) or wait
    /// for its task to publish one (detached), and remember it.
    ///
    /// Non-consuming and cancel-safe: an inline pump dropped mid-poll keeps its
    /// state in `self.driver`; a detached pump's channel keeps its value.
    ///
    /// A detached task that published nothing (its `finished` sender dropped
    /// with it, which only a runtime shutdown can cause) falls back to the
    /// shared terminal, so the join point reports the last state the pump or
    /// the transport recorded rather than collapsing it into "no outcome".
    async fn drive_to_terminal(&mut self) -> Option<UploadPumpOutcome> {
        let outcome = match &mut self.driver {
            PumpDriver::Inline(pump) => Some(pump.as_mut().await),
            PumpDriver::Detached(finished) => match finished.await {
                Ok(outcome) => Some(outcome),
                Err(_) => code_outcome(self.terminal.load(Ordering::Acquire)),
            },
            PumpDriver::Finished(outcome) => Some(*outcome),
            PumpDriver::Consumed => None,
        };
        self.driver = match outcome {
            Some(outcome) => PumpDriver::Finished(outcome),
            None => PumpDriver::Consumed,
        };
        outcome
    }

    /// The pump's terminal state, reported once.
    async fn await_outcome(&mut self) -> Option<UploadPumpOutcome> {
        let outcome = self.drive_to_terminal().await;
        self.driver = PumpDriver::Consumed;
        outcome
    }
}

impl Drop for UploadPumpJoin {
    fn drop(&mut self) {
        if self.cancel_on_drop {
            self.cancel();
        }
        // An inline pump loses its only poller with this handle. One poll
        // finishes a pump that was just told to stop, or whose consumer is
        // already done with it; any other still gets a task so it observes
        // cancellation, its deadlines, the closed bridge, and end of stream,
        // and still releases the client body.
        self.detach_if_live();
    }
}

/// Move a client request body into a gateway-owned pump.
///
/// The caller must have established that the body is not already at end of
/// stream; an empty upload needs no pump and keeps the direct path.
///
/// Despite the name, a task is spawned here only for a pump that carries an
/// authorization `plan`; a watermark-only pump is driven inline by the
/// dispatcher's race until it finishes or that race ends first (issue #5505,
/// module docs).
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
    let (mut controls, side) = PumpControls::new(write_timeout_ms, arm);
    let auth_armed = plan.is_some();
    let pump: PumpFuture = Box::pin(run_upload_pump(UploadPumpTask {
        body,
        sender,
        cancel_rx: side.cancel_rx,
        plan: plan.cloned(),
        write_timeout_ms,
        write_start_rx: side.write_start_rx,
        terminal: side.terminal,
        socket: side.socket,
    }));
    let mut join = controls.join(pump);
    // An authorization lifetime is absolute and armed right now, and the
    // dispatcher installing it may still be inside a pre-dispatch wait that
    // polls nothing else (pool acquisition, admission). It needs its own task
    // from the start. A watermark-only pump has nothing due before the
    // dispatcher's race starts polling it (see the module docs).
    //
    // A pump with nothing to enforce at all is a plain relay: no watermark race
    // will ever drive it, so inline it would relay nothing. Production never
    // installs one (`UploadSource::install_pump` returns early), but the join
    // contract must not depend on that.
    if auth_armed || write_timeout_ms == 0 {
        join.detach(&drain_diagnostics::PUMP_DETACHED_AT_INSTALL);
    }
    (
        controls.source(UploadFrames::Bridged(receiver), initial_hint),
        join,
    )
}

/// The dispatcher- and transport-side ends of one pump's controls, built the
/// same way for the bridged relay and for the direct buffered watcher.
struct PumpControls {
    cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
    dispatcher_write_start: Option<tokio::sync::oneshot::Sender<()>>,
    consumer_write_start: Option<tokio::sync::oneshot::Sender<()>>,
    terminal: Arc<AtomicU8>,
    socket: BackendSocketSlot,
}

/// The pump's own ends of those controls, moved into its future.
struct PumpSideControls {
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    write_start_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    terminal: Arc<AtomicU8>,
    socket: BackendSocketSlot,
}

impl PumpControls {
    fn new(write_timeout_ms: u64, arm: WriteWatermarkArm) -> (Self, PumpSideControls) {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        // One channel, one owner. A pump with no write bound creates none at
        // all, so `write_configured` and the arm condition can never disagree.
        let (dispatcher_write_start, consumer_write_start, write_start_rx) =
            if write_timeout_ms == 0 {
                (None, None, None)
            } else {
                let (tx, rx) = tokio::sync::oneshot::channel();
                match arm {
                    WriteWatermarkArm::Dispatcher => (Some(tx), None, Some(rx)),
                    WriteWatermarkArm::Consumer => (None, Some(tx), Some(rx)),
                }
            };
        let terminal = Arc::new(AtomicU8::new(PUMP_RUNNING));
        // Filled by the dispatcher before `send_request` when the gateway owns
        // the backend socket (issue #4411); left empty otherwise.
        let socket: BackendSocketSlot = Arc::new(std::sync::OnceLock::new());
        (
            Self {
                cancel_tx: Some(cancel_tx),
                dispatcher_write_start,
                consumer_write_start,
                terminal: Arc::clone(&terminal),
                socket: Arc::clone(&socket),
            },
            PumpSideControls {
                cancel_rx,
                write_start_rx,
                terminal,
                socket,
            },
        )
    }

    /// The join point, holding `pump` inline.
    fn join(&mut self, pump: PumpFuture) -> UploadPumpJoin {
        UploadPumpJoin {
            cancel: self.cancel_tx.take(),
            write_start: self.dispatcher_write_start.take(),
            driver: PumpDriver::Inline(pump),
            write_timeout_reported: false,
            terminal: Arc::clone(&self.terminal),
            socket: Arc::clone(&self.socket),
            cancel_on_drop: false,
        }
    }

    /// The transport-side body over `frames`.
    fn source(self, frames: UploadFrames, initial_hint: http_body::SizeHint) -> UploadPumpSource {
        UploadPumpSource {
            frames,
            terminal: Arc::clone(&self.terminal),
            _release: ReleasePumpOnDrop {
                terminal: self.terminal,
                suppressed: false,
            },
            initial_hint,
            write_start: self.consumer_write_start,
            delivered: 0,
            ended: false,
            reported_error: false,
        }
    }
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

/// State moved into the gateway-owned upload pump.
///
/// Keeping the controls together makes their shared lifecycle explicit: every
/// sender is consumed by exactly one pump invocation and every terminal path
/// publishes through the shared terminal before releasing anything.
struct UploadPumpTask<B> {
    body: B,
    sender: tokio::sync::mpsc::Sender<Frame<Bytes>>,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    plan: Option<RequestAuthLifetimePlan>,
    write_timeout_ms: u64,
    write_start_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    terminal: Arc<AtomicU8>,
    socket: BackendSocketSlot,
}

/// The relay itself. Its return value is the pump's terminal, published to the
/// shared state — and the client body and bridge sender released — BEFORE it
/// returns, so whichever task awaits this future (inline dispatcher or
/// detached task) observes a fully released upload the moment it resolves.
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
        socket,
    } = task;
    let mut cancel = Some(cancel_rx);
    // Absolute and armed once when a credential admitted the stream. Relayed
    // DATA, gRPC messages, and trailers never refresh it, and it is owned by
    // THIS pump, so it fires regardless of what the backend transport is doing.
    // A pump with no plan builds no timer at all.
    let expiry = plan
        .as_ref()
        .map(|(deadline, _, _)| tokio::time::sleep_until(deadline.at));
    tokio::pin!(expiry);
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
    // nonzero, and the timer exists only when the bound does, so a pump
    // installed purely for an authorization lifetime carries no write timer
    // (issue #4074). It is registered with the runtime lazily, on its first
    // poll — which cannot happen before the watermark is armed.
    let write_idle_dur = Duration::from_millis(write_timeout_ms);
    let write_idle = write_configured.then(|| tokio::time::sleep(write_idle_dur));
    tokio::pin!(write_idle);
    let outcome = 'pump: loop {
        // Reserve capacity BEFORE reading the client, so a transport that
        // stops draining stops the read rather than filling a buffer.
        if write_armed
            && let Some(idle) = write_idle.as_mut().as_pin_mut()
            && let Some(at) = tokio::time::Instant::now().checked_add(write_idle_dur)
        {
            idle.reset(at);
        }
        let permit = tokio::select! {
            biased;
            () = cancel_requested(&mut cancel) => break 'pump UploadPumpOutcome::Cancelled,
            () = optional_sleep_elapsed(expiry.as_mut()) => {
                if let Some((deadline, family, latch)) = plan.as_ref() {
                    latch.record_once(deadline.termination, *family);
                }
                break 'pump UploadPumpOutcome::AuthorizationExpired;
            }
            () = signal_requested(&mut write_start), if write_configured && !write_armed => {
                write_armed = true;
                continue 'pump;
            }
            () = optional_sleep_elapsed(write_idle.as_mut()), if write_armed => {
                break 'pump UploadPumpOutcome::WriteTimeout;
            }
            reserved = sender.reserve() => match reserved {
                Ok(permit) => permit,
                // A closed bridge is the consumer going away — unless the
                // consumer released the body only after taking every declared
                // byte (issue #4411). hyper's HTTP/1 length-delimited encoder
                // does exactly that, without polling for the trailing end of
                // stream, so the client body's own `None` is never observed
                // here; the delivered upload is complete all the same, and the
                // post-EOS drain judgment below still runs for it.
                Err(_) if terminal.load(Ordering::Acquire) == PUMP_CONSUMER_DONE => {
                    break 'pump UploadPumpOutcome::Completed;
                }
                Err(_) => break 'pump UploadPumpOutcome::ConsumerGone,
            },
        };
        let frame = 'frame: loop {
            break tokio::select! {
                biased;
                () = cancel_requested(&mut cancel) => break 'pump UploadPumpOutcome::Cancelled,
                () = optional_sleep_elapsed(expiry.as_mut()) => {
                    if let Some((deadline, family, latch)) = plan.as_ref() {
                        latch.record_once(deadline.termination, *family);
                    }
                    break 'pump UploadPumpOutcome::AuthorizationExpired;
                }
                () = signal_requested(&mut write_start), if write_configured && !write_armed => {
                    write_armed = true;
                    continue 'frame;
                }
                // The transport released the body while this pump was waiting
                // on the client — parked on a slow client, not on the bridge.
                // With a permit already in hand `reserve()` cannot report the
                // close, so watch for it here; otherwise a pump could sit on a
                // client that never sends another byte, owning that body, for
                // a transport that is long gone. Same terminals as the
                // `reserve()` error above.
                () = sender.closed() => {
                    drop(permit);
                    if terminal.load(Ordering::Acquire) == PUMP_CONSUMER_DONE {
                        break 'pump UploadPumpOutcome::Completed;
                    }
                    break 'pump UploadPumpOutcome::ConsumerGone;
                }
                frame = http_body_util::BodyExt::frame(&mut body) => frame,
            };
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
    // Resolving this future is what tells the join point about the terminal,
    // so a dispatcher woken by `backend_write_watermark_expired` already
    // observes the terminal state, the closed bridge, and a released body.
    settle_after_terminal(PostTerminal {
        outcome,
        write_configured,
        write_armed,
        write_timeout_ms,
        socket: &socket,
        cancel: &mut cancel,
    })
    .await
}

/// What the post-terminal judgment below needs from a pump that has just
/// published its terminal and released everything it owned.
struct PostTerminal<'a> {
    outcome: UploadPumpOutcome,
    write_configured: bool,
    write_armed: bool,
    write_timeout_ms: u64,
    socket: &'a BackendSocketSlot,
    cancel: &'a mut Option<tokio::sync::oneshot::Receiver<()>>,
}

/// The pump's return value once its terminal is published: the terminal
/// itself, or — for a completed upload under a live, armed write watermark —
/// the post-EOS send-queue drain verdict (issue #4411).
async fn settle_after_terminal(settle: PostTerminal<'_>) -> UploadPumpOutcome {
    let PostTerminal {
        outcome,
        write_configured,
        write_armed,
        write_timeout_ms,
        socket,
        cancel,
    } = settle;
    if outcome == UploadPumpOutcome::WriteTimeout {
        return outcome;
    }
    if outcome != UploadPumpOutcome::Completed || !write_configured || !write_armed {
        if write_configured {
            if outcome == UploadPumpOutcome::Completed {
                drain_diagnostics::bump(&drain_diagnostics::POST_EOS_UNARMED);
            } else {
                drain_diagnostics::bump(&drain_diagnostics::POST_EOS_NOT_COMPLETED);
            }
        }
        return outcome;
    }
    // Post-EOS transport-drain bound (issue #4411).
    //
    // Every client byte has now crossed the bridge and the transport body is at
    // a clean end of stream, so the pre-EOS idle arm above can never fire
    // again — and HTTP gives the gateway no request-side acknowledgement to
    // wait on. The remaining evidence is the kernel's: bytes this gateway wrote
    // that the peer has not accepted. A backend that `accept()`s and never
    // reads leaves them parked for the life of the connection, so a send queue
    // that is non-empty and never shrinks for `backend_write_timeout_ms` is the
    // write stall the watermark promises to bound.
    //
    // `sender` and `body` were dropped above BEFORE this point on purpose: the
    // transport must see the clean EOS and flush its last frames to the socket
    // before the drain is judged.
    let Some(socket) = socket.get() else {
        // No socket was published for this dispatch: a tunnelled HBONE upload,
        // HTTP/3, or a bundled-HTTP-client request served on an ALREADY-POOLED
        // connection (nothing was dialed, so patch 004's hook never fired).
        // Disarmed exactly as before #4411; `backend_read_timeout_ms` governs.
        drain_diagnostics::bump(&drain_diagnostics::POST_EOS_NO_SOCKET);
        return outcome;
    };
    drain_diagnostics::bump(&drain_diagnostics::POST_EOS_WATCHED);
    let stalled = tokio::select! {
        biased;
        // A dispatcher that got its response head (or gave up) cancels; the
        // drain is only interesting while the header wait is still running.
        () = cancel_requested(cancel) => {
            drain_diagnostics::bump(&drain_diagnostics::POST_EOS_CANCELLED);
            false
        }
        stalled = await_send_queue_stall(socket, write_timeout_ms) => stalled,
    };
    if !stalled {
        drain_diagnostics::bump(&drain_diagnostics::POST_EOS_NOT_STALLED);
        return outcome;
    }
    drain_diagnostics::bump(&drain_diagnostics::POST_EOS_STALLED);
    // Deliberately WITHOUT restating the shared terminal: the upload itself did
    // complete cleanly and the transport already observed that end of stream.
    // Rewriting it to a non-clean terminal would describe a whole upload as a
    // truncated one. What the dispatcher needs is only the signal that the
    // write watermark fired, which is what `backend_write_watermark_expired`
    // races against the response-header wait; this return value is it.
    UploadPumpOutcome::WriteTimeout
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

/// Frame size a fully buffered upload is handed to the transport in.
///
/// The watermark measures idleness from the transport's most recent take, so
/// it stays coupled to transport consumption only while frames remain to hand
/// over. A single giant frame would let hyper "consume" the whole upload in
/// one pull — completing the watch — while not one byte had reached the wire,
/// which is the opposite of what `backend_write_timeout_ms` promises. Slicing
/// keeps the judgment tied to the transport until the last byte has actually
/// been taken.
///
/// 64 KiB matches hyper's own write granularity and costs no copy: `split_to`
/// hands out a refcounted view of the same allocation.
const BUFFERED_UPLOAD_FRAME_BYTES: usize = 64 * 1024;

/// Zero-copy chunked view over a fully collected request body, plus the
/// optional validated terminal trailers frame that follows it.
///
/// It turns one `Bytes` into a bounded sequence of refcounted slices, handed
/// over one per transport poll, so the write watermark has per-frame progress
/// to judge. The size hint stays exact, so `Content-Length` framing is
/// identical to handing the transport the reusable `Bytes` directly.
///
/// `trailers` is only ever populated from the gRPC-Web plugin's validated
/// staging representation (the same source `ReplayableRequestBody` accepts),
/// and is emitted strictly AFTER the last DATA slice, so the replayable
/// mesh/HBONE/Unix paths keep their existing frame ordering.
struct BufferedUploadFrames {
    remaining: Bytes,
    trailers: Option<http::HeaderMap>,
}

impl BufferedUploadFrames {
    /// The next frame, synchronously: every frame of a buffered upload is
    /// already in memory, so there is never anything to wait for.
    fn next_frame(&mut self) -> Option<Frame<Bytes>> {
        if !self.remaining.is_empty() {
            let take = self.remaining.len().min(BUFFERED_UPLOAD_FRAME_BYTES);
            return Some(Frame::data(self.remaining.split_to(take)));
        }
        self.trailers.take().map(Frame::trailers)
    }

    fn is_end_stream(&self) -> bool {
        self.remaining.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // Trailers carry no DATA bytes, so the declared length is exactly the
        // DATA still to hand over.
        http_body::SizeHint::with_exact(self.remaining.len() as u64)
    }
}

/// The transport is still taking frames.
const DIRECT_CONSUMING: u8 = 0;
/// The transport took the last frame, or released the body only after taking
/// every declared byte: the upload is complete.
const DIRECT_DONE: u8 = 1;
/// The transport released the body with frames still unhanded.
const DIRECT_RELEASED: u8 = 2;

/// `last_progress_ms` before the transport's first poll.
const DIRECT_NOT_POLLED: u64 = u64::MAX;

/// What the transport side of a direct buffered source reports to its watcher
/// (issue #5505).
///
/// The bridged pump learns about transport consumption from its channel: a
/// `reserve()` that waits is a transport that stopped taking frames, and a
/// closed channel is a transport that released the body. A direct source has
/// no channel, so the transport records the same two facts here — one atomic
/// store per frame, and one notification per state change. Progress itself
/// never wakes the watcher: its idle timer re-arms from the recorded instant
/// whenever it fires, so a transport draining frame after frame costs the
/// dispatcher's task no poll.
struct DirectUploadProgress {
    /// Anchor for `last_progress_ms`, so the paused test clock is honoured.
    epoch: tokio::time::Instant,
    /// Milliseconds after `epoch` of the transport's most recent body poll,
    /// or [`DIRECT_NOT_POLLED`].
    last_progress_ms: AtomicU64,
    /// [`DIRECT_CONSUMING`], [`DIRECT_DONE`], or [`DIRECT_RELEASED`].
    consumer: AtomicU8,
    /// Woken on the first poll and on every `consumer` change.
    wake: tokio::sync::Notify,
}

impl DirectUploadProgress {
    fn new() -> Self {
        Self {
            epoch: tokio::time::Instant::now(),
            last_progress_ms: AtomicU64::new(DIRECT_NOT_POLLED),
            consumer: AtomicU8::new(DIRECT_CONSUMING),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// The transport polled the body: it is consuming this upload right now.
    fn polled(&self) {
        let now_ms = u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let was = self.last_progress_ms.swap(now_ms, Ordering::AcqRel);
        if was == DIRECT_NOT_POLLED {
            // The first poll is what lets a dispatcher-armed watermark start
            // measuring from real consumption; later polls are judged by the
            // timer when it fires.
            self.wake.notify_one();
        }
    }

    /// The transport took the last frame: nothing of the upload remains
    /// unhanded.
    fn consumer_took_last_frame(&self) {
        self.publish(DIRECT_DONE);
    }

    /// The transport released the body: `done` when it had already taken
    /// every declared byte, in which case the upload is complete all the same
    /// (hyper's HTTP/1 length-delimited encoder does exactly this).
    fn consumer_left(&self, done: bool) {
        self.publish(if done { DIRECT_DONE } else { DIRECT_RELEASED });
    }

    fn publish(&self, state: u8) {
        if self
            .consumer
            .compare_exchange(DIRECT_CONSUMING, state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.wake.notify_one();
        }
    }

    /// When the transport last showed progress, if it has polled at all.
    fn last_progress(&self) -> Option<tokio::time::Instant> {
        match self.last_progress_ms.load(Ordering::Acquire) {
            DIRECT_NOT_POLLED => None,
            ms => Some(self.epoch + Duration::from_millis(ms)),
        }
    }
}

/// State moved into the direct buffered watcher.
struct DirectUploadWatch {
    progress: Arc<DirectUploadProgress>,
    write_timeout_ms: u64,
    controls: PumpSideControls,
}

/// The watcher of a direct buffered source: the pump's terminals and bounds,
/// without the relay (issue #5505).
///
/// It relays nothing — the transport takes frames from the buffer itself — so
/// all it does is judge. It resolves `Completed` or `ConsumerGone` when the
/// transport reports either, `Cancelled` on the dispatcher's signal, and
/// `WriteTimeout` when an armed write watermark finds the transport idle:
/// `backend_write_timeout_ms` since the transport's latest poll, or since the
/// dispatcher armed it, whichever is later. On a non-clean terminal it
/// publishes that terminal, which the transport body reports as its next
/// frame in place of the upload's remaining bytes — the same fail-closed
/// truncation the bridged pump performs by closing its channel. A completed
/// upload under an armed watermark then owns the post-EOS drain judgment
/// exactly as the bridged pump does.
async fn run_direct_upload_watch(task: DirectUploadWatch) -> UploadPumpOutcome {
    let DirectUploadWatch {
        progress,
        write_timeout_ms,
        controls:
            PumpSideControls {
                cancel_rx,
                write_start_rx: mut write_start,
                terminal,
                socket,
            },
    } = task;
    let mut cancel = Some(cancel_rx);
    let write_configured = write_timeout_ms > 0;
    let write_idle_dur = Duration::from_millis(write_timeout_ms);
    // Registered with the runtime lazily, on its first poll, which cannot
    // happen before the watermark is armed.
    let write_idle = write_configured.then(|| tokio::time::sleep(write_idle_dur));
    tokio::pin!(write_idle);
    // `Some` from the moment the watermark is armed: a transport that never
    // polls after that is idle from the arming instant.
    let mut write_armed_at: Option<tokio::time::Instant> = None;
    let outcome = loop {
        match progress.consumer.load(Ordering::Acquire) {
            DIRECT_DONE => break UploadPumpOutcome::Completed,
            DIRECT_RELEASED => break UploadPumpOutcome::ConsumerGone,
            _ => {}
        }
        if let Some(armed_at) = write_armed_at
            && let Some(idle) = write_idle.as_mut().as_pin_mut()
        {
            // Idle since the transport's latest poll; since the arming instant
            // only for a dispatcher-armed watermark whose transport has not
            // polled at all yet (a consumer-armed one records its first poll
            // in the same instant it arms).
            let since = progress.last_progress().unwrap_or(armed_at);
            let due = since + write_idle_dur;
            if tokio::time::Instant::now() >= due {
                break UploadPumpOutcome::WriteTimeout;
            }
            idle.reset(due);
        }
        tokio::select! {
            biased;
            () = cancel_requested(&mut cancel) => break UploadPumpOutcome::Cancelled,
            () = signal_requested(&mut write_start), if write_configured && write_armed_at.is_none() => {
                write_armed_at = Some(tokio::time::Instant::now());
            }
            // Re-judged at the top of the loop against the progress recorded
            // since this timer was armed.
            () = optional_sleep_elapsed(write_idle.as_mut()), if write_armed_at.is_some() => {}
            () = progress.wake.notified() => {}
        }
    };
    // Publish BEFORE resolving: the transport body reads this on its next poll,
    // and the dispatcher woken by `backend_write_watermark_expired` must
    // already observe it.
    terminal.store(outcome_code(outcome), Ordering::Release);
    settle_after_terminal(PostTerminal {
        outcome,
        write_configured,
        write_armed: write_armed_at.is_some(),
        write_timeout_ms,
        socket: &socket,
        cancel: &mut cancel,
    })
    .await
}

/// Install the write watermark on a fully buffered upload as a direct source
/// with a watcher, in place of a relaying pump.
fn spawn_direct_upload_watch(
    frames: BufferedUploadFrames,
    write_timeout_ms: u64,
    arm: WriteWatermarkArm,
) -> (UploadPumpSource, UploadPumpJoin) {
    let initial_hint = frames.size_hint();
    let (mut controls, side) = PumpControls::new(write_timeout_ms, arm);
    let progress = Arc::new(DirectUploadProgress::new());
    let watch: PumpFuture = Box::pin(run_direct_upload_watch(DirectUploadWatch {
        progress: Arc::clone(&progress),
        write_timeout_ms,
        controls: side,
    }));
    // No authorization plan is ever armed on a buffered upload, so nothing is
    // due before the dispatcher's race starts polling this watcher: it is
    // driven inline and detached only if that race ends first.
    let join = controls.join(watch);
    (
        controls.source(UploadFrames::Direct { frames, progress }, initial_hint),
        join,
    )
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
    // No authorization plan: a buffered upload was already collected under
    // `collect_request_body_under_authorization`, and the response-header
    // wait still composes the admitted stream's deadline through
    // `compose_dispatch_phase_auth_bound`. Arming a second, pump-owned expiry
    // here would reorder that precedence.
    let (source, join) = spawn_direct_upload_watch(
        BufferedUploadFrames {
            remaining: body,
            trailers: None,
        },
        write_timeout_ms,
        WriteWatermarkArm::Consumer,
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
    Ok(spawn_direct_upload_watch(
        BufferedUploadFrames {
            remaining: data,
            trailers,
        },
        write_timeout_ms,
        WriteWatermarkArm::Consumer,
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
    Ok(spawn_direct_upload_watch(
        BufferedUploadFrames {
            remaining: data,
            trailers,
        },
        write_timeout_ms,
        WriteWatermarkArm::Dispatcher,
    ))
}

//! Gateway-owned cancellation for authenticated H1/H2 streaming responses
//! (issue #3815).
//!
//! # Why a body adapter alone cannot enforce an authorization deadline
//!
//! [`TotalDeadlineBody`](crate::proxy::body) fires only when hyper polls the
//! response body, and hyper does not always poll it:
//!
//! * **HTTP/2.** hyper's `PipeToSendStream` reserves stream send capacity and
//!   awaits `SendStream::poll_capacity` *before* it polls the body. A client
//!   that advertises `SETTINGS_INITIAL_WINDOW_SIZE: 0` — or that simply stops
//!   issuing `WINDOW_UPDATE` — parks that pipe for as long as it likes, and no
//!   timer living inside the body can be observed while it is parked.
//! * **HTTP/1.1.** the dispatcher flushes a connection that can no longer buffer
//!   before it polls the body, so a client that stops reading parks the write
//!   and the body is never polled either.
//!
//! Both are client-controlled, so a body-only bound is not an enforceable
//! authorization lifetime: the credential expires, and the admitted stream and
//! everything it holds survive at the client's discretion. This mirrors exactly
//! the reason the request direction needs
//! [`upload_pump`](crate::proxy::upload_pump).
//!
//! # The ownership model
//!
//! The upstream body is moved into ONE gateway-scheduled task — the response
//! pump — which is its sole owner and sole poller for the rest of its life. The
//! client-visible [`AuthorizationCancellableBody`] holds only the receiving end
//! of a bounded channel. Nothing is shared between the two except the channel,
//! a handful of write-once flags, and the terminal-owner CAS below, so:
//!
//! * There is **no lock on the response path.** The previous shape put the
//!   upstream behind a `std::sync::Mutex` and acquired it for every
//!   authenticated response frame, which both violates the repository's
//!   no-avoidable-locks hot-path invariant and lets a task enforcing the
//!   deadline block behind somebody else's inner `poll_frame`.
//! * There is **no terminal race.** Every terminal — the upstream's own and the
//!   authorization bound's — is settled by one compare-and-swap
//!   ([`AuthorizationTerminalOwner`]), so a body that reached its own terminal
//!   before the deadline can no longer be counted or closed by a concurrent
//!   observer, and a body still in flight at the deadline cannot escape it by
//!   completing in parallel.
//!
//! # One winner, decided by a CAS rather than by who is scheduled first
//!
//! The pump and the protocol adapter that wraps this body ([`TotalDeadlineBody`],
//! which owns the client-visible gRPC / gRPC-Web / HTTP terminal shapes) are two
//! independently scheduled observers of ONE response. Exactly one of them must
//! settle it, and which one may not depend on the runtime's scheduling order:
//!
//! * A **boolean** "did it expire?" flag is not enough. The adapter reads it,
//!   the pump publishes an expiry and closes the channel, and the adapter — in
//!   the SAME poll — then delivers the frame the pump had already queued, or the
//!   generic released-upstream error instead of the protocol-correct
//!   authorization terminal.
//! * A **timer** in the adapter is not enough either, in the other direction:
//!   the pump can poll the upstream to its own terminal well BEFORE the deadline
//!   and queue it, and — because the downstream transport is parked on flow
//!   control or on an unreadable socket — that queued terminal may not be polled
//!   until long after the deadline. An independent sleep would then overwrite a
//!   completed response with an authorization terminal, set the classification
//!   flag, and record the latch for a stream this contract never terminated.
//! * Reading NEITHER, and simply deferring to the pump, makes a poll that
//!   arrives at/after the deadline depend on the pump's timer task having been
//!   scheduled first — which the client, not the gateway, decides.
//!
//! [`AuthorizationTerminalOwner`] resolves all three. It is a shared
//! compare-and-swap over `{Open, InnerCompletion, AuthorizationExpiry}` carrying
//! the ONE absolute deadline instant, so:
//!
//! * either observer may claim the bound the moment the clock reaches it, with
//!   no timer and no allocation, and the first claim is final;
//! * the upstream's own terminal is claimable only while the clock is still
//!   BEFORE the deadline, so a completion can never overtake an elapsed bound
//!   because a tokio timer had not fired yet;
//! * a claimed expiry is visible to every observer before the channel closure
//!   that wakes them, so no protected frame queued before the bound can be
//!   delivered after it.
//!
//! Enforcement is unaffected by which side claims: releasing the upstream and
//! closing the transport are the pump's own work and are never waited on a
//! downstream poll.
//!
//! [`TotalDeadlineBody`]: crate::proxy::body
//!
//! # What this module guarantees
//!
//! Two gateway-owned mechanisms, armed from the same absolute plan and settled
//! through the same once-only latch:
//!
//! 1. **Upstream cancellation.** At the deadline the pump drops the backend
//!    body it owns. From that instant the gateway reads no further byte from the
//!    backend, and the backend stream, its pooled connection, and every guard
//!    rooted in that body are released — regardless of what hyper is parked on.
//!    A cancelled or dropped pump does the same thing through the ordinary task
//!    drop, so no detached producer can survive the response body.
//!
//! 2. **Transport close.** Dropping the upstream does not release what the
//!    RESPONSE body still owns: the request guard, the per-IP guard,
//!    circuit-breaker / load-balancer accounting, backend-admission permits, and
//!    the deferred transaction logger all live in `ProxyBody`, which hyper owns.
//!    If the downstream still has not drained the terminal a bounded grace after
//!    the deadline, the pump asks the connection task to close this client
//!    connection. hyper then drops the response body, which releases all of the
//!    above exactly once through the ordinary `Drop` path, and the client
//!    observes a protocol-visible termination: a `GOAWAY` followed by a close on
//!    HTTP/2, and a chunked or SSE body that ends without its terminating chunk
//!    on HTTP/1.1.
//!
//! # Backpressure and ordering
//!
//! The channel bound is [`RESPONSE_PUMP_CAPACITY`] — one frame. The pump
//! reserves capacity BEFORE it reads the next frame, so at most one frame is
//! ever in flight and the backend feels the downstream's backpressure almost
//! exactly as it did when hyper polled it directly. A full channel parks the
//! pump on `reserve()`, which is precisely why the deadline arm is biased ahead
//! of it: backpressure delays delivery, it never delays enforcement.
//!
//! Frames, trailers, and the terminal travel in order through one FIFO channel.
//! An upstream error is delivered as an error, never collapsed into a clean end
//! of stream, and an expiry closes the channel WITHOUT a terminal so the
//! downstream cannot mistake it for a complete response either.
//!
//! # Deliberate trade-off: HTTP/2 connection scope
//!
//! HTTP/2 gives a server no way to reset ONE stream from outside hyper: the
//! `h2::SendStream` is owned by the parked pipe. The transport close is
//! therefore connection-scoped, and sibling streams on the same connection end
//! with it. It is preceded by `graceful_shutdown` (a `GOAWAY`, then a bounded
//! settle window in which sibling streams can still complete), and it is only
//! ever reached for a connection that is demonstrably refusing to drain an
//! already-expired authenticated stream. Leaving that stream parked instead
//! would let a hostile client retain a request slot, a per-IP slot, an admission
//! permit, and a load-balancer connection indefinitely — which is the thing this
//! contract exists to prevent.
//!
//! # Redaction
//!
//! The only string this module can publish is a compiled-in literal. No expiry
//! instant, claim, subject, certificate field, provider, route, or backend
//! target reaches it.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::mpsc;

use crate::proxy::auth_lifetime::{
    AuthorizationConnectionCloser, StreamAuthDeadline, StreamAuthProtocolFamily,
    StreamAuthTermination, StreamAuthTerminationLatch,
};
use crate::proxy::body::ProxyBodyError;

/// How long after the authorization deadline the gateway waits for the
/// downstream to drain the protocol-correct terminal before closing the client
/// connection.
///
/// Long enough to absorb ordinary scheduling jitter on a loaded runner — a
/// client that is merely slow gets its `grpc-status: 16` trailers, its bounded
/// gRPC-Web frame, or its deterministic body error, and the connection survives.
/// Short enough that "terminated within a bounded grace at the validated
/// deadline" stays true for a client that is not draining at all.
pub(crate) const TRANSPORT_CLOSE_GRACE: Duration = Duration::from_secs(2);

/// In-flight frames between the gateway-owned pump and the client-visible body.
///
/// Deliberately ONE. The pump reserves a slot before reading, so this is the
/// entire buffering this adapter introduces over polling the upstream inline:
/// one frame, fixed, per authenticated streaming response. Anything larger
/// would blunt backend backpressure and would hold more protected bytes in
/// gateway memory past the deadline for no benefit.
const RESPONSE_PUMP_CAPACITY: usize = 1;

/// Fixed terminal for a body whose pump ended without delivering a terminal of
/// its own — an expiry this body itself observed, or a cancelled/dead pump.
///
/// Deliberately an error rather than a clean end of stream: a client must be
/// able to tell an authorization termination from a complete response. The
/// protocol adapter outside this body substitutes the protocol-correct terminal
/// (native `grpc-status: 16` trailers, the bounded gRPC-Web frame, the fixed
/// HTTP/SSE message) for the expiry case, so this message reaches a client only
/// when nothing wrapped this body.
const RELEASED_MESSAGE: &str =
    "authenticated stream terminated: authorization lifetime elapsed, upstream released";

/// One item moved from the gateway-owned pump to the client-visible body.
///
/// `End` and `Error` are explicit rather than implied by channel closure, so
/// "the upstream finished" and "the pump was cancelled at the deadline" are
/// distinguishable at the receiving end. Collapsing them would turn an
/// authorization termination into a clean, complete-looking response.
enum PumpItem {
    Frame(Frame<Bytes>),
    End,
    Error(ProxyBodyError),
}

/// Which owner settled one authenticated streaming response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationTerminalOwnership {
    /// Unclaimed: the upstream has not reached a terminal of its own and the
    /// authorization bound has not elapsed. Protected frames may be delivered.
    Open,
    /// The upstream reached its OWN terminal — a clean end of stream or an
    /// upstream error — while the credential was still authorized. That
    /// terminal is the client-visible one, however long the transport then
    /// takes to drain it.
    InnerCompletion,
    /// The admitted credential's authorization lifetime elapsed first. The
    /// protocol-correct authorization terminal is the client-visible one and no
    /// queued protected frame may be delivered.
    AuthorizationExpiry,
}

const TERMINAL_OPEN: u8 = 0;
const TERMINAL_INNER_COMPLETION: u8 = 1;
const TERMINAL_AUTHORIZATION_EXPIRY: u8 = 2;

const fn decode_ownership(claimed: u8) -> AuthorizationTerminalOwnership {
    match claimed {
        TERMINAL_INNER_COMPLETION => AuthorizationTerminalOwnership::InnerCompletion,
        TERMINAL_AUTHORIZATION_EXPIRY => AuthorizationTerminalOwnership::AuthorizationExpiry,
        _ => AuthorizationTerminalOwnership::Open,
    }
}

#[derive(Debug)]
struct TerminalOwnerState {
    /// The admitted credential's ONE absolute authorization deadline. Every
    /// observer decides "is this at/after expiry?" from this instant, so a poll
    /// arriving at/after the bound settles it itself instead of depending on
    /// the pump's timer task having been scheduled first.
    deadline_at: tokio::time::Instant,
    claimed: AtomicU8,
}

/// The single terminal owner for one authenticated streaming response, shared
/// by the gateway-owned pump and the protocol adapter outside the body.
///
/// Carries no class, instant beyond the bound, or identity: the bounded
/// termination class travels through [`StreamAuthTerminationLatch`] as before.
#[derive(Clone, Debug)]
pub(crate) struct AuthorizationTerminalOwner(Arc<TerminalOwnerState>);

impl AuthorizationTerminalOwner {
    pub(crate) fn new(deadline_at: tokio::time::Instant) -> Self {
        Self(Arc::new(TerminalOwnerState {
            deadline_at,
            claimed: AtomicU8::new(TERMINAL_OPEN),
        }))
    }

    /// The hot-path gate every response poll takes BEFORE it can deliver a
    /// frame: one acquire load, plus one monotonic clock read while the
    /// response is still unclaimed. No lock, no allocation, and no timer
    /// registration — a poll that never happens is enforced by the pump's own
    /// deadline arm instead.
    ///
    /// A poll at/after the bound CLAIMS the expiry here, so the security
    /// decision does not wait on another task being scheduled.
    #[inline]
    pub(crate) fn observe(&self) -> AuthorizationTerminalOwnership {
        let claimed = self.0.claimed.load(Ordering::Acquire);
        if claimed != TERMINAL_OPEN {
            return decode_ownership(claimed);
        }
        if tokio::time::Instant::now() < self.0.deadline_at {
            return AuthorizationTerminalOwnership::Open;
        }
        self.claim(TERMINAL_AUTHORIZATION_EXPIRY)
    }

    /// [`Self::observe`] projected to the only question a response poll asks:
    /// "is this response settled as an authorization expiry?"
    #[inline]
    pub(crate) fn observe_expiry(&self) -> bool {
        self.observe() == AuthorizationTerminalOwnership::AuthorizationExpiry
    }

    /// Whether the authorization bound has ALREADY been claimed, without
    /// consulting the clock.
    ///
    /// Used for the re-check immediately after an inner poll, where the only
    /// new information is a concurrent claim: the clock was read at the top of
    /// the same poll, so reading it again would decide nothing.
    #[inline]
    pub(crate) fn expiry_claimed(&self) -> bool {
        self.0.claimed.load(Ordering::Acquire) == TERMINAL_AUTHORIZATION_EXPIRY
    }

    /// Claim this response for the upstream's OWN terminal. `true` when this
    /// call won.
    ///
    /// Refused once the authorization deadline has elapsed, measured against
    /// the same instant every observer uses — so a terminal produced at/after
    /// the bound can never overtake it merely because a tokio timer had not
    /// fired yet. A refusal settles the response as an expiry, fail-closed.
    pub(crate) fn claim_inner_completion(&self) -> bool {
        if tokio::time::Instant::now() >= self.0.deadline_at {
            self.claim(TERMINAL_AUTHORIZATION_EXPIRY);
            return false;
        }
        self.claim(TERMINAL_INNER_COMPLETION) == AuthorizationTerminalOwnership::InnerCompletion
    }

    /// Claim this response for the authorization bound, returning the winner.
    /// Idempotent: a bound another observer already claimed stays claimed.
    pub(crate) fn claim_authorization_expiry(&self) -> AuthorizationTerminalOwnership {
        self.claim(TERMINAL_AUTHORIZATION_EXPIRY)
    }

    fn claim(&self, owner: u8) -> AuthorizationTerminalOwnership {
        match self.0.claimed.compare_exchange(
            TERMINAL_OPEN,
            owner,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => decode_ownership(owner),
            Err(claimed) => decode_ownership(claimed),
        }
    }
}

/// Aborts the pump when the client-visible body is dropped, so no producer can
/// outlive the body it feeds. The task's own drop releases the upstream body it
/// owns, which is what makes cancellation and expiry release identical state.
struct AbortPumpOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortPumpOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Why the pump stopped. Only [`PumpExit::Expired`] is an authorization
/// termination.
enum PumpExit {
    /// The upstream reached its own terminal (clean end or error) and that
    /// terminal was handed to the channel. This response completed; it is
    /// never counted and never closes a connection, however long the transport
    /// then holds the finished body.
    Completed,
    /// The client-visible body was dropped, so there is nothing left to deliver
    /// to and nothing left holding request accounting.
    DownstreamGone,
    /// The absolute authorization deadline elapsed while this response was
    /// still in flight.
    Expired,
}

/// A streaming response body whose upstream is owned by a gateway task and
/// released at the admitted credential's authorization deadline, without the
/// downstream transport polling anything.
pub struct AuthorizationCancellableBody {
    receiver: mpsc::Receiver<PumpItem>,
    /// Set once this body handed the downstream a terminal of its own. Read by
    /// the pump only to decide whether the transport close is still needed.
    settled: Arc<AtomicBool>,
    /// Local mirror of `settled` for the "already done, return `None`" fast
    /// path. Not shared, so no atomic load per poll after completion.
    finished: bool,
    /// Set by the pump once it no longer owns the upstream body. Observed
    /// through `crate::_test_support`.
    released: Arc<AtomicBool>,
    /// The ONE terminal owner, shared with the pump and with the protocol
    /// adapter that wraps this body.
    terminal: AuthorizationTerminalOwner,
    /// Bounded class, family, shared latch, and classification flag, so a bound
    /// this body claims on its own poll is accounted exactly once even when the
    /// pump is cancelled before its own deadline arm runs. Every one of these
    /// is idempotent, so the pump and the adapter may repeat it.
    termination: StreamAuthTermination,
    family: StreamAuthProtocolFamily,
    latch: StreamAuthTerminationLatch,
    fired: Arc<AtomicBool>,
    /// Held only for its `Drop`.
    _pump: AbortPumpOnDrop,
}

/// The fixed terminal for a body whose pump ended without delivering one.
///
/// Reachable only when this body is polled directly (the protocol adapter
/// outside it observes the same owner first and substitutes the
/// protocol-correct authorization terminal) or when the pump died.
fn released_terminal() -> ProxyBodyError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        RELEASED_MESSAGE,
    )) as ProxyBodyError
}

/// The gateway-owned response pump: sole owner and sole poller of `inner`.
#[allow(clippy::too_many_arguments)]
async fn run_response_pump<B>(
    mut inner: B,
    sender: mpsc::Sender<PumpItem>,
    deadline: StreamAuthDeadline,
    family: StreamAuthProtocolFamily,
    latch: StreamAuthTerminationLatch,
    fired: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    settled: Arc<AtomicBool>,
    terminal: AuthorizationTerminalOwner,
    closer: Option<AuthorizationConnectionCloser>,
) where
    B: http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + Unpin + 'static,
{
    // Absolute and armed once. Relayed DATA, SSE events, and gRPC messages
    // never refresh it, and this task is scheduled by the gateway, so it runs
    // while the downstream transport is parked.
    let expiry = tokio::time::sleep_until(deadline.at);
    tokio::pin!(expiry);

    let exit = loop {
        // Capacity first, so at most one frame is ever in flight and the
        // upstream is not read until the downstream can take what it produces.
        // The deadline arm is FIRST in this biased select: a full channel must
        // not be able to postpone enforcement, and a tie at the exact deadline
        // instant must resolve to the security decision.
        let permit = tokio::select! {
            biased;
            () = &mut expiry => break PumpExit::Expired,
            permit = sender.reserve() => match permit {
                Ok(permit) => permit,
                Err(_) => break PumpExit::DownstreamGone,
            },
        };
        // Same bias for the read itself: the upstream must not be able to hand
        // over a frame that is already past the credential's lifetime.
        let frame = tokio::select! {
            biased;
            () = &mut expiry => break PumpExit::Expired,
            frame = inner.frame() => frame,
        };
        match frame {
            Some(Ok(frame)) => {
                // A protected frame may only be queued while the bound is
                // unclaimed. The receiving side gates DELIVERY on the same
                // owner, so this is belt and braces — but it also stops the
                // pump reading one more frame past a bound another observer
                // has already settled.
                if terminal.expiry_claimed() {
                    break PumpExit::Expired;
                }
                permit.send(PumpItem::Frame(frame));
            }
            // Errors stay errors. Turning one into `End` would let a failed
            // backend look like a complete response.
            //
            // CLAIM BEFORE SENDING, on both terminal arms: the upstream's own
            // terminal is the client-visible one only if it wins the shared
            // CAS, which refuses once the bound has elapsed. Losing the claim
            // means an observer already settled this response as an expiry, so
            // the terminal is dropped rather than queued behind it.
            Some(Err(error)) => {
                if !terminal.claim_inner_completion() {
                    break PumpExit::Expired;
                }
                permit.send(PumpItem::Error(error));
                break PumpExit::Completed;
            }
            None => {
                if !terminal.claim_inner_completion() {
                    break PumpExit::Expired;
                }
                permit.send(PumpItem::End);
                break PumpExit::Completed;
            }
        }
    };

    // Release the backend body in EVERY exit path. This is the
    // security-critical step: from here the gateway reads no further protected
    // byte and the upstream stream, pooled connection, and body-rooted guards
    // are gone, whatever the downstream is doing. A cancelled pump reaches the
    // same state through the task's own drop.
    drop(inner);
    released.store(true, Ordering::Release);

    match exit {
        // A response that reached its own terminal before the deadline is not
        // an authorization termination. Deciding that here — in the single task
        // that owns the upstream — is what keeps the fixed-cardinality counter,
        // the shared latch, and the `fired` classification flag free of
        // completed responses without a check-then-act race. The decision stays
        // clear, so however long the transport then holds the finished body, no
        // later poll can reclassify it.
        PumpExit::Completed | PumpExit::DownstreamGone => {
            // Closing the channel is what lets the downstream distinguish an
            // expiry from a completion: a terminal was already queued for
            // `Completed`, and never is for `Expired`.
            drop(sender);
        }
        PumpExit::Expired => {
            // CLAIM BEFORE CLOSING. The closure below is what wakes a parked
            // receiver, and every observer reads the owner before it reads the
            // channel — so the claim must be visible to anything the closure
            // can wake. Idempotent: an observer that already claimed the bound
            // from its own poll stays the winner.
            terminal.claim_authorization_expiry();
            fired.store(true, Ordering::Release);
            // ONE latch, shared with the adapter outside this body, so the two
            // mechanisms record exactly one termination for the stream no
            // matter which of them fires first.
            latch.record_once(deadline.termination, family);
            drop(sender);
            let Some(closer) = closer else {
                return;
            };
            // Give the downstream a bounded chance to drain the
            // protocol-correct terminal on its own. A body that does so is
            // dropped, which aborts this task before the sleep completes.
            tokio::time::sleep(TRANSPORT_CLOSE_GRACE).await;
            if !settled.load(Ordering::Acquire) {
                closer.request_close();
            }
        }
    }
}

impl AuthorizationCancellableBody {
    /// Move `inner` into a gateway-owned pump bounded by `deadline`.
    ///
    /// `fired` is the same flag `TotalDeadlineBody` publishes, so a body that
    /// the downstream never polled still classifies as an authorization
    /// termination — health-neutral, with the bounded class — when `ProxyBody`
    /// is finally dropped by the transport close.
    ///
    /// `closer` is the client connection's close signal. `None` on frontends
    /// that own their own writes and already bound them (the native HTTP/3
    /// relays), where a transport close would be both unnecessary and wrong.
    pub(crate) fn new<B>(
        inner: B,
        deadline: StreamAuthDeadline,
        family: StreamAuthProtocolFamily,
        latch: StreamAuthTerminationLatch,
        fired: Arc<AtomicBool>,
        closer: Option<AuthorizationConnectionCloser>,
    ) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + Unpin + 'static,
    {
        let (sender, receiver) = mpsc::channel(RESPONSE_PUMP_CAPACITY);
        let settled = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let terminal = AuthorizationTerminalOwner::new(deadline.at);
        let handle = tokio::spawn(run_response_pump(
            inner,
            sender,
            deadline,
            family,
            latch.clone(),
            Arc::clone(&fired),
            Arc::clone(&released),
            Arc::clone(&settled),
            terminal.clone(),
            closer,
        ));
        Self {
            receiver,
            settled,
            finished: false,
            released,
            terminal,
            termination: deadline.termination,
            family,
            latch,
            fired,
            _pump: AbortPumpOnDrop(handle),
        }
    }

    /// The ONE terminal owner, for the protocol adapter that wraps this body.
    /// That adapter owns the client-visible terminal shapes and settles them
    /// through this same CAS — see the module documentation.
    pub(crate) fn terminal_owner(&self) -> AuthorizationTerminalOwner {
        self.terminal.clone()
    }

    fn settle(&mut self) {
        self.finished = true;
        self.settled.store(true, Ordering::Release);
    }

    /// Settle a bound this body observed itself. Every step is idempotent, so
    /// the pump's own expiry path and the adapter's terminal may repeat it.
    fn settle_authorization_expiry(&mut self) {
        self.settle();
        self.fired.store(true, Ordering::Release);
        self.latch.record_once(self.termination, self.family);
    }

    /// Whether the pump has released the upstream body. Reached through
    /// `crate::_test_support` so an external test can prove the release happens
    /// while the transport is polling nothing.
    #[allow(dead_code)]
    pub fn upstream_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }
}

impl http_body::Body for AuthorizationCancellableBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        // ONE-WINNER GATE, ahead of the channel and fail-closed. A frame the
        // pump queued while the credential was still authorized must not be
        // handed downstream once the bound has been reached, and a poll that
        // arrives at/after the bound claims it here rather than depending on
        // the pump's timer task having run first.
        if this.terminal.observe() == AuthorizationTerminalOwnership::AuthorizationExpiry {
            this.settle_authorization_expiry();
            return Poll::Ready(Some(Err(released_terminal())));
        }
        match this.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(PumpItem::Frame(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(PumpItem::End)) => {
                this.settle();
                Poll::Ready(None)
            }
            Poll::Ready(Some(PumpItem::Error(error))) => {
                this.settle();
                Poll::Ready(Some(Err(error)))
            }
            // The pump ended without a terminal: it was cancelled, or it died.
            // An expiry is settled by the gate above instead, so this stays the
            // defensive shape. Deliberately an error — a clean end of stream
            // here would be indistinguishable from a complete response.
            Poll::Ready(None) => {
                this.settle();
                Poll::Ready(Some(Err(released_terminal())))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        // Only a delivered terminal ends this stream. An expired pump is
        // deliberately NOT an end of stream: reporting one would let the
        // transport finish the response cleanly, which is exactly the outcome
        // an authorization termination must be distinguishable from.
        self.finished
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.finished {
            return http_body::SizeHint::with_exact(0);
        }
        // The remaining length is unknown, not zero, and the upstream's own
        // hint is no longer reachable from here. `SizeHint::default()` is what
        // keeps a transport from reconstructing a `Content-Length` for bytes
        // that may never come. The wrapper outside this one reports the same
        // thing for the whole authorization regime, so no framing decision
        // changes.
        http_body::SizeHint::default()
    }
}

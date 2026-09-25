//! Shared helpers for the HTTP/3 server/bridge paths.
//!
//! Centralises the logic needed to close out a request-body receive half
//! without the wire looking like a transport failure to the client. The
//! `stop_sending` helper must be invoked on any path that produces a
//! response (error or otherwise) while the client may still be pushing
//! body bytes — otherwise the recv half's `Drop` surfaces as
//! `RESET_STREAM(0x0)` on the QUIC wire and the client reports
//! "Remote reset: 0x0" plus a truncated upload.
//!
//! See RFC 9114 §8.1 (H3 error codes) and RFC 9000 §4.5 (STOP_SENDING).

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use bytes::Bytes;
use h3::error::Code;
use h3::quic::{RecvStream, SendStream, SendStreamStopped};
use h3::server::RequestStream;

/// Fixed gateway grace for writing an already-selected post-deadline /
/// post-timeout terminal H3 rejection (tiny HEADERS / trailers / FIN).
///
/// Independent of the expired client RPC deadline: racing that `Instant`
/// cancels on the first `Pending` poll and prevents response HEADERS from
/// becoming observable, while an unbounded await lets a flow-control-blocked
/// client retain the request task indefinitely (CWE-400 / CWE-770). One
/// second is long enough for a ready QUIC peer to accept a tiny rejection
/// under mild congestion, and short enough to bound retention when the peer
/// withholds credit. Not the detached plugin-cleanup bound — that governs
/// owned hook work, not the QUIC write.
pub(crate) const H3_POST_DEADLINE_TERMINAL_WRITE_GRACE: Duration = Duration::from_secs(1);

/// Result of a downstream HTTP/3 write that is bounded by the client's
/// absolute RPC deadline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum H3ResponseWriteError<E> {
    Write(E),
    DeadlineExceeded,
}

/// A deadline can still be reported with a clean terminal gRPC status only
/// while no response DATA has been offered to the H3 send half.
///
/// h3's `send_data` queues the DATA frame on `quic::SendStream::send_data`
/// *before* `poll_ready` waits for Quinn to accept the whole buffer. A
/// flow-control-blocked or cancelled write therefore leaves completed-write
/// accounting at 0 even though a prefix may already be client-visible. Callers
/// must pass the offered/queued byte count, charged when `send_data` is
/// actually polled. Once any DATA has been offered, resetting is the only safe
/// choice because a length-prefixed gRPC message may be partial.
#[inline]
pub(crate) fn grpc_deadline_can_send_terminal_status(bytes_offered: u64) -> bool {
    bytes_offered == 0
}

/// Race one potentially flow-control-blocked downstream H3 write against the
/// same absolute deadline that bounds the rest of the RPC.
///
/// The wait is expiry-first through [`crate::plugins::await_deadline_first`]:
/// an already-elapsed bound never polls `write`, and a biased deadline arm
/// wins an exact-deadline tie so a simultaneously writable DATA frame cannot
/// escape after the budget is spent. Dropping `write` cancels the h3 send
/// future; callers then reset the send half and drop/cancel their upstream
/// response body. No deadline keeps the no-timer hot path.
pub(crate) async fn await_response_write_before_deadline<F, T, E>(
    deadline: Option<tokio::time::Instant>,
    write: F,
) -> Result<T, H3ResponseWriteError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    match crate::plugins::await_deadline_first(deadline, write).await {
        Ok(result) => result.map_err(H3ResponseWriteError::Write),
        Err(()) => Err(H3ResponseWriteError::DeadlineExceeded),
    }
}

/// Give a terminal status/FIN one immediate polling opportunity, then keep the
/// write bounded by the same absolute RPC deadline.
///
/// This is only for the canonical zero-client-DATA deadline completion path.
/// The deadline has already fired when that path synthesizes `grpc-status: 4`,
/// so the normal deadline-biased helper would reject even an immediately-ready
/// trailer write. Biasing the write here preserves the clean gRPC status when
/// QUIC has credit, while a pending flow-control wait still loses immediately
/// to the expired deadline and is cancelled by the caller's stream reset.
///
/// For already-selected post-upload-cancel rejections that must remain visible
/// without unbounded retention, prefer
/// [`await_post_deadline_terminal_response_write`] — it uses a fresh gateway
/// grace instead of the expired client deadline.
pub(crate) async fn await_terminal_response_write_before_deadline<F, T, E>(
    deadline: Option<tokio::time::Instant>,
    write: F,
) -> Result<T, H3ResponseWriteError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let Some(deadline) = deadline else {
        return write.await.map_err(H3ResponseWriteError::Write);
    };

    tokio::pin!(write);
    let deadline_sleep = tokio::time::sleep_until(deadline);
    tokio::pin!(deadline_sleep);
    tokio::select! {
        biased;
        result = &mut write => result.map_err(H3ResponseWriteError::Write),
        () = &mut deadline_sleep => Err(H3ResponseWriteError::DeadlineExceeded),
    }
}

/// Await a post-deadline / post-timeout terminal rejection write under
/// [`H3_POST_DEADLINE_TERMINAL_WRITE_GRACE`].
///
/// Biases the write so an immediately-ready HEADERS/FIN completes; a Pending
/// flow-control wait is cancelled when the grace expires. Callers that see
/// [`H3ResponseWriteError::DeadlineExceeded`] must
/// [`abort_response_stream`]. Full-stream callers may then call
/// [`halt_request_body`] even after a mid-`recv_data` cancel: the vendored
/// h3-quinn transport keeps the receive stream reachable in that state. A
/// split-stream caller still leaves the halt to the task that owns its receive
/// half.
pub(crate) async fn await_post_deadline_terminal_response_write<F, T, E>(
    write: F,
) -> Result<T, H3ResponseWriteError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let grace_at = tokio::time::Instant::now() + H3_POST_DEADLINE_TERMINAL_WRITE_GRACE;
    await_terminal_response_write_before_deadline(Some(grace_at), write).await
}

/// Outcome of one downstream HTTP/3 body write raced against the admitted
/// stream's absolute authorization lifetime (issue #3815).
///
/// This is the single seam every H3 response writer uses, so the ~fifteen
/// `send_data` / `send_trailers` / `finish` call sites across the native-H3
/// and cross-protocol relays cannot drift apart in how they treat a write that
/// parks past the credential's deadline.
#[derive(Debug, PartialEq, Eq)]
pub enum H3AuthorizedWrite {
    /// The frame reached the QUIC send half.
    Written,
    /// The client's stream is gone; this is an ordinary disconnect.
    ClientWriteFailed,
    /// The absolute authorization bound elapsed while the write was parked in
    /// flow control (or was already elapsed when the write was offered). The
    /// termination has ALREADY been recorded here through the REQUEST's shared
    /// latch, so it is counted at most once for the stream even when the
    /// upload direction, a pre-commitment gate, or the relay's own idle arm
    /// reaches an authorization exit concurrently. The caller must drop any
    /// buffered tail, reset the send half, latch the bounded class into its
    /// summary, and end its relay.
    AuthorizationExpired(crate::proxy::auth_lifetime::StreamAuthTermination),
    /// The matched route's absolute response-body deadline elapsed while the
    /// client write was blocked by QUIC flow control.
    RouteDeadlineExceeded,
}

/// Race one potentially flow-control-blocked downstream H3 write against the
/// earliest route or authorization deadline.
///
/// A client that stops reading holds every `send_data` / `finish` in QUIC flow
/// control, so a relay loop never returns to its `select!` timer and the
/// admitted stream — plus its upstream body, request/CB/LB guards, and
/// buffered response state — survives the credential that authorized it. The
/// deadline arm is biased for the same reason the RPC-deadline helper biases
/// its own: once the authorization budget is spent, a simultaneously writable
/// frame must not escape downstream.
///
/// The plan is **absolute**. It is anchored once at credential acceptance and
/// passed down by value, so calling this per frame can neither refresh nor
/// re-derive it. The route deadline is the relay's own pinned `route_body_sleep`
/// (#5745): racing that one registered timer instead of a fresh `Sleep` keeps a
/// timed route from registering and deregistering a timer-wheel entry for every
/// frame, and its instant is the route deadline by construction. An
/// unauthenticated request without a timed route pays nothing at all: no timer
/// is registered on that path.
/// `latch` is the REQUEST's shared once-only termination latch. Routing the
/// blocked-write class through it — rather than incrementing the counter
/// directly — is what keeps the upload direction, the pre-commitment gates, the
/// relay's idle arm, and this seam from double counting one stream when several
/// of them become eligible at the same absolute instant.
pub(crate) async fn await_authorized_response_write<F, T, E>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    route_sleep: std::pin::Pin<&mut Option<tokio::time::Sleep>>,
    family: crate::proxy::auth_lifetime::StreamAuthProtocolFamily,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    write: F,
) -> H3AuthorizedWrite
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let route_deadline = Option::as_ref(&route_sleep).map(tokio::time::Sleep::deadline);
    // Authorization wins an exact tie, matching `ComposedAuthBound`. When it
    // owns the earlier bound the write races the plan exactly as before;
    // otherwise the route owns it and the write races the pinned route timer.
    let auth_bound = plan.filter(|plan| route_deadline.is_none_or(|route| plan.at <= route));
    let outcome = match (auth_bound, route_sleep.as_pin_mut()) {
        (None, Some(route_sleep)) => {
            await_response_write_before_pinned_sleep(route_sleep, write).await
        }
        _ => await_response_write_before_deadline(auth_bound.map(|plan| plan.at), write).await,
    };
    match outcome {
        Ok(_) => H3AuthorizedWrite::Written,
        Err(H3ResponseWriteError::Write(_)) => H3AuthorizedWrite::ClientWriteFailed,
        Err(H3ResponseWriteError::DeadlineExceeded) => {
            if let Some(plan) = auth_bound {
                latch.record_once(plan.termination, family);
                H3AuthorizedWrite::AuthorizationExpired(plan.termination)
            } else {
                H3AuthorizedWrite::RouteDeadlineExceeded
            }
        }
    }
}

/// [`await_response_write_before_deadline`] against a timer the caller already
/// pinned and registered, instead of a fresh `Sleep` per write (#5745).
///
/// Same contract: expiry-first, so an elapsed deadline never polls `write` (one
/// clock read, no timer registration), and a biased timer arm wins an
/// exact-deadline tie. The timer is borrowed, never reset, so the caller's own
/// `select!` arm keeps observing the same absolute instant.
async fn await_response_write_before_pinned_sleep<F, T, E>(
    mut sleep: std::pin::Pin<&mut tokio::time::Sleep>,
    write: F,
) -> Result<T, H3ResponseWriteError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    if tokio::time::Instant::now() >= sleep.deadline() {
        return Err(H3ResponseWriteError::DeadlineExceeded);
    }
    tokio::select! {
        biased;
        () = sleep.as_mut() => Err(H3ResponseWriteError::DeadlineExceeded),
        result = write => result.map_err(H3ResponseWriteError::Write),
    }
}

/// Race a response HEADERS write against `deadline`, also reporting whether
/// the write was polled — offered to the H3 send half — before it finished or
/// was cancelled (#5745).
///
/// h3 hands the whole frame to h3-quinn's `send_data` on the first poll and
/// only then waits in `poll_ready`, so a write the deadline cancels after that
/// leaves h3-quinn's `writing` buffer set. Any later write on the stream then
/// fails at `send_data` with a CONNECTION-level `InternalError`, and h3 closes
/// the whole QUIC connection — every sibling stream included — with
/// `H3_INTERNAL_ERROR`. A caller that sees `DeadlineExceeded` with `offered`
/// set must therefore reset the stream instead of writing another terminal;
/// part of the head may already be on the wire anyway. When `offered` is false
/// the deadline had already elapsed, nothing reached the send half, and a
/// terminal HEADERS is still legal.
pub(crate) async fn await_offered_response_write_before_deadline<F, T, E>(
    deadline: Option<tokio::time::Instant>,
    write: F,
) -> (Result<T, H3ResponseWriteError<E>>, bool)
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let mut offered = false;
    let mut write = std::pin::pin!(write);
    let tracked = std::future::poll_fn(|cx| {
        offered = true;
        write.as_mut().poll(cx)
    });
    let result = await_response_write_before_deadline(deadline, tracked).await;
    (result, offered)
}

/// Outcome of a native-H3 streaming response HEADERS write raced against the
/// composed authorization / client-RPC / route bound (issue #3815, #5646).
///
/// Distinct from [`H3AuthorizedWrite`] because a HEADERS write can also lose
/// to a strictly earlier protocol deadline, and because an authorization
/// expiry here means no protected response head exists on the wire yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3AuthorizedHeadersWrite {
    /// The response head reached the QUIC send half.
    Written,
    /// The client's stream is gone; this is an ordinary disconnect.
    ClientWriteFailed,
    /// The admitted credential's authorization lifetime is the bound that
    /// established the deadline, and that instant elapsed before HEADERS
    /// committed. The termination has ALREADY been recorded through the
    /// REQUEST's shared latch. The caller must not let the protected head
    /// commit: abort/reset fail-closed unless a bounded post-deadline
    /// terminal write is still protocol-legal.
    AuthorizationExpired(crate::proxy::auth_lifetime::StreamAuthTermination),
    /// A strictly earlier protocol deadline (for example a client
    /// `grpc-timeout`) elapsed. Not an authorization termination.
    ProtocolDeadlineExceeded,
    /// The matched route rule's body deadline (#5646) elapsed while HEADERS
    /// were parked in QPACK/QUIC flow control. Only
    /// `commit_authorized_streaming_response_headers` reports it; the caller
    /// cuts the response exactly as its relay's route deadline arm does.
    RouteDeadlineExceeded,
}

/// Race a native-H3 streaming response HEADERS write against the composed
/// authorization / client-RPC bound, attributing the winner from the captured
/// composition rather than from a second clock read.
///
/// QPACK encoding plus a QUIC stream the client is not reading can park
/// `send_response` indefinitely. Later DATA/FIN writes already race
/// [`await_authorized_response_write`]; the HEADERS write itself must use
/// the same absolute plan (never a refreshed one) so a stalled head cannot
/// retain upstream bodies, miss precommit semantics, or evade accounting.
///
/// The deadline arm is biased: once the budget is spent, a simultaneously
/// writable HEADERS frame must not escape. An already-elapsed bound therefore
/// never polls `write`, so no protected head can commit after expiry.
pub(crate) async fn await_authorized_headers_write<F, T, E>(
    bound: crate::proxy::auth_lifetime::ComposedAuthBound,
    family: crate::proxy::auth_lifetime::StreamAuthProtocolFamily,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    write: F,
) -> H3AuthorizedHeadersWrite
where
    F: std::future::Future<Output = Result<T, E>>,
{
    match await_response_write_before_deadline(bound.deadline(), write).await {
        Ok(_) => H3AuthorizedHeadersWrite::Written,
        Err(H3ResponseWriteError::Write(_)) => H3AuthorizedHeadersWrite::ClientWriteFailed,
        Err(H3ResponseWriteError::DeadlineExceeded) => {
            if let Some(termination) = bound.expired_authorization() {
                latch.record_once(termination, family);
                H3AuthorizedHeadersWrite::AuthorizationExpired(termination)
            } else {
                H3AuthorizedHeadersWrite::ProtocolDeadlineExceeded
            }
        }
    }
}

/// Compose the aggregate MCP SSE listener's absolute lifetime with the
/// admitted request's captured authorization plan (issue #3815).
///
/// The listener lifetime is a protocol bound, not an authorization bound:
/// when it is strictly earlier, the stream ends as it does today and the
/// authorization counters stay untouched. When authorization is earlier —
/// or the two instants are equal — the security decision wins, so a
/// short-TTL credential cannot keep receiving protected events until the
/// later listener lifetime.
#[inline]
#[must_use]
pub(crate) fn compose_aggregate_sse_bound(
    listener_deadline: tokio::time::Instant,
    auth_plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> crate::proxy::auth_lifetime::ComposedAuthBound {
    crate::proxy::auth_lifetime::ComposedAuthBound::compose(Some(listener_deadline), auth_plan)
}

/// Capture the admitted stream's authorization plan, race `send_response`
/// against that exact plan composed with any client RPC deadline and the
/// matched route's body deadline (#5646), and latch an authorization expiry
/// through the request. Used by every native-H3 streaming HTTP/SSE backend
/// relay so those three call sites cannot drift.
/// The aggregate MCP SSE listener composes against its broker lifetime
/// instead and calls [`await_authorized_headers_write`] directly.
pub(crate) async fn commit_authorized_streaming_response_headers<S>(
    stream: &mut RequestStream<S, Bytes>,
    resp: http::Response<()>,
    ctx: &mut crate::plugins::RequestContext,
    max_lifetime_seconds: u64,
    route_deadline: Option<tokio::time::Instant>,
) -> AuthorizedStreamingHeadersCommit
where
    S: RecvStream + SendStream<Bytes>,
{
    let plan =
        crate::proxy::auth_lifetime::effective_request_auth_deadline(ctx, max_lifetime_seconds);
    let latch = ctx.authorization_termination_latch();
    let grpc_deadline = ctx.grpc_deadline_at();
    let bound = crate::proxy::auth_lifetime::ComposedAuthBound::compose(
        crate::proxy::earliest_deadline(grpc_deadline, route_deadline),
        plan,
    );
    let outcome = await_authorized_headers_write(
        bound,
        crate::proxy::auth_lifetime::StreamAuthProtocolFamily::Http,
        &latch,
        stream.send_response(resp),
    )
    .await;
    let outcome = attribute_streaming_headers_deadline(outcome, grpc_deadline, route_deadline);
    if let H3AuthorizedHeadersWrite::AuthorizationExpired(termination) = outcome {
        ctx.latch_authorization_termination(termination);
    }
    AuthorizedStreamingHeadersCommit {
        plan,
        latch,
        outcome,
    }
}

/// Attribute a streaming HEADERS write's protocol-deadline expiry from the
/// captured instants: the route body deadline (#5646) owns it unless a client
/// RPC deadline is strictly earlier. Every other outcome passes through.
#[inline]
pub(crate) fn attribute_streaming_headers_deadline(
    outcome: H3AuthorizedHeadersWrite,
    grpc_deadline: Option<tokio::time::Instant>,
    route_deadline: Option<tokio::time::Instant>,
) -> H3AuthorizedHeadersWrite {
    let route_owns_expiry = match (route_deadline, grpc_deadline) {
        // Defensive: unreachable on today's callers. Only native streaming
        // HTTP/SSE relays commit HEADERS here, and a gRPC-flavored request
        // folds its route bounds into its RPC deadline instead of carrying a
        // route body deadline, so the two never coexist. Were they to, the
        // route would own a tie: it is the bound whose cut this path applies.
        (Some(route), Some(grpc)) => route <= grpc,
        (Some(_), None) => true,
        (None, _) => false,
    };
    match outcome {
        H3AuthorizedHeadersWrite::ProtocolDeadlineExceeded if route_owns_expiry => {
            H3AuthorizedHeadersWrite::RouteDeadlineExceeded
        }
        other => other,
    }
}

/// Plan, latch, and HEADERS-write outcome captured together so the body relay
/// cannot re-derive or refresh the lifetime that just bounded the head.
pub(crate) struct AuthorizedStreamingHeadersCommit {
    pub plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    pub latch: crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    pub outcome: H3AuthorizedHeadersWrite,
}

/// Signal the peer that we are done with the receive side of the
/// request stream. Without this call, dropping the `RequestStream`
/// surfaces as `RESET_STREAM(0x0)` on the QUIC wire — QUIC has no
/// "graceful half-close on the recv side" other than STOP_SENDING, and
/// `H3_NO_ERROR` (0x100) is the RFC-9114 canonical "closing without an
/// error" code. Using it tells the client its request was accepted and
/// no further body bytes are needed.
///
/// Prefer calling this **after** response HEADERS/DATA/trailers/FIN are
/// written, so the client observes the response before its request direction is
/// halted.
///
/// **Total, including a receive cancelled mid-poll.** A long-lived
/// request-upload pump is routinely cancelled while a `recv_data` /
/// `recv_trailers` future is `Pending` — that is the ordinary shape of a
/// bidirectional RPC whose backend answers before the client half-closes. Stock
/// `h3-quinn` 0.0.10 moves its `quinn::RecvStream` into a `ReusableBoxFuture`
/// for the duration of such a read and leaves its own `Option` as `None`, so
/// `stop_sending` would `unwrap`-abort the process under `panic = "abort"`;
/// avoiding the call instead would silently downgrade the wire signal to
/// `quinn::RecvStream::drop`'s `STOP_SENDING(0)`, which is not an HTTP/3 error
/// code and makes clients log a spurious "Remote reset" on a *successful* RPC.
/// The vendored `h3-quinn` patch keeps the stream owned inline so this call is
/// correct in both states — see
/// `docs/upstream-h3-quinn-patches/001-stop-sending-during-in-flight-read/`.
///
/// Safe to call after `finish()` / `send_response()`. Subsequent calls after a
/// successful halt are ignored by quinn (`ClosedStream`).
#[inline]
pub(crate) fn halt_request_body<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: RecvStream,
{
    // stop_sending is required here: otherwise dropping the recv half surfaces
    // as RESET_STREAM(0x0) on the wire and clients log
    // "Remote reset: 0x0" + a truncated response.
    stream.stop_sending(Code::H3_NO_ERROR);
}

/// Watch peer cancellation of this H3 request's response (send) direction.
///
/// Quinn's `SendStream::stopped` is `&self` and `'static`, so this future does
/// not borrow `stream` and can race a backend header wait while the receive
/// half is still polled or the send half is later used to write a response.
/// Completes on peer `STOP_SENDING` or a connection-level failure. A clean
/// local finish acknowledgement (`Ok(None)`) is not cancellation.
pub(crate) fn peer_response_cancelled<S>(
    stream: &RequestStream<S, Bytes>,
) -> impl Future<Output = ()> + Send + 'static
where
    S: SendStreamStopped,
{
    let stopped = stream.stopped();
    async move {
        match stopped.await {
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => std::future::pending::<()>().await,
        }
    }
}

/// Abort the response send half for a gateway-originated streaming failure.
///
/// Use this when we have already sent response headers but cannot complete the
/// backend body honestly (backend read error, response-size overflow, etc.).
/// A graceful `finish()` would make unknown-length responses look complete; a
/// reset lets H3 clients distinguish truncation from EOF.
///
/// `stop_stream` is idempotent at the Quinn layer. Callers that abort while an
/// h3-quinn `send_data` future still holds `writing` may see this as a no-op
/// (`h3-quinn`'s `reset` ignores Quinn errors and does not clear `writing`);
/// [`CommittedH3ResponseStream::settle_committed_terminal`] therefore retries
/// on drop after that future is gone (issue #4363).
#[inline]
pub(crate) fn abort_response_stream<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: SendStream<Bytes>,
{
    stream.stop_stream(Code::H3_INTERNAL_ERROR);
}

/// Whether a captured authorization plan has already elapsed.
///
/// Checks the captured Instant; it does not re-derive a plan or choose between
/// owners. Native plain-H3 relays call this at backend EOS so a `recv_data`
/// `Ok(None)` cannot proceed to `finish()` after the credential is spent
/// (issue #4363). `h3-quinn`'s `poll_finish` calls Quinn `finish()`
/// synchronously and does not park on a stalled client, so reaching that call
/// after expiry would present a clean FIN.
#[inline]
#[must_use]
pub(crate) fn captured_authorization_elapsed(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
) -> Option<crate::proxy::auth_lifetime::StreamAuthTermination> {
    plan.filter(|plan| tokio::time::Instant::now() >= plan.at)
        .map(|plan| plan.termination)
}

/// A COMMITTED HTTP/3 streaming response's request stream, with a fail-closed
/// terminal (issue #4112).
///
/// `quinn::SendStream::drop` implicitly `finish()`es a send half that was
/// neither finished nor reset, so EVERY way a relay can stop writing without
/// landing its own FIN hands a stalled client a well-formed end of response:
/// an authorization expiry, a backend body fault, a downstream write failure,
/// an early `break` a later change adds between the response-header commit and
/// the finish sites, or the request task being cancelled while parked in
/// `send_data`. RFC 9114 has no in-band way to retract a response whose HEADERS
/// already committed, so `RESET_STREAM` is the only honest terminal for all of
/// them.
///
/// This is deliberately NOT another conditional re-assertion over accumulated
/// `auth_termination` / `body_error_class` / `client_disconnected` bookkeeping
/// (compare [`committed_response_requires_reset`], which the cross-protocol
/// relays apply after their loops). The predicate is INVERTED and lives in the
/// type: the terminal is a reset unless the relay PROVED it landed a clean FIN,
/// so a branch that stops writing without latching a class — or a branch that
/// never runs to the post-loop check at all because the task was dropped — is
/// still fail-closed. Same shape as `ConnectUdpSendHalf` (issue #4072).
///
/// Wrap the stream once the relay is committed to writing a streaming response,
/// deref it exactly as before, call [`Self::abort_committed`] on every non-clean
/// exit, and call [`Self::record_clean_finish`] only where a `finish()` toward
/// the client actually returned `Ok` *and* the stream was not already forced
/// to reset (authorization-first: a later `finish()` `Ok` cannot disarm an
/// expiry that already won).
pub(crate) struct CommittedH3ResponseStream<S: SendStream<Bytes>> {
    stream: RequestStream<S, Bytes>,
    /// Set ONLY where a downstream `finish()` returned `Ok` and
    /// [`Self::abort_committed`] has not already latched a reset. The single
    /// thing that disarms the reset, and only when `force_reset` is false.
    clean_finish: bool,
    /// Latched by [`Self::abort_committed`]. Authorization-first: once set,
    /// [`Self::record_clean_finish`] is a no-op and settle always retries
    /// `stop_stream`. Unlike the previous `reset_applied` flag, this does NOT
    /// skip the Drop retry after a no-op abort (issue #4363). Same shape as
    /// `ConnectUdpSendHalf` (issue #4072), which always `stop_stream`s on drop
    /// while still armed.
    force_reset: bool,
}

impl<S: SendStream<Bytes>> CommittedH3ResponseStream<S> {
    /// Arm the fail-closed terminal for `stream`.
    pub(crate) fn new(stream: RequestStream<S, Bytes>) -> Self {
        Self {
            stream,
            clean_finish: false,
            force_reset: false,
        }
    }

    /// Record that a downstream `finish()` returned `Ok`, i.e. the relay landed
    /// a real clean end of body. Never call this for a finish that failed, was
    /// cancelled, or was skipped. A no-op once [`Self::abort_committed`] has
    /// latched, so a `finish()` that returns `Ok` after expiry cannot disarm
    /// the reset (authorization-first).
    pub(crate) fn record_clean_finish(&mut self) {
        if self.force_reset {
            return;
        }
        self.clean_finish = true;
    }

    /// Force a RESET terminal and apply it now. Authorization-first: a later
    /// `finish()` `Ok` cannot disarm this, and Drop retries `stop_stream` if
    /// the first abort was a no-op because an h3-quinn `send_data` still held
    /// `writing` (issue #4363).
    pub(crate) fn abort_committed(&mut self) {
        self.force_reset = true;
        self.clean_finish = false;
        abort_response_stream(&mut self.stream);
    }

    /// Apply the terminal now rather than at drop, so the `RESET_STREAM`
    /// reaches the wire before the relay's response-termination hooks and
    /// transaction logging await. Skipped only for a proven clean authorized
    /// FIN (`clean_finish && !force_reset`). Otherwise always `stop_stream`s
    /// — including on Drop after a no-op abort — because `stop_stream` is
    /// idempotent and a skipped retry is how Quinn's implicit `finish()`
    /// leaked a clean EOF (issue #4363).
    pub(crate) fn settle_committed_terminal(&mut self) {
        if self.clean_finish && !self.force_reset {
            return;
        }
        abort_response_stream(&mut self.stream);
    }
}

impl<S: SendStream<Bytes>> Deref for CommittedH3ResponseStream<S> {
    type Target = RequestStream<S, Bytes>;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl<S: SendStream<Bytes>> DerefMut for CommittedH3ResponseStream<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

impl<S: SendStream<Bytes>> Drop for CommittedH3ResponseStream<S> {
    /// The backstop the explicit settle cannot cover: a request task dropped
    /// while its `send_data` is parked in QUIC flow control never reaches any
    /// post-relay statement at all.
    fn drop(&mut self) {
        self.settle_committed_terminal();
    }
}

/// The BORROWING counterpart of [`CommittedH3ResponseStream`] (issue #4125).
///
/// Same contract, same inverted predicate, same `Drop` backstop; the only
/// difference is that it holds `&mut RequestStream` instead of owning it, for
/// the relays whose send half arrives as a borrow from the H3 request handler
/// and so cannot be moved into the owning guard without re-shaping their
/// signatures. `stream_h3_open_response_to_client` and
/// `proxy_to_backend_h3_streaming` are those relays.
///
/// The terminal is a RESET unless [`Self::record_clean_finish`] proved a
/// downstream `finish()` returned `Ok` *and* [`Self::abort_committed`] has not
/// already latched — never a re-assertion over accumulated `body_error_class` /
/// `client_disconnected` bookkeeping. Keep the settle body byte-identical to
/// the owning guard's: the source-shape guard in
/// `tests/unit/gateway_core/http3_server_dispatch_tests.rs` asserts both carry
/// the same predicate so the two cannot drift apart.
pub(crate) struct BorrowedCommittedH3ResponseStream<'a, S: SendStream<Bytes>> {
    stream: &'a mut RequestStream<S, Bytes>,
    /// Set ONLY where a downstream `finish()` returned `Ok` and
    /// [`Self::abort_committed`] has not already latched a reset. The single
    /// thing that disarms the reset, and only when `force_reset` is false.
    clean_finish: bool,
    /// Latched by [`Self::abort_committed`]. Authorization-first: once set,
    /// [`Self::record_clean_finish`] is a no-op and settle always retries
    /// `stop_stream`. Unlike the previous `reset_applied` flag, this does NOT
    /// skip the Drop retry after a no-op abort (issue #4363). Same shape as
    /// `ConnectUdpSendHalf` (issue #4072), which always `stop_stream`s on drop
    /// while still armed.
    force_reset: bool,
}

impl<'a, S: SendStream<Bytes>> BorrowedCommittedH3ResponseStream<'a, S> {
    /// Arm the fail-closed terminal for the borrowed `stream`.
    pub(crate) fn new(stream: &'a mut RequestStream<S, Bytes>) -> Self {
        Self {
            stream,
            clean_finish: false,
            force_reset: false,
        }
    }

    /// Record that a downstream `finish()` returned `Ok`, i.e. the relay landed
    /// a real clean end of body. Never call this for a finish that failed, was
    /// cancelled, or was skipped. A no-op once [`Self::abort_committed`] has
    /// latched, so a `finish()` that returns `Ok` after expiry cannot disarm
    /// the reset (authorization-first).
    pub(crate) fn record_clean_finish(&mut self) {
        if self.force_reset {
            return;
        }
        self.clean_finish = true;
    }

    /// Force a RESET terminal and apply it now. Authorization-first: a later
    /// `finish()` `Ok` cannot disarm this, and Drop retries `stop_stream` if
    /// the first abort was a no-op because an h3-quinn `send_data` still held
    /// `writing` (issue #4363).
    pub(crate) fn abort_committed(&mut self) {
        self.force_reset = true;
        self.clean_finish = false;
        abort_response_stream(&mut *self.stream);
    }

    /// Apply the terminal now rather than at drop, so the `RESET_STREAM`
    /// reaches the wire before the relay's response-termination hooks and
    /// transaction logging await. Skipped only for a proven clean authorized
    /// FIN (`clean_finish && !force_reset`). Otherwise always `stop_stream`s
    /// — including on Drop after a no-op abort — because `stop_stream` is
    /// idempotent and a skipped retry is how Quinn's implicit `finish()`
    /// leaked a clean EOF (issue #4363).
    pub(crate) fn settle_committed_terminal(&mut self) {
        if self.clean_finish && !self.force_reset {
            return;
        }
        abort_response_stream(&mut *self.stream);
    }
}

impl<S: SendStream<Bytes>> Deref for BorrowedCommittedH3ResponseStream<'_, S> {
    type Target = RequestStream<S, Bytes>;

    fn deref(&self) -> &Self::Target {
        &*self.stream
    }
}

impl<S: SendStream<Bytes>> DerefMut for BorrowedCommittedH3ResponseStream<'_, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.stream
    }
}

impl<S: SendStream<Bytes>> Drop for BorrowedCommittedH3ResponseStream<'_, S> {
    /// The backstop the explicit settle cannot cover: a request task dropped
    /// while its `send_data` is parked in QUIC flow control never reaches any
    /// post-relay statement at all. The borrow ends with the guard, so the
    /// caller's `&mut` is usable again only after the terminal was applied.
    fn drop(&mut self) {
        self.settle_committed_terminal();
    }
}

/// Whether a COMMITTED H3 streaming response must leave its send half RESET.
///
/// Quinn implicitly `finish()`es a send stream that was neither finished nor
/// reset when the stream is dropped (`quinn::SendStream::drop`). A relay that
/// merely stops writing — because the credential's authorization lifetime
/// elapsed, because the backend body failed, or because a downstream write
/// never landed its FIN — therefore hands the client a clean end of body on the
/// way out, which is indistinguishable from a complete response. RFC 9114 has
/// no in-band way to retract a response whose HEADERS already committed, so the
/// only honest terminal for those exits is `RESET_STREAM`.
///
/// Returns `false` only when the relay completed the body cleanly, so this can
/// never clobber a successful `finish()` with a reset.
#[inline]
#[must_use]
pub(crate) fn committed_response_requires_reset(
    authorization_terminated: bool,
    body_failed: bool,
    client_disconnected: bool,
) -> bool {
    authorization_terminated || body_failed || client_disconnected
}

#[cfg(test)]
mod tests {
    use super::{Code, committed_response_requires_reset};

    /// RFC 9114 §8.1 defines H3_NO_ERROR == 0x100. The halt helper
    /// must use exactly this code so peers treat the recv-half close
    /// as "no error, just done accepting body" rather than a
    /// transport failure.
    #[test]
    fn halt_code_matches_rfc9114_h3_no_error() {
        assert_eq!(Code::H3_NO_ERROR.value(), 0x100);
    }

    #[test]
    fn response_abort_code_matches_rfc9114_h3_internal_error() {
        assert_eq!(Code::H3_INTERNAL_ERROR.value(), 0x102);
    }

    /// A credential-expiry termination on a committed response is a RESET,
    /// unconditionally — whichever relay branch observed the expiry, and
    /// whether or not the downstream write also failed. Quinn would otherwise
    /// FIN the stream on drop and let a stalled client read a normal end of
    /// response instead of an authorization failure (issue #3995).
    #[test]
    fn authorization_expiry_always_requires_a_reset() {
        assert!(committed_response_requires_reset(true, false, false));
        assert!(committed_response_requires_reset(true, true, false));
        assert!(committed_response_requires_reset(true, false, true));
        assert!(committed_response_requires_reset(true, true, true));
    }

    /// Truncation for any other reason is a reset too: a backend body error, a
    /// response-size overflow, or a FIN that never reached the client must not
    /// present as a complete body.
    #[test]
    fn truncated_committed_responses_require_a_reset() {
        assert!(committed_response_requires_reset(false, true, false));
        assert!(committed_response_requires_reset(false, false, true));
    }

    /// The one case that must NOT reset: the relay finished the body cleanly.
    #[test]
    fn a_cleanly_finished_response_is_never_reset() {
        assert!(!committed_response_requires_reset(false, false, false));
    }
}

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

/// A deadline can still be reported with a clean terminal gRPC status while
/// the downstream client has not observed any response DATA. Once any DATA is
/// visible, resetting is the only safe choice because the deadline may have
/// interrupted a length-prefixed gRPC message.
#[inline]
pub(crate) fn grpc_deadline_can_send_terminal_status(bytes_streamed: u64) -> bool {
    bytes_streamed == 0
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
pub(crate) enum H3AuthorizedWrite {
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
}

/// Race one potentially flow-control-blocked downstream H3 write against the
/// admitted stream's absolute authorization deadline.
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
/// re-derive it, and an unauthenticated request (`None`) pays nothing at all —
/// no timer is registered on that path.
/// `latch` is the REQUEST's shared once-only termination latch. Routing the
/// blocked-write class through it — rather than incrementing the counter
/// directly — is what keeps the upload direction, the pre-commitment gates, the
/// relay's idle arm, and this seam from double counting one stream when several
/// of them become eligible at the same absolute instant.
pub(crate) async fn await_authorized_response_write<F, T, E>(
    plan: Option<crate::proxy::auth_lifetime::StreamAuthDeadline>,
    family: crate::proxy::auth_lifetime::StreamAuthProtocolFamily,
    latch: &crate::proxy::auth_lifetime::StreamAuthTerminationLatch,
    write: F,
) -> H3AuthorizedWrite
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let Some(plan) = plan else {
        return match write.await {
            Ok(_) => H3AuthorizedWrite::Written,
            Err(_) => H3AuthorizedWrite::ClientWriteFailed,
        };
    };
    match await_response_write_before_deadline(Some(plan.at), write).await {
        Ok(_) => H3AuthorizedWrite::Written,
        Err(H3ResponseWriteError::Write(_)) => H3AuthorizedWrite::ClientWriteFailed,
        Err(H3ResponseWriteError::DeadlineExceeded) => {
            latch.record_once(plan.termination, family);
            H3AuthorizedWrite::AuthorizationExpired(plan.termination)
        }
    }
}

/// Outcome of a native-H3 streaming response HEADERS write raced against the
/// composed authorization / client-RPC bound (issue #3815).
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
/// against that exact plan composed with any client RPC deadline, and latch
/// an authorization expiry through the request. Used by every native-H3
/// streaming HTTP/SSE backend relay so those three call sites cannot drift.
/// The aggregate MCP SSE listener composes against its broker lifetime
/// instead and calls [`await_authorized_headers_write`] directly.
pub(crate) async fn commit_authorized_streaming_response_headers<S>(
    stream: &mut RequestStream<S, Bytes>,
    resp: http::Response<()>,
    ctx: &mut crate::plugins::RequestContext,
    max_lifetime_seconds: u64,
) -> AuthorizedStreamingHeadersCommit
where
    S: RecvStream + SendStream<Bytes>,
{
    let plan =
        crate::proxy::auth_lifetime::effective_request_auth_deadline(ctx, max_lifetime_seconds);
    let latch = ctx.authorization_termination_latch();
    let bound =
        crate::proxy::auth_lifetime::ComposedAuthBound::compose(ctx.grpc_deadline_at(), plan);
    let outcome = await_authorized_headers_write(
        bound,
        crate::proxy::auth_lifetime::StreamAuthProtocolFamily::Http,
        &latch,
        stream.send_response(resp),
    )
    .await;
    if let H3AuthorizedHeadersWrite::AuthorizationExpired(termination) = outcome {
        ctx.latch_authorization_termination(termination);
    }
    AuthorizedStreamingHeadersCommit {
        plan,
        latch,
        outcome,
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
#[inline]
pub(crate) fn abort_response_stream<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: SendStream<Bytes>,
{
    stream.stop_stream(Code::H3_INTERNAL_ERROR);
}

#[cfg(test)]
mod tests {
    use super::Code;

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
}

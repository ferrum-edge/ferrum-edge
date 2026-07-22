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

use std::time::Duration;

use bytes::Bytes;
use h3::error::Code;
use h3::quic::{RecvStream, SendStream};
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
/// The deadline arm is intentionally biased. Once the budget is exhausted, a
/// simultaneously writable DATA frame must not escape downstream and turn a
/// clean no-DATA expiry into a partial-message reset. Dropping `write` cancels
/// the h3 send future; callers then reset the send half and drop/cancel their
/// upstream response body.
pub(crate) async fn await_response_write_before_deadline<F, T, E>(
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
        () = &mut deadline_sleep => Err(H3ResponseWriteError::DeadlineExceeded),
        result = &mut write => result.map_err(H3ResponseWriteError::Write),
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
/// [`abort_response_stream`] and must **not** call [`halt_request_body`] after
/// a mid-`recv_data` cancel (h3-quinn's recv slot is `None`).
pub(crate) async fn await_post_deadline_terminal_response_write<F, T, E>(
    write: F,
) -> Result<T, H3ResponseWriteError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let grace_at = tokio::time::Instant::now() + H3_POST_DEADLINE_TERMINAL_WRITE_GRACE;
    await_terminal_response_write_before_deadline(Some(grace_at), write).await
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
/// written. Do **not** call it after a drain cancelled mid-`recv_data` by
/// timeout/deadline: h3-quinn keeps the `quinn::RecvStream` inside a
/// `ReusableBoxFuture` while `poll_data` is `Pending`, leaving the outer
/// `Option` as `None`, and `stop_sending` would `unwrap`-abort under
/// `panic = "abort"`. Skip this helper in that case and let
/// `quinn::RecvStream::drop` issue `STOP_SENDING(0)` when the
/// `RequestStream` is released.
///
/// Safe to call after `finish()` / `send_response()` when the recv half is
/// idle. Subsequent calls after a successful halt are ignored by quinn
/// (`ClosedStream`).
#[inline]
pub(crate) fn halt_request_body<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: RecvStream,
{
    // stop_sending is required here: otherwise dropping an idle recv half
    // surfaces as RESET_STREAM(0x0) on the wire and clients log
    // "Remote reset: 0x0" + a truncated response.
    stream.stop_sending(Code::H3_NO_ERROR);
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
    use super::{Code, H3_POST_DEADLINE_TERMINAL_WRITE_GRACE, H3ResponseWriteError};
    use std::time::Duration;

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

    #[test]
    fn post_deadline_terminal_write_grace_is_short_and_fixed() {
        assert_eq!(
            H3_POST_DEADLINE_TERMINAL_WRITE_GRACE,
            Duration::from_secs(1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ready_post_deadline_terminal_write_completes_within_grace() {
        let result =
            super::await_post_deadline_terminal_response_write(async { Ok::<(), ()>(()) }).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_post_deadline_terminal_write_expires_grace() {
        let write = std::future::pending::<Result<(), ()>>();
        let task =
            tokio::spawn(
                async move { super::await_post_deadline_terminal_response_write(write).await },
            );
        tokio::task::yield_now().await;
        tokio::time::advance(H3_POST_DEADLINE_TERMINAL_WRITE_GRACE).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            task.await.expect("join"),
            Err(H3ResponseWriteError::DeadlineExceeded)
        ));
    }
}

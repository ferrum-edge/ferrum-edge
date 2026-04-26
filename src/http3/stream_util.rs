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

use bytes::Bytes;
use h3::error::Code;
use h3::quic::RecvStream;
use h3::server::RequestStream;

/// Signal the peer that we are done with the receive side of the
/// request stream. Without this call, dropping the `RequestStream`
/// surfaces as `RESET_STREAM(0x0)` on the QUIC wire — QUIC has no
/// "graceful half-close on the recv side" other than STOP_SENDING, and
/// `H3_NO_ERROR` (0x100) is the RFC-9114 canonical "closing without an
/// error" code. Using it tells the client its request was accepted and
/// no further body bytes are needed.
///
/// Safe to call after `finish()` / `send_response()` — the h3 crate
/// records the code into the underlying QUIC stream which then sends
/// the STOP_SENDING frame on the next write. This helper performs no
/// heap work.
#[inline]
pub(crate) fn halt_request_body<S>(stream: &mut RequestStream<S, Bytes>)
where
    S: RecvStream,
{
    // stop_sending is required here: otherwise dropping the recv half
    // surfaces as RESET_STREAM(0x0) on the wire and clients log
    // "Remote reset: 0x0" + a truncated response.
    stream.stop_sending(Code::H3_NO_ERROR);
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
}

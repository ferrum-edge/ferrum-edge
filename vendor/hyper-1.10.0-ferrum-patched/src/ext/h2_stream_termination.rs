//! FERRUM PATCH 006: why an HTTP/2 server stream ended before its response,
//! observable while hyper drops the stream's service future.

use std::cell::Cell;

/// Who ended an HTTP/2 server stream before the service produced a response.
///
/// hyper drops a pending service future when the stream is reset. The future's
/// own drop glue has no way to tell a peer's cancellation from a reset hyper's
/// HTTP/2 stack sent itself. While hyper drops that future, the service can
/// read the cause with [`take_h2_stream_termination`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H2StreamTermination {
    /// The peer reset the stream (`RST_STREAM`) or the connection (`GOAWAY`).
    PeerReset {
        /// The HTTP/2 error code the peer sent.
        reason: u32,
    },
    /// The connection's transport failed or closed underneath the stream.
    TransportLost,
    /// This endpoint reset the stream or connection, typically because what
    /// the peer sent violated the protocol.
    LocalReset {
        /// The HTTP/2 error code this endpoint sent.
        reason: u32,
    },
}

thread_local! {
    static PENDING: Cell<Option<H2StreamTermination>> = const { Cell::new(None) };
}

/// Take the termination cause hyper published for the HTTP/2 server stream
/// whose service future is being dropped on this thread.
///
/// Returns `Some` at most once, and only from code that runs during that drop
/// (the service future's drop glue). Everywhere else it returns `None`.
pub fn take_h2_stream_termination() -> Option<H2StreamTermination> {
    PENDING.with(Cell::take)
}

/// Publish `termination` for the service future the caller drops next on this
/// thread.
pub(crate) fn publish_h2_stream_termination(termination: H2StreamTermination) {
    PENDING.with(|pending| pending.set(Some(termination)));
}

/// Clears a published termination once the stream holding the service future
/// has been dropped, so it can never be read by an unrelated drop.
#[derive(Debug, Default)]
pub(crate) struct ClearH2StreamTermination;

impl Drop for ClearH2StreamTermination {
    fn drop(&mut self) {
        PENDING.with(|pending| pending.set(None));
    }
}

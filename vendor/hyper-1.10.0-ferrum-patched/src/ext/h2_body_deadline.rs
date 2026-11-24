//! FERRUM PATCH 007: an absolute deadline for an HTTP/2 client request body.

use std::time::Instant;

/// Request extension that ends an HTTP/2 client request body at an absolute
/// instant, whatever the body pipe is waiting on.
///
/// Insert it into a request sent on an HTTP/2 client connection
/// (`hyper::client::conn::http2`) that was built with a
/// [`Timer`](crate::rt::Timer). The request body pipe runs in its own task,
/// which outlives the response future. While it holds a chunk the peer has
/// granted no window for, it polls neither the body nor anything the caller
/// owns, so a deadline enforced in the body or by the caller cannot fire. This
/// extension arms one timer in the pipe task itself. If the deadline passes
/// before the body has finished, the stream is reset with `CANCEL`: both
/// halves of the exchange end, whether the pipe was waiting on the body or on
/// peer flow control.
///
/// The extension is removed from the request before it is sent. On a
/// connection built without a timer there is nothing to arm it with, and it is
/// ignored.
#[derive(Clone, Copy, Debug)]
pub struct Http2BodyDeadline {
    deadline: Instant,
}

impl Http2BodyDeadline {
    /// End the request body at `deadline`.
    pub fn new(deadline: Instant) -> Self {
        Self { deadline }
    }

    /// The absolute deadline.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

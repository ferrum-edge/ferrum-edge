//! Release an HTTP/1.1 connection whose dispatcher stopped reading requests
//! while a request was being queued on it (issue #5720).
//!
//! The pooled HTTP/1.1 carriers Ferrum drives directly — the HBONE inner
//! HTTP/1.1 pool and the Unix-socket backend pool — hold the connection's
//! only `hyper::client::conn::http1::SendRequest` while they await the
//! response. That is the same exposure the vendored hyper-util legacy client
//! had (issue #5714):
//!
//! 1. hyper queues the request on a tokio unbounded channel, and tokio's
//!    `UnboundedSender::send` checks that the channel is open and publishes the
//!    message as two separate steps.
//! 2. If the connection task closes the channel between them — the backend
//!    reset the connection, or closed it while it sat idle in the pool — the
//!    dispatcher's final `try_recv` sees nothing, and dropping its receiver
//!    drains only messages that were already published.
//! 3. The request is then published into a channel nobody reads. Its callback
//!    resolves only when the channel itself is dropped, which needs every
//!    sender gone, and the dispatch still holds the only sender. The response
//!    future waits for `backend_read_timeout_ms` (`504`), or forever when that
//!    timeout is `0`.
//!
//! [`await_h1_response_or_release`] closes that gap the same way the vendored
//! hyper-util patch does: while the response is outstanding it also watches
//! the sender's readiness, and once the dispatcher is gone or has closed its
//! queue it drops the connection handle. That drops the last sender, the
//! channel's destructor drops the stranded envelope, and hyper fails the
//! callback with a canceled error that carries the unsent request
//! (`TrySendError::take_message()` is `Some`). The dispatch then takes its
//! ordinary pre-wire path: a reused connection is replayed once on a fresh
//! one, and a fresh connection reports `ConnectionPoolError`.
//!
//! No byte of such a request reached the backend, whatever its body: hyper
//! polls the request body only after its dispatcher has dequeued the request,
//! and a dequeued request's callback belongs to the dispatcher, which fails it
//! with `message: None`. Releasing the handle therefore never turns a partly
//! sent request into a replayable one; only an envelope that never left the
//! channel comes back with its request.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use pin_project_lite::pin_project;

/// Await `sent`, the response future of a request already queued on the
/// HTTP/1.1 connection `conn`, and drop that connection as soon as its
/// dispatcher has stopped reading requests.
///
/// `poll_conn` is the sender's readiness poll, `SendRequest::poll_ready`
/// mapped to `Result<(), ()>`:
///
/// * `Ready(Err(()))` — the dispatcher is gone or has closed its queue. The
///   handle is dropped here, which fails a request that never reached the
///   dispatcher as unsent. A request the dispatcher had already taken is
///   unaffected: its callback is the dispatcher's, and hyper keeps serving it
///   after the last sender is dropped.
/// * `Ready(Ok(()))` — the dispatcher asked for more work after this request
///   was published, so it was open when the request arrived and will either
///   serve it or fail its callback. The watch ends there.
/// * `Pending` — parked on the dispatcher's readiness signal.
///
/// `sent` is polled first on every wake, so a response or error delivered
/// before the connection closed always wins and the handle comes back as
/// `Some` for the caller to pool. `None` means the connection was released and
/// must not be pooled; a response can still accompany it when the dispatcher
/// delivered one in the same instant it closed.
///
/// Allocation-free: one extra readiness poll per wake of the response future.
/// A named future rather than an `async fn`, so `sent` and `conn` are stored
/// once in the dispatch's state machine instead of once as arguments and again
/// as locals.
pub fn await_h1_response_or_release<F, T, P>(
    sent: F,
    conn: T,
    poll_conn: P,
) -> AwaitH1ResponseOrRelease<F, T, P>
where
    F: Future,
    P: FnMut(&mut T, &mut Context<'_>) -> Poll<Result<(), ()>>,
{
    AwaitH1ResponseOrRelease {
        sent,
        conn: Some(conn),
        poll_conn,
        watching: true,
    }
}

pin_project! {
    /// Future returned by [`await_h1_response_or_release`]. Resolves to the
    /// response future's output and the connection handle, or `None` when the
    /// handle was released.
    pub struct AwaitH1ResponseOrRelease<F, T, P> {
        #[pin]
        sent: F,
        conn: Option<T>,
        poll_conn: P,
        watching: bool,
    }
}

impl<F, T, P> Future for AwaitH1ResponseOrRelease<F, T, P>
where
    F: Future,
    P: FnMut(&mut T, &mut Context<'_>) -> Poll<Result<(), ()>>,
{
    type Output = (F::Output, Option<T>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        if let Poll::Ready(output) = this.sent.as_mut().poll(cx) {
            return Poll::Ready((output, this.conn.take()));
        }
        if !*this.watching {
            return Poll::Pending;
        }
        let Some(held) = this.conn.as_mut() else {
            return Poll::Pending;
        };
        match (this.poll_conn)(held, cx) {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => *this.watching = false,
            Poll::Ready(Err(())) => {
                *this.watching = false;
                tracing::debug!(
                    "HTTP/1.1 backend connection closed with a request queued; \
                     releasing its sender so the request fails as unsent"
                );
                // Dropping the handle drops the channel's last sender, which
                // may resolve `sent` synchronously. Poll it again before
                // parking.
                *this.conn = None;
                if let Poll::Ready(output) = this.sent.poll(cx) {
                    return Poll::Ready((output, None));
                }
            }
        }
        Poll::Pending
    }
}

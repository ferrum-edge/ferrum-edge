//! Lazy-initialized timeout wrapper that avoids timer allocation on fast paths.
//!
//! Standard `tokio::time::timeout()` creates a timer entry in the global timer
//! wheel immediately, even if the inner future completes on the first poll.
//! This wrapper defers timer creation until the inner future returns `Pending`,
//! so fast-path operations (e.g., reading from a buffer that already has data)
//! never allocate a timer.
//!
//! Other benchmarkes it delivered a 27x
//! speedup over tokio timeouts by combining lazy init with timer coalescing.

use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

/// Error returned when the lazy timeout expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LazyTimeoutError;

impl std::fmt::Display for LazyTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lazy timeout elapsed")
    }
}

impl std::error::Error for LazyTimeoutError {}

/// A future that wraps an inner future with a lazy-initialized timeout.
///
/// The timer is only created when the inner future first returns `Pending`.
/// If the inner future completes immediately (common for buffered I/O reads),
/// no timer is ever allocated.
///
/// Poll ordering matches [`tokio::time::timeout`]: the inner future is always
/// polled before the deadline, so simultaneous readiness favors completion.
pub fn lazy_timeout<F: Future>(duration: Duration, future: F) -> LazyTimeout<F> {
    LazyTimeout {
        future,
        duration,
        sleep: None,
    }
}

// `Sleep` is `!Unpin`. Storing it as `Option<Sleep>` would poison
// pin-project's generated `Unpin` impl (see `tests/scaffolding/network/latency.rs`).
// `Pin<Box<Sleep>>` stays `Unpin` and is allocated only once the timer arms.
type BoxedSleep = Pin<Box<tokio::time::Sleep>>;

pin_project! {
    /// Lazy timeout future. See [`lazy_timeout`] for details.
    pub struct LazyTimeout<F: Future> {
        #[pin]
        future: F,
        duration: Duration,
        sleep: Option<BoxedSleep>,
    }
}

impl<F: Future> Future for LazyTimeout<F> {
    type Output = Result<F::Output, LazyTimeoutError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // Always poll the inner future first (fast path + tokio timeout parity).
        if let Poll::Ready(v) = this.future.poll(cx) {
            return Poll::Ready(Ok(v));
        }

        // Inner future is Pending — create the timeout timer once.
        if this.sleep.is_none() {
            *this.sleep = Some(Box::pin(tokio::time::sleep(*this.duration)));
        }

        if let Some(sleep) = this.sleep.as_mut()
            && sleep.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(LazyTimeoutError));
        }

        Poll::Pending
    }
}

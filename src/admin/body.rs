//! Admin request-body collection with idle-read protection.
//!
//! Byte caps stay with [`http_body_util::Limited`]; this module adds an
//! inter-frame idle deadline so a slowloris-style trickle cannot hold an
//! admin request task open indefinitely after headers are complete.

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Frame, Incoming};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep, sleep_until};

use crate::util::body_limit::is_length_limit_error;

/// Failure modes for admin body collection.
#[derive(Debug)]
pub(crate) enum AdminBodyError {
    /// Body exceeded the configured byte cap.
    TooLarge,
    /// No body frame arrived within the idle deadline.
    TimedOut,
    /// Underlying transport / decode failure.
    Read(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for AdminBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "request body too large"),
            Self::TimedOut => write!(f, "request body read timed out"),
            Self::Read(err) => write!(f, "failed to read request body: {err}"),
        }
    }
}

impl std::error::Error for AdminBodyError {}

/// Collect an admin request body with a byte cap and optional idle timeout.
///
/// `idle_timeout_seconds == 0` disables the idle deadline (size limit only),
/// preserving the historical unbounded-wait behavior for operators that opt
/// out. Non-zero values re-arm after every delivered frame so large uploads
/// that keep making progress are not cut short.
pub(crate) async fn collect_admin_body(
    body: Incoming,
    max_bytes: usize,
    idle_timeout_seconds: u64,
) -> Result<Vec<u8>, AdminBodyError> {
    let limited = Limited::new(body, max_bytes);
    if idle_timeout_seconds == 0 {
        return match limited.collect().await {
            Ok(collected) => Ok(collected.to_bytes().to_vec()),
            Err(err) => {
                if is_length_limit_error(err.as_ref()) {
                    Err(AdminBodyError::TooLarge)
                } else {
                    Err(AdminBodyError::Read(err))
                }
            }
        };
    }

    let idle = Duration::from_secs(idle_timeout_seconds);
    let timed = IdleTimeoutBody::new(limited, idle);
    match timed.collect().await {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(AdminBodyError::TooLarge) => Err(AdminBodyError::TooLarge),
        Err(AdminBodyError::TimedOut) => Err(AdminBodyError::TimedOut),
        Err(AdminBodyError::Read(err)) => {
            if is_length_limit_error(err.as_ref()) {
                Err(AdminBodyError::TooLarge)
            } else {
                Err(AdminBodyError::Read(err))
            }
        }
    }
}

/// Body wrapper that fails when no frame arrives within `idle`.
struct IdleTimeoutBody<B> {
    inner: B,
    idle: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
    waiting: bool,
}

impl<B> IdleTimeoutBody<B> {
    fn new(inner: B, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: None,
            waiting: false,
        }
    }

    fn arm_deadline(&mut self) {
        match Instant::now().checked_add(self.idle) {
            Some(at) => match self.deadline.as_mut() {
                Some(sleep) => sleep.as_mut().reset(at),
                None => self.deadline = Some(Box::pin(sleep_until(at))),
            },
            None => self.deadline = None,
        }
    }
}

impl<B> Body for IdleTimeoutBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = AdminBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                self.waiting = false;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                self.waiting = false;
                Poll::Ready(Some(Err(AdminBodyError::Read(err.into()))))
            }
            Poll::Ready(None) => {
                self.waiting = false;
                Poll::Ready(None)
            }
            Poll::Pending => {
                if !self.waiting {
                    self.waiting = true;
                    self.arm_deadline();
                }
                if let Some(deadline) = self.deadline.as_mut() {
                    match deadline.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.waiting = false;
                            return Poll::Ready(Some(Err(AdminBodyError::TimedOut)));
                        }
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

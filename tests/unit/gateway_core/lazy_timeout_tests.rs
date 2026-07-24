//! Unit tests for lazy-initialized timeout wrapper.

use ferrum_edge::lazy_timeout::{LazyTimeoutError, lazy_timeout};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

struct ReadyOnSecondPoll {
    polls: Arc<AtomicUsize>,
}

impl Future for ReadyOnSecondPoll {
    type Output = &'static str;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.polls.fetch_add(1, Ordering::SeqCst) == 0 {
            Poll::Pending
        } else {
            Poll::Ready("late")
        }
    }
}

#[tokio::test]
async fn test_immediate_completion_no_timeout() {
    let result = lazy_timeout(Duration::from_secs(1), async { 42 }).await;
    assert_eq!(result.unwrap(), 42);
}

#[tokio::test]
async fn test_timeout_fires_when_inner_pending() {
    let result = lazy_timeout(Duration::from_millis(10), async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        42
    })
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_inner_completes_before_timeout() {
    let result = lazy_timeout(Duration::from_secs(10), async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        "done"
    })
    .await;
    assert_eq!(result.unwrap(), "done");
}

/// When the deadline wake and the inner future are both ready on the same
/// poll, prefer the completed value — matching `tokio::time::timeout`.
#[tokio::test(start_paused = true)]
async fn test_simultaneous_ready_favors_inner_completion() {
    let polls = Arc::new(AtomicUsize::new(0));
    let mut fut = std::pin::pin!(lazy_timeout(
        Duration::from_millis(10),
        ReadyOnSecondPoll {
            polls: polls.clone(),
        },
    ));

    // First poll: inner Pending → timer arms; deadline has not fired yet.
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(ready) => panic!("expected Pending on first poll, got {ready:?}"),
    })
    .await;
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "first poll must arm the timer after the inner future returns Pending"
    );

    // Fire the deadline. On the next poll both sleep and ReadyOnSecondPoll
    // are ready; simultaneous readiness must favor the completed value.
    tokio::time::advance(Duration::from_millis(10)).await;

    let result = fut.await;
    assert_eq!(result, Ok("late"));
    assert_eq!(
        polls.load(Ordering::SeqCst),
        2,
        "inner future must be polled after the deadline wake"
    );
}

#[test]
fn test_lazy_timeout_error_display() {
    let err = LazyTimeoutError;
    assert_eq!(format!("{}", err), "lazy timeout elapsed");
}

#[test]
fn test_lazy_timeout_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(LazyTimeoutError);
    assert_eq!(err.to_string(), "lazy timeout elapsed");
}

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

#[tokio::test]
async fn test_expired_timer_wins_over_future_ready_on_timeout_wake() {
    let polls = Arc::new(AtomicUsize::new(0));

    let result = lazy_timeout(
        Duration::from_millis(10),
        ReadyOnSecondPoll {
            polls: polls.clone(),
        },
    )
    .await;

    assert_eq!(result, Err(LazyTimeoutError));
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "future must not be polled again after the timeout has expired"
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

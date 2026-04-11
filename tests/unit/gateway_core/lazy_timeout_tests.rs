//! Unit tests for lazy-initialized timeout wrapper.

use ferrum_edge::lazy_timeout::{LazyTimeoutError, lazy_timeout};
use std::time::Duration;

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

//! Tests for startup signal waiting.

use ferrum_edge::startup::wait_for_start_signals;
use std::time::Duration;
use tokio::sync::oneshot;

#[tokio::test]
async fn test_all_signals_received_returns_ok() {
    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    tx1.send(()).unwrap();
    tx2.send(()).unwrap();

    let result = wait_for_start_signals(
        vec![("listener-1".into(), rx1), ("listener-2".into(), rx2)],
        Duration::from_secs(1),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_empty_signals_returns_ok() {
    let result = wait_for_start_signals(vec![], Duration::from_secs(1)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_channel_closed_before_signal_returns_error() {
    let (tx, rx) = oneshot::channel::<()>();
    drop(tx); // Close without sending

    let result = wait_for_start_signals(vec![("proxy".into(), rx)], Duration::from_secs(1)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("exited before completing startup"),
        "Expected channel-closed error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_timeout_returns_error() {
    let (_tx, rx) = oneshot::channel::<()>();
    // tx is held but never sent — will timeout

    let result =
        wait_for_start_signals(vec![("admin".into(), rx)], Duration::from_millis(10)).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Timed out"),
        "Expected timeout error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_second_signal_fails_first_succeeds() {
    let (tx1, rx1) = oneshot::channel();
    let (_tx2, rx2) = oneshot::channel::<()>();
    tx1.send(()).unwrap();
    drop(_tx2); // Second channel closed

    let result = wait_for_start_signals(
        vec![("ok-listener".into(), rx1), ("bad-listener".into(), rx2)],
        Duration::from_secs(1),
    )
    .await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("bad-listener"));
}

#[tokio::test]
async fn test_timeout_is_overall_deadline_not_per_signal() {
    let (tx1, rx1) = oneshot::channel();
    let (_tx2, rx2) = oneshot::channel::<()>();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx1.send(());
    });

    let result = tokio::time::timeout(
        Duration::from_millis(220),
        wait_for_start_signals(
            vec![
                ("slow-listener".into(), rx1),
                ("missing-listener".into(), rx2),
            ],
            Duration::from_millis(150),
        ),
    )
    .await
    .expect("startup wait should enforce one overall deadline");

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("missing-listener"),
        "expected timeout to report the pending listener, got: {err}"
    );
}

//! External coverage for control-plane listener supervision (issue #2367).
//!
//! Asserts the *mode result* (`Ok` / `Err`) after draining siblings — not only
//! that shutdown was signaled.

use std::time::{Duration, Instant};

use ferrum_edge::_test_support::wait_for_cp_listeners_until_shutdown_or_exit_for_test;

#[tokio::test]
async fn pending_sibling_plus_listener_error_returns_err() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut sibling_rx = shutdown_tx.subscribe();
    let sibling = tokio::spawn(async move {
        while !*sibling_rx.borrow() {
            if sibling_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let failing =
        tokio::spawn(async { Err::<(), anyhow::Error>(anyhow::anyhow!("accept loop failed")) });

    let started = Instant::now();
    let result = wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        vec![
            ("CP admin HTTP listener".to_string(), sibling),
            ("CP gRPC server".to_string(), failing),
        ],
        shutdown_tx,
        Duration::from_secs(30),
    )
    .await;
    let elapsed = started.elapsed();

    let err = result.expect_err("listener serve error must propagate as Err");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("accept loop failed"),
        "error should include serve failure cause; got {rendered}",
    );
    assert!(
        rendered.contains("CP gRPC server"),
        "error should name the failing listener; got {rendered}",
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "pending sibling must drain via shutdown trigger; took {elapsed:?}",
    );
}

#[tokio::test]
async fn pending_sibling_plus_listener_panic_returns_err() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut sibling_rx = shutdown_tx.subscribe();
    let sibling = tokio::spawn(async move {
        while !*sibling_rx.borrow() {
            if sibling_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let panicking = tokio::spawn(async {
        panic!("simulated CP listener panic");
    });

    let started = Instant::now();
    let result = wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        vec![
            ("CP admin HTTPS listener".to_string(), sibling),
            ("CP admin HTTP listener".to_string(), panicking),
        ],
        shutdown_tx,
        Duration::from_secs(30),
    )
    .await;
    let elapsed = started.elapsed();

    let err = result.expect_err("listener panic must propagate as Err");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("panicked"),
        "error should report panic; got {rendered}",
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "pending sibling must drain via shutdown trigger; took {elapsed:?}",
    );
}

#[tokio::test]
async fn graceful_shutdown_returns_ok() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut admin_rx = shutdown_tx.subscribe();
    let admin = tokio::spawn(async move {
        while !*admin_rx.borrow() {
            if admin_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut grpc_rx = shutdown_tx.subscribe();
    let grpc = tokio::spawn(async move {
        while !*grpc_rx.borrow() {
            if grpc_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    shutdown_tx
        .send(true)
        .expect("watch send must succeed with live receivers");

    let result = wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        vec![
            ("CP admin HTTP listener".to_string(), admin),
            ("CP gRPC server".to_string(), grpc),
        ],
        shutdown_tx,
        Duration::from_secs(2),
    )
    .await;

    result.expect("SIGINT/SIGTERM-driven shutdown must return Ok");
}

#[tokio::test]
async fn unsolicited_ok_exit_returns_err_and_drains_sibling() {
    let (shutdown_tx, mut observed_shutdown) = tokio::sync::watch::channel(false);

    let exited = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

    let mut sibling_rx = shutdown_tx.subscribe();
    let sibling = tokio::spawn(async move {
        while !*sibling_rx.borrow() {
            if sibling_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let result = wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        vec![
            ("CP admin HTTP listener".to_string(), sibling),
            ("CP gRPC server".to_string(), exited),
        ],
        shutdown_tx,
        Duration::from_secs(1),
    )
    .await;

    let err = result.expect_err("Ok exit without shutdown request must be Err");
    assert!(
        format!("{err:#}").contains("exited unexpectedly"),
        "error should report unsolicited exit; got {err:#}",
    );

    observed_shutdown
        .changed()
        .await
        .expect("unsolicited exit should trigger shutdown for siblings");
    assert!(
        *observed_shutdown.borrow(),
        "shared shutdown watch must flip after unsolicited listener exit"
    );
}

#[tokio::test]
async fn remaining_failure_keeps_its_listener_name_after_first_handle_is_removed() {
    let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
    shutdown_tx
        .send(true)
        .expect("shutdown receiver owned by helper must stay live");

    let first = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });
    let innocent = tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        Ok::<(), anyhow::Error>(())
    });
    let failing = tokio::spawn(async {
        Err::<(), anyhow::Error>(anyhow::anyhow!("sentinel remaining failure"))
    });

    let result = wait_for_cp_listeners_until_shutdown_or_exit_for_test(
        vec![
            ("first listener".to_string(), first),
            ("innocent listener".to_string(), innocent),
            ("failing listener".to_string(), failing),
        ],
        shutdown_tx,
        Duration::from_millis(100),
    )
    .await;

    let rendered = format!(
        "{:#}",
        result.expect_err("remaining listener failure must propagate")
    );
    assert!(
        rendered.contains("failing listener"),
        "failure must retain the matching listener name: {rendered}"
    );
    assert!(
        !rendered.contains("innocent listener failed"),
        "swap-removal must not misattribute the failure: {rendered}"
    );
}

#[tokio::test]
async fn unsolicited_exit_with_stuck_sibling_returns_err_after_drain_timeout() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let stuck = tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
    let exited = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for_cp_listeners_until_shutdown_or_exit_for_test(
            vec![
                ("stuck listener".to_string(), stuck),
                ("exited listener".to_string(), exited),
            ],
            shutdown_tx,
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("unsolicited exit must not wait forever on stuck siblings");

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "listener-triggered drain should honor the configured timeout"
    );
    let err = result.expect_err("unsolicited exit must still surface as Err after drain timeout");
    assert!(
        format!("{err:#}").contains("exited unexpectedly"),
        "error should report unsolicited exit; got {err:#}",
    );
}

#[tokio::test]
async fn operator_shutdown_with_stuck_sibling_returns_ok_after_drain_timeout() {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let stuck = tokio::spawn(async { std::future::pending::<Result<(), anyhow::Error>>().await });
    let mut draining_rx = shutdown_tx.subscribe();
    let draining = tokio::spawn(async move {
        while !*draining_rx.borrow() {
            if draining_rx.changed().await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    shutdown_tx
        .send(true)
        .expect("watch send must succeed with live receivers");

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        wait_for_cp_listeners_until_shutdown_or_exit_for_test(
            vec![
                ("stuck listener".to_string(), stuck),
                ("draining listener".to_string(), draining),
            ],
            shutdown_tx,
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("operator shutdown must not wait forever on stuck listeners");

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "operator drain should honor the configured timeout"
    );
    result.expect("SIGINT/SIGTERM plus stuck listener must stay Ok");
}

//! Regression test for #6753: a peer that sends response headers and then
//! stalls mid-body must be charged to the cell's error count when the
//! exchange deadline expires. Before the fix only `send_request` was bounded,
//! so the body read kept a worker (and the whole cell) alive until the harness
//! step timed out, with no result JSON written.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Upper bound on the child process, generous enough for a cold CI runner and
/// still far below the stalled peer's own hold-open time (30s).
const TEST_DEADLINE: Duration = Duration::from_secs(10);
/// The peer promises a large body, sends one byte, then holds the connection.
const STALL_HOLD: Duration = Duration::from_secs(30);

#[tokio::test]
async fn stalled_response_body_is_recorded_as_cell_error() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled-response peer");
    let addr = listener.local_addr().expect("peer address");

    let peer = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = vec![0u8; 64 * 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1048576\r\n\r\nx")
                    .await;
                let _ = stream.flush().await;
                tokio::time::sleep(STALL_HOLD).await;
            });
        }
    });

    let target = format!("http://{addr}/echo");
    let exchange_timeout = (TEST_DEADLINE.as_secs() / 5).to_string();
    let output = tokio::time::timeout(
        TEST_DEADLINE,
        tokio::process::Command::new(env!("CARGO_BIN_EXE_mesh_loadgen"))
            .kill_on_drop(true)
            .args([
                "--target",
                target.as_str(),
                "--mesh",
                "stalled",
                "--duration",
                "1",
                "--concurrency",
                "1",
                "--payload-size",
                "16",
                "--exchange-timeout-secs",
                exchange_timeout.as_str(),
                "--json",
            ])
            .output(),
    )
    .await
    .expect("loadgen must return after the exchange deadline, not hang on the body")
    .expect("run mesh_loadgen");

    peer.abort();

    assert!(output.status.success(), "loadgen failed: {output:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("loadgen JSON report");
    let stderr = String::from_utf8(output.stderr).expect("loadgen stderr");
    assert!(
        stderr.contains("MESH_LOADGEN_ERROR phase=measured "),
        "{stderr}"
    );
    assert!(
        stderr.contains("stage=response_body cause=exchange_timeout"),
        "{stderr}"
    );
    assert!(
        stderr.contains("status=Some(200) expected_body_bytes=16 actual_body_bytes=unknown"),
        "{stderr}"
    );
    assert_eq!(report["total_requests"], 0, "stalled body is not a result");
    assert!(
        report["total_errors"].as_u64().unwrap_or(0) >= 1,
        "timed-out exchange must be recorded as an error: {report}"
    );
}

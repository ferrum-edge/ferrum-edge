//! Functional coverage for the Linux splice-path backend directional
//! timeouts. `functional_tcp_proxy_test::test_tcp_proxy_backend_read_timeout`
//! covers the userspace `bidirectional_copy` path; this module covers the
//! `bidirectional_splice` and `bidirectional_splice_io_uring` paths which
//! were previously gated off when any backend directional timeout was set
//! (see PR #1141). The fix moves enforcement inside the splice loops via
//! per-direction watermarks — these tests pin that behavior.
//!
//! All tests are Linux-only because splice(2) and IORING_OP_SPLICE are
//! Linux features. Non-Linux platforms fall back to `bidirectional_copy`
//! which is already covered by `functional_tcp_proxy_test`.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- functional_tcp_splice_backend_timeout --ignored --nocapture

#![cfg(target_os = "linux")]

use crate::common::{TestGateway, ephemeral_port};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

// ── Backends ────────────────────────────────────────────────────────────────

/// Accepts connections, reads everything the proxy sends, but never writes a
/// response. Exercises `backend_read_timeout_ms` on the splice b2c direction.
fn spawn_silent_reader_backend(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => sleep(Duration::from_secs(60)).await,
                    }
                }
            });
        }
    })
}

/// Accepts connections and then never reads or writes. The client sends
/// continuously; once the backend's socket receive buffer fills, the
/// proxy's `pipe→backend` splice stalls in WouldBlock — exercises
/// `backend_write_timeout_ms` on the splice c2b direction.
fn spawn_stuck_reader_backend(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await
            });
        }
    })
}

/// Accepts connections, reads everything the client sends, then trickles a
/// response in small chunks separated by short pauses. Each chunk must
/// arrive faster than `backend_read_timeout_ms` so the watermark refreshes
/// and the relay continues — exercises the "slow but progressing" case.
fn spawn_trickle_backend(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // Read whatever the client sends first (may EOF on half-close).
                let _ = stream.read(&mut buf).await;
                let payload = vec![0xCDu8; 16];
                for _ in 0..6 {
                    if stream.write_all(&payload).await.is_err() {
                        return;
                    }
                    sleep(Duration::from_millis(150)).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    })
}

// ── Gateway harness ─────────────────────────────────────────────────────────

async fn start_gateway_with_retry(
    proxy_id: &str,
    backend_port: u16,
    backend_read_timeout_ms: u64,
    backend_write_timeout_ms: u64,
    tcp_idle_timeout_seconds: u64,
    extra_env: &[(&str, &str)],
) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let stream_port = ephemeral_port().await.expect("allocate stream port");
        let config = tcp_proxy_config(
            proxy_id,
            backend_port,
            stream_port,
            backend_read_timeout_ms,
            backend_write_timeout_ms,
            tcp_idle_timeout_seconds,
        );

        let mut builder = TestGateway::builder()
            .mode_file(config)
            .skip_auto_build()
            .max_attempts(1)
            .reserve_listener_port(stream_port)
            // This test exercises only the configured raw stream listener.
            .env("FERRUM_PROXY_HTTP_PORT", "0");
        for (key, value) in extra_env {
            builder = builder.env(*key, *value);
        }

        match builder.spawn().await {
            Ok(gateway) => return (gateway, stream_port),
            Err(error) => eprintln!(
                "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
                 (stream={stream_port}): {error}"
            ),
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts");
}

fn tcp_proxy_config(
    proxy_id: &str,
    backend_port: u16,
    stream_port: u16,
    backend_read_timeout_ms: u64,
    backend_write_timeout_ms: u64,
    tcp_idle_timeout_seconds: u64,
) -> String {
    let mut yaml = format!(
        r#"
version: "1"
proxies:
  - id: "{proxy_id}"
    listen_port: {stream_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    tcp_idle_timeout_seconds: {tcp_idle_timeout_seconds}
"#
    );
    if backend_read_timeout_ms > 0 {
        yaml.push_str(&format!(
            "    backend_read_timeout_ms: {backend_read_timeout_ms}\n"
        ));
    }
    if backend_write_timeout_ms > 0 {
        yaml.push_str(&format!(
            "    backend_write_timeout_ms: {backend_write_timeout_ms}\n"
        ));
    }
    yaml.push_str(
        r#"
consumers: []
plugin_configs: []
"#,
    );
    yaml
}

async fn connect_stream(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => return s,
            Err(err) if Instant::now() >= deadline => {
                panic!("stream port {port} did not accept: {err}")
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
}

// ── Per-test setup ──────────────────────────────────────────────────────────

struct SpliceTestSetup {
    gateway: TestGateway,
    proxy_port: u16,
    backend_task: JoinHandle<()>,
}

impl SpliceTestSetup {
    fn teardown(mut self) {
        self.gateway.shutdown();
        self.backend_task.abort();
    }
}

/// Bind a backend listener, spawn it via `backend_factory`, then start the
/// gateway pointed at it. The factory takes the bound listener directly so
/// the spawn lifetime matches `SpliceTestSetup::backend_task` and aborting
/// kills the accept loop along with the spawned per-connection tasks.
async fn setup_splice_proxy(
    proxy_id: &str,
    backend_factory: fn(TcpListener) -> JoinHandle<()>,
    backend_read_timeout_ms: u64,
    backend_write_timeout_ms: u64,
    tcp_idle_timeout_seconds: u64,
    extra_env: &[(&str, &str)],
) -> SpliceTestSetup {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = backend_factory(backend_listener);

    let (gateway, proxy_port) = start_gateway_with_retry(
        proxy_id,
        backend_port,
        backend_read_timeout_ms,
        backend_write_timeout_ms,
        tcp_idle_timeout_seconds,
        extra_env,
    )
    .await;

    SpliceTestSetup {
        gateway,
        proxy_port,
        backend_task,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// `backend_read_timeout_ms` must fire on a silent backend even when the
/// splice path is active. Forces the libc::splice path by disabling io_uring.
#[ignore]
#[tokio::test]
async fn functional_splice_backend_read_timeout_closes_silent_backend() {
    let setup = setup_splice_proxy(
        "splice-backend-read",
        spawn_silent_reader_backend,
        500,
        0,
        30,
        // Force the libc::splice async path (not io_uring) so we exercise
        // `splice_one_direction_no_guard`'s b2c_read_watermark.
        &[("FERRUM_IO_URING_SPLICE_ENABLED", "false")],
    )
    .await;

    let mut stream = connect_stream(setup.proxy_port).await;
    stream
        .write_all(b"splice-backend-read-timeout")
        .await
        .expect("write to splice proxy");

    // backend_read_timeout=500ms; allow ~45s overall for CI tolerance.
    let mut buf = vec![0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(45), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("silent backend should not send {n} bytes before splice timeout"),
        Err(_) => panic!("splice path did not enforce backend_read_timeout_ms within 45s"),
    }

    setup.teardown();
}

/// `backend_write_timeout_ms` must fire on a backend that accepts the
/// connection but never reads. Forces the libc::splice path.
#[ignore]
#[tokio::test]
async fn functional_splice_backend_write_timeout_closes_stuck_reader_backend() {
    let setup = setup_splice_proxy(
        "splice-backend-write",
        spawn_stuck_reader_backend,
        0,
        500,
        30,
        &[("FERRUM_IO_URING_SPLICE_ENABLED", "false")],
    )
    .await;

    let mut stream = connect_stream(setup.proxy_port).await;

    // Drive c2b traffic in a background task so kernel-side backpressure
    // builds up: client → proxy → backend's full receive buffer → WouldBlock
    // on the pipe→backend splice → c2b_write_watermark expires.
    let payload = vec![0x55u8; 256 * 1024];
    let driver = tokio::spawn(async move {
        // Loop until the proxy closes the connection.
        loop {
            if stream.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    // The proxy's watchdog ticks every 1s and closes once
    // `now - c2b_write_watermark >= backend_write_timeout_ms`. CI tolerance: 45s.
    match tokio::time::timeout(Duration::from_secs(45), driver).await {
        Ok(_) => { /* writer exited because the connection closed */ }
        Err(_) => panic!("splice path did not enforce backend_write_timeout_ms within 45s"),
    }

    setup.teardown();
}

/// A slow-but-progressing backend (chunks faster than the read timeout) must
/// not falsely trip `backend_read_timeout_ms` on the splice path. Mirrors the
/// equivalent unit test for `bidirectional_splice`.
#[ignore]
#[tokio::test]
async fn functional_splice_slow_progressing_backend_does_not_trip_read_timeout() {
    let setup = setup_splice_proxy(
        "splice-trickle",
        spawn_trickle_backend,
        // Each backend chunk arrives every 150ms; 500ms timeout leaves slack.
        500,
        0,
        30,
        &[("FERRUM_IO_URING_SPLICE_ENABLED", "false")],
    )
    .await;

    let mut stream = connect_stream(setup.proxy_port).await;
    stream.write_all(b"PING").await.expect("write to proxy");
    let _ = stream.shutdown().await;

    let mut received = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
        .await
        .expect("relay did not complete within 10s");
    result.expect("relay closed with an error");

    // 6 chunks of 16 bytes = 96 bytes total.
    assert_eq!(
        received.len(),
        96,
        "slow trickle backend should deliver full 96-byte response, got {} bytes",
        received.len()
    );

    setup.teardown();
}

/// Same scenario as `functional_splice_backend_read_timeout_closes_silent_backend`
/// but with io_uring splice enabled (when available). Falls through to the
/// libc fallback inside `io_uring_splice_direction` on kernels without
/// IORING_OP_SPLICE — either way, `backend_read_timeout_ms` must fire.
#[ignore]
#[tokio::test]
async fn functional_splice_io_uring_backend_read_timeout_closes_silent_backend() {
    let setup = setup_splice_proxy(
        "splice-io-uring-backend-read",
        spawn_silent_reader_backend,
        500,
        0,
        30,
        &[("FERRUM_IO_URING_SPLICE_ENABLED", "auto")],
    )
    .await;

    let mut stream = connect_stream(setup.proxy_port).await;
    stream
        .write_all(b"io-uring-backend-read-timeout")
        .await
        .expect("write to splice proxy");

    let mut buf = vec![0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(45), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("silent backend should not send {n} bytes before splice timeout"),
        Err(_) => panic!(
            "io_uring/libc-fallback splice did not enforce backend_read_timeout_ms within 45s"
        ),
    }

    setup.teardown();
}

/// Companion of `functional_splice_backend_write_timeout_closes_stuck_reader_backend`
/// but with io_uring splice enabled. Pins the io_uring path's write-watermark
/// enforcement end-to-end through the binary.
#[ignore]
#[tokio::test]
async fn functional_splice_io_uring_backend_write_timeout_closes_stuck_reader_backend() {
    let setup = setup_splice_proxy(
        "splice-io-uring-backend-write",
        spawn_stuck_reader_backend,
        0,
        500,
        30,
        &[("FERRUM_IO_URING_SPLICE_ENABLED", "auto")],
    )
    .await;

    let mut stream = connect_stream(setup.proxy_port).await;

    let payload = vec![0x55u8; 256 * 1024];
    let driver = tokio::spawn(async move {
        loop {
            if stream.write_all(&payload).await.is_err() {
                break;
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(45), driver).await {
        Ok(_) => { /* writer exited because the connection closed */ }
        Err(_) => panic!(
            "io_uring/libc-fallback splice did not enforce backend_write_timeout_ms within 45s"
        ),
    }

    setup.teardown();
}

fn spawn_request_then_push_backend(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if stream.read_u8().await.ok() != Some(b'S') {
                    return;
                }
                for byte in 0..30u8 {
                    if stream.write_all(&[byte]).await.is_err() {
                        return;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                if stream.read_u8().await.ok() == Some(b'Q') {
                    let _ = stream.write_all(b"!").await;
                }
            });
        }
    })
}

async fn verify_splice_push_after_request(io_uring: &str) {
    let setup = setup_splice_proxy(
        "splice-request-then-push",
        spawn_request_then_push_backend,
        0,
        500,
        30,
        &[("FERRUM_IO_URING_SPLICE_ENABLED", io_uring)],
    )
    .await;
    let mut stream = connect_stream(setup.proxy_port).await;
    tokio::time::timeout(Duration::from_secs(15), async {
        stream.write_all(b"S").await.unwrap();
        for expected in 0..30u8 {
            assert_eq!(stream.read_u8().await.unwrap(), expected);
        }
        stream.write_all(b"Q").await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), b'!');
    })
    .await
    .expect("backend pushes must survive a drained client write queue");
    setup.teardown();
}

#[ignore]
#[tokio::test]
async fn functional_splice_write_timeout_preserves_request_then_push_session() {
    verify_splice_push_after_request("false").await;
}

#[ignore]
#[tokio::test]
async fn functional_io_uring_or_fallback_preserves_request_then_push_session() {
    verify_splice_push_after_request("auto").await;
}

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

use std::time::{Duration, Instant};
use tempfile::TempDir;
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

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn spawn_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("RUST_LOG", "ferrum_edge=info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    Ok(cmd.spawn()?)
}

async fn wait_for_health(admin_port: u16) -> bool {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        match reqwest::get(&health_url).await {
            Ok(r) if r.status().is_success() => return true,
            _ => sleep(Duration::from_millis(250)).await,
        }
    }
}

async fn start_gateway_with_retry<F>(
    make_config: F,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16, u16, TempDir)
where
    F: Fn(u16) -> String,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let stream_port = bind_and_release_port().await;
        let http_port = bind_and_release_port().await;
        let admin_port = bind_and_release_port().await;

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(&config_path, make_config(stream_port)).unwrap();

        let mut child = match spawn_gateway(
            config_path.to_str().unwrap(),
            http_port,
            admin_port,
            extra_env,
        ) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Gateway spawn attempt {attempt}/{MAX_ATTEMPTS} failed: {e}");
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };
        if wait_for_health(admin_port).await {
            return (child, stream_port, admin_port, dir);
        }
        eprintln!(
            "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
             (stream={stream_port} http={http_port} admin={admin_port})"
        );
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts");
}

async fn bind_and_release_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
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
    listen_port: {stream_port: ''}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    tcp_idle_timeout_seconds: {tcp_idle_timeout_seconds: ''}
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
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
    gateway: std::process::Child,
    proxy_port: u16,
    backend_task: JoinHandle<()>,
    _dir: TempDir,
}

impl SpliceTestSetup {
    fn teardown(mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
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

    let (gateway, proxy_port, _admin_port, dir) = start_gateway_with_retry(
        |stream_port| {
            tcp_proxy_config(
                proxy_id,
                backend_port,
                stream_port,
                backend_read_timeout_ms,
                backend_write_timeout_ms,
                tcp_idle_timeout_seconds,
            )
        },
        extra_env,
    )
    .await;

    SpliceTestSetup {
        gateway,
        proxy_port,
        backend_task,
        _dir: dir,
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

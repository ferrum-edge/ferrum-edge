//! Functional tests for graceful shutdown & connection draining (P0-3).
//!
//! These tests start the real `ferrum-edge` binary in file mode, send SIGTERM,
//! and verify drain semantics per CLAUDE.md "Graceful Shutdown & Connection
//! Draining":
//!
//!   * In-flight requests complete within `FERRUM_SHUTDOWN_DRAIN_SECONDS`.
//!   * New TCP connections are refused once the accept loops exit.
//!   * `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` forces immediate exit (no drain wait).
//!   * HTTP/1.1 responses carry `Connection: close` during drain.
//!   * Drain timeout is respected — the gateway exits even if requests don't
//!     complete in time.
//!
//! The H2-streams drain case is intentionally not covered here: setting up a
//! real H2 client + long-lived stream over the gateway binary is fragile, and
//! the underlying `RequestGuard` is already covered by unit tests in
//! `src/overload.rs`. TODO: add H2 streaming drain coverage once a harness
//! exists.
//!
//! All tests are `#[ignore]` — run with:
//!   cargo test --test functional_tests -- --ignored functional_graceful_shutdown --nocapture

#![cfg(unix)]

use std::io::Write;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

// ============================================================================
// Slow Echo Backend
// ============================================================================

/// Start a slow HTTP/1.1 backend that reads the request, sleeps for
/// `backend_sleep_ms`, then writes a 200 OK response and closes.
///
/// The listener is pre-bound by the caller to avoid port races with other
/// in-process servers (per the functional-test playbook in CLAUDE.md).
async fn start_slow_backend_on(listener: TcpListener, backend_sleep_ms: u64) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                tokio::spawn(async move {
                    // Read request headers (consume until CRLFCRLF or up to 8 KiB).
                    let mut buf = vec![0u8; 8192];
                    let mut total = 0;
                    loop {
                        match stream.read(&mut buf[total..]).await {
                            Ok(0) => return,
                            Ok(n) => {
                                total += n;
                                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                                if total >= buf.len() {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }

                    // Simulate a slow backend.
                    sleep(Duration::from_millis(backend_sleep_ms)).await;

                    let body = "slow-ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
            Err(_) => return,
        }
    }
}

// ============================================================================
// Gateway Subprocess Helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn start_gateway(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    drain_seconds: u64,
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_PROXY_HTTPS_PORT", "0")
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", drain_seconds.to_string())
        .env("FERRUM_LOG_LEVEL", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start the gateway with retry against ephemeral-port races.
async fn start_gateway_with_retry(
    config_path: &str,
    drain_seconds: u64,
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway(config_path, proxy_port, admin_port, drain_seconds);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start after {} attempts (drain_seconds={})",
        MAX_ATTEMPTS, drain_seconds
    );
}

/// Send SIGTERM to a child process via the `kill` shell command. Using the
/// shell avoids pulling in `libc` / `nix` for portability and matches the
/// SIGHUP pattern used elsewhere in functional tests.
fn send_sigterm(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .output();
}

/// Poll a child process until it exits or the timeout elapses. Returns
/// `Some(status)` if the process exited, `None` on timeout.
fn wait_with_timeout(
    child: &mut std::process::Child,
    deadline: Duration,
) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

/// Build a file-mode YAML config with one echo proxy pointed at `backend_port`.
fn write_config(dir: &TempDir, backend_port: u16) -> std::path::PathBuf {
    let config_path = dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "slow-proxy"
    listen_path: "/slow"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );
    let mut f = std::fs::File::create(&config_path).expect("create config");
    f.write_all(config_content.as_bytes())
        .expect("write config");
    drop(f);
    config_path
}

// ============================================================================
// Tests
// ============================================================================

/// Case 1: An in-flight request at SIGTERM time must complete successfully
/// within the drain window.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_inflight_request_completes_during_drain() {
    let temp_dir = TempDir::new().unwrap();

    // Backend sleeps 3s so the request is definitively in flight when we
    // send SIGTERM 500ms later.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_slow_backend_on(backend_listener, 3_000));
    sleep(Duration::from_millis(200)).await;

    let config_path = write_config(&temp_dir, backend_port);
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 10).await;

    // Fire the slow request in the background.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/slow", proxy_port);
    let inflight = tokio::spawn(async move { client.get(&url).send().await });

    // Let the request reach the backend and start sleeping.
    sleep(Duration::from_millis(500)).await;

    // SIGTERM the gateway. Drain window is 10s; backend sleep + reply is ~3s.
    let start = Instant::now();
    send_sigterm(gateway.id());

    // The in-flight request must still return 200.
    let result = timeout(Duration::from_secs(8), inflight).await;
    match result {
        Ok(Ok(Ok(resp))) => {
            assert!(
                resp.status().is_success(),
                "in-flight request should complete with 200, got {}",
                resp.status()
            );
            let body = resp.bytes().await.unwrap_or_default();
            assert_eq!(&body[..], b"slow-ok");
        }
        Ok(Ok(Err(e))) => panic!("in-flight request errored during drain: {e}"),
        Ok(Err(e)) => panic!("in-flight task panicked: {e}"),
        Err(_) => panic!("in-flight request did not finish within 8s during drain"),
    }

    // The gateway must exit shortly after the request completes (drain complete).
    let status = wait_with_timeout(&mut gateway, Duration::from_secs(6));
    assert!(
        status.is_some(),
        "gateway did not exit within 6s after drain (elapsed={:?})",
        start.elapsed()
    );

    backend_task.abort();
}

/// Case 2: Once SIGTERM fires and accept loops close, new TCP connections
/// to the proxy port must be refused.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_new_connections_refused_during_drain() {
    let temp_dir = TempDir::new().unwrap();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_slow_backend_on(backend_listener, 3_000));
    sleep(Duration::from_millis(200)).await;

    let config_path = write_config(&temp_dir, backend_port);
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 10).await;

    // Fire an in-flight request to keep the drain alive.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/slow", proxy_port);
    let inflight = tokio::spawn(async move { client.get(&url).send().await });

    sleep(Duration::from_millis(500)).await;

    send_sigterm(gateway.id());

    // Give the accept loops a brief moment to exit. The drain path begins
    // immediately on signal receipt but listener shutdown is async.
    sleep(Duration::from_millis(500)).await;

    // Attempt a fresh TCP connection — it must fail (RST/refused) OR close
    // immediately. We try a few times over ~2s to survive any OS-level
    // residual backlog.
    let addr = format!("127.0.0.1:{}", proxy_port);
    let mut refused = false;
    for _ in 0..20 {
        match timeout(Duration::from_millis(500), TcpStream::connect(&addr)).await {
            Err(_) => {
                // Timeout on connect — count as refused.
                refused = true;
                break;
            }
            Ok(Err(_)) => {
                refused = true;
                break;
            }
            Ok(Ok(mut s)) => {
                // Connection succeeded at the syscall level but the listener
                // may have closed it immediately. Try a minimal write + read;
                // if the server dropped the socket this will EOF quickly.
                let _ = s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
                let mut buf = [0u8; 64];
                match timeout(Duration::from_millis(500), s.read(&mut buf)).await {
                    Ok(Ok(0)) => {
                        refused = true;
                        break;
                    }
                    Err(_) => {
                        // Hung, but listener definitely isn't handling new
                        // connections normally; accept as "refused enough".
                        refused = true;
                        break;
                    }
                    _ => {
                        // Got a real response — listener still alive. Sleep
                        // and retry to give the drain more time to close it.
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    assert!(
        refused,
        "proxy listener continued accepting new connections during drain"
    );

    // Let the in-flight request finish and the gateway exit.
    let _ = timeout(Duration::from_secs(10), inflight).await;
    let _ = wait_with_timeout(&mut gateway, Duration::from_secs(6));

    backend_task.abort();
}

/// Case 3: `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` disables draining — the process
/// exits almost immediately, even with a slow in-flight request.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_zero_exits_immediately() {
    let temp_dir = TempDir::new().unwrap();

    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_slow_backend_on(backend_listener, 5_000));
    sleep(Duration::from_millis(200)).await;

    let config_path = write_config(&temp_dir, backend_port);
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 0).await;

    // Start an in-flight request against a 5s backend sleep. We intentionally
    // don't assert it succeeds — with drain=0 the gateway may cut it off.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/slow", proxy_port);
    let inflight = tokio::spawn(async move { client.get(&url).send().await });

    sleep(Duration::from_millis(500)).await;

    let start = Instant::now();
    send_sigterm(gateway.id());

    // With drain=0 the gateway should exit within ~2s total (accept loops
    // close + background cleanup 5s budget is bypassed by the zero drain).
    let status = wait_with_timeout(&mut gateway, Duration::from_secs(2));
    assert!(
        status.is_some(),
        "gateway with drain=0 did not exit within 2s (elapsed={:?})",
        start.elapsed()
    );

    // The in-flight request should either error or return — but we don't
    // assert its specific outcome.
    let _ = timeout(Duration::from_secs(2), inflight).await;

    backend_task.abort();
}

/// Case 4: During drain, HTTP/1.1 responses must advertise `Connection: close`
/// so clients don't reuse the connection. Because new TCP connections are
/// refused during drain, we open a keep-alive connection BEFORE SIGTERM,
/// send a first request, then send a second request over the same socket
/// after SIGTERM and inspect its Connection header.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_sets_connection_close_header() {
    let temp_dir = TempDir::new().unwrap();

    // Use a fast backend (100ms sleep) so request turnaround is quick.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_slow_backend_on(backend_listener, 100));
    sleep(Duration::from_millis(200)).await;

    let config_path = write_config(&temp_dir, backend_port);
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 10).await;

    // Open a raw keep-alive HTTP/1.1 connection.
    let addr = format!("127.0.0.1:{}", proxy_port);
    let mut conn = TcpStream::connect(&addr).await.expect("connect to proxy");

    // Request 1: normal keep-alive.
    let req1 = format!(
        "GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive\r\n\r\n",
        proxy_port
    );
    conn.write_all(req1.as_bytes()).await.unwrap();

    // Read response 1 fully.
    let response1 = read_http_response(&mut conn).await.expect("read resp1");
    assert!(
        response1.starts_with("HTTP/1.1 200"),
        "first response should be 200: {}",
        response1.lines().next().unwrap_or("")
    );

    // Backend closes the gateway<->backend hop (its response set
    // `Connection: close`), but the gateway's FRONTEND response is what we
    // care about — and it does not re-emit backend hop-by-hop. Check whether
    // the frontend already marked the connection closed (if so, we'll need
    // to open a new connection pre-SIGTERM; do that now).
    let first_has_close = response1
        .to_ascii_lowercase()
        .contains("\r\nconnection: close");

    // If the gateway told us to close after response 1, we can't reuse this
    // socket. Open a second keep-alive socket before SIGTERM.
    let mut conn2 = if first_has_close {
        let mut c = TcpStream::connect(&addr)
            .await
            .expect("reconnect pre-SIGTERM");
        // Warm the connection with one request so we know it's alive.
        let probe = format!(
            "GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive\r\n\r\n",
            proxy_port
        );
        c.write_all(probe.as_bytes()).await.unwrap();
        let probe_resp = read_http_response(&mut c).await.expect("read probe resp");
        assert!(probe_resp.starts_with("HTTP/1.1 200"));
        c
    } else {
        conn
    };

    // Now SIGTERM the gateway — from this point on responses should carry
    // `Connection: close`.
    send_sigterm(gateway.id());

    // Give the signal handler time to flip the `draining` atomic.
    sleep(Duration::from_millis(300)).await;

    // Send a second request over the pre-opened keep-alive socket.
    let req2 = format!(
        "GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive\r\n\r\n",
        proxy_port
    );
    // If the write fails the server has already torn down the socket — which
    // is effectively the same signal (connection won't be reused). Treat
    // that as a pass for this case.
    let write_ok = conn2.write_all(req2.as_bytes()).await.is_ok();

    if write_ok {
        match timeout(Duration::from_secs(5), read_http_response(&mut conn2)).await {
            Ok(Some(response2)) => {
                let lower = response2.to_ascii_lowercase();
                assert!(
                    lower.contains("\r\nconnection: close"),
                    "second response during drain should include Connection: close, got:\n{}",
                    response2
                );
            }
            Ok(None) => {
                // Socket closed without a response — also acceptable: the
                // gateway won't keep it alive during drain.
            }
            Err(_) => panic!("timed out reading second response during drain"),
        }
    }

    // Cleanup.
    let _ = wait_with_timeout(&mut gateway, Duration::from_secs(8));
    backend_task.abort();
}

/// Case 5: Drain timeout is respected — with `FERRUM_SHUTDOWN_DRAIN_SECONDS=2`
/// and a 10-second backend, the gateway must exit within ~4s total even
/// though the in-flight request has not yet completed.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_timeout_respected() {
    let temp_dir = TempDir::new().unwrap();

    // Backend sleeps 10s — longer than the drain timeout of 2s.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_slow_backend_on(backend_listener, 10_000));
    sleep(Duration::from_millis(200)).await;

    let config_path = write_config(&temp_dir, backend_port);
    let (mut gateway, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), 2).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/slow", proxy_port);
    let inflight = tokio::spawn(async move { client.get(&url).send().await });

    sleep(Duration::from_millis(500)).await;

    let start = Instant::now();
    send_sigterm(gateway.id());

    // Drain timeout 2s + background-cleanup 5s gives a hard upper bound of
    // ~7s, but with nothing else to wait on the process should exit very
    // close to 2s (drain deadline). We allow 4s to cover CI jitter.
    let status = wait_with_timeout(&mut gateway, Duration::from_secs(4));
    assert!(
        status.is_some(),
        "gateway did not honor drain timeout (elapsed={:?})",
        start.elapsed()
    );

    // The in-flight request should have errored because the gateway exited.
    let _ = timeout(Duration::from_secs(2), inflight).await;

    backend_task.abort();
}

// ============================================================================
// Raw HTTP/1.1 response reader
// ============================================================================

/// Read a complete HTTP/1.1 response (status line + headers + body, where body
/// length is determined by `Content-Length`). Returns `None` if the socket
/// closed before a full response was seen.
async fn read_http_response(conn: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Read until we have the full header block.
    let header_end = loop {
        match timeout(Duration::from_secs(5), conn.read(&mut tmp)).await {
            Ok(Ok(0)) => return None,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    break pos + 4;
                }
            }
            _ => return None,
        }
    };

    // Parse Content-Length if present.
    let header_str = std::str::from_utf8(&buf[..header_end]).ok()?;
    let content_length: usize = header_str
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().ok())
        })
        .flatten()
        .unwrap_or(0);

    let total_needed = header_end + content_length;
    while buf.len() < total_needed {
        match timeout(Duration::from_secs(5), conn.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
            _ => break,
        }
    }

    String::from_utf8(buf).ok()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

//! Functional test for gRPC reverse proxying through Ferrum Edge.
//!
//! This test:
//! 1. Starts a local gRPC echo backend (h2c HTTP/2 server)
//! 2. Starts the gateway binary in file mode with a `grpc` proxy config
//! 3. Connects an HTTP/2 gRPC client through the gateway
//! 4. Verifies end-to-end gRPC request/response round-trips
//! 5. Tests gRPC trailers (grpc-status, grpc-message) forwarding
//! 6. Tests gRPC error propagation and metadata forwarding
//! 7. Tests backend unavailable returns proper gRPC error
//! 8. Tests `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` request-size rejection
//!
//! This test is marked with #[ignore] as it requires the binary to be built
//! and should be run with: cargo test --test functional_tests functional_grpc -- --ignored --nocapture

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http2::Builder as Http2ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;

// ============================================================================
// Helpers
// ============================================================================

/// Allocate a free port by binding to port 0 and returning the assigned port.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Start a mock gRPC backend server (h2c HTTP/2).
///
/// The backend:
/// - Accepts cleartext HTTP/2 connections (h2c / prior knowledge)
/// - Echoes the request path in `x-echo-path` header
/// - Echoes the request method in `x-echo-method` header
/// - Echoes the request body back in the response
/// - Returns `grpc-status: 0` (OK) by default
/// - Supports `x-test-grpc-status` / `x-test-grpc-message` headers to override status
/// - Echoes `authorization` header back as `x-echo-authorization` for metadata verification
async fn start_grpc_echo_backend(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind gRPC echo backend");

    tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let method = req.method().to_string();

                    // Echo the authorization header if present
                    let auth_header = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    // Check for custom test behavior headers
                    let test_status = req
                        .headers()
                        .get("x-test-grpc-status")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u32>().ok());
                    let test_message = req
                        .headers()
                        .get("x-test-grpc-message")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    // Collect request body to echo back
                    let body_bytes = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let grpc_status = test_status.unwrap_or(0);
                    let grpc_message = test_message.unwrap_or_else(|| "OK".to_string());

                    // Build gRPC response
                    let mut builder = Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .header("grpc-status", grpc_status.to_string())
                        .header("grpc-message", &grpc_message)
                        .header("x-echo-path", &path)
                        .header("x-echo-method", &method);

                    if let Some(auth) = auth_header {
                        builder = builder.header("x-echo-authorization", auth);
                    }

                    let response = builder.body(Full::new(body_bytes)).unwrap();

                    Ok::<_, hyper::Error>(response)
                });

                if let Err(e) = builder.serve_connection(io, service).await {
                    // Connection closed by client is normal
                    if !format!("{}", e).contains("connection closed") {
                        eprintln!("gRPC echo backend error: {}", e);
                    }
                }
            });
        }
    })
}

/// Start a mock server-streaming gRPC backend (h2c HTTP/2) that HOLDS its
/// response stream open.
///
/// Unlike [`start_grpc_echo_backend`] (which buffers the request, replies with
/// a complete `Full` body, and completes immediately), this backend:
/// - Sends `200 application/grpc` headers, then exactly ONE initial DATA frame.
/// - STALLS — withholds the gRPC trailers (`grpc-status`) and stream EOF until
///   the `release` watch channel flips to `true`.
///
/// Because the response stream never reaches EOF until released, the gateway's
/// streaming gRPC response body (and therefore the per-IP in-flight request
/// slot attached to it via `body.with_per_ip_request_guard`) stays alive for
/// the full streaming-response lifetime. This is exactly the condition the F15
/// per-IP-evasion fix protects.
///
/// A `watch::Receiver<bool>` (not a `Notify`) is used for the release signal so
/// the recovery probe is race-free: `watch` retains the latest value, so a
/// release flipped to `true` BEFORE a later request's sender parks is observed
/// immediately rather than lost (as `Notify::notify_waiters()` would be).
///
/// The caller passes a pre-bound `TcpListener` so the backend owns the
/// listening socket for its whole lifetime — there is no free-port→bind race
/// window between port allocation and accept.
async fn start_grpc_streaming_backend(
    listener: TcpListener,
    release: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, _addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let _ = stream.set_nodelay(true);
            let release = release.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let builder = Http2ServerBuilder::new(TokioExecutor::new());

                let service = service_fn(move |req: Request<Incoming>| {
                    let mut release = release.clone();
                    async move {
                        // Drain the request body in the background so client-
                        // streaming / unary uploads don't wedge; we don't need
                        // its contents for this test.
                        let mut req_body = req.into_body();
                        tokio::spawn(async move { while req_body.frame().await.is_some() {} });

                        // Frame channel: emit one initial DATA frame, then keep
                        // the stream open (Pending) until `release` is true, at
                        // which point we send the gRPC trailers and close.
                        let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(2);

                        // One initial gRPC DATA frame (a single empty unary
                        // message: [compressed=0][len=0]).
                        let initial = Bytes::from_static(b"\x00\x00\x00\x00\x00");
                        let _ = tx.send(Ok(Frame::data(initial))).await;

                        // Background sender: park until released, then emit
                        // trailers (grpc-status: 0) and drop tx to signal EOF.
                        tokio::spawn(async move {
                            // `watch::changed()` returns Err only if all senders
                            // drop; in that case fall through and close the
                            // stream so the test never hangs on drain.
                            while !*release.borrow_and_update() {
                                if release.changed().await.is_err() {
                                    break;
                                }
                            }
                            let mut trailers = hyper::HeaderMap::new();
                            trailers.insert(
                                "grpc-status",
                                hyper::header::HeaderValue::from_static("0"),
                            );
                            let _ = tx.send(Ok(Frame::trailers(trailers))).await;
                            // tx drops here → stream EOF.
                        });

                        let body = StreamBody::new(ReceiverStream::new(rx));
                        let response = Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(body)
                            .expect("build streaming gRPC response");
                        Ok::<_, hyper::Error>(response)
                    }
                });

                if let Err(e) = builder.serve_connection(io, service).await
                    && !format!("{}", e).contains("connection closed")
                {
                    eprintln!("gRPC streaming backend error: {}", e);
                }
            });
        }
    })
}

/// Build the gateway binary. Thin wrapper over the shared
/// [`crate::common::ensure_gateway_built`] so this file's tests share the
/// same `OnceLock` memoization and `FERRUM_SKIP_GATEWAY_BUILD=1` contract as
/// the [`crate::common::TestGateway`] builder.
fn build_gateway() -> Result<(), Box<dyn std::error::Error>> {
    crate::common::ensure_gateway_built().map_err(|e| -> Box<dyn std::error::Error> { e })
}

/// Find the gateway binary path.
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Start the gateway in file mode with additional environment overrides.
fn start_gateway_with_extra_env(
    config_path: &str,
    http_port: u16,
    extra_env: &[(&str, &str)],
) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    // Fresh admin HTTP port + admin HTTPS disabled so parallel gateways in the
    // same shard never contend on the default admin ports (9000/9443); an admin
    // bind failure aborts startup. These tests do not use the admin API.
    let admin_http_port = std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_http_port.to_string())
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    for (name, value) in extra_env {
        cmd.env(name, value);
    }

    Ok(cmd.spawn()?)
}

/// Write a YAML config file with a gRPC proxy pointing to the given backend port.
fn write_grpc_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-echo-proxy"
    listen_path: "/grpc"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

  - id: "grpc-nostrip-proxy"
    listen_path: "/grpc-full"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: false

  - id: "grpc-unavailable-proxy"
    listen_path: "/grpc-down"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 19999
    strip_listen_path: true

consumers: []
plugin_configs:
  - id: "grpc-security-policy"
    plugin_name: security_headers
    scope: global
    enabled: true
    config:
      set:
        X-Synthetic-Policy: "enforced"
        Grpc-Status: "0"
        Grpc-Message: "policy override"
      remove: []
"#,
        backend_port, backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a YAML config with a gRPC proxy protected by key_auth, including a consumer.
fn write_grpc_auth_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-secured-proxy"
    listen_path: "/grpc-secure"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-keyauth-grpc"

consumers:
  - id: "consumer-grpc-service"
    username: "grpc-test-service"
    credentials:
      keyauth:
        - key: "grpc-valid-api-key-99887766"

plugin_configs:
  - id: "plugin-keyauth-grpc"
    plugin_name: "key_auth"
    config:
      key_location: "header:x-api-key"
    scope: proxy
    proxy_id: "grpc-secured-proxy"
    enabled: true
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Write a YAML config with a gRPC proxy whose allowed_methods excludes POST.
///
/// Protocol-managed framing destinations are intentionally absent from
/// `security_headers.set`: construction now rejects them, and that rejection is
/// covered by the plugin unit tests. This fixture focuses on canonicalizing the
/// remaining application headers into a trailers-only gRPC error.
fn write_grpc_method_filter_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-method-filter-proxy"
    listen_path: "/grpc-method-filter"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true
    allowed_methods:
      - "GET"

consumers: []
plugin_configs:
  - id: "grpc-method-filter-security"
    plugin_name: security_headers
    scope: global
    enabled: true
    config:
      set:
        X-Synthetic-Policy: "enforced"
        Content-Type: "text/plain"
        Grpc-Status: "0"
        Grpc-Message: "policy override"
      remove: []
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

fn write_grpc_terminal_remove_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "grpc-terminal-remove-proxy"
    listen_path: "/grpc-remove"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {}
    strip_listen_path: true

consumers: []
plugin_configs:
  - id: "grpc-terminal-remove-security"
    plugin_name: security_headers
    scope: global
    enabled: true
    config:
      set:
        X-Synthetic-Policy: "enforced"
      remove:
        - Grpc-Status
        - Grpc-Message
"#,
        backend_port
    );

    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(config.as_bytes())
        .expect("Failed to write config");
}

/// Send a gRPC request through the gateway using hyper's HTTP/2 client (h2c).
fn grpc_unary_body(payload_len: usize, fill: u8) -> Vec<u8> {
    assert!(
        payload_len <= u32::MAX as usize,
        "test payload must fit the gRPC u32 length prefix"
    );

    let mut body = Vec::with_capacity(5 + payload_len);
    body.push(0);
    body.extend_from_slice(&(payload_len as u32).to_be_bytes());
    body.resize(5 + payload_len, fill);
    body
}

async fn send_grpc_request(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Result<(u16, HashMap<String, String>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("Client h2 connection error: {}", e);
        }
    });

    let mut req_builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers");

    for (k, v) in extra_headers {
        req_builder = req_builder.header(*k, *v);
    }

    let req = req_builder.body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;

    let status = response.status().as_u16();
    let mut headers = HashMap::new();
    for (k, v) in response.headers() {
        if let Ok(vs) = v.to_str() {
            headers.insert(k.as_str().to_string(), vs.to_string());
        }
    }

    let body_bytes = response
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();

    Ok((status, headers, body_bytes))
}

/// A live, still-open gRPC response stream returned by [`open_grpc_stream`].
///
/// Holds the response status, the first DATA frame that already arrived, and
/// the LIVE response body (not collected). Keeping this value alive keeps the
/// downstream H2 stream — and therefore the gateway's per-IP request slot —
/// open. Dropping it (or calling [`LiveGrpcStream::drain`]) tears the stream
/// down. The HTTP/2 client connection task is aborted on drop.
struct LiveGrpcStream {
    status: u16,
    first_frame: Bytes,
    body: Incoming,
    // Keep the request sender alive for the lifetime of the response. Dropping
    // the last sender can let Hyper begin connection shutdown while the test
    // still expects the server-streaming body (and its gateway request guard)
    // to remain open.
    _sender: hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    conn_task: tokio::task::JoinHandle<()>,
}

impl LiveGrpcStream {
    /// Drain the remaining response body to completion (consumes the stream),
    /// then drop the connection. Used after the backend has been released so
    /// the gateway can observe EOF and free the per-IP slot.
    async fn drain(mut self) {
        while self.body.frame().await.is_some() {}
        self.conn_task.abort();
    }
}

impl Drop for LiveGrpcStream {
    fn drop(&mut self) {
        self.conn_task.abort();
    }
}

/// Open a gRPC stream through the gateway and return it LIVE (without
/// collecting the body), so the downstream stream stays open.
///
/// Mirrors [`send_grpc_request`]'s `http2::handshake` + `send_request`, but
/// instead of `collect()`-ing the response it reads `response.status()` and
/// the FIRST response frame (via `poll_frame`/`BodyExt::frame`), then returns
/// the live body handle. This is what lets the test pin a long-lived
/// server-streaming RPC in flight while it probes the per-IP limit with a
/// second request.
async fn open_grpc_stream(
    gateway_addr: &str,
    path: &str,
    body: &[u8],
) -> Result<LiveGrpcStream, Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    let conn_task = tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("open_grpc_stream h2 connection error: {}", e);
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body.to_vec())))?;
    let response = sender.send_request(req).await?;
    let status = response.status().as_u16();
    let mut incoming = response.into_body();

    // Read the first frame so we know the stream is established and the
    // streaming body is actively held by the gateway. The streaming backend
    // sends one DATA frame up-front. Bound the wait so a hang fails the test
    // rather than blocking forever.
    let first_frame = match tokio::time::timeout(Duration::from_secs(5), incoming.frame()).await {
        Ok(Some(Ok(frame))) => frame.into_data().unwrap_or_default(),
        Ok(Some(Err(e))) => return Err(format!("first gRPC frame errored: {e}").into()),
        Ok(None) => return Err("gRPC stream ended before first frame".into()),
        Err(_) => return Err("timed out waiting for first gRPC frame".into()),
    };

    Ok(LiveGrpcStream {
        status,
        first_frame,
        body: incoming,
        _sender: sender,
        conn_task,
    })
}

async fn probe_gateway_h2c(
    gateway_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use hyper::client::conn::http2;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::time::timeout(
        Duration::from_millis(750),
        tokio::net::TcpStream::connect(addr),
    )
    .await??;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = tokio::time::timeout(
        Duration::from_secs(1),
        http2::handshake(TokioExecutor::new(), io),
    )
    .await??;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/__ferrum_startup_probe")
        .body(Full::new(Bytes::new()))?;
    let response = tokio::time::timeout(Duration::from_secs(1), sender.send_request(req)).await??;
    let _ = tokio::time::timeout(Duration::from_secs(1), response.into_body().collect()).await??;
    conn_task.abort();

    Ok(())
}

/// Wait for the gateway to start by proving the selected port speaks h2c.
/// Returns Ok(()) on success, Err on timeout — does not panic.
async fn wait_for_gateway(
    gateway_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let addr = format!("127.0.0.1:{}", gateway_port);
    let mut last_err = String::new();

    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Gateway did not become h2c-ready within 15 seconds: {}",
                last_err
            )
            .into());
        }
        match probe_gateway_h2c(&addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = e.to_string();
                sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

/// Start the gateway with retry logic to handle ephemeral port races.
///
/// Each attempt allocates a fresh gateway port, starts the gateway subprocess,
/// and waits for it to become healthy. On failure the process is killed and a
/// new attempt is made with a different port. Panics only after all attempts
/// are exhausted.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16) {
    start_gateway_with_retry_extra_env(config_path, &[]).await
}

async fn start_gateway_with_retry_extra_env(
    config_path: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        match start_gateway_with_extra_env(config_path, gateway_port, extra_env) {
            Ok(mut child) => match wait_for_gateway(gateway_port).await {
                Ok(()) => match child.try_wait() {
                    Ok(Some(status)) => {
                        last_err = format!("gateway exited during startup with status {status}");
                        eprintln!(
                            "Gateway startup attempt {}/{} failed (port {}): {}",
                            attempt, MAX_ATTEMPTS, gateway_port, last_err
                        );
                    }
                    Ok(None) => return (child, gateway_port),
                    Err(e) => {
                        last_err = format!("failed to inspect gateway process status: {e}");
                        eprintln!(
                            "Gateway startup attempt {}/{} failed (port {}): {}",
                            attempt, MAX_ATTEMPTS, gateway_port, last_err
                        );
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                },
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Gateway startup attempt {}/{} failed (port {}): {}",
                        attempt, MAX_ATTEMPTS, gateway_port, last_err
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                }
            },
            Err(e) => {
                last_err = e.to_string();
                eprintln!(
                    "Gateway spawn attempt {}/{} failed: {}",
                    attempt, MAX_ATTEMPTS, last_err
                );
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start after {} attempts: {}",
        MAX_ATTEMPTS, last_err
    );
}

// ============================================================================
// Tests
// ============================================================================

/// End-to-end test: gRPC unary call through the gateway.
/// Client →(h2c)→ Gateway →(h2c)→ gRPC backend → echo response.
#[ignore]
#[tokio::test]
async fn test_grpc_unary_echo_through_gateway() {
    // Allocate backend port and start gRPC echo backend (holds the port)
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    // Write config and start gateway with retry logic for port races
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send gRPC request through the gateway
    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // gRPC message: [compressed:0][length:5][payload:"hello"]
    let grpc_body = b"\x00\x00\x00\x00\x05hello";
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/grpc/my.EchoService/Echo", grpc_body, &[])
            .await
            .expect("gRPC request should succeed");

    // Verify HTTP 200 (gRPC always uses 200)
    assert_eq!(status, 200, "gRPC responses must use HTTP 200");

    // Verify gRPC content-type
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "Response should have application/grpc content-type"
    );

    // Verify grpc-status is OK (0)
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "grpc-status should be 0 (OK)"
    );

    // Verify path was stripped correctly
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.EchoService/Echo"),
        "Gateway should strip /grpc prefix and forward /my.EchoService/Echo"
    );

    // Verify method is POST (gRPC standard)
    assert_eq!(
        headers.get("x-echo-method").map(|s| s.as_str()),
        Some("POST"),
        "gRPC always uses POST"
    );

    // Verify body was echoed back
    assert_eq!(body, grpc_body, "Backend should echo the gRPC message body");

    // Cleanup
    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_unary_echo_through_gateway PASSED");
}

/// End-to-end test: FERRUM_MAX_GRPC_RECV_SIZE_BYTES rejects oversized
/// client request bodies using gRPC RESOURCE_EXHAUSTED semantics.
#[ignore]
#[tokio::test]
async fn test_grpc_recv_size_limit_returns_resource_exhausted() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "8")],
    )
    .await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);
    let grpc_body = grpc_unary_body(32, b'x');
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/grpc/my.EchoService/Echo", &grpc_body, &[])
            .await
            .expect("oversized gRPC request should receive a gRPC error response");

    assert_eq!(status, 200, "gRPC size-limit errors must use HTTP 200");
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "size-limit rejection should preserve gRPC content-type"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("8"),
        "oversized gRPC request should map to RESOURCE_EXHAUSTED"
    );
    assert!(
        body.is_empty(),
        "gateway-generated gRPC size-limit error should be trailers-only"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_recv_size_limit_returns_resource_exhausted PASSED");
}

/// End-to-end test: FERRUM_MAX_GRPC_RECV_SIZE_BYTES=0 disables the request
/// receive cap, allowing a unary request above the default 4 MiB limit.
#[ignore]
#[tokio::test]
async fn test_grpc_recv_size_zero_allows_over_default_request() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "0")],
    )
    .await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);
    let grpc_body = grpc_unary_body(4_194_304 + 1024, b'z');
    let (status, headers, body) =
        send_grpc_request(&gateway_addr, "/grpc/my.EchoService/Echo", &grpc_body, &[])
            .await
            .expect("zero gRPC recv size should allow over-default request");

    assert_eq!(status, 200, "gRPC responses must use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "zero recv-size limit should allow the request to reach the backend"
    );
    assert_eq!(
        body.len(),
        grpc_body.len(),
        "backend should echo the over-default gRPC request body"
    );
    assert_eq!(
        &body[..16],
        &grpc_body[..16],
        "echoed gRPC frame prefix should match"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_recv_size_zero_allows_over_default_request PASSED");
}

/// End-to-end test: gRPC error status forwarding through the gateway.
/// Backend returns a gRPC error (e.g. NOT_FOUND) and the gateway forwards it.
#[ignore]
#[tokio::test]
async fn test_grpc_error_status_forwarding() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Request the backend to return grpc-status 5 (NOT_FOUND)
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc/my.EchoService/NotFound",
        b"",
        &[
            ("x-test-grpc-status", "5"),
            ("x-test-grpc-message", "method not found"),
        ],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200, "gRPC errors still use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("5"),
        "Gateway should forward grpc-status 5 (NOT_FOUND)"
    );
    assert_eq!(
        headers.get("grpc-message").map(|s| s.as_str()),
        Some("method not found"),
        "Gateway should forward grpc-message"
    );
    assert_eq!(
        headers.get("x-synthetic-policy").map(String::as_str),
        Some("enforced"),
        "true Trailers-Only metadata must survive hostile initial-header policy"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_error_status_forwarding PASSED");
}

/// A true Trailers-Only backend response carries terminal metadata in its
/// initial END_STREAM HEADERS. Route policy must not erase that authority.
#[ignore]
#[tokio::test]
async fn test_grpc_trailers_only_terminal_metadata_survives_security_removal() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_terminal_remove_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;
    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    let (status, headers, body) = send_grpc_request(
        &gateway_addr,
        "/grpc-remove/my.EchoService/Denied",
        b"",
        &[
            ("x-test-grpc-status", "7"),
            ("x-test-grpc-message", "permission denied"),
        ],
    )
    .await
    .expect("Trailers-Only request should complete");

    assert_eq!(status, 200);
    assert!(body.is_empty());
    assert_eq!(headers.get("grpc-status").map(String::as_str), Some("7"));
    assert_eq!(
        headers.get("grpc-message").map(String::as_str),
        Some("permission denied")
    );
    assert_eq!(
        headers.get("x-synthetic-policy").map(String::as_str),
        Some("enforced")
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

/// End-to-end test: gRPC metadata (HTTP/2 headers) forwarding through the gateway.
/// Verifies that authorization and custom headers are forwarded to the backend.
#[ignore]
#[tokio::test]
async fn test_grpc_metadata_forwarding() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request with authorization metadata
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc/my.EchoService/Secure",
        b"",
        &[("authorization", "Bearer test-jwt-token-12345")],
    )
    .await
    .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request should succeed"
    );

    // Verify the authorization header was forwarded to the backend
    assert_eq!(
        headers.get("x-echo-authorization").map(|s| s.as_str()),
        Some("Bearer test-jwt-token-12345"),
        "Authorization metadata should be forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_metadata_forwarding PASSED");
}

/// End-to-end test: gRPC backend unavailable returns proper gRPC error.
/// The proxy points to a port with no server, so the gateway should return
/// grpc-status 14 (UNAVAILABLE) with HTTP 200.
#[ignore]
#[tokio::test]
async fn test_grpc_backend_unavailable() {
    let backend_port = free_port().await; // For config, but we also need the unavailable proxy
    // Start a real backend for the config (needed for other proxies in config)
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send to the proxy configured with port 19999 (no server running)
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/grpc-down/my.EchoService/Echo", b"", &[])
            .await
            .expect("Request should complete even if backend is down");

    assert_eq!(status, 200, "gRPC errors use HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("14"),
        "Backend unavailable should return grpc-status 14 (UNAVAILABLE)"
    );
    assert!(
        headers.contains_key("grpc-message"),
        "Should include a grpc-message explaining the error"
    );
    assert_eq!(
        headers.get("x-synthetic-policy").map(String::as_str),
        Some("enforced"),
        "post-routing UNAVAILABLE must carry initial-response policy"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_backend_unavailable PASSED");
}

/// End-to-end test: gRPC with strip_listen_path=false preserves full path.
#[ignore]
#[tokio::test]
async fn test_grpc_no_strip_listen_path() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Use the /grpc-full proxy which has strip_listen_path=false
    let (status, headers, _body) =
        send_grpc_request(&gateway_addr, "/grpc-full/my.EchoService/Echo", b"", &[])
            .await
            .expect("gRPC request should succeed");

    assert_eq!(status, 200);
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Request should succeed"
    );
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/grpc-full/my.EchoService/Echo"),
        "Full path including listen_path should be forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_no_strip_listen_path PASSED");
}

/// End-to-end test: multiple sequential gRPC calls through the gateway.
/// Verifies connection pooling and reuse work correctly for gRPC.
#[ignore]
#[tokio::test]
async fn test_grpc_multiple_sequential_calls() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send 10 sequential gRPC calls with different payloads
    for i in 0..10 {
        let payload = format!("message-{}", i);
        let grpc_body = {
            let mut buf = vec![0u8]; // not compressed
            let len = payload.len() as u32;
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(payload.as_bytes());
            buf
        };

        let (status, headers, body) = send_grpc_request(
            &gateway_addr,
            &format!("/grpc/my.EchoService/Echo{}", i),
            &grpc_body,
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("gRPC request {} failed: {}", i, e));

        assert_eq!(status, 200, "Call {} should return HTTP 200", i);
        assert_eq!(
            headers.get("grpc-status").map(|s| s.as_str()),
            Some("0"),
            "Call {} should return grpc-status OK",
            i
        );
        assert_eq!(body, grpc_body, "Call {} should echo the body", i);
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_multiple_sequential_calls PASSED");
}

/// End-to-end test: gRPC request rejected by key_auth plugin (no API key).
/// Verifies that gateway auth plugins properly reject unauthenticated gRPC requests.
#[ignore]
#[tokio::test]
async fn test_grpc_key_auth_rejects_missing_key() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request WITHOUT an API key — should be rejected
    let (status, headers, body) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/Echo",
        b"",
        &[], // No x-api-key header
    )
    .await
    .expect("Request should complete");

    assert_eq!(status, 200, "gRPC auth rejection should return HTTP 200");
    assert!(
        body.is_empty(),
        "gRPC auth rejection should be trailers-only"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("16"),
        "Missing API key should map to grpc-status 16 (UNAUTHENTICATED)"
    );
    assert!(
        headers
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("Authentication required")),
        "gRPC auth rejection should expose the auth-phase message"
    );

    // Also verify an INVALID key is rejected
    let (status2, _headers2, body2) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/Echo",
        b"",
        &[("x-api-key", "wrong-key-12345")],
    )
    .await
    .expect("Request should complete");

    assert_eq!(status2, 200, "gRPC auth rejection should return HTTP 200");
    assert!(
        body2.is_empty(),
        "gRPC auth rejection should be trailers-only"
    );
    assert_eq!(
        _headers2.get("grpc-status").map(|s| s.as_str()),
        Some("16"),
        "Invalid API key should map to grpc-status 16 (UNAUTHENTICATED)"
    );
    assert!(
        _headers2
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("Invalid API key")),
        "Invalid key rejection should preserve the plugin message"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_key_auth_rejects_missing_key PASSED");
}

/// End-to-end test: gRPC request authenticated by key_auth plugin with valid API key.
/// Verifies that the gateway auth plugin accepts the key, identifies the consumer,
/// and proxies the gRPC request to the backend successfully.
#[ignore]
#[tokio::test]
async fn test_grpc_key_auth_accepts_valid_key() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_auth_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Send gRPC request WITH a valid API key — should be accepted and proxied
    let (status, headers, _body) = send_grpc_request(
        &gateway_addr,
        "/grpc-secure/my.EchoService/SecureMethod",
        b"\x00\x00\x00\x00\x05hello",
        &[("x-api-key", "grpc-valid-api-key-99887766")],
    )
    .await
    .expect("gRPC request should succeed");

    // Request should pass through auth and reach the gRPC backend
    assert_eq!(
        status, 200,
        "Authenticated gRPC request should return HTTP 200"
    );
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc"),
        "Response should have gRPC content-type (request reached backend)"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("0"),
        "Authenticated gRPC request should succeed with grpc-status OK"
    );
    assert_eq!(
        headers.get("x-echo-path").map(|s| s.as_str()),
        Some("/my.EchoService/SecureMethod"),
        "Path should be stripped and forwarded to backend"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_key_auth_accepts_valid_key PASSED");
}

/// End-to-end test: early non-plugin gRPC rejects (route miss and method filter)
/// are translated into trailers-only gRPC errors.
#[ignore]
#[tokio::test]
async fn test_grpc_early_rejects_use_grpc_error_shape() {
    let backend_port = free_port().await;
    let echo_handle = start_grpc_echo_backend(backend_port).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_grpc_method_filter_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    let (mut gateway, gateway_port) = start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    let (status, headers, body) = send_grpc_request(
        &gateway_addr,
        "/grpc-route-miss/my.EchoService/Echo",
        b"",
        &[],
    )
    .await
    .expect("Route-miss request should complete");

    assert_eq!(status, 200, "gRPC route miss should return HTTP 200");
    assert!(body.is_empty(), "gRPC route miss should be trailers-only");
    assert!(
        !headers.contains_key("x-synthetic-policy"),
        "pre-routing route misses have no resolved policy configuration"
    );
    assert_eq!(
        headers.get("grpc-status").map(|s| s.as_str()),
        Some("5"),
        "Missing route should map to grpc-status 5 (NOT_FOUND)"
    );

    let (status2, headers2, body2) = send_grpc_request(
        &gateway_addr,
        "/grpc-method-filter/my.EchoService/Echo",
        b"",
        &[],
    )
    .await
    .expect("Method-filter request should complete");

    assert_eq!(status2, 200, "gRPC method filter should return HTTP 200");
    assert!(
        body2.is_empty(),
        "gRPC method filter rejection should be trailers-only"
    );
    assert_eq!(
        headers2.get("grpc-status").map(|s| s.as_str()),
        Some("12"),
        "Method filter rejection should map to grpc-status 12 (UNIMPLEMENTED)"
    );
    assert!(
        headers2
            .get("grpc-message")
            .is_some_and(|msg| msg.contains("Method Not Allowed")),
        "Method filter rejection should preserve the reject message"
    );
    assert_eq!(
        headers2.get("x-synthetic-policy").map(String::as_str),
        Some("enforced")
    );
    assert_eq!(
        headers2.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    // Trailers-only gRPC carries no DATA frames and gRPC never frames with
    // Content-Length, so the final wire boundary removes the field outright —
    // it neither preserves a policy-authored value nor invents `0`. Assert the
    // absence rather than one sentinel value: `security_headers.set` can no
    // longer author `Content-Length`, so a value-specific check would pass
    // vacuously while a leaked backend length still slipped through.
    assert!(
        !headers2
            .keys()
            .any(|name| name.eq_ignore_ascii_case("content-length")),
        "trailers-only gRPC error must not advertise Content-Length; headers={headers2:?}"
    );
    assert!(!headers2.contains_key("transfer-encoding"));

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_grpc_early_rejects_use_grpc_error_shape PASSED");
}

/// Regression for F15 (PR #1402): a long-lived server-streaming gRPC RPC must
/// HOLD the per-IP in-flight request slot for the FULL streaming-response
/// lifetime, not release it at response-header time.
///
/// The fix attaches the `PerIpRequestGuard` to the streaming `ProxyBody`
/// (`src/proxy/mod.rs`: `body.with_per_ip_request_guard(guard)`), so the slot
/// is occupied until the streaming body finishes. Pre-fix, the guard dropped
/// when the gRPC handler returned at header flush — releasing the slot while
/// the body was still streaming, which let a client EVADE the per-IP limit on
/// long-lived streaming RPCs.
///
/// With the limit at 1 and stream #1 parked mid-response, a SECOND request from
/// the same IP must be rejected with **HTTP 429**. The per-IP reject fires in
/// `proxy::handle_request` BEFORE gRPC dispatch and returns a plain
/// `build_response(StatusCode::TOO_MANY_REQUESTS, ...)` — so the rejection is a
/// real HTTP 429, NOT a `grpc-status` trailer frame.
///
/// Structural inverse of the WebSocket case
/// `test_h3_websocket_releases_per_ip_request_slot_after_200` (WS releases the
/// slot after the 200; gRPC streaming holds it).
#[ignore]
#[tokio::test]
async fn test_grpc_streaming_holds_per_ip_request_slot() {
    // Pre-bind the streaming backend's listener so it owns the socket for its
    // whole lifetime (no free-port→bind race). Read the port before moving the
    // listener into the backend.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind streaming gRPC backend");
    let backend_port = backend_listener
        .local_addr()
        .expect("backend local_addr")
        .port();

    // `release` watch channel: flip to `true` to let a parked streaming
    // response emit its trailers and EOF. Held `false` while we probe the limit.
    let (release_tx, release_rx) = watch::channel(false);
    let backend_handle = start_grpc_streaming_backend(backend_listener, release_rx).await;
    sleep(Duration::from_millis(300)).await;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    // Reuse the standard gRPC config: the `/grpc` route has no plugins and no
    // retries, so it takes the fully-streaming gRPC fast path
    // (`proxy_grpc_request_streaming`) whose response body holds the per-IP
    // guard.
    write_grpc_config(&config_path, backend_port);

    build_gateway().expect("Failed to build gateway");
    // FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP=1: a single in-flight request per
    // IP. FERRUM_POOL_WARMUP_ENABLED=false: warmup must not consume the slot —
    // only the test's own stream should hold it. (Warmup connects to the
    // backend at startup and could otherwise occupy the in-flight accounting.)
    let (mut gateway, gateway_port) = start_gateway_with_retry_extra_env(
        config_path.to_str().unwrap(),
        &[
            ("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP", "1"),
            ("FERRUM_POOL_WARMUP_ENABLED", "false"),
        ],
    )
    .await;

    let gateway_addr = format!("127.0.0.1:{}", gateway_port);

    // Stream #1: open a long-lived server-streaming RPC and keep it OPEN. The
    // backend sends headers + one DATA frame, then stalls — so the gateway's
    // streaming response body (and the per-IP slot bound to it) stays alive.
    let stream1 = open_grpc_stream(&gateway_addr, "/grpc/my.EchoService/ServerStream", b"")
        .await
        .expect("stream #1 should open");
    assert_eq!(
        stream1.status, 200,
        "streaming gRPC RPC should return HTTP 200"
    );
    assert!(
        !stream1.first_frame.is_empty(),
        "the streaming backend's first DATA frame should have arrived (slot now held)"
    );

    // Request #2 from the SAME IP while stream #1 holds the only slot. The
    // per-IP limiter must reject it with a plain HTTP 429 BEFORE gRPC dispatch.
    //
    // The 5s timeout converts the pre-fix regression into a fast, descriptive
    // failure instead of a hang: pre-fix, the slot was released at stream #1's
    // header flush, so request #2 would be ADMITTED — and `send_grpc_request`
    // would then block in `collect()` on the still-stalled streaming backend
    // (no EOF until release), hanging the test. Post-fix, the 429 returns
    // immediately, well inside the timeout.
    let (status2, _headers2, _body2) = tokio::time::timeout(
        Duration::from_secs(5),
        send_grpc_request(&gateway_addr, "/grpc/my.EchoService/Echo", b"", &[]),
    )
    .await
    .expect(
        "request #2 must resolve fast with a 429; a hang here means it was \
         wrongly admitted to the stalled streaming backend (F15 regression)",
    )
    .expect("request #2 should complete (with a 429)");
    assert_eq!(
        status2, 429,
        "a 2nd same-IP request while a streaming RPC holds the slot must be \
         rejected with HTTP 429 (per-IP limit), not admitted — this is the F15 \
         evasion the fix closes"
    );

    // Release the backend (flips the watch to `true`, waking every parked
    // streaming response) and drain stream #1 to completion so the gateway
    // observes EOF and frees the per-IP slot.
    let _ = release_tx.send(true);
    stream1.drain().await;
    // Give the gateway a moment to run the guard's Drop after body completion.
    sleep(Duration::from_millis(300)).await;

    // With the slot freed, a fresh same-IP streaming request must be admitted
    // again (status 200, first frame arrives). The watch is already `true`, so
    // this stream's backend sender releases as soon as it parks — no hang, and
    // no lost-wakeup race.
    let stream3 = open_grpc_stream(&gateway_addr, "/grpc/my.EchoService/ServerStream2", b"")
        .await
        .expect("stream #3 should open once the slot is freed");
    assert_eq!(
        stream3.status, 200,
        "after the streaming RPC finished, the per-IP slot must be free for a \
         new same-IP request"
    );
    stream3.drain().await;

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend_handle.abort();
    println!("test_grpc_streaming_holds_per_ip_request_slot PASSED");
}

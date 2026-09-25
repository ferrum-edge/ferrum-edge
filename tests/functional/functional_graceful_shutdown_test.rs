//! Functional tests for graceful shutdown & connection draining (P0-3).
//!
//! These tests start the real `ferrum-edge` binary in file mode, send SIGTERM,
//! and verify drain semantics per CLAUDE.md "Startup And Shutdown":
//!
//!   * In-flight requests complete within `FERRUM_SHUTDOWN_DRAIN_SECONDS`.
//!   * New TCP connections are refused once the accept loops exit.
//!   * `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` forces immediate exit (no drain wait).
//!   * An HTTP/1.1 response produced during drain carries `Connection: close`.
//!   * An idle keep-alive connection is closed when shutdown begins.
//!   * Drain timeout is respected — the gateway waits out the window, then
//!     exits even though the request did not complete.
//!   * A streaming response body keeps the drain open until it finishes, over
//!     HTTP/1.1 and over HTTP/2 (h2c prior knowledge).
//!
//! Issue #5739: every observation here must be positive evidence. A connected
//! socket that stays silent is not a refused connection, a read that stalls or
//! ends early is not a response, and a wait that times out is not a graceful
//! exit. In-flight requests are held by an explicit backend barrier instead of
//! a sleep that "should" cover the signal. The non-ignored `harness_*` tests at
//! the bottom pin these helpers against fake peers, so an assertion cannot
//! silently become vacuous.
//!
//! The gateway tests are `#[ignore]` — run with:
//!   cargo test --test functional_tests functional_graceful_shutdown -- --include-ignored

#![cfg(unix)]

use crate::common::{GatewayChildGuard, SpawnedGatewayIdentity};
use crate::scaffolding::port_registry::TestSocket;
use crate::scaffolding::ports::{
    REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY, reserve_refused_tcp_port,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, TRANSFER_ENCODING};
use hyper_util::rt::TokioIo;
use std::fmt;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

// ============================================================================
// Held Backend
// ============================================================================

/// Body of a [`HeldResponse::HeadAfterRelease`] response.
const HELD_BODY: &str = "held-ok";
/// First part of a [`HeldResponse::StreamAcrossRelease`] body, sent at once.
const STREAM_FIRST_PART: &str = "stream-part-1;";
/// Rest of a streamed body, sent only after the barrier is released.
const STREAM_SECOND_PART: &str = "stream-part-2";

/// How a [`HeldBackend`] places its response around the release barrier.
#[derive(Clone, Copy)]
enum HeldResponse {
    /// Write nothing until released, then a complete `Content-Length`
    /// response. The gateway can only produce the client-facing response head
    /// after the release.
    HeadAfterRelease,
    /// Write the head and a first chunk at once, then finish the chunked body
    /// only after release, so the response body is open across the barrier.
    StreamAcrossRelease,
}

/// An HTTP/1.1 backend whose responses wait on an explicit barrier.
///
/// Each request is reported on `arrivals` as soon as its head is read. That
/// report, not a sleep, proves a request is in flight through the gateway, and
/// the barrier keeps it in flight until the test calls [`HeldBackend::release`].
struct HeldBackend {
    port: u16,
    arrivals: mpsc::UnboundedReceiver<()>,
    release_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl HeldBackend {
    async fn start(shape: HeldResponse) -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind held backend");
        let port = listener.local_addr().expect("held backend addr").port();
        let (arrival_tx, arrivals) = mpsc::unbounded_channel();
        let (release_tx, release_rx) = watch::channel(false);
        let task = tokio::spawn(serve_held_backend(listener, shape, arrival_tx, release_rx));
        Self {
            port,
            arrivals,
            release_tx,
            task,
        }
    }

    /// Wait until the gateway has forwarded a request to this backend.
    async fn wait_for_arrival(&mut self) {
        match timeout(Duration::from_secs(10), self.arrivals.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => panic!("held backend stopped before a request arrived"),
            Err(_) => panic!("no request reached the held backend within 10s"),
        }
    }

    /// Let every held and future response proceed.
    fn release(&self) {
        let _ = self.release_tx.send_replace(true);
    }
}

impl Drop for HeldBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_held_backend(
    listener: TcpListener,
    shape: HeldResponse,
    arrival_tx: mpsc::UnboundedSender<()>,
    release_rx: watch::Receiver<bool>,
) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let arrival_tx = arrival_tx.clone();
        let mut release_rx = release_rx.clone();
        tokio::spawn(async move {
            if !read_request_head(&mut stream).await {
                return;
            }
            let _ = arrival_tx.send(());
            if matches!(shape, HeldResponse::StreamAcrossRelease) {
                let head = format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
                     Connection: close\r\n\r\n{:x}\r\n{STREAM_FIRST_PART}\r\n",
                    STREAM_FIRST_PART.len()
                );
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
            }
            let released = release_rx.wait_for(|released| *released).await.is_ok();
            if !released {
                return;
            }
            let rest = match shape {
                HeldResponse::HeadAfterRelease => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{HELD_BODY}",
                    HELD_BODY.len()
                ),
                HeldResponse::StreamAcrossRelease => format!(
                    "{:x}\r\n{STREAM_SECOND_PART}\r\n0\r\n\r\n",
                    STREAM_SECOND_PART.len()
                ),
            };
            let _ = stream.write_all(rest.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Read one request head, through its blank line. Returns `false` if the peer
/// closed or failed first, or the head grew past 16 KiB.
async fn read_request_head(stream: &mut TcpStream) -> bool {
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                head.extend_from_slice(&chunk[..n]);
                if head.windows(4).any(|window| window == b"\r\n\r\n") {
                    return true;
                }
                if head.len() > 16 * 1024 {
                    return false;
                }
            }
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

async fn ephemeral_port() -> u16 {
    crate::scaffolding::ports::unbound_port()
        .await
        .expect("lease test port")
}

/// A spawned gateway owned by an RAII guard (issue #4991): a failed assertion
/// or timeout anywhere kills and reaps it. That teardown is cleanup only; it is
/// never evidence of a graceful exit.
struct DrainGateway {
    guard: GatewayChildGuard,
    proxy_port: u16,
    _state_dir: TempDir,
}

impl DrainGateway {
    fn proxy_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.proxy_port))
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.proxy_port)
    }

    async fn connect_h1(&self) -> H1Connection {
        H1Connection::connect(self.proxy_addr(), GATEWAY_READ_BOUNDS).await
    }

    /// Deliver SIGTERM and fail unless the kernel accepted it for this child.
    /// A signal that never reached the gateway would make every drain
    /// assertion after it meaningless.
    fn send_sigterm(&self) {
        let pid = self
            .guard
            .id()
            .expect("gateway child was reaped before SIGTERM");
        let pid = libc::pid_t::try_from(pid).expect("pid fits in pid_t");
        // SAFETY: kill(2) only reads its two integer arguments.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            panic!("SIGTERM delivery to gateway pid {pid} failed: {error}");
        }
    }

    async fn expect_proxy_port_closed(&self, context: &str) {
        expect_listener_closed(self.proxy_addr(), HTTP_PROBE, context).await;
    }

    /// Assert that the gateway exits on its own, with status 0, within `bound`.
    async fn expect_clean_exit(&mut self, bound: Duration, context: &str) {
        let result = wait_for_clean_exit(self.guard.child_mut(), bound).await;
        if let Err(failure) = result {
            panic!(
                "{context}: gateway did not exit cleanly within {bound:?}: {failure}\n{}",
                self.guard.startup_diagnostics()
            );
        }
    }
}

/// Spawn the gateway in file mode. Pool warmup is off so a startup `HEAD /`
/// cannot count as a held-backend arrival, and the managed-TLS store stays in
/// the attempt's temp dir instead of the checkout (issue #5706).
fn spawn_gateway(
    config_path: &Path,
    state_dir: &Path,
    http_port: u16,
    admin_port: u16,
    drain_seconds: u64,
) -> std::io::Result<GatewayChildGuard> {
    let mut cmd = Command::new(gateway_binary_path());
    cmd.arg("run");
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_PROXY_HTTPS_PORT", "0")
        .env("FERRUM_ADMIN_HTTPS_PORT", "0")
        .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", drain_seconds.to_string())
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_TLS_MANAGED_STORE_PATH", state_dir.join("managed-tls"))
        .env("FERRUM_LOG_LEVEL", "info")
        .stdin(std::process::Stdio::null());
    // Deliberately no `configure_coverage_gateway_command`: it pins the drain
    // to 0, and the drain window is what these tests measure.
    GatewayChildGuard::spawn_with_identity(
        &mut cmd,
        admin_port,
        SpawnedGatewayIdentity::mint("graceful-shutdown"),
    )
}

/// Start the gateway, retrying with fresh ports and a fresh state dir when a
/// nonparticipating process wins a port race. `write_config` writes the
/// attempt's config into the attempt's directory.
async fn start_gateway_with_retry<F>(write_config: F, drain_seconds: u64) -> DrainGateway
where
    F: Fn(&Path) -> PathBuf,
{
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;
        let state_dir = TempDir::new().expect("gateway state dir");
        let config_path = write_config(state_dir.path());
        let mut guard = spawn_gateway(
            &config_path,
            state_dir.path(),
            proxy_port,
            admin_port,
            drain_seconds,
        )
        .expect("spawn ferrum-edge");
        match guard.wait_for_owned_ready(Duration::from_secs(15)).await {
            Ok(()) => {
                return DrainGateway {
                    guard,
                    proxy_port,
                    _state_dir: state_dir,
                };
            }
            Err(error) => {
                eprintln!(
                    "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed \
                     (proxy_port={proxy_port}, admin_port={admin_port}): {error}\n{}",
                    guard.startup_diagnostics()
                );
                guard.shutdown();
            }
        }
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {MAX_ATTEMPTS} attempts (drain_seconds={drain_seconds})");
}

async fn start_http_gateway(backend_port: u16, drain_seconds: u64) -> DrainGateway {
    start_gateway_with_retry(|dir| write_http_config(dir, backend_port), drain_seconds).await
}

/// Why a child was not shown to exit cleanly.
enum ExitFailure {
    /// Still running at the deadline.
    TimedOut,
    /// `try_wait` itself failed.
    WaitFailed(std::io::Error),
    /// Exited, but not with status 0.
    Unsuccessful(ExitStatus),
}

impl fmt::Display for ExitFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => f.write_str("still running at the deadline"),
            Self::WaitFailed(error) => write!(f, "try_wait failed: {error}"),
            Self::Unsuccessful(status) => write!(f, "exited unsuccessfully: {status}"),
        }
    }
}

/// Poll `child` until it exits or `bound` elapses. Only an exit with status 0
/// inside the bound succeeds; a timeout is a failure, never a pass.
async fn wait_for_clean_exit(child: &mut Child, bound: Duration) -> Result<(), ExitFailure> {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(ExitFailure::Unsuccessful(status)),
            Ok(None) if Instant::now() >= deadline => return Err(ExitFailure::TimedOut),
            Ok(None) => sleep(Duration::from_millis(25)).await,
            Err(error) => return Err(ExitFailure::WaitFailed(error)),
        }
    }
}

fn write_config_file(dir: &Path, content: &str) -> PathBuf {
    let config_path = dir.join("config.yaml");
    let mut file = std::fs::File::create(&config_path).expect("create config");
    file.write_all(content.as_bytes()).expect("write config");
    config_path
}

/// File-mode config with one HTTP proxy at `/slow` pointed at `backend_port`.
fn write_http_config(dir: &Path, backend_port: u16) -> PathBuf {
    write_config_file(
        dir,
        &format!(
            r#"
version: "1"
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
        ),
    )
}

// ============================================================================
// Listener Closure Probe
// ============================================================================

/// Probe bytes for an HTTP listener; a live gateway answers them.
const HTTP_PROBE: &[u8] = b"GET / HTTP/1.1\r\nHost: probe\r\n\r\n";
/// Probe bytes for a TCP stream listener; the echo backend answers them.
const TCP_PROBE: &[u8] = b"x";
/// Bound on each connect and read. Long enough that a loaded CI gateway
/// answering a probe is not mistaken for a silent socket.
const PROBE_STEP_BOUND: Duration = Duration::from_secs(2);
/// Deadline for a listener to show closure after SIGTERM.
const LISTENER_CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// Positive evidence that a listener stopped accepting.
enum ListenerClosed {
    /// The kernel refused the connect: nothing listens on the port.
    Refused,
    /// The connect completed, but the peer closed or reset it without
    /// answering: a backlog connection of a listener that has since closed.
    ClosedWithoutAnswer,
}

/// Why a listener was not shown to be closed.
enum ListenerStillOpen {
    /// `connect()` neither completed nor failed within the step bound.
    ConnectStalled,
    /// The connect or the probe read failed with something other than a
    /// refusal, a reset, or a close.
    Failed(ErrorKind),
    /// The connect completed and the peer held the socket open without
    /// answering or closing it. A hung listener is not a closed one.
    AcceptedButSilent,
    /// The peer kept answering probes until the deadline.
    StillServing,
}

impl fmt::Display for ListenerStillOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectStalled => f.write_str("connect() neither completed nor failed"),
            Self::Failed(kind) => write!(f, "probe failed without refusal or close: {kind:?}"),
            Self::AcceptedButSilent => {
                f.write_str("accepted the connection but neither answered nor closed it")
            }
            Self::StillServing => f.write_str("kept answering probes until the deadline"),
        }
    }
}

/// One probe's result: closure evidence, or a peer that is still serving.
enum ProbeStep {
    Closed(ListenerClosed),
    Answered,
}

async fn probe_listener_once(
    addr: SocketAddr,
    probe: &[u8],
) -> Result<ProbeStep, ListenerStillOpen> {
    let mut stream = match timeout(PROBE_STEP_BOUND, TcpStream::connect(addr)).await {
        Err(_) => return Err(ListenerStillOpen::ConnectStalled),
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
            return Ok(ProbeStep::Closed(ListenerClosed::Refused));
        }
        Ok(Err(error)) => return Err(ListenerStillOpen::Failed(error.kind())),
        Ok(Ok(stream)) => stream,
    };
    // A reset peer can fail this write; the read below observes the same
    // reset, so the write result adds no evidence either way.
    let _ = stream.write_all(probe).await;
    let mut buf = [0u8; 64];
    match timeout(PROBE_STEP_BOUND, stream.read(&mut buf)).await {
        Err(_) => Err(ListenerStillOpen::AcceptedButSilent),
        Ok(Ok(0)) => Ok(ProbeStep::Closed(ListenerClosed::ClosedWithoutAnswer)),
        Ok(Ok(_)) => Ok(ProbeStep::Answered),
        Ok(Err(error)) if is_peer_close(error.kind()) => {
            Ok(ProbeStep::Closed(ListenerClosed::ClosedWithoutAnswer))
        }
        Ok(Err(error)) => Err(ListenerStillOpen::Failed(error.kind())),
    }
}

fn is_peer_close(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

/// Probe `addr` until it shows closure evidence or `deadline` elapses. A peer
/// that answers is probed again (its accept loop may not have observed the
/// shutdown yet); every other outcome is final.
async fn wait_for_listener_closed(
    addr: SocketAddr,
    probe: &[u8],
    deadline: Duration,
) -> Result<ListenerClosed, ListenerStillOpen> {
    let start = Instant::now();
    loop {
        match probe_listener_once(addr, probe).await? {
            ProbeStep::Closed(closed) => return Ok(closed),
            ProbeStep::Answered if start.elapsed() >= deadline => {
                return Err(ListenerStillOpen::StillServing);
            }
            ProbeStep::Answered => sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn expect_listener_closed(addr: SocketAddr, probe: &[u8], context: &str) {
    if let Err(failure) = wait_for_listener_closed(addr, probe, LISTENER_CLOSE_DEADLINE).await {
        panic!("{context}: listener at {addr} was not shown closed: {failure}");
    }
}

// ============================================================================
// Typed HTTP/1.1 Response Reader
// ============================================================================

/// Per-phase bounds for [`read_h1_response`].
#[derive(Clone, Copy)]
struct ReadBounds {
    /// Until the complete response head arrives.
    head: Duration,
    /// Between consecutive body frames.
    body: Duration,
}

/// Bounds for responses through the gateway; `head` covers the longest
/// barrier hold in these tests.
const GATEWAY_READ_BOUNDS: ReadBounds = ReadBounds {
    head: Duration::from_secs(20),
    body: Duration::from_secs(10),
};

/// How long [`H1Connection::wait_for_peer_close`] waits.
const PEER_CLOSE_BOUND: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum ReadPhase {
    Head,
    Body,
}

/// A response whose declared framing was fully honoured.
struct CompleteResponse {
    status: u16,
    /// A `Connection` header carried the `close` token.
    connection_close: bool,
    body: Vec<u8>,
}

/// Every way reading one HTTP/1.1 response can end (issue #5739). Only
/// [`H1Read::Complete`] is evidence of a response; each failure keeps its own
/// variant so a stall or a truncation can never pass as a clean close.
enum H1Read {
    Complete(CompleteResponse),
    /// The peer closed before a complete response head arrived.
    ClosedBeforeResponse,
    /// Nothing more arrived within the phase bound while the socket stayed
    /// open.
    Stalled(ReadPhase),
    /// The response head is not valid HTTP/1.1, for example a malformed
    /// `Content-Length`.
    Malformed(String),
    /// Neither `Content-Length` nor chunked framing: the body could only end at
    /// a socket close, which cannot be told apart from truncation.
    UnsupportedFraming,
    /// The body ended before its declared framing completed.
    TruncatedBody { received: usize, error: String },
    /// Any other transport failure before the response head.
    Transport(String),
}

impl fmt::Display for H1Read {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(response) => write!(
                f,
                "complete response (status {}, connection_close={}, {} body bytes)",
                response.status,
                response.connection_close,
                response.body.len()
            ),
            Self::ClosedBeforeResponse => f.write_str("closed before the response head"),
            Self::Stalled(ReadPhase::Head) => f.write_str("stalled before the response head"),
            Self::Stalled(ReadPhase::Body) => f.write_str("stalled inside the response body"),
            Self::Malformed(error) => write!(f, "malformed response head: {error}"),
            Self::UnsupportedFraming => f.write_str("body delimited only by connection close"),
            Self::TruncatedBody { received, error } => {
                write!(f, "body truncated after {received} bytes: {error}")
            }
            Self::Transport(error) => write!(f, "transport failure: {error}"),
        }
    }
}

fn expect_complete(read: H1Read, context: &str) -> CompleteResponse {
    match read {
        H1Read::Complete(response) => response,
        other => panic!("{context}: expected a complete HTTP/1.1 response, got: {other}"),
    }
}

/// Join a response-read task. Every read phase is bounded, so this returns.
async fn finish(task: JoinHandle<H1Read>) -> H1Read {
    task.await.expect("HTTP/1.1 response read task panicked")
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

fn classify_head_error(error: &hyper::Error) -> H1Read {
    if error.is_parse() {
        H1Read::Malformed(error.to_string())
    } else if error.is_incomplete_message() || error.is_canceled() || error.is_closed() {
        H1Read::ClosedBeforeResponse
    } else {
        H1Read::Transport(error.to_string())
    }
}

/// Classify how one HTTP/1.1 response ends, using hyper's client parser
/// rather than a permissive hand-rolled one. Hyper verifies that
/// `Content-Length` and chunked bodies are complete; any other ending is
/// reported as its own variant, never collapsed into "closed".
async fn read_h1_response<F>(response: F, bounds: ReadBounds) -> H1Read
where
    F: Future<Output = hyper::Result<hyper::Response<hyper::body::Incoming>>>,
{
    let response = match timeout(bounds.head, response).await {
        Err(_) => return H1Read::Stalled(ReadPhase::Head),
        Ok(Err(error)) => return classify_head_error(&error),
        Ok(Ok(response)) => response,
    };
    let status = response.status().as_u16();
    let headers = response.headers();
    let chunked = header_has_token(headers, TRANSFER_ENCODING, "chunked");
    if !chunked && !headers.contains_key(CONTENT_LENGTH) {
        return H1Read::UnsupportedFraming;
    }
    let connection_close = header_has_token(headers, CONNECTION, "close");
    let mut incoming = response.into_body();
    let mut body = Vec::new();
    loop {
        match timeout(bounds.body, incoming.frame()).await {
            Err(_) => return H1Read::Stalled(ReadPhase::Body),
            Ok(None) => break,
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    body.extend_from_slice(&data);
                }
            }
            Ok(Some(Err(error))) => {
                return H1Read::TruncatedBody {
                    received: body.len(),
                    error: error.to_string(),
                };
            }
        }
    }
    H1Read::Complete(CompleteResponse {
        status,
        connection_close,
        body,
    })
}

/// One client HTTP/1.1 connection, driven by hyper. Responses are read through
/// [`read_h1_response`].
struct H1Connection {
    sender: http1::SendRequest<Empty<Bytes>>,
    driver: JoinHandle<hyper::Result<()>>,
    bounds: ReadBounds,
}

impl H1Connection {
    async fn connect(addr: SocketAddr, bounds: ReadBounds) -> Self {
        let stream = TcpStream::connect(addr)
            .await
            .expect("connect HTTP/1.1 client");
        let _ = stream.set_nodelay(true);
        let (sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .expect("HTTP/1.1 client handshake");
        Self {
            sender,
            driver: tokio::spawn(connection),
            bounds,
        }
    }

    /// Send `GET path` and read its response on a task, so the test can act
    /// (signal, release) before awaiting the result.
    async fn start_get(&mut self, path: &str) -> JoinHandle<H1Read> {
        if let Err(error) = self.sender.ready().await {
            let read = classify_head_error(&error);
            return tokio::spawn(async move { read });
        }
        let request = hyper::Request::get(path)
            .header(HOST, "127.0.0.1")
            .body(Empty::new())
            .expect("build HTTP/1.1 request");
        let response = self.sender.send_request(request);
        tokio::spawn(read_h1_response(response, self.bounds))
    }

    /// Wait for the peer to close this connection. The request sender stays
    /// alive meanwhile: dropping it would let hyper close the connection
    /// itself, which proves nothing about the peer.
    async fn wait_for_peer_close(&mut self) -> Result<(), String> {
        match timeout(PEER_CLOSE_BOUND, &mut self.driver).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(format!("client connection task panicked: {error}")),
            Err(_) => Err(format!("still open {PEER_CLOSE_BOUND:?} after shutdown")),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

/// Case 1: A request proven in flight at SIGTERM (it reached the backend and is
/// held there) completes with its full body once drain has begun, and the
/// gateway then exits cleanly. Uses a pooled reqwest client, as real callers
/// do.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_inflight_request_completes_during_drain() {
    let mut backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    let mut gateway = start_http_gateway(backend.port, 10).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build client");
    let url = gateway.url("/slow");
    let inflight = tokio::spawn(async move {
        let response = client.get(&url).send().await?;
        let status = response.status();
        Ok::<_, reqwest::Error>((status, response.bytes().await?))
    });
    backend.wait_for_arrival().await;

    gateway.send_sigterm();
    // Drain has provably begun once the accept loop is gone; only then may the
    // held response proceed.
    gateway.expect_proxy_port_closed("after SIGTERM").await;
    backend.release();

    let (status, body) = match timeout(Duration::from_secs(10), inflight).await {
        Ok(Ok(Ok(outcome))) => outcome,
        Ok(Ok(Err(error))) => panic!("in-flight request failed during drain: {error}"),
        Ok(Err(error)) => panic!("in-flight request task panicked: {error}"),
        Err(_) => panic!("in-flight request did not finish within 10s of its release"),
    };
    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(&body[..], HELD_BODY.as_bytes());

    gateway
        .expect_clean_exit(Duration::from_secs(6), "after the in-flight drain")
        .await;
}

/// Case 2: Once SIGTERM fires and the accept loops close, new TCP connections
/// to the proxy port are refused (or closed unanswered), never accepted and
/// left silent, for as long as a held request keeps the gateway draining. The
/// request then completes and the gateway exits cleanly.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_new_connections_refused_during_drain() {
    let mut backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    let mut gateway = start_http_gateway(backend.port, 10).await;

    let mut connection = gateway.connect_h1().await;
    let inflight = connection.start_get("/slow").await;
    backend.wait_for_arrival().await;

    gateway.send_sigterm();
    gateway.expect_proxy_port_closed("after SIGTERM").await;
    assert!(
        !gateway.guard.has_exited(),
        "gateway exited while a request was still held in flight"
    );
    // Closure must hold for the whole drain, not be a transient blip.
    gateway.expect_proxy_port_closed("while draining").await;

    backend.release();
    let response = expect_complete(finish(inflight).await, "in-flight request after refusal");
    assert_eq!(response.status, 200, "in-flight request after refusal");
    assert_eq!(response.body, HELD_BODY.as_bytes());

    gateway
        .expect_clean_exit(Duration::from_secs(6), "after refusing new connections")
        .await;
}

/// Case 3: `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` disables the drain wait. The
/// process exits cleanly and promptly with a request still held, and that
/// request is cut off rather than left open.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_zero_exits_immediately() {
    let mut backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    let mut gateway = start_http_gateway(backend.port, 0).await;

    let mut connection = gateway.connect_h1().await;
    let inflight = connection.start_get("/slow").await;
    backend.wait_for_arrival().await;

    gateway.send_sigterm();
    gateway
        .expect_clean_exit(Duration::from_secs(2), "with drain=0 and a held request")
        .await;

    // The backend was never released, so no response can exist. The exit must
    // have torn the client connection down, not left it open and silent.
    let read = finish(inflight).await;
    assert!(
        matches!(read, H1Read::ClosedBeforeResponse | H1Read::Transport(_)),
        "held request after a drain=0 exit should be cut off, got: {read}"
    );
}

/// Case 4: An HTTP/1.1 response the gateway produces during drain carries
/// `Connection: close` together with its complete body.
///
/// The held backend proves the request is in flight before SIGTERM, and it
/// releases the response only after the proxy listener is shown closed, so the
/// response head is written while draining. An idle socket that shutdown
/// closes fails this case because it has no response; idle closure is covered
/// by `test_idle_keepalive_connection_closed_on_drain`.
///
/// On this path the close token has two producers: the drain hint in the proxy
/// response builder, and hyper's keep-alive disable from the per-connection
/// `graceful_shutdown()`. This case pins the wire contract that either one
/// satisfies; it cannot tell them apart.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_sets_connection_close_header() {
    let mut backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    let mut gateway = start_http_gateway(backend.port, 10).await;

    let mut connection = gateway.connect_h1().await;
    let inflight = connection.start_get("/slow").await;
    backend.wait_for_arrival().await;

    gateway.send_sigterm();
    gateway.expect_proxy_port_closed("after SIGTERM").await;
    backend.release();

    let response = expect_complete(finish(inflight).await, "response released during drain");
    assert_eq!(response.status, 200, "response released during drain");
    assert_eq!(response.body, HELD_BODY.as_bytes());
    assert!(
        response.connection_close,
        "a response produced during drain must carry `Connection: close`"
    );

    gateway
        .expect_clean_exit(Duration::from_secs(6), "after the close-marked response")
        .await;
}

/// Case 5: Drain timeout is respected. With `FERRUM_SHUTDOWN_DRAIN_SECONDS=2`
/// and a request held forever, the gateway waits out the drain window, then
/// force-closes the request and exits cleanly.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_drain_timeout_respected() {
    let mut backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    let mut gateway = start_http_gateway(backend.port, 2).await;

    let mut connection = gateway.connect_h1().await;
    let inflight = connection.start_get("/slow").await;
    backend.wait_for_arrival().await;

    let signalled = Instant::now();
    gateway.send_sigterm();
    // The drain wait is 2s and background cleanup normally adds little; 4s
    // covers CI jitter.
    gateway
        .expect_clean_exit(Duration::from_secs(4), "after the drain timeout")
        .await;
    let elapsed = signalled.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1_500),
        "gateway exited {elapsed:?} after SIGTERM, before its 2s drain window: the held \
         request was not waited for"
    );

    let read = finish(inflight).await;
    assert!(
        matches!(read, H1Read::ClosedBeforeResponse | H1Read::Transport(_)),
        "held request after the drain timeout should be cut off, got: {read}"
    );
}

/// Case 6: An idle keep-alive HTTP/1.1 connection is closed by the gateway when
/// shutdown begins, and the gateway then exits cleanly. This is the
/// idle-connection contract, kept apart from the in-flight `Connection: close`
/// case above.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_idle_keepalive_connection_closed_on_drain() {
    let backend = HeldBackend::start(HeldResponse::HeadAfterRelease).await;
    backend.release();
    let mut gateway = start_http_gateway(backend.port, 10).await;

    let mut connection = gateway.connect_h1().await;
    let first = expect_complete(
        finish(connection.start_get("/slow").await).await,
        "keep-alive request before SIGTERM",
    );
    assert_eq!(first.status, 200, "keep-alive request before SIGTERM");
    assert!(
        !first.connection_close,
        "the pre-shutdown response closed the connection, so this case cannot observe an \
         idle close"
    );

    gateway.send_sigterm();
    if let Err(failure) = connection.wait_for_peer_close().await {
        panic!("idle keep-alive connection after SIGTERM: {failure}");
    }
    gateway
        .expect_clean_exit(Duration::from_secs(6), "after the idle close")
        .await;
}

/// How long a held stream is observed after the listener closes. A gateway
/// that stopped counting the open body would finish its drain and exit well
/// inside this window.
const HELD_STREAM_OBSERVATION: Duration = Duration::from_secs(1);

/// Case 7: A streaming HTTP/1.1 response body that is open when SIGTERM
/// arrives keeps the drain open until it finishes.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_h1_streaming_response_survives_drain() {
    assert_streaming_response_survives_drain(reqwest::Version::HTTP_11).await;
}

/// Case 8: The same over HTTP/2 (h2c prior knowledge), whose connection gets a
/// GOAWAY on shutdown instead of `Connection: close`. This is the real-process
/// H2 drain regression; `tests/integration/graceful_shutdown_tests.rs` covers
/// the in-process GOAWAY.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_h2_streaming_response_survives_drain() {
    assert_streaming_response_survives_drain(reqwest::Version::HTTP_2).await;
}

/// The gateway stays up while the body is held, relays the rest of the body
/// after release, and exits cleanly only then.
async fn assert_streaming_response_survives_drain(version: reqwest::Version) {
    let mut backend = HeldBackend::start(HeldResponse::StreamAcrossRelease).await;
    let mut gateway = start_http_gateway(backend.port, 10).await;

    let builder = reqwest::Client::builder().timeout(Duration::from_secs(30));
    let builder = if version == reqwest::Version::HTTP_2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    };
    let client = builder.build().expect("build streaming client");
    let request = client.get(gateway.url("/slow")).send();
    let mut response = timeout(Duration::from_secs(10), request)
        .await
        .expect("streaming response head did not arrive within 10s")
        .expect("streaming request failed before its head");
    backend.wait_for_arrival().await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.version(), version, "negotiated protocol");

    // The first part proves the body is open and flowing before shutdown.
    let mut body = Vec::new();
    while body.len() < STREAM_FIRST_PART.len() {
        match next_chunk(&mut response).await {
            Some(chunk) => body.extend_from_slice(&chunk),
            None => panic!("stream ended before its first part"),
        }
    }
    assert_eq!(body, STREAM_FIRST_PART.as_bytes());

    gateway.send_sigterm();
    gateway.expect_proxy_port_closed("after SIGTERM").await;
    sleep(HELD_STREAM_OBSERVATION).await;
    assert!(
        !gateway.guard.has_exited(),
        "gateway exited while a streaming response body was still open"
    );

    backend.release();
    while let Some(chunk) = next_chunk(&mut response).await {
        body.extend_from_slice(&chunk);
    }
    let expected = format!("{STREAM_FIRST_PART}{STREAM_SECOND_PART}");
    assert_eq!(body, expected.as_bytes(), "streamed body across the drain");

    gateway
        .expect_clean_exit(Duration::from_secs(6), "after the streamed body finished")
        .await;
}

/// Next body chunk. A transport error or a 10s stall fails the test.
async fn next_chunk(response: &mut reqwest::Response) -> Option<Bytes> {
    match timeout(Duration::from_secs(10), response.chunk()).await {
        Ok(Ok(chunk)) => chunk,
        Ok(Err(error)) => panic!("streaming body failed: {error}"),
        Err(_) => panic!("streaming body stalled for 10s"),
    }
}

// ============================================================================
// TCP/UDP stream-listener SIGTERM tests
// ============================================================================
//
// Regression coverage for the bug where TCP/UDP stream listeners ignored the
// gateway-wide SIGTERM and kept accepting connections until the runtime was
// dropped. The fix wires `StreamListenerManager` to the same `watch::Sender`
// `main.rs` uses for HTTP listeners and additionally calls `shutdown_all()`
// before `wait_for_drain` so the per-listener watch channels also fire.
//
// Each test starts the real binary in file mode with a TCP or UDP stream
// proxy, sends SIGTERM, and asserts that:
//   * The proxy port stops accepting connections / datagrams reasonably soon.
//   * The gateway process exits cleanly within `FERRUM_SHUTDOWN_DRAIN_SECONDS`
//     plus a small overhead.

/// Spawn a basic TCP echo backend on a pre-bound listener.
async fn start_tcp_echo_backend_on(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
                Err(_) => return,
            }
        }
    })
}

/// Spawn a basic UDP echo backend on a pre-bound socket.
async fn start_udp_echo_backend_on(socket: tokio::net::UdpSocket) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let _ = socket.send_to(&buf[..n], addr).await;
                }
                Err(_) => return,
            }
        }
    })
}

/// File-mode config with one TCP stream proxy.
fn write_tcp_stream_config(dir: &Path, tcp_listen_port: u16, tcp_backend_port: u16) -> PathBuf {
    write_config_file(
        dir,
        &format!(
            r#"
version: "1"
proxies:
  - id: "tcp-echo"
    listen_port: {tcp_listen_port}
    backend_scheme: tcp
    backend_host: "127.0.0.1"
    backend_port: {tcp_backend_port}

consumers: []
plugin_configs: []
"#
        ),
    )
}

/// Same as [`write_tcp_stream_config`] but for a UDP stream proxy.
fn write_udp_stream_config(dir: &Path, udp_listen_port: u16, udp_backend_port: u16) -> PathBuf {
    write_config_file(
        dir,
        &format!(
            r#"
version: "1"
proxies:
  - id: "udp-echo"
    listen_port: {udp_listen_port}
    backend_scheme: udp
    backend_host: "127.0.0.1"
    backend_port: {udp_backend_port}

consumers: []
plugin_configs: []
"#
        ),
    )
}

/// Verify TCP stream listener stops accepting after SIGTERM and the gateway
/// exits cleanly within the drain window.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_tcp_stream_listener_stops_on_sigterm() {
    // Backend echo on its own ephemeral port.
    let backend_listener = TcpListener::bind_test("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = start_tcp_echo_backend_on(backend_listener).await;

    // Pre-allocate the stream listener port.
    let stream_port = ephemeral_port().await;
    let mut gateway = start_gateway_with_retry(
        |dir| write_tcp_stream_config(dir, stream_port, backend_port),
        5,
    )
    .await;

    // Give the stream listener a moment to bind.
    sleep(Duration::from_millis(500)).await;

    // Open a long-lived TCP connection through the stream proxy and exchange
    // a frame so we know the relay is up.
    let addr = SocketAddr::from(([127, 0, 0, 1], stream_port));
    let mut conn = TcpStream::connect(addr)
        .await
        .expect("connect to stream listener");
    conn.write_all(b"hello").await.expect("write first frame");
    let mut buf = [0u8; 5];
    let n = timeout(Duration::from_secs(5), conn.read_exact(&mut buf))
        .await
        .expect("read first echo (timeout)")
        .expect("read first echo");
    assert_eq!(n, 5);
    assert_eq!(&buf, b"hello");

    gateway.send_sigterm();

    // New TCP connections to the stream port must be refused or closed
    // unanswered: the accept loop should have exited. An accepted connection
    // that stays silent fails.
    expect_listener_closed(addr, TCP_PROBE, "TCP stream listener after SIGTERM").await;

    // The gateway must exit cleanly within the drain window plus a small
    // overhead (background task drain caps at 5s). Drain is 5s, total budget
    // 12s.
    gateway
        .expect_clean_exit(Duration::from_secs(12), "after closing the TCP listener")
        .await;

    drop(conn);
    backend_task.abort();
}

/// Verify UDP stream listener stops receiving after SIGTERM and the gateway
/// exits cleanly within the drain window.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_udp_stream_listener_stops_on_sigterm() {
    // Backend echo on its own ephemeral UDP port.
    let backend_socket = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let backend_port = backend_socket.local_addr().unwrap().port();
    let backend_task = start_udp_echo_backend_on(backend_socket).await;

    // Pre-allocate the stream listener port. The OS treats TCP/UDP ports
    // independently, so the leased number serves the UDP listener.
    let stream_port = ephemeral_port().await;
    let mut gateway = start_gateway_with_retry(
        |dir| write_udp_stream_config(dir, stream_port, backend_port),
        5,
    )
    .await;

    // Give the listener a moment to bind.
    sleep(Duration::from_millis(500)).await;

    // Send a datagram and confirm the relay round-trips it.
    let client = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    client
        .connect(format!("127.0.0.1:{}", stream_port))
        .await
        .expect("client connect");
    client.send(b"ping").await.expect("send ping");
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("recv echo (timeout)")
        .expect("recv echo");
    assert_eq!(&buf[..n], b"ping");

    gateway.send_sigterm();

    // After shutdown, the listener should not be bound to the stream port
    // anymore. We confirm by binding a fresh UDP socket on that port — it
    // must succeed.
    let mut released = false;
    for _ in 0..50 {
        match tokio::net::UdpSocket::bind_test(format!("127.0.0.1:{}", stream_port)).await {
            Ok(_) => {
                released = true;
                break;
            }
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(
        released,
        "UDP stream listener continued holding port {} after SIGTERM",
        stream_port
    );

    // The gateway must exit cleanly within the drain window + overhead.
    gateway
        .expect_clean_exit(Duration::from_secs(12), "after releasing the UDP port")
        .await;

    backend_task.abort();
}

// ============================================================================
// Harness Negative Controls (issue #5739)
// ============================================================================
//
// Not `#[ignore]`: these need no gateway binary and run in every CI shard that
// selects this module. Each pins one helper against a fake peer, so a helper
// that silently accepts a stall, a truncation, or a missing exit cannot keep
// the gateway cases above green.

/// Bounds for scripted peers: short, so stall cases finish quickly.
const HARNESS_READ_BOUNDS: ReadBounds = ReadBounds {
    head: Duration::from_millis(500),
    body: Duration::from_millis(500),
};

#[derive(Clone, Copy)]
enum FakePeer {
    /// Accept and hold every connection open without reading, answering, or
    /// closing it: a listener that is up but hung.
    Silent,
    /// Answer every probe.
    Answering,
    /// Accept, then close at once without answering.
    CloseOnAccept,
}

async fn spawn_fake_peer(kind: FakePeer) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind fake peer");
    let addr = listener.local_addr().expect("fake peer addr");
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            match kind {
                FakePeer::Silent => held.push(stream),
                FakePeer::Answering => {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 64];
                        if matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {
                            let _ = stream.write_all(b"answer").await;
                        }
                    });
                }
                FakePeer::CloseOnAccept => drop(stream),
            }
        }
    });
    (addr, task)
}

#[tokio::test]
async fn harness_listener_probe_fails_on_accepted_silent_peer() {
    let (addr, peer) = spawn_fake_peer(FakePeer::Silent).await;
    let result = wait_for_listener_closed(addr, HTTP_PROBE, LISTENER_CLOSE_DEADLINE).await;
    peer.abort();
    assert!(
        matches!(result, Err(ListenerStillOpen::AcceptedButSilent)),
        "a peer that accepts, then neither answers nor closes, must fail the closure check"
    );
}

#[tokio::test]
async fn harness_listener_probe_fails_on_peer_that_keeps_answering() {
    let (addr, peer) = spawn_fake_peer(FakePeer::Answering).await;
    let result = wait_for_listener_closed(addr, TCP_PROBE, Duration::from_millis(500)).await;
    peer.abort();
    assert!(
        matches!(result, Err(ListenerStillOpen::StillServing)),
        "a peer that keeps answering must fail the closure check at the deadline"
    );
}

#[tokio::test]
async fn harness_listener_probe_accepts_close_without_answer() {
    let (addr, peer) = spawn_fake_peer(FakePeer::CloseOnAccept).await;
    let result = wait_for_listener_closed(addr, HTTP_PROBE, LISTENER_CLOSE_DEADLINE).await;
    peer.abort();
    assert!(
        matches!(result, Ok(ListenerClosed::ClosedWithoutAnswer)),
        "a peer that closes without answering is closure evidence"
    );
}

#[tokio::test]
async fn harness_listener_probe_accepts_kernel_refusal() {
    if !REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY {
        eprintln!("skipping: unlistened ports do not refuse on this host");
        return;
    }
    let refused = reserve_refused_tcp_port().expect("reserve refused port");
    let addr = refused.local_addr();
    let result = wait_for_listener_closed(addr, HTTP_PROBE, LISTENER_CLOSE_DEADLINE).await;
    assert!(
        matches!(result, Ok(ListenerClosed::Refused)),
        "a refused connect is closure evidence"
    );
}

/// Serve `reply` to one request, then close the socket or hold it open and
/// silent, and return how [`read_h1_response`] classified the exchange.
async fn read_scripted_reply(reply: &'static [u8], then_close: bool) -> H1Read {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind scripted peer");
    let addr = listener.local_addr().expect("scripted peer addr");
    let peer = tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if !read_request_head(&mut stream).await || stream.write_all(reply).await.is_err() {
            return;
        }
        if then_close {
            let _ = stream.shutdown().await;
        } else {
            // Hold the socket open and silent until the test aborts this task.
            std::future::pending::<()>().await;
        }
    });
    let mut connection = H1Connection::connect(addr, HARNESS_READ_BOUNDS).await;
    let read = finish(connection.start_get("/scripted").await).await;
    peer.abort();
    read
}

#[tokio::test]
async fn harness_h1_reader_accepts_complete_framed_responses() {
    let read = read_scripted_reply(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        true,
    )
    .await;
    let response = expect_complete(read, "complete Content-Length response");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert!(response.connection_close, "`Connection: close` expected");

    // Chunked and kept open: completion comes from the framing, not a close.
    let read = read_scripted_reply(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        false,
    )
    .await;
    let response = expect_complete(read, "complete chunked response");
    assert_eq!(response.body, b"hello");
    assert!(!response.connection_close, "no close token was sent");
}

#[tokio::test]
async fn harness_h1_reader_rejects_truncated_stalled_and_malformed_responses() {
    type Case = (&'static str, &'static [u8], bool, fn(&H1Read) -> bool);
    let cases: [Case; 8] = [
        (
            "Content-Length body cut short by a close",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel",
            true,
            |read| matches!(read, H1Read::TruncatedBody { .. }),
        ),
        (
            "chunked body cut short by a close",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel",
            true,
            |read| matches!(read, H1Read::TruncatedBody { .. }),
        ),
        (
            "Content-Length body that stalls with the socket open",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel",
            false,
            |read| matches!(read, H1Read::Stalled(ReadPhase::Body)),
        ),
        (
            "no response and the socket held open",
            b"",
            false,
            |read| matches!(read, H1Read::Stalled(ReadPhase::Head)),
        ),
        (
            "partial head and the socket held open",
            b"HTTP/1.1 200 OK\r\nContent-Le",
            false,
            |read| matches!(read, H1Read::Stalled(ReadPhase::Head)),
        ),
        (
            "close before any response",
            b"",
            true,
            |read| matches!(read, H1Read::ClosedBeforeResponse),
        ),
        (
            "malformed Content-Length",
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\nhello",
            true,
            |read| matches!(read, H1Read::Malformed(_)),
        ),
        (
            "body delimited only by close",
            b"HTTP/1.1 200 OK\r\n\r\nhello",
            true,
            |read| matches!(read, H1Read::UnsupportedFraming),
        ),
    ];
    for (label, reply, then_close, expected) in cases {
        let read = read_scripted_reply(reply, then_close).await;
        assert!(expected(&read), "{label}: misclassified as: {read}");
    }
}

/// Spawn `command`, apply [`wait_for_clean_exit`], then kill and reap whatever
/// is left. That cleanup is never the result under test.
async fn exit_check(command: &mut Command, bound: Duration) -> Result<(), ExitFailure> {
    let mut child = command.spawn().expect("spawn exit-check child");
    let result = wait_for_clean_exit(&mut child, bound).await;
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[tokio::test]
async fn harness_exit_wait_rejects_timeout_and_unsuccessful_exit() {
    let mut sleeper = Command::new("sleep");
    sleeper.arg("30");
    let hung = exit_check(&mut sleeper, Duration::from_millis(300)).await;
    assert!(
        matches!(hung, Err(ExitFailure::TimedOut)),
        "a child still running at the deadline must fail the exit check"
    );

    let mut failing = Command::new("sh");
    failing.args(["-c", "exit 3"]);
    let failed = exit_check(&mut failing, Duration::from_secs(5)).await;
    let failed_code = match failed {
        Err(ExitFailure::Unsuccessful(status)) => status.code(),
        _ => None,
    };
    assert_eq!(
        failed_code,
        Some(3),
        "a non-zero exit must fail the clean-exit check"
    );

    let clean = exit_check(&mut Command::new("true"), Duration::from_secs(5)).await;
    assert!(
        clean.is_ok(),
        "a zero exit within the bound must pass the exit check"
    );
}

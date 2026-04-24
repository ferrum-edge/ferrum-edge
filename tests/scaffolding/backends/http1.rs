//! `ScriptedHttp1Backend` — HTTP/1.1-aware wrapper around
//! [`super::tcp::ScriptedTcpBackend`].
//!
//! Lets tests describe an HTTP conversation as a sequence of
//! [`HttpStep`]s: "accept a request (optionally matching a pattern),
//! respond with status, header, body chunk, body end, or misbehave (close
//! before status, drip body, malformed header)".
//!
//! All behaviour is implemented directly on a `TcpStream` — no hyper
//! involvement on the server side — so misbehaviours like
//! `CloseBeforeStatus` and `SendMalformedHeader` are expressible with byte
//! precision.
//!
//! The backend records every parsed request in
//! [`ScriptedHttp1Backend::received_requests`] so tests can assert "gateway
//! forwarded the right path / headers".

use std::io;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

/// A single deterministic HTTP/1.1 step.
#[derive(Debug, Clone)]
pub enum HttpStep {
    /// Accept a request and (optionally) match it against a matcher. The
    /// matcher runs against the parsed request line + headers (not body).
    /// When the matcher returns false, the request is still recorded in
    /// `received_requests` and the rest of the script still fires, but the
    /// mismatch is counted — see
    /// [`ScriptedHttp1Backend::matcher_mismatches`] for the observable.
    ExpectRequest(RequestMatcher),
    /// Send `HTTP/1.1 <status> <reason>\r\n`.
    RespondStatus { status: u16, reason: String },
    /// Send a single header line `<name>: <value>\r\n`.
    RespondHeader { name: String, value: String },
    /// Send `\r\n` (end of headers) followed by `bytes` and no trailer/CRLF.
    /// Meant for chunked or Content-Length bodies; see the note on
    /// [`RespondBodyEnd`] below.
    ///
    /// [`RespondBodyEnd`]: HttpStep::RespondBodyEnd
    RespondBodyChunk(Vec<u8>),
    /// Terminate the response by sending `\r\n` (ending headers — if not
    /// already sent by a chunk step) and closing the connection cleanly.
    /// If `content_length` is `Some`, the step doesn't add one; the test is
    /// responsible for declaring a `Content-Length` header up front.
    RespondBodyEnd,
    /// Close the connection before writing any status bytes. The client
    /// sees `IncompleteMessage`-class errors.
    CloseBeforeStatus,
    /// Write `HTTP/1.1 <status> ...\r\nheaders...\r\n\r\n` then close
    /// (without the body). For tests that need "gateway saw status but
    /// stream ended before body arrived".
    CloseAfterHeaders {
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
    },
    /// Write headers, start the body, then close after writing `after_bytes`
    /// bytes of body — simulating a backend RST mid-body. This is the fixture
    /// for the `body_error_class` acceptance test.
    CloseMidBody {
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        /// Bytes the backend emits before abruptly closing. May be zero.
        body_prefix: Vec<u8>,
        /// How to terminate after writing `body_prefix`:
        /// - `true` → RST (SO_LINGER=0 + drop).
        /// - `false` → FIN (shutdown + drop).
        reset: bool,
    },
    /// Drip a body a chunk at a time, with a pause between chunks. Tests
    /// "slow backend" behaviour and `backend_read_timeout_ms`.
    TrickleBody {
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        chunk: Vec<u8>,
        pause: Duration,
        count: u32,
    },
    /// Send a deliberately malformed header line (e.g., missing colon) then
    /// close. Triggers client-side parse errors.
    SendMalformedHeader(String),
    /// Pause for `duration` without writing anything. Useful for triggering
    /// gateway `backend_read_timeout_ms`: pair with `ExpectRequest` and set
    /// the sleep ≫ the timeout, so the gateway's watchdog fires before the
    /// script returns.
    Sleep(Duration),
}

/// A matcher closure wrapped for `Clone` + `Debug`.
///
/// Hand-rolled rather than using `Box<dyn Fn(...)>` because we want `Clone`
/// for the "copy script into each connection" path.
#[derive(Clone)]
pub struct RequestMatcher(Arc<dyn Fn(&Request) -> bool + Send + Sync>);

impl std::fmt::Debug for RequestMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestMatcher").finish()
    }
}

impl RequestMatcher {
    /// Accept any request.
    pub fn any() -> Self {
        Self(Arc::new(|_| true))
    }

    /// Match by method.
    pub fn method(method: &'static str) -> Self {
        Self(Arc::new(move |r: &Request| r.method == method))
    }

    /// Match by exact path.
    pub fn path(path: &'static str) -> Self {
        Self(Arc::new(move |r: &Request| r.path == path))
    }

    /// Match by method + path.
    pub fn method_path(method: &'static str, path: &'static str) -> Self {
        Self(Arc::new(move |r: &Request| {
            r.method == method && r.path == path
        }))
    }

    /// Arbitrary closure.
    pub fn custom<F>(f: F) -> Self
    where
        F: Fn(&Request) -> bool + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }
}

/// A parsed HTTP/1.1 request line + headers. Body is not parsed — scripted
/// backends decide whether to read it based on headers (Content-Length /
/// Transfer-Encoding).
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: String,
    /// Header lines, original order preserved.
    pub headers: Vec<(String, String)>,
    /// Raw bytes of the request prelude (everything before the body).
    pub raw_prelude: Vec<u8>,
}

impl Request {
    /// Return the first matching header's value (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Fluent builder for [`ScriptedHttp1Backend`].
pub struct ScriptedHttp1BackendBuilder {
    listener: TcpListener,
    steps: Vec<HttpStep>,
}

impl ScriptedHttp1BackendBuilder {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            steps: Vec::new(),
        }
    }

    pub fn step(mut self, step: HttpStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn steps(mut self, steps: impl IntoIterator<Item = HttpStep>) -> Self {
        self.steps.extend(steps);
        self
    }

    pub fn spawn(self) -> io::Result<ScriptedHttp1Backend> {
        let port = self.listener.local_addr()?.port();
        let state = Arc::new(Http1State::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let steps = self.steps;
        let listener = self.listener;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((stream, _addr)) = accept_result else { continue; };
                        state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let state_conn = state_task.clone();
                        let script = steps.clone();
                        let track = state_conn.clone();
                        let jh = tokio::spawn(async move {
                            let state_err = state_conn.clone();
                            if let Err(e) = run_http_script(stream, script, state_conn).await {
                                state_err.step_errors.lock().await.push(e.to_string());
                            }
                        });
                        track.track_connection(jh.abort_handle());
                    }
                }
            }
        });
        Ok(ScriptedHttp1Backend {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

#[derive(Default)]
struct Http1State {
    accepted: AtomicU32,
    /// Count of `ExpectRequest` matchers that returned `false`. Exposed via
    /// [`ScriptedHttp1Backend::matcher_mismatches`] so tests can assert the
    /// gateway forwarded what they expected without silently ignoring a
    /// mismatch.
    matcher_mismatches: AtomicU32,
    requests: Mutex<Vec<Request>>,
    /// I/O errors returned by `run_http_script`. Without this, write
    /// failures (client hung up before response, etc.) would be silently
    /// dropped — see [`ScriptedHttp1Backend::step_errors`].
    step_errors: Mutex<Vec<String>>,
    /// AbortHandles for in-flight per-connection tasks (see
    /// `BackendState::connection_aborts` in `tcp.rs` for rationale).
    connection_aborts: StdMutex<Vec<AbortHandle>>,
}

impl Http1State {
    fn track_connection(&self, abort: AbortHandle) {
        if let Ok(mut guard) = self.connection_aborts.lock() {
            guard.retain(|h| !h.is_finished());
            guard.push(abort);
        }
    }
}

/// A running scripted HTTP/1.1 backend. Drop shuts it down.
pub struct ScriptedHttp1Backend {
    pub port: u16,
    state: Arc<Http1State>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedHttp1Backend {
    pub fn builder(listener: TcpListener) -> ScriptedHttp1BackendBuilder {
        ScriptedHttp1BackendBuilder::new(listener)
    }

    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Number of `ExpectRequest` matchers that returned `false` so far.
    /// Tests that supply a non-trivial matcher should assert this is zero;
    /// the matcher is otherwise informational and won't fail the script on
    /// its own.
    pub fn matcher_mismatches(&self) -> u32 {
        self.state.matcher_mismatches.load(Ordering::SeqCst)
    }

    /// Panic if any `ExpectRequest` matcher returned `false`. Call at the
    /// end of a test that uses a non-trivial matcher (e.g.,
    /// `RequestMatcher::method_path`) — without this, a gateway that
    /// forwarded the wrong method/path would not fail the test, defeating
    /// the purpose of the matcher.
    pub async fn assert_no_matcher_mismatches(&self) {
        let count = self.matcher_mismatches();
        if count == 0 {
            return;
        }
        let reqs = self.received_requests().await;
        let summary: Vec<String> = reqs
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect();
        panic!(
            "{} ExpectRequest matcher(s) returned false; received requests: {:?}",
            count, summary
        );
    }

    /// Clone of every parsed request observed so far.
    pub async fn received_requests(&self) -> Vec<Request> {
        self.state.requests.lock().await.clone()
    }

    /// Shorthand: returns the Nth parsed request (0-indexed).
    pub async fn request(&self, n: usize) -> Option<Request> {
        self.state.requests.lock().await.get(n).cloned()
    }

    /// I/O errors captured from each connection's script run. Empty on
    /// the happy path; see
    /// [`super::tcp::ScriptedTcpBackend::step_errors`] for rationale.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
    }

    /// Panic if any connection's script returned an I/O error.
    pub async fn assert_no_step_errors(&self) {
        let errs = self.step_errors().await;
        if !errs.is_empty() {
            panic!("{} script step error(s): {:?}", errs.len(), errs);
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        if let Ok(mut guard) = self.state.connection_aborts.lock() {
            for abort in guard.drain(..) {
                abort.abort();
            }
        }
    }
}

impl Drop for ScriptedHttp1Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Parse a request's prelude (up to `\r\n\r\n`) from a stream.
///
/// A single `read()` can return the prelude plus some body bytes in the
/// same buffer. The second return value is any bytes that arrived after
/// the `\r\n\r\n` separator; [`drain_body`] must consume them first before
/// reading more from the socket, otherwise it will wait for Content-Length
/// bytes that the peer already sent and POST-body tests hang.
async fn read_http_prelude(stream: &mut TcpStream) -> io::Result<Option<(Request, Vec<u8>)>> {
    let mut acc: Vec<u8> = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if acc.len() > 32 * 1024 {
            return Err(io::Error::other("prelude too large"));
        }
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(None),
            Ok(n) => acc.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e),
        }
    }
    let sep_pos = acc
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(acc.len());
    let prelude = &acc[..sep_pos];
    // Bytes past the `\r\n\r\n` separator are the start of the request body
    // (or pipelined next request). Hand them back so drain_body doesn't
    // double-read them from the socket.
    let body_start = sep_pos.saturating_add(4).min(acc.len());
    let leftover = acc[body_start..].to_vec();
    let text = std::str::from_utf8(prelude).map_err(io::Error::other)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((n, v)) = line.split_once(':') {
            headers.push((n.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(Some((
        Request {
            method,
            path,
            version,
            headers,
            raw_prelude: prelude.to_vec(),
        },
        leftover,
    )))
}

/// Consume any body the client still has in the socket, as advertised by
/// Content-Length. `leftover` is body bytes already read during prelude
/// parsing — they count toward the Content-Length quota, so we only read
/// the remainder from the socket.
///
/// Transfer-Encoding: chunked is not parsed; if the caller needs to drain a
/// chunked body they must do so themselves.
async fn drain_body(stream: &mut TcpStream, req: &Request, leftover: Vec<u8>) -> io::Result<()> {
    let Some(cl) = req.header("content-length") else {
        return Ok(());
    };
    let Ok(n) = cl.parse::<usize>() else {
        return Ok(());
    };
    if n == 0 {
        return Ok(());
    }
    let mut already = leftover.len().min(n);
    while already < n {
        let mut buf = [0u8; 4096];
        let want = (n - already).min(buf.len());
        match stream.read(&mut buf[..want]).await {
            Ok(0) => break,
            Ok(m) => already += m,
            Err(_) => break,
        }
    }
    Ok(())
}

async fn run_http_script(
    mut stream: TcpStream,
    script: Vec<HttpStep>,
    state: Arc<Http1State>,
) -> io::Result<()> {
    // Track whether we've already written the headers-body separator.
    let mut headers_ended = false;
    // Track whether the status line has been sent. Used only by the error
    // descriptions; not otherwise observable.
    let mut _status_sent = false;
    // Track whether a prior step has already parsed the request prelude on
    // this connection. Steps that implicitly consume a request
    // (`CloseAfterHeaders`, `CloseMidBody`, `TrickleBody`, `CloseBeforeStatus`)
    // must not re-read after an explicit `ExpectRequest`, or they'd wait on
    // a second request that never arrives and the test would hang.
    let mut request_consumed = false;

    // Always read one request first unless the very first step is
    // `CloseBeforeStatus` (in which case the client may not even get to
    // write a full request — but we still try to drain what's in the pipe).
    for step in script {
        match step {
            HttpStep::ExpectRequest(matcher) => {
                let parsed = read_http_prelude(&mut stream).await.ok().flatten();
                if let Some((req, leftover)) = parsed {
                    drain_body(&mut stream, &req, leftover).await.ok();
                    // Matcher is informational — the script continues either
                    // way — but we surface mismatches via a counter so tests
                    // can observe the result instead of it being silently
                    // discarded.
                    if !(matcher.0)(&req) {
                        state.matcher_mismatches.fetch_add(1, Ordering::SeqCst);
                    }
                    state.requests.lock().await.push(req);
                    request_consumed = true;
                }
            }
            HttpStep::RespondStatus { status, reason } => {
                let line = format!("HTTP/1.1 {status} {reason}\r\n");
                stream.write_all(line.as_bytes()).await?;
                _status_sent = true;
            }
            HttpStep::RespondHeader { name, value } => {
                let line = format!("{name}: {value}\r\n");
                stream.write_all(line.as_bytes()).await?;
            }
            HttpStep::RespondBodyChunk(bytes) => {
                if !headers_ended {
                    stream.write_all(b"\r\n").await?;
                    headers_ended = true;
                }
                stream.write_all(&bytes).await?;
            }
            HttpStep::RespondBodyEnd => {
                if !headers_ended {
                    stream.write_all(b"\r\n").await?;
                }
                let _ = stream.shutdown().await;
                return Ok(());
            }
            HttpStep::CloseBeforeStatus => {
                // Try to consume whatever request the client sent, but close
                // without ever writing a status line. Skip the read if a
                // prior `ExpectRequest` already consumed it.
                if !request_consumed {
                    let _ = read_http_prelude(&mut stream).await;
                }
                let _ = stream.shutdown().await;
                return Ok(());
            }
            HttpStep::CloseAfterHeaders {
                status,
                reason,
                headers,
            } => {
                // Consume a request so the client can reach the
                // "awaiting response" state — unless a prior `ExpectRequest`
                // already did. (The step returns right after writing the
                // response, so we don't bother flipping `request_consumed`.)
                if !request_consumed {
                    let parsed = read_http_prelude(&mut stream).await.ok().flatten();
                    if let Some((r, leftover)) = parsed {
                        drain_body(&mut stream, &r, leftover).await.ok();
                        state.requests.lock().await.push(r);
                    }
                }
                stream
                    .write_all(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes())
                    .await?;
                for (k, v) in headers {
                    stream.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
                }
                stream.write_all(b"\r\n").await?;
                let _ = stream.shutdown().await;
                return Ok(());
            }
            HttpStep::CloseMidBody {
                status,
                reason,
                headers,
                body_prefix,
                reset,
            } => {
                if !request_consumed {
                    let parsed = read_http_prelude(&mut stream).await.ok().flatten();
                    if let Some((r, leftover)) = parsed {
                        drain_body(&mut stream, &r, leftover).await.ok();
                        state.requests.lock().await.push(r);
                    }
                }
                stream
                    .write_all(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes())
                    .await?;
                for (k, v) in headers {
                    stream.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
                }
                stream.write_all(b"\r\n").await?;
                stream.write_all(&body_prefix).await?;
                if reset {
                    let std_stream = stream.into_std()?;
                    let sock = socket2::Socket::from(std_stream);
                    sock.set_linger(Some(Duration::from_secs(0)))?;
                    drop(sock);
                } else {
                    let _ = stream.shutdown().await;
                }
                return Ok(());
            }
            HttpStep::TrickleBody {
                status,
                reason,
                headers,
                chunk,
                pause,
                count,
            } => {
                if !request_consumed {
                    let parsed = read_http_prelude(&mut stream).await.ok().flatten();
                    if let Some((r, leftover)) = parsed {
                        drain_body(&mut stream, &r, leftover).await.ok();
                        state.requests.lock().await.push(r);
                    }
                }
                stream
                    .write_all(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes())
                    .await?;
                for (k, v) in headers {
                    stream.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
                }
                stream.write_all(b"\r\n").await?;
                for _ in 0..count {
                    if stream.write_all(&chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(pause).await;
                }
                let _ = stream.shutdown().await;
                return Ok(());
            }
            HttpStep::SendMalformedHeader(header) => {
                // Status 200, then garbage header, then close.
                stream.write_all(b"HTTP/1.1 200 OK\r\n").await?;
                stream.write_all(header.as_bytes()).await?;
                stream.write_all(b"\r\n\r\n").await?;
                let _ = stream.shutdown().await;
                return Ok(());
            }
            HttpStep::Sleep(d) => {
                tokio::time::sleep(d).await;
            }
        }
    }
    // End of script — close cleanly.
    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_port;

    async fn hit(port: u16) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.expect("read");
        String::from_utf8_lossy(&resp).to_string()
    }

    #[tokio::test]
    async fn simple_respond_chain() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "5".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"hello".to_vec()))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");
        let resp = hit(port).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("Content-Length: 5"));
        assert!(resp.ends_with("hello"));
        let reqs = backend.received_requests().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/hello");
    }

    #[tokio::test]
    async fn close_before_status_returns_empty_response() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::CloseBeforeStatus)
            .spawn()
            .expect("spawn");
        let resp = hit(port).await;
        assert!(resp.is_empty(), "expected empty, got {resp:?}");
    }

    #[tokio::test]
    async fn close_mid_body_writes_prefix_then_resets() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::CloseMidBody {
                status: 200,
                reason: "OK".into(),
                headers: vec![("Content-Length".into(), "10".into())],
                body_prefix: b"abc".to_vec(),
                reset: false,
            })
            .spawn()
            .expect("spawn");
        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.expect("read");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("Content-Length: 10"));
        // Body only has "abc" but Content-Length says 10 → client sees
        // truncated stream.
        assert!(text.ends_with("abc"), "expected body prefix, got {text:?}");
    }

    #[tokio::test]
    async fn trickle_body_writes_multiple_chunks() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::TrickleBody {
                status: 200,
                reason: "OK".into(),
                headers: vec![("Content-Length".into(), "4".into())],
                chunk: b"xy".to_vec(),
                pause: Duration::from_millis(5),
                count: 2,
            })
            .spawn()
            .expect("spawn");
        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.expect("read");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("xyxy"));
    }

    /// Regression test: sending the prelude and body in a single `write_all`
    /// must not hang the backend. Previously `read_http_prelude` dropped
    /// any body bytes that arrived in the same read as the `\r\n\r\n`
    /// separator, then `drain_body` waited on the socket for
    /// Content-Length bytes that the peer had already sent, and the
    /// subsequent response never fired until the socket was closed.
    #[tokio::test]
    async fn post_with_body_coalesced_with_prelude_does_not_hang() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "POST", "/echo",
            )))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "2".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        // Headers and body in a single write. The backend must not wait on
        // the socket for body bytes already delivered here.
        s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            .await
            .expect("write");

        let fut = async {
            let mut resp = Vec::new();
            s.read_to_end(&mut resp).await.expect("read");
            resp
        };
        let resp = tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("backend responded within timeout");
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.contains("HTTP/1.1 200 OK") && text.ends_with("ok"),
            "expected response, got {text:?}"
        );
        backend.assert_no_matcher_mismatches().await;
    }

    /// Regression test: chaining `ExpectRequest → CloseMidBody` must not
    /// hang. Previously `CloseMidBody` unconditionally called
    /// `read_http_prelude` a second time and waited for a request that
    /// would never arrive, so a perfectly natural "assert the request,
    /// then simulate a mid-body close" script deadlocked until the
    /// client timed out.
    #[tokio::test]
    async fn expect_request_then_close_mid_body_does_not_hang() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "GET", "/pipe",
            )))
            .step(HttpStep::CloseMidBody {
                status: 200,
                reason: "OK".into(),
                headers: vec![("Content-Length".into(), "10".into())],
                body_prefix: b"ab".to_vec(),
                reset: false,
            })
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(b"GET /pipe HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .expect("write");

        let fut = async {
            let mut resp = Vec::new();
            s.read_to_end(&mut resp).await.expect("read");
            resp
        };
        let resp = tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("backend responded within timeout");
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("HTTP/1.1 200 OK"), "got {text:?}");
        assert!(text.contains("Content-Length: 10"), "got {text:?}");
        assert!(text.ends_with("ab"), "got {text:?}");

        // Only the one request should have been recorded — if the bug
        // returned, we would observe zero requests (CloseMidBody would
        // hang in read_http_prelude) or two.
        let reqs = backend.received_requests().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].path, "/pipe");
        backend.assert_no_matcher_mismatches().await;
    }

    /// Short-reads on `ReadExact`-equivalents (here: a `Content-Length`
    /// body the client never completes) must surface in `step_errors`
    /// instead of being silently dropped. The backend closes when the
    /// client hangs up; `drain_body`'s loop bails with no visible
    /// error, but any _script-level_ error (an I/O write failure, a
    /// step that couldn't complete) shows up through the new helper.
    #[tokio::test]
    async fn step_errors_exposes_io_failures_to_callers() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "1000".into(),
            })
            .step(HttpStep::RespondBodyChunk(vec![b'x'; 1_000_000]))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        // Connect, send a request, then drop without reading the response
        // so the server's write hits `BrokenPipe`.
        {
            let mut s = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .expect("write");
            // Drop immediately — kernel sends FIN while server is still
            // writing the megabyte payload.
        }

        // Give the server task time to hit the write error.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let errs = backend.step_errors().await;
        assert!(
            !errs.is_empty(),
            "expected write failure to be captured in step_errors"
        );
    }
}

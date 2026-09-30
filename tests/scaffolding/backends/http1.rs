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
    /// Drip `body` `chunk_size` bytes at a time, with a pause between
    /// chunks. Tests "slow backend" behaviour and
    /// `backend_read_timeout_ms`.
    TrickleBody {
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        chunk_size: usize,
        pause: Duration,
    },
    /// Send a deliberately malformed header line (e.g., missing colon) then
    /// close. Triggers client-side parse errors.
    SendMalformedHeader(String),
    /// Pause for `duration` without writing anything. Useful for triggering
    /// gateway `backend_read_timeout_ms`: pair with `ExpectRequest` and set
    /// the sleep ≫ the timeout, so the gateway's watchdog fires before the
    /// script returns.
    Sleep(Duration),
    /// Complete an RFC 6455 HTTP upgrade: write `101 Switching Protocols`
    /// plus `Upgrade` / `Connection` / `Sec-WebSocket-Accept` derived from
    /// the last parsed request's `Sec-WebSocket-Key`, then keep the TCP
    /// socket for subsequent `HoldUntilPeerClose` / `Reset` steps.
    RespondWebSocketUpgrade,
    /// Read until the peer closes (EOF or read error). Used after a
    /// successful WebSocket upgrade so the backend stays up while the
    /// client injects frames or junk.
    HoldUntilPeerClose,
    /// Send a TCP RST (`SO_LINGER=0` then drop). After
    /// [`RespondWebSocketUpgrade`] this is a post-upgrade backend reset.
    Reset,
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

/// A parsed HTTP/1.1 request line + headers, plus the decoded request body.
///
/// The body is decoded from whichever framing the peer used (`Content-Length`
/// or `Transfer-Encoding: chunked`) and captured up to
/// [`MAX_CAPTURED_REQUEST_BODY`]. Anything that prevents a lossless capture —
/// a short body, an unparseable chunked stream, or a body larger than the cap
/// — sets [`Request::body_truncated`], so a test can never assert equality
/// against a silently clipped prefix.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub version: String,
    /// Header lines, original order preserved.
    pub headers: Vec<(String, String)>,
    /// Raw bytes of the request prelude (everything before the body).
    pub raw_prelude: Vec<u8>,
    /// Decoded request body bytes (chunk framing removed).
    pub body: Vec<u8>,
    /// `true` when `body` is NOT the complete body the peer intended to send.
    /// Always check this before asserting on `body` — otherwise a truncated
    /// or misframed body can make a `body.is_empty()` assertion pass for the
    /// wrong reason.
    pub body_truncated: bool,
}

impl Request {
    /// Return the first matching header's value (case-insensitive name).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The complete decoded body, or `None` when the fixture could not
    /// capture it losslessly. Prefer this over touching [`Request::body`]
    /// directly: it forces callers to handle the truncated case instead of
    /// asserting against a partial capture.
    pub fn complete_body(&self) -> Option<&[u8]> {
        if self.body_truncated {
            None
        } else {
            Some(&self.body)
        }
    }
}

/// Fluent builder for [`ScriptedHttp1Backend`].
pub struct ScriptedHttp1BackendBuilder {
    listener: TcpListener,
    steps: Vec<HttpStep>,
    connection_scripts: Vec<Vec<HttpStep>>,
}

impl ScriptedHttp1BackendBuilder {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            steps: Vec::new(),
            connection_scripts: Vec::new(),
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

    /// Supply connection-indexed scripts. Connection 0 receives the first
    /// script, connection 1 the second, and later connections repeat the
    /// final script. This is useful for deterministic retry tests such as
    /// `503 -> 200` without coordinating an out-of-band mutable flag.
    ///
    /// When non-empty, these scripts take precedence over [`Self::step`] /
    /// [`Self::steps`].
    pub fn connection_scripts(mut self, scripts: impl IntoIterator<Item = Vec<HttpStep>>) -> Self {
        self.connection_scripts.extend(scripts);
        self
    }

    pub fn spawn(self) -> io::Result<ScriptedHttp1Backend> {
        let port = self.listener.local_addr()?.port();
        let state = Arc::new(Http1State::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let steps = self.steps;
        let connection_scripts = self.connection_scripts;
        let listener = self.listener;
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((stream, _addr)) = accept_result else { continue; };
                        let connection_index =
                            state_task.accepted.fetch_add(1, Ordering::SeqCst) as usize;
                        let state_conn = state_task.clone();
                        let script = connection_scripts
                            .get(connection_index)
                            .or_else(|| connection_scripts.last())
                            .cloned()
                            .unwrap_or_else(|| steps.clone());
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
/// `carryover` is bytes already read in a previous step (pipelined body
/// tail, a second request coalesced into the previous `read`, etc.). The
/// function drains the prelude out of it and leaves any post-`\r\n\r\n`
/// bytes in place — those may be body bytes for this request or the start
/// of the *next* pipelined request. [`drain_body`] consumes them next and
/// leaves any further tail behind.
///
/// Returns `Ok(None)` on clean EOF before a full prelude arrives. Parse
/// failures (non-UTF8 bytes in the prelude, oversized prelude) surface as
/// `Err` so callers can record them in `step_errors`.
async fn read_http_prelude(
    stream: &mut TcpStream,
    carryover: &mut Vec<u8>,
) -> io::Result<Option<Request>> {
    let mut buf = [0u8; 1024];
    while !carryover.windows(4).any(|w| w == b"\r\n\r\n") {
        if carryover.len() > 32 * 1024 {
            return Err(io::Error::other("prelude too large"));
        }
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(None),
            Ok(n) => carryover.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e),
        }
    }
    let sep_pos = carryover
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(carryover.len());
    // Take the prelude out of carryover; everything past the `\r\n\r\n`
    // separator stays in carryover for drain_body / the next step.
    let body_start = sep_pos.saturating_add(4).min(carryover.len());
    let prelude: Vec<u8> = carryover.drain(..body_start).collect();
    let prelude_slice = &prelude[..sep_pos.min(prelude.len())];
    let text = std::str::from_utf8(prelude_slice).map_err(io::Error::other)?;
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
    Ok(Some(Request {
        method,
        path,
        version,
        headers,
        raw_prelude: prelude_slice.to_vec(),
        body: Vec::new(),
        body_truncated: false,
    }))
}

/// Upper bound on request-body bytes retained per request. Captured bodies
/// exist for assertions, not throughput. A body larger than this is still
/// drained off the socket (so the connection stays framed) but is reported
/// through [`Request::body_truncated`].
pub const MAX_CAPTURED_REQUEST_BODY: usize = 256 * 1024;

/// Hard ceiling on how many body bytes the fixture will pull off the socket
/// for a single request. Beyond this the capture is abandoned as truncated
/// rather than letting a hostile/looping peer pin the connection task.
const MAX_DRAINED_REQUEST_BODY: usize = 8 * 1024 * 1024;

/// Longest chunked-framing control line (`<hex-size>[;ext]` or a trailer)
/// the fixture will accept before declaring the stream unparseable.
const MAX_CHUNK_CONTROL_LINE: usize = 1024;

/// Body bytes captured for one request plus whether the capture is lossless.
#[derive(Default)]
struct BodyCapture {
    bytes: Vec<u8>,
    truncated: bool,
    drained: usize,
}

impl BodyCapture {
    fn push(&mut self, chunk: &[u8]) {
        self.drained = self.drained.saturating_add(chunk.len());
        let room = MAX_CAPTURED_REQUEST_BODY.saturating_sub(self.bytes.len());
        if chunk.len() > room {
            self.bytes.extend_from_slice(&chunk[..room]);
            self.truncated = true;
        } else {
            self.bytes.extend_from_slice(chunk);
        }
    }

    fn apply_to(self, req: &mut Request) {
        req.body = self.bytes;
        req.body_truncated = self.truncated;
    }
}

/// Read one more socket chunk into `carryover`. Returns `false` on EOF or an
/// I/O error — both mean "no more body bytes are coming".
async fn fill_carryover(stream: &mut TcpStream, carryover: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            carryover.extend_from_slice(&buf[..n]);
            true
        }
    }
}

/// Consume a CRLF-terminated control line from `carryover` (reading more from
/// the socket as needed), returning the line without its terminator. `None`
/// means EOF or a line longer than `MAX_CHUNK_CONTROL_LINE`.
async fn read_control_line(stream: &mut TcpStream, carryover: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(pos) = carryover.windows(2).position(|w| w == b"\r\n") {
            if pos > MAX_CHUNK_CONTROL_LINE {
                return None;
            }
            let line = carryover[..pos].to_vec();
            carryover.drain(..pos + 2);
            return Some(line);
        }
        if carryover.len() > MAX_CHUNK_CONTROL_LINE {
            return None;
        }
        if !fill_carryover(stream, carryover).await {
            return None;
        }
    }
}

/// Move exactly `n` body bytes out of `carryover`/the socket into `capture`.
/// Returns `false` if the peer closed first (capture marked truncated).
async fn take_body_bytes(
    stream: &mut TcpStream,
    carryover: &mut Vec<u8>,
    capture: &mut BodyCapture,
    n: usize,
) -> bool {
    let mut remaining = n;
    while remaining > 0 {
        if capture.drained >= MAX_DRAINED_REQUEST_BODY {
            capture.truncated = true;
            return false;
        }
        if carryover.is_empty() && !fill_carryover(stream, carryover).await {
            capture.truncated = true;
            return false;
        }
        let take = carryover.len().min(remaining);
        capture.push(&carryover[..take]);
        carryover.drain(..take);
        remaining -= take;
    }
    true
}

/// Consume and capture `req`'s body. `carryover` is the pre-read buffer
/// (bytes that arrived in the same `read()` as the prelude or a previous
/// step). Body bytes are drained from the front of `carryover` first, then
/// from the socket — **bytes past the end of the body stay in `carryover`**
/// so a subsequent `ExpectRequest` can parse a pipelined next request
/// without losing the bytes the peer already sent.
///
/// Both `Content-Length` and `Transfer-Encoding: chunked` framings are
/// decoded. Anything that stops the capture from being lossless (peer closed
/// mid-body, unparseable chunk framing, body above
/// [`MAX_CAPTURED_REQUEST_BODY`]) is reported through
/// [`Request::body_truncated`] rather than silently yielding a short body —
/// a silent short body would let a `body == expected` assertion fail for an
/// unrelated reason, and a silent empty body would let one pass vacuously.
async fn drain_body(stream: &mut TcpStream, req: &Request, carryover: &mut Vec<u8>) -> BodyCapture {
    let mut capture = BodyCapture::default();

    let chunked = req
        .header("transfer-encoding")
        .is_some_and(|te| te.to_ascii_lowercase().contains("chunked"));
    if chunked {
        loop {
            let Some(header) = read_control_line(stream, carryover).await else {
                capture.truncated = true;
                return capture;
            };
            let header_text = String::from_utf8_lossy(&header);
            // Strip any chunk extension (`<size>;name=value`).
            let size_text = header_text.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(size_text, 16) else {
                capture.truncated = true;
                return capture;
            };
            if size == 0 {
                // Trailer section: lines until the terminating empty line.
                loop {
                    match read_control_line(stream, carryover).await {
                        Some(line) if line.is_empty() => return capture,
                        Some(_) => continue,
                        None => {
                            capture.truncated = true;
                            return capture;
                        }
                    }
                }
            }
            if !take_body_bytes(stream, carryover, &mut capture, size).await {
                return capture;
            }
            // Every chunk's data is followed by a bare CRLF.
            match read_control_line(stream, carryover).await {
                Some(line) if line.is_empty() => {}
                _ => {
                    capture.truncated = true;
                    return capture;
                }
            }
        }
    }

    let Some(cl) = req.header("content-length") else {
        // No Content-Length and no chunked framing: RFC 9112 says there is
        // no body on a request. Nothing to capture, nothing lost.
        return capture;
    };
    let Ok(n) = cl.parse::<usize>() else {
        // An unparseable Content-Length means we cannot know where the body
        // ends; refuse to guess and report the capture as lossy.
        capture.truncated = true;
        return capture;
    };
    if n == 0 {
        return capture;
    }
    take_body_bytes(stream, carryover, &mut capture, n).await;
    capture
}

async fn run_http_script(
    mut stream: TcpStream,
    script: Vec<HttpStep>,
    state: Arc<Http1State>,
) -> io::Result<()> {
    // Track whether we've already written the headers-body separator.
    let mut headers_ended = false;
    // `RespondBodyEnd` closes this connection, so advertise that before the
    // header section ends unless the script already sent `Connection: close`.
    let mut connection_close_sent = false;
    // Track whether the status line has been sent. Used only by the error
    // descriptions; not otherwise observable.
    let mut _status_sent = false;
    // Track whether a prior step has already parsed the request prelude on
    // this connection. Steps that implicitly consume a request
    // (`CloseAfterHeaders`, `CloseMidBody`, `TrickleBody`, `CloseBeforeStatus`)
    // must not re-read after an explicit `ExpectRequest`, or they'd wait on
    // a second request that never arrives and the test would hang.
    let mut request_consumed = false;
    // Persistent pre-read buffer carried across steps: body tail past a
    // previous request's `Content-Length`, pipelined next request, etc.
    let mut carryover: Vec<u8> = Vec::new();
    let mut last_ws_key: Option<String> = None;

    // Always read one request first unless the very first step is
    // `CloseBeforeStatus` (in which case the client may not even get to
    // write a full request — but we still try to drain what's in the pipe).
    for step in script {
        match step {
            HttpStep::ExpectRequest(matcher) => {
                match read_http_prelude(&mut stream, &mut carryover).await {
                    Ok(Some(mut req)) => {
                        drain_body(&mut stream, &req, &mut carryover)
                            .await
                            .apply_to(&mut req);
                        // Matcher is informational — the script continues either
                        // way — but we surface mismatches via a counter so tests
                        // can observe the result instead of it being silently
                        // discarded.
                        if !(matcher.0)(&req) {
                            state.matcher_mismatches.fetch_add(1, Ordering::SeqCst);
                        }
                        last_ws_key = req
                            .header("sec-websocket-key")
                            .map(|value| value.to_string());
                        state.requests.lock().await.push(req);
                        request_consumed = true;
                    }
                    Ok(None) => {
                        state.step_errors.lock().await.push(
                            "ExpectRequest: peer closed before sending a full request".into(),
                        );
                    }
                    Err(e) => {
                        state
                            .step_errors
                            .lock()
                            .await
                            .push(format!("ExpectRequest: failed to parse request: {e}"));
                    }
                }
            }
            HttpStep::RespondStatus { status, reason } => {
                let line = format!("HTTP/1.1 {status} {reason}\r\n");
                stream.write_all(line.as_bytes()).await?;
                _status_sent = true;
            }
            HttpStep::RespondHeader { name, value } => {
                if name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("close"))
                {
                    connection_close_sent = true;
                }
                let line = format!("{name}: {value}\r\n");
                stream.write_all(line.as_bytes()).await?;
            }
            HttpStep::RespondBodyChunk(bytes) => {
                if !headers_ended {
                    if !connection_close_sent {
                        stream.write_all(b"Connection: close\r\n").await?;
                    }
                    stream.write_all(b"\r\n").await?;
                    headers_ended = true;
                }
                stream.write_all(&bytes).await?;
            }
            HttpStep::RespondBodyEnd => {
                if !headers_ended {
                    if !connection_close_sent {
                        stream.write_all(b"Connection: close\r\n").await?;
                    }
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
                    let _ = read_http_prelude(&mut stream, &mut carryover).await;
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
                if !request_consumed
                    && let Ok(Some(mut r)) = read_http_prelude(&mut stream, &mut carryover).await
                {
                    drain_body(&mut stream, &r, &mut carryover)
                        .await
                        .apply_to(&mut r);
                    state.requests.lock().await.push(r);
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
                if !request_consumed
                    && let Ok(Some(mut r)) = read_http_prelude(&mut stream, &mut carryover).await
                {
                    drain_body(&mut stream, &r, &mut carryover)
                        .await
                        .apply_to(&mut r);
                    state.requests.lock().await.push(r);
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
                body,
                chunk_size,
                pause,
            } => {
                if !request_consumed
                    && let Ok(Some(mut r)) = read_http_prelude(&mut stream, &mut carryover).await
                {
                    drain_body(&mut stream, &r, &mut carryover)
                        .await
                        .apply_to(&mut r);
                    state.requests.lock().await.push(r);
                }
                stream
                    .write_all(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes())
                    .await?;
                for (k, v) in headers {
                    stream.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
                }
                stream.write_all(b"\r\n").await?;
                if chunk_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TrickleBody chunk_size must be greater than zero",
                    ));
                }
                for chunk in body.chunks(chunk_size) {
                    if stream.write_all(chunk).await.is_err() {
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
            HttpStep::RespondWebSocketUpgrade => {
                if !request_consumed {
                    match read_http_prelude(&mut stream, &mut carryover).await {
                        Ok(Some(mut req)) => {
                            drain_body(&mut stream, &req, &mut carryover)
                                .await
                                .apply_to(&mut req);
                            last_ws_key = req
                                .header("sec-websocket-key")
                                .map(|value| value.to_string());
                            state.requests.lock().await.push(req);
                            request_consumed = true;
                        }
                        Ok(None) => {
                            state.step_errors.lock().await.push(
                                "RespondWebSocketUpgrade: peer closed before a full request".into(),
                            );
                            return Ok(());
                        }
                        Err(e) => {
                            state.step_errors.lock().await.push(format!(
                                "RespondWebSocketUpgrade: failed to parse request: {e}"
                            ));
                            return Ok(());
                        }
                    }
                }
                let Some(key) = last_ws_key.as_deref() else {
                    state
                        .step_errors
                        .lock()
                        .await
                        .push("RespondWebSocketUpgrade: missing Sec-WebSocket-Key".into());
                    return Ok(());
                };
                let accept =
                    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await?;
            }
            HttpStep::HoldUntilPeerClose => {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                return Ok(());
            }
            HttpStep::Reset => {
                let std_stream = stream.into_std()?;
                let sock = socket2::Socket::from(std_stream);
                sock.set_linger(Some(Duration::from_secs(0)))?;
                drop(sock);
                return Ok(());
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
                body: b"xyxy".to_vec(),
                chunk_size: 2,
                pause: Duration::from_millis(5),
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

    /// Regression test: a peer that pipelines two requests on one TCP
    /// connection (request A + Content-Length body + request B) must
    /// have both surface as `ExpectRequest` hits. Before the fix,
    /// `drain_body` consumed body bytes up to Content-Length and
    /// discarded the tail (request B's prelude) that arrived in the
    /// same `read()`, so the next `ExpectRequest` would block forever.
    #[tokio::test]
    async fn pipelined_requests_in_one_tcp_read_are_both_parsed() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "POST", "/first",
            )))
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "GET", "/second",
            )))
            .step(HttpStep::RespondStatus {
                status: 200,
                reason: "OK".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "4".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"done".to_vec()))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        // Both requests + the first request's body in a single `write_all`.
        s.write_all(
            b"POST /first HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n\
              abc\
              GET /second HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await
        .expect("write");

        let fut = async {
            let mut resp = Vec::new();
            s.read_to_end(&mut resp).await.expect("read");
            resp
        };
        let _ = tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .expect("second request parsed and response fired within timeout");

        let reqs = backend.received_requests().await;
        assert_eq!(reqs.len(), 2, "expected both requests: {reqs:?}");
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/first");
        assert_eq!(reqs[1].method, "GET");
        assert_eq!(reqs[1].path, "/second");
        backend.assert_no_matcher_mismatches().await;
        backend.assert_no_step_errors().await;
    }

    /// Regression test: if the peer closes before a full request prelude
    /// arrives, `ExpectRequest` must surface the failure via
    /// `step_errors` instead of silently treating it as a matched
    /// request. A naive `assert_no_matcher_mismatches()`-only test would
    /// otherwise pass against a zero-request connection.
    #[tokio::test]
    async fn expect_request_surfaces_eof_and_parse_failures() {
        // Case 1: EOF before prelude terminator.
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .spawn()
            .expect("spawn");

        {
            let mut s = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            // Partial prelude, then close.
            s.write_all(b"GET /never-finished HTTP/1.1\r\n")
                .await
                .expect("write");
            // Drop: FIN before \r\n\r\n.
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let errs = backend.step_errors().await;
        assert!(
            errs.iter().any(|e| e.contains("ExpectRequest")),
            "expected ExpectRequest error for EOF-before-prelude; got {errs:?}"
        );

        // Case 2: non-UTF-8 bytes in the prelude.
        let reservation2 = reserve_port().await.expect("port");
        let port2 = reservation2.port;
        let backend2 = ScriptedHttp1Backend::builder(reservation2.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .spawn()
            .expect("spawn");

        {
            let mut s = TcpStream::connect(("127.0.0.1", port2))
                .await
                .expect("connect");
            s.write_all(&[0xFF, 0xFE, b'\r', b'\n', b'\r', b'\n'])
                .await
                .expect("write");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let errs2 = backend2.step_errors().await;
        assert!(
            errs2.iter().any(|e| e.contains("ExpectRequest")),
            "expected ExpectRequest error for invalid UTF-8; got {errs2:?}"
        );
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

    // ── Request-body capture ────────────────────────────────────────────
    //
    // Regression coverage for the fixture capability that replaced the
    // hand-rolled `ReadUntil(\r\n\r\n) + ReadExact(len)` scripts in the
    // A2A SSE tests (issue #3431). Those scripts guessed the body length
    // instead of reading the framing, so any connection that was not the
    // expected HTTP/1.1 request — notably the gateway's startup h2c
    // capability probe, whose HTTP/2 preface contains a `\r\n\r\n` —
    // short-read and failed the test. Body assertions are only meaningful
    // if the capture is lossless and reports when it is not.

    /// Drive one request through a backend whose only job is to record it.
    async fn record_request(raw: &[u8]) -> Request {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .step(HttpStep::RespondStatus {
                status: 204,
                reason: "No Content".into(),
            })
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(raw).await.expect("write");
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp))
            .await
            .expect("backend answered within timeout")
            .expect("read");

        backend
            .request(0)
            .await
            .expect("backend recorded the request")
    }

    /// A `Content-Length` body coalesced with the prelude must be captured
    /// byte-for-byte and flagged complete.
    #[tokio::test]
    async fn content_length_body_is_captured_losslessly() {
        let body = br#"{"jsonrpc":"2.0","method":"message/send"}"#;
        let raw = format!(
            "POST /a2a HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let req = record_request(raw.as_bytes()).await;
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/a2a");
        assert!(!req.body_truncated, "capture should be complete");
        assert_eq!(req.complete_body(), Some(&body[..]));
    }

    /// The same body split across TCP segments must still be captured in
    /// full — the capture must read the socket, not just the pre-read
    /// buffer that happened to arrive with the prelude.
    #[tokio::test]
    async fn content_length_body_split_across_segments_is_captured_losslessly() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "POST", "/split",
            )))
            .step(HttpStep::RespondStatus {
                status: 204,
                reason: "No Content".into(),
            })
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(b"POST /split HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\n")
            .await
            .expect("write prelude");
        s.write_all(b"abc").await.expect("write part 1");
        s.write_all(b"def").await.expect("write part 2");
        s.write_all(b"ghi").await.expect("write part 3");

        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp))
            .await
            .expect("backend answered within timeout")
            .expect("read");

        let req = backend.request(0).await.expect("recorded request");
        assert!(!req.body_truncated);
        assert_eq!(req.complete_body(), Some(&b"abcdefghi"[..]));
        backend.assert_no_matcher_mismatches().await;
    }

    /// A chunked body must be decoded (framing removed) rather than left
    /// on the socket. Before this capability the fixture ignored chunked
    /// framing entirely, so the chunk bytes were misread as the next
    /// pipelined request.
    #[tokio::test]
    async fn chunked_body_is_decoded_and_framing_is_consumed() {
        let raw = b"POST /chunked HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n\
                    6;ext=1\r\n world\r\n\
                    0\r\n\r\n";
        let req = record_request(raw).await;
        assert_eq!(req.path, "/chunked");
        assert!(!req.body_truncated, "chunked capture should be complete");
        assert_eq!(req.complete_body(), Some(&b"hello world"[..]));
    }

    /// A peer that closes before delivering the declared `Content-Length`
    /// must produce a *flagged* partial capture. Silently returning the
    /// short prefix would let `body == expected` fail for the wrong
    /// reason, and silently returning nothing would let an
    /// `assert!(body.is_empty())` pass vacuously.
    #[tokio::test]
    async fn short_body_is_reported_as_truncated() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .spawn()
            .expect("spawn");

        {
            let mut s = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            s.write_all(b"POST /short HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
                .await
                .expect("write");
            // Drop: FIN after only 3 of the 10 declared body bytes.
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let req = loop {
            if let Some(r) = backend.request(0).await {
                break r;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "backend never recorded the truncated request"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(
            req.body_truncated,
            "an incomplete body must be flagged, got {:?}",
            String::from_utf8_lossy(&req.body)
        );
        assert_eq!(req.complete_body(), None);
        assert_eq!(req.body, b"abc".to_vec());
    }

    /// Unparseable chunk framing must be reported as truncated instead of
    /// being silently treated as an empty body.
    #[tokio::test]
    async fn malformed_chunked_body_is_reported_as_truncated() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::any()))
            .spawn()
            .expect("spawn");

        {
            let mut s = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            s.write_all(
                b"POST /bad HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nnot-hex\r\n",
            )
            .await
            .expect("write");
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let req = loop {
            if let Some(r) = backend.request(0).await {
                break r;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "backend never recorded the malformed request"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(req.body_truncated);
        assert_eq!(req.complete_body(), None);
    }

    /// The capture is bounded: a body above `MAX_CAPTURED_REQUEST_BODY` is
    /// still drained (so the connection stays framed and the response
    /// fires) but is reported as truncated.
    #[tokio::test]
    async fn oversized_body_is_bounded_and_flagged() {
        let over = MAX_CAPTURED_REQUEST_BODY + 4096;
        let mut raw =
            format!("POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: {over}\r\n\r\n").into_bytes();
        raw.extend(std::iter::repeat_n(b'z', over));
        let req = record_request(&raw).await;
        assert!(req.body_truncated, "oversized body must be flagged");
        assert_eq!(req.complete_body(), None);
        assert_eq!(
            req.body.len(),
            MAX_CAPTURED_REQUEST_BODY,
            "capture must stop at the documented cap"
        );
    }

    /// Body capture must not disturb the pipelining contract: the bytes
    /// following a `Content-Length` body still belong to the next request.
    #[tokio::test]
    async fn pipelined_request_after_captured_body_is_still_parsed() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "POST", "/first",
            )))
            .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
                "GET", "/second",
            )))
            .step(HttpStep::RespondStatus {
                status: 204,
                reason: "No Content".into(),
            })
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("spawn");

        let mut s = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect");
        s.write_all(
            b"POST /first HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n\
              abc\
              GET /second HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await
        .expect("write");

        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp))
            .await
            .expect("both requests parsed within timeout")
            .expect("read");

        let reqs = backend.received_requests().await;
        assert_eq!(reqs.len(), 2, "{reqs:?}");
        assert_eq!(reqs[0].complete_body(), Some(&b"abc"[..]));
        assert_eq!(
            reqs[1].complete_body(),
            Some(&b""[..]),
            "a bodyless request captures an empty, complete body"
        );
        backend.assert_no_matcher_mismatches().await;
        backend.assert_no_step_errors().await;
    }
}

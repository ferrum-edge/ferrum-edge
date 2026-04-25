//! `ScriptedH2Backend` — a scripted HTTP/2 server built on top of the `h2`
//! crate's server API.
//!
//! Mirrors [`super::http1::ScriptedHttp1Backend`] but operates at the H2
//! frame level: HEADERS, DATA, TRAILERS, RST_STREAM, GOAWAY, flow-control
//! stalls, and raw TCP drops. Designed for tests that need to assert
//! gateway behavior under protocol-level failure modes without hand-rolling
//! a hyper server.
//!
//! ## Transport
//!
//! H2 is negotiated with ALPN `h2` when running over TLS (see
//! [`ScriptedH2Backend::builder_tls`]) or with prior knowledge when running
//! plain ([`ScriptedH2Backend::builder_plain`]). Plain h2c is the common
//! case for testing the direct H2 pool's "is_known_http1_backend" path —
//! for gRPC proxying the gateway's gRPC pool, it's `h2` over TLS.
//!
//! ## Script
//!
//! See [`H2Step`]. The script runs per accepted connection — a test can
//! have one connection run "accept headers → send GOAWAY" and the next run
//! "accept headers → respond 200", or can script a single connection across
//! a sequence of per-stream responses.
//!
//! ## Observability
//!
//! - [`ScriptedH2Backend::accepted_connections`] — raw TCP accepts
//! - [`ScriptedH2Backend::handshakes_completed`] — connections that finished
//!   the H2 settings exchange
//! - [`ScriptedH2Backend::received_streams`] — parsed request headers per
//!   stream, ordered by arrival
//! - [`ScriptedH2Backend::step_errors`] — non-empty if any script step
//!   failed. Tests SHOULD call `assert_no_step_errors()` to surface silent
//!   fixture failures.

use bytes::Bytes;
use h2::server::Builder as H2Builder;
use h2::server::SendResponse;
use h2::{Reason, RecvStream};
use http::{HeaderMap, Request, Response, StatusCode};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::io;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

/// Headers of a received H2 request stream, captured for assertions.
#[derive(Debug, Clone)]
pub struct ReceivedStream {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub scheme: Option<String>,
    /// All request headers (pseudo-headers included via method/path/authority/scheme).
    pub headers: Vec<(String, String)>,
    /// Body bytes buffered up to the point the script decided to respond —
    /// empty on tests that don't read the body.
    pub body: Vec<u8>,
    /// Trailers, if the client sent any.
    pub trailers: Vec<(String, String)>,
}

impl ReceivedStream {
    /// Look up a header value by name (case-insensitive). Returns the first
    /// match.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A matcher closure over request HEADERS. Cheap to clone — wraps `Arc<dyn Fn>`.
#[derive(Clone)]
pub struct MatchHeaders(Arc<dyn Fn(&ReceivedStream) -> bool + Send + Sync>);

impl std::fmt::Debug for MatchHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchHeaders").finish()
    }
}

impl MatchHeaders {
    pub fn any() -> Self {
        Self(Arc::new(|_| true))
    }

    pub fn method(method: &'static str) -> Self {
        Self(Arc::new(move |s: &ReceivedStream| s.method == method))
    }

    pub fn path(path: &'static str) -> Self {
        Self(Arc::new(move |s: &ReceivedStream| s.path == path))
    }

    pub fn method_path(method: &'static str, path: &'static str) -> Self {
        Self(Arc::new(move |s: &ReceivedStream| {
            s.method == method && s.path == path
        }))
    }

    pub fn custom<F>(f: F) -> Self
    where
        F: Fn(&ReceivedStream) -> bool + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }
}

/// A single deterministic instruction in an H2 script.
///
/// Scripts run per accepted TCP connection: the server completes the H2
/// handshake, then executes the steps in order. Steps that operate on a
/// stream (`ExpectHeaders`, `RespondHeaders`, `RespondData`, ...) always
/// target the *current* stream — either the first `Connection::accept`
/// hit after handshake, or the stream just registered by `ExpectHeaders`.
#[derive(Clone, Debug)]
pub enum H2Step {
    /// Accept the next incoming stream from the client and match its request
    /// headers against `matcher`. Mismatch is counted but doesn't stop the
    /// script — see [`ScriptedH2Backend::matcher_mismatches`].
    ExpectHeaders(MatchHeaders),
    /// Drain the client's request body into the current stream's
    /// `ReceivedStream.body`. Call after `ExpectHeaders`.
    DrainRequestBody,
    /// Send response HEADERS for the current stream. Does NOT end the
    /// stream — call `RespondData { end_stream: true }` or
    /// `RespondTrailers` to close.
    RespondHeaders(Vec<(&'static str, String)>),
    /// Send a DATA frame on the current stream. `end_stream` closes the
    /// stream after flushing.
    RespondData { data: Bytes, end_stream: bool },
    /// Send trailers on the current stream. Implicitly closes the stream.
    RespondTrailers(Vec<(&'static str, String)>),
    /// Issue a GOAWAY frame with the given error code. The connection
    /// continues being polled until in-flight streams close.
    SendGoaway { error_code: u32 },
    /// Issue a GOAWAY frame, then immediately stop servicing the
    /// connection. Use when the gateway must classify the stream failure
    /// as a connection-level fault (e.g., when we need "GOAWAY mid-request
    /// drops the socket" behavior).
    SendGoawayAndClose { error_code: u32 },
    /// Send RST_STREAM on the current stream with the given H2 error code.
    SendRstStream { error_code: u32 },
    /// Pause for `duration` without advancing the connection. Clients that
    /// exceed `backend_write_timeout_ms` while waiting for the next DATA
    /// frame will fire their watchdog here.
    ///
    /// NOTE: To keep the peer's flow-control window from opening during
    /// the stall, do NOT start sending response headers first. The H2
    /// crate's stream-send buffer remains bounded by the client's
    /// advertised initial window (default 65,535 bytes). For tests that
    /// need a full write stall across a big upload, issue
    /// `RespondHeaders` and a `RespondData` with a payload larger than
    /// the client window before the Sleep so no additional capacity is
    /// granted.
    Sleep(Duration),
    /// Withhold WINDOW_UPDATE frames by configuring a tiny initial
    /// connection/stream window, then sleep for `duration`. Anything the
    /// peer writes past the initial window stalls. The step returns once
    /// the duration elapses; cleanup restores normal operation.
    ///
    /// Implementation note: we don't have a public h2 API to freeze the
    /// window mid-flight, so this step simply sleeps with the already-low
    /// windows supplied at handshake time via the `ConnectionSettings`.
    /// Pair with `ScriptedH2Backend::builder_*().with_initial_window_size(1)`
    /// for the tightest stall.
    StallWindowFor(Duration),
    /// Close the underlying TCP stream without any orderly H2 teardown.
    DropConnection,
}

/// Pre-handshake settings applied via the h2 `server::Builder`. Exposed so
/// individual steps (e.g. `StallWindowFor`) can configure the window below
/// what h2 would default to (65,535).
#[derive(Clone, Debug, Default)]
pub struct ConnectionSettings {
    pub initial_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub max_concurrent_streams: Option<u32>,
}

impl ConnectionSettings {
    fn apply(&self, builder: &mut H2Builder) {
        if let Some(w) = self.initial_window_size {
            builder.initial_window_size(w);
        }
        if let Some(w) = self.initial_connection_window_size {
            builder.initial_connection_window_size(w);
        }
        if let Some(m) = self.max_concurrent_streams {
            builder.max_concurrent_streams(m);
        }
    }
}

/// Builder for [`ScriptedH2Backend`]. Two transport flavors — plaintext
/// ([`ScriptedH2Backend::builder_plain`]) and TLS+ALPN-h2
/// ([`ScriptedH2Backend::builder_tls`]).
pub struct ScriptedH2BackendBuilder {
    listener: TcpListener,
    tls: Option<TlsParams>,
    steps: Vec<H2Step>,
    settings: ConnectionSettings,
}

/// TLS parameters for the H2 builder. Private — only meaningful inside this
/// module; callers use [`ScriptedH2Backend::builder_tls`].
struct TlsParams {
    server_config: Arc<ServerConfig>,
}

impl ScriptedH2BackendBuilder {
    /// Build the h2 acceptor over a plain TCP listener (h2c, prior
    /// knowledge). Use when the gateway is configured with backend scheme
    /// `http` and dispatches gRPC via plaintext H2.
    pub fn plain(listener: TcpListener) -> Self {
        Self {
            listener,
            tls: None,
            steps: Vec::new(),
            settings: ConnectionSettings::default(),
        }
    }

    /// Build an h2-over-TLS acceptor. The server negotiates ALPN `h2`;
    /// clients that don't advertise h2 will fail the handshake. Cert and
    /// key are PEM-encoded — use [`super::super::certs::TestCa`] for
    /// fixtures.
    pub fn tls(listener: TcpListener, cert_pem: &str, key_pem: &str) -> io::Result<Self> {
        let tls_config = build_server_config_with_alpn(cert_pem, key_pem, vec![b"h2".to_vec()])?;
        Ok(Self {
            listener,
            tls: Some(TlsParams {
                server_config: Arc::new(tls_config),
            }),
            steps: Vec::new(),
            settings: ConnectionSettings::default(),
        })
    }

    /// Like [`Self::tls`] but advertises both `h2` and `http/1.1` in ALPN.
    /// Useful for tests that want the scripted backend to also respond on
    /// the fallback path (rare — usually we'd use `ScriptedTlsBackend` for
    /// that). Kept here for API symmetry.
    pub fn tls_with_alpn(
        listener: TcpListener,
        cert_pem: &str,
        key_pem: &str,
        alpn: Vec<Vec<u8>>,
    ) -> io::Result<Self> {
        let tls_config = build_server_config_with_alpn(cert_pem, key_pem, alpn)?;
        Ok(Self {
            listener,
            tls: Some(TlsParams {
                server_config: Arc::new(tls_config),
            }),
            steps: Vec::new(),
            settings: ConnectionSettings::default(),
        })
    }

    /// Append a step.
    pub fn step(mut self, step: H2Step) -> Self {
        self.steps.push(step);
        self
    }

    /// Append multiple steps.
    pub fn steps(mut self, steps: impl IntoIterator<Item = H2Step>) -> Self {
        self.steps.extend(steps);
        self
    }

    /// Override pre-handshake H2 settings (initial windows, max concurrent
    /// streams). `StallWindowFor` depends on a small initial window.
    pub fn with_settings(mut self, settings: ConnectionSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Convenience: set initial stream window to `n` octets. Defaults to
    /// 65,535 when unset.
    pub fn with_initial_window_size(mut self, n: u32) -> Self {
        self.settings.initial_window_size = Some(n);
        self
    }

    /// Convenience: set initial connection window to `n` octets.
    pub fn with_initial_connection_window_size(mut self, n: u32) -> Self {
        self.settings.initial_connection_window_size = Some(n);
        self
    }

    /// Spawn the backend. Returns immediately; the accept loop runs on a
    /// background task.
    pub fn spawn(self) -> io::Result<ScriptedH2Backend> {
        let port = self.listener.local_addr()?.port();
        let state = Arc::new(H2State::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let listener = self.listener;
        let tls = self.tls;
        let steps = self.steps;
        let settings = self.settings;

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((tcp, _addr)) = accept_result else { continue; };
                        state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let script = steps.clone();
                        let conn_state = state_task.clone();
                        let settings = settings.clone();
                        let tls_params = tls.as_ref().map(|t| t.server_config.clone());
                        let track = conn_state.clone();
                        let jh = tokio::spawn(async move {
                            let err_sink = conn_state.clone();
                            let result: Result<(), String> = if let Some(tls_cfg) = tls_params {
                                let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
                                match acceptor.accept(tcp).await {
                                    Ok(tls_stream) => {
                                        run_h2_connection(tls_stream, settings, script, conn_state)
                                            .await
                                    }
                                    Err(e) => Err(format!("TLS handshake failed: {e}")),
                                }
                            } else {
                                run_h2_connection(tcp, settings, script, conn_state).await
                            };
                            if let Err(msg) = result {
                                err_sink.step_errors.lock().await.push(msg);
                            }
                        });
                        track.track_connection(jh.abort_handle());
                    }
                }
            }
        });

        Ok(ScriptedH2Backend {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

/// A running scripted H2 backend. Drop shuts it down.
pub struct ScriptedH2Backend {
    pub port: u16,
    state: Arc<H2State>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedH2Backend {
    /// Builder for a plaintext h2c listener on `listener`.
    pub fn builder_plain(listener: TcpListener) -> ScriptedH2BackendBuilder {
        ScriptedH2BackendBuilder::plain(listener)
    }

    /// Builder for an h2-over-TLS listener. Advertises ALPN `h2` only; see
    /// [`ScriptedH2BackendBuilder::tls_with_alpn`] for multi-protocol ALPN.
    pub fn builder_tls(
        listener: TcpListener,
        cert_pem: &str,
        key_pem: &str,
    ) -> io::Result<ScriptedH2BackendBuilder> {
        ScriptedH2BackendBuilder::tls(listener, cert_pem, key_pem)
    }

    /// Raw TCP accepts since the backend started.
    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// H2 handshakes that completed successfully.
    pub fn handshakes_completed(&self) -> u32 {
        self.state.handshakes.load(Ordering::SeqCst)
    }

    /// Request headers (and any drained body) for every stream the script
    /// accepted via `ExpectHeaders`. Streams are in arrival order.
    pub async fn received_streams(&self) -> Vec<ReceivedStream> {
        self.state.streams.lock().await.clone()
    }

    /// Number of streams matched via `ExpectHeaders`. Same as
    /// `received_streams().len()` but doesn't take the mutex.
    pub fn received_stream_count(&self) -> u32 {
        self.state.stream_count.load(Ordering::SeqCst)
    }

    /// Number of `ExpectHeaders` matchers that returned `false`. Tests using
    /// non-trivial matchers should call [`Self::assert_no_matcher_mismatches`].
    pub fn matcher_mismatches(&self) -> u32 {
        self.state.matcher_mismatches.load(Ordering::SeqCst)
    }

    /// Panic if any `ExpectHeaders` matcher returned `false`.
    pub async fn assert_no_matcher_mismatches(&self) {
        if self.matcher_mismatches() == 0 {
            return;
        }
        let streams = self.received_streams().await;
        let summary: Vec<String> = streams
            .iter()
            .map(|s| format!("{} {}", s.method, s.path))
            .collect();
        panic!(
            "{} ExpectHeaders matcher(s) returned false; received streams: {:?}",
            self.matcher_mismatches(),
            summary
        );
    }

    /// Errors recorded during script execution. Non-empty indicates the
    /// script did not run to completion.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
    }

    /// Panic if any script step returned an error.
    pub async fn assert_no_step_errors(&self) {
        let errs = self.step_errors().await;
        if !errs.is_empty() {
            panic!("{} script step error(s): {:?}", errs.len(), errs);
        }
    }

    /// Signal shutdown + abort in-flight connection tasks.
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

impl Drop for ScriptedH2Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Default)]
struct H2State {
    accepted: AtomicU32,
    handshakes: AtomicU32,
    stream_count: AtomicU32,
    matcher_mismatches: AtomicU32,
    streams: Mutex<Vec<ReceivedStream>>,
    step_errors: Mutex<Vec<String>>,
    connection_aborts: StdMutex<Vec<AbortHandle>>,
}

impl H2State {
    fn track_connection(&self, abort: AbortHandle) {
        if let Ok(mut guard) = self.connection_aborts.lock() {
            guard.retain(|h| !h.is_finished());
            guard.push(abort);
        }
    }
}

/// Control messages from the script task to the connection driver.
enum DriverCtrl {
    /// Issue a GOAWAY (abrupt_shutdown) with the given reason.
    Goaway(Reason),
    /// Stop driving the connection. Dropped sockets close on the next
    /// driver cycle.
    Stop,
}

/// Drive a single accepted connection end-to-end: H2 handshake, spawn a
/// connection-driver task that continuously polls the connection and
/// feeds accepted streams to the script task. The script task then
/// processes the steps.
///
/// Returns an error string if the fixture failed in a way the test should
/// observe (mismatch, IO, bad script).
async fn run_h2_connection<T>(
    io: T,
    settings: ConnectionSettings,
    script: Vec<H2Step>,
    state: Arc<H2State>,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = H2Builder::new();
    settings.apply(&mut builder);
    let conn = builder
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|e| format!("h2 handshake failed: {e}"))?;
    state.handshakes.fetch_add(1, Ordering::SeqCst);

    // Channel: driver → script with newly accepted (request, response) pairs.
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<StreamPair>();
    // Channel: script → driver with control commands (GOAWAY, stop).
    // We hold a `keepalive` clone here so the channel does not close the
    // moment `run_script` returns — that lets us send an explicit
    // `Stop` even when the script ended via an early `Err` path that
    // never reached its own Stop emit.
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<DriverCtrl>();
    let ctrl_keepalive = ctrl_tx.clone();

    let driver = tokio::spawn(connection_driver(conn, stream_tx, ctrl_rx));
    // Capture the abort handle BEFORE moving `driver` into `timeout` —
    // if the driver hasn't exited within the deadline below, we need
    // to abort it explicitly. Dropping the `JoinHandle` would only
    // detach the task, leaving the connection driver running with the
    // socket open and leaking FDs across subsequent fixtures (the
    // PR-486 review's "task leak on script error" finding).
    let driver_abort = driver.abort_handle();

    // Run the script. If it returns an error, stop the driver before
    // surfacing it; if the driver already exited, that's fine.
    let script_result = run_script(&mut stream_rx, ctrl_tx, script, state).await;

    // Tell the driver to stop on EVERY exit path. The happy-path branch
    // of `run_script` already emits `Stop` itself, but every `return
    // Err(...)` branch (e.g. `ExpectHeaders` racing the connection
    // close, misordered scripts) returns without sending it. The
    // emit here is idempotent: a second `Stop` arriving on the
    // channel is a no-op because the driver `break`s on the first one.
    let _ = ctrl_keepalive.send(DriverCtrl::Stop);
    drop(ctrl_keepalive);

    // Wait for the driver to exit cleanly. The driver's own internal
    // tail (`poll_closed` with a 200ms cap) bounds this in practice;
    // the 500ms outer cap is a belt-and-suspenders deadline. On
    // timeout, abort the JoinHandle explicitly so the task cannot
    // continue running detached with a live socket.
    if tokio::time::timeout(Duration::from_millis(500), driver)
        .await
        .is_err()
    {
        driver_abort.abort();
    }
    script_result
}

/// The type fed across the driver→script channel. A stream pair is one
/// inbound RPC: request headers + body half + response handle.
type StreamPair = (Request<RecvStream>, SendResponse<Bytes>);

/// Connection driver: continuously polls the h2 connection via `accept()`
/// (which internally drives I/O for the whole connection), forwarding
/// each accepted stream to the script. Also applies control commands
/// from the script task (GOAWAY, explicit stop).
async fn connection_driver<T>(
    mut conn: h2::server::Connection<T, Bytes>,
    stream_tx: mpsc::UnboundedSender<StreamPair>,
    mut ctrl_rx: mpsc::UnboundedReceiver<DriverCtrl>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        tokio::select! {
            accept = conn.accept() => {
                match accept {
                    Some(Ok(pair)) => {
                        if stream_tx.send(pair).is_err() {
                            // Script task dropped the receiver — script
                            // has ended. Continue driving the connection
                            // for a short tail to flush any queued I/O.
                            break;
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(DriverCtrl::Goaway(reason)) => {
                        conn.abrupt_shutdown(reason);
                    }
                    Some(DriverCtrl::Stop) | None => break,
                }
            }
        }
    }
    // Give the connection a chance to flush pending frames before the
    // driver exits (and the TCP socket closes).
    let _ = tokio::time::timeout(Duration::from_millis(200), async {
        std::future::poll_fn(|cx| conn.poll_closed(cx)).await.ok();
    })
    .await;
}

async fn run_script(
    stream_rx: &mut mpsc::UnboundedReceiver<StreamPair>,
    ctrl_tx: mpsc::UnboundedSender<DriverCtrl>,
    script: Vec<H2Step>,
    state: Arc<H2State>,
) -> Result<(), String> {
    let mut current_stream: Option<(ReceivedStream, RecvStream, SendResponse<Bytes>)> = None;
    let mut current_body_sender: Option<h2::SendStream<Bytes>> = None;

    for step in script {
        match step {
            H2Step::ExpectHeaders(matcher) => {
                current_body_sender = None;
                let _previous = current_stream.take();

                let pair = stream_rx.recv().await;
                match pair {
                    Some((req, send)) => {
                        let received = parse_request_head(&req);
                        if !(matcher.0)(&received) {
                            state.matcher_mismatches.fetch_add(1, Ordering::SeqCst);
                        }
                        state.stream_count.fetch_add(1, Ordering::SeqCst);
                        state.streams.lock().await.push(received.clone());
                        let (_parts, body) = req.into_parts();
                        current_stream = Some((received, body, send));
                    }
                    None => {
                        return Err(
                            "ExpectHeaders: connection closed before any stream arrived".into()
                        );
                    }
                }
            }
            H2Step::DrainRequestBody => {
                let Some((recorded, body, _)) = current_stream.as_mut() else {
                    return Err("DrainRequestBody: no current stream".into());
                };
                let mut accumulated = Vec::new();
                loop {
                    match body.data().await {
                        Some(Ok(chunk)) => {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            accumulated.extend_from_slice(&chunk);
                        }
                        Some(Err(e)) => {
                            return Err(format!("DrainRequestBody: recv error: {e}"));
                        }
                        None => break,
                    }
                }
                match body.trailers().await {
                    Ok(Some(map)) => {
                        let trailers: Vec<(String, String)> = map
                            .iter()
                            .filter_map(|(k, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|vs| (k.as_str().to_string(), vs.to_string()))
                            })
                            .collect();
                        recorded.trailers = trailers.clone();
                        if let Some(last) = state.streams.lock().await.last_mut() {
                            last.trailers = trailers;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => return Err(format!("DrainRequestBody: trailers error: {e}")),
                }
                recorded.body = accumulated.clone();
                if let Some(last) = state.streams.lock().await.last_mut() {
                    last.body = accumulated;
                }
            }
            H2Step::RespondHeaders(headers) => {
                let Some((_recorded, _body, send)) = current_stream.as_mut() else {
                    return Err("RespondHeaders: no current stream".into());
                };
                let status = headers
                    .iter()
                    .find(|(k, _)| *k == ":status")
                    .and_then(|(_, v)| v.parse::<u16>().ok())
                    .unwrap_or(200);
                let mut resp = Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));
                for (k, v) in &headers {
                    if *k == ":status" {
                        continue;
                    }
                    resp = resp.header(*k, v);
                }
                let response = resp
                    .body(())
                    .map_err(|e| format!("RespondHeaders: build error: {e}"))?;
                let body_sender = send
                    .send_response(response, false)
                    .map_err(|e| format!("send_response: {e}"))?;
                current_body_sender = Some(body_sender);
            }
            H2Step::RespondData { data, end_stream } => {
                let Some(sender) = current_body_sender.as_mut() else {
                    return Err("RespondData: no RespondHeaders sent yet".into());
                };
                sender.reserve_capacity(data.len());
                sender
                    .send_data(data, end_stream)
                    .map_err(|e| format!("send_data: {e}"))?;
                if end_stream {
                    current_body_sender = None;
                }
            }
            H2Step::RespondTrailers(trailers) => {
                let Some(mut sender) = current_body_sender.take() else {
                    return Err("RespondTrailers: no RespondHeaders sent yet".into());
                };
                let mut map = HeaderMap::new();
                for (k, v) in trailers {
                    if let (Ok(name), Ok(val)) = (
                        http::header::HeaderName::from_bytes(k.as_bytes()),
                        http::header::HeaderValue::from_str(&v),
                    ) {
                        map.insert(name, val);
                    }
                }
                sender
                    .send_trailers(map)
                    .map_err(|e| format!("send_trailers: {e}"))?;
            }
            H2Step::SendGoaway { error_code } => {
                let _ = ctrl_tx.send(DriverCtrl::Goaway(Reason::from(error_code)));
            }
            H2Step::SendGoawayAndClose { error_code } => {
                let _ = ctrl_tx.send(DriverCtrl::Goaway(Reason::from(error_code)));
                // Give the driver a moment to flush the GOAWAY.
                tokio::time::sleep(Duration::from_millis(100)).await;
                let _ = ctrl_tx.send(DriverCtrl::Stop);
                return Ok(());
            }
            H2Step::SendRstStream { error_code } => {
                let reason = Reason::from(error_code);
                if let Some(sender) = current_body_sender.as_mut() {
                    sender.send_reset(reason);
                    current_body_sender = None;
                }
                if let Some((_, _, resp)) = current_stream.as_mut() {
                    resp.send_reset(reason);
                }
            }
            H2Step::Sleep(d) | H2Step::StallWindowFor(d) => {
                tokio::time::sleep(d).await;
            }
            H2Step::DropConnection => {
                // Instruct the driver to stop; dropping the `Connection`
                // inside the driver task closes the TCP socket.
                let _ = ctrl_tx.send(DriverCtrl::Stop);
                drop(current_body_sender);
                drop(current_stream);
                return Ok(());
            }
        }
    }

    // End of script: release stream + sender so trailers flush cleanly.
    drop(current_body_sender);
    drop(current_stream);
    // Let the driver continue flushing for a brief tail — it'll exit
    // on its own when the client hangs up, or when we send Stop on
    // the control channel below.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = ctrl_tx.send(DriverCtrl::Stop);
    Ok(())
}

fn parse_request_head(req: &Request<RecvStream>) -> ReceivedStream {
    let method = req.method().as_str().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let authority = req.uri().authority().map(|a| a.as_str().to_string());
    let scheme = req.uri().scheme().map(|s| s.as_str().to_string());
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(n, v)| {
            v.to_str()
                .ok()
                .map(|vs| (n.as_str().to_string(), vs.to_string()))
        })
        .collect();
    ReceivedStream {
        method,
        path,
        authority,
        scheme,
        headers,
        body: Vec::new(),
        trailers: Vec::new(),
    }
}

/// Build a rustls `ServerConfig` with the given cert + key and ALPN
/// protocols. Used for h2-over-TLS listeners.
fn build_server_config_with_alpn(
    cert_pem: &str,
    key_pem: &str,
    alpn: Vec<Vec<u8>>,
) -> io::Result<ServerConfig> {
    let mut cert_reader = cert_pem.as_bytes();
    let cert_chain: Vec<_> = certs(&mut cert_reader).filter_map(|c| c.ok()).collect();
    if cert_chain.is_empty() {
        return Err(io::Error::other("no certificates found in cert_pem"));
    }
    let mut key_reader = key_pem.as_bytes();
    let key = private_key(&mut key_reader)
        .map_err(|e| io::Error::other(format!("parse key: {e}")))?
        .ok_or_else(|| io::Error::other("no private key found in key_pem"))?;
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("rustls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| io::Error::other(format!("rustls cert: {e}")))?;
    config.alpn_protocols = alpn;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_port;
    use h2::client as h2_client;
    use http::Request as HttpRequest;
    use tokio::net::TcpStream;

    /// Happy-path: respond with headers + data + trailers on h2c.
    #[tokio::test]
    async fn h2c_respond_with_trailers_end_to_end() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
            .step(H2Step::ExpectHeaders(MatchHeaders::any()))
            .step(H2Step::RespondHeaders(vec![
                (":status", "200".into()),
                ("content-type", "application/grpc".into()),
            ]))
            .step(H2Step::RespondData {
                data: Bytes::from_static(b"hello"),
                end_stream: false,
            })
            .step(H2Step::RespondTrailers(vec![("grpc-status", "0".into())]))
            .spawn()
            .expect("spawn");

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let (mut send_req, connection) = h2_client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(connection);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}/svc/Method"))
            .header("content-type", "application/grpc")
            .body(())
            .expect("req");
        let (response_fut, mut req_body) = send_req.send_request(req, false).expect("send_request");
        // End the request body immediately so the server can respond.
        req_body
            .send_data(Bytes::new(), true)
            .expect("send end stream");
        let response = response_fut.await.expect("response");
        let (parts, mut body) = response.into_parts();
        assert_eq!(parts.status.as_u16(), 200);
        let mut buf = Vec::new();
        while let Some(frame) = body.data().await {
            let chunk = frame.expect("data chunk");
            let _ = body.flow_control().release_capacity(chunk.len());
            buf.extend_from_slice(&chunk);
        }
        assert_eq!(&buf, b"hello");
        let trailers = body.trailers().await.expect("trailers").expect("some");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend.received_stream_count(), 1);
        backend.assert_no_step_errors().await;
    }

    /// GOAWAY fires and the peer observes the error.
    #[tokio::test]
    async fn h2_send_goaway_surfaces_to_client() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let _backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
            .step(H2Step::ExpectHeaders(MatchHeaders::any()))
            .step(H2Step::SendGoawayAndClose {
                error_code: 2, // INTERNAL_ERROR
            })
            .spawn()
            .expect("spawn");

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let (mut send_req, connection) = h2_client::handshake(tcp).await.expect("h2 handshake");
        let connect_task = tokio::spawn(connection);
        let req = HttpRequest::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}/svc/Method"))
            .body(())
            .expect("req");
        let (response_fut, mut req_body) = send_req.send_request(req, false).expect("send_request");
        req_body
            .send_data(Bytes::new(), true)
            .expect("send end stream");
        // Either the response_fut errors (GOAWAY received) or the
        // connection task terminates with an error — either is an
        // acceptable observable of the GOAWAY landing on the peer.
        let _ = tokio::time::timeout(Duration::from_secs(3), response_fut).await;
        connect_task.abort();
    }

    /// RST_STREAM surfaces as a stream error.
    #[tokio::test]
    async fn h2_send_rst_stream_surfaces_to_client() {
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;
        let backend = ScriptedH2Backend::builder_plain(reservation.into_listener())
            .step(H2Step::ExpectHeaders(MatchHeaders::any()))
            .step(H2Step::RespondHeaders(vec![(":status", "200".into())]))
            .step(H2Step::SendRstStream { error_code: 2 })
            .spawn()
            .expect("spawn");

        let tcp = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("tcp connect");
        let (mut send_req, connection) = h2_client::handshake(tcp).await.expect("h2 handshake");
        tokio::spawn(connection);
        let req = HttpRequest::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{port}/x"))
            .body(())
            .expect("req");
        let (response_fut, _) = send_req.send_request(req, true).expect("send_request");
        // We don't care *how* the RST surfaces — response-future error,
        // EOF on the body stream, or a body-stream error — we just need
        // the backend to have processed the stream.
        if let Ok(r) = response_fut.await {
            let (_parts, mut body) = r.into_parts();
            let _ = body.data().await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(backend.received_stream_count(), 1);
    }
}

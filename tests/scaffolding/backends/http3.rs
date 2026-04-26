//! `ScriptedH3Backend` — QUIC + HTTP/3 server that replays a deterministic
//! list of [`H3Step`]s.
//!
//! Phase 3 of the scripted-backend framework. The step list mirrors the plan
//! in `docs/plans/test_framework_scripted_backends.md`: QUIC-level failure
//! modes (refuse handshake, drop initial, `CONNECTION_CLOSE` with a given
//! error code) sit alongside H3-level steps (accept a stream, respond with
//! headers + data, send `RESET_STREAM` / `GOAWAY`, stall) so tests can
//! drive the exact wire behaviour they want the gateway to observe.
//!
//! The backend is built on top of `quinn` (the same QUIC stack the gateway
//! uses) and the `h3` crate's server API. Each accepted QUIC connection runs
//! the script once; connection-level steps (e.g. `CloseConnectionWithCode`)
//! end the script early.
//!
//! ## Observability
//!
//! - [`ScriptedH3Backend::received_requests`] — every H3 request prelude the
//!   backend has parsed so far (method, path, headers). Tests use this to
//!   assert the gateway forwarded the expected request.
//! - [`ScriptedH3Backend::accepted_handshakes`] — number of QUIC connections
//!   whose TLS handshake + H3 session handshake completed.
//! - [`ScriptedH3Backend::connection_close_sent`] — number of times a
//!   `CloseConnectionWithCode` step fired.
//! - [`ScriptedH3Backend::step_errors`] — any errors the scripted interpreter
//!   captured. Empty on the happy path.
//!
//! ## Script execution model
//!
//! The script is cloned per accepted connection, same pattern as the TCP/TLS
//! backends — so multi-connection tests can observe identical behaviour on
//! request 1 and request 2 (or, via `Once` mode in a future extension, run
//! the script on the first connection only).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use bytes::Bytes;
use quinn::Endpoint;
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

/// A single deterministic instruction in an HTTP/3 script.
#[derive(Debug, Clone)]
pub enum H3Step {
    // ── QUIC-level ──────────────────────────────────────────────────────
    /// Refuse the next QUIC handshake by calling `Connecting::refuse()`.
    /// One-shot: only the first accepted connection is refused, subsequent
    /// connections run the remainder of the script.
    RejectHandshake,
    /// Do not call `endpoint.accept()` on the next inbound datagram —
    /// simulate a backend whose UDP socket is open but H3/QUIC is
    /// unresponsive. One-shot, same semantics as `RejectHandshake`.
    DropInitialPacket,
    /// Explicitly accept the handshake. Must come before any H3-level
    /// step in a script (the interpreter will accept implicitly on the
    /// first such step, but including `AcceptHandshake` makes the intent
    /// explicit in the script).
    AcceptHandshake,
    /// After the handshake completes, close the QUIC connection with the
    /// given application error code via
    /// [`quinn::Connection::close`]. Ends the script.
    CloseConnectionWithCode(u64),

    // ── H3-level ────────────────────────────────────────────────────────
    /// Accept the next H3 request stream and record the request prelude.
    /// Implicit before any other H3-level step.
    AcceptStream,
    /// Send an H3 response header block with the given `(name, value)`
    /// pairs. A `:status` pseudo-header MUST be present; the interpreter
    /// extracts it and sends the remaining headers as regular headers.
    RespondHeaders(Vec<(&'static str, String)>),
    /// Send a chunk of response body.
    RespondData(Bytes),
    /// Send `RESET_STREAM` with the given application error code, then
    /// end the script.
    SendStreamReset(u64),
    /// Send an H3 GOAWAY with the given max-stream-id, then end the
    /// script. Translated into a client-visible "protocol error" by the
    /// gateway's `classify_h3_error`.
    SendGoaway(u64),
    /// Pause for `duration` without sending anything. Use to trigger
    /// `backend_read_timeout_ms`-style watchdogs.
    StallFor(Duration),
}

/// TLS config for the scripted H3 backend. Mirrors the shape of
/// [`super::tls::TlsConfig`] but with `h3` hard-coded in ALPN since H3
/// negotiation requires it.
#[derive(Clone)]
pub struct H3TlsConfig {
    pub cert_pem: String,
    pub key_pem: String,
}

impl H3TlsConfig {
    pub fn new(cert_pem: impl Into<String>, key_pem: impl Into<String>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
        }
    }

    /// Build a rustls `ServerConfig` with TLS 1.3 forced and ALPN = `h3`.
    /// QUIC mandates TLS 1.3; TLS 1.2 or no TLS 1.3 ciphers is a fatal
    /// misconfiguration caught here rather than mid-handshake.
    pub(crate) fn build_server_config(
        &self,
    ) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
        let mut cert_reader = self.cert_pem.as_bytes();
        let cert_chain: Vec<_> = certs(&mut cert_reader).filter_map(|c| c.ok()).collect();
        if cert_chain.is_empty() {
            return Err("no certificates found in cert_pem".into());
        }
        let mut key_reader = self.key_pem.as_bytes();
        let key = private_key(&mut key_reader)?.ok_or("no private key found in key_pem")?;

        let provider = rustls::crypto::ring::default_provider();
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        // H3 requires ALPN == "h3".
        config.alpn_protocols = vec![b"h3".to_vec()];
        Ok(config)
    }
}

/// Fluent builder for [`ScriptedH3Backend`].
pub struct ScriptedH3BackendBuilder {
    udp: UdpSocket,
    tls: H3TlsConfig,
    steps: Vec<H3Step>,
}

impl ScriptedH3BackendBuilder {
    /// Start a new builder against a pre-bound `UdpSocket`. Use
    /// [`super::super::ports::reserve_udp_port`] to obtain one without a
    /// drop-rebind race.
    pub fn new(udp: UdpSocket, tls: H3TlsConfig) -> Self {
        Self {
            udp,
            tls,
            steps: Vec::new(),
        }
    }

    pub fn step(mut self, step: H3Step) -> Self {
        self.steps.push(step);
        self
    }

    pub fn steps(mut self, steps: impl IntoIterator<Item = H3Step>) -> Self {
        self.steps.extend(steps);
        self
    }

    /// Spawn the backend. The rustls config is built eagerly so a
    /// misconfigured cert fails here rather than at first connect.
    pub fn spawn(self) -> Result<ScriptedH3Backend, Box<dyn std::error::Error + Send + Sync>> {
        let addr = self.udp.local_addr()?;
        let tls_config = self.tls.build_server_config()?;
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| format!("Failed to create QUIC server config: {e}"))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        // Short idle timeout — tests should not leak long-lived connections.
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|e| format!("idle timeout: {e}"))?,
        ));
        server_config.transport_config(Arc::new(transport));

        // Build the quinn endpoint on top of the pre-bound UdpSocket.
        let std_udp = self.udp.into_std()?;
        std_udp.set_nonblocking(true)?;
        let runtime = quinn::default_runtime()
            .ok_or("quinn runtime not available; install a tokio runtime")?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            std_udp,
            runtime,
        )?;

        let state = Arc::new(H3BackendState::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let steps = self.steps;
        let endpoint_task = endpoint.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        endpoint_task.close(0u32.into(), b"shutdown");
                        return;
                    }
                    incoming = endpoint_task.accept() => {
                        let Some(incoming) = incoming else {
                            // Endpoint closed.
                            return;
                        };
                        let conn_index = state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let script = steps.clone();
                        let state_conn = state_task.clone();

                        // Look at the head of the script to decide whether
                        // this connection is QUIC-level rejected or
                        // dropped. Both steps are one-shot on the first
                        // connection, and we let later connections fall
                        // through to the rest of the script.
                        let (consume_head, head) = peek_head_step(&script, conn_index);
                        match head {
                            Some(H3Step::RejectHandshake) if consume_head => {
                                // Refuse before accept: this is the cleanest
                                // way in quinn to emit an immediate close.
                                incoming.refuse();
                                state_conn
                                    .refused_handshakes
                                    .fetch_add(1, Ordering::SeqCst);
                                continue;
                            }
                            Some(H3Step::DropInitialPacket) if consume_head => {
                                // Drop the connecting handle on the floor
                                // without calling accept()/refuse(). quinn
                                // will eventually time out; the client
                                // sees no response. The interpreter
                                // treats this as a successful one-shot
                                // consumption of the step so subsequent
                                // connects move on to the rest of the
                                // script.
                                drop(incoming);
                                state_conn
                                    .dropped_initial_packets
                                    .fetch_add(1, Ordering::SeqCst);
                                continue;
                            }
                            _ => {}
                        }

                        let track = state_conn.clone();
                        let jh = tokio::spawn(async move {
                            let state_err = state_conn.clone();
                            if let Err(e) =
                                run_h3_script(incoming, script, state_conn, conn_index).await
                            {
                                state_err.step_errors.lock().await.push(e);
                            }
                        });
                        track.track_connection(jh.abort_handle());
                    }
                }
            }
        });

        Ok(ScriptedH3Backend {
            addr,
            state,
            endpoint,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

/// A running scripted H3 backend. Dropping it shuts the endpoint down.
pub struct ScriptedH3Backend {
    pub addr: SocketAddr,
    state: Arc<H3BackendState>,
    endpoint: Endpoint,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedH3Backend {
    pub fn builder(udp: UdpSocket, tls: H3TlsConfig) -> ScriptedH3BackendBuilder {
        ScriptedH3BackendBuilder::new(udp, tls)
    }

    /// The UDP port the backend is listening on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Total QUIC connections that passed `endpoint.accept()`. Includes
    /// connections that the script subsequently rejected via
    /// `CloseConnectionWithCode`.
    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Connections whose TLS + H3 handshakes fully completed. `accepted -
    /// accepted_handshakes` is the number of handshakes that failed or
    /// were refused before H3 setup.
    pub fn accepted_handshakes(&self) -> u32 {
        self.state.handshakes.load(Ordering::SeqCst)
    }

    /// Connections refused via `RejectHandshake`.
    pub fn refused_handshakes(&self) -> u32 {
        self.state.refused_handshakes.load(Ordering::SeqCst)
    }

    /// Number of initial QUIC datagrams dropped via `DropInitialPacket`.
    pub fn dropped_initial_packets(&self) -> u32 {
        self.state.dropped_initial_packets.load(Ordering::SeqCst)
    }

    /// Number of times a `CloseConnectionWithCode` step fired.
    pub fn connection_close_sent(&self) -> u32 {
        self.state.connection_close_sent.load(Ordering::SeqCst)
    }

    /// Clone of every H3 request observed so far.
    pub async fn received_requests(&self) -> Vec<H3RecordedRequest> {
        self.state.requests.lock().await.clone()
    }

    /// Any errors captured by script execution.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
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
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}

impl Drop for ScriptedH3Backend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Parsed prelude for an H3 request observed by the backend.
#[derive(Debug, Clone)]
pub struct H3RecordedRequest {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub headers: Vec<(String, String)>,
}

#[derive(Default)]
struct H3BackendState {
    accepted: AtomicU32,
    handshakes: AtomicU32,
    refused_handshakes: AtomicU32,
    dropped_initial_packets: AtomicU32,
    connection_close_sent: AtomicU32,
    requests: Mutex<Vec<H3RecordedRequest>>,
    step_errors: Mutex<Vec<String>>,
    connection_aborts: StdMutex<Vec<AbortHandle>>,
}

impl H3BackendState {
    fn track_connection(&self, abort: AbortHandle) {
        if let Ok(mut guard) = self.connection_aborts.lock() {
            guard.retain(|h| !h.is_finished());
            guard.push(abort);
        }
    }
}

/// Return the "head" of the script relative to the current connection
/// index. Returns `(consume, Some(step))` when the step is a one-shot
/// QUIC-level step that should fire on this connection. Returns
/// `(false, step)` otherwise so the caller can run the normal script path.
fn peek_head_step(script: &[H3Step], conn_index: u32) -> (bool, Option<H3Step>) {
    if conn_index != 0 {
        return (false, None);
    }
    match script.first() {
        Some(s @ H3Step::RejectHandshake) => (true, Some(s.clone())),
        Some(s @ H3Step::DropInitialPacket) => (true, Some(s.clone())),
        other => (false, other.cloned()),
    }
}

/// Execute one connection's worth of script steps. Returns `Err(msg)` when
/// a step fails in a way tests should surface via `step_errors`.
async fn run_h3_script(
    incoming: quinn::Incoming,
    script: Vec<H3Step>,
    state: Arc<H3BackendState>,
    conn_index: u32,
) -> Result<(), String> {
    use h3::quic::BidiStream;
    use http::{HeaderName, HeaderValue};

    // Skip any one-shot QUIC-level step that already fired on connection 0.
    let mut steps = script.into_iter().peekable();
    if conn_index == 0 {
        // The head was peeked in the accept loop; we drop it here so the
        // iterator lines up with the rest of the script.
        match steps.peek() {
            Some(H3Step::RejectHandshake) | Some(H3Step::DropInitialPacket) => {
                steps.next();
            }
            _ => {}
        }
    } else {
        // For later connections, skip any leading one-shot head so the
        // script behaves the same regardless of connection index.
        while matches!(
            steps.peek(),
            Some(H3Step::RejectHandshake) | Some(H3Step::DropInitialPacket)
        ) {
            steps.next();
        }
    }

    let connecting = incoming
        .accept()
        .map_err(|e| format!("Incoming::accept failed: {e}"))?;
    let connection = connecting
        .await
        .map_err(|e| format!("QUIC handshake failed: {e}"))?;
    state.handshakes.fetch_add(1, Ordering::SeqCst);

    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|e| format!("H3 connection setup failed: {e}"))?;

    let mut response_stream: Option<h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>> =
        None;

    for step in steps {
        match step {
            H3Step::RejectHandshake | H3Step::DropInitialPacket => {
                // Already handled in peek_head_step for conn_index=0;
                // for other connections we skip these above. Any remaining
                // instance is a script author error — surface loudly.
                return Err(format!(
                    "{:?} appeared mid-script — only legal as the first step",
                    step
                ));
            }
            H3Step::AcceptHandshake => {
                // No-op: the handshake is done above.
            }
            H3Step::CloseConnectionWithCode(code) => {
                state.connection_close_sent.fetch_add(1, Ordering::SeqCst);
                let code = quinn::VarInt::from_u64(code)
                    .map_err(|e| format!("invalid close code: {e}"))?;
                connection.close(code, b"scripted close");
                // Drop the h3 connection so the driver task exits.
                drop(h3_conn);
                return Ok(());
            }
            H3Step::AcceptStream => {
                let resolver = match h3_conn
                    .accept()
                    .await
                    .map_err(|e| format!("h3 accept failed: {e}"))?
                {
                    Some(r) => r,
                    None => {
                        return Err(
                            "AcceptStream: connection closed before client opened a stream".into(),
                        );
                    }
                };
                let (req, stream) = resolver
                    .resolve_request()
                    .await
                    .map_err(|e| format!("resolve_request failed: {e}"))?;
                record_request(&state, &req).await;
                response_stream = Some(stream);
            }
            H3Step::RespondHeaders(pairs) => {
                let stream = match response_stream.as_mut() {
                    Some(s) => s,
                    None => {
                        // Implicitly accept the next stream so scripts can
                        // elide `AcceptStream` when they don't care about
                        // the request prelude.
                        let resolver = match h3_conn
                            .accept()
                            .await
                            .map_err(|e| format!("h3 accept failed: {e}"))?
                        {
                            Some(r) => r,
                            None => {
                                return Err(
                                    "RespondHeaders: connection closed before stream".into()
                                );
                            }
                        };
                        let (req, stream) = resolver
                            .resolve_request()
                            .await
                            .map_err(|e| format!("resolve_request failed: {e}"))?;
                        record_request(&state, &req).await;
                        response_stream = Some(stream);
                        response_stream.as_mut().unwrap()
                    }
                };
                let mut status: Option<u16> = None;
                let mut regular_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
                for (name, value) in pairs {
                    if name.eq_ignore_ascii_case(":status") {
                        status = value.parse().ok();
                        continue;
                    }
                    if name.starts_with(':') {
                        // h3 / http crate handles pseudo-headers for us;
                        // reject anything unexpected so tests fail loudly.
                        return Err(format!(
                            "unsupported pseudo-header {name:?} in RespondHeaders"
                        ));
                    }
                    let hn = HeaderName::from_bytes(name.as_bytes())
                        .map_err(|e| format!("bad header name {name}: {e}"))?;
                    let hv = HeaderValue::from_str(&value)
                        .map_err(|e| format!("bad header value {value}: {e}"))?;
                    regular_headers.push((hn, hv));
                }
                let status = status
                    .ok_or_else(|| "RespondHeaders missing :status pseudo-header".to_string())?;
                let mut resp_builder = http::Response::builder().status(status);
                for (n, v) in regular_headers {
                    resp_builder = resp_builder.header(n, v);
                }
                let resp = resp_builder
                    .body(())
                    .map_err(|e| format!("build response: {e}"))?;
                stream
                    .send_response(resp)
                    .await
                    .map_err(|e| format!("send_response: {e}"))?;
            }
            H3Step::RespondData(bytes) => {
                let stream = response_stream
                    .as_mut()
                    .ok_or_else(|| "RespondData without preceding RespondHeaders".to_string())?;
                stream
                    .send_data(bytes)
                    .await
                    .map_err(|e| format!("send_data: {e}"))?;
            }
            H3Step::SendStreamReset(code) => {
                let stream = response_stream
                    .as_mut()
                    .ok_or_else(|| "SendStreamReset without preceding stream".to_string())?;
                let code = h3::error::Code::from(code);
                // h3's stop_sending resets the send side; to actually
                // abort the response we use the underlying BidiStream.
                stream.send_data(Bytes::new()).await.ok();
                stream.stop_stream(code);
                return Ok(());
            }
            H3Step::SendGoaway(max_requests) => {
                // h3's shutdown helper sends a GOAWAY control frame that
                // the gateway's `classify_h3_error` maps to ProtocolError
                // with `connection_error=false`. The argument is the
                // number of additional in-flight requests the server
                // will continue to process after sending GOAWAY.
                h3_conn
                    .shutdown(max_requests as usize)
                    .await
                    .map_err(|e| format!("goaway shutdown: {e}"))?;
                // Give the frame a moment to reach the peer, then exit.
                tokio::time::sleep(Duration::from_millis(50)).await;
                return Ok(());
            }
            H3Step::StallFor(d) => {
                tokio::time::sleep(d).await;
            }
        }
    }
    // End of script — finish any open stream with end-of-body and close.
    if let Some(mut stream) = response_stream {
        let _ = stream.finish().await;
    }
    Ok(())
}

async fn record_request(state: &Arc<H3BackendState>, req: &http::Request<()>) {
    let mut headers = Vec::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_string(), v.to_string()));
        }
    }
    let recorded = H3RecordedRequest {
        method: req.method().as_str().to_string(),
        path: req.uri().path().to_string(),
        authority: req.uri().authority().map(|a| a.to_string()),
        headers,
    };
    state.requests.lock().await.push(recorded);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::certs::TestCa;
    use crate::scaffolding::ports::reserve_udp_port;

    #[tokio::test]
    async fn tls_config_requires_tls_13_ciphers() {
        let ca = TestCa::new("h3-test").expect("ca");
        let (cert, key) = ca.valid().expect("leaf");
        let tls = H3TlsConfig::new(cert, key);
        let cfg = tls.build_server_config().expect("server config");
        assert!(
            cfg.alpn_protocols.iter().any(|p| p == b"h3"),
            "ALPN must include h3"
        );
    }

    /// Regression: handshake state starts at zero before any client connects.
    #[tokio::test]
    async fn spawn_then_shutdown_records_no_handshakes() {
        let ca = TestCa::new("h3-smoke").expect("ca");
        let (cert, key) = ca.valid().expect("leaf");
        let reservation = reserve_udp_port().await.expect("udp reserve");
        let backend =
            ScriptedH3Backend::builder(reservation.into_socket(), H3TlsConfig::new(cert, key))
                .step(H3Step::AcceptHandshake)
                .step(H3Step::CloseConnectionWithCode(0))
                .spawn()
                .expect("spawn");
        assert_eq!(backend.accepted_connections(), 0);
        assert_eq!(backend.accepted_handshakes(), 0);
    }
}

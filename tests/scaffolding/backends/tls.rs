//! `ScriptedTlsBackend` — a TLS-terminating wrapper around
//! [`super::tcp::ScriptedTcpBackend`].
//!
//! The backend accepts TCP, negotiates TLS with a caller-configured
//! [`TlsConfig`], and then replays a script of TCP-level steps through the
//! TLS stream. Same observability surface as the TCP backend
//! (`received_bytes`, `accepted_connections`) plus [`handshakes_completed`]
//! for TLS-specific assertions.
//!
//! ## ALPN scripting
//!
//! `TlsConfig::alpn` is the list of ALPN protocols advertised by the server.
//! rustls negotiates the highest-priority protocol both sides support; if the
//! test wants to assert a specific fallback (e.g., "advertise h2+http/1.1
//! but always select http/1.1"), the test can set `alpn = vec!["http/1.1"]`
//! which forces h2 clients to fall back. The gateway's H2 pool sees the
//! TLS handshake negotiate `http/1.1`, marks the pool key as
//! `BackendSelectedHttp1`, and `Http2ConnectionPool::is_known_http1_backend`
//! returns `true` on the next probe — that's the H2 ALPN fallback test.

use super::tcp::{ExecutionMode, StepError, TcpStep};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

/// Static configuration for the TLS handshake.
#[derive(Clone)]
pub struct TlsConfig {
    /// PEM-encoded server certificate chain.
    pub cert_pem: String,
    /// PEM-encoded server private key.
    pub key_pem: String,
    /// ALPN protocols to advertise, in server preference order. Empty = no ALPN.
    pub alpn: Vec<Vec<u8>>,
    /// Delay inserted after the TCP accept and before starting the TLS
    /// handshake. Useful for timeout tests where the gateway must give up
    /// before the TLS handshake completes.
    pub handshake_delay: Duration,
}

impl TlsConfig {
    /// Shorthand: build a `TlsConfig` with the given cert and key PEM and no
    /// ALPN, no handshake delay, no client-auth.
    pub fn new(cert_pem: impl Into<String>, key_pem: impl Into<String>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: key_pem.into(),
            alpn: Vec::new(),
            handshake_delay: Duration::ZERO,
        }
    }

    /// Advertise the provided ALPN protocols (byte vectors, e.g. `b"h2".to_vec()`).
    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Delay before starting the TLS handshake.
    pub fn with_handshake_delay(mut self, delay: Duration) -> Self {
        self.handshake_delay = delay;
        self
    }

    /// Build the rustls `ServerConfig`.
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
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        config.alpn_protocols = self.alpn.clone();
        Ok(config)
    }
}

/// Fluent builder for [`ScriptedTlsBackend`].
pub struct ScriptedTlsBackendBuilder {
    listener: TcpListener,
    tls: TlsConfig,
    steps: Vec<TcpStep>,
    mode: ExecutionMode,
}

impl ScriptedTlsBackendBuilder {
    pub fn new(listener: TcpListener, tls: TlsConfig) -> Self {
        Self {
            listener,
            tls,
            steps: Vec::new(),
            mode: ExecutionMode::RepeatEachConnection,
        }
    }

    pub fn step(mut self, step: TcpStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn steps(mut self, steps: impl IntoIterator<Item = TcpStep>) -> Self {
        self.steps.extend(steps);
        self
    }

    pub fn once(mut self) -> Self {
        self.mode = ExecutionMode::Once;
        self
    }

    pub fn repeat_each_connection(mut self) -> Self {
        self.mode = ExecutionMode::RepeatEachConnection;
        self
    }

    /// Spawn the backend. The rustls `ServerConfig` is built eagerly so a
    /// misconfigured cert fails at spawn time, not at the first connect.
    pub fn spawn(self) -> Result<ScriptedTlsBackend, Box<dyn std::error::Error + Send + Sync>> {
        let port = self.listener.local_addr()?.port();
        let tls_config = self.tls.build_server_config()?;
        let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));
        let state = Arc::new(TlsBackendState::default());
        let state_task = state.clone();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let steps = self.steps;
        let mode = self.mode;
        let handshake_delay = self.tls.handshake_delay;
        let listener = self.listener;
        let acceptor_task = acceptor;

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => return,
                    accept_result = listener.accept() => {
                        let Ok((tcp, _addr)) = accept_result else { continue; };
                        let conn_index = state_task.accepted.fetch_add(1, Ordering::SeqCst);
                        let state_conn = state_task.clone();
                        let script = steps.clone();
                        let acceptor = acceptor_task.clone();
                        match mode {
                            ExecutionMode::RepeatEachConnection => {
                                let track = state_conn.clone();
                                let jh = tokio::spawn(async move {
                                    if handshake_delay > Duration::ZERO {
                                        tokio::time::sleep(handshake_delay).await;
                                    }
                                    let tls_stream = match acceptor.accept(tcp).await {
                                        Ok(s) => s,
                                        Err(_e) => return,
                                    };
                                    state_conn.handshakes.fetch_add(1, Ordering::SeqCst);
                                    // Record the negotiated ALPN for the most recent handshake
                                    // *and* append to the per-handshake history.
                                    let alpn = tls_stream
                                        .get_ref()
                                        .1
                                        .alpn_protocol()
                                        .map(|a| a.to_vec());
                                    *state_conn.last_alpn.lock().await = alpn.clone();
                                    state_conn.all_alpn.lock().await.push(alpn);
                                    let state_err = state_conn.clone();
                                    if let Err(e) =
                                        run_tls_script(tls_stream, script, state_conn).await
                                    {
                                        state_err.step_errors.lock().await.push(e.to_string());
                                    }
                                });
                                track.track_connection(jh.abort_handle());
                            }
                            ExecutionMode::Once => {
                                if conn_index == 0 {
                                    let track = state_conn.clone();
                                    let jh = tokio::spawn(async move {
                                        if handshake_delay > Duration::ZERO {
                                            tokio::time::sleep(handshake_delay).await;
                                        }
                                        let tls_stream = match acceptor.accept(tcp).await {
                                            Ok(s) => s,
                                            Err(_e) => return,
                                        };
                                        state_conn.handshakes.fetch_add(1, Ordering::SeqCst);
                                        let alpn = tls_stream
                                            .get_ref()
                                            .1
                                            .alpn_protocol()
                                            .map(|a| a.to_vec());
                                        *state_conn.last_alpn.lock().await = alpn.clone();
                                        state_conn.all_alpn.lock().await.push(alpn);
                                        let state_err = state_conn.clone();
                                        if let Err(e) =
                                            run_tls_script(tls_stream, script, state_conn).await
                                        {
                                            state_err
                                                .step_errors
                                                .lock()
                                                .await
                                                .push(e.to_string());
                                        }
                                    });
                                    track.track_connection(jh.abort_handle());
                                } else {
                                    drop(tcp);
                                }
                            }
                        }
                    }
                }
            }
        });

        Ok(ScriptedTlsBackend {
            port,
            state,
            handle: Some(handle),
            shutdown: Some(shutdown_tx),
        })
    }
}

#[derive(Default)]
struct TlsBackendState {
    accepted: AtomicU32,
    handshakes: AtomicU32,
    received_bytes: Mutex<Vec<u8>>,
    last_alpn: Mutex<Option<Vec<u8>>>,
    /// Every ALPN protocol negotiated so far, in chronological order. A
    /// handshake that didn't negotiate ALPN contributes `None`.
    all_alpn: Mutex<Vec<Option<Vec<u8>>>>,
    /// Errors returned by `run_tls_script`. See
    /// [`ScriptedTlsBackend::step_errors`] for rationale.
    step_errors: Mutex<Vec<String>>,
    /// AbortHandles for in-flight per-connection tasks (see
    /// `BackendState::connection_aborts` in `tcp.rs` for rationale).
    connection_aborts: StdMutex<Vec<AbortHandle>>,
}

impl TlsBackendState {
    fn track_connection(&self, abort: AbortHandle) {
        if let Ok(mut guard) = self.connection_aborts.lock() {
            guard.retain(|h| !h.is_finished());
            guard.push(abort);
        }
    }
}

/// A running scripted TLS backend. Drop shuts it down.
pub struct ScriptedTlsBackend {
    pub port: u16,
    state: Arc<TlsBackendState>,
    handle: Option<JoinHandle<()>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ScriptedTlsBackend {
    /// Shortcut for [`ScriptedTlsBackendBuilder::new`].
    pub fn builder(listener: TcpListener, tls: TlsConfig) -> ScriptedTlsBackendBuilder {
        ScriptedTlsBackendBuilder::new(listener, tls)
    }

    /// Total TCP accepts since start.
    pub fn accepted_connections(&self) -> u32 {
        self.state.accepted.load(Ordering::SeqCst)
    }

    /// Total TLS handshakes that have completed. `accepted - handshakes` is
    /// the number of handshake failures (RST, cert rejected, etc.).
    pub fn handshakes_completed(&self) -> u32 {
        self.state.handshakes.load(Ordering::SeqCst)
    }

    /// ALPN protocol negotiated on the most recent successful handshake,
    /// or `None` if no handshake has completed or ALPN was not advertised.
    pub async fn last_alpn(&self) -> Option<Vec<u8>> {
        self.state.last_alpn.lock().await.clone()
    }

    /// ALPN protocols negotiated across all successful handshakes (in
    /// order). A handshake with no ALPN shows up as `None`. Useful when
    /// the client makes multiple connections and the test only cares that
    /// at least one negotiated a specific protocol.
    pub async fn all_alpn(&self) -> Vec<Option<Vec<u8>>> {
        self.state.all_alpn.lock().await.clone()
    }

    /// Concatenated bytes read by all connections' script steps so far.
    pub async fn received_bytes(&self) -> Vec<u8> {
        self.state.received_bytes.lock().await.clone()
    }

    /// Whether `received_bytes()` contains `needle`. An empty needle
    /// returns `true` (matches the TCP variant); avoids the `windows(0)`
    /// panic path.
    pub async fn received_contains(&self, needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        let buf = self.received_bytes().await;
        buf.windows(needle.len()).any(|w| w == needle)
    }

    /// Errors captured from every script execution so far. Empty on the
    /// happy path; see [`ScriptedTcpBackend::step_errors`] for rationale.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
    }

    /// Panic if any script execution failed. Call this before test-side
    /// asserts when a short-read or I/O failure should fail the test
    /// rather than be silently discarded.
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

impl Drop for ScriptedTlsBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Adapter: run the TCP-level script against a TLS stream.
async fn run_tls_script(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    script: Vec<TcpStep>,
    state: Arc<TlsBackendState>,
) -> Result<(), StepError> {
    // See the matching comment in `tcp.rs::run_script` — preserves bytes
    // read past a `ReadUntil` needle for the next step.
    let mut leftover: Vec<u8> = Vec::new();
    for step in script {
        match step {
            TcpStep::Accept => {}
            TcpStep::ReadExact(n) => {
                let mut buf = vec![0u8; n];
                let mut read = 0;
                if !leftover.is_empty() {
                    let take = leftover.len().min(n);
                    buf[..take].copy_from_slice(&leftover[..take]);
                    leftover.drain(..take);
                    read = take;
                }
                while read < n {
                    match stream.read(&mut buf[read..]).await {
                        Ok(0) => {
                            state
                                .received_bytes
                                .lock()
                                .await
                                .extend_from_slice(&buf[..read]);
                            return Err(StepError::ShortRead {
                                expected: n,
                                actual: read,
                            });
                        }
                        Ok(m) => read += m,
                        Err(e) => return Err(StepError::Io(e)),
                    }
                }
                state
                    .received_bytes
                    .lock()
                    .await
                    .extend_from_slice(&buf[..read]);
            }
            TcpStep::ReadUntil(needle) => {
                // An empty needle would cause `windows(0)` to panic. Fail
                // loudly with a deterministic script error instead.
                if needle.is_empty() {
                    return Err(StepError::InvalidScript(
                        "ReadUntil needle must be non-empty".into(),
                    ));
                }
                let mut acc = std::mem::take(&mut leftover);
                let find = |bytes: &[u8]| -> Option<usize> {
                    bytes
                        .windows(needle.len())
                        .position(|w| w == needle.as_slice())
                };
                let mut boundary = find(&acc).map(|p| p + needle.len());
                let mut buf = [0u8; 4096];
                while boundary.is_none() {
                    match stream.read(&mut buf).await {
                        Ok(0) => {
                            state.received_bytes.lock().await.extend_from_slice(&acc);
                            return Err(StepError::ShortRead {
                                expected: needle.len(),
                                actual: acc.len(),
                            });
                        }
                        Ok(m) => {
                            acc.extend_from_slice(&buf[..m]);
                            boundary = find(&acc).map(|p| p + needle.len());
                        }
                        Err(e) => {
                            state.received_bytes.lock().await.extend_from_slice(&acc);
                            return Err(StepError::Io(e));
                        }
                    }
                }
                let end = boundary.expect("boundary set by loop exit");
                state
                    .received_bytes
                    .lock()
                    .await
                    .extend_from_slice(&acc[..end]);
                leftover = acc[end..].to_vec();
            }
            TcpStep::Write(bytes) => stream.write_all(&bytes).await?,
            TcpStep::Sleep(d) => tokio::time::sleep(d).await,
            TcpStep::Drop => {
                // Clean TLS shutdown: `close_notify` + FIN.
                let _ = stream.shutdown().await;
                return Ok(());
            }
            TcpStep::Reset => {
                // For TLS streams we can't trivially set SO_LINGER on the inner
                // socket without consuming the stream. Dropping is the closest
                // deterministic behaviour for TLS-reset tests.
                drop(stream);
                return Ok(());
            }
            TcpStep::RefuseNextConnect => {
                drop(stream);
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::certs::TestCa;
    use crate::scaffolding::ports::reserve_port;

    async fn connect_tls_client(
        port: u16,
        ca_pem: &str,
        alpn: Vec<Vec<u8>>,
    ) -> Result<
        tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let mut root = rustls::RootCertStore::empty();
        let mut reader = ca_pem.as_bytes();
        for cert in certs(&mut reader).filter_map(|c| c.ok()) {
            root.add(cert)?;
        }
        let provider = rustls::crypto::ring::default_provider();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root)
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let name = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
        let tls = connector.connect(name, tcp).await?;
        Ok(tls)
    }

    #[tokio::test]
    async fn tls_backend_read_write() {
        let ca = TestCa::new("tls-test").expect("ca");
        let (cert_pem, key_pem) = ca.valid().expect("valid leaf");
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;

        let backend = ScriptedTlsBackend::builder(
            reservation.into_listener(),
            TlsConfig::new(cert_pem, key_pem),
        )
        .step(TcpStep::ReadExact(5))
        .step(TcpStep::Write(b"hello".to_vec()))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn tls");

        let mut client = connect_tls_client(port, &ca.cert_pem, vec![])
            .await
            .expect("connect");
        client.write_all(b"abcde").await.expect("write");
        let mut resp = Vec::new();
        // Use `read` in a loop so TLS close_notify surfaces as Ok(0).
        let mut buf = [0u8; 64];
        loop {
            let n = client.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&buf[..n]);
        }
        assert_eq!(resp, b"hello");
        assert_eq!(backend.handshakes_completed(), 1);
        assert!(backend.received_contains(b"abcde").await);
    }

    #[tokio::test]
    async fn alpn_server_picks_h1_when_client_prefers_h2() {
        let ca = TestCa::new("tls-alpn").expect("ca");
        let (cert_pem, key_pem) = ca.valid().expect("valid leaf");
        let reservation = reserve_port().await.expect("port");
        let port = reservation.port;

        // Server only advertises http/1.1 — any h2 client must fall back.
        let backend = ScriptedTlsBackend::builder(
            reservation.into_listener(),
            TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()]),
        )
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn tls");

        // Client advertises h2 first.
        let _client = connect_tls_client(
            port,
            &ca.cert_pem,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
        .await
        .expect("connect");

        // Give the server time to persist the ALPN observation.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let alpn = backend.last_alpn().await;
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]));
    }

    /// Regression test: mirror of the TCP variant. `received_contains(b"")`
    /// must not panic via `windows(0)`.
    #[tokio::test]
    async fn received_contains_empty_needle_returns_true_without_panicking() {
        let ca = TestCa::new("tls-empty-needle").expect("ca");
        let (cert_pem, key_pem) = ca.valid().expect("leaf");
        let reservation = reserve_port().await.expect("port");
        let backend = ScriptedTlsBackend::builder(
            reservation.into_listener(),
            TlsConfig::new(cert_pem, key_pem),
        )
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn tls");
        assert!(backend.received_contains(b"").await);
    }
}

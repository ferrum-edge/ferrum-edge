//! `ScriptedDtlsBackend` — a DTLS-terminating wrapper around
//! [`super::udp::ScriptedUdpBackend`].
//!
//! ## DTLS implementation choice: `dimpl` via `ferrum_edge::dtls::DtlsServer`
//!
//! The Rust DTLS ecosystem is still fairly thin. The options surveyed:
//!
//! - **`tokio-rustls`** — TLS only; rustls has not yet landed DTLS support
//!   in a stable release.
//! - **`openssl`** — exposes DTLS 1.2/1.3 via libssl but requires a
//!   non-trivial async wrapper and drags in vendored OpenSSL build times.
//! - **`dimpl`** — a Sans-IO DTLS 1.2/1.3 state machine already used in
//!   production by `src/dtls/mod.rs`. The gateway's own `DtlsServer`
//!   wraps it end-to-end with `FrontendDtlsConfig` ergonomics, so the
//!   simplest path for tests is to reuse `ferrum_edge::dtls::DtlsServer`
//!   directly — same crypto provider, same cert flow, same
//!   `ECDSA P-256` constraints.
//!
//! The wrapper here therefore:
//!
//! 1. Binds a UDP socket on a supplied port.
//! 2. Runs a `DtlsServer` accept loop in a background task.
//! 3. For each accepted client, spawns an echo task that forwards
//!    decrypted application-layer bytes to a script-driven handler.
//!
//! For SNI-routing tests (Phase 4 test #3) the gateway uses
//! `passthrough: true` — it does NOT terminate DTLS, it just peeks at the
//! ClientHello and forwards the opaque bytes. The backend on the far side
//! of passthrough is therefore a *real* DTLS server that completes the
//! handshake directly with the client. This backend fits that role.
//!
//! ## Caveats
//!
//! - **ECDSA-P256 only.** `dimpl`'s certificate helpers use ECDSA P-256
//!   or P-384; RSA won't compile in.
//! - **Handshake timeout.** The server side inherits `dimpl`'s 10 s
//!   handshake timeout; tests must trigger handshakes reasonably fast.
//! - **`DropSocket`.** Implementing it requires tearing down the
//!   `DtlsServer`, which owns its socket; call
//!   [`ScriptedDtlsBackend::shutdown`] from the test if needed.
//! - **Message boundaries.** `send()` / `recv()` go through `dimpl`
//!   records — each decoded payload is one write from the peer. Tests
//!   should not assume TCP-like byte-stream coalescing.
//!
//! Observability mirrors the UDP variant: every decrypted payload is
//! appended to `received_datagrams()` with the client address; replies
//! are counted by `packets_sent()`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dimpl::Config as DimplConfig;
use ferrum_edge::dtls::{DtlsServer, FrontendDtlsConfig};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use super::udp::{DatagramMatcher, RecordedDatagram, UdpStep};

/// Configuration for the DTLS handshake — thin wrapper so the rest of
/// the scaffolding calls into one entry point.
///
/// Use [`DtlsConfig::self_signed`] for tests that don't care about trust:
/// it mints a fresh ECDSA P-256 self-signed cert on the fly via
/// `dimpl::certificate::generate_self_signed_certificate`, which is the
/// same path the gateway's own functional tests use.
pub struct DtlsConfig {
    dimpl_config: Arc<DimplConfig>,
    certificate: dimpl::DtlsCertificate,
}

impl DtlsConfig {
    /// A config that generates a fresh ephemeral self-signed ECDSA P-256
    /// certificate. The test client must accept self-signed certs or
    /// skip verification.
    pub fn self_signed() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure rustls crypto provider is installed. rcgen and dimpl both
        // need it at generation time. The `install_default` call is a
        // no-op after the first installation.
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let certificate = dimpl::certificate::generate_self_signed_certificate()
            .map_err(|e| format!("generate self-signed dtls cert: {e}"))?;
        Ok(Self {
            dimpl_config: Arc::new(DimplConfig::default()),
            certificate,
        })
    }
}

/// Fluent builder for [`ScriptedDtlsBackend`].
pub struct ScriptedDtlsBackendBuilder {
    socket: UdpSocket,
    config: DtlsConfig,
    steps: Vec<UdpStep>,
}

impl ScriptedDtlsBackendBuilder {
    pub fn new(socket: UdpSocket, config: DtlsConfig) -> Self {
        Self {
            socket,
            config,
            steps: Vec::new(),
        }
    }

    pub fn step(mut self, step: UdpStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn steps(mut self, steps: impl IntoIterator<Item = UdpStep>) -> Self {
        self.steps.extend(steps);
        self
    }

    /// Spawn the backend. Reuses the existing `DtlsServer` — same code the
    /// gateway uses for DTLS frontend termination in production.
    pub async fn spawn(
        self,
    ) -> Result<ScriptedDtlsBackend, Box<dyn std::error::Error + Send + Sync>> {
        let local_addr = self.socket.local_addr()?;
        let port = local_addr.port();

        // `DtlsServer::bind` wants to create its own socket. We release
        // the reservation just before it rebinds — same pattern the
        // gateway's functional DTLS tests use. The race window is the
        // same millisecond-scale slot other Phase-1 tests accept under
        // the port-reservation contract.
        drop(self.socket);

        let frontend_config = FrontendDtlsConfig {
            dimpl_config: self.config.dimpl_config,
            certificate: self.config.certificate,
            client_cert_verifier: None,
        };
        let server = DtlsServer::bind(local_addr, frontend_config).await?;
        let server = Arc::new(server);

        let state = Arc::new(DtlsBackendState::default());
        let server_run = server.clone();
        let run_task = tokio::spawn(async move {
            let _ = server_run.run().await;
        });

        let accept_server = server.clone();
        let state_accept = state.clone();
        let steps = self.steps;
        let accept_task = tokio::spawn(async move {
            // The Phase-4 tests (SNI routing, passthrough) expect only
            // one client per backend — accept one connection, run the
            // script against it, then stop accepting so the UDP socket
            // is fully owned by the completed session.
            //
            // For tests that need multi-client, call `spawn` multiple
            // times against separate ports. Sharing a single backend is
            // rare in the scripted-backend tests.
            match accept_server.accept().await {
                Ok((conn, src)) => {
                    run_dtls_script(conn, src, steps, state_accept).await;
                }
                Err(e) => {
                    if let Ok(mut errs) = state_accept.step_errors.try_lock() {
                        errs.push(format!("DTLS accept failed: {e}"));
                    }
                }
            }
        });

        Ok(ScriptedDtlsBackend {
            port,
            state,
            run_task: Some(run_task),
            accept_task: Some(accept_task),
            server: StdMutex::new(Some(server)),
        })
    }
}

#[derive(Default)]
struct DtlsBackendState {
    /// Bytes received from the DTLS client after decryption. Each `recv`
    /// from `dimpl` is one entry.
    received_datagrams: Mutex<Vec<RecordedDatagram>>,
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    step_errors: Mutex<Vec<String>>,
    handshakes_completed: AtomicU64,
}

/// A running scripted DTLS backend. Drop shuts it down.
pub struct ScriptedDtlsBackend {
    pub port: u16,
    state: Arc<DtlsBackendState>,
    run_task: Option<JoinHandle<()>>,
    accept_task: Option<JoinHandle<()>>,
    /// Kept alive so the accept loop can continue; cleared on shutdown.
    /// `StdMutex` so `Drop` (non-async) can take it.
    server: StdMutex<Option<Arc<DtlsServer>>>,
}

impl ScriptedDtlsBackend {
    pub fn builder(socket: UdpSocket, config: DtlsConfig) -> ScriptedDtlsBackendBuilder {
        ScriptedDtlsBackendBuilder::new(socket, config)
    }

    /// Snapshot of every datagram (decrypted payload) the backend has
    /// received from the client.
    pub async fn received_datagrams(&self) -> Vec<RecordedDatagram> {
        self.state.received_datagrams.lock().await.clone()
    }

    /// Number of DTLS handshakes that have completed.
    pub fn handshakes_completed(&self) -> u64 {
        self.state.handshakes_completed.load(Ordering::SeqCst)
    }

    /// Number of reply datagrams sent to clients.
    pub fn packets_sent(&self) -> u64 {
        self.state.packets_sent.load(Ordering::SeqCst)
    }

    /// Total bytes sent to clients.
    pub fn bytes_sent(&self) -> u64 {
        self.state.bytes_sent.load(Ordering::SeqCst)
    }

    /// Errors captured from the script driver.
    pub async fn step_errors(&self) -> Vec<String> {
        self.state.step_errors.lock().await.clone()
    }

    /// Panic with any captured step errors.
    pub async fn assert_no_step_errors(&self) {
        let errs = self.step_errors().await;
        if !errs.is_empty() {
            panic!("{} DTLS script step error(s): {:?}", errs.len(), errs);
        }
    }

    /// Stop the server and drop its socket. Subsequent DTLS packets from
    /// the gateway fail to reach any handler.
    pub fn shutdown(&mut self) {
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
        if let Some(task) = self.run_task.take() {
            task.abort();
        }
        if let Ok(mut guard) = self.server.lock() {
            guard.take();
        }
    }
}

impl Drop for ScriptedDtlsBackend {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Execute the script against a single accepted DTLS client session.
async fn run_dtls_script(
    conn: ferrum_edge::dtls::DtlsServerConn,
    src: SocketAddr,
    script: Vec<UdpStep>,
    state: Arc<DtlsBackendState>,
) {
    state.handshakes_completed.fetch_add(1, Ordering::SeqCst);

    let sender = conn.clone_sender();
    for step in script {
        match step {
            UdpStep::ExpectDatagram(matcher) => {
                match tokio::time::timeout(Duration::from_secs(10), conn.recv()).await {
                    Ok(Ok(data)) => {
                        state
                            .received_datagrams
                            .lock()
                            .await
                            .push(RecordedDatagram {
                                src,
                                payload: data.clone(),
                            });
                        if let Err(reason) = matcher.check(&data) {
                            state
                                .step_errors
                                .lock()
                                .await
                                .push(format!("DTLS match failed: {reason}"));
                            return;
                        }
                    }
                    Ok(Err(e)) => {
                        state
                            .step_errors
                            .lock()
                            .await
                            .push(format!("DTLS recv error: {e}"));
                        return;
                    }
                    Err(_) => {
                        state
                            .step_errors
                            .lock()
                            .await
                            .push("DTLS ExpectDatagram timeout".into());
                        return;
                    }
                }
            }
            UdpStep::Reply(bytes) => {
                if let Err(e) = sender.send(&bytes).await {
                    state
                        .step_errors
                        .lock()
                        .await
                        .push(format!("DTLS Reply send failed: {e}"));
                    return;
                }
                state.packets_sent.fetch_add(1, Ordering::SeqCst);
                state
                    .bytes_sent
                    .fetch_add(bytes.len() as u64, Ordering::SeqCst);
            }
            UdpStep::ReplyN { payload, count } => {
                for _ in 0..count {
                    if let Err(e) = sender.send(&payload).await {
                        state
                            .step_errors
                            .lock()
                            .await
                            .push(format!("DTLS ReplyN send failed: {e}"));
                        return;
                    }
                    state.packets_sent.fetch_add(1, Ordering::SeqCst);
                    state
                        .bytes_sent
                        .fetch_add(payload.len() as u64, Ordering::SeqCst);
                }
            }
            UdpStep::Silence(d) => {
                // Drain decrypted datagrams without replying for `d`.
                let deadline = tokio::time::Instant::now() + d;
                loop {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining = deadline - now;
                    match tokio::time::timeout(remaining, conn.recv()).await {
                        Ok(Ok(data)) => {
                            state
                                .received_datagrams
                                .lock()
                                .await
                                .push(RecordedDatagram { src, payload: data });
                        }
                        Ok(Err(_)) => break,
                        Err(_) => break,
                    }
                }
            }
            UdpStep::DropSocket => {
                sender.close().await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scaffolding::ports::reserve_udp_port;

    #[tokio::test]
    async fn dtls_handshake_then_echo() {
        let reservation = reserve_udp_port().await.expect("reserve");
        let port = reservation.port;
        let backend = ScriptedDtlsBackend::builder(
            reservation.into_socket(),
            DtlsConfig::self_signed().expect("config"),
        )
        .step(UdpStep::ExpectDatagram(DatagramMatcher::exact(
            b"hello-dtls".to_vec(),
        )))
        .step(UdpStep::Reply(b"pong-dtls".to_vec()))
        .spawn()
        .await
        .expect("spawn dtls");

        // Give the accept loop a moment to be ready.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Use the in-crate DtlsConnection to exercise a real handshake.
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client_socket
            .connect(format!("127.0.0.1:{port}"))
            .await
            .expect("connect");

        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let client_cert =
            dimpl::certificate::generate_self_signed_certificate().expect("client cert");
        let params = ferrum_edge::dtls::BackendDtlsParams {
            config: Arc::new(dimpl::Config::default()),
            certificate: client_cert,
            server_name: None,
            server_cert_verifier: None,
        };

        let client = ferrum_edge::dtls::DtlsConnection::connect(client_socket, params)
            .await
            .expect("handshake");

        client.send(b"hello-dtls").await.expect("send");
        let reply = tokio::time::timeout(Duration::from_secs(5), client.recv())
            .await
            .expect("recv in time")
            .expect("recv");
        assert_eq!(reply, b"pong-dtls");

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(backend.handshakes_completed(), 1);
        assert!(backend.packets_sent() >= 1);
    }
}

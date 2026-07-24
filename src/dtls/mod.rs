//! DTLS 1.2/1.3 support for UDP stream proxies.
//!
//! Provides async wrappers around the `dimpl` Sans-IO DTLS state machine for:
//! - **Backend connections** (gateway → backend): `DtlsConnection` wraps a single
//!   client-role DTLS session over a connected `UdpSocket`.
//! - **Frontend termination** (client → gateway): `DtlsServer` demultiplexes
//!   incoming UDP datagrams by source address and manages per-client DTLS sessions.
//!
//! The `dimpl` crate supports DTLS 1.2 + 1.3 (RFC 9147) with ECDSA P-256/P-384 keys.
//! It uses a Sans-IO design where the caller drives the state machine via
//! `handle_packet()` / `poll_output()` / `handle_timeout()`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use dimpl::{Config, Dtls, DtlsCertificate, Output};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, trace, warn};

use crate::config::types::Proxy;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

/// Default MTU for DTLS records. Conservative default that works over most networks.
#[allow(dead_code)]
const DEFAULT_MTU: usize = 1200;

/// Default DTLS record overhead: 13-byte header + up to 16-byte auth tag (AES-GCM) +
/// padding. Observed: 22 bytes for AES-128-GCM. 64 bytes gives conservative headroom
/// for cipher suite variations and future DTLS versions.
///
/// Override: `FERRUM_DTLS_RECORD_OVERHEAD_BYTES` (default: 64).
const DEFAULT_DTLS_RECORD_OVERHEAD: usize = 64;

/// Default maximum plaintext payload per DTLS record: 2^14 (16,384) bytes per the DTLS
/// spec (RFC 9147 §4.1). Datagrams exceeding this are dropped with a warning before
/// reaching dimpl (which would panic on buffer overflow).
///
/// Override: `FERRUM_DTLS_MAX_PLAINTEXT_BYTES` (default: 16384).
const DEFAULT_DTLS_MAX_PLAINTEXT: usize = 16_384;
const DEFAULT_DTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cached DTLS buffer configuration, initialized from `EnvConfig` at startup.
struct DtlsBufConfig {
    /// Max plaintext payload that can be encrypted.
    max_plaintext: usize,
    /// Output buffer size = max_plaintext + record_overhead.
    output_buf_size: usize,
}

static DTLS_BUF_CONFIG: std::sync::OnceLock<DtlsBufConfig> = std::sync::OnceLock::new();

/// Initialize DTLS buffer configuration from resolved `EnvConfig` values.
/// Must be called after `EnvConfig` is parsed (before any DTLS connections).
/// Uses saturating arithmetic to prevent overflow with extreme values.
pub fn init_dtls_buf_config(max_plaintext: usize, record_overhead: usize) {
    let _ = DTLS_BUF_CONFIG.set(DtlsBufConfig {
        max_plaintext,
        output_buf_size: max_plaintext.saturating_add(record_overhead),
    });
}

/// Effective DTLS plaintext ceiling for one application datagram.
///
/// Sourced from `FERRUM_DTLS_MAX_PLAINTEXT_BYTES` after startup init, otherwise
/// the RFC 9147 default (16,384). Logging sinks and other callers must treat
/// payloads larger than this as local delivery failures rather than enqueueing
/// them into the driver.
pub fn max_plaintext_bytes() -> usize {
    dtls_buf_config().max_plaintext
}

fn dtls_buf_config() -> &'static DtlsBufConfig {
    DTLS_BUF_CONFIG.get_or_init(|| {
        // Fallback if init_dtls_buf_config() was never called (e.g. tests).
        DtlsBufConfig {
            max_plaintext: DEFAULT_DTLS_MAX_PLAINTEXT,
            output_buf_size: DEFAULT_DTLS_MAX_PLAINTEXT
                .saturating_add(DEFAULT_DTLS_RECORD_OVERHEAD),
        }
    })
}

/// Application payload waiting for the DTLS driver to encrypt and write it.
struct PendingAppSend {
    data: Vec<u8>,
    /// Completes with `Ok(())` only after `send_application_data` succeeds and
    /// every resulting ciphertext datagram is accepted by the connected UDP
    /// socket. Oversized plaintext, DTLS engine errors, and socket-send
    /// failures complete with `Err` so callers can drive retry/final-loss.
    completion: oneshot::Sender<Result<(), String>>,
}

/// Maximum datagrams to drain per `poll_output` loop before yielding.
const MAX_OUTPUTS_PER_DRAIN: usize = 64;

async fn fail_pending_app_sends(driver_app_rx: &mut mpsc::Receiver<PendingAppSend>) {
    while let Ok(pending) = driver_app_rx.try_recv() {
        let _ = pending
            .completion
            .send(Err("DTLS connection closed".to_string()));
    }
}

// ============================================================================
// Configuration Builders
// ============================================================================

/// Frontend DTLS server configuration (client → gateway).
pub struct FrontendDtlsConfig {
    pub dimpl_config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
}

/// Admission controls for the frontend DTLS demuxer.
#[derive(Clone)]
pub struct DtlsServerLimits {
    /// Maximum number of DTLS peers tracked by the demuxer, including peers
    /// still in the handshake and not yet visible through `accept()`.
    pub max_sessions: Option<usize>,
    /// Maximum time a peer may occupy demux state before completing its handshake.
    /// `None` disables the deadline.
    pub handshake_timeout: Option<Duration>,
    /// Optional gate checked before allocating per-peer handshake state.
    pub allow_new_session: Option<Arc<dyn Fn() -> bool + Send + Sync + 'static>>,
    /// Optional diagnostic mirror for surfaces that need to report demux state
    /// outside this server object, such as the admin `/overload` endpoint. This
    /// is eventually consistent with `active_sessions` and is not used for
    /// admission control.
    pub active_session_mirror: Option<Arc<AtomicU64>>,
}

impl Default for DtlsServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: None,
            handshake_timeout: Some(DEFAULT_DTLS_HANDSHAKE_TIMEOUT),
            allow_new_session: None,
            active_session_mirror: None,
        }
    }
}

/// Build a DTLS client config for backend connections (gateway → backend).
///
/// Maps the proxy's `backend_tls_*` fields to dimpl `Config`:
/// - `backend_tls_server_ca_cert_path` → used for peer cert validation callback
/// - `backend_tls_client_cert_path` + `backend_tls_client_key_path` → client certificate
///
/// Returns `(config, certificate, trusted_ca_certs, skip_verify)`.
pub fn build_backend_dtls_config(
    proxy: &Proxy,
    backend_host: &str,
    tls_no_verify: bool,
    crls: &crate::tls::CrlList,
    global_ca_bundle_path: Option<&str>,
) -> Result<BackendDtlsParams, anyhow::Error> {
    let skip_verify = !proxy.resolved_tls.verify_server_cert || tls_no_verify;

    // Load client certificate for mutual TLS, or generate an ephemeral one.
    let certificate = if let (Some(cert_path), Some(key_path)) = (
        &proxy.resolved_tls.client_cert_path,
        &proxy.resolved_tls.client_key_path,
    ) {
        load_dtls_certificate(cert_path, key_path)?
    } else {
        generate_ephemeral_cert()?
    };

    let config = Arc::new(Config::default());
    let (server_name, server_cert_verifier) = if skip_verify {
        (None, None)
    } else {
        let root_store = load_backend_root_store(proxy, global_ca_bundle_path)?;
        let server_name = rustls::pki_types::ServerName::try_from(backend_host.to_string())
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid DTLS backend host for certificate verification: {}",
                    backend_host
                )
            })?;
        let inner = crate::tls::build_server_verifier_with_crls(root_store, crls)?;
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            if proxy.resolved_tls.san_allow_list.is_empty() {
                inner
            } else {
                Arc::new(crate::tls::backend::SanAllowListVerifier::new(
                    inner,
                    proxy.resolved_tls.san_allow_list.clone(),
                )?)
            };
        (Some(server_name), Some(verifier as _))
    };

    debug!(
        proxy_id = %proxy.id,
        skip_verify = skip_verify,
        "Built DTLS backend client config (dimpl)"
    );

    Ok(BackendDtlsParams {
        config,
        certificate,
        server_name,
        server_cert_verifier,
        connect_timeout_ms: proxy.backend_connect_timeout_ms,
    })
}

/// Parameters for creating a backend DTLS connection.
#[derive(Clone)]
pub struct BackendDtlsParams {
    pub config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub server_name: Option<rustls::pki_types::ServerName<'static>>,
    pub server_cert_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    /// End-to-end deadline for the DTLS handshake, in milliseconds.
    ///
    /// Sourced from `Proxy.backend_connect_timeout_ms` for proxy backends, or
    /// from caller-supplied values for plugin/test contexts. Matches the
    /// gRPC/TCP TLS handshake budget semantics: the value is consumed verbatim
    /// via `Duration::from_millis(...)`, so `0` behaves like an immediate
    /// timeout (not "unbounded"), keeping behavior consistent with sibling
    /// backend handshake paths.
    pub connect_timeout_ms: u64,
}

/// Build a DTLS server config for frontend termination (client → gateway).
///
/// Requires ECDSA P-256 or P-384 certificates.
pub fn build_frontend_dtls_config(
    cert_path: &str,
    key_path: &str,
    client_ca_cert_path: Option<&str>,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
) -> Result<FrontendDtlsConfig, anyhow::Error> {
    let certificate = load_dtls_certificate(cert_path, key_path)?;

    let (require_client_cert, client_cert_verifier) = if let Some(ca_path) = client_ca_cert_path {
        let root_store = load_root_store_from_pem(ca_path)?;
        let mut verifier_builder =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store));
        if !crls.is_empty() {
            verifier_builder = verifier_builder
                .with_crls(crls.iter().cloned())
                .allow_unknown_revocation_status()
                .only_check_end_entity_revocation();
        }
        let verifier = verifier_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build DTLS client verifier: {}", e))?;
        debug!(
            ca_path = %ca_path,
            "Frontend DTLS mTLS enabled: requiring and verifying client certificates"
        );
        (true, Some(verifier))
    } else {
        (false, None)
    };

    let config_builder = Config::builder().require_client_certificate(require_client_cert);
    let config = Arc::new(
        config_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build DTLS config: {}", e))?,
    );

    Ok(FrontendDtlsConfig {
        dimpl_config: config,
        certificate,
        client_cert_verifier,
    })
}

// ============================================================================
// DtlsConnection — async wrapper for a single DTLS session (client role)
// ============================================================================

/// An async DTLS connection wrapping a connected `UdpSocket`.
///
/// Drives the dimpl Sans-IO state machine on a dedicated tokio task, exposing
/// simple `send()` / `recv()` / `close()` methods. Data is exchanged via channels
/// to avoid locking the state machine on the hot path.
pub struct DtlsConnection {
    /// Send application data to the DTLS engine for encryption + transmission.
    app_tx: mpsc::Sender<PendingAppSend>,
    /// Receive decrypted application data from the DTLS engine.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Signal the driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
}

fn client_send_output_drain_needs_another_round(
    has_pending_completion: bool,
    wrote_ciphertext_datagram: bool,
    socket_send_failed: bool,
    fatal_send_failed: bool,
    drain_round_exhausted: bool,
) -> bool {
    has_pending_completion
        && !wrote_ciphertext_datagram
        && !socket_send_failed
        && !fatal_send_failed
        && drain_round_exhausted
}

/// Pin the fairness-boundary decision for external hosted tests without
/// exposing it as runtime API.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn client_send_output_drain_needs_another_round_for_test(
    has_pending_completion: bool,
    wrote_ciphertext_datagram: bool,
    socket_send_failed: bool,
    fatal_send_failed: bool,
    drain_round_exhausted: bool,
) -> bool {
    client_send_output_drain_needs_another_round(
        has_pending_completion,
        wrote_ciphertext_datagram,
        socket_send_failed,
        fatal_send_failed,
        drain_round_exhausted,
    )
}

impl DtlsConnection {
    /// Perform a DTLS client handshake over the given connected socket and return
    /// an established `DtlsConnection`.
    ///
    /// The handshake is bounded by `params.connect_timeout_ms`, which is the
    /// per-proxy `backend_connect_timeout_ms` for proxy backends. The semantic
    /// matches sibling backend handshake paths (gRPC h2/h2c in
    /// `proxy/grpc_proxy.rs`, TCP TLS in `proxy/tcp_proxy.rs`): the value is
    /// consumed verbatim via `Duration::from_millis(...)`, so `0` behaves like
    /// an immediate timeout rather than "unbounded".
    pub async fn connect(
        socket: UdpSocket,
        params: BackendDtlsParams,
    ) -> Result<Self, anyhow::Error> {
        let socket = Arc::new(socket);
        let server_name = params.server_name;
        let server_cert_verifier = params.server_cert_verifier;
        let connect_timeout = Duration::from_millis(params.connect_timeout_ms);
        let handshake_deadline = Instant::now() + connect_timeout;
        let mut dtls = Dtls::new_auto(params.config, params.certificate, Instant::now());
        dtls.set_active(true); // client role

        // Drive handshake to completion
        let mut out_buf = vec![0u8; dtls_buf_config().output_buf_size];
        let mut recv_buf = vec![0u8; 65536];
        let mut next_timeout: Option<Instant> = None;
        let mut verified_server_cert = false;

        // Kick off the handshake by draining initial outputs (ClientHello + Timeout)
        drain_handshake_outputs(
            &mut dtls,
            &mut out_buf,
            &socket,
            None,
            &mut next_timeout,
            server_name.as_ref(),
            server_cert_verifier.as_deref(),
            &mut verified_server_cert,
        )
        .await?;

        loop {
            // Top-of-loop deadline check guards against a sustained datagram
            // flood starving the deadline arm in the select below.
            if Instant::now() >= handshake_deadline {
                return Err(anyhow::anyhow!(
                    "DTLS handshake timed out after {}ms",
                    connect_timeout.as_millis()
                ));
            }

            let sleep_dur = next_timeout
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(1));
            let deadline_sleep_dur = handshake_deadline.saturating_duration_since(Instant::now());

            tokio::select! {
                result = socket.recv(&mut recv_buf) => {
                    let len = result.map_err(|e| anyhow::anyhow!("UDP recv during handshake: {}", e))?;
                    if let Err(e) = dtls.handle_packet(&recv_buf[..len]) {
                        return Err(anyhow::anyhow!("DTLS handshake packet error: {}", e));
                    }
                }
                _ = tokio::time::sleep(sleep_dur) => {
                    if let Some(t) = next_timeout
                        && Instant::now() >= t
                    {
                        if let Err(e) = dtls.handle_timeout(Instant::now()) {
                            return Err(anyhow::anyhow!("DTLS handshake timeout error: {}", e));
                        }
                        next_timeout = None;
                    }
                }
                // Defense in depth: ensure the deadline fires even if the
                // socket recv arm and the dimpl retransmit timer never wake
                // up (e.g., backend silently drops every datagram).
                _ = tokio::time::sleep(deadline_sleep_dur) => {
                    return Err(anyhow::anyhow!(
                        "DTLS handshake timed out after {}ms",
                        connect_timeout.as_millis()
                    ));
                }
            }

            // Drain outputs — check for Connected, validate peer cert
            let connected = drain_handshake_outputs(
                &mut dtls,
                &mut out_buf,
                &socket,
                None,
                &mut next_timeout,
                server_name.as_ref(),
                server_cert_verifier.as_deref(),
                &mut verified_server_cert,
            )
            .await?;

            if connected {
                if server_cert_verifier.is_some() && !verified_server_cert {
                    return Err(anyhow::anyhow!(
                        "DTLS backend server certificate verification required but no verified server certificate was presented"
                    ));
                }
                return Ok(Self::spawn_driver(dtls, socket));
            }
        }
    }

    /// Spawn the background driver task and return the connection handle.
    fn spawn_driver(dtls: Dtls, socket: Arc<UdpSocket>) -> Self {
        // Channels: app data in/out, shutdown signal
        let (app_tx, mut driver_app_rx) = mpsc::channel::<PendingAppSend>(256);
        let (driver_app_tx, app_rx) = mpsc::channel::<Vec<u8>>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            let mut dtls = dtls;
            let mut out_buf = vec![0u8; dtls_buf_config().output_buf_size];
            let mut recv_buf = vec![0u8; 65536];
            let mut next_timeout: Option<Instant> = None;

            loop {
                let sleep_dur = next_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(60));

                let mut pending_completion: Option<oneshot::Sender<Result<(), String>>> = None;
                let mut fatal_send_error: Option<String> = None;

                tokio::select! {
                    // Incoming UDP datagram from peer
                    result = socket.recv(&mut recv_buf) => {
                        match result {
                            Ok(len) => {
                                if let Err(e) = dtls.handle_packet(&recv_buf[..len]) {
                                    trace!("DTLS handle_packet error: {}", e);
                                    fatal_send_error =
                                        Some(format!("DTLS handle_packet error: {e}"));
                                }
                            }
                            Err(e) => {
                                fatal_send_error = Some(format!("DTLS UDP recv error: {e}"));
                            }
                        }
                    }
                    // Application data to send — complete only after encrypt + socket write.
                    Some(pending) = driver_app_rx.recv() => {
                        let PendingAppSend { data, completion } = pending;
                        let max_plaintext = dtls_buf_config().max_plaintext;
                        if data.len() > max_plaintext {
                            let _ = completion.send(Err(format!(
                                "DTLS plaintext exceeds max_plaintext ({max_plaintext} bytes, got {})",
                                data.len()
                            )));
                        } else if let Err(e) = dtls.send_application_data(&data) {
                            let msg = format!("DTLS send_application_data error: {e}");
                            trace!("{msg}");
                            let _ = completion.send(Err(msg.clone()));
                            fatal_send_error = Some(msg);
                        } else {
                            pending_completion = Some(completion);
                        }
                    }
                    // Timer fired
                    _ = tokio::time::sleep(sleep_dur) => {
                        if let Some(t) = next_timeout
                            && Instant::now() >= t
                        {
                            if let Err(e) = dtls.handle_timeout(Instant::now()) {
                                trace!("DTLS handle_timeout error: {}", e);
                                fatal_send_error =
                                    Some(format!("DTLS handle_timeout error: {e}"));
                            }
                            next_timeout = None;
                        }
                    }
                    // Shutdown requested
                    _ = shutdown_rx.recv() => {
                        fatal_send_error = Some("DTLS connection closed".to_string());
                    }
                }

                // Drain pending outputs in bounded rounds. dimpl deliberately
                // returns received ApplicationData before queued ciphertext,
                // so a send awaiting completion must continue across a full
                // fairness round instead of being declared a false failure.
                let mut socket_send_error: Option<String> = None;
                let mut wrote_ciphertext_datagram = false;
                loop {
                    let mut drain_round_exhausted = true;
                    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                        match dtls.poll_output(&mut out_buf) {
                            Output::Packet(data) => match socket.send(data).await {
                                Ok(written) if written == data.len() => {
                                    wrote_ciphertext_datagram = true;
                                }
                                Ok(written) => {
                                    socket_send_error = Some(format!(
                                        "DTLS UDP send was incomplete: wrote {written} of {} bytes",
                                        data.len()
                                    ));
                                    drain_round_exhausted = false;
                                    break;
                                }
                                Err(e) => {
                                    socket_send_error = Some(format!("DTLS UDP send error: {e}"));
                                    drain_round_exhausted = false;
                                    break;
                                }
                            },
                            Output::Timeout(t) => {
                                next_timeout = Some(t);
                                drain_round_exhausted = false;
                                break;
                            }
                            Output::ApplicationData(data) => {
                                if driver_app_tx.send(data.to_vec()).await.is_err() {
                                    if let Some(completion) = pending_completion.take() {
                                        let _ = completion
                                            .send(Err("DTLS connection closed".to_string()));
                                    }
                                    fail_pending_app_sends(&mut driver_app_rx).await;
                                    return;
                                }
                            }
                            Output::Connected | Output::PeerCert(_) => {
                                // Already handled during handshake
                            }
                            _ => {
                                drain_round_exhausted = false;
                                break;
                            }
                        }
                    }

                    if client_send_output_drain_needs_another_round(
                        pending_completion.is_some(),
                        wrote_ciphertext_datagram,
                        socket_send_error.is_some(),
                        fatal_send_error.is_some(),
                        drain_round_exhausted,
                    ) {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    break;
                }

                if let Some(completion) = pending_completion.take() {
                    if let Some(error) = socket_send_error.as_ref() {
                        let _ = completion.send(Err(error.clone()));
                    } else if !wrote_ciphertext_datagram {
                        let error =
                            "DTLS application send produced no ciphertext datagram".to_string();
                        let _ = completion.send(Err(error.clone()));
                        fatal_send_error = Some(error);
                    } else {
                        let _ = completion.send(Ok(()));
                    }
                }

                // A connected UDP send error is per-datagram: report it to the
                // caller, but retain the shared DTLS association. Callers such
                // as udp_logging may still reset their own sender. Receive,
                // engine, timeout-engine, and shutdown failures remain fatal.
                if fatal_send_error.is_some() {
                    fail_pending_app_sends(&mut driver_app_rx).await;
                    break;
                }
            }
        });

        Self {
            app_tx,
            app_rx: tokio::sync::Mutex::new(app_rx),
            shutdown_tx,
        }
    }

    /// Send application data through the DTLS tunnel.
    ///
    /// Success means the local DTLS engine accepted the plaintext and every
    /// resulting ciphertext datagram was accepted by the connected UDP socket.
    /// It does **not** mean the remote peer delivered or acknowledged the
    /// payload. Oversized plaintext, DTLS engine failures, and local socket
    /// send errors return `Err` so callers can retry or account for final loss.
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        let max_plaintext = dtls_buf_config().max_plaintext;
        if data.len() > max_plaintext {
            return Err(anyhow::anyhow!(
                "DTLS plaintext exceeds max_plaintext ({max_plaintext} bytes, got {})",
                data.len()
            ));
        }
        let (completion_tx, completion_rx) = oneshot::channel();
        self.app_tx
            .send(PendingAppSend {
                data: data.to_vec(),
                completion: completion_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("DTLS connection closed"))?;
        match completion_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!(error)),
            Err(_) => Err(anyhow::anyhow!("DTLS connection closed")),
        }
    }

    /// Receive decrypted application data from the DTLS tunnel.
    pub async fn recv(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut rx = self.app_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("DTLS connection closed"))
    }

    /// Gracefully shut down the DTLS connection.
    pub async fn close(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

impl Drop for DtlsConnection {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

// ============================================================================
// DtlsServer — frontend DTLS session demuxer
// ============================================================================

/// Snapshot of the swappable per-DTLS-server crypto material.
///
/// Stored in [`DtlsServer::active_config`] behind an `ArcSwap` so an operator
/// rotating the underlying mTLS materials (PeerAuthentication live reload for
/// mesh UDP+DTLS stream listeners) can publish a new `dimpl_config`,
/// `certificate`, and client verifier without dropping in-flight DTLS
/// sessions. New sessions snapshot the slot in
/// [`DtlsServer::spawn_session`]; existing sessions retain the material they
/// were spawned with until they end.
struct DtlsServerActiveConfig {
    dimpl_config: Arc<Config>,
    certificate: DtlsCertificate,
    client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
}

/// A DTLS server that manages multiple client sessions on a single UDP socket.
///
/// Demultiplexes incoming UDP datagrams by source address, creating a new `Dtls`
/// state machine for each new client. Accepted connections are delivered via
/// a channel as `DtlsServerConn` instances.
pub struct DtlsServer {
    socket: Arc<UdpSocket>,
    /// Swappable crypto material (config / certificate / client verifier).
    ///
    /// Spawned sessions snapshot this once at construction so the running
    /// handshake / session cannot observe a partial rotation. Operators can
    /// publish a new snapshot via [`Self::swap_frontend_config`] (used by mesh
    /// PeerAuthentication live reload); new sessions pick it up on the next
    /// ClientHello.
    active_config: ArcSwap<DtlsServerActiveConfig>,
    sessions: Arc<DashMap<SocketAddr, DtlsSessionState>>,
    active_sessions: Arc<AtomicUsize>,
    /// Monotonic generation assigned to each demux session so removal is
    /// identity-aware: a stale `SessionGuard` or `Closed`-channel cleanup must
    /// not evict a newer live session that replaced the same `peer_addr`.
    next_session_generation: AtomicU64,
    limits: DtlsServerLimits,
    /// Channel to deliver accepted (post-handshake) connections.
    accept_tx: mpsc::Sender<(DtlsServerConn, SocketAddr)>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(DtlsServerConn, SocketAddr)>>,
    shutdown_tx: watch::Sender<bool>,
}

/// State for a server-side DTLS session being managed by the DtlsServer.
struct DtlsSessionState {
    /// Send incoming UDP data to this session's driver task.
    incoming_tx: mpsc::Sender<Vec<u8>>,
    /// Signal this session's driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
    /// Identity token for this map entry. Compared on removal so a racing
    /// replacement at the same peer address is not evicted.
    generation: u64,
}

fn remove_session(
    sessions: &DashMap<SocketAddr, DtlsSessionState>,
    active_sessions: &AtomicUsize,
    active_session_mirror: Option<&AtomicU64>,
    peer_addr: &SocketAddr,
    generation: u64,
) {
    if sessions
        .remove_if(peer_addr, |_, s| s.generation == generation)
        .is_some()
    {
        active_sessions.fetch_sub(1, Ordering::Relaxed);
        if let Some(mirror) = active_session_mirror {
            mirror.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct SessionGuard {
    sessions: Arc<DashMap<SocketAddr, DtlsSessionState>>,
    active_sessions: Arc<AtomicUsize>,
    active_session_mirror: Option<Arc<AtomicU64>>,
    peer_addr: SocketAddr,
    generation: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        remove_session(
            &self.sessions,
            &self.active_sessions,
            self.active_session_mirror.as_deref(),
            &self.peer_addr,
            self.generation,
        );
    }
}

/// A server-side DTLS connection for a single accepted client.
///
/// Provides `send()` / `recv()` / `close()` similar to `DtlsConnection`.
/// The send side is cloneable (via `clone_sender()`) so bidirectional forwarding
/// tasks can each hold a sender.
pub struct DtlsServerConn {
    /// Send application data to the DTLS engine for encryption.
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Receive decrypted application data.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Signal this connection's driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
    /// DER-encoded client leaf certificate from the DTLS handshake.
    /// Populated when the client presents a certificate during mutual DTLS authentication.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// Always `None` for the current dimpl-backed DTLS path: dimpl 0.6.1
    /// exposes only the peer leaf through `Output::PeerCert`, not the
    /// intermediate chain. The field remains for stream-plugin context parity
    /// with TCP/TLS frontends.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// SNI hostname extracted from the initial DTLS ClientHello, if supplied.
    pub sni_hostname: Option<String>,
}

/// A cloneable sender half of a `DtlsServerConn`, used to send data back to
/// the DTLS client from a separate task (e.g., backend→client forwarding).
#[derive(Clone)]
pub struct DtlsServerSender {
    app_tx: mpsc::Sender<Vec<u8>>,
    shutdown_tx: mpsc::Sender<()>,
}

impl DtlsServerSender {
    /// Send application data through the DTLS tunnel to this client.
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS server connection closed"))
    }

    /// Close this client's DTLS connection.
    pub async fn close(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

impl DtlsServerConn {
    /// Send application data through the DTLS tunnel to this client.
    #[allow(dead_code)]
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS server connection closed"))
    }

    /// Receive decrypted application data from this client.
    pub async fn recv(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut rx = self.app_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("DTLS server connection closed"))
    }

    /// Get a cloneable sender for this connection, allowing another task
    /// to send data back to the client independently.
    pub fn clone_sender(&self) -> DtlsServerSender {
        DtlsServerSender {
            app_tx: self.app_tx.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    /// Close this client's DTLS connection.
    pub async fn close(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

impl Drop for DtlsServerConn {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

impl DtlsServer {
    /// Create a new DTLS server bound to the given address.
    #[allow(dead_code)] // Public helper used by tests and external DTLS backends.
    pub async fn bind(
        addr: SocketAddr,
        frontend_config: FrontendDtlsConfig,
    ) -> Result<Self, anyhow::Error> {
        Self::bind_with_limits(addr, frontend_config, DtlsServerLimits::default()).await
    }

    /// Create a new DTLS server bound to the given address with admission limits.
    pub async fn bind_with_limits(
        addr: SocketAddr,
        frontend_config: FrontendDtlsConfig,
        limits: DtlsServerLimits,
    ) -> Result<Self, anyhow::Error> {
        let socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to bind DTLS server on {}: {}", addr, e))?;
        Ok(Self::from_socket_with_limits(
            socket,
            frontend_config,
            limits,
        ))
    }

    /// Create a `DtlsServer` from an already-bound `UdpSocket`. Useful when the
    /// caller has reserved the port via a separate pathway (e.g. test
    /// scaffolding holding a `UdpSocket` open across the
    /// reserve-then-construct gap to avoid the bind-drop-rebind race) and
    /// wants to hand the socket directly to the DTLS server without any
    /// release/rebind window.
    #[allow(dead_code)] // Public helper used by tests and scripted DTLS backends.
    pub fn from_socket(socket: UdpSocket, frontend_config: FrontendDtlsConfig) -> Self {
        Self::from_socket_with_limits(socket, frontend_config, DtlsServerLimits::default())
    }

    /// Create a `DtlsServer` from an already-bound `UdpSocket` with admission limits.
    pub fn from_socket_with_limits(
        socket: UdpSocket,
        frontend_config: FrontendDtlsConfig,
        limits: DtlsServerLimits,
    ) -> Self {
        let socket = Arc::new(socket);
        let (accept_tx, accept_rx) = mpsc::channel(256);
        let (shutdown_tx, _) = watch::channel(false);

        let active_config = ArcSwap::from_pointee(DtlsServerActiveConfig {
            dimpl_config: frontend_config.dimpl_config,
            certificate: frontend_config.certificate,
            client_cert_verifier: frontend_config.client_cert_verifier,
        });

        Self {
            socket,
            active_config,
            sessions: Arc::new(DashMap::new()),
            active_sessions: Arc::new(AtomicUsize::new(0)),
            next_session_generation: AtomicU64::new(1),
            limits,
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            shutdown_tx,
        }
    }

    /// Atomically swap the DTLS crypto material used for **new** sessions.
    ///
    /// Used by mesh PeerAuthentication live reload to rotate the inbound DTLS
    /// `ServerConfig` equivalent (dimpl `Config` + certificate + optional
    /// `ClientCertVerifier`) without re-binding the socket or evicting any
    /// in-flight session. Active sessions keep the snapshot they handshake
    /// with until they end (see
    /// [`DtlsServerActiveConfig`] doc-comment for the invariant).
    pub fn swap_frontend_config(&self, frontend_config: FrontendDtlsConfig) {
        self.active_config.store(Arc::new(DtlsServerActiveConfig {
            dimpl_config: frontend_config.dimpl_config,
            certificate: frontend_config.certificate,
            client_cert_verifier: frontend_config.client_cert_verifier,
        }));
        info!(
            local_addr = ?self.socket.local_addr().ok(),
            "DTLS server frontend crypto material swapped (existing sessions retain old material)"
        );
    }

    /// Get the local address this server is bound to.
    #[allow(dead_code)] // Used by integration tests
    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("DTLS server socket has no local address")
    }

    /// Number of peers currently tracked by the DTLS demuxer.
    #[allow(dead_code)] // Used by tests and useful for diagnostics.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// Accept the next fully-handshaked DTLS client connection.
    ///
    /// Returns the connection handle and the client's socket address.
    pub async fn accept(&self) -> Result<(DtlsServerConn, SocketAddr), anyhow::Error> {
        let mut rx = self.accept_rx.lock().await;
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if *shutdown_rx.borrow() {
            return Err(anyhow::anyhow!("DTLS server shut down"));
        }
        tokio::select! {
            result = rx.recv() => {
                result.ok_or_else(|| anyhow::anyhow!("DTLS server shut down"))
            }
            _ = shutdown_rx.changed() => Err(anyhow::anyhow!("DTLS server shut down")),
        }
    }

    /// Run the DTLS server recv loop. Call this in a spawned task.
    ///
    /// Reads UDP datagrams, demuxes by source address, and drives per-client
    /// DTLS state machines. New clients are delivered via `accept()`.
    pub async fn run(&self) -> Result<(), anyhow::Error> {
        let mut buf = vec![0u8; 65536];
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        if *shutdown_rx.borrow() {
            return Ok(());
        }
        loop {
            let (len, peer_addr) = tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok(v) => v,
                        // Transient, per-peer recv errors must not kill the
                        // single demux loop for every session on the listener.
                        // Notably, on Windows `recvfrom` on an unconnected UDP
                        // socket fails with WSAECONNRESET whenever a prior
                        // `send_to` elicited an ICMP port-unreachable — i.e.,
                        // any DTLS client that disappears abruptly would
                        // permanently brick the listener (the caller only logs
                        // a warn and never restarts this loop).
                        Err(e) if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::WouldBlock
                        ) => {
                            trace!("DTLS server transient recv error (ignored): {}", e);
                            continue;
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("DTLS server recv error: {}", e));
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    return Ok(());
                }
            };
            if *shutdown_rx.borrow() {
                return Ok(());
            }

            let data = buf[..len].to_vec();

            // Clone the sender out of the DashMap guard before sending.
            // The `Ref` from `sessions.get()` holds a read lock on the shard;
            // holding it while a `SessionGuard::Drop` on the same shard needs
            // a write lock to call `sessions.remove()` would deadlock.
            let incoming_tx = self.sessions.get(&peer_addr).map(|s| s.incoming_tx.clone());
            if let Some(tx) = incoming_tx {
                // Existing session — forward packet to its driver. Never
                // `.send().await`: one session whose driver has stalled (its
                // proxy-side consumer stopped draining `app_out`) would fill
                // its bounded channel and park this single shared recv loop,
                // freezing demux — handshakes, retransmits, everything — for
                // EVERY peer on the listener. Dropping the datagram is correct
                // UDP semantics; DTLS retransmission recovers the loss.
                match tx.try_send(data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        trace!(
                            client = %peer_addr,
                            "DTLS session channel full; dropping datagram"
                        );
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Driver task exited — remove only THIS generation's
                        // stale map entry. A replacement session for the same
                        // peer may already have been inserted.
                        if let Some(generation) = self
                            .sessions
                            .get(&peer_addr)
                            .and_then(|s| s.incoming_tx.same_channel(&tx).then_some(s.generation))
                        {
                            remove_session(
                                &self.sessions,
                                &self.active_sessions,
                                self.limits.active_session_mirror.as_deref(),
                                &peer_addr,
                                generation,
                            );
                        }
                    }
                }
            } else if len >= 13 && data[0] == 0x16 {
                // New client — spawn a session driver. Only for datagrams that
                // plausibly start a DTLS handshake (content-type 0x16 with a
                // full 13-byte record header): spawning reserves a
                // `max_sessions` slot, allocates four channels, and holds the
                // slot for the handshake timeout, so arbitrary garbage from
                // scanners or spoofed floods must not reach it.
                self.spawn_session(peer_addr, data);
            } else {
                trace!(
                    client = %peer_addr,
                    len,
                    "DTLS: dropping non-handshake datagram from unknown source"
                );
            }
        }
    }

    /// Spawn a driver task for a new client session.
    ///
    /// Admission ordering is intentional and not jointly atomic:
    ///   1. `allow_new_session` is a *soft* gate (e.g. an overload-state flag).
    ///      It is read once before the cap check, so a brief burst between the
    ///      gate read and the CAS below can let a few sessions in past the
    ///      gate's intent. This is acceptable because the gate's job is
    ///      coarse-grained backpressure, not exact admission.
    ///   2. `max_sessions` is the *hard* cap, enforced via a CAS loop on
    ///      `active_sessions`. This is the authoritative bound — even if the
    ///      soft gate races, the hard cap cannot be exceeded.
    fn spawn_session(&self, peer_addr: SocketAddr, initial_packet: Vec<u8>) {
        if let Some(ref allow) = self.limits.allow_new_session
            && !allow()
        {
            trace!(client = %peer_addr, "DTLS new session rejected by admission gate");
            return;
        }

        if let Some(max_sessions) = self.limits.max_sessions {
            let mut current = self.active_sessions.load(Ordering::Relaxed);
            loop {
                if current >= max_sessions {
                    debug!(
                        client = %peer_addr,
                        max_sessions,
                        "DTLS pre-handshake session limit reached, dropping datagram"
                    );
                    return;
                }
                match self.active_sessions.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        } else {
            self.active_sessions.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(mirror) = self.limits.active_session_mirror.as_deref() {
            mirror.fetch_add(1, Ordering::Relaxed);
        }

        let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let (app_out_tx, app_out_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut app_out_rx = Some(app_out_rx);
        let (app_in_tx, mut app_in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let generation = self.next_session_generation.fetch_add(1, Ordering::Relaxed);
        // Terminating DTLS: this is best-effort SNI for the session's identity /
        // logging field only — dimpl runs the real handshake and rejects malformed
        // input itself, so a continuation fragment or no-SNI ClientHello both map
        // to `None` here (no drop-routing like the passthrough path does).
        let sni_hostname =
            match crate::proxy::sni::extract_sni_from_dtls_client_hello(&initial_packet) {
                crate::proxy::sni::DtlsSniResult::Hostname(host) => Some(host),
                crate::proxy::sni::DtlsSniResult::NoSni
                | crate::proxy::sni::DtlsSniResult::InvalidFragment => None,
            };

        self.sessions.insert(
            peer_addr,
            DtlsSessionState {
                incoming_tx: incoming_tx.clone(),
                shutdown_tx: shutdown_tx.clone(),
                generation,
            },
        );

        // Snapshot the swappable crypto material once per session so the
        // running handshake / session cannot observe a partial rotation.
        let active = self.active_config.load_full();
        let socket = self.socket.clone();
        let config = active.dimpl_config.clone();
        let certificate = active.certificate.clone();
        let accept_tx = self.accept_tx.clone();
        let sessions = self.sessions.clone();
        let active_sessions = self.active_sessions.clone();
        let active_session_mirror = self.limits.active_session_mirror.clone();
        let client_cert_verifier = active.client_cert_verifier.clone();
        let handshake_deadline = self
            .limits
            .handshake_timeout
            .map(|timeout| Instant::now() + timeout);

        tokio::spawn(async move {
            let _session_guard = SessionGuard {
                sessions: sessions.clone(),
                active_sessions: active_sessions.clone(),
                active_session_mirror: active_session_mirror.clone(),
                peer_addr,
                generation,
            };

            let mut dtls = Dtls::new_auto(config, certificate, Instant::now());
            // Server role (default — is_active=false)
            // Initialize server state (random, etc.) — required before handle_packet.
            // Drain the resulting Timeout outputs so they don't interfere with the
            // post-ClientHello drain.
            let _ = dtls.handle_timeout(Instant::now());

            let mut out_buf = vec![0u8; dtls_buf_config().output_buf_size];
            let mut next_timeout: Option<Instant> = None;
            let mut connected = false;
            // dimpl 0.6.1 emits only the peer leaf via Output::PeerCert, not
            // the rest of the client certificate chain.
            let mut peer_cert_der: Option<Arc<Vec<u8>>> = None;
            // Whether a client certificate was actually presented AND verified
            // against the configured client CA during the handshake. dimpl's
            // `require_client_certificate(true)` only makes the server SEND a
            // CertificateRequest; it still completes the handshake when the
            // client returns an empty Certificate (both DTLS 1.2 and 1.3), so an
            // empty cert produces no `Output::PeerCert` and `validate_client_cert`
            // never runs. We track verification explicitly and refuse to deliver
            // an unauthenticated session in the `Output::Connected` arm below.
            let mut verified_peer_cert = false;

            // Drain init outputs (just Timeout from handle_timeout)
            for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                if let Output::Timeout(t) = dtls.poll_output(&mut out_buf) {
                    next_timeout = Some(t);
                    break;
                }
            }

            // Process the initial ClientHello packet
            if let Err(e) = dtls.handle_packet(&initial_packet) {
                warn!(client = %peer_addr, "DTLS initial packet error: {}", e);
                return;
            }

            // Drain initial handshake outputs (ServerHello, etc.)
            match drain_server_outputs(
                &mut dtls,
                &mut out_buf,
                &socket,
                peer_addr,
                &mut next_timeout,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    warn!(client = %peer_addr, "DTLS initial drain error: {}", e);
                    return;
                }
            }

            loop {
                // Check the handshake deadline at the top of each iteration so
                // a sustained datagram flood cannot starve the timeout arm
                // in the select below.
                if !connected
                    && let Some(deadline) = handshake_deadline
                    && Instant::now() >= deadline
                {
                    warn!(client = %peer_addr, "DTLS handshake timed out");
                    break;
                }

                let handshake_sleep_dur = if connected {
                    Duration::from_secs(60)
                } else {
                    handshake_deadline
                        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_secs(60))
                };
                let sleep_dur = next_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(60));

                tokio::select! {
                    // Application data to send back to this client
                    Some(data) = app_in_rx.recv(), if connected => {
                        if data.len() > dtls_buf_config().max_plaintext {
                            warn!(
                                client = %peer_addr,
                                "DTLS dropping oversized datagram ({} bytes, max {})",
                                data.len(),
                                dtls_buf_config().max_plaintext,
                            );
                            continue;
                        }
                        if let Err(e) = dtls.send_application_data(&data) {
                            trace!(client = %peer_addr, "DTLS send error: {}", e);
                            break;
                        }
                    }
                    // Shutdown signal — drain any queued replies before
                    // exiting so a final reply pushed right before
                    // `DtlsServerConn::Drop` is not lost.
                    _ = shutdown_rx.recv() => {
                        while let Ok(data) = app_in_rx.try_recv() {
                            if connected
                                && data.len() <= dtls_buf_config().max_plaintext
                            {
                                let _ = dtls.send_application_data(&data);
                            }
                        }
                        break;
                    }
                    // Incoming UDP packet from this client (demuxed by the server)
                    Some(data) = incoming_rx.recv() => {
                        if let Err(e) = dtls.handle_packet(&data) {
                            trace!(client = %peer_addr, "DTLS handle_packet error: {}", e);
                            break;
                        }
                    }
                    // DTLS retransmit timer
                    _ = tokio::time::sleep(sleep_dur) => {
                        if let Some(t) = next_timeout
                            && Instant::now() >= t
                        {
                            if let Err(e) = dtls.handle_timeout(Instant::now()) {
                                trace!(client = %peer_addr, "DTLS timeout error: {}", e);
                                break;
                            }
                            next_timeout = None;
                        }
                    }
                    // Handshake deadline (top-of-loop check is primary;
                    // this is defense in depth).
                    _ = tokio::time::sleep(handshake_sleep_dur), if !connected && handshake_deadline.is_some() => {
                        warn!(client = %peer_addr, "DTLS handshake timed out");
                        break;
                    }
                }

                // Drain all pending outputs. After Connected, skip one Timeout
                // to capture final flight packets (dimpl emits Connected before
                // flushing CCS+Finished).
                let mut just_connected = false;
                for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                    match dtls.poll_output(&mut out_buf) {
                        Output::Packet(data) => {
                            let _ = socket.send_to(data, peer_addr).await;
                        }
                        Output::Timeout(t) => {
                            next_timeout = Some(t);
                            if just_connected {
                                just_connected = false;
                                continue;
                            }
                            break;
                        }
                        Output::Connected => {
                            just_connected = true;
                            connected = true;
                            // Enforce client-certificate authentication as a hard
                            // requirement. dimpl completes the handshake even when
                            // the client returns an empty Certificate, so without
                            // this gate an unauthenticated peer would be delivered
                            // with `tls_client_cert_der = None`, bypassing DTLS
                            // frontend mTLS. Refuse to deliver such a session.
                            if client_cert_verifier.is_some() && !verified_peer_cert {
                                warn!(
                                    client = %peer_addr,
                                    "DTLS frontend mTLS required but client presented no verified certificate; dropping session"
                                );
                                return;
                            }
                            // Deliver accepted connection (take app_out_rx — only happens once)
                            let Some(rx) = app_out_rx.take() else {
                                continue; // Already connected — should not happen
                            };
                            let conn = DtlsServerConn {
                                app_tx: app_in_tx.clone(),
                                app_rx: tokio::sync::Mutex::new(rx),
                                shutdown_tx: shutdown_tx.clone(),
                                tls_client_cert_der: peer_cert_der.clone(),
                                tls_client_cert_chain_der: None,
                                sni_hostname: sni_hostname.clone(),
                            };
                            if accept_tx.send((conn, peer_addr)).await.is_err() {
                                return;
                            }
                        }
                        Output::PeerCert(der) => {
                            if let Some(verifier) = client_cert_verifier.as_deref() {
                                if let Err(e) = validate_client_cert(der, verifier) {
                                    warn!(client = %peer_addr, "Client cert validation failed: {}", e);
                                    return;
                                }
                                // A client certificate was presented and verified
                                // against the configured client CA.
                                verified_peer_cert = true;
                            }
                            // Store the leaf certificate DER for plugin access
                            // after Connected.
                            peer_cert_der = Some(Arc::new(der.to_vec()));
                        }
                        Output::ApplicationData(data)
                            if app_out_tx.send(data.to_vec()).await.is_err() =>
                        {
                            // Application receiver dropped
                            break;
                        }
                        _ => {
                            // KeyingMaterial or future variants — continue draining
                        }
                    }
                }
            }

            // Flush any DTLS-buffered data produced by the shutdown
            // handler's reply drain so it reaches the wire.
            for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                match dtls.poll_output(&mut out_buf) {
                    Output::Packet(data) => {
                        let _ = socket.send_to(data, peer_addr).await;
                    }
                    _ => break,
                }
            }
        });
    }

    /// Shut down the server (close underlying socket).
    pub async fn close(&self) {
        self.shutdown_tx.send_replace(true);
        let session_shutdowns: Vec<mpsc::Sender<()>> = self
            .sessions
            .iter()
            .map(|entry| entry.shutdown_tx.clone())
            .collect();
        for shutdown_tx in session_shutdowns {
            let _ = shutdown_tx.try_send(());
        }

        if let Ok(local_addr) = self.socket.local_addr() {
            let wake_addr = if local_addr.ip().is_unspecified() {
                if local_addr.is_ipv6() {
                    SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                        local_addr.port(),
                    )
                } else {
                    SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        local_addr.port(),
                    )
                }
            } else {
                local_addr
            };
            let bind_addr = if wake_addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            if let Ok(waker) = UdpSocket::bind(bind_addr).await {
                let _ = waker.send_to(&[0], wake_addr).await;
            }
        }
    }
}

// ============================================================================
// Certificate Loading
// ============================================================================

/// Load a DTLS certificate from PEM files and convert to DER for dimpl.
///
/// Supports ECDSA P-256 and P-384 private keys. Ed25519 is NOT supported
/// by dimpl for DTLS signatures (unlike the previous webrtc-dtls library).
pub fn load_dtls_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<DtlsCertificate, anyhow::Error> {
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load DTLS cert {}: {}",
            cert_source.redacted_source_id(),
            e
        )
    })?;
    let key_material = load_material_blocking(&key_source, MaterialKind::Key).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load DTLS key {}: {}",
            key_source.redacted_source_id(),
            e
        )
    })?;

    // Parse PEM to DER
    let mut cert_reader = cert_material.bytes.expose_secret();
    let cert_der = rustls_pemfile::certs(&mut cert_reader)
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No certificate found in {}",
                cert_material.display_source_id
            )
        })?
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

    let mut key_reader = key_material.bytes.expose_secret();
    let key_der = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e))?
        .ok_or_else(|| {
            anyhow::anyhow!("No private key found in {}", key_material.display_source_id)
        })?;

    rustls::sign::CertifiedKey::from_der(
        vec![cert_der.clone()],
        key_der.clone_key(),
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "DTLS certificate {} and private key {} do not form a valid pair: {error}",
            cert_material.display_source_id,
            key_material.display_source_id
        )
    })?;

    // dimpl only supports ECDSA P-256 / P-384. Reject unsupported algorithms at
    // materialization time so admission/config load surfaces the defect instead
    // of panicking inside the DTLS handshake on first use.
    let private_key = key_der.secret_der().to_vec();
    Config::default()
        .crypto_provider()
        .key_provider
        .load_private_key(&private_key)
        .map_err(|e| {
            anyhow::anyhow!(
                "Unsupported DTLS private key in {} (dimpl requires ECDSA P-256 or P-384): {e}",
                key_material.display_source_id
            )
        })?;

    // SAFETY: dimpl::DtlsCertificate stores `private_key` as plain Vec<u8>
    // without zeroize-on-drop. Unlike the kTLS path (which uses
    // Zeroizing<Vec<u8>>), we cannot wrap the key here because dimpl owns
    // the Vec. The key material persists in freed heap until reallocation.
    // Upstream contribution needed to add Zeroize to dimpl::DtlsCertificate.
    Ok(DtlsCertificate {
        certificate: cert_der.to_vec(),
        private_key,
    })
}

/// Load a rustls root store from a PEM file.
pub fn load_root_store_from_pem(pem_path: &str) -> Result<rustls::RootCertStore, anyhow::Error> {
    let source = CertSource::parse(pem_path, MaterialKind::CaBundle);
    let material = load_material_blocking(&source, MaterialKind::CaBundle).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load PEM source {}: {}",
            source.redacted_source_id(),
            e
        )
    })?;
    let mut certs = Vec::new();
    let mut parse_errors = 0usize;
    let mut reader = material.bytes.expose_secret();
    for cert in rustls_pemfile::certs(&mut reader) {
        match cert {
            Ok(cert) => certs.push(cert),
            Err(err) => {
                parse_errors += 1;
                tracing::warn!(
                    pem_path = %material.display_source_id,
                    error = %err,
                    "Skipping unparsable certificate while loading DTLS CA bundle"
                );
            }
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow::anyhow!(
            "No valid certificates found in DTLS CA file {} (ignored: {}, parse_errors: {})",
            material.display_source_id,
            ignored,
            parse_errors
        ));
    }
    Ok(roots)
}

fn load_backend_root_store(
    proxy: &Proxy,
    global_ca_bundle_path: Option<&str>,
) -> Result<rustls::RootCertStore, anyhow::Error> {
    if let Some(ca_path) = &proxy.resolved_tls.server_ca_cert_path {
        load_root_store_from_pem(ca_path)
    } else if let Some(global_ca) = global_ca_bundle_path {
        load_root_store_from_pem(global_ca)
    } else {
        Ok(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }
}

/// Generate an ephemeral self-signed certificate for DTLS clients that don't
/// need client authentication (the common case for backend connections).
fn generate_ephemeral_cert() -> Result<DtlsCertificate, anyhow::Error> {
    dimpl::certificate::generate_self_signed_certificate()
        .map_err(|e| anyhow::anyhow!("Failed to generate ephemeral DTLS cert: {}", e))
}

/// Generate a self-signed DTLS certificate for testing.
#[allow(dead_code)]
pub fn generate_self_signed_cert() -> Result<DtlsCertificate, anyhow::Error> {
    generate_ephemeral_cert()
}

/// Generate an ephemeral self-signed certificate for DTLS clients that don't
/// need client authentication.
pub fn generate_ephemeral_cert_public() -> Result<DtlsCertificate, anyhow::Error> {
    generate_ephemeral_cert()
}

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate a backend server's DER-encoded leaf certificate.
///
/// `dimpl` surfaces only the peer leaf certificate, not the peer's full
/// certificate chain. Verification therefore runs fail-closed against the leaf,
/// the configured trust anchors, and the expected server name.
fn validate_server_cert(
    peer_der: &[u8],
    server_name: &rustls::pki_types::ServerName<'static>,
    verifier: &dyn rustls::client::danger::ServerCertVerifier,
) -> Result<(), anyhow::Error> {
    let cert = rustls::pki_types::CertificateDer::from(peer_der.to_vec());
    verifier
        .verify_server_cert(
            &cert,
            &[],
            server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("DTLS server certificate verification failed: {}", e))
}

/// Validate a frontend client certificate when DTLS mTLS is enabled.
fn validate_client_cert(
    peer_der: &[u8],
    verifier: &dyn rustls::server::danger::ClientCertVerifier,
) -> Result<(), anyhow::Error> {
    let cert = rustls::pki_types::CertificateDer::from(peer_der.to_vec());
    verifier
        .verify_client_cert(&cert, &[], rustls::pki_types::UnixTime::now())
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("DTLS client certificate verification failed: {}", e))
}

// ============================================================================
// Sans-IO Helpers
// ============================================================================

/// Drain `poll_output()` during a client-side handshake. Sends packets via
/// a connected socket, captures the retransmit timeout, validates peer cert.
/// Returns `true` when `Output::Connected` is observed (handshake complete).
///
/// **Important dimpl behavior**: `poll_output()` returns `Timeout` repeatedly
/// once all actionable outputs are drained, so we normally break on the first
/// `Timeout`. However, dimpl emits `Connected` from a local event queue BEFORE
/// flushing the final handshake flight packets (CCS+Finished). So after seeing
/// `Connected`, we must skip one Timeout and keep draining to capture those
/// final packets.
#[allow(clippy::too_many_arguments)]
async fn drain_handshake_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    next_timeout: &mut Option<Instant>,
    server_name: Option<&rustls::pki_types::ServerName<'static>>,
    server_cert_verifier: Option<&dyn rustls::client::danger::ServerCertVerifier>,
    verified_server_cert: &mut bool,
) -> Result<bool, anyhow::Error> {
    let mut connected = false;
    let mut saw_timeout_after_connected = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                if let Some(addr) = peer {
                    socket
                        .send_to(data, addr)
                        .await
                        .map_err(|e| anyhow::anyhow!("UDP send_to: {}", e))?;
                } else {
                    socket
                        .send(data)
                        .await
                        .map_err(|e| anyhow::anyhow!("UDP send: {}", e))?;
                }
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                // After Connected, dimpl may emit Timeout before final flight
                // packets. Skip one Timeout, then break on the next.
                if connected && !saw_timeout_after_connected {
                    saw_timeout_after_connected = true;
                    continue;
                }
                break;
            }
            Output::Connected => {
                connected = true;
            }
            Output::PeerCert(der) => {
                if let (Some(server_name), Some(verifier)) = (server_name, server_cert_verifier) {
                    validate_server_cert(der, server_name, verifier)?;
                    *verified_server_cert = true;
                }
            }
            Output::ApplicationData(_) => {
                // Unexpected during handshake but not fatal
            }
            _ => {
                // KeyingMaterial or future non_exhaustive variants — continue draining
            }
        }
    }
    Ok(connected)
}

/// Drain `poll_output()` and send packets to a specific peer address (for server-side).
/// Captures the retransmit timeout. Returns `true` on `Connected`.
/// Same Timeout-skipping logic as `drain_handshake_outputs` for post-Connected packets.
async fn drain_server_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: SocketAddr,
    next_timeout: &mut Option<Instant>,
) -> Result<bool, anyhow::Error> {
    let mut connected = false;
    let mut saw_timeout_after_connected = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                socket
                    .send_to(data, peer)
                    .await
                    .map_err(|e| anyhow::anyhow!("UDP send_to: {}", e))?;
            }
            Output::Timeout(t) => {
                *next_timeout = Some(t);
                if connected && !saw_timeout_after_connected {
                    saw_timeout_after_connected = true;
                    continue;
                }
                break;
            }
            Output::Connected => {
                connected = true;
            }
            Output::PeerCert(_) | Output::ApplicationData(_) => {}
            _ => {
                // KeyingMaterial or future variants — continue draining
            }
        }
    }
    Ok(connected)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_server(limits: DtlsServerLimits) -> DtlsServer {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind UDP");
        let config = Config::builder().build().expect("build DTLS config");
        let certificate =
            dimpl::certificate::generate_self_signed_certificate().expect("generate cert");
        DtlsServer::from_socket_with_limits(
            socket,
            FrontendDtlsConfig {
                dimpl_config: Arc::new(config),
                certificate,
                client_cert_verifier: None,
            },
            limits,
        )
    }

    fn client_hello_packet() -> Vec<u8> {
        let config = Arc::new(Config::builder().build().expect("build DTLS config"));
        let certificate =
            dimpl::certificate::generate_self_signed_certificate().expect("generate client cert");
        let mut client = Dtls::new_auto(config, certificate, Instant::now());
        client.set_active(true);
        let mut buf = vec![0u8; 4096];

        for _ in 0..MAX_OUTPUTS_PER_DRAIN {
            if let Output::Packet(data) = client.poll_output(&mut buf) {
                return data.to_vec();
            }
        }

        panic!("client did not emit a ClientHello packet");
    }

    fn dtls_client_hello_packet_with_sni(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 1 + 2 + name_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&0x0000u16.to_be_bytes());
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let mut body = Vec::new();
        body.extend_from_slice(&[0xfe, 0xfd]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x2f]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni_ext);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let body_len = body.len();
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8);
        handshake.extend_from_slice(&[0x00, 0x00]);
        handshake.extend_from_slice(&[0x00, 0x00, 0x00]);
        handshake.push((body_len >> 16) as u8);
        handshake.push((body_len >> 8) as u8);
        handshake.push(body_len as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0xfe, 0xfd]);
        record.extend_from_slice(&[0x00, 0x00]);
        record.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn dtls_client_hello_sni_is_extracted_for_server_connections() {
        let packet = dtls_client_hello_packet_with_sni("Admin.Mesh.Internal");
        assert_eq!(
            crate::proxy::sni::extract_sni_from_dtls_client_hello(&packet),
            crate::proxy::sni::DtlsSniResult::Hostname("admin.mesh.internal".to_string())
        );
    }

    #[tokio::test]
    async fn dtls_server_rejects_new_peer_when_pre_handshake_cap_is_full() {
        let server = test_server(DtlsServerLimits {
            max_sessions: Some(0),
            ..DtlsServerLimits::default()
        })
        .await;

        server.spawn_session("127.0.0.1:12345".parse().unwrap(), vec![0x16; 32]);

        assert_eq!(server.active_session_count(), 0);
        assert!(server.sessions.is_empty());
    }

    #[tokio::test]
    async fn dtls_server_rejects_new_peer_when_admission_gate_is_closed() {
        let server = test_server(DtlsServerLimits {
            allow_new_session: Some(Arc::new(|| false)),
            ..DtlsServerLimits::default()
        })
        .await;

        server.spawn_session("127.0.0.1:12346".parse().unwrap(), vec![0x16; 32]);

        assert_eq!(server.active_session_count(), 0);
        assert!(server.sessions.is_empty());
    }

    #[tokio::test]
    async fn dtls_server_rejects_second_peer_at_cap_and_releases_mirror_on_timeout() {
        let mirror = Arc::new(AtomicU64::new(0));
        let server = test_server(DtlsServerLimits {
            max_sessions: Some(1),
            handshake_timeout: Some(Duration::from_millis(50)),
            active_session_mirror: Some(mirror.clone()),
            ..DtlsServerLimits::default()
        })
        .await;

        server.spawn_session("127.0.0.1:12347".parse().unwrap(), client_hello_packet());
        assert_eq!(server.active_session_count(), 1);
        assert_eq!(mirror.load(Ordering::Relaxed), 1);

        server.spawn_session("127.0.0.1:12348".parse().unwrap(), client_hello_packet());
        assert_eq!(server.active_session_count(), 1);
        assert_eq!(mirror.load(Ordering::Relaxed), 1);

        tokio::time::timeout(Duration::from_secs(1), async {
            while server.active_session_count() != 0 || mirror.load(Ordering::Relaxed) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("DTLS handshake timeout should release the reserved slot");

        assert!(server.sessions.is_empty());
    }

    /// Backend DTLS handshake honors the configured `connect_timeout_ms`
    /// instead of the previously hardcoded 10s budget.
    ///
    /// Sets `connect_timeout_ms = 500` against a UDP socket whose peer is a
    /// silent black-hole (binds + drops every datagram). The handshake must
    /// fail well before the old 10s budget — generous slack of 5s catches
    /// loaded CI runners while still distinguishing the configured budget.
    #[tokio::test]
    async fn dtls_backend_handshake_honors_connect_timeout_ms() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        // Black-hole peer: bind a UDP socket that never replies. The client
        // socket is `connect()`-ed to it so all datagrams go to /dev/null.
        let blackhole = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole");
        let blackhole_addr = blackhole.local_addr().expect("blackhole local addr");

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        client_socket
            .connect(blackhole_addr)
            .await
            .expect("client connect");

        let certificate =
            dimpl::certificate::generate_self_signed_certificate().expect("generate client cert");
        let params = BackendDtlsParams {
            config: Arc::new(Config::default()),
            certificate,
            server_name: None,
            server_cert_verifier: None,
            connect_timeout_ms: 500,
        };

        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            DtlsConnection::connect(client_socket, params),
        )
        .await
        .expect("outer guard should not fire — connect_timeout_ms=500 must bound the handshake");
        let elapsed = started.elapsed();

        let err = match result {
            Ok(_) => panic!("handshake against black hole should fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("DTLS handshake timed out"),
            "expected timeout error, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "handshake should fail close to the configured 500ms budget, took {elapsed:?}"
        );
    }

    /// PeerAuthentication live reload (T3-A) for mesh UDP+DTLS stream
    /// listeners hot-swaps the `FrontendDtlsConfig` on a running
    /// `DtlsServer` without recycling the socket. The swap is atomic and
    /// new sessions snapshot the latest material at spawn time; existing
    /// sessions are unaffected.
    #[tokio::test]
    async fn dtls_server_swap_frontend_config_updates_active_config_atomically() {
        let server = test_server(DtlsServerLimits::default()).await;

        // Capture a pointer to the old active config so we can prove the
        // swap actually replaced it (not just mutated in place).
        let before = Arc::as_ptr(&server.active_config.load_full());

        let new_certificate =
            dimpl::certificate::generate_self_signed_certificate().expect("generate cert");
        let new_config = Config::builder().build().expect("build DTLS config");
        server.swap_frontend_config(FrontendDtlsConfig {
            dimpl_config: Arc::new(new_config),
            certificate: new_certificate.clone(),
            client_cert_verifier: None,
        });

        let after = Arc::as_ptr(&server.active_config.load_full());
        assert_ne!(
            before, after,
            "swap_frontend_config must replace the active_config Arc"
        );

        // New session spawns must observe the swapped certificate. Drive a
        // single session to validate the snapshot path: `spawn_session`
        // captures the swapped `certificate` value rather than the
        // original.
        server.spawn_session("127.0.0.1:43210".parse().unwrap(), client_hello_packet());
        assert!(
            server.active_session_count() <= 1,
            "spawn_session honored admission limits after a live-reload swap"
        );
    }

    #[test]
    fn remove_session_is_generation_aware() {
        let sessions: DashMap<SocketAddr, DtlsSessionState> = DashMap::new();
        let active = AtomicUsize::new(0);
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();

        let (tx1, _rx1) = mpsc::channel::<Vec<u8>>(1);
        let (shutdown1, _) = mpsc::channel::<()>(1);
        sessions.insert(
            peer,
            DtlsSessionState {
                incoming_tx: tx1,
                shutdown_tx: shutdown1,
                generation: 1,
            },
        );
        active.store(1, Ordering::Relaxed);

        // Replacement generation-2 entry for the same peer.
        let (tx2, _rx2) = mpsc::channel::<Vec<u8>>(1);
        let (shutdown2, _) = mpsc::channel::<()>(1);
        sessions.insert(
            peer,
            DtlsSessionState {
                incoming_tx: tx2,
                shutdown_tx: shutdown2,
                generation: 2,
            },
        );
        active.store(1, Ordering::Relaxed);

        // Stale generation-1 cleanup must not evict the live generation-2 entry.
        remove_session(&sessions, &active, None, &peer, 1);
        assert_eq!(sessions.get(&peer).unwrap().generation, 2);
        assert_eq!(active.load(Ordering::Relaxed), 1);

        remove_session(&sessions, &active, None, &peer, 2);
        assert!(sessions.get(&peer).is_none());
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn session_guard_drop_does_not_evict_replacement_generation() {
        let sessions = Arc::new(DashMap::new());
        let active = Arc::new(AtomicUsize::new(1));
        let peer: SocketAddr = "127.0.0.1:5556".parse().unwrap();

        let (tx2, _rx2) = mpsc::channel::<Vec<u8>>(1);
        let (shutdown2, _) = mpsc::channel::<()>(1);
        sessions.insert(
            peer,
            DtlsSessionState {
                incoming_tx: tx2,
                shutdown_tx: shutdown2,
                generation: 2,
            },
        );

        {
            let _stale_guard = SessionGuard {
                sessions: Arc::clone(&sessions),
                active_sessions: Arc::clone(&active),
                active_session_mirror: None,
                peer_addr: peer,
                generation: 1,
            };
            // Drop stale generation-1 guard while generation-2 is live.
        }

        assert_eq!(
            sessions.get(&peer).unwrap().generation,
            2,
            "stale SessionGuard must not remove a newer live session"
        );
        assert_eq!(active.load(Ordering::Relaxed), 1);
    }
}

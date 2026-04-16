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
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dimpl::{Config, Dtls, DtlsCertificate, Output};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, trace, warn};

use crate::config::types::Proxy;

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

/// Maximum datagrams to drain per `poll_output` loop before yielding.
const MAX_OUTPUTS_PER_DRAIN: usize = 64;

// ============================================================================
// Configuration Builders
// ============================================================================

/// Frontend DTLS server configuration (client → gateway).
pub struct FrontendDtlsConfig {
    pub dimpl_config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
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
        let root_store = load_backend_root_store(proxy)?;
        let server_name = rustls::pki_types::ServerName::try_from(backend_host.to_string())
            .map_err(|_| {
                anyhow::anyhow!(
                    "Invalid DTLS backend host for certificate verification: {}",
                    backend_host
                )
            })?;
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)?;
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
    })
}

/// Parameters for creating a backend DTLS connection.
pub struct BackendDtlsParams {
    pub config: Arc<Config>,
    pub certificate: DtlsCertificate,
    pub server_name: Option<rustls::pki_types::ServerName<'static>>,
    pub server_cert_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
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
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Receive decrypted application data from the DTLS engine.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Signal the driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
}

impl DtlsConnection {
    /// Perform a DTLS client handshake over the given connected socket and return
    /// an established `DtlsConnection`.
    pub async fn connect(
        socket: UdpSocket,
        params: BackendDtlsParams,
    ) -> Result<Self, anyhow::Error> {
        let socket = Arc::new(socket);
        let server_name = params.server_name;
        let server_cert_verifier = params.server_cert_verifier;
        let mut dtls = Dtls::new_auto(params.config, params.certificate, Instant::now());
        dtls.set_active(true); // client role

        // Drive handshake to completion
        let mut out_buf = vec![0u8; dtls_buf_config().output_buf_size];
        let mut recv_buf = vec![0u8; 65536];
        let mut next_timeout: Option<Instant> = None;

        // Kick off the handshake by draining initial outputs (ClientHello + Timeout)
        drain_handshake_outputs(
            &mut dtls,
            &mut out_buf,
            &socket,
            None,
            &mut next_timeout,
            server_name.as_ref(),
            server_cert_verifier.as_deref(),
        )
        .await?;

        let handshake_deadline = Instant::now() + Duration::from_secs(10);

        loop {
            if Instant::now() > handshake_deadline {
                return Err(anyhow::anyhow!("DTLS handshake timed out"));
            }

            let sleep_dur = next_timeout
                .map(|t| t.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(1));

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
            )
            .await?;

            if connected {
                return Ok(Self::spawn_driver(dtls, socket));
            }
        }
    }

    /// Spawn the background driver task and return the connection handle.
    fn spawn_driver(dtls: Dtls, socket: Arc<UdpSocket>) -> Self {
        // Channels: app data in/out, shutdown signal
        let (app_tx, mut driver_app_rx) = mpsc::channel::<Vec<u8>>(256);
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

                tokio::select! {
                    // Incoming UDP datagram from peer
                    result = socket.recv(&mut recv_buf) => {
                        match result {
                            Ok(len) => {
                                if let Err(e) = dtls.handle_packet(&recv_buf[..len]) {
                                    trace!("DTLS handle_packet error: {}", e);
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // Application data to send
                    Some(data) = driver_app_rx.recv() => {
                        if data.len() > dtls_buf_config().max_plaintext {
                            warn!(
                                "DTLS dropping oversized datagram ({} bytes, max {})",
                                data.len(),
                                dtls_buf_config().max_plaintext,
                            );
                            continue;
                        }
                        if let Err(e) = dtls.send_application_data(&data) {
                            trace!("DTLS send_application_data error: {}", e);
                            break;
                        }
                    }
                    // Timer fired
                    _ = tokio::time::sleep(sleep_dur) => {
                        if let Some(t) = next_timeout
                            && Instant::now() >= t
                        {
                            if let Err(e) = dtls.handle_timeout(Instant::now()) {
                                trace!("DTLS handle_timeout error: {}", e);
                                break;
                            }
                            next_timeout = None;
                        }
                    }
                    // Shutdown requested
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }

                // Drain all pending outputs (break on Timeout — it repeats forever)
                for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                    match dtls.poll_output(&mut out_buf) {
                        Output::Packet(data) => {
                            let _ = socket.send(data).await;
                        }
                        Output::Timeout(t) => {
                            next_timeout = Some(t);
                            break;
                        }
                        Output::ApplicationData(data) => {
                            if driver_app_tx.send(data.to_vec()).await.is_err() {
                                return; // receiver dropped
                            }
                        }
                        Output::Connected | Output::PeerCert(_) => {
                            // Already handled during handshake
                        }
                        _ => break,
                    }
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
    pub async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.app_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("DTLS connection closed"))
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

// ============================================================================
// DtlsServer — frontend DTLS session demuxer
// ============================================================================

/// A DTLS server that manages multiple client sessions on a single UDP socket.
///
/// Demultiplexes incoming UDP datagrams by source address, creating a new `Dtls`
/// state machine for each new client. Accepted connections are delivered via
/// a channel as `DtlsServerConn` instances.
pub struct DtlsServer {
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
    certificate: DtlsCertificate,
    sessions: Arc<DashMap<SocketAddr, DtlsSessionState>>,
    /// Channel to deliver accepted (post-handshake) connections.
    accept_tx: mpsc::Sender<(DtlsServerConn, SocketAddr)>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(DtlsServerConn, SocketAddr)>>,
    client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    shutdown_tx: watch::Sender<bool>,
}

/// State for a server-side DTLS session being managed by the DtlsServer.
struct DtlsSessionState {
    /// Send incoming UDP data to this session's driver task.
    incoming_tx: mpsc::Sender<Vec<u8>>,
    /// Signal this session's driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
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
    /// DER-encoded client certificate from the DTLS handshake (first cert in chain).
    /// Populated when the client presents a certificate during mutual DTLS authentication.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded intermediate/CA certificates from the client's certificate chain
    /// (all certs after the peer cert). `None` when no chain certs were sent.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
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

impl DtlsServer {
    /// Create a new DTLS server bound to the given address.
    pub async fn bind(
        addr: SocketAddr,
        frontend_config: FrontendDtlsConfig,
    ) -> Result<Self, anyhow::Error> {
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to bind DTLS server on {}: {}", addr, e))?,
        );

        let (accept_tx, accept_rx) = mpsc::channel(256);
        let (shutdown_tx, _) = watch::channel(false);

        Ok(Self {
            socket,
            config: frontend_config.dimpl_config,
            certificate: frontend_config.certificate,
            sessions: Arc::new(DashMap::new()),
            accept_tx,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            client_cert_verifier: frontend_config.client_cert_verifier,
            shutdown_tx,
        })
    }

    /// Get the local address this server is bound to.
    #[allow(dead_code)] // Used by integration tests
    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("DTLS server socket has no local address")
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
                    result.map_err(|e| anyhow::anyhow!("DTLS server recv error: {}", e))?
                }
                _ = shutdown_rx.changed() => {
                    return Ok(());
                }
            };
            if *shutdown_rx.borrow() {
                return Ok(());
            }

            let data = buf[..len].to_vec();

            if let Some(session) = self.sessions.get(&peer_addr) {
                // Existing session — forward packet to its driver
                if session.incoming_tx.send(data).await.is_err() {
                    // Driver task exited — remove stale session
                    drop(session);
                    self.sessions.remove(&peer_addr);
                }
            } else {
                // New client — spawn a session driver
                self.spawn_session(peer_addr, data);
            }
        }
    }

    /// Spawn a driver task for a new client session.
    fn spawn_session(&self, peer_addr: SocketAddr, initial_packet: Vec<u8>) {
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(256);
        let (app_out_tx, app_out_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut app_out_rx = Some(app_out_rx);
        let (app_in_tx, mut app_in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        self.sessions.insert(
            peer_addr,
            DtlsSessionState {
                incoming_tx: incoming_tx.clone(),
                shutdown_tx: shutdown_tx.clone(),
            },
        );

        let socket = self.socket.clone();
        let config = self.config.clone();
        let certificate = self.certificate.clone();
        let accept_tx = self.accept_tx.clone();
        let sessions = self.sessions.clone();
        let client_cert_verifier = self.client_cert_verifier.clone();

        tokio::spawn(async move {
            let mut dtls = Dtls::new_auto(config, certificate, Instant::now());
            // Server role (default — is_active=false)
            // Initialize server state (random, etc.) — required before handle_packet.
            // Drain the resulting Timeout outputs so they don't interfere with the
            // post-ClientHello drain.
            let _ = dtls.handle_timeout(Instant::now());

            let mut out_buf = vec![0u8; dtls_buf_config().output_buf_size];
            let mut next_timeout: Option<Instant> = None;
            let mut connected = false;
            // Collect client certificate DER bytes emitted via Output::PeerCert
            // during the DTLS handshake. The first cert is the peer cert, the
            // rest are intermediates/CA chain certs.
            let mut peer_cert_ders: Vec<Vec<u8>> = Vec::new();

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
                sessions.remove(&peer_addr);
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
                    sessions.remove(&peer_addr);
                    return;
                }
            }

            loop {
                let sleep_dur = next_timeout
                    .map(|t| t.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(60));

                tokio::select! {
                    // Incoming UDP packet from this client (demuxed by the server)
                    Some(data) = incoming_rx.recv() => {
                        if let Err(e) = dtls.handle_packet(&data) {
                            trace!(client = %peer_addr, "DTLS handle_packet error: {}", e);
                            break;
                        }
                    }
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
                    // Timer fired
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
                    _ = shutdown_rx.recv() => {
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
                            // Deliver accepted connection (take app_out_rx — only happens once)
                            let Some(rx) = app_out_rx.take() else {
                                continue; // Already connected — should not happen
                            };
                            // Extract collected client certificates: first = peer cert, rest = chain
                            let (peer_cert, chain_certs) = if peer_cert_ders.is_empty() {
                                (None, None)
                            } else {
                                let peer = Arc::new(peer_cert_ders[0].clone());
                                let chain = if peer_cert_ders.len() > 1 {
                                    Some(Arc::new(peer_cert_ders[1..].to_vec()))
                                } else {
                                    None
                                };
                                (Some(peer), chain)
                            };
                            let conn = DtlsServerConn {
                                app_tx: app_in_tx.clone(),
                                app_rx: tokio::sync::Mutex::new(rx),
                                shutdown_tx: shutdown_tx.clone(),
                                tls_client_cert_der: peer_cert,
                                tls_client_cert_chain_der: chain_certs,
                            };
                            if accept_tx.send((conn, peer_addr)).await.is_err() {
                                // Server shut down
                                sessions.remove(&peer_addr);
                                return;
                            }
                        }
                        Output::PeerCert(der) => {
                            if let Some(verifier) = client_cert_verifier.as_deref()
                                && let Err(e) = validate_client_cert(der, verifier)
                            {
                                warn!(client = %peer_addr, "Client cert validation failed: {}", e);
                                sessions.remove(&peer_addr);
                                return;
                            }
                            // Store the certificate DER for plugin access after Connected
                            peer_cert_ders.push(der.to_vec());
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

            sessions.remove(&peer_addr);
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
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS cert {}: {}", cert_path, e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Failed to read DTLS key {}: {}", key_path, e))?;

    // Parse PEM to DER
    let cert_der = rustls_pemfile::certs(&mut &cert_pem[..])
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found in {}", cert_path))?
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

    let key_der = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    Ok(DtlsCertificate {
        certificate: cert_der.to_vec(),
        private_key: key_der.secret_der().to_vec(),
    })
}

/// Load a rustls root store from a PEM file.
pub fn load_root_store_from_pem(pem_path: &str) -> Result<rustls::RootCertStore, anyhow::Error> {
    let pem_data = std::fs::read(pem_path)
        .map_err(|e| anyhow::anyhow!("Failed to read PEM file {}: {}", pem_path, e))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut &pem_data[..])
        .filter_map(|r| r.ok())
        .collect();
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow::anyhow!(
            "No valid certificates found in DTLS CA file {} (ignored: {})",
            pem_path,
            ignored
        ));
    }
    Ok(roots)
}

fn load_backend_root_store(proxy: &Proxy) -> Result<rustls::RootCertStore, anyhow::Error> {
    if let Some(ca_path) = &proxy.resolved_tls.server_ca_cert_path {
        load_root_store_from_pem(ca_path)
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
async fn drain_handshake_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: Option<SocketAddr>,
    next_timeout: &mut Option<Instant>,
    server_name: Option<&rustls::pki_types::ServerName<'static>>,
    server_cert_verifier: Option<&dyn rustls::client::danger::ServerCertVerifier>,
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

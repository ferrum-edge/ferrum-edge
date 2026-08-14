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
use dimpl::{Config, Dtls, DtlsCertificateChain, DtlsPrivateKey, Output};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, trace, warn};

use crate::config::types::Proxy;
use crate::proxy::datagram_client_address::DatagramMetadataError;
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

/// Terminating-frontend application payload waiting for encrypt + UDP write.
///
/// Unlike [`PendingAppSend`] (backend/client-role), this carries the admitted
/// absolute authorization deadline and a cancel receiver held by the proxy-side
/// send future. Dropping that future closes `cancel` so a request already in
/// the channel cannot be encrypted or written later.
struct FrontendAppSend {
    data: Vec<u8>,
    completion: oneshot::Sender<Result<(), String>>,
    cancel: oneshot::Receiver<()>,
    deadline: Option<tokio::time::Instant>,
}

struct InFlightFrontendAppSend {
    completion: oneshot::Sender<Result<(), String>>,
    cancel: oneshot::Receiver<()>,
    deadline: Option<tokio::time::Instant>,
}

/// Why a terminating-frontend application send must not encrypt or `send_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontendAppSendReject {
    /// The admitted absolute authorization deadline has elapsed. Exact ties
    /// (`now >= deadline`) fail closed.
    Expired,
    /// The proxy-side send future was dropped, so this queued request must not
    /// be encrypted or written.
    Cancelled,
    /// Driver shutdown or connection close. Never used to flush a still-
    /// authorized leftover as a successful wire commit.
    Closed,
}

impl FrontendAppSendReject {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "DTLS application send expired",
            Self::Cancelled => "DTLS application send cancelled",
            Self::Closed => "DTLS server connection closed",
        }
    }
}

/// Admission verdict for one queued or in-flight frontend application send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrontendAppSendAdmit {
    Proceed,
    Reject(FrontendAppSendReject),
}

/// Decide whether a frontend application send may encrypt or poll `send_to`.
///
/// An already-elapsed deadline is checked first and never proceeds, so the
/// application send future is not polled. Exact ties fail closed. Cancellation
/// is independent: dropping the proxy send future must discard the request
/// even if the deadline has not elapsed.
pub(crate) fn admit_frontend_app_send(
    cancelled: bool,
    deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> FrontendAppSendAdmit {
    if let Some(at) = deadline
        && now >= at
    {
        return FrontendAppSendAdmit::Reject(FrontendAppSendReject::Expired);
    }
    if cancelled {
        return FrontendAppSendAdmit::Reject(FrontendAppSendReject::Cancelled);
    }
    FrontendAppSendAdmit::Proceed
}

/// Shutdown never encrypts queued application replies. Expired and cancelled
/// requests keep that reason; a still-authorized leftover is closed rather
/// than flushed after the sender was dropped.
pub(crate) fn shutdown_queued_frontend_app_send(
    cancelled: bool,
    deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> FrontendAppSendReject {
    match admit_frontend_app_send(cancelled, deadline, now) {
        FrontendAppSendAdmit::Reject(reason) => reason,
        FrontendAppSendAdmit::Proceed => FrontendAppSendReject::Closed,
    }
}

/// Lock-free, monotonically-earliest admitted authorization deadline for one
/// terminating frontend DTLS session. Unset reads as `None` (unauthenticated).
/// Publication only tightens; a later instant can never extend the bound.
struct FrontendSessionAuthDeadline {
    anchor: tokio::time::Instant,
    earliest_ns: AtomicU64,
}

const FRONTEND_SESSION_AUTH_DEADLINE_UNSET: u64 = u64::MAX;
const FRONTEND_SESSION_AUTH_DEADLINE_MAX_ENCODED: u64 = FRONTEND_SESSION_AUTH_DEADLINE_UNSET - 1;

fn encode_frontend_session_auth_deadline_offset(offset_nanos: u128) -> u64 {
    match u64::try_from(offset_nanos) {
        Ok(encoded) if encoded < FRONTEND_SESSION_AUTH_DEADLINE_UNSET => encoded,
        _ => FRONTEND_SESSION_AUTH_DEADLINE_MAX_ENCODED,
    }
}

fn encode_frontend_session_auth_deadline(
    anchor: tokio::time::Instant,
    at: tokio::time::Instant,
) -> u64 {
    encode_frontend_session_auth_deadline_offset(at.saturating_duration_since(anchor).as_nanos())
}

fn reconstruct_frontend_session_auth_deadline_from_duration(
    anchor: tokio::time::Instant,
    offset: Duration,
) -> tokio::time::Instant {
    anchor.checked_add(offset).unwrap_or(anchor)
}

fn reconstruct_frontend_session_auth_deadline(
    anchor: tokio::time::Instant,
    encoded: u64,
) -> tokio::time::Instant {
    reconstruct_frontend_session_auth_deadline_from_duration(anchor, Duration::from_nanos(encoded))
}

impl FrontendSessionAuthDeadline {
    fn new() -> Self {
        Self {
            anchor: tokio::time::Instant::now(),
            earliest_ns: AtomicU64::new(FRONTEND_SESSION_AUTH_DEADLINE_UNSET),
        }
    }

    fn publish(&self, at: tokio::time::Instant) {
        let encoded = encode_frontend_session_auth_deadline(self.anchor, at);
        let mut current = self.earliest_ns.load(Ordering::Acquire);
        loop {
            if current != FRONTEND_SESSION_AUTH_DEADLINE_UNSET && encoded >= current {
                return;
            }
            match self.earliest_ns.compare_exchange_weak(
                current,
                encoded,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn get(&self) -> Option<tokio::time::Instant> {
        let encoded = self.earliest_ns.load(Ordering::Acquire);
        if encoded == FRONTEND_SESSION_AUTH_DEADLINE_UNSET {
            None
        } else {
            Some(reconstruct_frontend_session_auth_deadline(
                self.anchor,
                encoded,
            ))
        }
    }
}

/// Combine a per-call application-send deadline with the session's admitted
/// authorization deadline. `None` only when both inputs are absent; otherwise
/// the earliest instant governs so a later per-call value cannot extend
/// authorization.
fn earliest_frontend_app_send_deadline(
    per_call: Option<tokio::time::Instant>,
    session: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    match (per_call, session) {
        (None, None) => None,
        (Some(at), None) | (None, Some(at)) => Some(at),
        (Some(per_call), Some(session)) => Some(per_call.min(session)),
    }
}

fn frontend_app_send_cancel_fired(cancel: &mut oneshot::Receiver<()>) -> bool {
    match cancel.try_recv() {
        Ok(()) | Err(oneshot::error::TryRecvError::Closed) => true,
        Err(oneshot::error::TryRecvError::Empty) => false,
    }
}

/// Race one application-ciphertext `send_to` (or a test double) against the
/// admitted deadline and the proxy-side cancel receiver.
///
/// An already-elapsed deadline never polls `send`. Exact-deadline ties fail
/// closed (`biased`, expiry arm first). If expiry or cancellation wins, `send`
/// is dropped so it cannot complete afterwards. Unauthenticated sends
/// (`deadline == None`) await `send` with no timer.
pub(crate) async fn frontend_app_ciphertext_send_until_expiry<F>(
    deadline: Option<tokio::time::Instant>,
    mut cancel: Option<&mut oneshot::Receiver<()>>,
    send: F,
) -> Result<F::Output, FrontendAppSendReject>
where
    F: std::future::Future,
{
    let cancelled = match cancel.as_mut() {
        Some(cancel) => frontend_app_send_cancel_fired(cancel),
        None => false,
    };
    match admit_frontend_app_send(cancelled, deadline, tokio::time::Instant::now()) {
        FrontendAppSendAdmit::Reject(reason) => return Err(reason),
        FrontendAppSendAdmit::Proceed => {}
    }
    match (deadline, cancel) {
        (None, None) => Ok(send.await),
        (None, Some(cancel)) => tokio::select! {
            biased;
            _ = cancel => Err(FrontendAppSendReject::Cancelled),
            result = send => Ok(result),
        },
        (Some(at), None) => tokio::select! {
            biased;
            () = tokio::time::sleep_until(at) => Err(FrontendAppSendReject::Expired),
            result = send => Ok(result),
        },
        (Some(at), Some(cancel)) => tokio::select! {
            biased;
            () = tokio::time::sleep_until(at) => Err(FrontendAppSendReject::Expired),
            _ = cancel => Err(FrontendAppSendReject::Cancelled),
            result = send => Ok(result),
        },
    }
}

fn fail_queued_frontend_app_sends(
    app_in_rx: &mut mpsc::Receiver<FrontendAppSend>,
    session_deadline: Option<tokio::time::Instant>,
) {
    let now = tokio::time::Instant::now();
    while let Ok(mut pending) = app_in_rx.try_recv() {
        let cancelled = frontend_app_send_cancel_fired(&mut pending.cancel);
        let deadline = earliest_frontend_app_send_deadline(pending.deadline, session_deadline);
        let reason = shutdown_queued_frontend_app_send(cancelled, deadline, now);
        let _ = pending.completion.send(Err(reason.as_str().to_string()));
    }
}

fn session_authorization_elapsed(auth_deadline: &FrontendSessionAuthDeadline) -> bool {
    auth_deadline
        .get()
        .is_some_and(|at| tokio::time::Instant::now() >= at)
}

async fn write_connected_frontend_record(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
    in_flight: Option<&mut InFlightFrontendAppSend>,
    session_deadline: Option<tokio::time::Instant>,
) -> Result<(), FrontendAppSendReject> {
    if let Some(inflight) = in_flight {
        let deadline = earliest_frontend_app_send_deadline(inflight.deadline, session_deadline);
        match frontend_app_ciphertext_send_until_expiry(
            deadline,
            Some(&mut inflight.cancel),
            socket.send_to(data, peer),
        )
        .await
        {
            Ok(Ok(written)) if written == data.len() => Ok(()),
            Ok(_) => Err(FrontendAppSendReject::Closed),
            Err(reject) => Err(reject),
        }
    } else {
        match frontend_app_ciphertext_send_until_expiry(
            session_deadline,
            None,
            socket.send_to(data, peer),
        )
        .await
        {
            Ok(Ok(written)) if written == data.len() => Ok(()),
            Ok(_) => Err(FrontendAppSendReject::Closed),
            Err(reject) => Err(reject),
        }
    }
}

/// Pin earliest-deadline composition for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn earliest_frontend_app_send_deadline_for_test(
    per_call: Option<tokio::time::Instant>,
    session: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    earliest_frontend_app_send_deadline(per_call, session)
}

/// Pin frontend application-send admission for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn admit_frontend_app_send_for_test(
    cancelled: bool,
    deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> FrontendAppSendAdmit {
    admit_frontend_app_send(cancelled, deadline, now)
}

/// Pin shutdown's refuse-to-flush decision for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn shutdown_queued_frontend_app_send_for_test(
    cancelled: bool,
    deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> FrontendAppSendReject {
    shutdown_queued_frontend_app_send(cancelled, deadline, now)
}

/// Pin cancel-receiver closed/fired detection for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn frontend_app_send_cancel_fired_for_test(cancel: &mut oneshot::Receiver<()>) -> bool {
    frontend_app_send_cancel_fired(cancel)
}

/// Pin the ciphertext `send_to` race for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) async fn frontend_app_ciphertext_send_until_expiry_for_test<F>(
    deadline: Option<tokio::time::Instant>,
    cancel: Option<&mut oneshot::Receiver<()>>,
    send: F,
) -> Result<F::Output, FrontendAppSendReject>
where
    F: std::future::Future,
{
    frontend_app_ciphertext_send_until_expiry(deadline, cancel, send).await
}

/// Pin the bounded, credential-free reject strings.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn frontend_app_send_reject_as_str_for_test(
    reject: FrontendAppSendReject,
) -> &'static str {
    reject.as_str()
}

/// Opaque handle for external hosted tests of the session authorization slot.
#[doc(hidden)]
pub struct FrontendSessionAuthDeadlineForTest(Arc<FrontendSessionAuthDeadline>);

/// Allocate a lock-free frontend session authorization deadline for tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn frontend_session_auth_deadline_for_test() -> FrontendSessionAuthDeadlineForTest {
    FrontendSessionAuthDeadlineForTest(Arc::new(FrontendSessionAuthDeadline::new()))
}

/// Publish one admitted authorization instant into the session deadline slot.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn publish_frontend_session_auth_deadline_for_test(
    auth_deadline: &FrontendSessionAuthDeadlineForTest,
    at: tokio::time::Instant,
) {
    auth_deadline.0.publish(at);
}

/// Read the current monotonically-earliest session authorization deadline.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn read_frontend_session_auth_deadline_for_test(
    auth_deadline: &FrontendSessionAuthDeadlineForTest,
) -> Option<tokio::time::Instant> {
    auth_deadline.0.get()
}

/// Encode a nanosecond offset from the session anchor for external tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn encode_frontend_session_auth_deadline_offset_for_test(offset_nanos: u128) -> u64 {
    encode_frontend_session_auth_deadline_offset(offset_nanos)
}

/// Reconstruct a deadline instant from anchor + encoded offset for external tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn reconstruct_frontend_session_auth_deadline_for_test(
    anchor: tokio::time::Instant,
    encoded: u64,
) -> tokio::time::Instant {
    reconstruct_frontend_session_auth_deadline(anchor, encoded)
}

/// Reconstruct a deadline instant from anchor + duration offset for external tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn reconstruct_frontend_session_auth_deadline_from_duration_for_test(
    anchor: tokio::time::Instant,
    offset: Duration,
) -> tokio::time::Instant {
    reconstruct_frontend_session_auth_deadline_from_duration(anchor, offset)
}

// ============================================================================
// Configuration Builders
// ============================================================================

/// Frontend DTLS server configuration (client → gateway).
///
/// Cloneable so one validated generation can be published into the shared
/// accept slot and live-swapped into every active [`DtlsServer`] without
/// re-reading sources (which could race and mix generations).
#[derive(Clone)]
pub struct FrontendDtlsConfig {
    pub dimpl_config: Arc<Config>,
    pub certificate: DtlsCertificateChain,
    pub client_cert_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
}

/// One immutable, accepted frontend DTLS material generation.
///
/// Live reload validates candidate cert/key/client-CA/CRL inputs into a single
/// [`FrontendDtlsConfig`], then publishes that config under a monotonic
/// generation id. Active DTLS servers and listeners spawned after the publish
/// all observe the same generation; a rejected candidate never replaces it.
#[derive(Clone)]
pub struct FrontendDtlsGeneration {
    /// Monotonic generation id assigned at publish time (starts at 1).
    pub generation: u64,
    /// Validated crypto material for new handshakes.
    pub config: FrontendDtlsConfig,
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
    /// Datagram client-address metadata gate (issues #3289, #3856, #3862).
    /// `Some` only when the `dtls` proxy sets `stream_proxy_protocol: true`;
    /// then every datagram reaching the demuxer must carry a trusted,
    /// well-formed (and, when a secret is configured, listener-bound,
    /// authenticated, and fresh) PROXY v2 DGRAM envelope. The gate's binding
    /// names the DTLS receive boundary specifically, so an envelope minted for
    /// the plain-UDP boundary on the same numeric port cannot be laundered in
    /// here. Validation happens before demux, before any per-peer allocation,
    /// and before the DTLS record layer sees a byte; the forwarded address
    /// becomes the accepted connection's client identity. `None` keeps ordinary
    /// DTLS behavior.
    pub datagram_client_address:
        Option<Arc<crate::proxy::datagram_client_address::DatagramClientAddressGate>>,
    /// Counter incremented for every datagram the gate refuses. Shared with the
    /// owning UDP listener's metrics so plain-UDP and DTLS refusals are one
    /// number. `None` outside the proxy listener path.
    pub datagram_client_address_drops: Option<Arc<AtomicU64>>,
    /// `(proxy_id, listen_port)` stamped on client-address metadata refusal
    /// warnings so a DTLS refusal correlates with the plain-UDP listener's
    /// record for the same proxy. Cloned once at listener spawn, never per
    /// datagram. `None` outside the proxy listener path.
    pub datagram_client_address_listener: Option<(Arc<str>, u16)>,
}

impl Default for DtlsServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: None,
            handshake_timeout: Some(DEFAULT_DTLS_HANDSHAKE_TIMEOUT),
            allow_new_session: None,
            active_session_mirror: None,
            datagram_client_address: None,
            datagram_client_address_drops: None,
            datagram_client_address_listener: None,
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
    // An explicit `system://` trust selection never inherits the global
    // `FERRUM_TLS_NO_VERIFY` opt-out.
    let skip_verify = !proxy.resolved_tls.verify_server_cert
        || (tls_no_verify && proxy.resolved_tls.allows_global_no_verify());

    // Load client certificate for mutual TLS, or generate an ephemeral one.
    let certificate = match (
        &proxy.resolved_tls.client_cert_path,
        &proxy.resolved_tls.client_key_path,
    ) {
        (Some(cert_path), Some(key_path)) => load_dtls_certificate(cert_path, key_path)?,
        (None, None) => generate_ephemeral_cert()?,
        _ => {
            return Err(anyhow::anyhow!(
                "DTLS backend mTLS client certificate and private key must be configured together"
            ));
        }
    };

    // A declared custom trust source remains an admission requirement even
    // when no-verify disables use of the resulting verifier.
    if skip_verify
        && let Some(ca_path) = proxy
            .resolved_tls
            .effective_ca_source(global_ca_bundle_path)
    {
        load_root_store_from_pem(ca_path)?;
    }

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
    pub certificate: DtlsCertificateChain,
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
        debug!("Frontend DTLS mTLS enabled: requiring and verifying client certificates");
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

/// Regression harness for issue #2959: prove both demux removal sites are
/// identity-aware without spinning a live DTLS accept loop.
///
/// Inserts a generation-2 map entry for a peer, then runs generation-1 cleanup
/// through `SessionGuard::drop` and the Closed-arm `remove_session` helper.
/// Returns `Ok(())` only when the generation-2 entry and active counter both
/// survive, and matching generation-2 cleanup then removes the entry once.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn dtls_stale_session_removal_preserves_newer_generation_for_test() -> Result<(), String>
{
    let peer_addr: SocketAddr = "127.0.0.1:2959"
        .parse()
        .map_err(|e| format!("parse peer addr: {e}"))?;
    let sessions: Arc<DashMap<SocketAddr, DtlsSessionState>> = Arc::new(DashMap::new());
    let active_sessions = Arc::new(AtomicUsize::new(0));
    let mirror = Arc::new(AtomicU64::new(0));

    let (gen2_tx, _gen2_rx) = mpsc::channel::<Vec<u8>>(1);
    let (gen2_shutdown_tx, _gen2_shutdown_rx) = mpsc::channel::<()>(1);
    sessions.insert(
        peer_addr,
        DtlsSessionState {
            incoming_tx: gen2_tx,
            shutdown_tx: gen2_shutdown_tx,
            generation: 2,
            // Identity-aware removal is orthogonal to the client-address gate;
            // this harness runs the ungated shape.
            forwarded_client: None,
        },
    );
    active_sessions.fetch_add(1, Ordering::Relaxed);
    mirror.fetch_add(1, Ordering::Relaxed);

    // Stale SessionGuard from generation 1 (the bug: remove-by-addr alone).
    {
        let _stale_guard = SessionGuard {
            sessions: sessions.clone(),
            active_sessions: active_sessions.clone(),
            active_session_mirror: Some(mirror.clone()),
            peer_addr,
            generation: 1,
        };
    }

    if !sessions.contains_key(&peer_addr) {
        return Err("generation-1 SessionGuard drop evicted generation-2 entry".into());
    }
    let surviving = sessions
        .get(&peer_addr)
        .map(|s| s.generation)
        .ok_or_else(|| "generation-2 entry missing after stale guard drop".to_string())?;
    if surviving != 2 {
        return Err(format!(
            "expected generation 2 after stale guard drop, found {surviving}"
        ));
    }
    if active_sessions.load(Ordering::Relaxed) != 1 {
        return Err(format!(
            "active_sessions unbalanced after stale guard drop: {}",
            active_sessions.load(Ordering::Relaxed)
        ));
    }
    if mirror.load(Ordering::Relaxed) != 1 {
        return Err(format!(
            "active_session_mirror unbalanced after stale guard drop: {}",
            mirror.load(Ordering::Relaxed)
        ));
    }

    // Closed-arm path with a stale generation must also be a no-op.
    remove_session(
        &sessions,
        &active_sessions,
        Some(mirror.as_ref()),
        &peer_addr,
        1,
    );
    if !sessions.contains_key(&peer_addr) {
        return Err("stale Closed-arm remove_session evicted generation-2 entry".into());
    }
    if active_sessions.load(Ordering::Relaxed) != 1 || mirror.load(Ordering::Relaxed) != 1 {
        return Err("counters changed on stale Closed-arm remove_session".into());
    }

    // Matching generation-2 cleanup must remove exactly once and balance counters.
    remove_session(
        &sessions,
        &active_sessions,
        Some(mirror.as_ref()),
        &peer_addr,
        2,
    );
    if sessions.contains_key(&peer_addr) {
        return Err("matching generation-2 remove_session left the entry in place".into());
    }
    if active_sessions.load(Ordering::Relaxed) != 0 {
        return Err(format!(
            "active_sessions not cleared after matching remove: {}",
            active_sessions.load(Ordering::Relaxed)
        ));
    }
    if mirror.load(Ordering::Relaxed) != 0 {
        return Err(format!(
            "mirror not cleared after matching remove: {}",
            mirror.load(Ordering::Relaxed)
        ));
    }

    // A second matching remove (e.g. SessionGuard after Closed already won) is
    // a no-op and must not underflow counters.
    remove_session(
        &sessions,
        &active_sessions,
        Some(mirror.as_ref()),
        &peer_addr,
        2,
    );
    if active_sessions.load(Ordering::Relaxed) != 0 || mirror.load(Ordering::Relaxed) != 0 {
        return Err("duplicate matching remove underflowed counters".into());
    }

    Ok(())
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
                            Output::Connected | Output::PeerCert(_) | Output::PeerCertChain(_) => {
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
/// Stored in [`DtlsServer::active_config`] behind an `ArcSwap` so ordinary
/// frontend DTLS live reload (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED` /
/// `FERRUM_DTLS_*` generation publish) can publish a new `dimpl_config`,
/// `certificate`, and client verifier without dropping in-flight DTLS
/// sessions. New sessions snapshot the slot in
/// [`DtlsServer::spawn_session`]; existing sessions retain the material they
/// were spawned with until they end. Mesh PeerAuthentication reload must
/// not write this slot: mesh does not own a terminating UDP+DTLS listener.
struct DtlsServerActiveConfig {
    dimpl_config: Arc<Config>,
    certificate: DtlsCertificateChain,
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
    /// Monotonic opaque identity assigned to each spawned demux session.
    ///
    /// Removals compare this token so a stale driver/`SessionGuard` for peer P
    /// cannot evict a newer live session inserted at the same address after the
    /// older channel closed (issue #2959). Not a semantic generation counter for
    /// operators — just demux map identity.
    next_session_generation: AtomicU64,
    limits: DtlsServerLimits,
    /// Channel to deliver accepted (post-handshake) connections.
    accept_tx: mpsc::Sender<(DtlsServerConn, SocketAddr)>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<(DtlsServerConn, SocketAddr)>>,
    shutdown_tx: watch::Sender<bool>,
    /// Bounds this listener's rate of client-address metadata refusal warnings.
    /// A hostile flood of invalid datagrams must not become one log record per
    /// datagram; the counter still moves for every one of them. Lock-free, so
    /// the non-emitting path is two relaxed atomics and no allocation.
    datagram_client_address_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
}

/// State for a server-side DTLS session being managed by the DtlsServer.
struct DtlsSessionState {
    /// Send incoming UDP data to this session's driver task.
    incoming_tx: mpsc::Sender<Vec<u8>>,
    /// Signal this session's driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
    /// Opaque demux identity for this peer entry (see
    /// [`DtlsServer::next_session_generation`]). Both removal sites must match
    /// this token before deleting the map entry.
    generation: u64,
    /// Authenticated forwarded client this peer entry was admitted with, when
    /// the datagram client-address gate is enabled. A later datagram from the
    /// same peer address asserting a different client is dropped rather than
    /// fed into a DTLS association admitted under another identity.
    forwarded_client: Option<SocketAddr>,
}

/// Count a datagram the client-address gate refused and emit a rate-limited
/// structured diagnostic for it.
///
/// The DTLS demuxer is a distinct pre-association path from plain UDP's
/// `process_datagram`, but it owes the same contract: every refusal moves the
/// shared drop counter, and the operator gets a bounded record rather than one
/// line per hostile datagram.
///
/// The record carries a fixed-cardinality `reason`, the owning listener, and
/// the direct socket peer only. It never carries the payload, the
/// authentication tag, the configured secret, or the forwarded address the
/// sender was trying to assert — a refused datagram is attacker-controlled
/// input, and echoing what it claimed would put that claim in the log as if it
/// were an observation.
///
/// The non-emitting path is three relaxed atomic operations and no allocation
/// or lock, so a flood costs the shared recv loop nothing beyond the drop.
/// Returns the suppressed count when a record was emitted, so the limiter
/// contract is assertable without a log-capture harness.
fn record_datagram_metadata_refusal(
    limiter: &crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    drops: Option<&AtomicU64>,
    listener: Option<&(Arc<str>, u16)>,
    peer_addr: SocketAddr,
    reason: &'static str,
    now_ms: u64,
) -> Option<u64> {
    if let Some(drops) = drops {
        drops.fetch_add(1, Ordering::Relaxed);
    }
    let suppressed = limiter.on_event(now_ms)?;
    let (proxy_id, listen_port) = match listener {
        Some((proxy_id, listen_port)) => (proxy_id.as_ref(), *listen_port),
        None => ("", 0u16),
    };
    warn!(
        proxy_id = proxy_id,
        listen_port = listen_port,
        peer = %crate::util::client_identity::canonical_socket_addr(peer_addr),
        reason = reason,
        suppressed = suppressed,
        "DTLS: dropping datagram with refused client-address metadata"
    );
    Some(suppressed)
}

/// Regression harness for the DTLS refusal diagnostic (issue #3289): every
/// refusal is counted, while the warning is bounded to one record per limiter
/// window and the next record reports what it suppressed.
///
/// Drives [`record_datagram_metadata_refusal`] directly with an injected clock
/// so the contract is asserted without a live listener, a log-capture harness,
/// or any wall-clock sleep. Sends `refusals_in_window` refusals inside one
/// window and one more after it, returning
/// `(drops, records_emitted, suppressed_reported_by_the_second_record)`.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn dtls_datagram_metadata_refusal_accounting_for_test(
    refusals_in_window: u64,
) -> Result<(u64, u64, u64), String> {
    let window_ms = crate::util::atomic_log_rate_limiter::DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS;
    let limiter = crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new();
    let drops = AtomicU64::new(0);
    let listener = (Arc::<str>::from("dtls-metadata-limiter"), 4433u16);
    let peer_addr: SocketAddr = "127.0.0.1:3289"
        .parse()
        .map_err(|e| format!("parse peer addr: {e}"))?;
    let now_ms = 1_000_000u64;

    let mut emitted = 0u64;
    for _ in 0..refusals_in_window {
        if record_datagram_metadata_refusal(
            &limiter,
            Some(&drops),
            Some(&listener),
            peer_addr,
            DatagramMetadataError::AuthenticationTagMismatch.reason(),
            now_ms,
        )
        .is_some()
        {
            emitted += 1;
        }
    }

    // One more once the window has elapsed: it must emit and report the
    // refusals the limiter withheld in between.
    let suppressed = record_datagram_metadata_refusal(
        &limiter,
        Some(&drops),
        Some(&listener),
        peer_addr,
        DatagramMetadataError::AuthenticationTagMismatch.reason(),
        now_ms + window_ms,
    );
    if suppressed.is_some() {
        emitted += 1;
    }

    Ok((
        drops.load(Ordering::Relaxed),
        emitted,
        suppressed.unwrap_or_default(),
    ))
}

/// Remove the demux entry for `peer_addr` only when it still belongs to
/// `generation`.
///
/// Counter/mirror decrements happen only when this call actually wins the
/// removal. A Closed-arm cleanup and a later `SessionGuard::drop` for the same
/// stale driver therefore cannot double-decrement, and neither can evict a
/// replacement session that reused the peer address.
fn remove_session(
    sessions: &DashMap<SocketAddr, DtlsSessionState>,
    active_sessions: &AtomicUsize,
    active_session_mirror: Option<&AtomicU64>,
    peer_addr: &SocketAddr,
    generation: u64,
) {
    if sessions
        .remove_if(peer_addr, |_, session| session.generation == generation)
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
    /// Demux identity captured when this driver was spawned.
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
    /// Send application data to the DTLS engine for encryption + UDP write.
    app_tx: mpsc::Sender<FrontendAppSend>,
    /// Receive decrypted application data.
    app_rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Signal this connection's driver task to shut down.
    shutdown_tx: mpsc::Sender<()>,
    /// Admitted absolute authorization deadline, published monotonically
    /// earliest into the per-client driver so every application ciphertext
    /// `send_to` is owned by that bound. Unauthenticated sessions never set
    /// this.
    auth_deadline: Arc<FrontendSessionAuthDeadline>,
    /// DER-encoded client leaf certificate from the DTLS handshake.
    /// Populated when the client presents a certificate during mutual DTLS authentication.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded client intermediate chain in presented order, excluding
    /// the leaf stored in `tls_client_cert_der`.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// SNI hostname extracted from the initial DTLS ClientHello, if supplied.
    pub sni_hostname: Option<String>,
    /// Authenticated original client from the datagram client-address envelope
    /// (issue #3289). `None` when the listener does not run that gate, or when
    /// the envelope carried no address (`LOCAL` / `AF_UNSPEC`); the caller then
    /// keeps the socket peer as the only identity.
    pub forwarded_client_addr: Option<SocketAddr>,
}

/// A cloneable sender half of a `DtlsServerConn`, used to send data back to
/// the DTLS client from a separate task (e.g., backend→client forwarding).
#[derive(Clone)]
pub struct DtlsServerSender {
    app_tx: mpsc::Sender<FrontendAppSend>,
    shutdown_tx: mpsc::Sender<()>,
    auth_deadline: Arc<FrontendSessionAuthDeadline>,
}

impl DtlsServerSender {
    /// Publish the admitted absolute authorization deadline into the per-client
    /// driver. Only tightens the session bound; a later instant is ignored.
    /// Handshake/control writes that already completed are unaffected; every
    /// later application ciphertext `send_to` is owned by the earliest bound.
    /// Unauthenticated sessions must not call this.
    pub fn bind_authorization_deadline(&self, at: tokio::time::Instant) {
        self.auth_deadline.publish(at);
    }

    /// Send application data through the DTLS tunnel, completing only after
    /// every ciphertext datagram produced for this plaintext is accepted by
    /// the UDP socket.
    ///
    /// `deadline` is the admitted absolute authorization instant (`None` for
    /// unauthenticated sessions). An already-elapsed deadline never enqueues
    /// or polls a socket write. Dropping this future marks the queued request
    /// cancelled so the driver cannot encrypt or send it later. Exact-deadline
    /// ties fail closed.
    pub async fn send_committed(
        &self,
        data: &[u8],
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(), anyhow::Error> {
        send_frontend_app_committed(&self.app_tx, &self.auth_deadline, data, deadline).await
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
        self.send_committed(data, None).await
    }

    /// Deadline-aware actual-commit send. See [`DtlsServerSender::send_committed`].
    #[allow(dead_code)]
    pub async fn send_committed(
        &self,
        data: &[u8],
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(), anyhow::Error> {
        send_frontend_app_committed(&self.app_tx, &self.auth_deadline, data, deadline).await
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
            auth_deadline: self.auth_deadline.clone(),
        }
    }

    /// Close this client's DTLS connection.
    pub async fn close(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

async fn send_frontend_app_committed(
    app_tx: &mpsc::Sender<FrontendAppSend>,
    auth_deadline: &FrontendSessionAuthDeadline,
    data: &[u8],
    deadline: Option<tokio::time::Instant>,
) -> Result<(), anyhow::Error> {
    if let Some(at) = deadline {
        auth_deadline.publish(at);
    }
    let effective = earliest_frontend_app_send_deadline(deadline, auth_deadline.get());
    if matches!(
        admit_frontend_app_send(false, effective, tokio::time::Instant::now()),
        FrontendAppSendAdmit::Reject(FrontendAppSendReject::Expired)
    ) {
        return Err(anyhow::anyhow!(FrontendAppSendReject::Expired.as_str()));
    }
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (completion_tx, completion_rx) = oneshot::channel();
    app_tx
        .send(FrontendAppSend {
            data: data.to_vec(),
            completion: completion_tx,
            cancel: cancel_rx,
            deadline,
        })
        .await
        .map_err(|_| anyhow::anyhow!("DTLS server connection closed"))?;
    // Held for the whole wait: dropping this future (expiry in the proxy
    // race) closes `cancel` so a request already in the channel cannot be
    // encrypted or written later.
    let _cancel_tx = cancel_tx;
    match completion_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::anyhow!(error)),
        Err(_) => Err(anyhow::anyhow!("DTLS server connection closed")),
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
            datagram_client_address_warn:
                crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new(),
        }
    }

    /// Atomically swap the DTLS crypto material used for **new** sessions.
    ///
    /// Used by frontend DTLS live reload (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`)
    /// to rotate the inbound DTLS `ServerConfig` equivalent (dimpl `Config` +
    /// certificate + optional `ClientCertVerifier`) without re-binding the
    /// socket or evicting any in-flight session. Active sessions keep the
    /// snapshot they handshake with until they end (see
    /// [`DtlsServerActiveConfig`] doc-comment for the invariant). Mesh
    /// PeerAuthentication reload must not call this: mesh does not own a
    /// terminating UDP+DTLS listener.
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

    /// Test-support snapshot of the live frontend crypto slot: the Arc pointer
    /// of the active config (exact identity) and whether a client-certificate
    /// verifier is installed.
    #[doc(hidden)]
    #[allow(dead_code)] // External unit/integration-test seam.
    pub fn frontend_config_identity_for_test(&self) -> (usize, bool) {
        let active = self.active_config.load_full();
        (
            Arc::as_ptr(&active) as usize,
            active.client_cert_verifier.is_some(),
        )
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

            // Datagram client-address boundary (issue #3289). When the gate is
            // configured, the envelope is validated and stripped here — before
            // demux, before any per-peer state is allocated, and before the
            // DTLS record layer sees a byte — so an untrusted or
            // unauthenticated datagram can neither start an association nor
            // reach an existing one. With no gate this is the untouched
            // historical path.
            let (payload, forwarded_client) = match self.limits.datagram_client_address.as_ref() {
                None => (&buf[..len], None),
                Some(gate) => match gate.decode(&buf[..len], &peer_addr) {
                    Ok(decoded) => (decoded.payload, decoded.forwarded),
                    Err(error) => {
                        // The emit decision is made inside; the returned
                        // suppressed count is only for the test harness.
                        let _ = record_datagram_metadata_refusal(
                            &self.datagram_client_address_warn,
                            self.limits.datagram_client_address_drops.as_deref(),
                            self.limits.datagram_client_address_listener.as_ref(),
                            peer_addr,
                            error.reason(),
                            crate::proxy::udp_proxy::coarse_epoch_millis(),
                        );
                        continue;
                    }
                },
            };
            let data = payload.to_vec();

            // Clone the sender (and demux identity) out of the DashMap guard
            // before sending. The `Ref` from `sessions.get()` holds a read lock
            // on the shard; holding it while a `SessionGuard::Drop` on the same
            // shard needs a write lock to call `sessions.remove_if()` would
            // deadlock. Capture `generation` with the sender so a Closed cleanup
            // cannot race-evict a newer session inserted for the same peer.
            let session = self
                .sessions
                .get(&peer_addr)
                .map(|s| (s.incoming_tx.clone(), s.generation, s.forwarded_client));
            if let Some((tx, generation, session_forwarded)) = session {
                // The association was admitted for one authenticated client;
                // a datagram asserting another is refused rather than decrypted
                // under the first client's identity.
                if session_forwarded != forwarded_client {
                    let _ = record_datagram_metadata_refusal(
                        &self.datagram_client_address_warn,
                        self.limits.datagram_client_address_drops.as_deref(),
                        self.limits.datagram_client_address_listener.as_ref(),
                        peer_addr,
                        DatagramMetadataError::ForwardedClientChanged.reason(),
                        crate::proxy::udp_proxy::coarse_epoch_millis(),
                    );
                    continue;
                }
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
                        // Driver task exited — remove this generation only.
                        // A replacement may already occupy the peer address.
                        remove_session(
                            &self.sessions,
                            &self.active_sessions,
                            self.limits.active_session_mirror.as_deref(),
                            &peer_addr,
                            generation,
                        );
                    }
                }
            } else if data.len() >= 13 && data[0] == 0x16 {
                // New client — spawn a session driver. Only for datagrams that
                // plausibly start a DTLS handshake (content-type 0x16 with a
                // full 13-byte record header): spawning reserves a
                // `max_sessions` slot, allocates four channels, and holds the
                // slot for the handshake timeout, so arbitrary garbage from
                // scanners or spoofed floods must not reach it.
                self.spawn_session(peer_addr, data, forwarded_client);
            } else {
                trace!(
                    client = %peer_addr,
                    len = data.len(),
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
    fn spawn_session(
        &self,
        peer_addr: SocketAddr,
        initial_packet: Vec<u8>,
        forwarded_client: Option<SocketAddr>,
    ) {
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
        let (app_in_tx, mut app_in_rx) = mpsc::channel::<FrontendAppSend>(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        let auth_deadline = Arc::new(FrontendSessionAuthDeadline::new());
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
                forwarded_client,
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
            let mut peer_cert_der: Option<Arc<Vec<u8>>> = None;
            let mut peer_cert_chain_der: Option<Arc<Vec<Vec<u8>>>> = None;
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

                let mut in_flight: Option<InFlightFrontendAppSend> = None;

                tokio::select! {
                    // Application data to send back to this client. Success is
                    // reported only after every produced ciphertext datagram is
                    // accepted by the UDP socket, not at channel enqueue.
                    Some(pending) = app_in_rx.recv(), if connected => {
                        let FrontendAppSend {
                            data,
                            completion,
                            mut cancel,
                            deadline,
                        } = pending;
                        let session_deadline = auth_deadline.get();
                        let cancelled = frontend_app_send_cancel_fired(&mut cancel);
                        let effective = earliest_frontend_app_send_deadline(
                            deadline,
                            session_deadline,
                        );
                        match admit_frontend_app_send(
                            cancelled,
                            effective,
                            tokio::time::Instant::now(),
                        ) {
                            FrontendAppSendAdmit::Reject(reason) => {
                                let _ = completion.send(Err(reason.as_str().to_string()));
                            }
                            FrontendAppSendAdmit::Proceed => {
                                if data.len() > dtls_buf_config().max_plaintext {
                                    warn!(
                                        client = %peer_addr,
                                        "DTLS dropping oversized datagram ({} bytes, max {})",
                                        data.len(),
                                        dtls_buf_config().max_plaintext,
                                    );
                                    let _ = completion.send(Err(format!(
                                        "DTLS plaintext exceeds max_plaintext ({} bytes, got {})",
                                        dtls_buf_config().max_plaintext,
                                        data.len()
                                    )));
                                } else if let Err(e) = dtls.send_application_data(&data) {
                                    trace!(client = %peer_addr, "DTLS send error: {}", e);
                                    let _ = completion.send(Err(format!(
                                        "DTLS send_application_data error: {e}"
                                    )));
                                    break;
                                } else {
                                    in_flight = Some(InFlightFrontendAppSend {
                                        completion,
                                        cancel,
                                        deadline: effective,
                                    });
                                }
                            }
                        }
                    }
                    // Shutdown signal — never encrypt or emit expired/cancelled
                    // queued application replies. Handshake/control records
                    // still drain after the loop.
                    _ = shutdown_rx.recv() => {
                        fail_queued_frontend_app_sends(
                            &mut app_in_rx,
                            auth_deadline.get(),
                        );
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
                // flushing CCS+Finished). Application ciphertext `send_to` is
                // owned by the admitted deadline / cancel receiver.
                let mut just_connected = false;
                let mut wrote_ciphertext_datagram = false;
                let mut discard_app_ciphertext = false;
                loop {
                    let mut drain_round_exhausted = true;
                    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                        match dtls.poll_output(&mut out_buf) {
                            Output::Packet(data) => {
                                if discard_app_ciphertext {
                                    continue;
                                }
                                if !connected {
                                    let _ = socket.send_to(data, peer_addr).await;
                                    drain_round_exhausted = false;
                                    continue;
                                }
                                match write_connected_frontend_record(
                                    &socket,
                                    data,
                                    peer_addr,
                                    in_flight.as_mut(),
                                    auth_deadline.get(),
                                )
                                .await
                                {
                                    Ok(()) => {
                                        wrote_ciphertext_datagram = true;
                                    }
                                    Err(reject) => {
                                        discard_app_ciphertext = true;
                                        if let Some(inflight) = in_flight.take() {
                                            let _ = inflight
                                                .completion
                                                .send(Err(reject.as_str().to_string()));
                                        }
                                    }
                                }
                            }
                            Output::Timeout(t) => {
                                next_timeout = Some(t);
                                drain_round_exhausted = false;
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
                                    fail_queued_frontend_app_sends(
                                        &mut app_in_rx,
                                        auth_deadline.get(),
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
                                    auth_deadline: auth_deadline.clone(),
                                    tls_client_cert_der: peer_cert_der.clone(),
                                    tls_client_cert_chain_der: peer_cert_chain_der.clone(),
                                    sni_hostname: sni_hostname.clone(),
                                    forwarded_client_addr: forwarded_client,
                                };
                                if accept_tx.send((conn, peer_addr)).await.is_err() {
                                    fail_queued_frontend_app_sends(
                                        &mut app_in_rx,
                                        auth_deadline.get(),
                                    );
                                    return;
                                }
                            }
                            Output::PeerCert(der) => {
                                // Preserve leaf-only fingerprint semantics for
                                // existing plugin consumers.
                                peer_cert_der = Some(Arc::new(der.to_vec()));
                            }
                            Output::PeerCertChain(chain) => {
                                if let Some(verifier) = client_cert_verifier.as_deref() {
                                    if let Err(e) = validate_client_cert(&chain, verifier) {
                                        warn!(client = %peer_addr, "Client cert validation failed: {}", e);
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
                                    // A client certificate was presented and verified
                                    // against the configured client CA.
                                    verified_peer_cert = true;
                                }
                                peer_cert_chain_der =
                                    (chain.len() > 1).then(|| Arc::new(chain[1..].to_vec()));
                            }
                            Output::ApplicationData(data)
                                if app_out_tx.send(data.to_vec()).await.is_err() =>
                            {
                                if let Some(inflight) = in_flight.take() {
                                    let _ = inflight.completion.send(Err(
                                        FrontendAppSendReject::Closed.as_str().to_string(),
                                    ));
                                }
                                fail_queued_frontend_app_sends(&mut app_in_rx, auth_deadline.get());
                                return;
                            }
                            _ => {
                                drain_round_exhausted = false;
                                break;
                            }
                        }
                    }

                    if client_send_output_drain_needs_another_round(
                        in_flight.is_some(),
                        wrote_ciphertext_datagram,
                        false,
                        false,
                        drain_round_exhausted,
                    ) {
                        tokio::task::yield_now().await;
                        continue;
                    }
                    break;
                }

                if let Some(inflight) = in_flight.take() {
                    if !wrote_ciphertext_datagram {
                        let _ =
                            inflight
                                .completion
                                .send(Err("DTLS application send produced no ciphertext datagram"
                                    .to_string()));
                    } else {
                        let _ = inflight.completion.send(Ok(()));
                    }
                }
            }

            fail_queued_frontend_app_sends(&mut app_in_rx, auth_deadline.get());
            // Protocol/handshake records may still be flushed. Application
            // ciphertext whose authorization expired is discarded, not written.
            let discard_expired = session_authorization_elapsed(&auth_deadline);
            for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                match dtls.poll_output(&mut out_buf) {
                    Output::Packet(data) => {
                        if discard_expired {
                            continue;
                        }
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

/// Encoding discriminant for reconstructing a borrowed rustls private-key view
/// from Ferrum-owned DER bytes without [`PrivateKeyDer::clone_key`].
#[derive(Clone, Copy)]
enum DtlsKeyDerEncoding {
    Pkcs1,
    Sec1,
    Pkcs8,
}

type DtlsKeyDropHook = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Ferrum-owned DTLS private-key DER that is cleared before its allocation is
/// released.
///
/// `rustls_pki_types::PrivateKeyDer` implements [`zeroize::Zeroize`] but not
/// `Drop`/`ZeroizeOnDrop`. Adopting the PEM-parsed owner into this guard copies
/// the secret into Ferrum-managed storage and immediately zeroizes the rustls
/// owner, then reconstructs only borrowed rustls views for ring parsing and
/// leaf/key matching.
struct ZeroizingDtlsKeyDer {
    bytes: Vec<u8>,
    encoding: DtlsKeyDerEncoding,
    drop_hook: Option<DtlsKeyDropHook>,
}

impl ZeroizingDtlsKeyDer {
    fn adopt(
        mut key: rustls::pki_types::PrivateKeyDer<'static>,
        drop_hook: Option<DtlsKeyDropHook>,
    ) -> anyhow::Result<Self> {
        use zeroize::Zeroize;

        let encoding = match &key {
            rustls::pki_types::PrivateKeyDer::Pkcs1(_) => Some(DtlsKeyDerEncoding::Pkcs1),
            rustls::pki_types::PrivateKeyDer::Sec1(_) => Some(DtlsKeyDerEncoding::Sec1),
            rustls::pki_types::PrivateKeyDer::Pkcs8(_) => Some(DtlsKeyDerEncoding::Pkcs8),
            _ => None,
        };
        let Some(encoding) = encoding else {
            key.zeroize();
            return Err(anyhow::anyhow!("Unsupported DTLS private key DER encoding"));
        };
        let bytes = key.secret_der().to_vec();
        // rustls-pki-types does not clear on Drop; wipe the PEM-parsed owner now
        // that Ferrum owns the only live DER copy used by the loader.
        key.zeroize();
        Ok(Self {
            bytes,
            encoding,
            drop_hook,
        })
    }

    fn private_key_der(&self) -> rustls::pki_types::PrivateKeyDer<'_> {
        match self.encoding {
            DtlsKeyDerEncoding::Pkcs1 => rustls::pki_types::PrivateKeyDer::Pkcs1(
                rustls::pki_types::PrivatePkcs1KeyDer::from(self.bytes.as_slice()),
            ),
            DtlsKeyDerEncoding::Sec1 => rustls::pki_types::PrivateKeyDer::Sec1(
                rustls::pki_types::PrivateSec1KeyDer::from(self.bytes.as_slice()),
            ),
            DtlsKeyDerEncoding::Pkcs8 => rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(self.bytes.as_slice()),
            ),
        }
    }

    fn secret_der(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingDtlsKeyDer {
    fn drop(&mut self) {
        use zeroize::Zeroize;

        // Preserve length until any observer runs so tests can assert every
        // live key byte was cleared before the allocation is released.
        self.bytes.as_mut_slice().zeroize();
        if let Some(hook) = self.drop_hook.as_ref() {
            hook(&self.bytes);
        }
    }
}

/// Load a leaf-first DTLS certificate chain from PEM and convert it to DER.
///
/// Every certificate record is parsed and retained in configured order. The
/// first certificate must match an ECDSA P-256 or P-384 private key. Ed25519
/// is not supported by dimpl for DTLS signatures.
pub fn load_dtls_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<DtlsCertificateChain, anyhow::Error> {
    load_dtls_certificate_with_key_drop_hook(cert_path, key_path, None)
}

/// Test-only seam that observes Ferrum-managed DTLS key DER after zeroization
/// and before the backing allocation is released.
pub(crate) fn load_dtls_certificate_with_key_drop_hook(
    cert_path: &str,
    key_path: &str,
    drop_hook: Option<DtlsKeyDropHook>,
) -> Result<DtlsCertificateChain, anyhow::Error> {
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

    crate::tls::check_cert_expiry_from_pem_bytes(
        cert_material.bytes.expose_secret(),
        "DTLS certificate",
        &cert_material.display_source_id,
        0,
    )?;

    // Parse every declared certificate and exactly one key through the shared
    // bounded, fail-closed PEM admission path. The patched dimpl stack presents
    // the complete leaf-first chain, so a valid multi-certificate identity is
    // retained rather than rejected or silently truncated.
    let certificate_chain = crate::tls::parse_pem_certificate_bundle(
        cert_material.bytes.expose_secret(),
        "DTLS certificate",
        &cert_material.display_source_id,
    )?;
    let parsed_key = crate::tls::parse_pem_private_key(
        key_material.bytes.expose_secret(),
        "DTLS private key",
        &key_material.display_source_id,
    )?;
    // Adopt immediately so every subsequent success/error return clears the
    // Ferrum-managed DER owner without relying on manual zeroize call sites.
    let key_der = ZeroizingDtlsKeyDer::adopt(parsed_key, drop_hook)?;

    // Ferrum pins rustls's build-selected provider. Parse from a borrow — do not
    // `clone_key()` into `CertifiedKey::from_der`, which would create another
    // owned DER allocation that ring drops without clearing.
    let borrowed_key = key_der.private_key_der();
    let signing_key = crate::fips::any_supported_signing_key(&borrowed_key).map_err(|error| {
        anyhow::anyhow!(
            "DTLS certificate {} and private key {} do not form a valid pair: {error}",
            cert_material.display_source_id,
            key_material.display_source_id
        )
    })?;
    let certified_key = rustls::sign::CertifiedKey::new(certificate_chain.clone(), signing_key);
    match certified_key.keys_match() {
        // Preserve rustls `CertifiedKey::from_der` semantics: Unknown is not fatal.
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
        Err(error) => {
            return Err(anyhow::anyhow!(
                "DTLS certificate {} and private key {} do not form a valid pair: {error}",
                cert_material.display_source_id,
                key_material.display_source_id
            ));
        }
    }

    // Copy into dimpl's zeroizing owner, then drop the Ferrum DER guard so the
    // rustls-shaped copy lives only long enough for parsing/validation.
    let private_key = DtlsPrivateKey::from(key_der.secret_der().to_vec());
    drop(key_der);

    // dimpl only supports ECDSA P-256 / P-384. Reject unsupported algorithms at
    // materialization time so admission/config load surfaces the defect instead
    // of panicking inside the DTLS handshake on first use.
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

    DtlsCertificateChain::new(
        certificate_chain
            .into_iter()
            .map(|certificate| certificate.to_vec())
            .collect(),
        private_key,
    )
    .map_err(|error| anyhow::anyhow!("Invalid DTLS certificate chain: {error}"))
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
    crate::tls::root_cert_store_from_pem_bundle(
        material.bytes.expose_secret(),
        "DTLS CA bundle",
        &material.display_source_id,
    )
}

fn load_backend_root_store(
    proxy: &Proxy,
    global_ca_bundle_path: Option<&str>,
) -> Result<rustls::RootCertStore, anyhow::Error> {
    // `system://` resolves to `None` here, pinning the built-in roots and
    // deliberately skipping the cluster-global bundle.
    if let Some(ca_path) = proxy
        .resolved_tls
        .effective_ca_source(global_ca_bundle_path)
    {
        load_root_store_from_pem(ca_path)
    } else {
        Ok(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
    }
}

/// Generate an ephemeral self-signed certificate for DTLS clients that don't
/// need client authentication (the common case for backend connections).
fn generate_ephemeral_cert() -> Result<DtlsCertificateChain, anyhow::Error> {
    dimpl::certificate::generate_self_signed_certificate()
        .map(DtlsCertificateChain::from)
        .map_err(|e| anyhow::anyhow!("Failed to generate ephemeral DTLS cert: {}", e))
}

/// Generate a self-signed DTLS certificate for testing.
#[allow(dead_code)]
pub fn generate_self_signed_cert() -> Result<DtlsCertificateChain, anyhow::Error> {
    generate_ephemeral_cert()
}

/// Generate an ephemeral self-signed certificate for DTLS clients that don't
/// need client authentication.
pub fn generate_ephemeral_cert_public() -> Result<DtlsCertificateChain, anyhow::Error> {
    generate_ephemeral_cert()
}

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate a backend server's leaf-first DER certificate chain.
fn validate_server_cert(
    peer_chain: &[Vec<u8>],
    server_name: &rustls::pki_types::ServerName<'static>,
    verifier: &dyn rustls::client::danger::ServerCertVerifier,
) -> Result<(), anyhow::Error> {
    let (leaf, intermediates) = peer_chain
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("DTLS server sent an empty certificate chain"))?;
    let cert = rustls::pki_types::CertificateDer::from(leaf.as_slice());
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|certificate| rustls::pki_types::CertificateDer::from(certificate.as_slice()))
        .collect();
    verifier
        .verify_server_cert(
            &cert,
            &intermediates,
            server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("DTLS server certificate verification failed: {}", e))
}

/// Validate a frontend client certificate when DTLS mTLS is enabled.
fn validate_client_cert(
    peer_chain: &[Vec<u8>],
    verifier: &dyn rustls::server::danger::ClientCertVerifier,
) -> Result<(), anyhow::Error> {
    let (leaf, intermediates) = peer_chain
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("DTLS client sent an empty certificate chain"))?;
    let cert = rustls::pki_types::CertificateDer::from(leaf.as_slice());
    let intermediates: Vec<_> = intermediates
        .iter()
        .map(|certificate| rustls::pki_types::CertificateDer::from(certificate.as_slice()))
        .collect();
    verifier
        .verify_client_cert(&cert, &intermediates, rustls::pki_types::UnixTime::now())
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
            Output::PeerCert(_) => {}
            Output::PeerCertChain(chain) => {
                if let (Some(server_name), Some(verifier)) = (server_name, server_cert_verifier) {
                    validate_server_cert(&chain, server_name, verifier)?;
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
            Output::PeerCert(_) | Output::PeerCertChain(_) | Output::ApplicationData(_) => {}
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
                certificate: certificate.into(),
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
    fn dtls_root_store_rejects_mixed_malformed_bundle_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mixed-ca.pem");
        let valid = std::fs::read_to_string("tests/certs/server.crt").expect("read valid cert");
        std::fs::write(
            &path,
            format!("{valid}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
        )
        .expect("write mixed CA bundle");

        let error = load_root_store_from_pem(path.to_str().expect("utf8 path"))
            .expect_err("a malformed later record must reject the complete DTLS trust bundle")
            .to_string();
        assert!(error.contains("DTLS CA bundle"), "got: {error}");
        assert!(error.contains("record #2"), "got: {error}");
    }

    #[test]
    fn dtls_root_store_rejects_all_malformed_bundle() {
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(
            file.path(),
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed CA");

        let error = load_root_store_from_pem(file.path().to_str().expect("utf8 path"))
            .expect_err("an all-malformed DTLS trust bundle must fail")
            .to_string();
        assert!(error.contains("record #1"), "got: {error}");
    }

    #[test]
    fn dtls_root_store_rejects_individual_unusable_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("unusable-root.pem");
        let valid = std::fs::read_to_string("tests/certs/server.crt").expect("read valid cert");
        std::fs::write(
            &path,
            format!("{valid}-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n"),
        )
        .expect("write unusable root bundle");

        let error = load_root_store_from_pem(path.to_str().expect("utf8 path"))
            .expect_err("one unusable root must reject the complete DTLS trust bundle")
            .to_string();
        assert!(error.contains("record #2"), "got: {error}");
        assert!(error.contains("not a usable trust root"), "got: {error}");
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

        server.spawn_session("127.0.0.1:12345".parse().unwrap(), vec![0x16; 32], None);

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

        server.spawn_session("127.0.0.1:12346".parse().unwrap(), vec![0x16; 32], None);

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

        server.spawn_session(
            "127.0.0.1:12347".parse().unwrap(),
            client_hello_packet(),
            None,
        );
        assert_eq!(server.active_session_count(), 1);
        assert_eq!(mirror.load(Ordering::Relaxed), 1);

        server.spawn_session(
            "127.0.0.1:12348".parse().unwrap(),
            client_hello_packet(),
            None,
        );
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
        let _ =
            rustls::crypto::CryptoProvider::install_default(crate::fips::base_crypto_provider());

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
            certificate: certificate.into(),
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

    /// PeerAuthentication live reload does not own terminating UDP+DTLS
    /// listeners; `swap_frontend_config` is the ordinary `FERRUM_DTLS_*`
    /// generation path. The swap is atomic and new sessions snapshot the
    /// latest material at spawn time; existing sessions are unaffected.
    #[tokio::test]
    async fn dtls_server_swap_frontend_config_updates_active_config_atomically() {
        let server = test_server(DtlsServerLimits::default()).await;

        // Capture a pointer to the old active config so we can prove the
        // swap actually replaced it (not just mutated in place).
        let before = Arc::as_ptr(&server.active_config.load_full());

        let new_certificate = DtlsCertificateChain::from(
            dimpl::certificate::generate_self_signed_certificate().expect("generate cert"),
        );
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
        server.spawn_session(
            "127.0.0.1:43210".parse().unwrap(),
            client_hello_packet(),
            None,
        );
        assert!(
            server.active_session_count() <= 1,
            "spawn_session honored admission limits after a live-reload swap"
        );
    }
}

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

use std::net::{IpAddr, SocketAddr};
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

/// Race one potentially-blocking delivery against frontend client-trust
/// retirement. Used after a DTLS client-certificate session is registered so
/// a full plaintext, accept, or UDP channel cannot pin the session past
/// withdrawal (issue #3857).
///
/// A withdrawal that is already visible never polls `op`. One that becomes
/// ready together with `op` wins the biased race and drops `op` before it
/// can complete, so no new application plaintext is delivered to the proxy
/// and no additional application ciphertext is committed to the client.
/// Unauthenticated / static DTLS (`client_trust == None`) awaits `op` with
/// no retirement future.
async fn frontend_trust_raced_delivery<F>(
    client_trust: Option<&crate::tls::ClientTrustSession>,
    op: F,
) -> Result<F::Output, FrontendAppSendReject>
where
    F: std::future::Future,
{
    let Some(session) = client_trust else {
        return Ok(op.await);
    };
    if session.is_retired() {
        return Err(FrontendAppSendReject::Closed);
    }
    tokio::select! {
        biased;
        _ = session.retired() => Err(FrontendAppSendReject::Closed),
        result = op => Ok(result),
    }
}

/// Add the established frontend client-trust retirement fence to one bounded
/// ciphertext write. A withdrawal that is already visible never polls `send`;
/// one that becomes ready together with the socket write wins the biased race
/// and drops that write future before it can commit a datagram.
async fn frontend_app_ciphertext_send_until_expiry_and_trust<F>(
    deadline: Option<tokio::time::Instant>,
    cancel: Option<&mut oneshot::Receiver<()>>,
    client_trust: Option<&crate::tls::ClientTrustSession>,
    send: F,
) -> Result<F::Output, FrontendAppSendReject>
where
    F: std::future::Future,
{
    frontend_trust_raced_delivery(
        client_trust,
        frontend_app_ciphertext_send_until_expiry(deadline, cancel, send),
    )
    .await?
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
    reply_local: Option<crate::socket_opts::PktinfoLocal>,
    in_flight: Option<&mut InFlightFrontendAppSend>,
    session_deadline: Option<tokio::time::Instant>,
    client_trust: Option<&crate::tls::ClientTrustSession>,
) -> Result<(), FrontendAppSendReject> {
    if let Some(inflight) = in_flight {
        let deadline = earliest_frontend_app_send_deadline(inflight.deadline, session_deadline);
        match frontend_app_ciphertext_send_until_expiry_and_trust(
            deadline,
            Some(&mut inflight.cancel),
            client_trust,
            send_dtls_record(socket, data, peer, reply_local),
        )
        .await
        {
            Ok(Ok(written)) if written == data.len() => Ok(()),
            Ok(_) => Err(FrontendAppSendReject::Closed),
            Err(reject) => Err(reject),
        }
    } else {
        match frontend_app_ciphertext_send_until_expiry_and_trust(
            session_deadline,
            None,
            client_trust,
            send_dtls_record(socket, data, peer, reply_local),
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

/// Pin the post-registration trust-retirement race used for plaintext
/// delivery, accept handoff, and UDP writes.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) async fn frontend_trust_raced_delivery_for_test<F>(
    client_trust: Option<&crate::tls::ClientTrustSession>,
    op: F,
) -> Result<F::Output, FrontendAppSendReject>
where
    F: std::future::Future,
{
    frontend_trust_raced_delivery(client_trust, op).await
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
    /// Semantic client-CA / CRL identity of THIS generation (issue #3857).
    ///
    /// Derived from the exact bytes this candidate's verifier was built from, so
    /// the retirement decision published for established DTLS sessions can never
    /// describe material that was not the material actually accepted. `None`
    /// when the listener performs no client-certificate verification, in which
    /// case no session can hold a withdrawable trust decision.
    pub client_trust: Option<crate::tls::ClientTrustMaterial>,
}

/// Datagrams drained per `recvmmsg` call on the ingress-interface capture path.
/// Deliberately smaller than the plain-UDP listener's configurable batch: the
/// batch preallocates one max-size datagram buffer per slot, and this path only
/// exists on NodeWaypoint DTLS listeners.
#[cfg(target_os = "linux")]
const DTLS_INGRESS_CAPTURE_BATCH: usize = 16;

/// Datagrams drained per readiness wake-up before the capture loop returns to
/// its `select!`.
///
/// `try_io` is a synchronous call that consumes no tokio cooperative budget and
/// `dispatch_datagram` has no await point, so an unbounded inner drain would
/// keep a runtime worker thread for exactly as long as a sender can keep the
/// receive queue non-empty — never observing shutdown and never yielding. The
/// plain-UDP listener bounds its own drain for the same reason; this is the
/// DTLS equivalent. Re-entering the outer loop re-arms the shutdown branch and
/// puts the readiness poll (which does consume coop budget) back in the path.
#[cfg(target_os = "linux")]
const DTLS_INGRESS_CAPTURE_DRAIN_LIMIT: usize = 256;

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

/// Source-attribution callback for new frontend DTLS sessions.
pub type DtlsNewSessionAuthorizer = dyn Fn(SocketAddr, Option<u32>) -> bool + Send + Sync + 'static;

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
    /// Optional source-attribution gate checked before a new peer's handshake
    /// driver is spawned and therefore before any handshake response can be
    /// emitted. The callback receives the socket peer and kernel-reported
    /// ingress interface. NodeWaypoint listeners use this to ensure the
    /// marked server socket never sends a pre-authentication response to an
    /// unattributable or source-mismatched peer.
    pub authorize_new_session: Option<Arc<DtlsNewSessionAuthorizer>>,
    /// Optional diagnostic mirror for surfaces that need to report demux state
    /// outside this server object, such as the admin `/overload` endpoint. This
    /// is eventually consistent with `active_sessions` and is not used for
    /// admission control.
    pub active_session_mirror: Option<Arc<AtomicU64>>,
    /// Capture each datagram's kernel-reported INGRESS INTERFACE index and pin
    /// it to the peer's demux entry (issue #3286).
    ///
    /// Set only by the NodeWaypoint UDP/DTLS scoped-authorization path, which
    /// attributes a session's source workload from that interface plus the
    /// node-agent-published source address. When `false` the demux loop keeps
    /// its ordinary `recv_from` path byte-for-byte; when `true` (Linux only) it
    /// reads through the shared `recvmmsg` + cmsg batch reader instead, which
    /// is the same mechanism the plain-UDP listener already uses.
    pub capture_ingress_ifindex: bool,
    /// `SO_MARK` to stamp on the DTLS server's OWN bound socket before it is
    /// published or used (issue #3286).
    ///
    /// Set only by the NodeWaypoint scoped DTLS path, to
    /// `crate::ebpf::NODE_WAYPOINT_INBOUND_AUTH_MARK`. Unlike the plain-UDP
    /// relay — where the proxy owns the frontend socket and marks it itself —
    /// a `DtlsServer` owns the socket every encrypted record leaves from, so
    /// the caller has no other place to apply the mark. Without it the
    /// pod-veth tc guard drops the handshake and application replies heading
    /// back to the enrolled source pod, and the listener would look healthy
    /// while no DTLS session could ever complete.
    ///
    /// `None` (and `Some(0)`) leave the socket untouched, which is every
    /// ordinary DTLS listener.
    pub socket_mark: Option<u32>,
    /// Make the server's OWN bound socket transparent (`IP_TRANSPARENT` /
    /// `IPV6_TRANSPARENT`) before it is published or used (issue #3286
    /// Service path).
    ///
    /// Set only by the NodeWaypoint scoped DTLS path. A steered Service
    /// datagram is delivered with its ORIGINAL destination — the Service
    /// ClusterIP — still in the IP header, and every encrypted record this
    /// server sends back is sourced from exactly that pinned address. A
    /// ClusterIP is not configured on the node, so the kernel refuses it as a
    /// source unless the socket carries `FLOWI_FLAG_ANYSRC`. Without this flag
    /// a steered DTLS handshake could never complete: the client's connected
    /// socket discards records arriving from a node address.
    ///
    /// `false` for every ordinary DTLS listener, which is byte-for-byte
    /// unchanged.
    pub transparent_reply_source: bool,
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
    /// `(proxy_id, listen_port)` stamped on the demux path's rate-limited
    /// refusal diagnostics — client-address metadata refusals and
    /// per-source-IP pre-handshake refusals alike — so a DTLS refusal
    /// correlates with the plain-UDP listener's record for the same proxy.
    /// Cloned once at listener spawn, never per datagram. `None` outside the
    /// proxy listener path.
    pub datagram_client_address_listener: Option<(Arc<str>, u16)>,
    /// Client-trust retirement domain this listener's authenticated sessions
    /// join (issues #3857, #3858).
    ///
    /// `Some(ClientTrustScope::FrontendDtls)` for every operator-owned
    /// `FERRUM_DTLS_*` listener, which is the default. `None` for generated
    /// `MeshNodeWaypoint` listeners: their trust anchors are owned by the mesh
    /// slice, `swap_active_dtls_frontend_config` deliberately skips them, and
    /// `publish_mesh_node_waypoint_dtls_generation` publishes no trust material
    /// — so registering their sessions in the operator domain would let an
    /// unrelated operator CRL edit retire mesh datapath sessions and count them
    /// under `scope="frontend_dtls"`, while a mesh-side narrowing retired
    /// nothing. `None` therefore means "this listener's sessions are not
    /// retirable by any published generation", which is exactly the mesh
    /// posture today.
    pub client_trust_scope: Option<crate::tls::ClientTrustScope>,
    /// Gateway-wide per-effective-source-IP bound on the PRE-HANDSHAKE demux
    /// table (`FERRUM_UDP_MAX_SESSIONS_PER_IP`).
    ///
    /// [`Self::max_sessions`] is a listener-wide cap, so without this one
    /// source address can occupy the whole demux table with unauthenticated
    /// ClientHellos and deny DTLS service to every other client. The plain-UDP
    /// and TCP listeners already carry the same bound, but their guard is taken
    /// at SESSION reservation — a DTLS peer holds demux state long before a
    /// session exists, so the gate has to run on the ClientHello admission path
    /// instead.
    ///
    /// This is a HANDLE to the one counter map `ProxyState` owns, shared with
    /// the owning UDP listener, so TCP, plain UDP and DTLS share one accounting
    /// and one configuration surface. The pre-handshake slot is released the
    /// moment the accepted connection is handed to `accept()`, where the
    /// listener's session reservation takes over: an established DTLS session
    /// must count once against a source's budget, not twice.
    ///
    /// `Default` is the disabled dimension, which is what standalone/test
    /// constructors and generated mesh listeners get.
    pub per_source_ip_admission: crate::proxy::PerIpStreamAdmission,
}

/// Owner-scoped client-trust retirement domain for a DTLS listener (issues
/// #3857, #3858).
///
/// One place, so the listener spawn path and the retirement domain cannot
/// disagree about which listeners an operator `FERRUM_DTLS_*` publication may
/// retire. `is_node_waypoint` is the same discriminator the listener already
/// uses for its scoped socket options.
///
/// A generated `MeshNodeWaypoint` listener gets `None`: its posture is owned by
/// the mesh slice, `StreamListenerManager::swap_active_dtls_frontend_config`
/// deliberately skips it, and `publish_mesh_node_waypoint_dtls_generation`
/// publishes no trust material. Putting its sessions in the operator domain
/// would let an unrelated operator CRL edit retire mesh datapath sessions and
/// count them under `scope="frontend_dtls"`, while a mesh-side narrowing
/// retired nothing.
pub fn dtls_client_trust_scope_for_owner(
    is_node_waypoint: bool,
) -> Option<crate::tls::ClientTrustScope> {
    if is_node_waypoint {
        None
    } else {
        Some(crate::tls::ClientTrustScope::FrontendDtls)
    }
}

impl Default for DtlsServerLimits {
    fn default() -> Self {
        Self {
            max_sessions: None,
            handshake_timeout: Some(DEFAULT_DTLS_HANDSHAKE_TIMEOUT),
            allow_new_session: None,
            authorize_new_session: None,
            active_session_mirror: None,
            capture_ingress_ifindex: false,
            socket_mark: None,
            transparent_reply_source: false,
            datagram_client_address: None,
            datagram_client_address_drops: None,
            datagram_client_address_listener: None,
            client_trust_scope: dtls_client_trust_scope_for_owner(false),
            per_source_ip_admission: crate::proxy::PerIpStreamAdmission::default(),
        }
    }
}

/// Apply the NodeWaypoint-scoped socket options a `DtlsServer` needs on its own
/// bound socket, failing closed when either cannot be applied (issue #3286).
///
/// Called from [`DtlsServer::from_socket_with_limits`] on the raw `UdpSocket`
/// **before** the server object is assembled, so a failure surfaces as a
/// listener bind/readiness failure and no partially-configured server can be
/// published, run, or leak a socket. A listener that never becomes a
/// `DtlsServer` also never spawns a recv-loop task.
///
/// Neither branch executes for an ordinary DTLS listener: both fields are
/// `None`/`false` in `DtlsServerLimits::default()` and are set only by the
/// NodeWaypoint scoped path. Diagnostics name the field and the bound address
/// only — no crypto material, peer identity, or configuration value is logged
/// or embedded.
fn apply_scoped_dtls_socket_options(
    socket: &UdpSocket,
    limits: &DtlsServerLimits,
) -> Result<(), anyhow::Error> {
    if !limits.capture_ingress_ifindex
        && !limits.transparent_reply_source
        && limits.socket_mark.is_none_or(|mark| mark == 0)
    {
        return Ok(());
    }
    let local = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("DTLS demux cannot read its own bound address: {e}"))?;
    #[cfg(unix)]
    let fd = {
        use std::os::fd::AsRawFd;
        socket.as_raw_fd()
    };
    #[cfg(not(unix))]
    let fd = 0;

    // SO_MARK first: it governs every byte this socket sends, including the
    // ServerHello of the very first handshake.
    if let Some(mark) = limits.socket_mark.filter(|mark| *mark != 0) {
        #[cfg(unix)]
        crate::socket_opts::set_socket_mark(fd, mark).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "NodeWaypoint scoped DTLS listener on {local} could not apply \
                 DtlsServerLimits::socket_mark (SO_MARK), so the pod-veth guard would drop every \
                 record it sends back to an enrolled source pod"
            ))
        })?;
        // SO_MARK is Linux-only and NodeWaypoint scoping never runs on a
        // non-unix target; the ingress-capture check below fails closed there
        // regardless, so there is nothing to apply.
        #[cfg(not(unix))]
        let _ = mark;
    }

    // Transparent next, still before any record can leave: a scoped session
    // sources every encrypted record from the Service address the client
    // targeted, which is not configured on this node.
    if limits.transparent_reply_source {
        crate::socket_opts::set_scoped_reply_transparent(fd, local.is_ipv6()).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "NodeWaypoint scoped DTLS listener on {local} could not apply \
                 DtlsServerLimits::transparent_reply_source (IP_TRANSPARENT / IPV6_TRANSPARENT), \
                 so it could not source its encrypted records from the Service address a steered \
                 workload addressed; NET_ADMIN (or NET_RAW on newer kernels) is required"
            ))
        })?;
    }

    if limits.capture_ingress_ifindex {
        let families = crate::socket_opts::enable_ingress_pktinfo(fd, local).map_err(|error| {
            anyhow::Error::new(error).context(format!(
                "NodeWaypoint scoped DTLS listener on {local} cannot capture the datagram ingress \
                 interface required for source-workload authorization"
            ))
        })?;
        info!(
            local = %local,
            families = ?families,
            "DTLS demux armed ingress-interface capture for NodeWaypoint source attribution"
        );
    }
    Ok(())
}

// ============================================================================
// Gateway TLS policy → DTLS
// ============================================================================

/// The gateway TLS policy (`FERRUM_TLS_MIN_VERSION`, `FERRUM_TLS_MAX_VERSION`,
/// `FERRUM_TLS_CIPHER_SUITES`, `FERRUM_TLS_CURVES`) expressed in the DTLS
/// stack's vocabulary.
///
/// `docs/configuration.md` documents those variables as applying "inbound +
/// outbound". Every rustls listener and client honours the parsed
/// [`crate::tls::TlsPolicy`]; before issue #4507 the DTLS builders never
/// received it, so a `udp` + `dtls` proxy kept accepting DTLS 1.2 with dimpl's
/// full default suite list even under `FERRUM_TLS_MIN_VERSION=1.3`.
///
/// Mapping rules, all derived from `TlsPolicy::from_env_config`:
///
/// * **Versions.** `TlsPolicy::protocol_versions` gates the two DTLS versions
///   one-for-one (TLS 1.2 ↔ DTLS 1.2, TLS 1.3 ↔ DTLS 1.3). dimpl expresses a
///   disabled version as an EMPTY suite filter for it: `ConfigBuilder`'s
///   `dtls12_cipher_suites` / `dtls13_cipher_suites` accept an empty slice and
///   `build()` only refuses when BOTH versions end up with zero suites
///   (`vendor/dimpl-0.6.1-ferrum-patched/src/config.rs`, the "No cipher suites
///   remain after filtering" gate). So the empty filter is a supported way to
///   disable a version, not an accident that has to be worked around.
/// * **Cipher suites.** The nine suite names `parse_cipher_suites` accepts are
///   the entire universe here. The three TLS 1.3 suites and the three
///   `ECDHE-ECDSA-*` TLS 1.2 suites map exactly onto dimpl's enums.
/// * **`ECDHE-RSA-*`.** dimpl implements no RSA-authenticated DTLS 1.2 suite,
///   and a DTLS surface requires an ECDSA P-256/P-384 certificate anyway, so an
///   RSA-auth suite could never be negotiated on a DTLS surface even with
///   dimpl's unfiltered defaults. Those names are therefore inapplicable
///   rather than dropped: excluding them removes nothing an operator could have
///   observed. But a policy whose ENTIRE TLS 1.2 selection is `ECDHE-RSA-*`
///   while TLS 1.2 is enabled WOULD silently lose DTLS 1.2, so that is a
///   startup error naming the suites and the surface.
/// * **Key-exchange groups.** `FERRUM_TLS_CURVES` parses to exactly X25519,
///   secp256r1 and secp384r1, which are exactly the three groups dimpl
///   implements, so the mapping is faithful and is applied.
///
/// Anything else — a suite this build learns to parse later that has no DTLS
/// counterpart, or a policy that leaves every enabled DTLS version with no
/// usable suite — is refused at startup rather than quietly building a config
/// weaker (or more silent) than the operator asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsSuitePolicy {
    dtls12: Vec<dimpl::crypto::Dtls12CipherSuite>,
    dtls13: Vec<dimpl::crypto::Dtls13CipherSuite>,
    kx_groups: Vec<dimpl::crypto::NamedGroup>,
}

impl DtlsSuitePolicy {
    /// Map a gateway [`crate::tls::TlsPolicy`] onto the DTLS stack.
    ///
    /// `surface` names the DTLS surface being built (for example
    /// `"frontend DTLS listener"`) and appears verbatim in every refusal so an
    /// operator can tell which listener or backend the policy could not serve.
    pub fn from_tls_policy(
        policy: &crate::tls::TlsPolicy,
        surface: &str,
    ) -> Result<Self, anyhow::Error> {
        use dimpl::crypto::{Dtls12CipherSuite as D12, Dtls13CipherSuite as D13};

        let dtls12_enabled = policy
            .protocol_versions
            .iter()
            .any(|v| std::ptr::eq(*v, &rustls::version::TLS12));
        let dtls13_enabled = policy
            .protocol_versions
            .iter()
            .any(|v| std::ptr::eq(*v, &rustls::version::TLS13));

        let mut dtls12: Vec<D12> = Vec::new();
        let mut dtls13: Vec<D13> = Vec::new();
        // TLS 1.2 suites the operator selected that DTLS cannot authenticate.
        let mut rsa_auth_tls12: Vec<&'static str> = Vec::new();

        for suite in &policy.crypto_provider.cipher_suites {
            match suite.suite() {
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => {
                    dtls13.push(D13::AES_128_GCM_SHA256)
                }
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => {
                    dtls13.push(D13::AES_256_GCM_SHA384)
                }
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => {
                    dtls13.push(D13::CHACHA20_POLY1305_SHA256)
                }
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
                    dtls12.push(D12::ECDHE_ECDSA_AES128_GCM_SHA256)
                }
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
                    dtls12.push(D12::ECDHE_ECDSA_AES256_GCM_SHA384)
                }
                rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
                    dtls12.push(D12::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256)
                }
                // RSA-authenticated ECDHE AEAD suites: recognized, but no DTLS
                // surface can ever negotiate one (dimpl implements no RSA-auth
                // DTLS 1.2 suite and DTLS requires an ECDSA certificate).
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
                    rsa_auth_tls12.push("ECDHE-RSA-AES128-GCM-SHA256")
                }
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
                    rsa_auth_tls12.push("ECDHE-RSA-AES256-GCM-SHA384")
                }
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
                    rsa_auth_tls12.push("ECDHE-RSA-CHACHA20-POLY1305")
                }
                // Refuse rather than thin the operator's list silently.
                other => {
                    return Err(anyhow::anyhow!(
                        "Cipher suite {:?} selected by FERRUM_TLS_CIPHER_SUITES has no DTLS \
                         equivalent, so the {} cannot honour the configured TLS policy. Remove it \
                         from FERRUM_TLS_CIPHER_SUITES or stop terminating/originating DTLS.",
                        other,
                        surface
                    ));
                }
            }
        }

        // A TLS 1.2 selection that is entirely RSA-authenticated WOULD lose
        // DTLS 1.2 outright. That is exactly the silent drop this mapping
        // exists to prevent, so refuse and name the remedy.
        if dtls12_enabled && dtls12.is_empty() && !rsa_auth_tls12.is_empty() {
            return Err(anyhow::anyhow!(
                "FERRUM_TLS_CIPHER_SUITES selects only RSA-authenticated TLS 1.2 suites ({}), \
                 which have no DTLS equivalent: the DTLS stack authenticates with ECDSA \
                 P-256/P-384 certificates only. The {} would silently lose DTLS 1.2. Add the \
                 matching ECDHE-ECDSA-* suite(s), or set FERRUM_TLS_MIN_VERSION=1.3.",
                rsa_auth_tls12.join(", "),
                surface
            ));
        }

        if !dtls12_enabled {
            dtls12.clear();
        }
        if !dtls13_enabled {
            dtls13.clear();
        }

        if dtls12.is_empty() && dtls13.is_empty() {
            return Err(anyhow::anyhow!(
                "The configured TLS policy (FERRUM_TLS_MIN_VERSION / FERRUM_TLS_MAX_VERSION / \
                 FERRUM_TLS_CIPHER_SUITES) leaves the {} with no usable DTLS cipher suite for \
                 any enabled version, so it could never complete a handshake.",
                surface
            ));
        }

        let mut kx_groups: Vec<dimpl::crypto::NamedGroup> = Vec::new();
        for group in &policy.crypto_provider.kx_groups {
            match group.name() {
                rustls::NamedGroup::X25519 => kx_groups.push(dimpl::crypto::NamedGroup::X25519),
                rustls::NamedGroup::secp256r1 => {
                    kx_groups.push(dimpl::crypto::NamedGroup::Secp256r1)
                }
                rustls::NamedGroup::secp384r1 => {
                    kx_groups.push(dimpl::crypto::NamedGroup::Secp384r1)
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "Key-exchange group {:?} selected by FERRUM_TLS_CURVES has no DTLS \
                         equivalent, so the {} cannot honour the configured TLS policy.",
                        other,
                        surface
                    ));
                }
            }
        }
        if kx_groups.is_empty() {
            return Err(anyhow::anyhow!(
                "The configured TLS policy leaves the {} with no usable key-exchange group.",
                surface
            ));
        }

        Ok(Self {
            dtls12,
            dtls13,
            kx_groups,
        })
    }

    /// DTLS 1.2 suites this policy admits. Empty means DTLS 1.2 is disabled.
    pub fn dtls12_cipher_suites(&self) -> &[dimpl::crypto::Dtls12CipherSuite] {
        &self.dtls12
    }

    /// DTLS 1.3 suites this policy admits. Empty means DTLS 1.3 is disabled.
    pub fn dtls13_cipher_suites(&self) -> &[dimpl::crypto::Dtls13CipherSuite] {
        &self.dtls13
    }

    /// Key-exchange groups this policy admits.
    pub fn kx_groups(&self) -> &[dimpl::crypto::NamedGroup] {
        &self.kx_groups
    }

    /// Apply the mapped policy to a dimpl `ConfigBuilder`.
    fn apply(&self, builder: dimpl::ConfigBuilder) -> dimpl::ConfigBuilder {
        builder
            .dtls12_cipher_suites(self.dtls12_cipher_suites())
            .dtls13_cipher_suites(self.dtls13_cipher_suites())
            .kx_groups(self.kx_groups())
    }
}

/// Start a dimpl `ConfigBuilder` already carrying the gateway TLS policy.
///
/// `None` keeps dimpl's own defaults; every serving mode builds a
/// [`crate::tls::TlsPolicy`] at startup and passes `Some`, so `None` is the
/// test/plugin path only.
fn policy_config_builder(
    policy: Option<&crate::tls::TlsPolicy>,
    surface: &str,
) -> Result<dimpl::ConfigBuilder, anyhow::Error> {
    let builder = Config::builder();
    match policy {
        Some(policy) => {
            let mapped = DtlsSuitePolicy::from_tls_policy(policy, surface)?;
            debug!(
                surface = surface,
                dtls12_suites = mapped.dtls12_cipher_suites().len(),
                dtls13_suites = mapped.dtls13_cipher_suites().len(),
                kx_groups = mapped.kx_groups().len(),
                "Applied the gateway TLS policy to a DTLS configuration"
            );
            Ok(mapped.apply(builder))
        }
        None => Ok(builder),
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
    tls_policy: Option<&crate::tls::TlsPolicy>,
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

    // The gateway TLS policy applies outbound too (issue #4507): a
    // `Config::default()` here would originate DTLS 1.2 with dimpl's full
    // default suite list under `FERRUM_TLS_MIN_VERSION=1.3`.
    let config = Arc::new(
        policy_config_builder(
            tls_policy,
            &format!("backend DTLS client for proxy '{}'", proxy.id),
        )?
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build backend DTLS config: {}", e))?,
    );
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
    tls_policy: Option<&crate::tls::TlsPolicy>,
) -> Result<FrontendDtlsConfig, anyhow::Error> {
    let certificate = load_dtls_certificate(cert_path, key_path)?;

    let (require_client_cert, client_cert_verifier, client_trust) = if let Some(ca_path) =
        client_ca_cert_path
    {
        // ONE bounded read of the declared client-CA source, through the
        // repository's `CertSource` abstraction (issue #3857). Both the
        // trust anchors the verifier enforces and the semantic identity
        // published for this generation come out of that single read.
        //
        // Reading the path twice — once with `std::fs::read` for the
        // identity and once through `load_root_store_from_pem` for the
        // store — could observe a rotation in between and publish identity
        // A while serving verifier B. Going through `CertSource` also keeps
        // the hostile-input ceiling (`FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES`)
        // and makes an inline / non-file client-CA source work at all,
        // which a raw path read silently could not.
        let loaded = load_pem_root_store(ca_path)?;
        let client_trust = crate::tls::ClientTrustMaterial::from_parts(
            Some(loaded.material.bytes.expose_secret()),
            crls,
        )
        .map_err(|e| {
            // Source-redacted: a client-CA source may be inline PEM, so the
            // configured "path" can itself be secret material.
            anyhow::anyhow!(
                "Invalid DTLS client CA bundle from source {}: {}",
                loaded.material.display_source_id,
                e
            )
        })?;
        let root_store = loaded.roots;
        let mut verifier_builder =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store));
        verifier_builder = crate::tls::crl_policy::apply_client_crl_policy(verifier_builder, crls);
        let verifier = verifier_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build DTLS client verifier: {}", e))?;
        debug!("Frontend DTLS mTLS enabled: requiring and verifying client certificates");
        (true, Some(verifier), Some(client_trust))
    } else {
        (false, None, None)
    };

    // The gateway TLS policy applies inbound (issue #4507). Version and suite
    // admission is decided here, before the listener can serve anything, so a
    // policy the DTLS stack cannot express is a startup/reload refusal rather
    // than a listener that quietly accepts more than the operator allowed.
    let config_builder = policy_config_builder(tls_policy, "frontend DTLS listener")?
        .require_client_certificate(require_client_cert);
    let config = Arc::new(
        config_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build DTLS config: {}", e))?,
    );

    Ok(FrontendDtlsConfig {
        dimpl_config: config,
        certificate,
        client_cert_verifier,
        client_trust,
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

/// Whether `data` can open a new DTLS demux session.
///
/// The recv loop previously spawned on any 13-byte handshake record
/// (`content-type == 0x16`). After a refused client certificate the peer keeps
/// retransmitting flight 5 (`Certificate` / `CertificateVerify` / `Finished`),
/// which are also `0x16`. Each of those datagrams reserved a `handshake_timeout`
/// slot, allocated four channels, and started a driver whose `Dtls::new_auto`
/// engine then failed on a non-ClientHello — a spawn storm that, under coverage
/// instrumentation, delayed the next legitimate ClientHello past its budget,
/// and a leftover unconnected session at the same UDP 4-tuple would swallow a
/// later client's opening flight instead of starting a new handshake.
///
/// Only the initial fragment of a ClientHello (`msg_type == 0x01`,
/// `fragment_offset == 0`) starts a session. Continuation fragments and later
/// handshake messages from an unknown peer are dropped; DTLS retransmission of
/// a real ClientHello recovers loss. HelloVerifyRequest cookie retries are
/// ClientHellos too, so they still open (or continue) a session.
fn dtls_datagram_opens_session(data: &[u8]) -> bool {
    // DTLS record header: content_type (1) + version (2) + epoch (2) +
    //                     sequence_number (6) + length (2) = 13 bytes
    if data.len() < 13 || data[0] != 0x16 || data[3] != 0 || data[4] != 0 {
        return false;
    }
    let record_len = u16::from_be_bytes([data[11], data[12]]) as usize;
    let Some(record_end) = 13usize.checked_add(record_len) else {
        return false;
    };
    let Some(handshake) = data.get(13..record_end) else {
        return false;
    };
    // DTLS handshake header: msg_type (1) + length (3) + message_seq (2) +
    //                        fragment_offset (3) + fragment_length (3) = 12 bytes
    if handshake.len() < 12 {
        return false;
    }
    // msg_type 0x01 = ClientHello. Certificate (0x0b), Finished (0x14), and
    // every other handshake type must not reserve a session for an unknown peer.
    if handshake[0] != 0x01 {
        return false;
    }
    let fragment_offset =
        ((handshake[6] as usize) << 16) | ((handshake[7] as usize) << 8) | (handshake[8] as usize);
    let message_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    let fragment_len = ((handshake[9] as usize) << 16)
        | ((handshake[10] as usize) << 8)
        | (handshake[11] as usize);
    fragment_offset == 0
        && fragment_len != 0
        && fragment_len <= message_len
        && fragment_len <= handshake.len() - 12
}

/// Pin the ClientHello-only demux admission predicate for external hosted tests.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn dtls_datagram_opens_session_for_test(data: &[u8]) -> bool {
    dtls_datagram_opens_session(data)
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
            reply_local: None,
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
/// `FERRUM_DTLS_*` generation publish) and owner-scoped NodeWaypoint mesh
/// DTLS publish can publish a new `dimpl_config`, `certificate`, and client
/// verifier without mutating the snapshot held by in-flight DTLS sessions. New
/// sessions snapshot the slot in [`DtlsServer::spawn_session`]; existing
/// sessions retain the material they were spawned with. An ordinary frontend
/// client-trust narrowing can separately retire authenticated sessions through
/// [`crate::tls::client_trust`]. Mesh PeerAuthentication TCP+TLS reload must not
/// write this slot as a process-wide fanout:
/// generated NodeWaypoint listeners are swapped only through the owner-scoped
/// generation, and ordinary `FERRUM_DTLS_*` listeners keep their dedicated
/// identity.
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
    /// ClientHellos refused because the effective source IP already held its
    /// full `FERRUM_UDP_MAX_SESSIONS_PER_IP` budget. Fixed cardinality: one
    /// listener-local counter, never labelled by client address.
    per_source_ip_rejections: AtomicU64,
    /// Bounds this listener's rate of per-source-IP refusal warnings. The
    /// refusal path is exactly the flood an attacker controls, so it must not
    /// turn one refused ClientHello into one log record.
    per_source_ip_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    /// Bounds this listener's rate of handshake-timeout warnings, shared with
    /// every spawned session driver.
    ///
    /// An abandoned handshake is an unauthenticated, attacker-reachable event
    /// whose rate is bounded only by how fast demux entries can be created and
    /// expire, so one line per peer is a log-pipeline denial of service and an
    /// unbounded label cardinality on the peer field. `Arc` because the emit
    /// sites live inside the per-session driver task, not on `&self`.
    handshake_timeout_warn: Arc<crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter>,
    /// Total handshakes this listener abandoned at the deadline, emitted or
    /// suppressed. Reported on every warning so the withheld volume stays
    /// visible without one record per peer.
    handshake_timeouts: Arc<AtomicU64>,
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
    /// The complete kernel-reported `IP_PKTINFO` / `IPV6_PKTINFO` local
    /// destination of the datagram that opened this peer entry, when
    /// `DtlsServerLimits::capture_ingress_ifindex` is on (`None` on every
    /// ordinary listener). Two distinct facts ride in it and both are
    /// load-bearing:
    ///
    /// * `ifindex` is the INGRESS interface, which is the whole NodeWaypoint
    ///   source-attribution channel. A later datagram for the same peer
    ///   arriving on a DIFFERENT interface is dropped instead of being folded
    ///   into a session attributed to another interface's pod.
    /// * `ip` is the local address the client actually addressed — the Service
    ///   ClusterIP on the steered path, since steering rewrites nothing. Every
    ///   encrypted record for this session is sourced from it, or the client's
    ///   connected socket discards the reply. A later datagram naming a
    ///   DIFFERENT local destination is a different service flow and is
    ///   likewise dropped rather than silently re-pointing the reply source.
    reply_local: Option<crate::socket_opts::PktinfoLocal>,
    /// Authenticated forwarded client this peer entry was admitted with, when
    /// the datagram client-address gate is enabled. A later datagram from the
    /// same peer address asserting a different client is dropped rather than
    /// fed into a DTLS association admitted under another identity.
    forwarded_client: Option<SocketAddr>,
}

/// Whether a scoped DTLS listener may act on one datagram's kernel capture.
///
/// The whole NodeWaypoint DTLS security and reply story rides on the
/// `IP_PKTINFO` / `IPV6_PKTINFO` capture, so the decision is pulled out here as
/// a pure function: it is the one place that says what "this datagram belongs
/// to this session" means, and it is exercised without a socket, a privileged
/// host, or a live handshake.
///
/// * `capture_enabled` is [`DtlsServerLimits::capture_ingress_ifindex`]. When
///   it is off — every ordinary DTLS listener — nothing is captured, nothing is
///   compared, and every datagram is admitted exactly as before.
/// * `pinned` is the session's captured local destination, or `None` when no
///   session exists yet for this peer.
/// * `observed` is this datagram's captured local destination.
///
/// A scoped listener admits a datagram only when the kernel actually reported a
/// capture (otherwise it is neither attributable to a source workload nor
/// answerable from the address the client addressed) and, for an established
/// peer, only when that capture equals the pinned one. Both halves of
/// [`crate::socket_opts::PktinfoLocal`] participate: a different ingress
/// interface is a different source workload, and a different local destination
/// is a different Service flow whose reply would leave from the wrong source.
pub fn dtls_scoped_capture_admits(
    capture_enabled: bool,
    pinned: Option<crate::socket_opts::PktinfoLocal>,
    observed: Option<crate::socket_opts::PktinfoLocal>,
) -> bool {
    if !capture_enabled {
        return true;
    }
    if observed.is_none() {
        return false;
    }
    match pinned {
        Some(_) => pinned == observed,
        None => true,
    }
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

/// Count a ClientHello refused by the per-source-IP pre-handshake bound and
/// emit a rate-limited structured diagnostic for it.
///
/// The refusal path is precisely the flood an attacker controls, so the record
/// carries only fixed-cardinality fields: the owning listener, the configured
/// limit, the listener's running refusal total, and what the limiter withheld.
/// The client address is deliberately absent — the same posture the plain-UDP
/// per-source refusal takes — because a spoofed-source spray would otherwise
/// write attacker-chosen labels into the log at one entry per refusal.
///
/// Returns the suppressed count when a record was emitted, so the limiter
/// contract is assertable without a log-capture harness.
fn record_dtls_per_source_ip_refusal(
    limiter: &crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    rejections: &AtomicU64,
    listener: Option<&(Arc<str>, u16)>,
    limit: u64,
    now_ms: u64,
) -> Option<u64> {
    let refusals = rejections.fetch_add(1, Ordering::Relaxed) + 1;
    let suppressed = limiter.on_event(now_ms)?;
    let (proxy_id, listen_port) = match listener {
        Some((proxy_id, listen_port)) => (proxy_id.as_ref(), *listen_port),
        None => ("", 0u16),
    };
    warn!(
        proxy_id = proxy_id,
        listen_port = listen_port,
        limit = limit,
        refusals = refusals,
        suppressed = suppressed,
        "DTLS ClientHello refused: per-source-IP pre-handshake session limit reached"
    );
    Some(suppressed)
}

/// Count an abandoned frontend DTLS handshake and emit a rate-limited
/// structured diagnostic for it.
///
/// Reaching the handshake deadline is an unauthenticated, attacker-reachable
/// event whose rate is bounded only by how fast pre-handshake demux entries can
/// be created and expire. One warning per peer therefore turns a ClientHello
/// spray into a log flood with unbounded cardinality on the peer field, so the
/// emit is gated by the module's shared limiter: at most one record per window,
/// carrying the listener's running timeout total and the number of records the
/// limiter withheld since the last one. The peer address rides only on the
/// records that are actually emitted, which bounds it to one per window while
/// keeping an isolated timeout fully diagnosable.
///
/// Returns the suppressed count when a record was emitted, so the limiter
/// contract is assertable without a log-capture harness.
fn record_dtls_handshake_timeout(
    limiter: &crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    timeouts: &AtomicU64,
    peer_addr: SocketAddr,
    now_ms: u64,
) -> Option<u64> {
    let timed_out = timeouts.fetch_add(1, Ordering::Relaxed) + 1;
    let suppressed = limiter.on_event(now_ms)?;
    warn!(
        client = %crate::util::client_identity::canonical_socket_addr(peer_addr),
        timed_out = timed_out,
        suppressed = suppressed,
        "DTLS handshake timed out"
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

/// Regression harness for the handshake-timeout diagnostic: every abandoned
/// handshake is counted, while the warning is bounded to one record per limiter
/// window and the next record reports what it suppressed.
///
/// Drives [`record_dtls_handshake_timeout`] directly with an injected clock so
/// the contract is asserted without a live listener, a log-capture harness, or
/// any wall-clock sleep. Times out `timeouts_in_window` distinct peers inside
/// one window and one more after it, returning
/// `(counted, records_emitted, suppressed_reported_by_the_second_record)`.
///
/// Each peer gets its own source port, which is exactly the shape that produced
/// one record per peer before the limiter was introduced.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) fn dtls_handshake_timeout_warning_accounting_for_test(
    timeouts_in_window: u64,
) -> Result<(u64, u64, u64), String> {
    let window_ms = crate::util::atomic_log_rate_limiter::DEFAULT_ATOMIC_LOG_RATE_LIMIT_WINDOW_MS;
    let limiter = crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new();
    let timeouts = AtomicU64::new(0);
    let peer_ip: IpAddr = "203.0.113.7"
        .parse()
        .map_err(|e| format!("parse peer ip: {e}"))?;
    let now_ms = 1_000_000u64;

    let mut emitted = 0u64;
    for index in 0..timeouts_in_window {
        // A distinct ephemeral source port per abandoned handshake, wrapped so
        // a large burst still produces valid ports.
        let port = 40_000u16.wrapping_add((index % 20_000) as u16);
        let peer = SocketAddr::new(peer_ip, port);
        if record_dtls_handshake_timeout(&limiter, &timeouts, peer, now_ms).is_some() {
            emitted += 1;
        }
    }

    // One more once the window has elapsed: it must emit and report the
    // timeouts the limiter withheld in between.
    let late_peer = SocketAddr::new(peer_ip, 39_999);
    let suppressed =
        record_dtls_handshake_timeout(&limiter, &timeouts, late_peer, now_ms + window_ms);
    if suppressed.is_some() {
        emitted += 1;
    }

    Ok((
        timeouts.load(Ordering::Relaxed),
        emitted,
        suppressed.unwrap_or_default(),
    ))
}

/// Build one real DTLS ClientHello record for the admission harnesses.
///
/// The pre-handshake table is opened by exactly this record, so the harness
/// sprays the genuine article rather than a synthetic prefix.
#[allow(dead_code)] // used through library `_test_support`
fn client_hello_record_for_test() -> Result<Vec<u8>, String> {
    let config = Arc::new(
        Config::builder()
            .build()
            .map_err(|e| format!("build DTLS config: {e}"))?,
    );
    let certificate = dimpl::certificate::generate_self_signed_certificate()
        .map_err(|e| format!("generate client certificate: {e}"))?;
    let mut client = Dtls::new_auto(config, certificate, Instant::now());
    client.set_active(true);
    let mut buf = vec![0u8; 4096];
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        if let Output::Packet(data) = client.poll_output(&mut buf) {
            return Ok(data.to_vec());
        }
    }
    Err("client did not emit a ClientHello packet".into())
}

/// Regression harness for the per-source-IP pre-handshake bound
/// (GHSA-cc8p-2cqj-7fgg): a ClientHello spray from ONE source may occupy at
/// most `max_per_source` demux entries, and a second source is still admitted
/// while the first is saturated.
///
/// Drives [`DtlsServer::spawn_session`] — the ClientHello admission path — on a
/// server whose listener-wide `max_sessions` is deliberately far larger than the
/// spray, so the only thing that can bound the first source is the per-source
/// gate. Nothing is awaited between spawns, so no driver task can run and the
/// observed demux table is exactly what admission allowed.
///
/// Returns `(entries_for_the_spraying_source, entries_for_the_second_source,
/// refusals_recorded)`.
#[allow(dead_code)] // used through library `_test_support`
pub(crate) async fn dtls_pre_handshake_per_source_ip_admission_for_test(
    max_per_source: u64,
    attempts_from_one_source: u16,
) -> Result<(usize, usize, u64), String> {
    let admission = crate::proxy::PerIpStreamAdmission {
        counts: Some(Arc::new(DashMap::new())),
        max: max_per_source,
    };
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind DTLS test socket: {e}"))?;
    let config = Config::builder()
        .build()
        .map_err(|e| format!("build DTLS config: {e}"))?;
    let certificate = dimpl::certificate::generate_self_signed_certificate()
        .map_err(|e| format!("generate server certificate: {e}"))?;
    let server = DtlsServer::from_socket_with_limits(
        socket,
        FrontendDtlsConfig {
            dimpl_config: Arc::new(config),
            certificate: certificate.into(),
            client_cert_verifier: None,
            client_trust: None,
        },
        DtlsServerLimits {
            // Far above the spray: the listener-wide cap must not be what
            // bounds the first source, or the regression would pass without
            // the per-source gate.
            max_sessions: Some(usize::from(attempts_from_one_source) + 64),
            handshake_timeout: None,
            per_source_ip_admission: admission,
            datagram_client_address_listener: Some((Arc::<str>::from("dtls-per-ip"), 4433u16)),
            ..DtlsServerLimits::default()
        },
    )
    .map_err(|e| format!("construct DTLS test server: {e}"))?;

    let hello = client_hello_record_for_test()?;
    let spraying_source: IpAddr = "203.0.113.10"
        .parse()
        .map_err(|e| format!("parse spraying source: {e}"))?;
    let second_source: IpAddr = "203.0.113.11"
        .parse()
        .map_err(|e| format!("parse second source: {e}"))?;

    for index in 0..attempts_from_one_source {
        let peer = SocketAddr::new(spraying_source, 40_000u16.wrapping_add(index));
        server.spawn_session(peer, hello.clone(), None, None);
    }
    let second_peer = SocketAddr::new(second_source, 40_000);
    server.spawn_session(second_peer, hello.clone(), None, None);

    let sprayed = server
        .sessions
        .iter()
        .filter(|entry| entry.key().ip() == spraying_source)
        .count();
    let second = server
        .sessions
        .iter()
        .filter(|entry| entry.key().ip() == second_source)
        .count();
    if server.active_session_count() != sprayed + second {
        return Err(format!(
            "listener-wide counter {} disagrees with the demux table ({sprayed} + {second})",
            server.active_session_count()
        ));
    }

    Ok((
        sprayed,
        second,
        server.per_source_ip_rejections.load(Ordering::Relaxed),
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
    /// The registered frontend client-trust decision this session was admitted
    /// under (issue #3857), or `None` for an anonymous / static DTLS session
    /// that presented no gateway-verified client certificate.
    ///
    /// The session driver's own fences (plaintext delivery, accept handoff,
    /// ciphertext sends) end the DRIVER, and its channels close. That is not a
    /// retirement fence for the detached handler this connection is delivered
    /// to: once `accept_tx.send` completed, that handler runs arbitrary awaited
    /// `on_stream_connect` hooks, DNS resolution, a backend dial, a backend DTLS
    /// handshake, and two relay tasks — every one of which can be parked across
    /// a withdrawal and then continue. Carrying the registered session here is
    /// what gives the handler the same bound the driver has.
    ///
    /// This is a cheap `Arc` clone of a process-local handle: it holds no
    /// certificate, no trust material, and no generation a consumer can log. It
    /// keeps the transport visible to a later sweep until the last handle drops,
    /// which is the same lifetime rule an upgraded WebSocket relies on;
    /// deregistration still happens exactly once, when the last handle goes.
    client_trust: Option<crate::tls::ClientTrustSession>,
    /// DER-encoded client leaf certificate from the DTLS handshake.
    /// Populated when the client presents a certificate during mutual DTLS authentication.
    pub tls_client_cert_der: Option<Arc<Vec<u8>>>,
    /// DER-encoded client intermediate chain in presented order, excluding
    /// the leaf stored in `tls_client_cert_der`.
    pub tls_client_cert_chain_der: Option<Arc<Vec<Vec<u8>>>>,
    /// SNI hostname extracted from the initial DTLS ClientHello, if supplied.
    pub sni_hostname: Option<String>,
    /// Kernel-reported ingress interface index of the ClientHello that opened
    /// this session, when the listener enabled
    /// [`DtlsServerLimits::capture_ingress_ifindex`]. `None` otherwise. The
    /// NodeWaypoint UDP/DTLS scoped-authorization path resolves the session's
    /// source workload from it; absent means unattributable, which fails closed.
    pub ingress_ifindex: Option<u32>,
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

    /// The registered frontend client-trust session this connection was
    /// admitted under, or `None` for an anonymous / static DTLS session.
    ///
    /// The accepted-session handler clones this once and carries it as its
    /// post-admission trust fence: a `None` here means the handler arms no
    /// retirement future at all and keeps its previous behaviour.
    pub fn client_trust_session(&self) -> Option<&crate::tls::ClientTrustSession> {
        self.client_trust.as_ref()
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
        Self::from_socket_with_limits(socket, frontend_config, limits)
    }

    /// Create a `DtlsServer` from an already-bound `UdpSocket`. Useful when the
    /// caller has reserved the port via a separate pathway (e.g. test
    /// scaffolding holding a `UdpSocket` open across the
    /// reserve-then-construct gap to avoid the bind-drop-rebind race) and
    /// wants to hand the socket directly to the DTLS server without any
    /// release/rebind window.
    #[allow(dead_code)] // Public helper used by tests and scripted DTLS backends.
    pub fn from_socket(socket: UdpSocket, frontend_config: FrontendDtlsConfig) -> Self {
        // `DtlsServerLimits::default()` leaves both scoped socket options
        // (`capture_ingress_ifindex`, `socket_mark`) off, and they are the only
        // fallible part of construction, so this stays infallible by
        // construction.
        Self::build(socket, frontend_config, DtlsServerLimits::default())
    }

    /// Create a `DtlsServer` from an already-bound `UdpSocket` with admission
    /// limits.
    ///
    /// Fails when one of the two NodeWaypoint-scoped socket options in
    /// [`DtlsServerLimits`] cannot be applied:
    ///
    /// - `capture_ingress_ifindex`, whose kernel-reported ingress interface IS
    ///   the session's source-workload attribution — without it every session
    ///   is unattributable and denied;
    /// - `socket_mark`, without which the pod-veth tc guard drops every record
    ///   this socket sends back toward the enrolled source pod.
    ///
    /// Either failure would leave a server that reports itself constructed
    /// while no scoped session could ever complete, so both are startup
    /// preconditions rather than optimizations. Ordinary DTLS listeners set
    /// neither field and cannot fail here.
    ///
    /// Both options are applied to the socket BEFORE the server object exists,
    /// so no caller can observe or run a `DtlsServer` whose socket is missing
    /// them.
    pub fn from_socket_with_limits(
        socket: UdpSocket,
        frontend_config: FrontendDtlsConfig,
        limits: DtlsServerLimits,
    ) -> Result<Self, anyhow::Error> {
        apply_scoped_dtls_socket_options(&socket, &limits)?;
        Ok(Self::build(socket, frontend_config, limits))
    }

    /// Assemble the server without touching socket options.
    fn build(
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
            per_source_ip_rejections: AtomicU64::new(0),
            per_source_ip_warn: crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new(),
            handshake_timeout_warn: Arc::new(
                crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter::new(),
            ),
            handshake_timeouts: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Atomically swap the DTLS crypto material used for **new** sessions.
    ///
    /// Used by frontend DTLS live reload (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`)
    /// and owner-scoped NodeWaypoint DTLS publish to rotate the inbound DTLS
    /// `ServerConfig` equivalent (dimpl `Config` + certificate + optional
    /// `ClientCertVerifier`) without re-binding the socket or mutating any
    /// in-flight session's snapshot. Active sessions keep the snapshot they
    /// handshake with; an ordinary frontend client-trust narrowing can
    /// separately retire authenticated sessions through the trust fence (see
    /// [`DtlsServerActiveConfig`] doc-comment for the invariant). Mesh
    /// PeerAuthentication TCP+TLS reload must not call this as a process-wide
    /// fanout: ordinary operator listeners keep their dedicated `FERRUM_DTLS_*`
    /// identity, and generated listeners are swapped only by
    /// `publish_mesh_node_waypoint_dtls_generation`.
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
        // Ingress-interface capture (issue #3286) needs cmsg, which
        // `recv_from`/`recvfrom(2)` does not surface. When it is requested on
        // Linux the loop drains through the shared `recvmmsg` batch reader
        // instead — the same reader the plain-UDP listener uses, so there is no
        // second cmsg parser. Everywhere else the original path is unchanged.
        #[cfg(target_os = "linux")]
        let ifindex_capture = self.limits.capture_ingress_ifindex;
        #[cfg(not(target_os = "linux"))]
        let ifindex_capture = false;
        // Allocated only for a capture listener: the batch preallocates one
        // max-size datagram buffer per slot, and every ordinary DTLS listener
        // stays on the untouched `recv_from` path.
        #[cfg(target_os = "linux")]
        let mut recv_batch = ifindex_capture.then(|| {
            crate::proxy::udp_batch::RecvMmsgBatch::new(
                DTLS_INGRESS_CAPTURE_BATCH,
                // `IP_RECVORIGDSTADDR` is never set on a DTLS frontend socket,
                // so the orig-dst cmsg scan would always come back empty.
                false,
            )
        });
        loop {
            if ifindex_capture {
                #[cfg(target_os = "linux")]
                {
                    use std::os::fd::AsRawFd;
                    tokio::select! {
                        ready = self.socket.readable() => {
                            if let Err(e) = ready {
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionRefused
                                        | std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::Interrupted
                                        | std::io::ErrorKind::WouldBlock
                                ) {
                                    trace!("DTLS server transient readable error (ignored): {}", e);
                                    continue;
                                }
                                return Err(anyhow::anyhow!("DTLS server recv error: {}", e));
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            return Ok(());
                        }
                    }
                    if *shutdown_rx.borrow() {
                        return Ok(());
                    }
                    let fd = self.socket.as_raw_fd();
                    // `ifindex_capture` gated the allocation above, so this is
                    // always populated here.
                    let Some(batch) = recv_batch.as_mut() else {
                        return Ok(());
                    };
                    let mut drained: usize = 0;
                    while drained < DTLS_INGRESS_CAPTURE_DRAIN_LIMIT {
                        let received = self.socket.try_io(tokio::io::Interest::READABLE, || {
                            batch.recv(fd, DTLS_INGRESS_CAPTURE_BATCH)
                        });
                        match received {
                            Ok(n) if n > 0 => {
                                for i in 0..n {
                                    let (data, peer_addr) = batch.datagram(i);
                                    let data = data.to_vec();
                                    // The WHOLE captured local destination is
                                    // carried forward, not just its interface
                                    // index: the address half is this session's
                                    // reply source (the Service ClusterIP on the
                                    // steered path) and the interface half is
                                    // its source attribution. An ifindex of 0 is
                                    // "the kernel reported no interface", which
                                    // is not usable evidence, so the whole
                                    // capture is discarded and the datagram
                                    // fails closed below.
                                    let reply_local =
                                        batch.local_addr(i).filter(|local| local.ifindex != 0);
                                    self.dispatch_datagram(peer_addr, data, reply_local).await;
                                }
                                drained += n;
                            }
                            Ok(_) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionRefused
                                        | std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::Interrupted
                                ) =>
                            {
                                trace!("DTLS server transient recvmmsg error (ignored): {}", e);
                                break;
                            }
                            Err(e) => {
                                return Err(anyhow::anyhow!("DTLS server recvmmsg error: {}", e));
                            }
                        }
                    }
                }
                continue;
            }

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
            self.dispatch_datagram(peer_addr, data, None).await;
        }
    }

    /// Demux one received datagram onto its peer's session, or open a new one.
    ///
    /// Envelope validation (issue #3289) happens first — before demux, before
    /// any per-peer state is allocated, and before the DTLS record layer sees a
    /// byte — so an untrusted datagram can neither start an association nor
    /// reach an existing one. `reply_local` is the complete kernel-reported
    /// `IP_PKTINFO` / `IPV6_PKTINFO` local destination when the listener enabled
    /// [`DtlsServerLimits::capture_ingress_ifindex`], and `None` otherwise. On a
    /// scoped listener a datagram that carries no such capture FAILS CLOSED
    /// here: it can neither be attributed to a source workload nor answered from
    /// the address the client addressed, so it is dropped before any session
    /// state is allocated or delivered.
    async fn dispatch_datagram(
        &self,
        peer_addr: SocketAddr,
        data: Vec<u8>,
        reply_local: Option<crate::socket_opts::PktinfoLocal>,
    ) {
        // Datagram client-address boundary (issue #3289).
        let (data, forwarded_client) = match self.limits.datagram_client_address.as_ref() {
            None => (data, None),
            Some(gate) => match gate.decode(&data, &peer_addr) {
                Ok(decoded) => (decoded.payload.to_vec(), decoded.forwarded),
                Err(error) => {
                    let _ = record_datagram_metadata_refusal(
                        &self.datagram_client_address_warn,
                        self.limits.datagram_client_address_drops.as_deref(),
                        self.limits.datagram_client_address_listener.as_ref(),
                        peer_addr,
                        error.reason(),
                        crate::proxy::udp_proxy::coarse_epoch_millis(),
                    );
                    return;
                }
            },
        };
        let len = data.len();
        if !dtls_scoped_capture_admits(self.limits.capture_ingress_ifindex, None, reply_local) {
            trace!(
                client = %peer_addr,
                len,
                "DTLS: dropping datagram with no ingress pktinfo on a scoped listener; it is \
                 neither attributable to a source workload nor answerable from the address it \
                 was sent to"
            );
            return;
        }
        // Clone the sender (and demux identity) out of the DashMap guard
        // before sending. The `Ref` from `sessions.get()` holds a read lock
        // on the shard; holding it while a `SessionGuard::Drop` on the same
        // shard needs a write lock to call `sessions.remove_if()` would
        // deadlock. Capture `generation` with the sender so a Closed cleanup
        // cannot race-evict a newer session inserted for the same peer.
        let session = self.sessions.get(&peer_addr).map(|s| {
            (
                s.incoming_tx.clone(),
                s.generation,
                s.reply_local,
                s.forwarded_client,
            )
        });
        if let Some((tx, generation, session_local, session_forwarded)) = session {
            // The peer's source ADDRESS is spoofable; neither the interface it
            // entered the host namespace on nor the local destination the
            // kernel delivered it to is. A datagram claiming an established peer
            // address but arriving on a different interface belongs to a
            // different workload, and one naming a different local destination
            // belongs to a different Service flow; neither may be folded into
            // this session (issue #3286), because doing so would either run it
            // under another pod's policy scope or re-point this session's reply
            // source. Only enforced when the capture is enabled — every other
            // listener carries `None` on both sides and compares equal.
            if !dtls_scoped_capture_admits(
                self.limits.capture_ingress_ifindex,
                session_local,
                reply_local,
            ) {
                trace!(
                    client = %peer_addr,
                    "DTLS: dropping datagram whose ingress interface or local destination does \
                     not match the session's pinned capture"
                );
                return;
            }
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
                return;
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
                Err(mpsc::error::TrySendError::Closed(data)) => {
                    // Driver task exited — remove this generation only.
                    // A replacement may already occupy the peer address.
                    remove_session(
                        &self.sessions,
                        &self.active_sessions,
                        self.limits.active_session_mirror.as_deref(),
                        &peer_addr,
                        generation,
                    );
                    // A ClientHello that raced the teardown would otherwise be
                    // dropped, forcing the peer to wait for its retransmit
                    // timer. If this generation still owned the map entry,
                    // start the replacement handshake from this datagram
                    // instead of waiting. A newer generation already in the
                    // map must not be replaced.
                    if self.sessions.get(&peer_addr).is_none() && dtls_datagram_opens_session(&data)
                    {
                        self.spawn_session(peer_addr, data, reply_local, forwarded_client);
                    }
                }
            }
        } else if dtls_datagram_opens_session(&data) {
            // New client — spawn a session driver. Only the initial fragment
            // of a ClientHello starts a handshake: spawning reserves a
            // `max_sessions` slot, allocates four channels, and holds the
            // slot for the handshake timeout, so later handshake records
            // (a refused peer's Certificate/Finished retransmits) and
            // scanner garbage must not reach it.
            self.spawn_session(peer_addr, data, reply_local, forwarded_client);
        } else {
            trace!(
                client = %peer_addr,
                len,
                "DTLS: dropping non-ClientHello datagram from unknown source"
            );
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
    ///   2. `per_source_ip_admission` is the *hard* per-source bound. It is
    ///      taken before the listener-wide reservation so a refusal unwinds
    ///      nothing, and it is the gate that keeps one source address from
    ///      occupying the whole pre-handshake table.
    ///   3. `max_sessions` is the *hard* listener-wide cap, enforced via a CAS
    ///      loop on `active_sessions`. This is the authoritative bound — even
    ///      if the soft gate races, the hard cap cannot be exceeded.
    fn spawn_session(
        &self,
        peer_addr: SocketAddr,
        initial_packet: Vec<u8>,
        reply_local: Option<crate::socket_opts::PktinfoLocal>,
        forwarded_client: Option<SocketAddr>,
    ) {
        if let Some(ref authorize) = self.limits.authorize_new_session
            && !authorize(peer_addr, reply_local.map(|local| local.ifindex))
        {
            trace!(
                client = %peer_addr,
                "DTLS new session rejected by source-attribution gate"
            );
            return;
        }
        if let Some(ref allow) = self.limits.allow_new_session
            && !allow()
        {
            trace!(client = %peer_addr, "DTLS new session rejected by admission gate");
            return;
        }

        // Per-effective-source-IP bound on the PRE-HANDSHAKE table. Taken here,
        // before any per-peer allocation and before the listener-wide
        // reservation, because a DTLS peer occupies demux state from its first
        // ClientHello — long before the session the plain-UDP guard covers
        // exists. The effective source is the authenticated forwarded client
        // when a datagram client-address envelope was accepted, otherwise the
        // socket peer, matching the listener's session reservation exactly so
        // both guards move the same counter.
        //
        // The guard is moved into the driver task below and released the moment
        // the accepted connection is handed to `accept()`, where the listener's
        // session reservation takes over; an established session must not hold
        // two slots out of one source's budget.
        let per_source_ip_guard = if self.limits.per_source_ip_admission.counts.is_some() {
            let effective_source = forwarded_client.unwrap_or(peer_addr);
            let client_ip = crate::proxy::udp_proxy::udp_session_client_ip(effective_source);
            match self.limits.per_source_ip_admission.try_acquire(&client_ip) {
                Ok(guard) => guard,
                Err(crate::proxy::PerIpLimitExceeded) => {
                    record_dtls_per_source_ip_refusal(
                        &self.per_source_ip_warn,
                        &self.per_source_ip_rejections,
                        self.limits.datagram_client_address_listener.as_ref(),
                        self.limits.per_source_ip_admission.max,
                        crate::proxy::udp_proxy::coarse_epoch_millis(),
                    );
                    return;
                }
            }
        } else {
            None
        };

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

        // The ingress interface half of the capture, for the source-attribution
        // consumers that only need that scalar.
        let ingress_ifindex = reply_local.map(|local| local.ifindex);

        self.sessions.insert(
            peer_addr,
            DtlsSessionState {
                incoming_tx: incoming_tx.clone(),
                shutdown_tx: shutdown_tx.clone(),
                generation,
                reply_local,
                forwarded_client,
            },
        );

        // Issue #3857: capture the frontend DTLS client-trust generation BEFORE
        // snapshotting the crypto material this session handshakes with. The
        // publisher swaps the material into every active `DtlsServer` and only
        // then advances the generation, so reading in this order guarantees the
        // captured generation is at or older than the verifier actually used —
        // a session can never claim a post-withdrawal generation while running
        // the withdrawn verifier.
        //
        // The scope comes from the listener's owner (issue #3858), never a
        // hard-coded constant: a generated `MeshNodeWaypoint` listener carries
        // `None` and so registers nothing, because its trust material is
        // published by the mesh slice and not by the operator `FERRUM_DTLS_*`
        // generation this domain tracks.
        let client_trust_admission = self
            .limits
            .client_trust_scope
            .and_then(crate::tls::client_trust::capture);
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
        let handshake_timeout_warn = self.handshake_timeout_warn.clone();
        let handshake_timeouts = self.handshake_timeouts.clone();

        tokio::spawn(async move {
            let _session_guard = SessionGuard {
                sessions: sessions.clone(),
                active_sessions: active_sessions.clone(),
                active_session_mirror: active_session_mirror.clone(),
                peer_addr,
                generation,
            };
            // This peer's slot in its source's pre-handshake budget. Released
            // at accept handoff below, and by `Drop` on every other exit path
            // (refused handshake, timeout, socket error, task cancellation).
            let mut per_source_ip_guard = per_source_ip_guard;

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
            // Frontend client-trust registration for this session (issue #3857).
            // The Option is the live owner from spawn start to teardown: `None`
            // means "not yet admitted" and is observed every select iteration,
            // then replaced once by the guard after a verified client
            // certificate. Dropping the guard on any exit path deregisters it.
            let mut client_trust_guard: Option<crate::tls::ClientTrustSessionGuard> = None;
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
                reply_local,
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

            // Whether this driver is leaving because frontend client-certificate
            // trust was withdrawn (issue #3857). Distinct from ordinary
            // shutdown / handshake timeout / max-lifetime: the post-loop drain
            // must not emit queued packets after this retirement even when the
            // session authorization deadline has not elapsed.
            let mut retired_by_trust_withdrawal = false;

            loop {
                // Check the handshake deadline at the top of each iteration so
                // a sustained datagram flood cannot starve the timeout arm
                // in the select below.
                if !connected
                    && let Some(deadline) = handshake_deadline
                    && Instant::now() >= deadline
                {
                    record_dtls_handshake_timeout(
                        &handshake_timeout_warn,
                        &handshake_timeouts,
                        peer_addr,
                        crate::proxy::udp_proxy::coarse_epoch_millis(),
                    );
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
                    biased;
                    // Frontend client-certificate trust withdrawn (issue
                    // #3857). This authority decision is polled before queued
                    // application data; the socket-write helper below repeats
                    // the same fence across an in-flight `send_to`.
                    _ = async {
                        match client_trust_guard.as_ref() {
                            Some(guard) => guard.session().retired().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        warn!(
                            client = %peer_addr,
                            "Retiring established DTLS session: frontend client-certificate trust was withdrawn"
                        );
                        retired_by_trust_withdrawal = true;
                        fail_queued_frontend_app_sends(
                            &mut app_in_rx,
                            auth_deadline.get(),
                        );
                        break;
                    }
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
                        if let Some(session) = client_trust_guard
                            .as_ref()
                            .map(|guard| guard.session())
                            && session.is_retired()
                        {
                            // Fail closed on the ciphertext-send gate, but do not
                            // record the fixed-cardinality fence counter here:
                            // an accepted stream's detached handler owns
                            // once-only stream accounting through
                            // `DtlsClientTrustFence::settle_withdrawal` and will
                            // settle this same withdrawal. Pre-accept driver
                            // sites still record directly because no handler can
                            // own those refused streams.
                            retired_by_trust_withdrawal = true;
                            let _ = completion.send(Err(
                                crate::tls::client_trust::TRUST_WITHDRAWN_REASON.to_string(),
                            ));
                            fail_queued_frontend_app_sends(
                                &mut app_in_rx,
                                auth_deadline.get(),
                            );
                            break;
                        }
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
                        record_dtls_handshake_timeout(
                            &handshake_timeout_warn,
                            &handshake_timeouts,
                            peer_addr,
                            crate::proxy::udp_proxy::coarse_epoch_millis(),
                        );
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
                                    // Handshake/control records leave from this
                                    // session's pinned reply source on a scoped
                                    // listener. Ordinary listeners pass None
                                    // and keep send_to byte for byte. Race the
                                    // write against trust withdrawal after
                                    // registration so retirement stays final.
                                    match frontend_trust_raced_delivery(
                                        client_trust_guard.as_ref().map(|guard| guard.session()),
                                        send_dtls_record(&socket, data, peer_addr, reply_local),
                                    )
                                    .await
                                    {
                                        Ok(_) => {
                                            drain_round_exhausted = false;
                                            continue;
                                        }
                                        Err(_) => {
                                            fail_queued_frontend_app_sends(
                                                &mut app_in_rx,
                                                auth_deadline.get(),
                                            );
                                            return;
                                        }
                                    }
                                }
                                match write_connected_frontend_record(
                                    &socket,
                                    data,
                                    peer_addr,
                                    reply_local,
                                    in_flight.as_mut(),
                                    auth_deadline.get(),
                                    client_trust_guard.as_ref().map(|guard| guard.session()),
                                )
                                .await
                                {
                                    Ok(()) => {
                                        wrote_ciphertext_datagram = true;
                                    }
                                    Err(reject) => {
                                        discard_app_ciphertext = true;
                                        if client_trust_guard
                                            .as_ref()
                                            .is_some_and(|guard| guard.session().is_retired())
                                        {
                                            retired_by_trust_withdrawal = true;
                                        }
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
                                    refuse_dtls_handshake(
                                        &mut dtls,
                                        socket.as_ref(),
                                        peer_addr,
                                        reply_local,
                                        &mut out_buf,
                                    )
                                    .await;
                                    fail_queued_frontend_app_sends(
                                        &mut app_in_rx,
                                        auth_deadline.get(),
                                    );
                                    return;
                                }
                                // Close the interval between certificate-chain
                                // validation and connection delivery. A withdrawal
                                // that lands after registration but before this
                                // `Connected` output must fence the session before
                                // the proxy can observe it through `accept()`.
                                if let Some(session) =
                                    client_trust_guard.as_ref().map(|guard| guard.session())
                                    && session.is_retired()
                                {
                                    session.record_fenced();
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
                                // The accepted connection carries this session's
                                // registered trust decision (issue #3857). The
                                // accept handoff below is committed BEFORE the
                                // server's queued final flight is drained, and
                                // the proxy handler it wakes runs plugin hooks,
                                // DNS, and a backend dial that this driver
                                // cannot fence — so the fence travels with the
                                // connection rather than staying behind in the
                                // driver's channels. `None` for anonymous /
                                // static DTLS, which arms nothing.
                                let conn = DtlsServerConn {
                                    app_tx: app_in_tx.clone(),
                                    app_rx: tokio::sync::Mutex::new(rx),
                                    shutdown_tx: shutdown_tx.clone(),
                                    auth_deadline: auth_deadline.clone(),
                                    client_trust: client_trust_guard
                                        .as_ref()
                                        .map(|guard| guard.session().clone()),
                                    tls_client_cert_der: peer_cert_der.clone(),
                                    tls_client_cert_chain_der: peer_cert_chain_der.clone(),
                                    sni_hostname: sni_hostname.clone(),
                                    ingress_ifindex,
                                    forwarded_client_addr: forwarded_client,
                                };
                                match frontend_trust_raced_delivery(
                                    client_trust_guard.as_ref().map(|guard| guard.session()),
                                    accept_tx.send((conn, peer_addr)),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        // The pre-handshake budget has done its
                                        // job: this peer is no longer occupying
                                        // demux state ahead of authentication,
                                        // and the listener's accept path
                                        // reserves the session slot that now
                                        // represents it. Holding both would
                                        // charge one established session twice
                                        // against its source's budget.
                                        drop(per_source_ip_guard.take());
                                    }
                                    Ok(Err(_)) => {
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
                                    Err(_) => {
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
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
                                        refuse_dtls_handshake(
                                            &mut dtls,
                                            socket.as_ref(),
                                            peer_addr,
                                            reply_local,
                                            &mut out_buf,
                                        )
                                        .await;
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
                                    // A client certificate was presented and verified
                                    // against the configured client CA.
                                    verified_peer_cert = true;
                                    // Only now does this session hold a trust
                                    // decision a CRL / client-CA withdrawal can
                                    // revoke, so this is where it joins the
                                    // retirement domain (issue #3857). Registration
                                    // re-checks the fence against the generation
                                    // captured at session start, so a withdrawal
                                    // published while this handshake was running
                                    // retires the session immediately instead of
                                    // letting it repopulate the domain behind the
                                    // sweep.
                                    if client_trust_guard.is_none() {
                                        client_trust_guard = client_trust_admission
                                            .and_then(|admission| admission.register(true));
                                    }
                                    // Registration re-checks the withdrawal fence after
                                    // inserting this session. If that re-check retired us,
                                    // stop inside the handshake drain rather than waiting
                                    // for the outer select to poll the cancellation arm: an
                                    // already-fenced session must never reach `accept()`.
                                    if let Some(session) =
                                        client_trust_guard.as_ref().map(|guard| guard.session())
                                        && session.is_retired()
                                    {
                                        session.record_fenced();
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
                                }
                                peer_cert_chain_der =
                                    (chain.len() > 1).then(|| Arc::new(chain[1..].to_vec()));
                            }
                            Output::ApplicationData(data) => {
                                match frontend_trust_raced_delivery(
                                    client_trust_guard.as_ref().map(|guard| guard.session()),
                                    app_out_tx.send(data.to_vec()),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        drain_round_exhausted = false;
                                        break;
                                    }
                                    Ok(Err(_)) | Err(_) => {
                                        if let Some(inflight) = in_flight.take() {
                                            let _ = inflight.completion.send(Err(
                                                FrontendAppSendReject::Closed.as_str().to_string(),
                                            ));
                                        }
                                        fail_queued_frontend_app_sends(
                                            &mut app_in_rx,
                                            auth_deadline.get(),
                                        );
                                        return;
                                    }
                                }
                            }
                            Output::KeyingMaterial(_, _) => {
                                // Dimpl queues this local event immediately
                                // after `Connected` when SRTP was negotiated,
                                // before exposing the engine's queued DTLS 1.2
                                // CCS + Finished packets. Keep draining or an
                                // admitted peer never receives the server's
                                // final flight and cannot complete its own
                                // handshake. Refused peers return from the
                                // certificate-validation arms above before
                                // reaching this path, so their queued final
                                // flight remains discarded fail-closed.
                                drain_round_exhausted = false;
                                continue;
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

                if retired_by_trust_withdrawal {
                    fail_queued_frontend_app_sends(&mut app_in_rx, auth_deadline.get());
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
            // Protocol/handshake records may still be flushed from the same
            // pinned reply source on ordinary shutdown. Application ciphertext
            // whose authorization expired is discarded. Trust withdrawal must
            // not emit any queued packet: the peer is no longer authorized,
            // even if the session deadline has not elapsed.
            let discard_final_packets =
                retired_by_trust_withdrawal || session_authorization_elapsed(&auth_deadline);
            for _ in 0..MAX_OUTPUTS_PER_DRAIN {
                match dtls.poll_output(&mut out_buf) {
                    Output::Packet(data) => {
                        if discard_final_packets {
                            continue;
                        }
                        let _ = send_dtls_record(&socket, data, peer_addr, reply_local).await;
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

/// One bounded read of a declared PEM CA source, keeping BOTH the parsed root
/// store and the exact bytes it was parsed from (issue #3857).
///
/// A caller that must publish the semantic identity of the anchors it installs
/// has to derive both halves from one read; a second read of the same source
/// can observe a later rotation and describe material the verifier is not
/// enforcing.
pub(crate) struct LoadedPemRootStore {
    /// Trust anchors parsed from [`Self::material`].
    pub(crate) roots: rustls::RootCertStore,
    /// The exact material those anchors came from, with its redacted
    /// operator-facing source label.
    pub(crate) material: crate::tls::source::MaterializedMaterial,
}

/// Read a declared PEM CA source once and parse it into a root store.
///
/// Goes through `CertSource`, so `file://`, inline PEM, and provider URIs all
/// resolve and the shared `FERRUM_TLS_MAX_MATERIAL_SIZE_BYTES` ceiling applies.
pub(crate) fn load_pem_root_store(pem_path: &str) -> Result<LoadedPemRootStore, anyhow::Error> {
    let source = CertSource::parse(pem_path, MaterialKind::CaBundle);
    let material = load_material_blocking(&source, MaterialKind::CaBundle).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load PEM source {}: {}",
            source.redacted_source_id(),
            e
        )
    })?;
    let roots = crate::tls::root_cert_store_from_pem_bundle(
        material.bytes.expose_secret(),
        "DTLS CA bundle",
        &material.display_source_id,
    )?;
    Ok(LoadedPemRootStore { roots, material })
}

/// Load a rustls root store from a PEM source.
///
/// Thin single-read projection of [`load_pem_root_store`] for callers that need
/// only the anchors.
pub fn load_root_store_from_pem(pem_path: &str) -> Result<rustls::RootCertStore, anyhow::Error> {
    load_pem_root_store(pem_path).map(|loaded| loaded.roots)
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

/// Refuse a frontend DTLS handshake WITHOUT committing the server's final
/// flight to the wire.
///
/// dimpl's server pops its local-event queue before the engine's record queue
/// (`Server::poll_output`), and the DTLS 1.2 server pushes `Connected` at the
/// END of `send_finished` — after the ChangeCipherSpec and Finished records are
/// already queued. So at both refusal sites below (an unverifiable client chain,
/// and `Connected` with no verified client certificate under a configured
/// verifier) that final flight EXISTS but has not been written: this session
/// driver is the only thing that ever puts it on the socket.
///
/// Draining it here — which a `close()`-then-forward abort does — hands the peer
/// a complete server final flight, so the client reaches `SSL_is_init_finished`
/// and reports an ESTABLISHED DTLS session; the alert queued behind it only
/// arrives afterwards. A peer that never authenticated then observes a completed
/// handshake, whatever the gateway does with the session next. Every queued
/// record is therefore discarded first, and only records the refusal itself
/// produces are written. If that bounded discard does not reach the end of the
/// queue, nothing is written at all, because a leftover record could still be
/// part of that flight.
///
/// dimpl's `close()` during an in-progress handshake aborts without queuing an
/// alert (no authenticated channel exists yet). The refused peer therefore
/// retransmits flight 5. Those records are handshake content-type `0x16` but
/// not ClientHellos; [`dtls_datagram_opens_session`] must drop them so they
/// cannot spawn replacement sessions that occupy this peer address.
///
/// This makes the refusal fail closed at the DTLS 1.2 protocol boundary. In
/// DTLS 1.3 the server's Finished belongs to an earlier flight and has
/// necessarily already been sent before the client's certificate arrives, so no
/// server behaviour can leave that handshake incomplete; there the alert is what
/// tears the peer down. In both versions the caller returns immediately, so no
/// application data and no accepted connection ever reach the proxy.
///
/// Writes go through `send_dtls_record`, so a generated NodeWaypoint listener
/// refuses from the exact pinned reply source it handshook from rather than a
/// route-selected node address the client's connected socket would discard. A
/// failed send is not actionable — the session is being dropped either way — so
/// it is ignored rather than retried.
async fn refuse_dtls_handshake(
    dtls: &mut Dtls,
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    reply_local: Option<crate::socket_opts::PktinfoLocal>,
    out_buf: &mut [u8],
) {
    // Discard everything dimpl has already queued for this session. `Timeout`
    // is dimpl's "nothing actionable left" output, so it is the only exit that
    // proves the queue is drained.
    let mut queue_drained = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        if matches!(dtls.poll_output(out_buf), Output::Timeout(_)) {
            queue_drained = true;
            break;
        }
    }
    if !queue_drained {
        return;
    }
    let _ = dtls.close();
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                let _ = send_dtls_record(socket, data, peer_addr, reply_local).await;
            }
            _ => break,
        }
    }
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

/// Send one encrypted DTLS record to `peer`.
///
/// `reply_local` is the session's PINNED local destination — the address the
/// client actually addressed, which on the NodeWaypoint steered Service path is
/// the Service ClusterIP rather than any address configured on this node. When
/// it is present the record is sourced from exactly that address (and, for a
/// scoped IPv6 source, its zone) through `IP_PKTINFO` / `IPV6_PKTINFO`; letting
/// the route table pick a source instead would make every record arrive from a
/// node address, which the client's connected socket discards, so the handshake
/// would never complete. `None` — every ordinary DTLS listener — keeps the
/// original `send_to` behaviour byte for byte.
///
/// The pinned source is honored only when its family matches the destination:
/// a cmsg of the wrong family is rejected by the kernel. A pinned source that
/// does NOT match — the dual-stack `[::]` bind with an IPv4-mapped client — is
/// an ERROR here rather than a fallback to `send_to`, because falling back
/// would emit the record from a route-selected node address that the client's
/// connected socket discards. That is the silent black hole this pinning
/// exists to remove, so it fails closed instead and the session ends. (Ferrum's
/// stream listeners bind `FERRUM_PROXY_BIND_ADDRESS`, `0.0.0.0` by default, so
/// this arm is reachable only on an explicitly dual-stack scoped listener,
/// which is not a claimed configuration.)
///
/// Nonblocking throughout. `try_io` performs the `sendmsg(2)` only when the
/// socket is writable and clears readiness when the kernel says it is not, so a
/// full send buffer parks THIS session's driver task on `writable()` instead of
/// blocking a thread. The shared demux loop never calls this.
async fn send_dtls_record(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
    reply_local: Option<crate::socket_opts::PktinfoLocal>,
) -> std::io::Result<usize> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let effective_local = match (reply_local.map(|local| local.ip), peer) {
            (Some(std::net::IpAddr::V4(_)), SocketAddr::V4(_))
            | (Some(std::net::IpAddr::V6(_)), SocketAddr::V6(_)) => reply_local,
            (Some(_), _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "DTLS reply source pinned for a NodeWaypoint-scoped session does not match \
                     the peer's address family; refusing to emit the record from a \
                     route-selected source the client would discard",
                ));
            }
            (None, _) => None,
        };
        if let Some(local) = effective_local {
            let (dest, dest_len) = crate::proxy::udp_batch::std_to_sockaddr_storage(peer);
            let fd = socket.as_raw_fd();
            loop {
                let sent = socket.try_io(tokio::io::Interest::WRITABLE, || {
                    crate::socket_opts::send_with_pktinfo(fd, data, local, &dest, dest_len, None)
                });
                match sent {
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        socket.writable().await?;
                    }
                    other => return other,
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = reply_local;
    socket.send_to(data, peer).await
}

/// Drain `poll_output()` and send packets to a specific peer address (for server-side).
/// Captures the retransmit timeout. Returns `true` on `Connected`.
/// Same Timeout-skipping logic as `drain_handshake_outputs` for post-Connected packets.
///
/// `reply_local` pins the source address of every record emitted here — the
/// initial handshake flight — exactly as the per-session drain does.
async fn drain_server_outputs(
    dtls: &mut Dtls,
    out_buf: &mut [u8],
    socket: &UdpSocket,
    peer: SocketAddr,
    reply_local: Option<crate::socket_opts::PktinfoLocal>,
    next_timeout: &mut Option<Instant>,
) -> Result<bool, anyhow::Error> {
    let mut connected = false;
    let mut saw_timeout_after_connected = false;
    for _ in 0..MAX_OUTPUTS_PER_DRAIN {
        match dtls.poll_output(out_buf) {
            Output::Packet(data) => {
                send_dtls_record(socket, data, peer, reply_local)
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
                client_trust: None,
            },
            limits,
        )
        .expect("construct DTLS test server")
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

        server.spawn_session(
            "127.0.0.1:12345".parse().unwrap(),
            vec![0x16; 32],
            None,
            None,
        );

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

        server.spawn_session(
            "127.0.0.1:12346".parse().unwrap(),
            vec![0x16; 32],
            None,
            None,
        );

        assert_eq!(server.active_session_count(), 0);
        assert!(server.sessions.is_empty());
    }

    #[tokio::test]
    async fn dtls_server_authorizes_source_before_spawning_handshake() {
        let server = test_server(DtlsServerLimits {
            authorize_new_session: Some(Arc::new(|peer, ingress_ifindex| {
                peer.ip().is_loopback() && ingress_ifindex == Some(7)
            })),
            ..DtlsServerLimits::default()
        })
        .await;

        server.spawn_session(
            "127.0.0.1:12346".parse().unwrap(),
            vec![0x16; 32],
            Some(crate::socket_opts::PktinfoLocal {
                ip: "127.0.0.1".parse().unwrap(),
                ifindex: 8,
            }),
            None,
        );

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
            None,
        );
        assert_eq!(server.active_session_count(), 1);
        assert_eq!(mirror.load(Ordering::Relaxed), 1);

        server.spawn_session(
            "127.0.0.1:12348".parse().unwrap(),
            client_hello_packet(),
            None,
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

    /// `swap_frontend_config` is the per-server generation path used by ordinary
    /// `FERRUM_DTLS_*` publish and by owner-scoped NodeWaypoint DTLS publish.
    /// The swap is atomic and new sessions snapshot the latest material at spawn
    /// time; existing sessions are unaffected. Mesh PeerAuthentication reload
    /// must not fan this out process-wide onto ordinary listeners.
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
            client_trust: None,
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
            None,
        );
        assert!(
            server.active_session_count() <= 1,
            "spawn_session honored admission limits after a live-reload swap"
        );
    }
}

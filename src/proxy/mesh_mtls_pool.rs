//! Sidecar-to-sidecar SVID-mTLS HTTP/2 connection pool (Sidecar egress).
//!
//! The Sidecar mesh transport is plain HTTP over mutual TLS to the peer
//! sidecar's inbound listener (`:15006`) — NOT HBONE (HBONE is the
//! Ambient/Waypoint transport on `:15008`; a Sidecar peer has no HBONE
//! listener). This pool owns multiplexed HTTP/2 client connections whose TLS
//! layer presents this gateway's SVID and verifies the peer's server SVID
//! against the mesh trust bundle, PINNED to the destination workload identity
//! from the target's `mesh.spiffe_id` tag. The peer's `auto`-serving frontend
//! terminates mTLS, sniffs the h2 preface (its mesh inbound `ServerConfig`
//! also advertises `h2` at ALPN), and routes the request by `:authority` to
//! its materialized local inbound loopback route.
//!
//! Pool mechanics mirror [`super::hbone_pool::HboneConnectionPool`]: a
//! `DashMap` of per-key sender lists with a shared-lock fast path, coalesced
//! creation, idle pruning, and an SVID-fingerprint + pinned-peer pool key so a
//! rotated SVID or a different pinned identity never reuses an old session.
//! Errors reuse [`HbonePoolError`] — the two pools share every failure shape
//! (DNS, TCP, SPIFFE TLS config, TLS/H2 handshake) except HBONE's CONNECT
//! stream, so the dispatch error mapping stays single-sourced.
//!
//! The pool has two lanes. The HTTP lane pools hyper HTTP/2 senders for
//! HTTP-family egress. The raw-TCP tunnel lane (issue #7537) pools raw-`h2`
//! SVID-mTLS carriers that multiplex captured raw-TCP streams as bare CONNECT
//! streams; it reuses the HBONE pool's carrier entry, least-loaded selection,
//! pruning, keepalive eviction, idle sweeper and dialer rather than adding a
//! third pool, and shares this pool's SVID-rotation, trust and CRL drains.

use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::FutureExt;
use http_body::Frame;
use hyper::client::conn::http2;
use hyper_util::rt::TokioIo;
use std::cell::RefCell;
use std::fmt::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::dns::DnsCache;
use crate::identity::{SharedSvidBundle, SpiffeId, SvidBundle, TrustDomain};
use crate::pool::{SharedCreationRole, SharedCreationSlot};
use crate::proxy::body::{ReplayableRequestBody, SizeLimitedIncoming};
use crate::proxy::mesh_trust_registry::{
    MESH_TRUST_WITHDRAWN_MESSAGE, MeshTransportGate, MeshTransportKind, MeshTransportRegistration,
    MeshTrustRegistry,
};
use crate::tls::backend::BackendSvidGeneration;
use crate::tls::spiffe::build_spiffe_outbound_config;

use super::hbone_pool::{
    H2ConnectTunnel, H2WsConnectTunnel, HboneKeepalivePoolHandle, HbonePoolEntry, HbonePoolError,
    HboneStreamLease, MESH_SPIFFE_ID_TAG, MeshH2Transport, authority_for_host_port,
    connect_multiplex_flow_control, dial_h2_connect_sender, entry_idle_expired, h2_window_sizes,
    matches_boolish_true, open_h2_connect_stream, open_h2_connect_stream_reserved,
    open_h2_ws_connect_stream_within, prune_pool_entries as prune_tunnel_entries,
    select_least_loaded, spawn_idle_entry_sweeper as spawn_tunnel_sweeper, svid_fingerprint,
    target_expected_peer_spiffe, unix_secs, write_pool_config_key,
};

/// Tag marking a target for Sidecar SVID-mTLS dispatch (the peer is a mesh
/// sidecar reached over mutual TLS on its inbound listener). Mutually
/// exclusive with `mesh.hbone` — the materializer emits exactly one per
/// topology.
pub const MESH_MTLS_TARGET_TAG: &str = "mesh.mtls";
/// Tag overriding the peer sidecar's inbound mTLS port. Absent ⇒ Istio's
/// conventional `15006`.
pub const MESH_MTLS_PORT_TAG: &str = "mesh.mtls_port";
/// Istio-convention sidecar inbound mTLS port.
pub const ISTIO_SIDECAR_INBOUND_PORT: u16 = 15006;
/// Tag carrying the OWNING SERVICE port a multi-port Sidecar egress target
/// serves. Stamped at materialization ONLY when the destination service
/// declares more than one HTTP-family port; `proxy_to_backend_mesh_mtls`
/// then rewrites the request `:authority` to `<host>:<service_port>` so the
/// destination sidecar's inbound multi-port disambiguation can pick the
/// right per-port loopback sibling (its `:15006` dials are direct — never
/// NATed — so the authority is the only port channel the source controls).
/// Single-port destinations are never stamped and keep the client authority
/// byte-for-byte.
pub const MESH_MTLS_AUTHORITY_PORT_TAG: &str = "mesh.mtls_authority_port";
/// Tag carrying the destination MESH SERVICE host a Sidecar target's request
/// `:authority` must name. Stamped by `sidecar`-topology mesh service
/// discovery (the gateway-to-mesh bridge) and for carried VirtualService
/// destinations (below): a north-south gateway's client
/// `Host` is typically a public hostname (and without `preserve_host_header`
/// the authority falls back to the pod dial address), neither of which the
/// destination sidecar's materialized inbound routes match — so dispatch
/// forces this service host (`<service>.<namespace>.svc`, one of the
/// destination's registered host variants) as the `:authority` instead. The
/// original client `Host` still rides `x-forwarded-host`. Mesh-mode Sidecar
/// egress stamps it only on the route-scoped upstream clones and split-leg
/// targets carried VirtualService routes dial (issue #7423): such a route does
/// not preserve the client `Host`, and on a split or dispatch branch that
/// `Host` names the VirtualService host rather than the selected Service.
/// The shared Service upstreams are never stamped: plain Service routes are
/// host-routed by the service name, so the client authority is already the
/// routing key the peer matches.
pub const MESH_MTLS_AUTHORITY_HOST_TAG: &str = "mesh.mtls_authority_host";
/// Outer network dial host for a Sidecar cross-cluster L4 tunnel. The target's
/// `host` remains a scoped synthetic workload identity for LB/health maps while
/// this tag carries the remote east-west gateway address. Absent means the
/// normal in-cluster shape where `target.host` is dialed directly.
pub const MESH_MTLS_DIAL_HOST_TAG: &str = "mesh.mtls_dial_host";
/// Tag overriding the ClientHello SNI of a Sidecar mesh-mTLS dial. Value = the
/// DESTINATION service port's east-west alias `p<port>.<fqdn>` (`p<port>-udp`
/// for UDP). Stamped ONLY on cross-cluster east-west targets
/// (see [`MESH_CROSS_CLUSTER_TAG`]): the dial host is the remote east-west
/// gateway address, but the gateway does SNI passthrough and routes the opaque
/// outer TLS to the destination workload by the ClientHello SNI, so the SNI
/// must name the destination service rather than the gateway. Absent ⇒ the SNI
/// is the dial host (the normal in-cluster sidecar path). When a cross-cluster
/// target is missing this tag the dispatch path FAILS CLOSED — it never falls
/// back to the gateway IP as SNI (that would silently break passthrough
/// routing).
pub const MESH_EASTWEST_SNI_TAG: &str = "mesh.eastwest_sni";
/// Tag (`= "true"`) marking a Sidecar mesh-mTLS target as a CROSS-CLUSTER
/// east-west target whose dial host is a remote east-west gateway. The
/// gateway SNI-passes the connection to an LB-picked destination workload the
/// client cannot name, so the dial uses TRUST-DOMAIN-ONLY peer verification
/// (`expected_peer = None`) rather than a pinned pod SPIFFE — the destination
/// SVID must still be in a TRUSTED (federated) trust domain, never unverified.
/// A cross-cluster target therefore carries NO `mesh.spiffe_id` and MUST carry
/// [`MESH_EASTWEST_SNI_TAG`]. The pool key is partitioned so a trust-domain-only
/// / SNI-overridden session never shares a pooled connection with a
/// pinned-peer one.
pub const MESH_CROSS_CLUSTER_TAG: &str = "mesh.cross_cluster";

/// Request representation accepted by the multiplexed sidecar H2 pool.
///
/// * [`Streaming`](MeshMtlsRequestBody::Streaming) — generic HTTP-family
///   requests, retaining the inline size limiter.
/// * [`Replayable`](MeshMtlsRequestBody::Replayable) — retry-enabled requests
///   whose bytes were finalized once before the first attempt.
/// * [`Grpc`](MeshMtlsRequestBody::Grpc) — a gRPC dispatch handing the SHARED
///   [`GrpcBody`](crate::proxy::grpc_proxy::GrpcBody) through unchanged, so the
///   direct-dial gRPC pool and the mesh transport cannot drift on request
///   framing: buffered DATA, buffered DATA plus a terminal TRAILERS frame, a
///   hyper `Incoming`, or the H3 bridge's channel source all keep their inline
///   receive-limit accounting, upload-termination observer, and gRPC message
///   counting when they ride the mesh (issue #3284).
///
/// A manual [`http_body::Body`] impl (rather than nested `Either`s) keeps the
/// arms named at every construction site and boxes each arm's error into the
/// one shared error type hyper needs.
pub enum MeshMtlsRequestBody {
    Streaming(SizeLimitedIncoming),
    Replayable(ReplayableRequestBody),
    Grpc(crate::proxy::grpc_proxy::GrpcBody),
}

impl http_body::Body for MeshMtlsRequestBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            MeshMtlsRequestBody::Streaming(body) => http_body::Body::poll_frame(Pin::new(body), cx),
            // `ReplayableRequestBody` already speaks the shared boxed error:
            // its DATA can now cross a gateway-owned upload pump, whose
            // terminal (`backend_write_timeout_ms`, cancellation) is delivered
            // to the transport as an error rather than a clean end-of-stream.
            MeshMtlsRequestBody::Replayable(body) => {
                http_body::Body::poll_frame(Pin::new(body), cx)
            }
            MeshMtlsRequestBody::Grpc(body) => http_body::Body::poll_frame(Pin::new(body), cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            MeshMtlsRequestBody::Streaming(body) => http_body::Body::is_end_stream(body),
            MeshMtlsRequestBody::Replayable(body) => http_body::Body::is_end_stream(body),
            MeshMtlsRequestBody::Grpc(body) => http_body::Body::is_end_stream(body),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            MeshMtlsRequestBody::Streaming(body) => http_body::Body::size_hint(body),
            MeshMtlsRequestBody::Replayable(body) => http_body::Body::size_hint(body),
            MeshMtlsRequestBody::Grpc(body) => http_body::Body::size_hint(body),
        }
    }
}

/// Readiness or pre-wire send refusal for a pooled mesh-mTLS sender.
///
/// [`TrustWithdrawn`](Self::TrustWithdrawn) is the gated refusal: a checkout
/// or clone that still holds a live hyper sender must not open the next stream
/// after a trust withdrawal, even if the connection driver has not yet dropped
/// the H2 session. [`Hyper`](Self::Hyper) preserves the underlying readiness
/// error for the caller's standard response classification.
#[derive(Debug)]
pub enum MeshMtlsSenderError {
    TrustWithdrawn,
    Hyper(hyper::Error),
}

impl std::fmt::Display for MeshMtlsSenderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustWithdrawn => formatter.write_str(MESH_TRUST_WITHDRAWN_MESSAGE),
            Self::Hyper(err) => write!(formatter, "{err}"),
        }
    }
}

impl std::error::Error for MeshMtlsSenderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TrustWithdrawn => None,
            Self::Hyper(err) => Some(err),
        }
    }
}

/// Multiplexed hyper H2 sender over the SVID-mTLS session, carried together
/// with the retirement gate that owns the transport (issue #3859).
///
/// The gate travels with every clone. [`Self::ready`] and [`Self::send_request`]
/// consult it synchronously at the last pre-wire boundary, so a trust
/// withdrawal refuses the next stream without waiting for the connection
/// driver to drop the H2 session. In-flight streams still terminate through
/// driver/socket teardown.
#[derive(Clone)]
pub struct MeshMtlsSender {
    inner: http2::SendRequest<MeshMtlsRequestBody>,
    gate: MeshTransportGate,
    /// Requests dispatched on this physical connection whose response head has
    /// not arrived yet, shared by every clone of the same transport. This is
    /// the pool's load signal (issue #5043): hyper's H2 `SendRequest::ready()`
    /// is always ready while the connection is open, so it carries no load
    /// information at all.
    pending: Arc<AtomicUsize>,
}

pin_project_lite::pin_project! {
    /// Response-head future that keeps [`MeshMtlsSender::pending_requests`]
    /// accurate: the count drops when the head arrives, when hyper fails the
    /// request, or when the caller abandons the future (deadline, cancellation).
    struct PendingResponse<F> {
        #[pin]
        inner: F,
        pending: Option<Arc<AtomicUsize>>,
    }

    impl<F> PinnedDrop for PendingResponse<F> {
        fn drop(this: Pin<&mut Self>) {
            settle_pending(this.project().pending);
        }
    }
}

fn settle_pending(pending: &mut Option<Arc<AtomicUsize>>) {
    if let Some(pending) = pending.take() {
        pending.fetch_sub(1, Ordering::Relaxed);
    }
}

impl<F: std::future::Future> std::future::Future for PendingResponse<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let output = std::task::ready!(this.inner.poll(cx));
        settle_pending(this.pending);
        Poll::Ready(output)
    }
}

/// Pool-internal name for one established mesh-mTLS HTTP/2 transport. The
/// public checkout type [`MeshMtlsSender`] *is* this handle: the gate is not
/// stripped on the way out of the pool.
pub(crate) type MeshMtlsTransport = MeshMtlsSender;

type BoxedCreateSenderFuture<'a> = Pin<
    Box<dyn std::future::Future<Output = Result<MeshMtlsTransport, HbonePoolError>> + Send + 'a>,
>;

impl std::fmt::Debug for MeshMtlsSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MeshMtlsSender")
            .field("retired", &self.is_retired())
            .finish_non_exhaustive()
    }
}

impl MeshMtlsSender {
    /// Wrap a sender whose gate is never retired. Unix-domain h2c carriers and
    /// focused tests without a trust registry share the same send/ready
    /// surface as mesh-mTLS, so they still consult a gate — it is simply
    /// ungoverned.
    pub fn ungoverned(inner: http2::SendRequest<MeshMtlsRequestBody>) -> Self {
        Self {
            inner,
            gate: MeshTransportGate::new(),
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn governed(
        inner: http2::SendRequest<MeshMtlsRequestBody>,
        gate: MeshTransportGate,
    ) -> Self {
        Self {
            inner,
            gate,
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[inline]
    pub fn is_retired(&self) -> bool {
        self.gate.is_retired()
    }

    /// Requests sent on this physical connection (through any clone) that are
    /// still waiting for their response head. One relaxed load.
    #[inline]
    pub fn pending_requests(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// True when the gate is retired or the underlying H2 client has closed.
    /// Pool lookup/eviction uses this so a withdrawn transport is never handed
    /// out again, even before its socket has finished closing.
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.gate.is_retired() || self.inner.is_closed()
    }

    /// Last-safe pre-wire readiness. A retired gate fails immediately with
    /// [`MeshMtlsSenderError::TrustWithdrawn`] and does not wait for the
    /// driver to close the H2 connection.
    pub async fn ready(&mut self) -> Result<(), MeshMtlsSenderError> {
        if self.gate.is_retired() {
            return Err(MeshMtlsSenderError::TrustWithdrawn);
        }
        self.inner
            .ready()
            .await
            .map_err(MeshMtlsSenderError::Hyper)?;
        if self.gate.is_retired() {
            return Err(MeshMtlsSenderError::TrustWithdrawn);
        }
        Ok(())
    }

    /// Last-safe pre-wire send. A retired gate refuses synchronously —
    /// `Err(TrustWithdrawn)` — before hyper queues a new stream.
    /// [`HbonePoolError::TrustWithdrawn`] classifies as
    /// [`crate::retry::ErrorClass::TrustWithdrawn`], which is both pre-wire
    /// (retryable under the freshly published generation) and backend-health
    /// neutral, so a revocation cannot trip the destination's circuit breaker.
    pub fn send_request(
        &mut self,
        request: http::Request<MeshMtlsRequestBody>,
    ) -> Result<
        impl std::future::Future<Output = Result<hyper::Response<hyper::body::Incoming>, hyper::Error>>
        + use<>,
        HbonePoolError,
    > {
        if self.gate.is_retired() {
            return Err(HbonePoolError::TrustWithdrawn);
        }
        let pending = Arc::clone(&self.pending);
        pending.fetch_add(1, Ordering::Relaxed);
        Ok(PendingResponse {
            inner: self.inner.send_request(request),
            pending: Some(pending),
        })
    }
}

thread_local! {
    static MESH_MTLS_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(192));
}

struct MeshMtlsPoolEntry {
    transport: MeshMtlsTransport,
    /// Unix seconds of the last checkout; atomic so the shared-lock fast path
    /// refreshes recency without the exclusive shard write lock.
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
}

pub fn target_mesh_mtls_enabled(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(MESH_MTLS_TARGET_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

pub fn target_mesh_mtls_port(target: &UpstreamTarget) -> u16 {
    target
        .tags
        .get(MESH_MTLS_PORT_TAG)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(ISTIO_SIDECAR_INBOUND_PORT)
}

/// The owning service port of a multi-port Sidecar egress target, when the
/// materializer stamped one — see [`MESH_MTLS_AUTHORITY_PORT_TAG`]. A corrupt
/// (non-numeric / zero) tag yields `None`, which leaves the authority
/// port-less; the destination's inbound multi-port selection then fails the
/// request closed (502) rather than guessing, so corruption cannot misroute.
pub fn target_mesh_mtls_authority_port(target: &UpstreamTarget) -> Option<u16> {
    target
        .tags
        .get(MESH_MTLS_AUTHORITY_PORT_TAG)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
}

/// The destination mesh SERVICE host a Sidecar target's `:authority` must
/// name, when `sidecar`-topology mesh service discovery stamped one — see
/// [`MESH_MTLS_AUTHORITY_HOST_TAG`]. An empty tag yields `None` (treated as
/// absent rather than producing an unroutable empty authority).
pub fn target_mesh_mtls_authority_host(target: &UpstreamTarget) -> Option<&str> {
    target
        .tags
        .get(MESH_MTLS_AUTHORITY_HOST_TAG)
        .map(String::as_str)
        .filter(|host| !host.is_empty())
}

/// Network host a Sidecar mesh-mTLS tunnel dials. A present-but-empty override
/// is invalid and must fail closed; callers use the target host only when the
/// tag is genuinely absent.
pub fn target_mesh_mtls_dial_host(target: &UpstreamTarget) -> Result<&str, HbonePoolError> {
    match target.tags.get(MESH_MTLS_DIAL_HOST_TAG) {
        Some(host) if host.trim().is_empty() => Err(HbonePoolError::InvalidDialHostTag {
            value: host.clone(),
            message: format!("{MESH_MTLS_DIAL_HOST_TAG} must not be empty"),
        }),
        Some(host) => Ok(host.trim()),
        None => Ok(target.host.as_str()),
    }
}

/// Whether a target is a CROSS-CLUSTER east-west mesh-mTLS target (carries
/// [`MESH_CROSS_CLUSTER_TAG`] = boolish-true). Such a target dials the remote
/// east-west gateway with a destination-FQDN SNI override and uses
/// trust-domain-only peer verification — see [`MESH_CROSS_CLUSTER_TAG`].
pub fn target_mesh_mtls_cross_cluster(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(MESH_CROSS_CLUSTER_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

/// The destination-service-FQDN SNI override a cross-cluster target MUST carry
/// ([`MESH_EASTWEST_SNI_TAG`]). Returns `None` when the tag is absent OR empty
/// so the dispatch path can FAIL CLOSED — a cross-cluster dial without a usable
/// SNI must be refused, never fall back to the gateway address as SNI.
pub fn target_mesh_mtls_eastwest_sni(target: &UpstreamTarget) -> Option<&str> {
    target
        .tags
        .get(MESH_EASTWEST_SNI_TAG)
        .map(String::as_str)
        .filter(|sni| !sni.is_empty())
}

/// Tag carrying the destination workloads' trust domain (`mesh.trust_domain`).
/// On a CROSS-CLUSTER east-west target this is the REMOTE trust domain the dial
/// scopes verification to (the gateway LB-picks the workload, so the client
/// cannot pin a pod, but it CAN require the server SVID to be in exactly this
/// federated trust domain).
pub const MESH_TRUST_DOMAIN_TAG: &str = "mesh.trust_domain";

/// The remote trust domain a CROSS-CLUSTER east-west target scopes verification
/// to ([`MESH_TRUST_DOMAIN_TAG`]). Returns `None` when the tag is absent, empty,
/// or unparseable so the dispatch path can FAIL CLOSED — a cross-cluster dial
/// with no usable trust domain must be REFUSED, never fall back to any-federated
/// verification (which would let a federated cert from a DIFFERENT trust domain
/// complete the handshake). Only meaningful for cross-cluster targets; the
/// in-cluster pinned path constrains the domain via the pinned peer identity and
/// never reads this.
pub fn target_mesh_mtls_cross_cluster_trust_domain(target: &UpstreamTarget) -> Option<TrustDomain> {
    target
        .tags
        .get(MESH_TRUST_DOMAIN_TAG)
        .filter(|value| !value.is_empty())
        .and_then(|value| TrustDomain::new(value.as_str()).ok())
}

/// The pinned peer identity a `mesh.mtls` target MUST declare. Unlike HBONE
/// (where operator-supplied targets may legitimately omit the tag), Sidecar
/// mTLS targets are only ever produced by the mesh materializer, which always
/// stamps the destination workload identity — so an absent tag here is a
/// config-corruption signal and fails the dial closed rather than silently
/// downgrading to trust-domain-only verification.
///
/// NOTE: this is for PINNED (in-cluster) targets only. CROSS-CLUSTER east-west
/// targets ([`target_mesh_mtls_cross_cluster`]) deliberately carry NO
/// `mesh.spiffe_id` and use trust-domain-only verification; dispatch must NOT
/// call this for them.
pub fn target_mesh_mtls_expected_peer(target: &UpstreamTarget) -> Result<SpiffeId, HbonePoolError> {
    target_expected_peer_spiffe(target)?.ok_or_else(|| HbonePoolError::InvalidPeerSpiffeTag {
        value: String::new(),
        message: format!(
            "mesh.mtls target {}:{} carries no {MESH_SPIFFE_ID_TAG} tag; refusing unpinned \
             sidecar mTLS dial",
            target.host, target.port
        ),
    })
}

/// Why a [`MeshMtlsDialPlan`] could not be resolved for a target. Each variant
/// is a FAIL-CLOSED condition — dispatch must never fall back to a plaintext /
/// wrong-SNI dial for a mesh-tagged target.
#[derive(Debug)]
pub enum MeshMtlsDialError {
    /// In-cluster (pinned-peer) target with a missing / invalid `mesh.spiffe_id`
    /// tag. Carries the underlying [`HbonePoolError`] so callers keep the exact
    /// error mapping (`error_class`, response shaping) they had inline.
    PinnedPeer(HbonePoolError),
    /// Cross-cluster east-west target with a missing / empty `mesh.eastwest_sni`
    /// tag — the destination-FQDN SNI the remote gateway's passthrough routes on
    /// is mandatory (never dial the gateway IP as SNI).
    MissingCrossClusterSni,
    /// Cross-cluster east-west target with a missing / empty / unparseable
    /// `mesh.trust_domain` tag — the remote trust domain verification is scoped
    /// to is mandatory (never fall back to any-federated verification).
    MissingCrossClusterTrustDomain,
}

impl std::fmt::Display for MeshMtlsDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshMtlsDialError::PinnedPeer(err) => {
                write!(f, "unusable pinned sidecar mesh-mTLS peer identity: {err}")
            }
            MeshMtlsDialError::MissingCrossClusterSni => f.write_str(
                "cross-cluster sidecar mesh-mTLS target missing mesh.eastwest_sni \
                 (fail closed, never dial the gateway address as SNI)",
            ),
            MeshMtlsDialError::MissingCrossClusterTrustDomain => f.write_str(
                "cross-cluster sidecar mesh-mTLS target missing mesh.trust_domain \
                 (fail closed, never any-federated verification)",
            ),
        }
    }
}

impl std::error::Error for MeshMtlsDialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MeshMtlsDialError::PinnedPeer(err) => Some(err),
            _ => None,
        }
    }
}

impl MeshMtlsDialError {
    /// PRE-WIRE error class for a dial-plan resolution failure — no backend dial
    /// happened, so this is a gateway-side (connect-phase) failure that stays
    /// neutral to backend/circuit-breaker health and is retryable onto another
    /// target. The WebSocket egress path boxes this error, and
    /// `retry::classify_boxed_setup_error` recognizes it via
    /// [`retry::classify_typed_chain`] so a metadata reject is not charged to the
    /// backend as post-wire (issue #2010 codex). `PinnedPeer` delegates to the
    /// wrapped [`HbonePoolError`] (which the same walk would reach via `source`,
    /// but delegating keeps one mapping); the missing-SNI / trust-domain variants
    /// map to `ConnectionPoolError`, exactly like the HTTP mesh-mTLS path returns
    /// for these cases.
    pub fn error_class(&self) -> crate::retry::ErrorClass {
        match self {
            MeshMtlsDialError::PinnedPeer(err) => err.error_class(),
            MeshMtlsDialError::MissingCrossClusterSni
            | MeshMtlsDialError::MissingCrossClusterTrustDomain => {
                crate::retry::ErrorClass::ConnectionPoolError
            }
        }
    }
}

/// Resolved peer-verification + SNI parameters for a Sidecar mesh-mTLS dial,
/// derived ONCE from a target's mesh tags and shared by every mesh-mTLS dispatch
/// surface — HTTP/gRPC, WebSocket, raw TCP, and UDP — so the in-cluster-pinned
/// vs cross-cluster (east-west) split cannot drift between paths (issue #2010).
///
/// The two shapes:
/// - **In-cluster** (default): the destination workload identity is PINNED from
///   `mesh.spiffe_id` (mandatory; absent/corrupt fails closed) and the SNI is
///   the dial host (no override, no trust-domain scope).
/// - **Cross-cluster** (`mesh.cross_cluster`): the SNI-passthrough east-west
///   gateway LB-picks the destination workload, so NO pod SPIFFE is pinned
///   (`expected_peer = None`); verification is scoped to the remote
///   `mesh.trust_domain` and the ClientHello SNI is overridden to the
///   destination service port's east-west alias (`mesh.eastwest_sni`,
///   `p<port>.<fqdn>`). Both are mandatory — a missing one fails closed.
#[derive(Debug)]
pub struct MeshMtlsDialPlan<'a> {
    /// Whether this is a cross-cluster east-west dial.
    pub cross_cluster: bool,
    /// Pinned destination workload identity (in-cluster) or `None`
    /// (cross-cluster: the gateway LB-picks the workload).
    pub expected_peer: Option<SpiffeId>,
    /// Remote trust domain verification is scoped to (cross-cluster only);
    /// `None` in-cluster (the pinned peer already constrains the domain).
    pub expected_trust_domain: Option<TrustDomain>,
    /// ClientHello SNI override = the destination service port's east-west
    /// alias `p<port>.<fqdn>` (cross-cluster only); `None` in-cluster (SNI =
    /// the dial host). Borrowed from the target tag to avoid a per-dispatch
    /// allocation.
    pub sni_override: Option<&'a str>,
}

impl<'a> MeshMtlsDialPlan<'a> {
    /// Resolve the dial plan for `target`, or a fail-closed [`MeshMtlsDialError`].
    /// Callers map the error to their own protocol-appropriate refusal (a 502 on
    /// the HTTP path, a boxed error that fails the WebSocket upgrade closed) —
    /// never a plaintext fallback.
    pub fn resolve(target: &'a UpstreamTarget) -> Result<Self, MeshMtlsDialError> {
        if target_mesh_mtls_cross_cluster(target) {
            // Cross-cluster: SNI override THEN trust domain, both mandatory (same
            // order the HTTP dispatch path checked them inline).
            let sni_override = target_mesh_mtls_eastwest_sni(target)
                .ok_or(MeshMtlsDialError::MissingCrossClusterSni)?;
            let trust_domain = target_mesh_mtls_cross_cluster_trust_domain(target)
                .ok_or(MeshMtlsDialError::MissingCrossClusterTrustDomain)?;
            Ok(Self {
                cross_cluster: true,
                expected_peer: None,
                expected_trust_domain: Some(trust_domain),
                sni_override: Some(sni_override),
            })
        } else {
            let expected_peer =
                target_mesh_mtls_expected_peer(target).map_err(MeshMtlsDialError::PinnedPeer)?;
            Ok(Self {
                cross_cluster: false,
                expected_peer: Some(expected_peer),
                expected_trust_domain: None,
                sni_override: None,
            })
        }
    }
}

/// Upper bound on retired-generation records kept while waiting for their
/// drain timers. With `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS=0` no drain
/// task ever consumes the records, so the registry must be capped or a
/// rotation storm grows it unbounded.
const MAX_RETIRED_SVID_GENERATIONS: usize = 16;
/// Upper bound on fingerprints filed under one generation. Normally a
/// generation retires exactly one fingerprint; a frozen generation counter
/// (starved rotation consumer) funnels every rotation into one bucket, which
/// must not grow unbounded either.
const MAX_RETIRED_FINGERPRINTS_PER_GENERATION: usize = 8;

/// Per-key coalesced-creation slot for the sidecar mesh-mTLS pool (issue
/// #5046). Same shape as the HBONE pool's slot: the serialization mutex the
/// pool has always used, plus a generation-scoped broadcast of the creator's
/// own typed [`HbonePoolError`] (shared behind an `Arc`, rebuilt per waiter
/// with [`HbonePoolError::clone_for_broadcast`]).
pub(crate) type MeshMtlsCreationSlot = SharedCreationSlot<Arc<HbonePoolError>>;

/// Pending response heads on the least-loaded pooled connection at or above
/// which a checkout tries to add one more physical connection for its key
/// (issue #5043), never exceeding `http2_connections_per_host`.
///
/// One hyper H2 connection is one driver task: on a loopback mTLS bench its
/// throughput sat flat at ~70k req/s / ~2.5 GB/s from 16 to 512 concurrent
/// streams, while four connections gave 1.8-3.2x that with ~2x lower p50.
/// The same bench showed widening costs CPU per request only for bulk bodies
/// at low concurrency, so width follows measured pressure rather than being
/// eager: sequential and lightly concurrent traffic keeps one connection.
pub const MESH_MTLS_GROWTH_PENDING_PER_CONNECTION: usize = 8;

/// After a growth dial fails (peer down, `maxConnections` reached, TLS/DNS
/// error), growth for that key is not retried for this long. Requests keep
/// flowing on the existing connections; only the widening pauses.
const MESH_MTLS_GROWTH_BACKOFF_SECS: u64 = 10;

pub struct MeshMtlsConnectionPool {
    /// Shared with the periodic idle sweeper, which holds it weakly.
    entries: Arc<DashMap<String, Vec<MeshMtlsPoolEntry>>>,
    /// key -> unix seconds before which no growth dial is attempted for the
    /// key. Written only when a growth dial fails; pruned with idle entries.
    growth_backoff_until: DashMap<String, u64>,
    /// Per-key creation slots: the serialization mutex plus the failure
    /// broadcast that releases every caller queued behind a failed dial
    /// instead of letting each repeat it (issue #5046).
    creation_locks: DashMap<String, Arc<MeshMtlsCreationSlot>>,
    gateway_svid: SharedSvidBundle,
    crls: crate::tls::SharedCrlList,
    svid_identity_cache: ArcSwap<Option<MeshMtlsSvidIdentityCache>>,
    /// Shared backend SVID generation counter (same `Arc` the HTTP/H2/gRPC/H3
    /// pools stamp into their `|svidg=` key fields). Mesh mTLS keys embed the
    /// SVID *fingerprint* instead, so the identity cache stamps the generation
    /// it was built under and `retired_svid_fingerprints` maps each retired
    /// generation back to its fingerprint(s) for the rotation drain.
    backend_svid_generation: BackendSvidGeneration,
    /// generation -> fingerprints that were current under that generation but
    /// have since rotated out. Written only on rotation (cold path); consumed
    /// and removed by `force_drain_svid_generation`.
    retired_svid_fingerprints: DashMap<u64, Vec<Arc<str>>>,
    dns_cache: DnsCache,
    pool_config: PoolConfig,
    last_idle_prune_unix_secs: AtomicU64,
    /// Shared gateway-wide DestinationRule `connectionPool.tcp.maxConnections`
    /// counter, installed once by `ProxyState` via
    /// [`MeshMtlsConnectionPool::attach_backend_conn_limit`]. Unset for focused
    /// tests and standalone callers, in which case no cap is enforced.
    backend_conn_limit: OnceLock<crate::backend_conn_limit::SharedBackendConnectionLimiter>,
    /// Gateway-to-mesh transport ownership registry (issue #3859), installed
    /// once by `ProxyState`. Unset for focused tests and standalone callers.
    mesh_trust_registry: OnceLock<Arc<MeshTrustRegistry>>,
    /// The raw-TCP egress tunnel lane (issue #7537): pooled raw-`h2` SVID-mTLS
    /// connections to peer sidecars' `:15006`, each multiplexing bare CONNECT
    /// streams up to its stream cap. Same entry type, selection, pruning,
    /// keepalive eviction and idle sweeper as the HBONE pool; keyed by
    /// `write_mesh_mtls_tunnel_pool_key`, whose SVID fingerprint sits at the
    /// same index as the HTTP lane's so one rotation drain covers both lanes.
    /// Shares `creation_locks` with the HTTP lane (the key prefixes differ).
    tunnel_entries: Arc<DashMap<String, Vec<HbonePoolEntry>>>,
    tunnel_counters: MeshMtlsTunnelCounters,
    /// Advanced FIRST by every drain of the tunnel lane; a carrier whose dial
    /// began under an older generation is never published or handed out
    /// (issue #7537, see `publish_tunnel_carrier`).
    tunnel_drain_generation: AtomicU64,
}

/// A carrier dialed for one tunnel, with that tunnel's reserved stream slot.
struct DialedTunnelCarrier {
    transport: MeshH2Transport,
    reservation: HboneStreamLease,
    /// The SVID and CRL slots were unchanged across the dial.
    poolable: bool,
    /// The lane's drain generation when the dial began.
    drain_generation: u64,
}

/// Lifetime counters of the raw-TCP tunnel lane (issue #7537), rendered on
/// `/metrics` through `MeshMtlsConnectionPool::tunnel_pool_stats`. Each tunnel
/// open bumps at most two relaxed counters; nothing here is on the byte path.
#[derive(Default)]
struct MeshMtlsTunnelCounters {
    connections_opened: AtomicU64,
    streams_reused: AtomicU64,
    streams_new_connection: AtomicU64,
    saturation_waits_admitted: AtomicU64,
    saturation_waits_timed_out: AtomicU64,
}

/// Scrape-time view of the Sidecar raw-TCP tunnel lane (issue #7537).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeshMtlsTunnelPoolStats {
    /// Pooled carrier connections resident in the lane.
    pub connections: usize,
    /// CONNECT streams open on pooled carriers right now.
    pub active_streams: usize,
    /// Carrier connections the lane dialed (pooled or served unpooled).
    pub connections_opened: u64,
    /// Tunnels opened on an already-pooled carrier.
    pub streams_reused: u64,
    /// Tunnels opened on a carrier dialed for them.
    pub streams_new_connection: u64,
    /// Tunnels that waited for a stream slot (every carrier at its stream cap,
    /// lane at `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`) and then got one.
    pub saturation_waits_admitted: u64,
    /// Tunnels that waited for a stream slot and ran out of connect budget.
    pub saturation_waits_timed_out: u64,
}

/// Outcome of the tunnel lane's write-path checkout for one key.
enum TunnelCheckout {
    /// A pooled carrier with a stream slot reserved for this tunnel.
    Reserved(MeshH2Transport, HboneStreamLease),
    /// Every live carrier is at its stream cap and the key is at its
    /// configured width: wait for a sibling stream to close.
    SaturatedAtWidth,
    /// No carrier with room and the key can widen: dial one.
    NeedsCarrier,
}

/// Longest single sleep while a tunnel waits for a stream slot on a saturated,
/// width-capped key. The wait starts at 2 ms and doubles up to this.
const MESH_MTLS_TUNNEL_SLOT_WAIT_MAX: Duration = Duration::from_millis(50);

struct MeshMtlsSvidIdentityCache {
    source: Arc<Option<SvidBundle>>,
    fingerprint: Arc<str>,
    /// Backend SVID generation observed when this cache entry was built.
    /// Used to file the fingerprint under the right generation once it
    /// rotates out, so `force_drain_svid_generation(old_gen)` can resolve
    /// the passed generation to the fingerprint embedded in pool keys.
    svid_generation: u64,
}

impl MeshMtlsConnectionPool {
    pub fn new(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        shard_amount: usize,
    ) -> Self {
        Self::new_with_svid_generation(
            pool_config,
            dns_cache,
            gateway_svid,
            shard_amount,
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub fn new_with_svid_generation(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_crls(
            pool_config,
            dns_cache,
            gateway_svid,
            Arc::new(Vec::new()),
            shard_amount,
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_crls(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        crls: crate::tls::CrlList,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_shared_crls(
            pool_config,
            dns_cache,
            gateway_svid,
            crate::tls::shared_crl_list(crls),
            shard_amount,
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_shared_crls(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        crls: crate::tls::SharedCrlList,
        shard_amount: usize,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        let entries = Arc::new(DashMap::with_shard_amount(shard_amount));
        spawn_idle_entry_sweeper(&entries, &pool_config);
        let tunnel_entries = Arc::new(DashMap::with_shard_amount(shard_amount));
        spawn_tunnel_sweeper(
            &tunnel_entries,
            &pool_config,
            crate::runtime_metrics::PoolKind::MeshMtlsTunnel,
        );
        Self {
            tunnel_entries,
            tunnel_counters: MeshMtlsTunnelCounters::default(),
            tunnel_drain_generation: AtomicU64::new(0),
            entries,
            growth_backoff_until: DashMap::new(),
            creation_locks: DashMap::with_shard_amount(shard_amount),
            gateway_svid,
            crls,
            svid_identity_cache: ArcSwap::new(Arc::new(None)),
            backend_svid_generation,
            // Low-cardinality, rotation-only map — default sharding is fine.
            retired_svid_fingerprints: DashMap::new(),
            dns_cache,
            pool_config,
            last_idle_prune_unix_secs: AtomicU64::new(0),
            backend_conn_limit: OnceLock::new(),
            mesh_trust_registry: OnceLock::new(),
        }
    }

    /// Install the gateway trust ownership registry (issue #3859) so every
    /// mesh-mTLS transport this pool dials — pooled HTTP senders, pooled
    /// raw-TCP tunnel carriers, datagram 1:1, or WebSocket 1:1 — is registered under the accepted gateway trust
    /// generation and can be synchronously retired when an authority is
    /// withdrawn. Idempotent; later calls are ignored.
    pub fn attach_mesh_trust_registry(&self, registry: Arc<MeshTrustRegistry>) {
        let _ = self.mesh_trust_registry.set(registry);
    }

    fn trust_registry(&self) -> Option<&Arc<MeshTrustRegistry>> {
        self.mesh_trust_registry.get()
    }

    /// Install the gateway-wide `connectionPool.tcp.maxConnections` counter so
    /// Sidecar mesh-mTLS connections are admitted against the same
    /// per-destination ceiling as every other transport. Idempotent; later
    /// calls are ignored.
    pub fn attach_backend_conn_limit(
        &self,
        limiter: crate::backend_conn_limit::SharedBackendConnectionLimiter,
    ) {
        let _ = self.backend_conn_limit.set(limiter);
    }

    /// Resolve the `maxConnections` admission lane for a mesh-mTLS dial.
    ///
    /// Keyed by the DIAL host (the peer sidecar whose socket is opened) and the
    /// destination's APP/service policy port — never the `:15006` transport
    /// listener — so a mesh-mTLS connection shares one ceiling with the
    /// destination's WebSocket, raw-TCP, and other pooled connections.
    fn conn_admission<'a>(
        &'a self,
        proxy: &'a Proxy,
        dial_host: &'a str,
        app_policy_port: u16,
    ) -> Option<crate::backend_conn_limit::PooledConnectionAdmission<'a>> {
        crate::backend_conn_limit::PooledConnectionAdmission::resolve_tracking_uncapped(
            self.backend_conn_limit.get().map(|limiter| &**limiter),
            proxy,
            dial_host,
            app_policy_port,
        )
    }

    pub fn pool_size(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
    }

    /// Pooled raw-TCP tunnel carrier connections (issue #7537). Scrape-time
    /// only: walks every shard.
    pub fn tunnel_pool_size(&self) -> usize {
        self.tunnel_entries
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    /// Scrape-time view of the raw-TCP tunnel lane (issue #7537): resident
    /// carriers, open CONNECT streams on them, and the lane's lifetime
    /// counters. Walks every shard, so call it from `/metrics`, not a hot path.
    pub fn tunnel_pool_stats(&self) -> MeshMtlsTunnelPoolStats {
        let mut connections = 0usize;
        let mut active_streams = 0usize;
        for entry in self.tunnel_entries.iter() {
            connections = connections.saturating_add(entry.value().len());
            for carrier in entry.value() {
                active_streams =
                    active_streams.saturating_add(carrier.transport.load.active_streams());
            }
        }
        let counters = &self.tunnel_counters;
        MeshMtlsTunnelPoolStats {
            connections,
            active_streams,
            connections_opened: counters.connections_opened.load(Ordering::Relaxed),
            streams_reused: counters.streams_reused.load(Ordering::Relaxed),
            streams_new_connection: counters.streams_new_connection.load(Ordering::Relaxed),
            saturation_waits_admitted: counters.saturation_waits_admitted.load(Ordering::Relaxed),
            saturation_waits_timed_out: counters.saturation_waits_timed_out.load(Ordering::Relaxed),
        }
    }

    /// Cached gateway SVID fingerprint, keyed by `Arc::ptr_eq` on the SVID
    /// slot snapshot — recomputing `Sha256::digest` + hex-formatting on every
    /// dispatched request is hot-path waste when the SVID rotates rarely.
    /// Unlike the HBONE pool's identity cache this stores only the
    /// fingerprint: sidecar mTLS dispatch never needs the source SPIFFE id
    /// (there is no baggage header on this transport).
    fn current_svid_fingerprint_cached(&self) -> Result<Arc<str>, HbonePoolError> {
        let snapshot = self.gateway_svid.load_full();
        let cached = self.svid_identity_cache.load_full();
        if let Some(cache) = cached.as_ref()
            && Arc::ptr_eq(&cache.source, &snapshot)
        {
            return Ok(cache.fingerprint.clone());
        }

        let bundle = snapshot.as_ref().as_ref().ok_or(HbonePoolError::NoSvid)?;
        let fingerprint: Arc<str> = Arc::from(svid_fingerprint(bundle)?);
        if let Some(previous) = cached.as_ref() {
            // The SVID slot rotated: file the outgoing fingerprint under the
            // generation it was current for, so the delayed drain task can
            // resolve `force_drain_svid_generation(old_gen)` to it. Slot
            // stores are change-gated by the rotation watcher, so EVERY
            // rebuild is a genuine material change — record even when the
            // fingerprint is unchanged (a trust-bundle-only rotation keeps
            // the leaf, but sessions verified against the previous bundle
            // must still not outlive the drain window). A same-as-current
            // fingerprint record makes that drain force a one-time reconnect
            // wave for keys that are also current; that churn is the intent.
            self.record_retired_fingerprint(previous.svid_generation, previous.fingerprint.clone());
        }
        self.svid_identity_cache
            .store(Arc::new(Some(MeshMtlsSvidIdentityCache {
                source: snapshot,
                fingerprint: fingerprint.clone(),
                svid_generation: self.backend_svid_generation.load(Ordering::Acquire),
            })));
        Ok(fingerprint)
    }

    fn record_retired_fingerprint(&self, generation: u64, fingerprint: Arc<str>) {
        // Bound the per-generation list as well as the generation count: when
        // the rotation consumer is starved or dead, every rotation stamps the
        // same frozen generation and would grow one Vec unbounded while the
        // key-count cap below never trips. Overflow is drained immediately
        // (early is safe, never is not). Drains happen after the shard guard
        // is released.
        let mut overflowed: Vec<Arc<str>> = Vec::new();
        {
            let mut retired = self
                .retired_svid_fingerprints
                .entry(generation)
                .or_default();
            if !retired
                .iter()
                .any(|existing| existing.as_ref() == fingerprint.as_ref())
            {
                retired.push(fingerprint);
            }
            while retired.len() > MAX_RETIRED_FINGERPRINTS_PER_GENERATION {
                overflowed.push(retired.remove(0));
            }
        }
        if !overflowed.is_empty() {
            self.drain_retired_fingerprints(&overflowed);
        }
        // Cap the registry: with the drain window disabled nothing consumes
        // these records, and a rotation storm must not grow them unbounded.
        // An evicted record's drain timer may not have fired yet (or drains
        // may be disabled entirely) — dropping it silently would leak its
        // sessions past the configured drain window, so drain the evicted
        // fingerprints immediately: early is safe, never is not. Cold path
        // (rotation only), so the min-scan eviction is fine.
        while self.retired_svid_fingerprints.len() > MAX_RETIRED_SVID_GENERATIONS {
            let Some(oldest) = self
                .retired_svid_fingerprints
                .iter()
                .map(|entry| *entry.key())
                .min()
            else {
                break;
            };
            if let Some((_, evicted)) = self.retired_svid_fingerprints.remove(&oldest) {
                self.drain_retired_fingerprints(&evicted);
            }
        }
    }

    /// Remove every pool entry and creation lock whose key embeds one of the
    /// `retired` SVID fingerprints.
    fn drain_retired_fingerprints(&self, retired: &[Arc<str>]) {
        let fingerprint_retired = |key: &str| {
            mesh_mtls_key_svid_fingerprint(key)
                .is_some_and(|fingerprint| retired.iter().any(|fp| fp.as_ref() == fingerprint))
        };
        let mut evicted = 0usize;
        self.entries.retain(|key, entries| {
            let drain = fingerprint_retired(key);
            if drain {
                evicted = evicted.saturating_add(entries.len());
            }
            !drain
        });
        // The raw-TCP tunnel lane keys the fingerprint at the same index, so
        // one rotation drain retires both lanes (issue #7537). The generation
        // advances first so a dial in flight cannot publish afterwards. Tunnels already
        // open on a drained carrier keep running on it, exactly as a 1:1
        // tunnel kept its own connection; no NEW stream is ever opened on it.
        let mut tunnels_evicted = 0usize;
        self.advance_tunnel_drain_generation();
        self.tunnel_entries.retain(|key, entries| {
            let drain = fingerprint_retired(key);
            if drain {
                tunnels_evicted = tunnels_evicted.saturating_add(entries.len());
            }
            !drain
        });
        self.creation_locks
            .retain(|key, _| !fingerprint_retired(key));
        record_mesh_mtls_evictions(evicted);
        record_mesh_mtls_tunnel_evictions(tunnels_evicted);
    }

    /// Drain pool entries belonging to the retired SVID `generation` — and to
    /// any older generation whose record is still pending.
    ///
    /// Mirrors the `SvidGenerationMatcher` semantics of the HTTP/H2/gRPC/H3
    /// pools: generations NEWER than the passed one are never touched, so
    /// overlapping rotation drain windows (A→B→C within one
    /// `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS` window) never drain a newer
    /// generation's connections before that generation's own timer fires.
    /// Mesh mTLS keys embed the SVID *fingerprint* rather than the generation,
    /// so the identity cache records which fingerprint was current under each
    /// generation and this method resolves the passed generation through that
    /// registry.
    ///
    /// The sweep is `<= generation` rather than `== generation` to close the
    /// slot-swap/generation-store race: the rotation watcher swaps the SVID
    /// slot BEFORE the async rotation consumer advances
    /// `backend_svid_generation`, so traffic landing in that window stamps the
    /// incoming fingerprint with the outgoing generation and the next rotation
    /// files it one generation too low. Drain timers fire in rotation order
    /// with equal delays, so a record misfiled under an already-drained older
    /// generation is picked up by the next drain instead of leaking until idle
    /// pruning.
    pub fn force_drain_svid_generation(&self, generation: u64) {
        // Refresh the identity cache first so a rotation with no sidecar mTLS
        // traffic since the SVID slot swap still records the outgoing
        // fingerprint.
        if self.current_svid_fingerprint_cached().is_err() {
            // No SVID in the slot: every pooled connection is stale.
            self.force_drain_all();
            return;
        }

        let stale_generations: Vec<u64> = self
            .retired_svid_fingerprints
            .iter()
            .map(|entry| *entry.key())
            .filter(|recorded| *recorded <= generation)
            .collect();
        let mut retired: Vec<Arc<str>> = Vec::new();
        for stale in stale_generations {
            if let Some((_, fingerprints)) = self.retired_svid_fingerprints.remove(&stale) {
                retired.extend(fingerprints);
            }
        }
        if retired.is_empty() {
            // Nothing was retired at or before this generation: either its
            // fingerprint is still current or it never carried pool entries.
            return;
        }

        self.drain_retired_fingerprints(&retired);
    }

    /// Remove every pooled connection from BOTH lanes — the HTTP-family
    /// senders and the raw-TCP tunnel carriers (issue #7537). Called for a
    /// missing SVID, a committed gateway trust change, and every backend
    /// TLS/CRL reload, so a carrier verified against withdrawn trust or a
    /// since-revoked peer certificate is never handed to a new tunnel.
    pub fn force_drain_all(&self) {
        let evicted = self.pool_size();
        // Generation first: a tunnel carrier whose dial is in flight cannot
        // publish after this drain (issue #7537).
        self.advance_tunnel_drain_generation();
        let tunnels_evicted = self.tunnel_pool_size();
        self.entries.clear();
        self.tunnel_entries.clear();
        self.creation_locks.clear();
        self.retired_svid_fingerprints.clear();
        record_mesh_mtls_evictions(evicted);
        record_mesh_mtls_tunnel_evictions(tunnels_evicted);
    }

    /// Checkout (or create) a multiplexed H2 sender to `target_host:mtls_port`.
    /// The returned sender is a cheap clone of the pooled connection handle.
    /// `app_port` is the target's app (container) port — it never changes what
    /// is dialed, but it partitions the pool so per-port siblings of a
    /// multi-port service don't share connections (stream-cap saturation / idle
    /// pruning isolation; the same per-app-port pool-key isolation the HBONE
    /// pool keeps).
    ///
    /// Peer verification follows `expected_peer`:
    /// - `Some(id)` — PINNED (in-cluster) dial: the peer's server SVID URI SAN
    ///   must EQUAL `id` (trust-domain membership alone is not enough).
    /// - `None` — TRUST-DOMAIN-ONLY (cross-cluster east-west) dial: the peer's
    ///   SVID must be in a TRUSTED (federated) trust domain, but no specific
    ///   pod identity is pinned (the east-west gateway LB-picks the workload).
    ///   NEVER unverified — `build_spiffe_outbound_config(None)` still requires
    ///   a trust bundle for the peer's trust domain.
    ///
    /// `sni_override` sets the ClientHello SNI when `Some` (cross-cluster: the
    /// destination service port's `p<port>.<fqdn>` alias so the gateway's SNI
    /// passthrough routes the opaque TLS to that port's workload backend);
    /// `None` uses `target_host`.
    ///
    /// `expected_trust_domain` scopes verification to a single remote trust
    /// domain on cross-cluster east-west dials (always paired with
    /// `expected_peer = None`); the in-cluster pinned path passes `None`.
    ///
    /// The pool key folds the SNI override, an expected-peer-or-`td-only`
    /// discriminator, AND the expected trust domain so a session verified
    /// against one remote trust domain is NEVER reused for another (and a
    /// trust-domain-scoped / SNI-overridden session never shares a pooled
    /// connection with a pinned-peer one).
    #[allow(clippy::too_many_arguments)]
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        app_port: u16,
        app_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
    ) -> Result<MeshMtlsSender, HbonePoolError> {
        let fingerprint = self.current_svid_fingerprint_cached()?;
        let pool_config = self.pool_config.for_proxy(proxy);
        let max_entries = pool_config.http2_connections_per_host.max(1);

        let fast_sender = with_mesh_mtls_pool_key(
            target_host,
            app_port,
            mtls_port,
            proxy.dns_override.as_deref(),
            fingerprint.as_ref(),
            expected_peer,
            sni_override,
            expected_trust_domain,
            &pool_config,
            |key| self.try_cached_sender_read(key),
        );
        if let Some((transport, live_connections)) = fast_sender {
            // The least-loaded connection is still carrying at least the
            // growth threshold of unanswered requests and the key has room:
            // try to widen (issue #5043). Growth is opportunistic — a busy
            // creation lock, a backoff, or a failed dial all leave this
            // request on the connection it already has.
            if live_connections < max_entries
                && transport.pending_requests() >= MESH_MTLS_GROWTH_PENDING_PER_CONNECTION
            {
                let key = with_mesh_mtls_pool_key(
                    target_host,
                    app_port,
                    mtls_port,
                    proxy.dns_override.as_deref(),
                    fingerprint.as_ref(),
                    expected_peer,
                    sni_override,
                    expected_trust_domain,
                    &pool_config,
                    |key| key.to_string(),
                );
                if let Some(grown) = self
                    .try_grow_sender(
                        proxy,
                        target_host,
                        app_policy_port,
                        mtls_port,
                        expected_peer,
                        expected_trust_domain,
                        sni_override,
                        &key,
                        &pool_config,
                        max_entries,
                    )
                    .await
                {
                    return Ok(grown);
                }
            }
            return Ok(transport);
        }

        let key = with_mesh_mtls_pool_key(
            target_host,
            app_port,
            mtls_port,
            proxy.dns_override.as_deref(),
            fingerprint.as_ref(),
            expected_peer,
            sni_override,
            expected_trust_domain,
            &pool_config,
            |key| key.to_string(),
        );
        self.get_or_create_sender(
            proxy,
            target_host,
            app_port,
            app_policy_port,
            mtls_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            &key,
            &pool_config,
        )
        .await
    }

    /// Open a raw-TCP egress CONNECT tunnel to a peer sidecar's inbound mTLS
    /// listener (`:15006`, or the `mesh.mtls_port`-tagged override) as one
    /// CONNECT stream multiplexed over a POOLED SVID-mTLS HTTP/2 connection
    /// (issue #7537). `target_host:target_port` is the destination workload's
    /// address and app (container) port — the CONNECT `:authority` the peer's
    /// transport-agnostic inbound relay dials locally. `dial_host` is the peer
    /// pod in-cluster or the east-west gateway cross-cluster;
    /// `authority_host:target_port` is always the real destination workload.
    ///
    /// **Pool key.** Carriers live in the tunnel lane, keyed by
    /// `write_mesh_mtls_tunnel_pool_key`: the dial target (`dial_host`,
    /// `mtls_port`, DNS override), the CONNECT authority (`authority_host`,
    /// `target_port`) and the DestinationRule policy port, the gateway SVID
    /// fingerprint, and the peer verification scope — the pinned
    /// `expected_peer` in-cluster, or the `td-only` marker plus the
    /// cross-cluster trust domain and SNI override. A carrier verified for one
    /// identity or trust scope is therefore never reused for another, and a
    /// carrier only ever carries streams for one exact authority.
    ///
    /// **Limits.** A new tunnel takes a stream slot on the least-loaded live
    /// carrier still under its stream cap (the peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`, lowered to the effective
    /// `maxConcurrentStreams`), reserved by compare-and-swap so racing opens
    /// cannot overshoot the cap. Only when every carrier is full does the lane
    /// dial another, up to `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`, so `N`
    /// concurrent tunnels use at most `⌈N / cap⌉` connections. Every dial
    /// takes the destination's DestinationRule `maxConnections` slot, owned by
    /// the connection driver. When every carrier is full and the key is at its
    /// width, the tunnel waits for a sibling stream to close, bounded by the
    /// destination's connect timeout. Idle carriers are pruned by the idle
    /// timeout and the periodic sweeper.
    ///
    /// **Retirement.** SVID rotation (fingerprint drain), trust-bundle change,
    /// backend TLS/CRL reload and committed gateway trust changes all remove
    /// carriers from the lane (`force_drain_svid_generation` /
    /// `force_drain_all`); a gateway trust withdrawal additionally retires
    /// every registered carrier's gate, which errors every stream on it; and a
    /// carrier is never handed out past the earlier of its peer's and this
    /// gateway's leaf `notAfter`. One stream's reset (`RST_STREAM`) is local
    /// to that stream; its siblings and the carrier stay up.
    ///
    /// **Flow control.** Each tunnel reads with its own HTTP/2 stream window
    /// and releases credit only as the relay consumes bytes, and writes only
    /// the capacity the peer granted that stream, so a stalled reader or
    /// writer back-pressures its own captured socket. Carrier connections
    /// size their connection-level receive window so stalled streams cannot
    /// consume the credit live siblings need (`tunnel_carrier_pool_config`).
    ///
    /// The CONNECT is BARE — no `x-ferrum-mesh-protocol` marker and no W3C
    /// baggage: the peer authenticates this gateway by its mTLS client
    /// certificate (one sidecar SVID == one workload identity), and the
    /// destination's inbound relay (`build_inbound_hbone_relay_proxy`, gated by
    /// `is_hbone_connect` + `mesh_direction == Inbound`, which a bare H2 CONNECT
    /// satisfies) dials the authority. Fail-closed: a missing gateway SVID
    /// errors before any checkout or dial. In-cluster dials pin
    /// `expected_peer`; cross-cluster dials use the caller's trust-domain scope
    /// + SNI override.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_connect_tunnel(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        authority_host: &str,
        target_port: u16,
        target_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        // Fail closed when no gateway SVID is loaded — never check out or dial
        // a mesh peer identity-less (parity with `get_sender` and the HBONE
        // raw-TCP path). The fingerprint is also the key's identity field.
        let fingerprint = self.current_svid_fingerprint_cached()?;
        // The proxy's pool settings with the destination port's DestinationRule
        // `connectionPool.http` overrides applied, as the HTTP lane sees them.
        let pool_config = self.tunnel_pool_config(proxy, target_policy_port);
        // DR `connectTimeout` override resolved for the destination's APP /
        // service policy port, not the transport `mtls_port`.
        let effective_connect_timeout_ms =
            self.effective_connect_timeout_ms(proxy, target_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let key_fields = MeshMtlsTunnelKey {
            dial_host,
            target_port,
            mtls_port,
            dns_override: proxy.dns_override.as_deref(),
            svid_fingerprint: fingerprint.as_ref(),
            expected_peer,
            sni_override,
            expected_trust_domain,
            authority_host,
            policy_port: target_policy_port,
        };
        key_fields.delimiter_free()?;

        // Shared-lock fast path: reserve a slot on a live pooled carrier.
        let fast = with_mesh_mtls_tunnel_pool_key(&key_fields, &pool_config, |key| {
            self.try_reserve_pooled_tunnel_carrier(key)
        });
        let (tunnel, fresh_carrier) = match fast {
            Some((transport, reservation)) => (
                Self::open_tunnel_stream(
                    transport,
                    reservation,
                    &key_fields,
                    connect_timeout,
                    effective_connect_timeout_ms,
                )
                .await?,
                false,
            ),
            None => {
                let key = with_mesh_mtls_tunnel_pool_key(&key_fields, &pool_config, |key| {
                    key.to_string()
                });
                self.checkout_or_dial_tunnel(
                    proxy,
                    &key_fields,
                    &key,
                    &pool_config,
                    connect_timeout,
                    effective_connect_timeout_ms,
                )
                .await?
            }
        };
        let opened = if fresh_carrier {
            &self.tunnel_counters.streams_new_connection
        } else {
            &self.tunnel_counters.streams_reused
        };
        opened.fetch_add(1, Ordering::Relaxed);
        Ok(tunnel)
    }

    /// Open a datagram-over-mesh-mTLS CONNECT tunnel to a peer sidecar's inbound
    /// mTLS listener (`:15006`, or the `mesh.mtls_port`-tagged override) over a
    /// FRESH SVID-mTLS H2 connection — the Sidecar counterpart of
    /// [`HboneConnectionPool::get_datagram_tunnel`] (F3 §3.3 Stage 4 Sidecar
    /// relay). `authority_host:target_port` is the destination workload's address
    /// and UDP app port; the CONNECT `:authority` is that app addr+port the
    /// peer's transport-agnostic inbound relay unframes the tunnel into a local
    /// `UdpSocket` toward.
    ///
    /// Unlike [`Self::open_connect_tunnel`] (raw-TCP byte stream), this stamps
    /// the `udp` protocol marker (`crate::modes::mesh::hbone::UDP_PROTOCOL`)
    /// AND the W3C source-identity baggage, EXACTLY the way
    /// [`HboneConnectionPool::get_datagram_tunnel`] does for the Ambient HBONE
    /// path: the destination's relay branches on the `udp` marker
    /// (`is_udp_hbone_connect`) to unframe length-delimited datagrams (see
    /// `crate::proxy::mesh_udp_frame`) into a `UdpSocket`, rather than
    /// byte-relaying to a TCP backend. The returned [`H2ConnectTunnel`] carries
    /// length-delimited datagrams, NOT a raw byte stream.
    ///
    /// `source_identity` is the Ambient per-pod capture evidence (principal +
    /// pod UID) when the producer enrolled an attested workload. Sidecar /
    /// default callers pass `None` and keep the gateway-SVID principal baggage.
    /// Destination authorization still applies the existing trusted-assertor /
    /// trust-domain gates before treating either assertion as authoritative.
    ///
    /// Unlike [`Self::open_connect_tunnel`] (whose raw-TCP streams share pooled
    /// carriers, issue #7537) each UDP session gets its OWN
    /// mesh-mTLS H2 connection carrying exactly ONE CONNECT stream (1:1, dropped
    /// when the session ends), NOT multiplexed over the pooled
    /// [`MeshMtlsSender`] connections — a captured UDP flow is a distinct
    /// session with its own lifetime, and a dedicated connection keeps the
    /// wire-visible `udp` marker on a stream that is unambiguously a datagram
    /// tunnel. SVID rotation is automatic (each session dials with the current
    /// SVID). Honors the destination app port's DR `connectTimeout` /
    /// `tcpKeepalive` overrides the same way `get_datagram_tunnel` does. NO
    /// capability probe: a slice-declared sidecar peer speaks mesh-mTLS by
    /// construction. Fail-closed: a missing gateway SVID errors before the dial;
    /// in-cluster dials pin `expected_peer`, while cross-cluster dials require
    /// trust-domain scope + SNI override.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub async fn open_datagram_tunnel(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        authority_host: &str,
        target_port: u16,
        target_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        source_identity: Option<&crate::modes::mesh::hbone::UdpSourceIdentity>,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        // Fail closed when no gateway SVID is loaded — never dial a mesh peer
        // identity-less (parity with `open_connect_tunnel` and `get_sender`).
        // This also drives the rotation/retired-fingerprint bookkeeping.
        let _ = self.current_svid_fingerprint_cached()?;
        let baggage = datagram_tunnel_baggage(&self.gateway_svid, source_identity)?;
        let pool_config = self.pool_config.for_proxy(proxy);
        // Per-port DestinationRule overrides are resolved for the destination's
        // APP port (`target_port`, the DR keying port), not the transport
        // `mtls_port` — mirrors `get_datagram_tunnel`:
        // - `tcpKeepalive` flows into the dial's socket keepalive;
        // - `connectTimeout` bounds the WHOLE dial AND the CONNECT-stream wait.
        let port_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&target_policy_port));
        let keepalive_override = port_override.and_then(|o| o.tcp_keepalive.as_ref());
        let effective_connect_timeout_ms = port_override
            .and_then(|o| o.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        // Each datagram tunnel session dials its OWN connection, so it
        // is admitted on the destination's `maxConnections` lane (keyed by the
        // dial peer + the APP/service policy port, never `:15006`).
        let conn_admission = self.conn_admission(proxy, dial_host, target_policy_port);
        // Registered like every pooled transport (issue #3859): a 1:1 datagram
        // bridge never enters the pool map either.
        let transport = dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            self.crls.load_full(),
            proxy,
            dial_host,
            mtls_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            &pool_config,
            keepalive_override,
            Some(connect_timeout),
            conn_admission.as_ref(),
            self.trust_registry(),
            MeshTransportKind::MeshMtls,
            None,
            // The Sidecar mesh-mTLS CONNECT tunnel shares the raw-`h2` dial with
            // Ambient HBONE, so it inherits the same receive-side header-block
            // bound: hyper's 16 KiB, never `h2`'s 16 MiB default.
            crate::proxy::hbone_pool::HBONE_DEFAULT_MAX_HEADER_LIST_SIZE,
        )
        .await?;
        tokio::time::timeout(
            connect_timeout,
            open_h2_connect_stream(
                transport,
                authority_host,
                target_port,
                Some(&baggage),
                Some(crate::modes::mesh::hbone::UDP_PROTOCOL),
            ),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(authority_host, target_port),
            message: format!(
                "timed out after {}ms waiting for sidecar mesh-mTLS datagram CONNECT response",
                effective_connect_timeout_ms
            ),
        })?
    }

    /// Open a WebSocket Extended CONNECT (RFC 8441) byte tunnel to a peer
    /// sidecar's inbound mTLS listener over a FRESH SVID-mTLS H2 connection. The
    /// connection is DIALED to `dial_host:mtls_port` (the peer's pod address +
    /// `:15006`/`mesh.mtls_port`); the Extended CONNECT `:authority` is the
    /// pre-built `authority` — the SERVICE routing key the peer's inbound
    /// WebSocket route matches on, computed by the caller with the same
    /// preserve-host / multi-port logic as the HTTP-family egress path so parity
    /// holds byte-for-byte. Separating them mirrors `proxy_to_backend_mesh_mtls`,
    /// where the dial target and the inner request authority are distinct.
    /// `path_and_query` is the client's request target (`:path`), preserved
    /// byte-for-byte so a non-root upgrade (`ws://svc-b/ws?room=1`) reaches the
    /// peer as `/ws?room=1` rather than `/` — the destination routes and builds
    /// the local backend WebSocket URL on the path the client requested.
    ///
    /// Unlike [`Self::open_connect_tunnel`] (pooled raw-TCP carriers) this is **1:1**: each
    /// WebSocket session gets its OWN mesh-mTLS H2 connection carrying exactly
    /// ONE Extended CONNECT stream (dropped when the session closes), NOT
    /// multiplexed over the pooled [`MeshMtlsSender`] connections. A proxied
    /// WebSocket already opens one dedicated backend connection bounded by
    /// `DestinationRule.maxConnections`, so a per-session H2 connection keeps
    /// long-lived sessions off the multiplexed HTTP pool; SVID rotation is
    /// automatic (every session dials with the current SVID).
    ///
    /// Unlike the bare raw-TCP CONNECT, this is an **Extended** CONNECT carrying
    /// `:protocol=websocket` and the forwardable WebSocket handshake headers
    /// (`Sec-WebSocket-Protocol`, etc.) — the destination sidecar's `:15006`
    /// listener (`auto`, advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`) treats it
    /// as a client-originated WebSocket upgrade and bridges it to the local app.
    /// The mTLS client certificate authenticates this gateway (no baggage,
    /// `marker = None`). Peer verification follows the caller's resolved
    /// [`MeshMtlsDialPlan`]: an IN-CLUSTER dial pins `expected_peer =
    /// Some(id)` with no SNI override; a CROSS-CLUSTER east-west dial passes
    /// `expected_peer = None` + `expected_trust_domain = Some(td)` +
    /// `sni_override = Some(dest_fqdn)` so the ClientHello SNI names the
    /// destination service (the remote gateway's passthrough routes on it) and
    /// verification is trust-domain-scoped (issue #2010). Fail-closed: a missing
    /// gateway SVID errors before the dial, and a peer that never negotiated
    /// Extended CONNECT errors before any stream is opened.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_ws_connect_tunnel(
        &self,
        proxy: &Proxy,
        dial_host: &str,
        _app_port: u16,
        app_policy_port: u16,
        mtls_port: u16,
        authority: &str,
        path_and_query: &str,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        ws_handshake_headers: &[(String, String)],
    ) -> Result<H2WsConnectTunnel, HbonePoolError> {
        // Fail closed when no gateway SVID is loaded — never dial a mesh peer
        // identity-less (parity with `open_connect_tunnel` and `get_sender`).
        let _ = self.current_svid_fingerprint_cached()?;
        let pool_config = self.pool_config.for_proxy(proxy);
        // DR keepalive override resolved for the destination's APP port, not
        // the transport `mtls_port`. `authority` carries the SERVICE routing
        // port for the inner request; the socket-level keepalive uses the
        // dial target's app port like the other mesh-mTLS sites.
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        // A WebSocket-over-mesh-mTLS session dials its OWN 1:1 connection, and
        // that connection's `maxConnections` slot is ALREADY held by the caller:
        // the WebSocket connect loop (`src/proxy/mod.rs`) reserves a session
        // guard on the caller's logical `(backend host, policy port)` lane before
        // this dial and holds it for the whole session. Admitting again here would
        // charge the one socket twice — and at `maxConnections: 1` the dial would refuse
        // itself, making every WebSocket upgrade to a capped mesh destination
        // fail. The session guard is the single owner; do NOT re-admit.
        // Registered like every pooled transport (issue #3859): a 1:1 WebSocket
        // bridge never enters the pool map either.
        let transport = dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            self.crls.load_full(),
            proxy,
            dial_host,
            mtls_port,
            // In-cluster: `Some(peer)` pins the workload identity, no SNI/TD
            // override. Cross-cluster: `None` peer + trust-domain scope + SNI
            // override to the destination service port's alias (the plan the caller
            // resolved via `MeshMtlsDialPlan`).
            expected_peer,
            expected_trust_domain,
            sni_override,
            &pool_config,
            keepalive_override,
            None,
            // Caller-owned admission (see above).
            None,
            self.trust_registry(),
            MeshTransportKind::MeshMtls,
            None,
            // The Sidecar mesh-mTLS CONNECT tunnel shares the raw-`h2` dial with
            // Ambient HBONE, so it inherits the same receive-side header-block
            // bound: hyper's 16 KiB, never `h2`'s 16 MiB default.
            crate::proxy::hbone_pool::HBONE_DEFAULT_MAX_HEADER_LIST_SIZE,
        )
        .await?;
        // The connect budget bounds the Extended CONNECT up to the peer's
        // response head; a refusal's optional body read runs after it, so an
        // in-time refusal is always relayed (GHSA-7x2j-3389-2h35).
        open_h2_ws_connect_stream_within(
            Duration::from_millis(proxy.backend_connect_timeout_ms),
            transport,
            authority,
            path_and_query,
            ws_handshake_headers,
            None,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_or_create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        _app_port: u16,
        app_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        key: &str,
        pool_config: &PoolConfig,
    ) -> Result<MeshMtlsTransport, HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        if let Some(transport) = self.cached_sender(key) {
            return Ok(transport);
        }

        let effective_connect_timeout_ms =
            self.effective_connect_timeout_ms(proxy, app_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let creation_started = Instant::now();
        let creation_slot = self.creation_slot(key);
        // Join the cohort BEFORE awaiting the lock: subscribing is what scopes
        // this caller to the attempt that is in flight right now, so it can be
        // released by that attempt's failure instead of repeating the dial
        // (issue #5046). Every waiter keeps its OWN `connect_timeout` here.
        let cohort = creation_slot.join();
        let joined = tokio::time::timeout(connect_timeout, cohort.wait()).await;
        let mut creation_lease = match joined {
            Ok(SharedCreationRole::Creator(lease)) => lease,
            Ok(SharedCreationRole::Failed(shared)) => return Err(shared.clone_for_broadcast()),
            Err(_) => {
                return Err(HbonePoolError::ConnectTimeout {
                    addr: format!("{target_host}:{mtls_port}"),
                    timeout_ms: effective_connect_timeout_ms,
                });
            }
        };
        // Double-check under the creation lock: a coalesced waiter may find the
        // winner's connection already inserted.
        if let Some(transport) = self.cached_sender(key) {
            return Ok(transport);
        }
        // A concurrent creator for this key failed while this caller was queued
        // for the creation lock: adopt that cohort's typed outcome instead of
        // repeating the same dial (issue #5046). Checked AFTER the cache
        // re-check so a usable connection always wins over a shared failure,
        // and before any budget is spent on a dial.
        if let Some(shared) = creation_lease.take_broadcast_failure() {
            return Err(shared.clone_for_broadcast());
        }

        self.dial_and_publish(
            Some(&creation_lease),
            proxy,
            target_host,
            app_policy_port,
            mtls_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            key,
            pool_config,
            max_entries,
            creation_started,
            connect_timeout,
            effective_connect_timeout_ms,
        )
        .await
    }

    fn effective_connect_timeout_ms(&self, proxy: &Proxy, app_policy_port: u16) -> u64 {
        proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms)
    }

    fn creation_slot(&self, key: &str) -> Arc<MeshMtlsCreationSlot> {
        self.creation_locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(MeshMtlsCreationSlot::new()))
            .clone()
    }

    /// Add one physical connection to a key that already has a usable one
    /// (issue #5043). Returns the new transport, or `None` whenever growth is
    /// not possible right now — the caller then serves on the connection it
    /// already checked out. Never waits for the creation lock: a cold dial or
    /// another grower in flight means "not now", not "queue".
    #[allow(clippy::too_many_arguments)]
    async fn try_grow_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        app_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        key: &str,
        pool_config: &PoolConfig,
        max_entries: usize,
    ) -> Option<MeshMtlsTransport> {
        if self
            .growth_backoff_until
            .get(key)
            .is_some_and(|until| *until.value() > unix_secs())
        {
            return None;
        }
        let creation_slot = self.creation_slot(key);
        let creation_lease = creation_slot.try_claim()?;
        // Re-check under the lock: a grower that failed between the read above
        // and this claim has published its backoff before releasing the lease,
        // and another grower may have widened the key (or a prune may have
        // narrowed it) since the fast-path read.
        if self
            .growth_backoff_until
            .get(key)
            .is_some_and(|until| *until.value() > unix_secs())
        {
            return None;
        }
        let live_connections = self
            .entries
            .get(key)
            .map(|entries| entries.value().len())
            .unwrap_or(0);
        if live_connections >= max_entries {
            return None;
        }
        let effective_connect_timeout_ms =
            self.effective_connect_timeout_ms(proxy, app_policy_port);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let dialed = self
            .dial_and_publish(
                None,
                proxy,
                target_host,
                app_policy_port,
                mtls_port,
                expected_peer,
                expected_trust_domain,
                sni_override,
                key,
                pool_config,
                max_entries,
                Instant::now(),
                connect_timeout,
                effective_connect_timeout_ms,
            )
            .await;
        let grown = match dialed {
            Ok(transport) => {
                debug!(
                    target_host,
                    mtls_port,
                    expected_peer = expected_peer_display(expected_peer),
                    connections = live_connections + 1,
                    max_connections = max_entries,
                    "Widened sidecar SVID-mTLS HTTP/2 pool under load"
                );
                Some(transport)
            }
            Err(err) => {
                // Measured from the failure, not the dial start, so a dial
                // that used its whole connect timeout still backs off the full
                // window. Recorded before the lock is released, and re-checked
                // after every claim, so once a dial has failed no other caller
                // starts a second one for the key in between. A dial whose
                // future is dropped (cancellation) records no backoff.
                self.growth_backoff_until
                    .insert(key.to_string(), unix_secs() + MESH_MTLS_GROWTH_BACKOFF_SECS);
                debug!(
                    target_host,
                    mtls_port,
                    expected_peer = expected_peer_display(expected_peer),
                    error = %err,
                    "Sidecar SVID-mTLS pool growth dial failed; continuing on existing connections"
                );
                None
            }
        };
        drop(creation_lease);
        grown
    }

    /// Dial one physical connection for `key` while holding its creation lock,
    /// then pool it if the TLS material it was built from is still current.
    /// `cohort` is the cold path's lease, whose waiters receive a dial failure
    /// (issue #5046); growth passes `None` because nobody is queued behind it.
    #[allow(clippy::too_many_arguments)]
    async fn dial_and_publish(
        &self,
        cohort: Option<&crate::pool::SharedCreationLease<'_, Arc<HbonePoolError>>>,
        proxy: &Proxy,
        target_host: &str,
        app_policy_port: u16,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        key: &str,
        pool_config: &PoolConfig,
        max_entries: usize,
        creation_started: Instant,
        connect_timeout: Duration,
        effective_connect_timeout_ms: u64,
    ) -> Result<MeshMtlsTransport, HbonePoolError> {
        let remaining = crate::pool::remaining_connect_timeout(creation_started, connect_timeout)
            .ok_or_else(|| HbonePoolError::ConnectTimeout {
            addr: format!("{target_host}:{mtls_port}"),
            timeout_ms: effective_connect_timeout_ms,
        })?;
        // Snapshot the SVID and CRL slots before dialing: the SPIFFE TLS
        // resolver/verifier use these snapshots for the handshake, so an
        // unchanged slot across the dial proves the session was built from the
        // material that is still current when it is pooled.
        let svid_slot_before_dial = self.gateway_svid.load_full();
        let crls_before_dial = self.crls.load_full();
        // Resolve the DR `connectionPool.tcp.tcpKeepalive` per-port override for
        // the destination's APP port (`app_port`), NOT the transport
        // `mtls_port` (always `:15006`). Falls back to the global pool
        // keepalive inside `create_sender` when absent.
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        let pooled_conn_admission = self.conn_admission(proxy, target_host, app_policy_port);
        // Constructed out of line so the TLS + hyper HTTP/2 handshake is not a
        // frame slot in `get_or_create_sender`. An H3 plain Sidecar attempt
        // already sits on a deep unoptimized poll stack; boxing here keeps
        // that handshake off the checkout coroutine.
        let create = self.boxed_create_sender(
            proxy,
            target_host,
            mtls_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            pool_config,
            keepalive_override,
            remaining,
            effective_connect_timeout_ms,
            crls_before_dial.clone(),
            pooled_conn_admission.as_ref(),
        );
        let transport = match tokio::time::timeout(remaining, create).await {
            Ok(Ok(transport)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::MeshMtls);
                transport
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
                // Release the whole cohort on this one physical dial: every
                // caller that joined while it was in flight gets the same typed
                // outcome rather than taking the lock and repeating it (issue
                // #5046). Published while the lock is still held, so no waiter
                // can slip past the broadcast. `record_pool_failure` stays on
                // the creator alone — one physical dial, one pool failure —
                // while each waiter still reports its own logical outcome.
                if let Some(cohort) = cohort {
                    cohort.publish_failure(Arc::new(err.clone_for_broadcast()));
                }
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
                // Deliberately NOT broadcast: this is the CREATOR's own connect
                // budget expiring, not evidence about the peer. A waiter may
                // have a longer deadline (per-port `connect_timeout_ms`
                // overrides are not part of the pool key), and #5046 requires
                // each waiter's original deadline to survive — so the lease
                // drops without publishing and the next waiter is elected as a
                // fresh creator with its own remaining budget.
                return Err(HbonePoolError::ConnectTimeout {
                    addr: format!("{target_host}:{mtls_port}"),
                    timeout_ms: effective_connect_timeout_ms,
                });
            }
        };
        // An SVID rotation or CRL reload drain may have fired while this dial was in
        // flight: pooling the sender under a retired-fingerprint key would
        // resurrect it AFTER its one-shot drain already ran, leaving an
        // old-identity session alive until idle pruning (forever with
        // `idle_timeout_seconds=0`). Serve the triggering request on the
        // connection, but only pool it while (a) the slot is unchanged across
        // the dial — catches same-leaf trust-bundle rotations the fingerprint
        // cannot see — (b) the CRL slot is unchanged across the dial, and (c)
        // the key's fingerprint is still the current one
        // — catches rotations between key construction and the slot snapshot.
        // Pre-drain inserts under a retired-but-undrained key are also
        // skipped, which merely costs those stragglers pooling during the
        // drain window.
        let svid_slot_unchanged =
            Arc::ptr_eq(&svid_slot_before_dial, &self.gateway_svid.load_full());
        let crls_unchanged = Arc::ptr_eq(&crls_before_dial, &self.crls.load_full());
        let key_fingerprint_is_current = self
            .current_svid_fingerprint_cached()
            .ok()
            .is_some_and(|current| mesh_mtls_key_svid_fingerprint(key) == Some(current.as_ref()));
        // A gateway trust withdrawal that landed between registration and here
        // already retired this transport; fail closed rather than pool or serve
        // it (issue #3859).
        if transport.is_retired() {
            return Err(HbonePoolError::TrustWithdrawn);
        }
        if !svid_slot_unchanged || !crls_unchanged || !key_fingerprint_is_current {
            debug!(
                target_host,
                mtls_port,
                expected_peer = expected_peer_display(expected_peer),
                "Sidecar SVID-mTLS connection completed under rotated TLS material; serving without pooling"
            );
            return Ok(transport);
        }
        self.entries
            .entry(key.to_string())
            .and_modify(|entries| {
                record_mesh_mtls_evictions(prune_pool_entries(entries));
                entries.push(MeshMtlsPoolEntry {
                    transport: transport.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                });
                if entries.len() > max_entries {
                    let overflow = entries.len() - max_entries;
                    entries.drain(0..overflow);
                    record_mesh_mtls_evictions(overflow);
                }
            })
            .or_insert_with(|| {
                vec![MeshMtlsPoolEntry {
                    transport: transport.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                }]
            });
        debug!(
            target_host,
            mtls_port,
            expected_peer = expected_peer_display(expected_peer),
            "Created sidecar SVID-mTLS HTTP/2 connection"
        );
        Ok(transport)
    }

    /// Exclusive-lock scan: prune dead/idle entries, return the least-loaded
    /// live multiplexed sender. Unlike the HBONE pool there is no
    /// Ready/Pending split — hyper's H2 sender accepts new streams as long as
    /// the connection is open (`is_closed()`); per-stream backpressure is
    /// awaited at send.
    fn cached_sender(&self, key: &str) -> Option<MeshMtlsTransport> {
        let mut entries = self.entries.get_mut(key)?;
        record_mesh_mtls_evictions(prune_pool_entries(&mut entries));
        let now = unix_secs();
        let chosen = select_least_pending(&entries, now).chosen?;
        let entry = &entries[chosen];
        entry.last_used_at.store(now, Ordering::Relaxed);
        Some(entry.transport.clone())
    }

    /// Shared-lock fast path mirroring the HBONE pool: pick the least-loaded
    /// live sender and refresh its recency via a relaxed store, avoiding the
    /// exclusive shard write lock. Returns the transport and how many
    /// connections the key currently holds (the growth decision's input).
    ///
    /// Any closed or idle-expired entry makes this a miss so the write path
    /// prunes it: that is what lets a key widened under load narrow again once
    /// the load is gone — least-pending selection breaks ties toward the
    /// lowest index, so the extra connections stop being used and expire.
    fn try_cached_sender_read(&self, key: &str) -> Option<(MeshMtlsTransport, usize)> {
        let entries = self.entries.get(key)?;
        let now = unix_secs();
        let selection = select_least_pending(entries.value(), now);
        if selection.stale {
            return None;
        }
        let entry = &entries.value()[selection.chosen?];
        entry.last_used_at.store(now, Ordering::Relaxed);
        Some((entry.transport.clone(), entries.value().len()))
    }

    fn maybe_prune_idle_entries(&self) {
        let now = unix_secs();
        let interval = idle_prune_interval_secs(&self.pool_config);
        let last = self.last_idle_prune_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < interval {
            return;
        }
        if self
            .last_idle_prune_unix_secs
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.entries.retain(|_, entries| {
            record_mesh_mtls_evictions(prune_pool_entries(entries));
            !entries.is_empty()
        });
        self.tunnel_entries.retain(|_, entries| {
            record_mesh_mtls_tunnel_evictions(prune_tunnel_entries(entries));
            !entries.is_empty()
        });
        self.creation_locks.retain(|key, lock| {
            self.entries.contains_key(key.as_str())
                || self.tunnel_entries.contains_key(key.as_str())
                || Arc::strong_count(lock) > 1
        });
        self.growth_backoff_until.retain(|_, until| *until > now);
    }

    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn boxed_create_sender<'a>(
        &'a self,
        proxy: &'a Proxy,
        target_host: &'a str,
        mtls_port: u16,
        expected_peer: Option<&'a SpiffeId>,
        expected_trust_domain: Option<&'a TrustDomain>,
        sni_override: Option<&'a str>,
        pool_config: &'a PoolConfig,
        keepalive_override: Option<&'a crate::config::types::TcpKeepaliveCfg>,
        connect_budget: Duration,
        effective_connect_timeout_ms: u64,
        crls: crate::tls::CrlList,
        conn_admission: Option<&'a crate::backend_conn_limit::PooledConnectionAdmission<'_>>,
    ) -> BoxedCreateSenderFuture<'a> {
        Box::pin(self.create_sender(
            proxy,
            target_host,
            mtls_port,
            expected_peer,
            expected_trust_domain,
            sni_override,
            pool_config,
            keepalive_override,
            connect_budget,
            effective_connect_timeout_ms,
            crls,
            conn_admission,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        mtls_port: u16,
        expected_peer: Option<&SpiffeId>,
        expected_trust_domain: Option<&TrustDomain>,
        sni_override: Option<&str>,
        pool_config: &PoolConfig,
        keepalive_override: Option<&crate::config::types::TcpKeepaliveCfg>,
        connect_budget: Duration,
        effective_connect_timeout_ms: u64,
        crls: crate::tls::CrlList,
        // DestinationRule `connectionPool.tcp.maxConnections` lane for the
        // destination's APP/service policy port. `None` = uncapped destination.
        // A reserved slot is handed to the spawned connection driver below, so
        // it retires exactly when this pooled mesh-mTLS connection closes.
        conn_admission: Option<&crate::backend_conn_limit::PooledConnectionAdmission<'_>>,
    ) -> Result<MeshMtlsTransport, HbonePoolError> {
        // Stamp the accepted trust generation BEFORE dialing (issue #3859); the
        // registration below refuses a ticket the withdrawal path has since
        // superseded, closing the creation race.
        let admission_ticket = self
            .trust_registry()
            .map(|registry| registry.admission_ticket());
        let trust_registry = self.trust_registry().cloned();
        let conn_slot = match conn_admission {
            Some(admission) => match admission.acquire() {
                Ok(slot) => Some(slot),
                Err(limit) => {
                    return Err(HbonePoolError::MaxConnectionsExceeded {
                        host: admission.host().to_string(),
                        port: admission.policy_port(),
                        current: limit.current,
                        cap: limit.cap,
                    });
                }
            },
            None => None,
        };
        let candidates = self
            .dns_cache
            .resolve_candidates(
                target_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| HbonePoolError::DnsLookup {
                host: target_host.to_string(),
                message: e.to_string(),
            })?;
        // Plain mesh HTTP over mTLS speaks h2 to the peer sidecar's frontend
        // (which advertises h2 and preface-sniffs via `auto`), so advertise h2
        // only.
        //
        // Peer verification:
        // - `Some(id)` (in-cluster) — the peer's server SVID URI SAN must EQUAL
        //   `id` exactly (pinned identity); `expected_trust_domain` is `None`
        //   (the pin already constrains the domain).
        // - `None` + `expected_trust_domain = Some(td)` (cross-cluster
        //   east-west) — TRUST-DOMAIN-SCOPED: the peer's SVID must be in EXACTLY
        //   `td` (the TARGET's remote trust domain) AND chain to a federated
        //   bundle — a federated cert from a DIFFERENT trust domain is rejected.
        //   No pod identity is pinned (the gateway LB-picks the workload). NOT
        //   unverified, and NOT any-federated.
        let tls_config = build_spiffe_outbound_config(
            self.gateway_svid.clone(),
            expected_peer.cloned(),
            expected_trust_domain.cloned(),
            vec![b"h2".to_vec()],
            crls,
        )?;
        let connector = TlsConnector::from(tls_config);
        // SNI: the destination service port's alias for a cross-cluster dial
        // (so the remote gateway's SNI passthrough routes the opaque TLS to the
        // destination workload), else the dial host (the normal in-cluster
        // path).
        let sni_host = sni_override.unwrap_or(target_host);
        let server_name =
            rustls::pki_types::ServerName::try_from(sni_host.to_string()).map_err(|e| {
                HbonePoolError::InvalidServerName {
                    host: sni_host.to_string(),
                    message: e.to_string(),
                }
            })?;

        crate::dns::connect_candidates(&candidates, mtls_port, connect_budget, |sock_addr| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            // One reservation, cloned per DNS candidate: a failed attempt drops
            // its clone, so only an established connection keeps the slot.
            let conn_slot = conn_slot.clone();
            let trust_registry = trust_registry.clone();
            async move {
                let tcp = crate::socket_opts::connect_with_socket_opts(sock_addr)
                    .await
                    .map_err(|source| HbonePoolError::Connect {
                        addr: sock_addr.to_string(),
                        source,
                    })?;
                let _ = tcp.set_nodelay(true);
                // Apply the app-port DR keepalive override to every candidate
                // socket, not only to the first TCP-successful address.
                crate::socket_opts::apply_pooled_tcp_keepalive(
                    "mesh_mtls_pool",
                    &tcp,
                    keepalive_override,
                    pool_config.enable_http_keep_alive,
                    pool_config.tcp_keepalive_seconds,
                );

                let tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|source| HbonePoolError::TlsHandshake {
                        host: target_host.to_string(),
                        source,
                    })?;
                if !matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2")) {
                    return Err(HbonePoolError::TlsHandshake {
                        host: target_host.to_string(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "peer did not negotiate ALPN h2",
                        ),
                    });
                }

                // The shared builder every H2 pool family uses: the DR stream
                // cap this pool keys on bounds outbound streams from the first
                // one, not only after the peer's SETTINGS (issue #7071).
                let builder = crate::pool::hyper_h2_client_builder(pool_config);

                let io = TokioIo::new(tls_stream);
                let (sender, connection) =
                    builder
                        .handshake(io)
                        .await
                        .map_err(|e| HbonePoolError::H2Handshake {
                            host: target_host.to_string(),
                            message: e.to_string(),
                        })?;

                // Admit the established transport under the generation it was
                // dialed with, BEFORE the driver is spawned and before the
                // sender can be pooled or served (issue #3859).
                let gate = MeshTransportGate::new();
                let registration: Option<Arc<MeshTransportRegistration>> =
                    match (trust_registry.as_ref(), admission_ticket) {
                        (Some(registry), Some(ticket)) => Some(
                            registry
                                .register(ticket, MeshTransportKind::MeshMtls, gate.clone())
                                .map_err(|_| HbonePoolError::TrustWithdrawn)?,
                        ),
                        _ => None,
                    };

                // TLS ALPN already proved H2 for this sidecar candidate.
                let driver_gate = gate.clone();
                tokio::spawn(async move {
                    // The `maxConnections` slot lives exactly as long as the
                    // connection driver, i.e. as long as the socket is open.
                    let _conn_slot = conn_slot;
                    // The registration lives exactly as long as the driver.
                    let _registration = registration;
                    tokio::pin!(connection);
                    tokio::select! {
                        biased;
                        // Trust withdrawal. Returning drops the HTTP/2
                        // connection so in-flight streams terminate. New
                        // streams are refused synchronously by
                        // `MeshMtlsSender::{ready,send_request}` consulting
                        // the gate; they must not wait for this driver to be
                        // scheduled.
                        () = driver_gate.cancelled() => {
                            debug!(
                                "mesh_mtls_pool: sidecar mTLS HTTP/2 connection retired after gateway trust withdrawal"
                            );
                        }
                        result = &mut connection => {
                            if let Err(e) = result {
                                debug!(
                                    "mesh_mtls_pool: sidecar mTLS HTTP/2 connection closed: {}",
                                    e
                                );
                            }
                        }
                    }
                });
                Ok(MeshMtlsSender::governed(sender, gate))
            }
        })
        .await
        .map(|(transport, _)| transport)
        .map_err(|error| match error {
            crate::dns::CandidateConnectError::TimedOut { last_addr } => {
                HbonePoolError::ConnectTimeout {
                    addr: last_addr.to_string(),
                    timeout_ms: effective_connect_timeout_ms,
                }
            }
            crate::dns::CandidateConnectError::Failed { source, .. } => source,
        })
    }

    /// Effective pool settings for a raw-TCP tunnel to `policy_port`
    /// (issue #7537): the proxy's pool fields, then the DestinationRule
    /// `connectionPool.http` settings the HTTP lane honours, with the same
    /// precedence `resolve_effective_proxy_for_target` applies there — the
    /// destination port's explicit `portLevelSettings` value, else the
    /// inherited top-level / selected-subset value carried as
    /// `dispatch_port_override_fallback`. The captured-egress relay proxies
    /// carry both maps, so `maxConcurrentStreams` bounds streams per carrier
    /// and `idleTimeout` evicts carriers for raw-TCP egress exactly as for HTTP.
    fn tunnel_pool_config(&self, proxy: &Proxy, policy_port: u16) -> PoolConfig {
        let mut pool_config = self.pool_config.for_proxy(proxy);
        let per_port = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|overrides| overrides.get(&policy_port));
        let fallback = proxy.dispatch_port_override_fallback.as_ref();
        if let Some(streams) = per_port
            .and_then(|o| o.h2_max_concurrent_streams)
            .or_else(|| fallback.and_then(|f| f.h2_max_concurrent_streams))
        {
            pool_config.http2_max_concurrent_streams = Some(streams.max(1));
        }
        if let Some(idle_ms) = per_port
            .and_then(|o| o.http_idle_timeout_ms)
            .or_else(|| fallback.and_then(|f| f.http_idle_timeout_ms))
        {
            pool_config.idle_timeout_seconds = idle_ms / 1000;
        }
        pool_config
    }

    /// Shared-lock fast path of the raw-TCP tunnel lane (issue #7537): reserve
    /// a stream slot on the least-loaded live carrier still under its stream
    /// cap. A miss (empty key, every carrier full, a closed carrier) falls
    /// through to [`Self::checkout_or_dial_tunnel`], whose write path prunes.
    /// No allocation; the reservation is one CAS.
    fn try_reserve_pooled_tunnel_carrier(
        &self,
        key: &str,
    ) -> Option<(MeshH2Transport, HboneStreamLease)> {
        let entries = self.tunnel_entries.get(key)?;
        reserve_tunnel_carrier(
            entries.value(),
            unix_secs(),
            self.tunnel_drain_generation.load(Ordering::Acquire),
        )
    }

    /// Exclusive-lock checkout of the tunnel lane: drop carriers from a drain
    /// generation that has since been retired, prune dead, retired,
    /// keepalive-failed, credential-expired and idle carriers, then reserve a
    /// slot on the least-loaded carrier with room, or report whether the key
    /// may widen.
    fn cached_tunnel_carrier(&self, key: &str, max_entries: usize) -> TunnelCheckout {
        let Some(mut entries) = self.tunnel_entries.get_mut(key) else {
            return TunnelCheckout::NeedsCarrier;
        };
        let generation = self.tunnel_drain_generation.load(Ordering::Acquire);
        let before = entries.len();
        entries.retain(|entry| entry.drain_generation == generation);
        record_mesh_mtls_tunnel_evictions(before - entries.len());
        record_mesh_mtls_tunnel_evictions(prune_tunnel_entries(&mut entries));
        let now = unix_secs();
        if let Some((transport, reservation)) = reserve_tunnel_carrier(&entries, now, generation) {
            return TunnelCheckout::Reserved(transport, reservation);
        }
        if select_least_loaded(&entries, now).live >= max_entries {
            TunnelCheckout::SaturatedAtWidth
        } else {
            TunnelCheckout::NeedsCarrier
        }
    }

    /// Open this tunnel's CONNECT stream on a carrier whose slot it reserved,
    /// bounded by the destination's connect timeout.
    async fn open_tunnel_stream(
        transport: MeshH2Transport,
        reservation: HboneStreamLease,
        fields: &MeshMtlsTunnelKey<'_>,
        connect_timeout: Duration,
        effective_connect_timeout_ms: u64,
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        tokio::time::timeout(
            connect_timeout,
            open_h2_connect_stream_reserved(
                transport,
                reservation,
                fields.authority_host,
                fields.target_port,
                None,
                None,
            ),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(fields.authority_host, fields.target_port),
            message: format!(
                "timed out after {}ms waiting for sidecar mesh-mTLS CONNECT response",
                effective_connect_timeout_ms
            ),
        })?
    }

    /// Slow path of the tunnel lane: open on a pooled carrier with room, wait
    /// for a stream slot when every carrier is full and the key is at its
    /// width, or dial one more carrier (coalesced with every other caller that
    /// reached the same conclusion for this key, issue #5046). Returns the
    /// opened tunnel and whether its carrier was dialed for it.
    ///
    /// A freshly dialed carrier is published only AFTER its first CONNECT
    /// response, while the creation lock is still held: that response cannot
    /// precede the peer's SETTINGS, so every caller queued behind the creator
    /// reserves against the peer's real `SETTINGS_MAX_CONCURRENT_STREAMS`
    /// rather than the configured seed, and a peer that allows fewer streams
    /// than the client cap makes the queue widen instead of parking streams
    /// inside `h2`.
    async fn checkout_or_dial_tunnel(
        &self,
        proxy: &Proxy,
        fields: &MeshMtlsTunnelKey<'_>,
        key: &str,
        pool_config: &PoolConfig,
        connect_timeout: Duration,
        effective_connect_timeout_ms: u64,
    ) -> Result<(H2ConnectTunnel, bool), HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        let started = Instant::now();
        let mut slot_wait = TunnelSlotWait::new(started, connect_timeout);
        loop {
            match self.cached_tunnel_carrier(key, max_entries) {
                TunnelCheckout::Reserved(transport, reservation) => {
                    slot_wait.admitted(&self.tunnel_counters);
                    let tunnel = Self::open_tunnel_stream(
                        transport,
                        reservation,
                        fields,
                        connect_timeout,
                        effective_connect_timeout_ms,
                    )
                    .await?;
                    return Ok((tunnel, false));
                }
                TunnelCheckout::SaturatedAtWidth => {
                    slot_wait
                        .wait(&self.tunnel_counters, fields, effective_connect_timeout_ms)
                        .await?;
                    continue;
                }
                TunnelCheckout::NeedsCarrier => {}
            }

            let Some(remaining) = crate::pool::remaining_connect_timeout(started, connect_timeout)
            else {
                return Err(HbonePoolError::ConnectTimeout {
                    addr: format!("{}:{}", fields.dial_host, fields.mtls_port),
                    timeout_ms: effective_connect_timeout_ms,
                });
            };
            let creation_slot = self.creation_slot(key);
            // Join the cohort BEFORE awaiting the lock so a failed dial in
            // flight releases this caller with its typed outcome (issue #5046).
            let cohort = creation_slot.join();
            let mut creation_lease = match tokio::time::timeout(remaining, cohort.wait()).await {
                Ok(SharedCreationRole::Creator(lease)) => lease,
                Ok(SharedCreationRole::Failed(shared)) => {
                    return Err(shared.clone_for_broadcast());
                }
                Err(_) => {
                    return Err(HbonePoolError::ConnectTimeout {
                        addr: format!("{}:{}", fields.dial_host, fields.mtls_port),
                        timeout_ms: effective_connect_timeout_ms,
                    });
                }
            };
            // Re-check under the creation lock: the creator this caller queued
            // behind may have published a carrier with room, or filled the key.
            match self.cached_tunnel_carrier(key, max_entries) {
                TunnelCheckout::Reserved(transport, reservation) => {
                    drop(creation_lease);
                    slot_wait.admitted(&self.tunnel_counters);
                    let tunnel = Self::open_tunnel_stream(
                        transport,
                        reservation,
                        fields,
                        connect_timeout,
                        effective_connect_timeout_ms,
                    )
                    .await?;
                    return Ok((tunnel, false));
                }
                TunnelCheckout::SaturatedAtWidth => {
                    drop(creation_lease);
                    slot_wait
                        .wait(&self.tunnel_counters, fields, effective_connect_timeout_ms)
                        .await?;
                    continue;
                }
                TunnelCheckout::NeedsCarrier => {}
            }
            if let Some(shared) = creation_lease.take_broadcast_failure() {
                return Err(shared.clone_for_broadcast());
            }
            let dialed = self
                .dial_tunnel_carrier(
                    &creation_lease,
                    proxy,
                    fields,
                    key,
                    pool_config,
                    started,
                    connect_timeout,
                    effective_connect_timeout_ms,
                )
                .await?;
            let carrier = dialed.transport.clone();
            let opened = Self::open_tunnel_stream(
                dialed.transport,
                dialed.reservation,
                fields,
                connect_timeout,
                effective_connect_timeout_ms,
            )
            .await;
            // A CONNECT the peer answered (accepted or refused) proves the
            // connection healthy and its SETTINGS applied; only then is it
            // offered to other tunnels.
            if dialed.poolable
                && matches!(&opened, Ok(_) | Err(HbonePoolError::ConnectRejected { .. }))
            {
                self.publish_tunnel_carrier(
                    key,
                    carrier,
                    dialed.drain_generation,
                    pool_config.idle_timeout_seconds,
                    max_entries,
                    fields,
                );
            }
            drop(creation_lease);
            return opened.map(|tunnel| (tunnel, true));
        }
    }

    /// Dial one raw-TCP tunnel carrier for `key` while holding its creation
    /// lock and reserve this tunnel's stream slot on it. The dial is the shared
    /// raw-`h2` SVID-mTLS dialer (`dial_h2_connect_sender`): it takes the
    /// destination's `maxConnections` slot (owned by the connection driver),
    /// registers the transport with the gateway trust registry, and arms
    /// HTTP/2 keepalive with an identity-safe eviction handle into this lane.
    /// Whether the carrier may be pooled is decided here from the SVID and CRL
    /// slots across the dial; publication itself is fenced by the lane's drain
    /// generation in [`Self::publish_tunnel_carrier`].
    #[allow(clippy::too_many_arguments)]
    async fn dial_tunnel_carrier(
        &self,
        cohort: &crate::pool::SharedCreationLease<'_, Arc<HbonePoolError>>,
        proxy: &Proxy,
        fields: &MeshMtlsTunnelKey<'_>,
        key: &str,
        pool_config: &PoolConfig,
        creation_started: Instant,
        connect_timeout: Duration,
        effective_connect_timeout_ms: u64,
    ) -> Result<DialedTunnelCarrier, HbonePoolError> {
        let remaining = crate::pool::remaining_connect_timeout(creation_started, connect_timeout)
            .ok_or_else(|| HbonePoolError::ConnectTimeout {
            addr: format!("{}:{}", fields.dial_host, fields.mtls_port),
            timeout_ms: effective_connect_timeout_ms,
        })?;
        // The drain generation is read BEFORE anything the dial is built from:
        // a drain that runs at any point after this (CRL reload, trust change,
        // rotation, `force_drain_all`) advances it, and the publish refuses a
        // carrier from an older generation.
        let drain_generation = self.tunnel_drain_generation.load(Ordering::Acquire);
        let svid_slot_before_dial = self.gateway_svid.load_full();
        let crls_before_dial = self.crls.load_full();
        // DR `tcpKeepalive` per-port override for the destination's APP /
        // service policy port, never the transport `:15006`.
        let keepalive_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&fields.policy_port))
            .and_then(|o| o.tcp_keepalive.as_ref());
        // The carrier is a physical connection, so it is admitted on the
        // destination's `maxConnections` lane (keyed by the dial peer + the
        // APP/service policy port, never `:15006`); the streams it carries take
        // no slot.
        let conn_admission = self.conn_admission(proxy, fields.dial_host, fields.policy_port);
        let carrier_config = tunnel_carrier_pool_config(pool_config);
        // Boxed so the TLS + HTTP/2 handshake is not a frame slot in the
        // captured-connection task that awaits `open_connect_tunnel`.
        let dial = Box::pin(dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            crls_before_dial.clone(),
            proxy,
            fields.dial_host,
            fields.mtls_port,
            fields.expected_peer,
            fields.expected_trust_domain,
            fields.sni_override,
            &carrier_config,
            keepalive_override,
            Some(remaining),
            conn_admission.as_ref(),
            self.trust_registry(),
            MeshTransportKind::MeshMtls,
            Some(HboneKeepalivePoolHandle::new(
                Arc::clone(&self.tunnel_entries),
                key.to_string(),
                crate::runtime_metrics::PoolKind::MeshMtlsTunnel,
            )),
            // Hyper's 16 KiB response header-block bound, never `h2`'s 16 MiB.
            crate::proxy::hbone_pool::HBONE_DEFAULT_MAX_HEADER_LIST_SIZE,
        ));
        let transport = match tokio::time::timeout(remaining, dial).await {
            Ok(Ok(transport)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::MeshMtlsTunnel);
                transport
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtlsTunnel);
                // One physical dial, one outcome for the whole cohort (#5046).
                cohort.publish_failure(Arc::new(err.clone_for_broadcast()));
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtlsTunnel);
                // The creator's own budget expiring is not evidence about the
                // peer: not broadcast, so each waiter keeps its own deadline.
                return Err(HbonePoolError::ConnectTimeout {
                    addr: format!("{}:{}", fields.dial_host, fields.mtls_port),
                    timeout_ms: effective_connect_timeout_ms,
                });
            }
        };
        self.tunnel_counters
            .connections_opened
            .fetch_add(1, Ordering::Relaxed);
        // A gateway trust withdrawal that landed between registration and here
        // already retired this transport: neither pool nor serve it (#3859).
        if transport.is_retired() {
            return Err(HbonePoolError::TrustWithdrawn);
        }
        // Reserve this tunnel's slot BEFORE the carrier can become visible.
        let reservation =
            transport
                .load
                .try_reserve()
                .ok_or_else(|| HbonePoolError::ConnectStream {
                    authority: authority_for_host_port(fields.authority_host, fields.target_port),
                    message: "freshly dialed sidecar mesh-mTLS connection has no stream slot"
                        .to_string(),
                })?;
        let svid_slot_unchanged =
            Arc::ptr_eq(&svid_slot_before_dial, &self.gateway_svid.load_full());
        let crls_unchanged = Arc::ptr_eq(&crls_before_dial, &self.crls.load_full());
        let key_fingerprint_is_current = self
            .current_svid_fingerprint_cached()
            .ok()
            .is_some_and(|current| mesh_mtls_key_svid_fingerprint(key) == Some(current.as_ref()));
        let poolable = !transport.keepalive_failed()
            && svid_slot_unchanged
            && crls_unchanged
            && key_fingerprint_is_current;
        if !poolable {
            debug!(
                dial_host = fields.dial_host,
                mtls_port = fields.mtls_port,
                expected_peer = expected_peer_display(fields.expected_peer),
                "Sidecar SVID-mTLS tunnel connection completed under rotated TLS material; serving without pooling"
            );
        }
        Ok(DialedTunnelCarrier {
            transport,
            reservation,
            poolable,
            drain_generation,
        })
    }

    /// Publish a carrier into the tunnel lane unless a drain ran since its dial
    /// began. The drain generation is compared while the key's shard is
    /// write-locked: every drain advances the generation BEFORE it clears or
    /// filters the map, so a publish either sees the advanced generation and
    /// refuses, or completes before the drain's own pass over that shard and is
    /// removed by it. Either way a carrier authenticated before a drain is
    /// never reachable after the drain returns.
    fn publish_tunnel_carrier(
        &self,
        key: &str,
        transport: MeshH2Transport,
        drain_generation: u64,
        idle_timeout_seconds: u64,
        max_entries: usize,
        fields: &MeshMtlsTunnelKey<'_>,
    ) {
        if transport.is_retired() || transport.keepalive_failed() {
            return;
        }
        let mut entries = self.tunnel_entries.entry(key.to_string()).or_default();
        if self.tunnel_drain_generation.load(Ordering::Acquire) != drain_generation {
            debug!(
                dial_host = fields.dial_host,
                mtls_port = fields.mtls_port,
                "Sidecar SVID-mTLS tunnel connection outlived a pool drain; serving without pooling"
            );
            return;
        }
        record_mesh_mtls_tunnel_evictions(prune_tunnel_entries(&mut entries));
        entries.push(HbonePoolEntry::new(
            transport,
            idle_timeout_seconds,
            drain_generation,
        ));
        if entries.len() > max_entries {
            let overflow = entries.len() - max_entries;
            entries.drain(0..overflow);
            record_mesh_mtls_tunnel_evictions(overflow);
        }
        debug!(
            dial_host = fields.dial_host,
            mtls_port = fields.mtls_port,
            expected_peer = expected_peer_display(fields.expected_peer),
            "Created sidecar SVID-mTLS raw-TCP tunnel connection"
        );
    }

    /// Advance the tunnel lane's drain generation. Every drain calls this
    /// FIRST, before it touches the map (see [`Self::publish_tunnel_carrier`]).
    fn advance_tunnel_drain_generation(&self) {
        self.tunnel_drain_generation.fetch_add(1, Ordering::AcqRel);
    }
}

/// SVID-fingerprint field of a mesh mTLS pool key:
/// `mesh-mtls|{host}|{app_port}|{mtls_port}|{dns_override}|{svid_fingerprint}|{peer}|{sni}|{td}|pool=...`
/// — keep the index (5) in sync with `write_mesh_mtls_pool_key`. The `{peer}`,
/// `{sni}`, and `{td}` discriminators were appended AFTER the fingerprint field
/// specifically so this positional parse did not move.
fn mesh_mtls_key_svid_fingerprint(key: &str) -> Option<&str> {
    key.split('|').nth(5)
}

/// `tracing` display for the optional expected-peer identity used in pool/debug
/// logs. `Some(id)` shows the pinned SPIFFE id; `None` shows the
/// trust-domain-only marker (cross-cluster east-west dials).
fn expected_peer_display(expected_peer: Option<&SpiffeId>) -> &str {
    match expected_peer {
        Some(peer) => peer.as_str(),
        None => "td-only",
    }
}

/// Outcome of scanning one key's connections for a checkout.
struct LeastPendingSelection {
    /// Index of the live, non-expired entry with the fewest pending response
    /// heads; ties go to the lowest index.
    chosen: Option<usize>,
    /// Whether the scan saw a closed or idle-expired entry that the write
    /// path should prune.
    stale: bool,
}

/// Measured-load selection (issue #5043): fewest unanswered requests wins, and
/// an exact tie prefers the earliest connection so light load concentrates on
/// one connection while the ones added under pressure idle out.
fn select_least_pending(entries: &[MeshMtlsPoolEntry], now: u64) -> LeastPendingSelection {
    let mut chosen: Option<(usize, usize)> = None;
    let mut stale = false;
    for (index, entry) in entries.iter().enumerate() {
        // A retired transport is never handed out again, even before its
        // socket has finished closing (issue #3859). One relaxed load.
        if entry.transport.is_closed()
            || entry_idle_expired(
                entry.last_used_at.load(Ordering::Relaxed),
                entry.idle_timeout_seconds,
                now,
            )
        {
            stale = true;
            continue;
        }
        let pending = entry.transport.pending_requests();
        if chosen.is_none_or(|(_, best)| pending < best) {
            chosen = Some((index, pending));
        }
    }
    LeastPendingSelection {
        chosen: chosen.map(|(index, _)| index),
        stale,
    }
}

fn prune_pool_entries(entries: &mut Vec<MeshMtlsPoolEntry>) -> usize {
    let before = entries.len();
    let now = unix_secs();
    entries.retain(|entry| {
        // Retired by a gateway trust withdrawal: evict without consulting the
        // socket at all (issue #3859).
        !entry.transport.is_closed()
            && !entry_idle_expired(
                entry.last_used_at.load(Ordering::Relaxed),
                entry.idle_timeout_seconds,
                now,
            )
    });
    before.saturating_sub(entries.len())
}

fn record_mesh_mtls_evictions(count: usize) {
    crate::runtime_metrics::global_ref()
        .record_pool_evictions(crate::runtime_metrics::PoolKind::MeshMtls, count as u64);
}

fn record_mesh_mtls_tunnel_evictions(count: usize) {
    crate::runtime_metrics::global_ref().record_pool_evictions(
        crate::runtime_metrics::PoolKind::MeshMtlsTunnel,
        count as u64,
    );
}

/// Seconds between idle sweeps: the global idle timeout clamped to `1..=60`,
/// or 60 when idle expiry is off globally (a per-proxy timeout may still
/// apply to individual entries).
fn idle_prune_interval_secs(pool_config: &PoolConfig) -> u64 {
    if pool_config.idle_timeout_seconds == 0 {
        60
    } else {
        pool_config.idle_timeout_seconds.clamp(1, 60)
    }
}

/// Periodic idle sweep for the Sidecar mesh-mTLS pool (issue #7182).
///
/// The rate-limited prune also runs on the cold create path, but a
/// destination that stops receiving lookups never reaches it, so without this
/// task its connections — sockets, DestinationRule `maxConnections` slots,
/// trust-registry registrations — would outlive `idleTimeout` indefinitely.
/// Holds only a `Weak` reference to the entry map, so the task ends with the
/// pool, exactly like the direct pools' sweepers. Spawned only inside a Tokio
/// runtime.
fn spawn_idle_entry_sweeper(
    entries: &Arc<DashMap<String, Vec<MeshMtlsPoolEntry>>>,
    pool_config: &PoolConfig,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak = Arc::downgrade(entries);
    let interval = Duration::from_secs(idle_prune_interval_secs(pool_config));
    handle.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(entries) = weak.upgrade() else { break };
            entries.retain(|_, entries| {
                record_mesh_mtls_evictions(prune_pool_entries(entries));
                !entries.is_empty()
            });
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn with_mesh_mtls_pool_key<R>(
    host: &str,
    app_port: u16,
    mtls_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&TrustDomain>,
    pool_config: &PoolConfig,
    f: impl FnOnce(&str) -> R,
) -> R {
    MESH_MTLS_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_mesh_mtls_pool_key(
            &mut buf,
            host,
            app_port,
            mtls_port,
            dns_override,
            svid_fingerprint,
            expected_peer,
            sni_override,
            expected_trust_domain,
            pool_config,
        );
        f(&buf)
    })
}

#[allow(clippy::too_many_arguments)]
fn write_mesh_mtls_pool_key(
    buf: &mut String,
    host: &str,
    app_port: u16,
    mtls_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&TrustDomain>,
    pool_config: &PoolConfig,
) {
    buf.clear();
    // The peer-verification mode is connection identity: a session verified
    // against one pinned SVID must never serve a target pinning another, and a
    // TRUST-DOMAIN-SCOPED / SNI-overridden cross-cluster session must NEVER
    // share a pooled connection with a pinned-peer one. The peer field is the
    // pinned SPIFFE id, or the `td-only` discriminator when verification is
    // trust-domain-only (`expected_peer == None`). The SNI override (the
    // destination FQDN on cross-cluster dials; empty otherwise) follows it so
    // two cross-cluster targets to the SAME gateway for DIFFERENT destination
    // services also keep isolated connections (each needs its own SNI). The
    // expected trust domain (the remote TD a cross-cluster session was VERIFIED
    // against; empty otherwise) follows the SNI so a session verified against
    // remote trust domain B is never reused for C. `peer`, `sni`, and `td` are
    // all appended AFTER `svid_fingerprint` so `mesh_mtls_key_svid_fingerprint`'s
    // positional parse (index 5) is unchanged. `app_port` mirrors the HBONE
    // key's target-port field: per-port siblings of a multi-port service keep
    // isolated connections.
    let _ = write!(
        buf,
        "mesh-mtls|{host}|{app_port}|{mtls_port}|{}|{svid_fingerprint}|{}|{}|{}",
        dns_override.unwrap_or_default(),
        expected_peer_display(expected_peer),
        sni_override.unwrap_or_default(),
        expected_trust_domain
            .map(TrustDomain::as_str)
            .unwrap_or_default()
    );
    write_pool_config_key(buf, pool_config);
}

thread_local! {
    static MESH_MTLS_TUNNEL_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(224));
}

/// Every field that pins a raw-TCP tunnel carrier's peer (issue #7537). Two
/// tunnels share a carrier only when every field is equal.
pub(crate) struct MeshMtlsTunnelKey<'a> {
    /// Network peer the carrier is dialed to (the peer pod in-cluster, the
    /// east-west gateway cross-cluster).
    pub(crate) dial_host: &'a str,
    /// CONNECT authority port (the destination workload's app port).
    pub(crate) target_port: u16,
    /// Peer sidecar inbound mTLS port (`:15006` or `mesh.mtls_port`).
    pub(crate) mtls_port: u16,
    pub(crate) dns_override: Option<&'a str>,
    /// This gateway's SVID leaf fingerprint. Index 5 of the key, the same
    /// index as the HTTP lane, so `mesh_mtls_key_svid_fingerprint` and the
    /// rotation drain read both lanes.
    pub(crate) svid_fingerprint: &'a str,
    /// Pinned destination identity (in-cluster), or `None` for the
    /// trust-domain-scoped cross-cluster dial (rendered `td-only`).
    pub(crate) expected_peer: Option<&'a SpiffeId>,
    /// Cross-cluster ClientHello SNI override.
    pub(crate) sni_override: Option<&'a str>,
    /// Cross-cluster remote trust domain the peer must belong to.
    pub(crate) expected_trust_domain: Option<&'a TrustDomain>,
    /// CONNECT authority host (the real destination workload), so a carrier
    /// only ever carries streams for one exact authority.
    pub(crate) authority_host: &'a str,
    /// DestinationRule policy port: the `maxConnections` lane the carrier's
    /// slot is charged to.
    pub(crate) policy_port: u16,
}

impl MeshMtlsTunnelKey<'_> {
    /// The key is `|`-delimited, so a free-text field containing `|` could
    /// make two different field tuples render the same key (or shift the
    /// fingerprint index the rotation drain parses). SPIFFE IDs and trust
    /// domains cannot contain `|` by construction; the remaining free-text
    /// fields are refused here, fail-closed, before any lookup or dial.
    fn delimiter_free(&self) -> Result<(), HbonePoolError> {
        let fields = [
            Some(self.dial_host),
            Some(self.authority_host),
            self.sni_override,
            self.dns_override,
        ];
        match fields
            .into_iter()
            .flatten()
            .find(|value| value.contains('|'))
        {
            Some(value) => Err(HbonePoolError::InvalidDialHostTag {
                value: value.to_string(),
                message: "sidecar mesh-mTLS tunnel dial metadata must not contain '|'".to_string(),
            }),
            None => Ok(()),
        }
    }
}

fn with_mesh_mtls_tunnel_pool_key<R>(
    fields: &MeshMtlsTunnelKey<'_>,
    pool_config: &PoolConfig,
    f: impl FnOnce(&str) -> R,
) -> R {
    MESH_MTLS_TUNNEL_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_mesh_mtls_tunnel_pool_key(&mut buf, fields, pool_config);
        f(&buf)
    })
}

/// `mesh-mtls-tcp|{dial_host}|{target_port}|{mtls_port}|{dns_override}|{svid_fingerprint}|{peer}|{sni}|{td}|{authority_host}|{policy_port}|pool=...`
///
/// The fingerprint is field 5, exactly as in `write_mesh_mtls_pool_key`, so
/// `mesh_mtls_key_svid_fingerprint` and `drain_retired_fingerprints` cover the
/// tunnel lane unchanged. The `mesh-mtls-tcp` prefix keeps the lane's keys
/// disjoint from the HTTP lane's in the shared `creation_locks` map.
pub(crate) fn write_mesh_mtls_tunnel_pool_key(
    buf: &mut String,
    fields: &MeshMtlsTunnelKey<'_>,
    pool_config: &PoolConfig,
) {
    buf.clear();
    let _ = write!(
        buf,
        "mesh-mtls-tcp|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        fields.dial_host,
        fields.target_port,
        fields.mtls_port,
        fields.dns_override.unwrap_or_default(),
        fields.svid_fingerprint,
        expected_peer_display(fields.expected_peer),
        fields.sni_override.unwrap_or_default(),
        fields
            .expected_trust_domain
            .map(TrustDomain::as_str)
            .unwrap_or_default(),
        fields.authority_host,
        fields.policy_port,
    );
    write_pool_config_key(buf, pool_config);
}

/// Reserve a stream slot on the least-loaded live carrier under its cap.
///
/// `select_least_loaded` (shared with the HBONE pool) skips retired,
/// keepalive-failed, credential-expired, idle-expired and saturated carriers;
/// the reservation is a CAS, so a racing checkout that took the last slot
/// makes this rescan instead of overshooting the cap. Bounded: at most one
/// rescan per entry.
fn reserve_tunnel_carrier(
    entries: &[HbonePoolEntry],
    now: u64,
    drain_generation: u64,
) -> Option<(MeshH2Transport, HboneStreamLease)> {
    for _ in 0..=entries.len() {
        let (index, _) = select_least_loaded(entries, now).chosen?;
        let entry = &entries[index];
        // A carrier from a retired drain generation is never reused; the
        // write path removes it.
        if entry.drain_generation != drain_generation {
            return None;
        }
        let Some(reservation) = entry.transport.load.try_reserve() else {
            continue;
        };
        // One liveness probe for the chosen carrier only: a closed connection
        // reports `Err` here and the write path prunes it.
        return match entry.transport.sender.clone().ready().now_or_never() {
            Some(Ok(sender)) => {
                entry.last_used_at.store(now, Ordering::Relaxed);
                Some((
                    MeshH2Transport {
                        sender,
                        gate: entry.transport.gate.clone(),
                        load: entry.transport.load.clone(),
                        credential_not_after: entry.transport.credential_not_after,
                    },
                    reservation,
                ))
            }
            _ => None,
        };
    }
    None
}

/// Bounded wait for a stream slot on a saturated, width-capped key: the
/// tunnel lane's overload behaviour (issue #7537). It never dials past
/// `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` and never opens a stream past a
/// carrier's cap; a burst above `cap × width` drains as sibling tunnels close,
/// or fails once the destination's connect timeout is spent. Polls with
/// exponential backoff (2 ms doubling to 50 ms): this runs only at overload,
/// and polling keeps every stream close free of any wake-up bookkeeping.
struct TunnelSlotWait {
    started: Instant,
    budget: Duration,
    next_sleep: Duration,
    waited: bool,
}

impl TunnelSlotWait {
    fn new(started: Instant, budget: Duration) -> Self {
        Self {
            started,
            budget,
            next_sleep: Duration::from_millis(2),
            waited: false,
        }
    }

    async fn wait(
        &mut self,
        counters: &MeshMtlsTunnelCounters,
        fields: &MeshMtlsTunnelKey<'_>,
        effective_connect_timeout_ms: u64,
    ) -> Result<(), HbonePoolError> {
        let Some(remaining) = crate::pool::remaining_connect_timeout(self.started, self.budget)
        else {
            counters
                .saturation_waits_timed_out
                .fetch_add(1, Ordering::Relaxed);
            return Err(HbonePoolError::ConnectStream {
                authority: authority_for_host_port(fields.authority_host, fields.target_port),
                message: format!(
                    "timed out after {effective_connect_timeout_ms}ms waiting for a stream slot: \
                     every pooled sidecar mesh-mTLS connection is at its stream cap and the \
                     pool is at its connection limit"
                ),
            });
        };
        if !self.waited {
            debug!(
                dial_host = fields.dial_host,
                mtls_port = fields.mtls_port,
                expected_peer = expected_peer_display(fields.expected_peer),
                "Every pooled sidecar mesh-mTLS tunnel connection is at its stream cap; waiting for a stream slot"
            );
        }
        self.waited = true;
        tokio::time::sleep(self.next_sleep.min(remaining)).await;
        self.next_sleep = (self.next_sleep * 2).min(MESH_MTLS_TUNNEL_SLOT_WAIT_MAX);
        Ok(())
    }

    fn admitted(&self, counters: &MeshMtlsTunnelCounters) {
        if self.waited {
            counters
                .saturation_waits_admitted
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// HTTP/2 settings a raw-TCP tunnel carrier is dialed with (issue #7537).
///
/// Every setting except the receive windows and the per-connection stream cap
/// is the effective pool config. A tunnel releases receive credit only as its
/// relay consumes bytes, so a stream whose captured client stops reading holds
/// up to one stream window of connection credit indefinitely. The windows are
/// therefore fixed (adaptive windowing is resolved through the same
/// `h2_window_sizes` floors the HBONE dial uses, then pinned) and sized by
/// [`connect_multiplex_flow_control`]: the connection window covers EVERY
/// stream the carrier admits at a full stream window, so even with all but one
/// of its streams stalled the remaining one still has a whole window. Where the
/// HTTP/2 window ceiling cannot hold that, the stream window shrinks and then
/// the per-carrier stream cap does; buffered memory stays bounded by open
/// streams × stream window, as it was with one connection per tunnel.
fn tunnel_carrier_pool_config(pool_config: &PoolConfig) -> PoolConfig {
    let (stream_window, connection_window) = h2_window_sizes(pool_config);
    let flow = connect_multiplex_flow_control(
        stream_window,
        connection_window,
        pool_config.http2_max_concurrent_streams,
    );
    let mut carrier = pool_config.clone();
    carrier.http2_adaptive_window = false;
    carrier.http2_initial_stream_window_size = flow.stream_window;
    carrier.http2_initial_connection_window_size = flow.connection_window;
    carrier.http2_max_concurrent_streams = Some(flow.max_streams);
    carrier
}

/// Test view of the tunnel carrier flow control:
/// `(stream window, connection window, streams per connection)`.
#[doc(hidden)]
pub fn tunnel_carrier_flow_control_for_tests(pool_config: &PoolConfig) -> (u32, u32, Option<u32>) {
    let carrier = tunnel_carrier_pool_config(pool_config);
    (
        carrier.http2_initial_stream_window_size,
        carrier.http2_initial_connection_window_size,
        carrier.http2_max_concurrent_streams,
    )
}

/// Test view of the tunnel lane's pool key.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn mesh_mtls_tunnel_pool_key_for_tests(
    dial_host: &str,
    target_port: u16,
    mtls_port: u16,
    svid_fingerprint: &str,
    expected_peer: Option<&SpiffeId>,
    sni_override: Option<&str>,
    expected_trust_domain: Option<&TrustDomain>,
    authority_host: &str,
    policy_port: u16,
    pool_config: &PoolConfig,
) -> String {
    let fields = MeshMtlsTunnelKey {
        dial_host,
        target_port,
        mtls_port,
        dns_override: None,
        svid_fingerprint,
        expected_peer,
        sni_override,
        expected_trust_domain,
        authority_host,
        policy_port,
    };
    with_mesh_mtls_tunnel_pool_key(&fields, pool_config, str::to_string)
}

/// Build CONNECT baggage for a mesh-mTLS datagram tunnel.
///
/// Ambient capture supplies workload + pod evidence. Sidecar / default callers
/// pass `None`, so the gateway SVID principal remains the source. Destination
/// authorization still validates either assertion through the shared trusted
/// assertor / trust-domain gates before using it.
fn datagram_tunnel_baggage(
    gateway_svid: &SharedSvidBundle,
    source_identity: Option<&crate::modes::mesh::hbone::UdpSourceIdentity>,
) -> Result<String, HbonePoolError> {
    // Re-read the bundle after `current_svid_fingerprint_cached`: rotation can
    // clear the slot between those loads. Ambient source evidence selects the
    // baggage principal, but it must never replace the gateway SVID required
    // to authenticate the tunnel itself.
    let snapshot = gateway_svid.load_full();
    let bundle = snapshot.as_ref().as_ref().ok_or(HbonePoolError::NoSvid)?;
    if let Some(source) = source_identity {
        return Ok(crate::modes::mesh::hbone::baggage_header_for_udp_source(
            source,
        ));
    }
    Ok(crate::modes::mesh::hbone::baggage_header_for_source(
        &bundle.spiffe_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsConfig;
    use crate::identity::spiffe::TrustDomain;
    use crate::identity::{TrustBundle, TrustBundleSet};
    use std::collections::HashMap;

    fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
        UpstreamTarget {
            host: "10.0.0.1".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 1,
            tags: tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            locality: None,
            path: None,
        }
    }

    #[test]
    fn mtls_tag_and_port_parse() {
        assert!(!target_mesh_mtls_enabled(&target_with_tags(&[])));
        assert!(target_mesh_mtls_enabled(&target_with_tags(&[(
            MESH_MTLS_TARGET_TAG,
            "true"
        )])));
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[])),
            ISTIO_SIDECAR_INBOUND_PORT
        );
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[(MESH_MTLS_PORT_TAG, "16006")])),
            16006
        );
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[(MESH_MTLS_PORT_TAG, "0")])),
            ISTIO_SIDECAR_INBOUND_PORT
        );
    }

    #[test]
    fn mtls_expected_peer_is_required_and_fails_closed() {
        // Absent tag: a mesh.mtls target without a pinned identity must error.
        let err =
            target_mesh_mtls_expected_peer(&target_with_tags(&[(MESH_MTLS_TARGET_TAG, "true")]))
                .expect_err("missing mesh.spiffe_id must fail closed");
        assert!(matches!(err, HbonePoolError::InvalidPeerSpiffeTag { .. }));

        // Corrupt tag: same fail-closed shape.
        let err = target_mesh_mtls_expected_peer(&target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_SPIFFE_ID_TAG, "not-a-spiffe-id"),
        ]))
        .expect_err("invalid mesh.spiffe_id must fail closed");
        assert!(matches!(err, HbonePoolError::InvalidPeerSpiffeTag { .. }));

        // Valid tag resolves to the pinned identity.
        let peer = target_mesh_mtls_expected_peer(&target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (
                MESH_SPIFFE_ID_TAG,
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
        ]))
        .expect("valid pinned identity");
        assert_eq!(
            peer.as_str(),
            "spiffe://cluster.local/ns/default/sa/reviews"
        );
    }

    #[test]
    fn cross_cluster_tag_and_eastwest_sni_parse() {
        // Absent tags: an ordinary (in-cluster) target is not cross-cluster and
        // carries no SNI override.
        let plain = target_with_tags(&[(MESH_MTLS_TARGET_TAG, "true")]);
        assert!(!target_mesh_mtls_cross_cluster(&plain));
        assert_eq!(target_mesh_mtls_eastwest_sni(&plain), None);

        // Cross-cluster target: the marker is boolish-true and the SNI override
        // is the destination FQDN.
        let xc = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, "svc-b.ferrum.svc.cluster.local"),
        ]);
        assert!(target_mesh_mtls_cross_cluster(&xc));
        assert_eq!(
            target_mesh_mtls_eastwest_sni(&xc),
            Some("svc-b.ferrum.svc.cluster.local")
        );

        // Empty SNI fails closed (None) so dispatch refuses the dial rather
        // than falling back to the gateway address as SNI.
        let empty_sni = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, ""),
        ]);
        assert!(target_mesh_mtls_cross_cluster(&empty_sni));
        assert_eq!(target_mesh_mtls_eastwest_sni(&empty_sni), None);
    }

    // ── Shared mesh-mTLS dial plan (issue #2010) ────────────────────────────
    //
    // `MeshMtlsDialPlan::resolve` is the single source of truth the HTTP/gRPC
    // dispatch (`proxy_to_backend_mesh_mtls`) and the WebSocket egress path
    // (`open_ws_connect_tunnel`) both consult, so the in-cluster-pinned vs
    // cross-cluster (east-west trust-domain-only + SNI-override) split cannot
    // drift between transports.

    #[test]
    fn dial_plan_in_cluster_pins_peer_no_override() {
        let target = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (
                MESH_SPIFFE_ID_TAG,
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
        ]);
        let plan = MeshMtlsDialPlan::resolve(&target).expect("in-cluster dial plan resolves");
        assert!(!plan.cross_cluster);
        assert_eq!(
            plan.expected_peer.as_ref().map(|p| p.as_str()),
            Some("spiffe://cluster.local/ns/default/sa/reviews"),
            "in-cluster dial pins the destination workload identity"
        );
        assert!(
            plan.expected_trust_domain.is_none(),
            "in-cluster verification is constrained by the pinned peer, not a trust-domain scope"
        );
        assert_eq!(
            plan.sni_override, None,
            "in-cluster SNI is the dial host, never overridden"
        );
    }

    #[test]
    fn dial_plan_in_cluster_missing_pin_fails_closed() {
        let target = target_with_tags(&[(MESH_MTLS_TARGET_TAG, "true")]);
        match MeshMtlsDialPlan::resolve(&target) {
            Err(MeshMtlsDialError::PinnedPeer(HbonePoolError::InvalidPeerSpiffeTag { .. })) => {}
            other => panic!("missing pinned identity must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn dial_plan_cross_cluster_wellformed_uses_trust_domain_and_sni_override() {
        let target = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, "svc-c.ferrum.svc.cluster.local"),
            (MESH_TRUST_DOMAIN_TAG, "cluster-b.local"),
        ]);
        let plan = MeshMtlsDialPlan::resolve(&target).expect("cross-cluster dial plan resolves");
        assert!(plan.cross_cluster);
        assert!(
            plan.expected_peer.is_none(),
            "cross-cluster east-west LB-picks the destination; no pod SPIFFE is pinned"
        );
        assert_eq!(
            plan.expected_trust_domain.as_ref().map(|td| td.as_str()),
            Some("cluster-b.local"),
            "verification is scoped to the remote trust domain"
        );
        assert_eq!(
            plan.sni_override,
            Some("svc-c.ferrum.svc.cluster.local"),
            "the ClientHello SNI is overridden to the destination service FQDN"
        );
    }

    #[test]
    fn dial_plan_cross_cluster_missing_metadata_fails_closed() {
        // Missing SNI (SNI checked first).
        let no_sni = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_TRUST_DOMAIN_TAG, "cluster-b.local"),
        ]);
        assert!(matches!(
            MeshMtlsDialPlan::resolve(&no_sni),
            Err(MeshMtlsDialError::MissingCrossClusterSni)
        ));

        // Empty SNI is treated as absent — never dial the gateway address as SNI.
        let empty_sni = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, ""),
            (MESH_TRUST_DOMAIN_TAG, "cluster-b.local"),
        ]);
        assert!(matches!(
            MeshMtlsDialPlan::resolve(&empty_sni),
            Err(MeshMtlsDialError::MissingCrossClusterSni)
        ));

        // SNI present, trust domain missing.
        let no_td = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, "svc-c.ferrum.svc.cluster.local"),
        ]);
        assert!(matches!(
            MeshMtlsDialPlan::resolve(&no_td),
            Err(MeshMtlsDialError::MissingCrossClusterTrustDomain)
        ));

        // Unparseable trust domain is treated as absent (fail closed).
        let bad_td = target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_CROSS_CLUSTER_TAG, "true"),
            (MESH_EASTWEST_SNI_TAG, "svc-c.ferrum.svc.cluster.local"),
            (MESH_TRUST_DOMAIN_TAG, "not a trust domain"),
        ]);
        assert!(matches!(
            MeshMtlsDialPlan::resolve(&bad_td),
            Err(MeshMtlsDialError::MissingCrossClusterTrustDomain)
        ));
    }

    #[tokio::test]
    async fn open_datagram_tunnel_fails_closed_without_svid() {
        // The Sidecar UDP datagram tunnel (#1808) must fail closed before dialing
        // when no gateway SVID is loaded, exactly like `open_connect_tunnel` —
        // never dial a mesh peer identity-less. This also proves the new function
        // is wired and reachable (it stamps the `udp` marker on the CONNECT, the
        // Sidecar counterpart of `HboneConnectionPool::get_datagram_tunnel`).
        let pool = MeshMtlsConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "backend_host": "10.0.0.1",
            "backend_port": 8080,
        }))
        .expect("minimal proxy");
        let peer = test_peer();
        // `H2ConnectTunnel` (the Ok type) is not `Debug`, so match rather than
        // `expect_err`.
        match pool
            .open_datagram_tunnel(
                &proxy,
                "10.0.0.1",
                "10.0.0.1",
                53,
                53,
                ISTIO_SIDECAR_INBOUND_PORT,
                Some(&peer),
                None,
                None,
                None,
            )
            .await
        {
            Err(HbonePoolError::NoSvid) => {}
            Err(other) => panic!("expected NoSvid, got {other:?}"),
            Ok(_) => panic!("a missing gateway SVID must fail the datagram dial closed"),
        }
    }

    #[tokio::test]
    async fn open_datagram_tunnel_fails_closed_without_svid_even_with_asserted_source() {
        // Ambient evidence cannot skip the gateway-SVID dial gate: the tunnel
        // still presents this proxy's client certificate.
        let pool = MeshMtlsConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let proxy: Proxy = serde_json::from_value(serde_json::json!({
            "backend_host": "10.0.0.1",
            "backend_port": 8080,
        }))
        .expect("minimal proxy");
        let peer = test_peer();
        let asserted = crate::modes::mesh::hbone::UdpSourceIdentity::new(
            SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/client").unwrap(),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        .expect("valid Ambient source evidence");
        match pool
            .open_datagram_tunnel(
                &proxy,
                "10.0.0.1",
                "10.0.0.1",
                53,
                53,
                ISTIO_SIDECAR_INBOUND_PORT,
                Some(&peer),
                None,
                None,
                Some(&asserted),
            )
            .await
        {
            Err(HbonePoolError::NoSvid) => {}
            Err(other) => panic!("expected NoSvid, got {other:?}"),
            Ok(_) => panic!("asserted Ambient identity must not bypass a missing gateway SVID"),
        }
    }

    #[test]
    fn datagram_tunnel_baggage_propagates_ambient_principal_and_pod_uid() {
        let gateway = Arc::new(ArcSwap::new(Arc::new(Some(svid_bundle(b"gateway-leaf")))));
        let asserted = crate::modes::mesh::hbone::UdpSourceIdentity::new(
            SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/client").unwrap(),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        .expect("valid Ambient source evidence");

        let header = datagram_tunnel_baggage(&gateway, Some(&asserted)).expect("baggage");
        let identity = crate::modes::mesh::hbone::HboneIdentity::from_baggage_header(&header);

        assert_eq!(identity.source_principal, Some(asserted.principal.clone()));
        assert_eq!(
            identity.source_pod_uid,
            crate::modes::mesh::node_waypoint::parse_pod_uid(&asserted.pod_uid).ok()
        );
    }

    #[test]
    fn datagram_tunnel_baggage_falls_back_to_gateway_svid_without_asserted_source() {
        let gateway_bundle = svid_bundle(b"gateway-leaf");
        let gateway_id = gateway_bundle.spiffe_id.clone();
        let gateway = Arc::new(ArcSwap::new(Arc::new(Some(gateway_bundle))));

        let header = datagram_tunnel_baggage(&gateway, None).expect("gateway baggage");
        let identity = crate::modes::mesh::hbone::HboneIdentity::from_baggage_header(&header);

        assert_eq!(identity.source_principal, Some(gateway_id));
        assert!(
            identity.source_pod_uid.is_none(),
            "Sidecar/default fallback must not invent a pod UID"
        );
    }

    #[test]
    fn datagram_tunnel_baggage_fails_closed_without_svid() {
        let gateway = Arc::new(ArcSwap::new(Arc::new(None)));
        let asserted = crate::modes::mesh::hbone::UdpSourceIdentity::new(
            SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/client").unwrap(),
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        )
        .expect("valid Ambient source evidence");

        assert!(matches!(
            datagram_tunnel_baggage(&gateway, None),
            Err(HbonePoolError::NoSvid)
        ));
        assert!(matches!(
            datagram_tunnel_baggage(&gateway, Some(&asserted)),
            Err(HbonePoolError::NoSvid)
        ));
    }

    #[test]
    fn datagram_tunnel_baggage_rejects_malformed_pod_uid_at_construction() {
        // Capture managers never stamp malformed evidence: `UdpSourceIdentity::new`
        // fails closed so open_datagram_tunnel never sees a forgeable/malformed UID.
        assert!(
            crate::modes::mesh::hbone::UdpSourceIdentity::new(
                SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/client").unwrap(),
                "not-a-uid",
            )
            .is_none(),
            "malformed pod UID must be rejected before CONNECT baggage is built"
        );
    }

    #[test]
    fn pool_key_partitions_by_peer_identity_and_svid() {
        let pool_config = PoolConfig::default();
        let peer_a = SpiffeId::new("spiffe://cluster.local/ns/default/sa/a").unwrap();
        let peer_b = SpiffeId::new("spiffe://cluster.local/ns/default/sa/b").unwrap();
        let key = |peer: &SpiffeId, fp: &str| {
            with_mesh_mtls_pool_key(
                "10.0.0.1",
                8080,
                15006,
                None,
                fp,
                Some(peer),
                None,
                None,
                &pool_config,
                |key| key.to_string(),
            )
        };
        assert_ne!(
            key(&peer_a, "fp"),
            key(&peer_b, "fp"),
            "different pinned identities must not share a session"
        );
        assert_ne!(
            key(&peer_a, "fp1"),
            key(&peer_a, "fp2"),
            "an SVID rotation must repartition the pool"
        );
        assert_eq!(key(&peer_a, "fp"), key(&peer_a, "fp"));
    }

    #[test]
    fn pool_key_isolates_trust_domain_only_and_sni_overridden_sessions() {
        // A cross-cluster (trust-domain-scoped) / SNI-overridden mesh-mTLS session
        // must NEVER share a pooled connection with a pinned-peer one, and two
        // cross-cluster targets to the same gateway for different destination
        // services must not share either. A session verified against one remote
        // trust domain must also never be reused for another.
        let pool_config = PoolConfig::default();
        let peer = test_peer();
        let td_b = TrustDomain::new("cluster-b.local").unwrap();
        let td_c = TrustDomain::new("cluster-c.local").unwrap();
        let key = |peer: Option<&SpiffeId>, sni: Option<&str>, td: Option<&TrustDomain>| {
            with_mesh_mtls_pool_key(
                "10.9.9.9", // east-west gateway address
                8080,
                15443,
                None,
                "fp",
                peer,
                sni,
                td,
                &pool_config,
                |key| key.to_string(),
            )
        };
        let pinned = key(Some(&peer), None, None);
        let td_only = key(None, Some("svc-b.ferrum.svc.cluster.local"), Some(&td_b));
        assert_ne!(
            pinned, td_only,
            "a trust-domain-scoped / SNI-overridden session must not share a pinned-peer connection"
        );
        // Same gateway + same td-only verification, different destination SNI.
        let td_only_other = key(None, Some("svc-c.ferrum.svc.cluster.local"), Some(&td_b));
        assert_ne!(
            td_only, td_only_other,
            "cross-cluster targets to the same gateway for different services need isolated pools"
        );
        // Same gateway + same SNI but a DIFFERENT expected trust domain: a session
        // verified against B must never be reused for C.
        let td_b_session = key(None, Some("svc-b.ferrum.svc.cluster.local"), Some(&td_b));
        let td_c_session = key(None, Some("svc-b.ferrum.svc.cluster.local"), Some(&td_c));
        assert_ne!(
            td_b_session, td_c_session,
            "a session verified against trust domain B must not be reused for trust domain C"
        );
        // The fingerprint field stays positionally parseable with the new
        // peer/SNI/td discriminators appended.
        assert_eq!(mesh_mtls_key_svid_fingerprint(&td_only), Some("fp"));
    }

    #[test]
    fn pool_key_partitions_by_app_port() {
        let pool_config = PoolConfig::default();
        let peer = test_peer();
        let key = |app_port: u16| {
            with_mesh_mtls_pool_key(
                "10.0.0.1",
                app_port,
                15006,
                None,
                "fp",
                Some(&peer),
                None,
                None,
                &pool_config,
                |key| key.to_string(),
            )
        };
        assert_ne!(
            key(8080),
            key(9090),
            "per-port siblings of a multi-port service must not share a session"
        );
    }

    fn svid_bundle(leaf: &[u8]) -> SvidBundle {
        let td = TrustDomain::new("cluster.local").unwrap();
        SvidBundle {
            spiffe_id: SpiffeId::from_parts(&td, "ns/default/sa/gateway").unwrap(),
            cert_chain_der: vec![leaf.to_vec()],
            private_key_pkcs8_der: Vec::new().into(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![],
                jwt_authorities: vec![],
                refresh_hint_seconds: None,
            }),
        }
    }

    fn test_peer() -> SpiffeId {
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/orders").unwrap()
    }

    fn key_for_fingerprint(host: &str, fingerprint: &str) -> String {
        with_mesh_mtls_pool_key(
            host,
            8080,
            ISTIO_SIDECAR_INBOUND_PORT,
            None,
            fingerprint,
            Some(&test_peer()),
            None,
            None,
            &PoolConfig::default(),
            |key| key.to_string(),
        )
    }

    fn insert_empty_entry(pool: &MeshMtlsConnectionPool, key: &str) {
        pool.entries.insert(key.to_string(), Vec::new());
        pool.creation_locks
            .insert(key.to_string(), Arc::new(MeshMtlsCreationSlot::new()));
    }

    #[test]
    fn mesh_mtls_key_svid_fingerprint_reads_fingerprint_field() {
        let key = key_for_fingerprint("orders.default.svc.cluster.local", "0123456789abcdef");

        assert_eq!(
            mesh_mtls_key_svid_fingerprint(&key),
            Some("0123456789abcdef")
        );
        assert_eq!(mesh_mtls_key_svid_fingerprint("not-a-pool-key"), None);
    }

    #[test]
    fn force_drain_svid_generation_removes_only_passed_generation() {
        let bundle_a = svid_bundle(b"generation-a-leaf");
        let fingerprint_a = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(7));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );

        // Traffic under generation 7 builds the identity cache for A.
        let cached_fp = pool.current_svid_fingerprint_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_a);
        let key_a = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_a);
        insert_empty_entry(&pool, &key_a);

        // Rotation A -> B: slot swap, then the rotation consumer bumps the
        // generation. Traffic under generation 8 builds B entries.
        let bundle_b = svid_bundle(b"generation-b-leaf");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        generation.store(8, Ordering::Release);
        let cached_fp = pool.current_svid_fingerprint_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_b);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        // Rotation B -> C before A's drain timer fires.
        let bundle_c = svid_bundle(b"generation-c-leaf");
        let fingerprint_c = svid_fingerprint(&bundle_c).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_c)));
        generation.store(9, Ordering::Release);
        let key_c = key_for_fingerprint("c.default.svc.cluster.local", &fingerprint_c);
        insert_empty_entry(&pool, &key_c);

        // A's delayed drain must remove only generation-7 (fingerprint A)
        // entries: B's own drain window has not elapsed yet.
        pool.force_drain_svid_generation(7);
        assert!(!pool.entries.contains_key(&key_a));
        assert!(pool.entries.contains_key(&key_b));
        assert!(pool.entries.contains_key(&key_c));
        assert!(!pool.creation_locks.contains_key(&key_a));
        assert!(pool.creation_locks.contains_key(&key_b));
        assert!(pool.creation_locks.contains_key(&key_c));

        // B's drain removes B; C (current) stays.
        pool.force_drain_svid_generation(8);
        assert!(!pool.entries.contains_key(&key_b));
        assert!(pool.entries.contains_key(&key_c));
        assert!(!pool.creation_locks.contains_key(&key_b));
        assert!(pool.creation_locks.contains_key(&key_c));
    }

    #[test]
    fn force_drain_svid_generation_records_rotation_with_no_traffic() {
        // No sidecar mTLS request runs between the slot swap and the drain
        // timer: the drain itself must refresh the identity cache, record the
        // outgoing fingerprint, and still drain the old generation.
        let bundle_a = svid_bundle(b"idle-generation-a");
        let fingerprint_a = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(3));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );

        let cached_fp = pool.current_svid_fingerprint_cached().unwrap();
        assert_eq!(cached_fp.as_ref(), fingerprint_a);
        let key_a = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_a);
        insert_empty_entry(&pool, &key_a);

        let bundle_b = svid_bundle(b"idle-generation-b");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        generation.store(4, Ordering::Release);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        pool.force_drain_svid_generation(3);
        assert!(!pool.entries.contains_key(&key_a));
        assert!(pool.entries.contains_key(&key_b));

        // Draining the current generation is a no-op: nothing was retired
        // under it.
        pool.force_drain_svid_generation(4);
        assert!(pool.entries.contains_key(&key_b));
    }

    #[test]
    fn force_drain_svid_generation_drains_all_without_svid() {
        let pool = MeshMtlsConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let key = key_for_fingerprint("a.default.svc.cluster.local", "anyfingerprint");
        insert_empty_entry(&pool, &key);

        pool.force_drain_svid_generation(1);

        assert!(pool.entries.is_empty());
        assert!(pool.creation_locks.is_empty());
    }

    #[test]
    fn force_drain_sweeps_generations_at_or_below_passed() {
        // The slot-swap → generation-store race can file a fingerprint one
        // generation too low (see `force_drain_svid_generation` docs). A
        // record misfiled under an already-drained generation must be picked
        // up by the next drain rather than leaking until idle pruning.
        let bundle_a = svid_bundle(b"sweep-generation-a");
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(7));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_fingerprint_cached().unwrap();

        // Race: the slot swaps to B and traffic rebuilds the cache while the
        // rotation consumer has not stored generation 8 yet, so B is stamped
        // with generation 7.
        let bundle_b = svid_bundle(b"sweep-generation-b");
        let fingerprint_b = svid_fingerprint(&bundle_b).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_b)));
        pool.current_svid_fingerprint_cached().unwrap();
        // Generation 7's drain fires and consumes A's record.
        pool.force_drain_svid_generation(7);
        generation.store(8, Ordering::Release);
        let key_b = key_for_fingerprint("b.default.svc.cluster.local", &fingerprint_b);
        insert_empty_entry(&pool, &key_b);

        // Rotation B -> C files B's fingerprint under its (stale) stamped
        // generation 7 — a generation whose drain already ran.
        let bundle_c = svid_bundle(b"sweep-generation-c");
        let fingerprint_c = svid_fingerprint(&bundle_c).unwrap();
        gateway_svid.store(Arc::new(Some(bundle_c)));
        generation.store(9, Ordering::Release);
        pool.current_svid_fingerprint_cached().unwrap();
        let key_c = key_for_fingerprint("c.default.svc.cluster.local", &fingerprint_c);
        insert_empty_entry(&pool, &key_c);

        // Generation 8's drain must sweep the misfiled record; C (newer)
        // stays untouched.
        pool.force_drain_svid_generation(8);
        assert!(
            !pool.entries.contains_key(&key_b),
            "record misfiled under an already-drained generation must be swept by the next drain"
        );
        assert!(pool.entries.contains_key(&key_c));
    }

    #[test]
    fn trust_bundle_only_rotation_retires_current_fingerprint() {
        // A trust-bundle-only reload keeps the leaf (and thus the
        // fingerprint) but still publishes a rotation: sessions verified
        // against the previous bundle must not outlive the drain window even
        // though their keys collide with current ones.
        let bundle_a = svid_bundle(b"bundle-rotation-leaf");
        let fingerprint = svid_fingerprint(&bundle_a).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_a))));
        let generation = Arc::new(AtomicU64::new(5));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_fingerprint_cached().unwrap();
        let key = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint);
        insert_empty_entry(&pool, &key);

        // Same leaf, fresh slot store (the rotation watcher is change-gated,
        // so any store is a genuine material change — here: new trust
        // bundle). No traffic runs before the drain.
        gateway_svid.store(Arc::new(Some(svid_bundle(b"bundle-rotation-leaf"))));
        generation.store(6, Ordering::Release);

        pool.force_drain_svid_generation(5);
        assert!(
            !pool.entries.contains_key(&key),
            "old-trust-bundle sessions must drain even when the leaf fingerprint is unchanged"
        );
    }

    #[test]
    fn capped_registry_eviction_drains_evicted_generations() {
        let bundle_0 = svid_bundle(b"evict-leaf-0");
        let fingerprint_0 = svid_fingerprint(&bundle_0).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_0))));
        let generation = Arc::new(AtomicU64::new(0));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_fingerprint_cached().unwrap();
        let key_0 = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_0);
        insert_empty_entry(&pool, &key_0);

        // Rotation storm overflows the registry; generation 0's record is
        // evicted before any drain timer fires — its entries must drain at
        // eviction instead of leaking until idle pruning.
        for revision in 1..=(MAX_RETIRED_SVID_GENERATIONS as u64 + 2) {
            let leaf = format!("evict-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            generation.store(revision, Ordering::Release);
            pool.current_svid_fingerprint_cached().unwrap();
        }

        assert!(
            !pool.entries.contains_key(&key_0),
            "registry cap eviction must drain the evicted generation's entries"
        );
        assert!(pool.retired_svid_fingerprints.len() <= MAX_RETIRED_SVID_GENERATIONS);
    }

    #[test]
    fn per_generation_retired_list_is_capped_and_drains_overflow() {
        let bundle_0 = svid_bundle(b"frozen-leaf-0");
        let fingerprint_0 = svid_fingerprint(&bundle_0).unwrap();
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle_0))));
        // Frozen generation counter: a starved rotation consumer stamps every
        // rotation with the same generation, funnelling all retirements into
        // one bucket.
        let generation = Arc::new(AtomicU64::new(3));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_fingerprint_cached().unwrap();
        let key_0 = key_for_fingerprint("a.default.svc.cluster.local", &fingerprint_0);
        insert_empty_entry(&pool, &key_0);

        for revision in 1..=(MAX_RETIRED_FINGERPRINTS_PER_GENERATION as u64 * 2) {
            let leaf = format!("frozen-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            pool.current_svid_fingerprint_cached().unwrap();
        }

        let bucket_len = pool
            .retired_svid_fingerprints
            .get(&3)
            .map(|bucket| bucket.len())
            .unwrap_or(0);
        assert!(
            bucket_len <= MAX_RETIRED_FINGERPRINTS_PER_GENERATION,
            "per-generation bucket must stay bounded under a frozen generation counter"
        );
        assert!(
            !pool.entries.contains_key(&key_0),
            "fingerprints evicted from a full bucket must drain their entries"
        );
    }

    #[test]
    fn retired_fingerprint_registry_is_capped() {
        let bundle = svid_bundle(b"cap-initial-leaf");
        let gateway_svid = Arc::new(ArcSwap::new(Arc::new(Some(bundle))));
        let generation = Arc::new(AtomicU64::new(0));
        let pool = MeshMtlsConnectionPool::new_with_svid_generation(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            gateway_svid.clone(),
            4,
            generation.clone(),
        );
        pool.current_svid_fingerprint_cached().unwrap();

        // Rotation storm with the drain window disabled: nothing consumes the
        // retired records, so the registry must stay capped.
        for revision in 1..=(MAX_RETIRED_SVID_GENERATIONS as u64 * 3) {
            let leaf = format!("cap-leaf-{revision}");
            gateway_svid.store(Arc::new(Some(svid_bundle(leaf.as_bytes()))));
            generation.store(revision, Ordering::Release);
            pool.current_svid_fingerprint_cached().unwrap();
        }

        assert!(pool.retired_svid_fingerprints.len() <= MAX_RETIRED_SVID_GENERATIONS);
    }
}

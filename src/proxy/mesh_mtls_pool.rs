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

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::dns::DnsCache;
use crate::identity::{SharedSvidBundle, SpiffeId, SvidBundle, TrustDomain};
use crate::proxy::body::SizeLimitedIncoming;
use crate::tls::backend::BackendSvidGeneration;
use crate::tls::spiffe::build_spiffe_outbound_config;

use super::hbone_pool::{
    H2ConnectTunnel, H2WsConnectTunnel, HbonePoolError, MESH_SPIFFE_ID_TAG,
    authority_for_host_port, dial_h2_connect_sender, entry_idle_expired, matches_boolish_true,
    open_h2_connect_stream, open_h2_ws_connect_stream, svid_fingerprint,
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
/// `:authority` must name. Stamped ONLY by `sidecar`-topology mesh service
/// discovery (the gateway-to-mesh bridge): a north-south gateway's client
/// `Host` is typically a public hostname (and without `preserve_host_header`
/// the authority falls back to the pod dial address), neither of which the
/// destination sidecar's materialized inbound routes match — so dispatch
/// forces this service host (`<service>.<namespace>.svc`, one of the
/// destination's registered host variants) as the `:authority` instead. The
/// original client `Host` still rides `x-forwarded-host`. Mesh-mode egress
/// never stamps this tag: its outbound routes are host-routed by the service
/// name, so the client authority is already the routing key the peer matches.
pub const MESH_MTLS_AUTHORITY_HOST_TAG: &str = "mesh.mtls_authority_host";
/// Outer network dial host for a Sidecar cross-cluster L4 tunnel. The target's
/// `host` remains a scoped synthetic workload identity for LB/health maps while
/// this tag carries the remote east-west gateway address. Absent means the
/// normal in-cluster shape where `target.host` is dialed directly.
pub const MESH_MTLS_DIAL_HOST_TAG: &str = "mesh.mtls_dial_host";
/// Tag overriding the ClientHello SNI of a Sidecar mesh-mTLS dial. Value = the
/// DESTINATION service FQDN. Stamped ONLY on cross-cluster east-west targets
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

/// Multiplexed hyper H2 sender over the SVID-mTLS session. The body type is
/// [`SizeLimitedIncoming`] so dispatch enforces `max_request_body_size_bytes`
/// on the streamed request body exactly like the HBONE path.
pub type MeshMtlsSender = http2::SendRequest<SizeLimitedIncoming>;

thread_local! {
    static MESH_MTLS_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(192));
}

struct MeshMtlsPoolEntry {
    sender: MeshMtlsSender,
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
///   destination service FQDN (`mesh.eastwest_sni`). Both are mandatory —
///   a missing one fails closed.
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
    /// ClientHello SNI override = the destination service FQDN (cross-cluster
    /// only); `None` in-cluster (SNI = the dial host). Borrowed from the target
    /// tag to avoid a per-dispatch allocation.
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

pub struct MeshMtlsConnectionPool {
    entries: DashMap<String, Vec<MeshMtlsPoolEntry>>,
    creation_locks: DashMap<String, Arc<Mutex<()>>>,
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
}

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
    #[allow(dead_code)] // Used by tests and external lib callers; binary wires the shared generation counter.
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
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
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
        }
    }

    pub fn pool_size(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
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
        self.creation_locks
            .retain(|key, _| !fingerprint_retired(key));
        record_mesh_mtls_evictions(evicted);
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

    pub fn force_drain_all(&self) {
        let evicted = self.pool_size();
        self.entries.clear();
        self.creation_locks.clear();
        self.retired_svid_fingerprints.clear();
        record_mesh_mtls_evictions(evicted);
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
    /// destination service FQDN so the gateway's SNI passthrough routes the
    /// opaque TLS to the destination workload); `None` uses `target_host`.
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
        if let Some(sender) = fast_sender {
            return Ok(sender);
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
    /// listener (`:15006`, or the `mesh.mtls_port`-tagged override) over a
    /// FRESH SVID-mTLS H2 connection. `target_host:target_port` is the
    /// destination workload's address and app (container) port — the CONNECT
    /// `:authority` the peer's transport-agnostic inbound relay dials locally.
    ///
    /// Unlike HTTP-family Sidecar egress (which multiplexes over the pooled
    /// [`MeshMtlsSender`] connections) and Ambient raw-TCP egress (which
    /// multiplexes over the shared HBONE pool), each captured raw-TCP stream
    /// gets its OWN mesh-mTLS H2 connection carrying exactly ONE CONNECT
    /// stream (1:1, dropped when the stream closes). `dial_host` is the peer
    /// pod in-cluster or the east-west gateway cross-cluster;
    /// `authority_host:target_port` is always the real destination workload.
    /// Raw-TCP streams are
    /// long-lived, so the handshake amortizes over the connection's lifetime,
    /// and SVID rotation is automatic because every new stream dials with the
    /// current SVID. Pooling these tunnels is a documented follow-up.
    ///
    /// The CONNECT is BARE — no `x-ferrum-mesh-protocol` marker and no W3C
    /// baggage: the peer authenticates this gateway by its mTLS client
    /// certificate (one sidecar SVID == one workload identity), and the
    /// destination's inbound relay (`build_inbound_hbone_relay_proxy`, gated by
    /// `is_hbone_connect` + `mesh_direction == Inbound`, which a bare H2 CONNECT
    /// satisfies) dials the authority. Fail-closed: a missing gateway SVID
    /// errors before the dial. In-cluster dials pin `expected_peer`; cross-
    /// cluster dials use the caller's trust-domain scope + SNI override.
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
        // Fail closed when no gateway SVID is loaded — never dial a mesh peer
        // identity-less (parity with `get_sender` and the HBONE raw-TCP path).
        let _ = self.current_svid_fingerprint_cached()?;
        let pool_config = self.pool_config.for_proxy(proxy);
        // DR keepalive override resolved for the destination's APP port
        // (`target_port`), not the transport `mtls_port`.
        let port_override = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&target_policy_port));
        let keepalive_override = port_override.and_then(|o| o.tcp_keepalive.as_ref());
        let effective_connect_timeout_ms = port_override
            .and_then(|o| o.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let sender = dial_h2_connect_sender(
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
        )
        .await?;
        tokio::time::timeout(
            connect_timeout,
            open_h2_connect_stream(sender, authority_host, target_port, None, None),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(authority_host, target_port),
            message: format!(
                "timed out after {}ms waiting for sidecar mesh-mTLS CONNECT response",
                effective_connect_timeout_ms
            ),
        })?
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
    /// Like [`Self::open_connect_tunnel`] each UDP session gets its OWN
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
    ) -> Result<H2ConnectTunnel, HbonePoolError> {
        // Fail closed when no gateway SVID is loaded — never dial a mesh peer
        // identity-less (parity with `open_connect_tunnel` and `get_sender`).
        // This also drives the rotation/retired-fingerprint bookkeeping.
        let _ = self.current_svid_fingerprint_cached()?;
        // The datagram path (unlike the byte-stream / WS mesh-mTLS paths) carries
        // the W3C source-identity baggage, so read the source SPIFFE id from the
        // current SVID bundle. `current_svid_fingerprint_cached` above already
        // proved a bundle is present, but the slot can rotate to empty between the
        // two loads, so this re-checks and fails closed rather than dialing
        // identity-less. The `MeshMtlsConnectionPool` identity cache stores only
        // the fingerprint (no SPIFFE id — the other transports need none), so the
        // id is read directly off the bundle here.
        let source_identity = {
            let snapshot = self.gateway_svid.load_full();
            let bundle = snapshot.as_ref().as_ref().ok_or(HbonePoolError::NoSvid)?;
            bundle.spiffe_id.clone()
        };
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
        let sender = dial_h2_connect_sender(
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
        )
        .await?;
        let baggage = crate::modes::mesh::hbone::baggage_header_for_source(&source_identity);
        tokio::time::timeout(
            connect_timeout,
            open_h2_connect_stream(
                sender,
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
    /// Like [`Self::open_connect_tunnel`] (raw-TCP egress) this is **1:1**: each
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
        let sender = dial_h2_connect_sender(
            &self.dns_cache,
            &self.gateway_svid,
            self.crls.load_full(),
            proxy,
            dial_host,
            mtls_port,
            // In-cluster: `Some(peer)` pins the workload identity, no SNI/TD
            // override. Cross-cluster: `None` peer + trust-domain scope + SNI
            // override to the destination service FQDN (the plan the caller
            // resolved via `MeshMtlsDialPlan`).
            expected_peer,
            expected_trust_domain,
            sni_override,
            &pool_config,
            keepalive_override,
            None,
        )
        .await?;
        tokio::time::timeout(
            Duration::from_millis(proxy.backend_connect_timeout_ms),
            open_h2_ws_connect_stream(
                sender,
                authority,
                path_and_query,
                ws_handshake_headers,
                None,
                None,
            ),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority.to_string(),
            message: format!(
                "timed out after {}ms waiting for sidecar mesh-mTLS WebSocket Extended CONNECT \
                 response",
                proxy.backend_connect_timeout_ms
            ),
        })?
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
    ) -> Result<MeshMtlsSender, HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        if let Some(sender) = self.cached_sender(key, max_entries) {
            return Ok(sender);
        }

        let effective_connect_timeout_ms = proxy
            .dispatch_port_overrides
            .as_ref()
            .and_then(|m| m.get(&app_policy_port))
            .and_then(|o| o.connect_timeout_ms)
            .unwrap_or(proxy.backend_connect_timeout_ms);
        let connect_timeout = Duration::from_millis(effective_connect_timeout_ms);
        let creation_started = Instant::now();
        let creation_lock = self
            .creation_locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _creation_guard = tokio::time::timeout(connect_timeout, creation_lock.lock())
            .await
            .map_err(|_| HbonePoolError::ConnectTimeout {
                addr: format!("{target_host}:{mtls_port}"),
                timeout_ms: effective_connect_timeout_ms,
            })?;
        // Double-check under the creation lock: a coalesced waiter may find the
        // winner's connection already inserted.
        if let Some(sender) = self.cached_sender(key, max_entries) {
            return Ok(sender);
        }

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
        let sender = match tokio::time::timeout(
            remaining,
            self.create_sender(
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
            ),
        )
        .await
        {
            Ok(Ok(sender)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::MeshMtls);
                sender
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
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
        if !svid_slot_unchanged || !crls_unchanged || !key_fingerprint_is_current {
            debug!(
                target_host,
                mtls_port,
                expected_peer = expected_peer_display(expected_peer),
                "Sidecar SVID-mTLS connection completed under rotated TLS material; serving without pooling"
            );
            return Ok(sender);
        }
        self.entries
            .entry(key.to_string())
            .and_modify(|entries| {
                record_mesh_mtls_evictions(prune_pool_entries(entries));
                entries.push(MeshMtlsPoolEntry {
                    sender: sender.clone(),
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
                    sender: sender.clone(),
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
        Ok(sender)
    }

    /// Exclusive-lock scan: prune dead/idle entries, return the first live
    /// multiplexed sender. Unlike the HBONE pool there is no Ready/Pending
    /// split — hyper's H2 sender accepts new streams as long as the connection
    /// is open (`is_closed()`); per-stream backpressure is awaited at send.
    fn cached_sender(&self, key: &str, _max_entries: usize) -> Option<MeshMtlsSender> {
        let mut entries = self.entries.get_mut(key)?;
        record_mesh_mtls_evictions(prune_pool_entries(&mut entries));
        for entry in entries.iter() {
            if entry.sender.is_closed() {
                continue;
            }
            entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
            return Some(entry.sender.clone());
        }
        None
    }

    /// Shared-lock fast path mirroring the HBONE pool: scan for a live sender
    /// and refresh recency via a relaxed store, avoiding the exclusive shard
    /// write lock. Expired entries are skipped (not removed); dead senders fall
    /// through to the write path.
    fn try_cached_sender_read(&self, key: &str) -> Option<MeshMtlsSender> {
        let entries = self.entries.get(key)?;
        let now = unix_secs();
        for entry in entries.value().iter() {
            let last_used = entry.last_used_at.load(Ordering::Relaxed);
            if entry_idle_expired(last_used, entry.idle_timeout_seconds, now) {
                continue;
            }
            if entry.sender.is_closed() {
                continue;
            }
            entry.last_used_at.store(now, Ordering::Relaxed);
            return Some(entry.sender.clone());
        }
        None
    }

    fn maybe_prune_idle_entries(&self) {
        let now = unix_secs();
        let interval = if self.pool_config.idle_timeout_seconds == 0 {
            60
        } else {
            self.pool_config.idle_timeout_seconds.clamp(1, 60)
        };
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
        self.creation_locks.retain(|key, lock| {
            self.entries.contains_key(key.as_str()) || Arc::strong_count(lock) > 1
        });
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
    ) -> Result<MeshMtlsSender, HbonePoolError> {
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
        // SNI: the destination service FQDN for a cross-cluster east-west dial
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

                let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                    HbonePoolError::TlsHandshake {
                        host: target_host.to_string(),
                        message: e.to_string(),
                    }
                })?;
                if !matches!(tls_stream.get_ref().1.alpn_protocol(), Some(b"h2")) {
                    return Err(HbonePoolError::TlsHandshake {
                        host: target_host.to_string(),
                        message: "peer did not negotiate ALPN h2".to_string(),
                    });
                }

                let mut builder = http2::Builder::new(TokioExecutor::new());
                builder.timer(TokioTimer::new());
                if pool_config.enable_http2 {
                    builder
                        .keep_alive_interval(Duration::from_secs(
                            pool_config.http2_keep_alive_interval_seconds,
                        ))
                        .keep_alive_timeout(Duration::from_secs(
                            pool_config.http2_keep_alive_timeout_seconds,
                        ))
                        .max_concurrent_reset_streams(4096);
                }
                builder
                    .initial_stream_window_size(pool_config.http2_initial_stream_window_size)
                    .initial_connection_window_size(
                        pool_config.http2_initial_connection_window_size,
                    )
                    .adaptive_window(pool_config.http2_adaptive_window)
                    .max_frame_size(pool_config.http2_max_frame_size);
                if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
                    builder.max_concurrent_streams(max_streams);
                }

                let io = TokioIo::new(tls_stream);
                let (sender, connection) =
                    builder
                        .handshake(io)
                        .await
                        .map_err(|e| HbonePoolError::H2Handshake {
                            host: target_host.to_string(),
                            message: e.to_string(),
                        })?;

                // TLS ALPN already proved H2 for this sidecar candidate.
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!(
                            "mesh_mtls_pool: sidecar mTLS HTTP/2 connection closed: {}",
                            e
                        );
                    }
                });
                Ok(sender)
            }
        })
        .await
        .map(|(sender, _)| sender)
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

fn prune_pool_entries(entries: &mut Vec<MeshMtlsPoolEntry>) -> usize {
    let before = entries.len();
    let now = unix_secs();
    entries.retain(|entry| {
        !entry.sender.is_closed()
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
            )
            .await
        {
            Err(HbonePoolError::NoSvid) => {}
            Err(other) => panic!("expected NoSvid, got {other:?}"),
            Ok(_) => panic!("a missing gateway SVID must fail the datagram dial closed"),
        }
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
            .insert(key.to_string(), Arc::new(Mutex::new(())));
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

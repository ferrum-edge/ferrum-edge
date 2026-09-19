//! Source-side reuse of the APPLICATION connection inside a fenced HBONE
//! tunnel (issue #5042 step 2).
//!
//! The outer HBONE HTTP/2 transport has always been pooled
//! ([`super::hbone_pool`]), but the connection the gateway runs INSIDE it was
//! built per request: one CONNECT stream, one inner HTTP/1.1 handshake for
//! plain HTTP, and for gRPC an entire nested HTTP/2 preface/SETTINGS exchange
//! through the destination relay — every time. The destination saw one
//! `accept(2)` per request, and a warm intra-cluster call paid one extra
//! round trip (HTTP) or two (gRPC) before its first request byte left.
//!
//! This module holds that inner connection open across requests.
//!
//! # Why this is admissible at all
//!
//! Pooling an application tunnel changes how often the DESTINATION authorizes.
//! Before step 1 of this issue, a tunnel admitted under one policy generation
//! kept flowing under every later one, so reuse would have carried later
//! requests under a stale decision with nothing able to notice. Step 1 closed
//! that: [`super::hbone_admission_fence`] re-applies the CONNECT admission
//! gates — policy AND credential — to every live tunnel on every publication,
//! and cuts the ones a later generation would refuse.
//!
//! Reuse is therefore gated on the destination SAYING it runs that fence:
//! `handle_hbone_request` stamps
//! [`crate::modes::mesh::hbone::TUNNEL_REUSE_HEADER`] on the CONNECT `200`
//! only while the fence really holds the tunnel, and a source that does not
//! see it keeps today's per-request behaviour exactly. The header is read for
//! that one decision and nothing else; it authorizes no request, and a peer
//! that forges it gains no more than it already gets by holding one long-lived
//! tunnel open.
//!
//! # What is NOT skipped
//!
//! Only the repeated CONNECT and the repeated inner handshake. Every NEW
//! CONNECT still runs the full source-side dial (SVID-mTLS to the peer, pinned
//! peer identity / SNI / trust-domain scope) and the destination still runs the
//! authenticated-peer gate, the PeerAuthentication transport mode, the
//! relay-destination ownership guard, and the authorize chain. There is no
//! plaintext fallback anywhere on this path: a peer that does not advertise the
//! fence gets more connections, never a weaker one.
//!
//! # The key IS the admission identity
//!
//! [`write_hbone_inner_pool_key`] encodes the COMPLETE transport and admission
//! identity of the connection, so nothing that would change who is talking to
//! whom, under what credential, or over what wire settings can share a pooled
//! connection:
//!
//! * the application endpoint as dialled (the CONNECT `:authority` host and
//!   port) and the dial peer (`dial_host` + the peer's HBONE listener port) —
//!   these are different hosts for NodeWaypoint and cross-cluster egress;
//! * the peer verification scope: pinned peer SPIFFE id, ClientHello SNI
//!   override, and the remote trust domain a cross-cluster session was verified
//!   against;
//! * the ASSERTED SOURCE PRINCIPAL and its scope — the identity stamped into
//!   the CONNECT baggage, plus whether it was asserted by an authenticated
//!   frontend peer or defaulted to this gateway's own SVID. Two principals
//!   never share an inner connection, and "gateway SVID acting as itself" is a
//!   different key from "gateway asserting that same identity on behalf of a
//!   peer";
//! * the route/policy generation: namespace, proxy id, effective upstream id,
//!   and the admitting proxy's lifecycle generation, so a republished or
//!   re-bound proxy is a new incarnation that inherits nothing;
//! * the source credential generation: the gateway SVID leaf fingerprint and
//!   the shared backend SVID/trust generation, so a rotation partitions the
//!   pool rather than laundering a connection across it;
//! * the effective connection policy that configures the constructed
//!   client — keep-alive, protocol selection, and the HTTP/2 SETTINGS — through
//!   the same `write_pool_config_key` segment every sibling pool uses.
//!
//! Per-request policy is deliberately EXCLUDED, exactly as
//! [`super::unix_backend_pool`] excludes it and for the same reason the repo
//! pool-key rule states: `backend_connect_timeout_ms`,
//! `backend_read_timeout_ms`, `backend_write_timeout_ms` and the route-scoped
//! body ceilings are applied per dispatch by the caller (they compose the
//! phase deadlines and the size-limiting body adapters on every request,
//! reused connection or not). They change nothing about the connection that was
//! constructed, so keying on them would fragment the pool without bounding
//! anything.
//!
//! # Credential lifetime
//!
//! A lease NEVER prolongs a credential. An exclusive HTTP/1.1 connection records
//! the earliest monotonic deadline across the admitting request's
//! `RequestContext::credential_deadline_at` (the minimum over its accepted SVID
//! and JWT credentials) and the gateway SVID leaf's `notAfter`. Checkout rejects
//! expired entries and folds the current request's bound into the exclusive lease.
//!
//! A shared HTTP/2 carrier instead records the gateway SVID leaf's `notAfter`,
//! the credential its CONNECT presents. Checkout enforces that carrier bound;
//! it deliberately does not fold in an individual RPC's credential deadline,
//! which would retire a shared transport because one caller has a short-lived
//! JWT. Each RPC still passes source-side authorization before dispatch, and
//! inner reuse requires every plugin's explicit reuse permission. Carrier reuse
//! does not transfer one RPC's authorization to another.
//!
//! A gateway SVID leaf that cannot be parsed has an already-elapsed deadline
//! and is never poolable. A `notAfter` beyond the representable monotonic range
//! publishes no deadline, exactly as
//! [`crate::plugins::utils::auth_flow::CredentialDeadline::Unbounded`] does,
//! and the idle timeout plus the pool bounds still apply.
//!
//! # Per-protocol lease semantics
//!
//! * **HTTP/1.1** — an EXCLUSIVE lease. It returns to the idle set ONLY after a
//!   clean, fully consumed response, for both the buffered and the streaming
//!   response shape, and only after hyper's own dispatcher has re-armed. A
//!   truncated body, a body error, a `Connection: close`, an early client
//!   cancel, a fired deadline, a read timeout, a size-limit refusal, or a
//!   dropped body all leave the lease in place and its `Drop` retires the
//!   tunnel. Receiving response HEADERS is never sufficient, and neither is
//!   hyper's `can_write_head()`: it is already true while a response body is
//!   still being read, so pooling on readiness alone would pipeline the next
//!   request onto a half-read connection.
//! * **HTTP/2 (native gRPC)** — a small BOUNDED set of shared multiplexed
//!   senders per key, cloned per RPC. Liveness is `!is_closed()`, which is
//!   EXACTLY the predicate the direct HTTP/2 pool uses
//!   (`Http2PoolManager::is_healthy`), so the two cannot judge a carrier
//!   differently. A sender whose connection has ended — a received GOAWAY that
//!   drained, a connection-level error, or a tunnel a fence sweep cut — reports
//!   closed, is EVICTED on the next checkout, and is never handed out again.
//!   Between a peer's GOAWAY and its connection task finishing there is a
//!   window in which a clone can still be taken; its `send_request` then fails
//!   and is classified and retried exactly as the direct pool's is, because
//!   reuse must not introduce a second error regime. Trailers, RST_STREAM,
//!   cancellation and flow control are the transport's own and are unchanged by
//!   pooling.
//!
//!   The set is bounded the way the OUTER pool bounds its own
//!   (`hbone_pool::select_least_loaded` + `record_peer_max_streams`, issue
//!   #5465): every carrier tracks the nested peer's
//!   `SETTINGS_MAX_CONCURRENT_STREAMS` and counts the dispatches holding it,
//!   checkout picks the LEAST LOADED carrier with room under that cap, and a
//!   key whose carriers are all at their cap opens another — up to
//!   [`MAX_SHARED_H2_PER_KEY`] and never past the operator's own
//!   `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`. At that width a burst queues
//!   pending-open inside `h2` on the least-loaded carrier, exactly as the outer
//!   pool's saturated branch does. **That ceiling is the concurrency bound for
//!   native gRPC to ONE destination under ONE key.** Before reuse each RPC
//!   opened its own nested connection, so concurrency was bounded only by the
//!   outer stream budget; a deployment that needs more concurrent RPCs to one
//!   destination than `cap x width` must raise
//!   `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST` (see `docs/mesh.md`).
//!
//!   That cap is kept CURRENT by the carrier's own connection driver, not
//!   sampled once (issue #5042 step 2 re-review). hyper exposes
//!   `current_max_send_streams()` on the `Connection`, never on the
//!   `SendRequest` the pool holds, and the value it reports right after
//!   `h2c_preface::await_peer_settings` is still hyper's
//!   `DEFAULT_INITIAL_MAX_SEND_STREAMS` (100): observing the peer's SETTINGS
//!   BYTES is not the same as `h2` having applied them, which it defers until
//!   it writes the SETTINGS ACK. A single sample therefore recorded 100 for a
//!   destination advertising 8, `is_saturated()` never fired, and RPCs 9..100
//!   queued pending-open behind the peer's real cap — the head-of-line
//!   queueing the width exists to avoid. The dial in
//!   `grpc_proxy::open_hbone_grpc_sender` instead creates the
//!   [`HboneInnerH2Load`] BEFORE spawning the driver and wraps the connection
//!   future so every poll stores the connection's current value into it, so
//!   the pool reads whatever the peer last advertised — including a cap the
//!   peer lowers mid-connection.
//!
//! # Revocation reaches a pooled connection
//!
//! Three independent paths, all of them fail-closed:
//!
//! 1. **The receiver cut the tunnel.** A fence sweep resets the CONNECT stream,
//!    which the [`super::hbone_pool::H2ConnectTunnel`] under the inner sender
//!    surfaces as a terminal transport error; hyper's driver ends and
//!    `is_closed()` becomes true. Checkout evicts it. If the close has not
//!    propagated yet, the H1 path's PRE-WIRE `try_send_request` hands the
//!    untouched request back and the dispatch replays it on a fresh CONNECT
//!    that the destination judges under the CURRENT policy — see
//!    "Retry semantics" below.
//! 2. **Source trust changed.** This pool is owned by
//!    [`super::hbone_pool::HboneConnectionPool`], so the drains that already
//!    reach the outer transports reach these too, through the same two
//!    funnels: `drain_retired_fingerprints` (the SVID rotation drain, matched
//!    on the retired leaf fingerprint every key embeds) and `force_drain_all`
//!    (an SVID slot with no bundle, a CRL reload, and `retire_withdrawn_trust`,
//!    which clears the mesh pools WHOLE for every committed gateway trust
//!    change because their keys carry no generation partition). That ownership
//!    is why this is structural rather than a list of call sites: an inner
//!    connection is only ever as trustworthy as the tunnel it rides.
//!
//!    Clearing the maps is only HALF of a drain, and on its own it is a
//!    fail-OPEN: an exclusive H1 lease that is checked out right now is not in
//!    them — `take_idle_h1` removed it precisely so that it is not — so the
//!    clear cannot reach it and its check-in would re-insert it under the very
//!    same key. Every retirement therefore advances a monotonic
//!    [`HboneInnerConnectionPool::drain_generation`] FIRST, each lease records
//!    the generation current when it was taken (or when its CONNECT was
//!    dialled), and the check-in compares that value before AND after its
//!    insert. A lease that straddled a drain is discarded and the next request
//!    pays a fresh CONNECT the destination judges under the CURRENT policy.
//!
//!    Clearing the maps is not the whole of the ENTRY side either, because the
//!    clear takes each shard lock in turn: a checkout can win a shard the pass
//!    has not reached yet and take a pre-drain entry. The two whole-pool
//!    retirements therefore also advance
//!    [`HboneInnerConnectionPool::entry_drain_generation`], which every entry
//!    is stamped with at insert and every checkout re-reads INSIDE the shard
//!    guard — evicting a superseded entry rather than handing it out, and never
//!    laundering it by adopting the caller's generation. That counter is
//!    deliberately NOT advanced by `retain_live_routes`, which removes the keys
//!    it retires by name and would otherwise evict every resident entry on any
//!    publication that withdrew anything.
//!
//!    The sibling that already carries this exact rule is
//!    `unix_backend_pool::take_idle_h1`, which reads its publication
//!    generation inside the shard guard and refuses a mismatch rather than
//!    re-stamping it. The EXCLUSIVE-lease shape is what makes the stamp
//!    load-bearing on the H1 leg: the entry is REMOVED from the map at
//!    checkout, so a drain's own pass can never reach it again. The outer
//!    [`super::hbone_pool`] and [`super::mesh_mtls_pool`] instead hand out
//!    clones and leave their entries resident — the milder shape this module's
//!    H2 leg has — and neither is changed by this issue.
//!    The nested-HTTP/2 publication carries the same fence, plus the outer
//!    pool's own mid-dial refusal: a gateway SVID slot, CRL slot, or leaf
//!    fingerprint that moved during the dial means the outer pool declined to
//!    pool that transport, and the nested sender riding it declines for the
//!    same reason.
//! 3. **Credential expiry.** The recorded deadline above.
//!
//! A FOURTH path is not about trust: a publication that withdraws a proxy,
//! re-binds it (a new lifecycle generation), or turns its effective
//! `pool_enable_http_keep_alive` off changes the KEY, which makes the resident
//! entries unreachable but does not retire them.
//! [`HboneInnerConnectionPool::retain_live_routes`] does, synchronously, from
//! every publication that becomes current — the same discipline
//! `unix_backend_pool::retain_live_targets_for_publication` applies.
//!
//! # What a pooled connection costs while idle
//!
//! One outer HTTP/2 stream, held for as long as the inner connection is
//! pooled — the CONNECT stream is what the inner connection IS. It therefore
//! counts against the destination's `http2MaxRequests` / `SETTINGS_MAX_CONCURRENT_STREAMS`
//! exactly as an in-flight tunnel does, through the same
//! `HboneStreamLease` the outer pool uses to measure connection load. It is
//! also a live entry in the DESTINATION's `HboneAdmissionFence.tunnels`, and
//! every policy publication there re-runs the authorize chain over all of
//! them — so an idle pooled tunnel costs the destination sweep work it would
//! not otherwise do. That is bounded, and strictly better than the alternative
//! it replaces: per request the unpooled path holds an equivalent stream for
//! the whole exchange and then opens another, whereas [`MAX_IDLE_H1_PER_KEY`]
//! plus [`MAX_SHARED_H2_PER_KEY`] plus [`MAX_POOLED_INNER_CONNECTIONS`] plus
//! the idle timeout cap what reuse can hold at rest. Do not raise those bounds
//! without re-reading this paragraph.
//!
//! # Retry semantics are UNCHANGED
//!
//! Reuse must not turn a non-idempotent request into a replayed one. The only
//! replay this module enables is hyper's PRE-WIRE handback: `try_send_request`
//! returns the untouched request through `TrySendError::take_message()` ONLY
//! when nothing was written to the wire, it is taken at most once per dispatch,
//! and only for a lease that came from the idle set (a freshly dialled
//! connection that fails has a real failure to report). That is the identical
//! contract [`super::unix_backend_pool`]'s H1 dispatch already relies on. Every
//! post-wire failure is classified and surfaced exactly as it is today, and the
//! ordinary `retry::should_retry` path — with its `retryable_methods` guard —
//! is the only thing that may replay it.
//!
//! # Bounds
//!
//! Fixed defaults rather than new operator knobs: at most
//! [`MAX_IDLE_H1_PER_KEY`] idle HTTP/1.1 connections per key, at most
//! [`MAX_SHARED_H2_PER_KEY`] nested HTTP/2 carriers per key (and never more
//! than the operator's own `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`), at most
//! [`MAX_POOLED_INNER_CONNECTIONS`] pooled inner connections in total across
//! every key and both protocols, and an idle timeout taken from the effective
//! `PoolConfig::idle_timeout_seconds` the dispatch already resolved (floored by
//! [`MIN_INNER_IDLE_TIMEOUT_SECONDS`] so a `0` "never expire" transport setting
//! cannot make an inner application connection immortal). Over-cap is never an
//! error: the connection simply is not pooled, which is today's behaviour.
//!
//! The pool can never open more inner connections than the per-request path
//! would have. Every miss opens exactly one, exactly as today, and concurrent
//! cold misses for one key each serve their own request — the first to publish
//! wins the slot and the others are used once and closed, which is precisely
//! the pre-#5042 cost.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use dashmap::DashMap;
use hyper::client::conn::{http1, http2};
use tracing::debug;

use crate::config::PoolConfig;
use crate::identity::SpiffeId;
use crate::identity::spiffe::TrustDomain;
use crate::plugins::prometheus_metrics::HboneInnerPoolEvent;
use crate::proxy::body::{ReplayableRequestBody, SizeLimitedIncoming};
use crate::proxy::grpc_proxy::GrpcBody;
use crate::proxy::hbone_pool::{entry_idle_expired, unix_secs, write_pool_config_key};

/// Most idle HTTP/1.1 inner connections retained for ONE key.
///
/// One key is one `(principal, app endpoint, dial peer, verification scope,
/// route generation, credential generation, wire settings)` tuple, so this
/// bounds the concurrency a single logical caller→callee lane keeps warm. Eight
/// covers the concurrency the measurement in issue #5042 exercised without
/// letting one busy lane monopolise the global ceiling.
pub const MAX_IDLE_H1_PER_KEY: usize = 8;

/// Hard ceiling on POOLED inner connections across every key and both
/// protocols.
///
/// Reached only by breadth — many distinct principals or destinations — since
/// each key is already bounded above. An over-cap connection is used for its
/// own request and then closed, which is exactly the per-request behaviour this
/// module replaces, so the ceiling degrades to the old cost rather than to an
/// error.
pub const MAX_POOLED_INNER_CONNECTIONS: usize = 1024;

/// Hard clamp on NESTED HTTP/2 carriers retained for ONE key.
///
/// The effective width is the operator's own
/// `FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`, clamped by this constant — the
/// same knob that widens the OUTER HBONE sessions these carriers ride, rather
/// than a new one. The clamp exists because each nested carrier also holds one
/// outer CONNECT stream against the destination's `http2MaxRequests`, so the
/// inner width must not be able to outrun what the outer pool would open.
pub const MAX_SHARED_H2_PER_KEY: usize = 4;

/// Floor applied to the effective `PoolConfig::idle_timeout_seconds` for inner
/// application connections.
///
/// `0` on the transport pool means "never expire", which is a defensible
/// setting for a gateway's own outbound mTLS sessions but not for a connection
/// held open inside a peer's application. A stale inner connection is also the
/// shape most likely to meet a destination that reaped its side, so it is
/// floored rather than honoured literally.
pub const MIN_INNER_IDLE_TIMEOUT_SECONDS: u64 = 15;

/// Amortisation interval for the idle sweep. The sweep runs at most this often,
/// on a checkout, never on a timer and never on the byte path.
const IDLE_PRUNE_INTERVAL_SECONDS: u64 = 5;

/// Request body carried by a pooled inner HTTP/1.1 sender.
///
/// Byte-identical to the shape the unpooled HBONE dispatch already built, so
/// naming the sender's concrete `SendRequest<B>` type changes nothing about
/// what the dispatch path constructs: `Left` is the streaming, size-limited
/// frontend body; `Right` is the retry-replayable buffered body.
pub type HboneInnerH1RequestBody =
    http_body_util::Either<SizeLimitedIncoming, ReplayableRequestBody>;

/// Concrete pooled inner HTTP/1.1 sender type.
pub type HboneInnerH1Sender = http1::SendRequest<HboneInnerH1RequestBody>;

/// Concrete shared inner HTTP/2 sender type (native gRPC inside the tunnel).
pub type HboneInnerH2Sender = http2::SendRequest<GrpcBody>;

/// Wire protocol spoken INSIDE the tunnel. Part of the key: an HTTP/1.1
/// application dispatch and a nested HTTP/2 gRPC dispatch must never share a
/// connection even when every other field agrees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HboneInnerProtocol {
    Http1,
    H2,
}

impl HboneInnerProtocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::H2 => "h2",
        }
    }

    const fn event_protocol(self) -> crate::plugins::prometheus_metrics::HboneInnerPoolProtocol {
        match self {
            Self::Http1 => crate::plugins::prometheus_metrics::HboneInnerPoolProtocol::Http1,
            Self::H2 => crate::plugins::prometheus_metrics::HboneInnerPoolProtocol::H2,
        }
    }
}

/// The source credential every inner lease is keyed and bounded by.
///
/// Resolved once per dispatch by
/// [`super::hbone_pool::HboneConnectionPool::source_credential_identity`], from
/// the same cached gateway SVID snapshot the outer dial uses, so the key's
/// credential fields and the connection's actual client certificate can never
/// come from two different generations.
#[derive(Clone)]
pub struct HboneSourceCredential {
    /// The gateway's own SPIFFE identity — the source principal a dispatch with
    /// no authenticated frontend peer asserts.
    pub identity: SpiffeId,
    /// Leaf fingerprint, the same value the outer HBONE pool key embeds.
    pub fingerprint: Arc<str>,
    /// Shared backend SVID/trust generation counter.
    pub generation: u64,
    /// The gateway leaf's `notAfter` on the monotonic clock. `None` means the
    /// expiry is beyond the representable range, not that it is unbounded in
    /// policy terms; an unparseable leaf collapses to an already-elapsed
    /// deadline so nothing is poolable under it.
    pub leaf_deadline: Option<tokio::time::Instant>,
}

/// Everything that identifies ONE reusable inner application connection,
/// borrowed from the dispatch so a pool LOOKUP allocates nothing.
///
/// [`with_hbone_inner_pool_key`] renders the key into a thread-local buffer, so
/// a checkout that misses and a check-in that is refused both cost zero
/// allocations. A lease that is actually handed out owns one `String` copy of
/// the key — it has to outlive the borrowed dispatch frame to be filed back
/// under the same identity — which is one allocation per dispatch that reaches
/// a lease, against the CONNECT plus inner handshake it replaces. The check-in
/// itself adds none: it reaches an already-resident key through
/// `DashMap::get_mut`, and only a genuine FIRST insert under a key pays the
/// second copy `DashMap::entry` requires.
pub struct HboneInnerKeyParts<'a> {
    pub protocol: HboneInnerProtocol,
    pub namespace: &'a str,
    pub proxy_id: &'a str,
    pub upstream_id: Option<&'a str>,
    /// The admitting proxy's lifecycle generation, when the request path
    /// resolved one. A proxy withdrawn and recreated is a new incarnation and
    /// must inherit nothing.
    pub proxy_lifecycle_generation: Option<u64>,
    /// CONNECT `:authority` host — the real destination the relay dials.
    pub app_host: &'a str,
    pub app_port: u16,
    /// The host the outer HTTP/2 session is dialled to. Differs from `app_host`
    /// on NodeWaypoint secured egress and cross-cluster east-west.
    pub dial_host: &'a str,
    pub hbone_port: u16,
    pub expected_peer: Option<&'a SpiffeId>,
    pub expected_trust_domain: Option<&'a TrustDomain>,
    pub sni_override: Option<&'a str>,
    /// The principal stamped into the CONNECT baggage.
    pub source_principal: &'a SpiffeId,
    /// `true` when `source_principal` was ASSERTED on behalf of an
    /// authenticated frontend peer, `false` when it is this gateway's own SVID
    /// identity acting as itself. The two are different admission facts at the
    /// destination and must not share a connection.
    pub source_principal_asserted: bool,
    pub credential: &'a HboneSourceCredential,
    pub pool_config: &'a PoolConfig,
}

thread_local! {
    static HBONE_INNER_POOL_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(256));
}

/// Byte offsets of the route-generation run inside a rendered key.
///
/// The run is `|<namespace>|<proxy id>|<lifecycle generation>`, written by
/// [`write_hbone_inner_route_identity`]. Recorded as offsets rather than
/// re-derived by splitting on `|`, because a namespace or proxy id the
/// configuration accepted is not guaranteed to be delimiter-free and a
/// mis-resolved route would retire the wrong connections. The writer knows
/// exactly where it wrote them; nothing else has to guess.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HboneInnerKeySpans {
    route_start: u32,
    route_end: u32,
}

impl HboneInnerKeySpans {
    /// The route-generation run of `key`, or `None` when the recorded span does
    /// not address `key` (a key this writer did not produce).
    pub fn route<'a>(&self, key: &'a str) -> Option<&'a str> {
        key.get(self.route_start as usize..self.route_end as usize)
    }
}

/// Render the route-generation run — namespace, proxy id and the admitting
/// proxy's lifecycle generation — into `buf`.
///
/// Shared by the key writer and by the publication-time retention pass
/// (`ProxyState::reconcile_hbone_inner_pool`), so the identity a pooled
/// connection was filed under and the identity the published configuration
/// declares cannot be rendered two different ways.
///
/// The EFFECTIVE upstream id is deliberately NOT part of this run, even though
/// it IS part of the key. A route override resolves an effective upstream the
/// published proxy does not declare, so comparing on it would make every
/// publication retire a perfectly live overridden route. The run therefore
/// carries only what a published proxy can be compared on directly; an
/// upstream re-pointed under an unchanged proxy still changes the KEY (so it is
/// unreachable and secure) and is reclaimed by the idle sweep rather than
/// synchronously.
///
/// An ABSENT lifecycle generation is the empty trailing segment — the run ends
/// with `|`. That is not a cosmetic detail: a lease whose proxy was not
/// resolvable in any published generation (a synthesized relay proxy) is one
/// the configuration cannot speak about, so the retention pass exempts it and
/// leaves it to the idle sweep.
pub fn write_hbone_inner_route_identity(
    buf: &mut String,
    namespace: &str,
    proxy_id: &str,
    proxy_lifecycle_generation: Option<u64>,
) {
    use std::fmt::Write as _;

    let _ = write!(buf, "|{}|{}|", namespace, proxy_id);
    // Written by `write!` rather than through `to_string()` so a key build
    // allocates nothing on the dispatch path; an absent generation is the
    // empty segment, which no `u64` rendering can collide with.
    if let Some(generation) = proxy_lifecycle_generation {
        let _ = write!(buf, "{generation}");
    }
}

/// Render the complete inner-connection identity into `buf`.
///
/// `|` is the repo's pool-key delimiter. The SVID fingerprint is written at a
/// FIXED early index (2) — after two compiled-in literals that contain no
/// delimiter — so the rotation drain can resolve it positionally without
/// depending on any later field being delimiter-free. A cross-cluster
/// `target.host` really does contain `|`, which is exactly why the fingerprint
/// is not parsed from the tail.
///
/// Returns the byte span of the route-generation run, which the publication
/// retention pass compares without splitting the key at all.
pub fn write_hbone_inner_pool_key(
    buf: &mut String,
    parts: &HboneInnerKeyParts<'_>,
) -> HboneInnerKeySpans {
    use std::fmt::Write as _;

    buf.clear();
    let _ = write!(
        buf,
        "hbone-inner|{}|{}|{}",
        parts.protocol.as_str(),
        parts.credential.fingerprint.as_ref(),
        parts.credential.generation
    );
    let route_start = buf.len();
    write_hbone_inner_route_identity(
        buf,
        parts.namespace,
        parts.proxy_id,
        parts.proxy_lifecycle_generation,
    );
    let route_end = buf.len();
    let _ = write!(
        buf,
        "|{}|{}|{}|{}|{}",
        parts.upstream_id.unwrap_or_default(),
        parts.app_host,
        parts.app_port,
        parts.dial_host,
        parts.hbone_port
    );
    let _ = write!(
        buf,
        "|{}|{}|{}",
        parts
            .expected_peer
            .map(SpiffeId::as_str)
            .unwrap_or_default(),
        parts.sni_override.unwrap_or_default(),
        parts
            .expected_trust_domain
            .map(TrustDomain::as_str)
            .unwrap_or_default()
    );
    let _ = write!(
        buf,
        "|{}|{}",
        parts.source_principal.as_str(),
        u8::from(parts.source_principal_asserted)
    );
    write_pool_config_key(buf, parts.pool_config);
    HboneInnerKeySpans {
        route_start: route_start as u32,
        route_end: route_end as u32,
    }
}

/// The SVID leaf fingerprint embedded in an inner pool key, for the rotation
/// drain. See [`write_hbone_inner_pool_key`] for why the index is 2.
fn hbone_inner_key_svid_fingerprint(key: &str) -> Option<&str> {
    key.split('|').nth(2)
}

/// Build the key for `parts` in a thread-local buffer and hand it, with its
/// route span, to `f` without allocating. Mirrors `with_hbone_pool_key`.
pub fn with_hbone_inner_pool_key<R>(
    parts: &HboneInnerKeyParts<'_>,
    f: impl FnOnce(&str, HboneInnerKeySpans) -> R,
) -> R {
    HBONE_INNER_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        let spans = write_hbone_inner_pool_key(&mut buf, parts);
        f(&buf, spans)
    })
}

/// An EXCLUSIVE inner HTTP/1.1 lease.
///
/// Dropping the lease retires the connection AND the CONNECT tunnel under it.
/// Only [`HboneInnerConnectionPool::checkin_h1_when_idle`] returns it to the
/// idle set, and only after the response body has been completely read.
pub struct HboneInnerH1Checkout {
    key: String,
    /// Byte span of the route-generation run inside `key`, recorded so a
    /// check-in files the entry with the same route the publication retention
    /// pass compares.
    spans: HboneInnerKeySpans,
    /// The pool's drain generation when this lease was taken (a checkout) or
    /// when its CONNECT was dialled (a cold miss).
    ///
    /// An outstanding lease is NOT in the pool's maps — `take_idle_h1` removed
    /// it precisely so that it is not — so a whole-pool drain cannot reach it
    /// by clearing them. This is what reaches it: every retirement advances the
    /// generation FIRST, and the check-in compares this value before and after
    /// its insert, so a lease that straddled a drain is discarded rather than
    /// resurrected under its old key. Mirrors
    /// `unix_backend_pool`'s publication fence.
    generation: u64,
    /// `true` when this lease came from the idle set rather than a fresh
    /// CONNECT. The dispatch uses it to decide whether a PRE-WIRE send failure
    /// is a reuse race worth replaying once on a fresh tunnel.
    reused: bool,
    /// The earliest credential deadline that admitted this connection, or
    /// `None` when none of them published a representable bound.
    credential_deadline: Option<tokio::time::Instant>,
    /// Effective idle timeout for this connection, resolved at checkout so the
    /// check-in (which has no `PoolConfig`) applies the same value.
    idle_timeout_seconds: u64,
    /// `false` when the destination did not advertise the admission fence, or
    /// when keep-alive reuse is off for this dispatch. Such a lease is used
    /// once and never enters the idle set.
    poolable: bool,
    pub sender: HboneInnerH1Sender,
}

impl HboneInnerH1Checkout {
    /// Whether this lease came from the idle set.
    #[inline]
    pub fn reused(&self) -> bool {
        self.reused
    }

    /// Whether this lease may re-enter the idle set at all.
    ///
    /// `false` for a destination that did not advertise the admission fence,
    /// for a dispatch with keep-alive off, and for an unpooled lease. The
    /// plain-HTTP dispatch also reads it to decide whether it may apply the
    /// eager small-response buffering that keeps an exclusive H1 carrier
    /// alive, so a peer without the capability keeps byte-for-byte today's
    /// streaming behaviour.
    #[inline]
    pub fn poolable(&self) -> bool {
        self.poolable
    }

    /// The drain generation this lease is bound to. Exposed for the external
    /// fence regression tests.
    #[inline]
    #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
    pub fn drain_generation(&self) -> u64 {
        self.generation
    }
}

/// EOF-anchored owner of an exclusive inner HTTP/1.1 lease for a STREAMING
/// response.
///
/// Constructed by [`HboneInnerConnectionPool::streaming_lease`] and stored on
/// the `ProxyBody` that owns the backend `hyper::body::Incoming`. Two exits,
/// and only two:
///
/// * `release_on_clean_eof` — the body yielded `Ready(None)`, or a successful
///   terminal frame after `Body::is_end_stream()` proved the whole `Incoming`
///   was consumed.
/// * `Drop` with the lease still present — every abnormal terminal. The
///   `SendRequest` drops, hyper's driver ends, and the CONNECT tunnel closes.
struct HboneInnerH1StreamingLease {
    pool: Arc<HboneInnerConnectionPool>,
    checkout: Option<HboneInnerH1Checkout>,
}

impl crate::proxy::body::PooledBackendLease for HboneInnerH1StreamingLease {
    fn release_on_clean_eof(mut self: Box<Self>) {
        if let Some(checkout) = self.checkout.take() {
            HboneInnerConnectionPool::checkin_h1_when_idle(&self.pool, checkout);
        }
    }
}

struct IdleH1 {
    /// Process-unique id, so the check-in's second fence read withdraws exactly
    /// the entry it inserted and never a newer replacement under the same key.
    id: u64,
    /// [`HboneInnerConnectionPool::entry_drain_generation`] when this entry was
    /// inserted. Read again INSIDE the shard guard on checkout; a mismatch is
    /// an eviction, never a hand-out. See
    /// [`HboneInnerConnectionPool::entry_drain_generation`].
    entry_generation: u64,
    sender: HboneInnerH1Sender,
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
    credential_deadline: Option<tokio::time::Instant>,
}

/// Measured load of ONE nested HTTP/2 carrier, shared by the pooled entry and
/// by every dispatch that cloned its sender (issue #5042 step 2 review).
///
/// The direct analogue of `hbone_pool::HboneConnectionLoad`, and for the same
/// reason: `SendRequest::clone()` says nothing about how many streams the
/// connection is carrying, and hyper's `poll_ready` for HTTP/2 reports only
/// whether the connection is closed — never whether the peer's
/// `SETTINGS_MAX_CONCURRENT_STREAMS` is already reached. Without this the pool
/// would pin every RPC to one destination onto a single nested connection and
/// turn saturation into silent head-of-line queueing.
#[derive(Clone, Default)]
pub struct HboneInnerH2Load(Arc<HboneInnerH2LoadInner>);

#[derive(Debug)]
struct HboneInnerH2LoadInner {
    /// Dispatches currently holding a clone of this carrier's sender.
    ///
    /// An APPROXIMATION of in-flight streams, and the approximation is
    /// specific: the hold is the `GrpcPooledSender` the gRPC dispatch owns, so
    /// it is released when that dispatch function RETURNS — which for a
    /// streaming RPC is at the RESPONSE HEADERS, not at stream end. A
    /// server-streaming or bidirectional RPC whose response body and trailers
    /// keep flowing for minutes therefore stops being counted long before its
    /// `h2` stream closes, so a carrier can read as idle while it is still
    /// carrying streams and `is_saturated()` under-reports saturation on
    /// exactly the long-lived shapes where it would matter most. The
    /// consequence is bounded and one-directional: the key widens LATER than
    /// ideal, and a burst above the peer's real cap still queues pending-open
    /// inside `h2` exactly as the unpooled path did — never an error, and never
    /// more streams than the peer will accept. Making it exact means carrying
    /// the hold on the response body and trailers the way the H1 streaming
    /// lease travels on `ProxyBody`, which `GrpcStreamingResponse` has no seam
    /// for today.
    active_rpcs: AtomicUsize,
    /// The nested peer's `SETTINGS_MAX_CONCURRENT_STREAMS` as the carrier's
    /// connection driver last observed it; `usize::MAX` before the first poll
    /// and when the peer advertises none.
    peer_max_streams: AtomicUsize,
}

impl Default for HboneInnerH2LoadInner {
    fn default() -> Self {
        Self {
            active_rpcs: AtomicUsize::new(0),
            peer_max_streams: AtomicUsize::new(usize::MAX),
        }
    }
}

impl std::fmt::Debug for HboneInnerH2Load {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HboneInnerH2Load")
            .field("active_rpcs", &self.active_rpcs())
            .field("peer_max_streams", &self.peer_max_streams())
            .finish()
    }
}

impl HboneInnerH2Load {
    #[inline]
    fn active_rpcs(&self) -> usize {
        self.0.active_rpcs.load(Ordering::Relaxed)
    }

    /// The nested peer's advertised stream cap as of the driver's last poll.
    /// `usize::MAX` before the peer's SETTINGS have been applied.
    #[inline]
    pub fn peer_max_streams(&self) -> usize {
        self.0.peer_max_streams.load(Ordering::Relaxed)
    }

    /// True when one more RPC would only queue pending-open inside `h2` behind
    /// the nested peer's stream cap.
    #[inline]
    fn is_saturated(&self) -> bool {
        self.active_rpcs() >= self.peer_max_streams()
    }

    /// Account one dispatch's hold on this carrier.
    fn lease(&self) -> HboneInnerH2StreamLease {
        self.0.active_rpcs.fetch_add(1, Ordering::Relaxed);
        HboneInnerH2StreamLease(self.clone())
    }

    /// Record the nested peer's advertised stream cap.
    ///
    /// Called by the carrier's CONNECTION DRIVER after every poll, with
    /// `hyper::client::conn::http2::Connection::current_max_send_streams()`.
    /// hyper exposes that only on the `Connection`, never on the `SendRequest`
    /// the pool holds, so the driver is the only place the value stays
    /// current — and it has to stay current, because the value right after
    /// `h2c_preface::await_peer_settings` is still hyper's pre-settings default
    /// of 100 (`h2` defers applying the peer's SETTINGS until it writes the
    /// ACK). A one-shot sample there recorded 100 for every destination and
    /// silently disabled the widen decision; see the module doc.
    ///
    /// `Relaxed` is sufficient: the value only steers a widen heuristic, and a
    /// stale read costs at most one late widen, never a stream `h2` will not
    /// accept.
    pub fn set_peer_max_streams(&self, max: usize) {
        self.0.peer_max_streams.store(max, Ordering::Relaxed);
    }
}

/// RAII decrement for [`HboneInnerH2Load::active_rpcs`].
///
/// Held by the dispatch's `GrpcPooledSender` (behind an `Arc`, so cloning the
/// dispatch sender shares ONE hold rather than double-counting) and dropped
/// when that dispatch releases the carrier.
#[derive(Debug)]
pub struct HboneInnerH2StreamLease(HboneInnerH2Load);

impl Drop for HboneInnerH2StreamLease {
    fn drop(&mut self) {
        self.0.0.active_rpcs.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Everything a freshly dialled nested carrier is published under.
///
/// A struct rather than five positional arguments because every field is a
/// fact the CALLER establishes at a specific point in the dial, and getting two
/// of them the wrong way round would silently disable a fence.
pub struct HboneInnerH2Publication {
    /// `H2ConnectTunnel::peer_advertises_inner_reuse` for the CONNECT this
    /// carrier runs inside, read before the tunnel is consumed.
    pub peer_advertises_fence: bool,
    /// Whether the gateway's SVID slot, CRL slot and current leaf fingerprint
    /// are still the ones this dial started under
    /// (`HboneConnectionPool::source_dial_fence_intact`).
    pub source_material_unchanged: bool,
    /// The carrier's live load accounting, created by the dial BEFORE the
    /// connection driver was spawned and kept current by that driver: every
    /// poll stores `Connection::current_max_send_streams()` into it. Passing
    /// the shared load rather than a one-shot `usize` is what keeps the widen
    /// decision wired to the cap the peer actually advertised.
    pub load: HboneInnerH2Load,
    /// The earliest SOURCE credential deadline admitting this carrier.
    pub credential_deadline: Option<tokio::time::Instant>,
    /// `HboneInnerConnectionPool::drain_generation` read BEFORE the dial.
    pub generation: u64,
}

/// One nested HTTP/2 carrier plus the dispatch hold that accounts for it.
pub struct HboneInnerH2Checkout {
    pub sender: HboneInnerH2Sender,
    /// Dropped by the dispatch when it releases the carrier; see
    /// [`HboneInnerH2StreamLease`].
    pub lease: HboneInnerH2StreamLease,
}

struct SharedH2 {
    sender: HboneInnerH2Sender,
    load: HboneInnerH2Load,
    /// See [`IdleH1::entry_generation`].
    entry_generation: u64,
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
    credential_deadline: Option<tokio::time::Instant>,
}

/// Everything one key owns.
struct KeySlot {
    h1_idle: Vec<IdleH1>,
    /// Nested HTTP/2 carriers for this key, bounded by
    /// [`HboneInnerConnectionPool::shared_h2_width`].
    h2: Vec<SharedH2>,
    /// Byte span of the route-generation run inside this slot's key, recorded
    /// when the slot is created so the publication retention pass never has to
    /// split a key that may legitimately contain `|`.
    spans: HboneInnerKeySpans,
}

impl KeySlot {
    fn new(spans: HboneInnerKeySpans) -> Self {
        Self {
            h1_idle: Vec::new(),
            h2: Vec::new(),
            spans,
        }
    }

    fn is_empty(&self) -> bool {
        self.h1_idle.is_empty() && self.h2.is_empty()
    }

    /// File `entry` unless this key already holds [`MAX_IDLE_H1_PER_KEY`] idle
    /// senders. Returns the entry back when it was refused, so the caller
    /// gives its residency slot back and accounts a discard.
    fn try_push_h1(&mut self, entry: IdleH1) -> Option<IdleH1> {
        if self.h1_idle.len() >= MAX_IDLE_H1_PER_KEY {
            return Some(entry);
        }
        self.h1_idle.push(entry);
        None
    }

    /// File `entry` unless this key already holds `width` live carriers. A
    /// live incumbent set already at its width WINS: a concurrent cold miss
    /// must not evict a carrier other RPCs are already multiplexed on.
    fn try_push_h2(&mut self, entry: SharedH2, width: usize) -> Option<SharedH2> {
        if self.h2.len() >= width {
            return Some(entry);
        }
        self.h2.push(entry);
        None
    }

    /// Drop every carrier whose connection has ended, and report how many
    /// left. A closed incumbent is an EVICTION, not a silent replacement: it
    /// leaves the pool and its residency slot goes back to the ceiling.
    fn retire_closed_h2(&mut self) -> usize {
        let before = self.h2.len();
        self.h2.retain(|entry| !entry.sender.is_closed());
        before.saturating_sub(self.h2.len())
    }
}

/// A snapshot of this pool's own process-lifetime counters.
///
/// The operator-facing view is the Prometheus family
/// `ferrum_mesh_hbone_inner_pool_events_total`, which every recorder below
/// increments in step; this struct is the same accounting read back directly,
/// which is what lets a test assert "one CONNECT, two hits" rather than
/// scraping an exposition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HboneInnerPoolStats {
    pub h1_hits: u64,
    pub h1_misses: u64,
    pub h2_hits: u64,
    pub h2_misses: u64,
    /// Connections removed from the pool because they were closed, idle-expired,
    /// or their credential deadline elapsed.
    pub evictions: u64,
    /// Connections that finished their exchange healthy but were NOT pooled: a
    /// peer that did not advertise the fence, keep-alive off, an elapsed
    /// credential deadline, source TLS material that moved during the dial, a
    /// key already at its width, or the global ceiling. A check-in a
    /// RETIREMENT refused is counted separately — see
    /// [`HboneInnerConnectionPool::fenced_checkins`] — because "the destination
    /// stopped advertising the fence" and "a trust drain cut live leases" are
    /// different operator questions.
    pub discards: u64,
    /// Inner connections currently resident in the pool.
    pub pooled: u64,
}

/// Bounded pool of inner application connections inside fenced HBONE tunnels.
///
/// Owned by [`super::hbone_pool::HboneConnectionPool`], which is what makes
/// every existing source-side trust drain reach these connections too.
pub struct HboneInnerConnectionPool {
    entries: DashMap<String, KeySlot>,
    /// Resident inner connections, maintained at every insert and removal so
    /// the global ceiling never scans the map.
    pooled: AtomicUsize,
    /// Monotonic retirement generation. Advanced by EVERY retirement
    /// ([`Self::drain_all`], [`Self::retire_svid_fingerprints`],
    /// [`Self::retain_live_routes`]) BEFORE the retirement pass runs, so a
    /// lease that is CHECKED OUT — and therefore not in `entries` for any pass
    /// to reach — is fenced out at check-in instead of being re-inserted under
    /// its old key. See [`HboneInnerH1Checkout::generation`].
    ///
    /// This is the OUTSTANDING-LEASE half of the fence. The RESIDENT-ENTRY
    /// half is [`Self::entry_drain_generation`]; the two are separate counters
    /// on purpose.
    drain_generation: AtomicU64,
    /// Monotonic ENTRY retirement generation, stamped onto every resident
    /// entry at insert and re-read inside the shard guard on checkout.
    ///
    /// Deliberately a SECOND counter rather than [`Self::drain_generation`],
    /// which [`Self::retain_live_routes`] also advances: stamping entries
    /// against that value would evict every resident entry on any publication
    /// that retired anything. This one is advanced ONLY by the two whole-pool
    /// retirements — [`Self::drain_all`] and [`Self::retire_svid_fingerprints`]
    /// — which are rare and for which the module already accepts over-broad
    /// fencing.
    ///
    /// It closes the ENTRY-side half of the drain race (issue #5042 step 2
    /// re-review). Both retirements bump FIRST and then walk `entries` shard by
    /// shard; a checkout that read the lease fence after the bump and won the
    /// shard race before the walk reached that shard would otherwise take a
    /// pre-drain entry, serve a request on it, and stamp the CURRENT lease
    /// generation onto its check-in — re-pooling, under its old key, a
    /// connection built on CRL-revoked or rotated-out material, with every
    /// later hit refreshing its idle clock. Stamping the entry is the only
    /// thing that catches it: reading the generation after the take does not.
    /// The sibling `unix_backend_pool::take_idle_h1` carries the same stamp and
    /// the same rule — never hand it out, and never launder it by adopting the
    /// caller's generation.
    entry_drain_generation: AtomicU64,
    /// Source of [`IdleH1::id`].
    next_entry_id: AtomicU64,
    last_idle_prune_unix_secs: AtomicU64,
    h1_hits: AtomicU64,
    h1_misses: AtomicU64,
    h2_hits: AtomicU64,
    h2_misses: AtomicU64,
    evictions: AtomicU64,
    discards: AtomicU64,
    /// Check-ins and publications refused because a retirement ran while the
    /// lease was outstanding.
    fenced_checkins: AtomicU64,
}

impl HboneInnerConnectionPool {
    pub fn new(shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount.max(1)),
            pooled: AtomicUsize::new(0),
            drain_generation: AtomicU64::new(0),
            entry_drain_generation: AtomicU64::new(0),
            next_entry_id: AtomicU64::new(0),
            last_idle_prune_unix_secs: AtomicU64::new(0),
            h1_hits: AtomicU64::new(0),
            h1_misses: AtomicU64::new(0),
            h2_hits: AtomicU64::new(0),
            h2_misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            discards: AtomicU64::new(0),
            fenced_checkins: AtomicU64::new(0),
        }
    }

    /// The current retirement generation, snapshotted by a dispatch BEFORE it
    /// dials so a retirement that lands during the dial cannot be laundered.
    #[inline]
    pub fn drain_generation(&self) -> u64 {
        self.drain_generation.load(Ordering::Acquire)
    }

    /// Invalidate every OUTSTANDING lease by advancing the retirement
    /// generation. Called BEFORE each retirement pass, never on the request
    /// path.
    #[inline]
    fn advance_drain_generation(&self) {
        self.drain_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// The current ENTRY retirement generation. Stamped onto an entry at
    /// insert and compared against inside the shard guard on checkout.
    #[inline]
    fn entry_drain_generation(&self) -> u64 {
        self.entry_drain_generation.load(Ordering::Acquire)
    }

    /// Supersede every RESIDENT entry. Called by the two whole-pool
    /// retirements BEFORE their map pass, so an entry a concurrent checkout
    /// snatches out of a shard the pass has not reached yet is still refused.
    #[inline]
    fn advance_entry_drain_generation(&self) {
        self.entry_drain_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Account one check-in or publication a RETIREMENT refused.
    ///
    /// Deliberately its OWN `event` label value rather than folding into
    /// `discard`: a discard says the destination did not offer reuse or a bound
    /// was reached, while this says a revocation ran while a lease was
    /// outstanding. An operator cannot act on the second without being able to
    /// see it apart from the first.
    #[inline]
    fn record_fenced_checkin(&self, protocol: HboneInnerProtocol) {
        self.fenced_checkins.fetch_add(1, Ordering::Relaxed);
        self.record(protocol, HboneInnerPoolEvent::Fenced);
    }

    pub fn stats(&self) -> HboneInnerPoolStats {
        HboneInnerPoolStats {
            h1_hits: self.h1_hits.load(Ordering::Relaxed),
            h1_misses: self.h1_misses.load(Ordering::Relaxed),
            h2_hits: self.h2_hits.load(Ordering::Relaxed),
            h2_misses: self.h2_misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            discards: self.discards.load(Ordering::Relaxed),
            pooled: self.pooled.load(Ordering::Relaxed) as u64,
        }
    }

    /// Resident inner connections right now.
    pub fn pooled_connections(&self) -> usize {
        self.pooled.load(Ordering::Relaxed)
    }

    /// Check-ins and publications a retirement fenced out. Exposed for the
    /// external fence regression tests.
    #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
    pub fn fenced_checkins(&self) -> u64 {
        self.fenced_checkins.load(Ordering::Relaxed)
    }

    /// The effective idle timeout for an inner connection under `pool_config`.
    fn idle_timeout_seconds(pool_config: &PoolConfig) -> u64 {
        pool_config
            .idle_timeout_seconds
            .max(MIN_INNER_IDLE_TIMEOUT_SECONDS)
    }

    /// How many nested HTTP/2 carriers ONE key may hold.
    ///
    /// The operator's existing per-destination HTTP/2 width
    /// (`FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST`) rather than a new knob,
    /// clamped by [`MAX_SHARED_H2_PER_KEY`]: the nested carriers ride CONNECT
    /// streams on the OUTER sessions that same knob already widens, so letting
    /// the inner width exceed the fixed clamp would multiply the destination's
    /// held stream count without an operator ever asking for it.
    ///
    /// `clamp` cannot panic here: its bounds are the literal `1` and a
    /// compile-time constant that is greater than it.
    fn shared_h2_width(pool_config: &PoolConfig) -> usize {
        pool_config
            .http2_connections_per_host
            .clamp(1, MAX_SHARED_H2_PER_KEY)
    }

    fn record(&self, protocol: HboneInnerProtocol, event: HboneInnerPoolEvent) {
        crate::plugins::prometheus_metrics::global_registry()
            .record_hbone_inner_pool_event(protocol.event_protocol(), event);
    }

    fn record_hit(&self, protocol: HboneInnerProtocol) {
        match protocol {
            HboneInnerProtocol::Http1 => self.h1_hits.fetch_add(1, Ordering::Relaxed),
            HboneInnerProtocol::H2 => self.h2_hits.fetch_add(1, Ordering::Relaxed),
        };
        self.record(protocol, HboneInnerPoolEvent::Hit);
    }

    fn record_miss(&self, protocol: HboneInnerProtocol) {
        match protocol {
            HboneInnerProtocol::Http1 => self.h1_misses.fetch_add(1, Ordering::Relaxed),
            HboneInnerProtocol::H2 => self.h2_misses.fetch_add(1, Ordering::Relaxed),
        };
        self.record(protocol, HboneInnerPoolEvent::Miss);
    }

    fn record_evictions(&self, protocol: HboneInnerProtocol, count: usize) {
        if count == 0 {
            return;
        }
        self.evictions.fetch_add(count as u64, Ordering::Relaxed);
        self.release_pooled(count);
        // Resolve the registry ONCE: a whole-pool drain evicts many entries at
        // a time and `global_registry()` clones an `Arc` on every call.
        let registry = crate::plugins::prometheus_metrics::global_registry();
        for _ in 0..count {
            registry.record_hbone_inner_pool_event(
                protocol.event_protocol(),
                HboneInnerPoolEvent::Eviction,
            );
        }
    }

    fn record_discard(&self, protocol: HboneInnerProtocol) {
        self.discards.fetch_add(1, Ordering::Relaxed);
        self.record(protocol, HboneInnerPoolEvent::Discard);
    }

    /// Give `count` residency slots back to the global ceiling.
    ///
    /// Saturating: the counter is maintained at every insert and removal, and a
    /// gauge that can go negative would be worse than one that briefly
    /// over-reports, since the ceiling is what it guards.
    fn release_pooled(&self, count: usize) {
        let _ = self
            .pooled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(count))
            });
    }

    /// Claim ONE residency slot under the global ceiling, or report that the
    /// pool is full.
    ///
    /// An atomic reservation rather than a read-then-insert: N concurrent
    /// check-ins that each merely OBSERVED `pooled < MAX` would all insert and
    /// overshoot the ceiling by up to N-1 until the next prune. The caller
    /// gives the slot back with [`Self::release_pooled`] if its insert is then
    /// refused for any other reason.
    fn reserve_pooled(&self) -> bool {
        self.pooled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_POOLED_INNER_CONNECTIONS).then_some(current + 1)
            })
            .is_ok()
    }

    /// Whether a pooled entry is still usable right now.
    fn entry_live(
        closed: bool,
        last_used_at: u64,
        idle_timeout_seconds: u64,
        credential_deadline: Option<tokio::time::Instant>,
        now_secs: u64,
        now_mono: tokio::time::Instant,
    ) -> bool {
        !closed
            && !entry_idle_expired(last_used_at, idle_timeout_seconds, now_secs)
            && credential_deadline.is_none_or(|deadline| now_mono < deadline)
    }

    /// The earlier of two optional monotonic deadlines. `None` on either side
    /// means "this credential published no representable bound", never
    /// "unbounded wins".
    pub fn earliest_deadline(
        left: Option<tokio::time::Instant>,
        right: Option<tokio::time::Instant>,
    ) -> Option<tokio::time::Instant> {
        match (left, right) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }

    /// Amortised idle/expiry sweep. Runs at most once every
    /// [`IDLE_PRUNE_INTERVAL_SECONDS`], on a checkout, never on a timer and
    /// never on the byte path.
    fn maybe_prune(&self) {
        let now = unix_secs();
        let last = self.last_idle_prune_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < IDLE_PRUNE_INTERVAL_SECONDS
            || self
                .last_idle_prune_unix_secs
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let now_mono = tokio::time::Instant::now();
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|_, slot| {
            let before = slot.h1_idle.len();
            slot.h1_idle.retain(|entry| {
                Self::entry_live(
                    entry.sender.is_closed(),
                    entry.last_used_at.load(Ordering::Relaxed),
                    entry.idle_timeout_seconds,
                    entry.credential_deadline,
                    now,
                    now_mono,
                )
            });
            h1_dropped = h1_dropped.saturating_add(before.saturating_sub(slot.h1_idle.len()));
            let before_h2 = slot.h2.len();
            slot.h2.retain(|entry| {
                Self::entry_live(
                    entry.sender.is_closed(),
                    entry.last_used_at.load(Ordering::Relaxed),
                    entry.idle_timeout_seconds,
                    entry.credential_deadline,
                    now,
                    now_mono,
                )
            });
            h2_dropped = h2_dropped.saturating_add(before_h2.saturating_sub(slot.h2.len()));
            !slot.is_empty()
        });
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }

    /// Take an idle inner HTTP/1.1 sender for `key`, with the credential
    /// deadline it was pooled under.
    ///
    /// Every entry the scan rejects is EVICTED rather than skipped: a closed,
    /// idle-expired, credential-expired, or drain-superseded connection must
    /// not stay reachable.
    ///
    /// The ENTRY retirement generation is read INSIDE the shard guard, after
    /// the guard is taken — the sibling `unix_backend_pool::take_idle_h1` reads
    /// it in exactly that position and for exactly this reason. A whole-pool
    /// retirement bumps it and then walks the shards; holding this shard's
    /// guard means the walk has either already passed here (and this entry
    /// would be gone) or has not reached here yet (and the bump is visible in
    /// this read). Either way an entry stamped with an older value is dropped,
    /// never handed out and never re-stamped with the caller's generation.
    fn take_idle_h1(
        &self,
        key: &str,
    ) -> Option<(HboneInnerH1Sender, Option<tokio::time::Instant>)> {
        let now = unix_secs();
        let now_mono = tokio::time::Instant::now();
        let mut evicted = 0usize;
        let mut taken = None;
        let mut emptied = false;
        if let Some(mut slot) = self.entries.get_mut(key) {
            let entry_generation = self.entry_drain_generation();
            while let Some(entry) = slot.h1_idle.pop() {
                if entry.entry_generation == entry_generation
                    && Self::entry_live(
                        entry.sender.is_closed(),
                        entry.last_used_at.load(Ordering::Relaxed),
                        entry.idle_timeout_seconds,
                        entry.credential_deadline,
                        now,
                        now_mono,
                    )
                {
                    taken = Some((entry.sender, entry.credential_deadline));
                    break;
                }
                evicted = evicted.saturating_add(1);
            }
            emptied = slot.is_empty();
        }
        if emptied {
            self.entries.remove_if(key, |_, slot| slot.is_empty());
        }
        self.record_evictions(HboneInnerProtocol::Http1, evicted);
        if taken.is_some() {
            // The taken connection leaves the pool for the duration of the
            // exclusive lease; a check-in re-counts it.
            self.release_pooled(1);
        }
        taken
    }

    /// Check out an inner HTTP/1.1 lease for `parts`, or `None` when nothing
    /// reusable exists and the caller must dial a fresh CONNECT.
    ///
    /// `keep_alive` is the dispatch's effective `pool_enable_http_keep_alive`.
    /// With it off the idle set is not even consulted: nothing is ever checked
    /// in under that policy, so there is nothing to find.
    ///
    /// `credential_deadline` is the CURRENT request's source credential bound.
    /// It does NOT decide whether the pooled entry may exist — that is the
    /// entry's OWN recorded bound, and an elapsed one evicts. It is folded
    /// into the lease that comes back, so the bound a connection carries only
    /// ever TIGHTENS across the requests that use it and reuse can never
    /// prolong a credential's lifetime. Whether a request whose own credential
    /// has already elapsed may be dispatched at all is the request
    /// authorization lifetime's decision, taken before this pool is consulted.
    pub fn checkout_h1(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        keep_alive: bool,
        credential_deadline: Option<tokio::time::Instant>,
    ) -> Option<HboneInnerH1Checkout> {
        if !keep_alive {
            return None;
        }
        self.maybe_prune();
        let idle_timeout_seconds = Self::idle_timeout_seconds(parts.pool_config);
        // Read the retirement generation BEFORE the take. A drain that lands
        // between here and the check-in must fence this lease out, and reading
        // first is what makes "concurrent with the take" fall on the refusing
        // side.
        let generation = self.drain_generation();
        let taken = with_hbone_inner_pool_key(parts, |key, spans| {
            self.take_idle_h1(key)
                .map(|(sender, pooled_deadline)| (key.to_string(), spans, sender, pooled_deadline))
        });
        let (key, spans, sender, pooled_deadline) = taken?;
        self.record_hit(HboneInnerProtocol::Http1);
        Some(HboneInnerH1Checkout {
            key,
            spans,
            generation,
            reused: true,
            credential_deadline: Self::earliest_deadline(pooled_deadline, credential_deadline),
            idle_timeout_seconds,
            poolable: true,
            sender,
        })
    }

    /// Wrap a freshly established inner HTTP/1.1 sender as a lease that is
    /// used ONCE and never pooled, with no key and no accounting.
    ///
    /// The escape hatch for a dispatch that has no pool identity to file the
    /// connection under — this gateway could not resolve its own SVID
    /// identity, which is already fatal for the dial the caller is about to
    /// report. Behaviourally identical to the pre-#5042 path, which is the
    /// point: the absence of a key must degrade to per-request behaviour, never
    /// to a connection pooled under a partial identity.
    pub fn unpooled_h1(sender: HboneInnerH1Sender) -> HboneInnerH1Checkout {
        HboneInnerH1Checkout {
            key: String::new(),
            spans: HboneInnerKeySpans::default(),
            // Never pooled, so no retirement can reach it and no generation
            // can fence it; the check-in refuses on `poolable` first.
            generation: 0,
            reused: false,
            credential_deadline: None,
            idle_timeout_seconds: MIN_INNER_IDLE_TIMEOUT_SECONDS,
            poolable: false,
            sender,
        }
    }

    /// Wrap a freshly established inner HTTP/1.1 sender as a lease.
    ///
    /// `peer_advertises_fence` is
    /// [`super::hbone_pool::H2ConnectTunnel::peer_advertises_inner_reuse`] for
    /// the CONNECT this sender runs inside. `false` produces a lease that is
    /// used once and never pooled, which is exactly the pre-#5042 behaviour.
    ///
    /// `generation` is [`Self::drain_generation`] read BEFORE the CONNECT was
    /// dialled. A retirement that landed while the dial was in flight retired
    /// everything this connection's key could name, so the lease must not be
    /// able to re-populate that key afterwards — the same hazard the outer
    /// pool refuses to pool a mid-rotation transport for.
    pub fn fresh_h1(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        sender: HboneInnerH1Sender,
        peer_advertises_fence: bool,
        keep_alive: bool,
        credential_deadline: Option<tokio::time::Instant>,
        generation: u64,
    ) -> HboneInnerH1Checkout {
        let (key, spans) = with_hbone_inner_pool_key(parts, |key, spans| (key.to_string(), spans));
        self.record_miss(HboneInnerProtocol::Http1);
        HboneInnerH1Checkout {
            key,
            spans,
            generation,
            reused: false,
            credential_deadline,
            idle_timeout_seconds: Self::idle_timeout_seconds(parts.pool_config),
            poolable: peer_advertises_fence && keep_alive,
            sender,
        }
    }

    /// Return an inner HTTP/1.1 lease to the idle set once hyper's dispatcher
    /// has re-armed.
    ///
    /// The caller must already have proven that the ENTIRE response body was
    /// read: `SendRequest::is_ready()` is only the second half of the check.
    /// h1 `can_write_head()` is true while a response body is still being read,
    /// so readiness alone would pool a connection mid-body. It is consulted
    /// only to close the dispatcher re-arm gap — `try_send_request` does not
    /// wait for readiness, so a sender pooled before its dispatcher re-arms
    /// would bounce the next request.
    ///
    /// If the connection died instead, `ready()` resolves `Err` and the lease
    /// is dropped, so the waiter lives exactly as long as the connection it
    /// owns and cannot leak.
    pub fn checkin_h1_when_idle(pool: &Arc<Self>, mut checkout: HboneInnerH1Checkout) {
        if !checkout.poolable
            || checkout.sender.is_closed()
            || checkout
                .credential_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            pool.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        // Retirement fence, fast path. A lease whose incarnation is already
        // retired is dropped HERE rather than parked in a waiter task for a
        // connection that can never be pooled. `checkin_h1` re-evaluates the
        // fence in full; this only avoids the task.
        if pool.drain_generation() != checkout.generation {
            pool.record_fenced_checkin(HboneInnerProtocol::Http1);
            return;
        }
        if checkout.sender.is_ready() {
            pool.checkin_h1(checkout);
            return;
        }
        let pool = Arc::clone(pool);
        tokio::spawn(async move {
            if checkout.sender.ready().await.is_ok() {
                pool.checkin_h1(checkout);
            } else {
                pool.record_discard(HboneInnerProtocol::Http1);
            }
        });
    }

    /// Insert a proven-idle inner HTTP/1.1 sender, subject to the per-key and
    /// global bounds. Over-cap is a DISCARD, not an error: the connection is
    /// simply closed, which is the pre-#5042 cost.
    ///
    /// The dispatch path MUST NOT call this directly for a connection that
    /// carried a request — use [`Self::checkin_h1_when_idle`], which first
    /// waits for hyper to report the exchange complete. This entry point is for
    /// a lease whose request was abandoned before it was ever sent, and for
    /// tests. A closed sender is still dropped rather than pooled.
    ///
    /// # The retirement fence
    ///
    /// The generation is read TWICE, around the insert, exactly as
    /// `unix_backend_pool::checkin_h1_fenced` reads its publication generation.
    /// An outstanding lease is not in `entries`, so a retirement pass cannot
    /// reach it by clearing them; the first read refuses a lease whose
    /// retirement already completed, and the second catches a retirement that
    /// ran concurrently — either it saw this entry and removed it, or it
    /// released the shard before this insert took it and the bump is visible
    /// now. The shard guard is released BEFORE the second read on purpose: that
    /// release/acquire pair is what orders the two.
    pub fn checkin_h1(&self, checkout: HboneInnerH1Checkout) {
        let HboneInnerH1Checkout {
            key,
            spans,
            generation,
            credential_deadline,
            idle_timeout_seconds,
            sender,
            ..
        } = checkout;
        if sender.is_closed() {
            self.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        // Fence, first read.
        if self.drain_generation() != generation {
            drop(sender);
            self.record_fenced_checkin(HboneInnerProtocol::Http1);
            return;
        }
        if !self.reserve_pooled() {
            self.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        let entry_id = self.next_entry_id.fetch_add(1, Ordering::Relaxed);
        let mut pending = Some(IdleH1 {
            id: entry_id,
            // The ENTRY fence, stamped at insert. A whole-pool retirement that
            // already ran makes this stamp stale on arrival and the next
            // checkout evicts instead of serving; one that runs afterwards is
            // caught by the second read below or by its own map pass.
            entry_generation: self.entry_drain_generation(),
            sender,
            last_used_at: AtomicU64::new(unix_secs()),
            idle_timeout_seconds,
            credential_deadline,
        });
        // Fast path: a key that is already resident needs no second copy of the
        // key string, so a steady-state check-in allocates nothing. Only a
        // genuine first insert pays `entry(key.clone())`.
        let mut resident = false;
        if let Some(mut slot) = self.entries.get_mut(key.as_str()) {
            resident = true;
            if let Some(entry) = pending.take() {
                pending = slot.try_push_h1(entry);
            }
            // The shard guard is released HERE, before the second fence read.
        }
        if !resident {
            let mut slot = self
                .entries
                .entry(key.clone())
                .or_insert_with(|| KeySlot::new(spans));
            if let Some(entry) = pending.take() {
                pending = slot.try_push_h1(entry);
            }
            // The shard guard is released HERE, before the second fence read.
        }
        if pending.is_some() {
            self.release_pooled(1);
            self.record_discard(HboneInnerProtocol::Http1);
            return;
        }
        // Fence, second read.
        if self.drain_generation() != generation && self.withdraw_h1_entry(&key, entry_id) {
            self.record_fenced_checkin(HboneInnerProtocol::Http1);
        }
    }

    /// Remove the idle HTTP/1.1 entry `id` from `key`, releasing its residency
    /// slot. Returns whether it was still there.
    ///
    /// Matched by entry id rather than by key alone so a retirement-fenced
    /// check-in never withdraws a NEWER carrier that a concurrent dispatch
    /// pooled under the same key.
    fn withdraw_h1_entry(&self, key: &str, id: u64) -> bool {
        let mut withdrawn = false;
        let mut emptied = false;
        if let Some(mut slot) = self.entries.get_mut(key) {
            let before = slot.h1_idle.len();
            slot.h1_idle.retain(|entry| entry.id != id);
            withdrawn = slot.h1_idle.len() < before;
            emptied = slot.is_empty();
        }
        if emptied {
            self.entries.remove_if(key, |_, slot| slot.is_empty());
        }
        if withdrawn {
            self.release_pooled(1);
        }
        withdrawn
    }

    /// Wrap an exclusive inner HTTP/1.1 lease as a
    /// [`crate::proxy::body::PooledBackendLease`] for a STREAMING response.
    ///
    /// The returned guard owns the lease for as long as the `ProxyBody` holding
    /// the backend stream lives; that body releases it only on a proven clean
    /// backend end and drops it on every other terminal. Because the guard owns
    /// the only checkout, the connection cannot be handed to another request
    /// while the body is still streaming.
    pub fn streaming_lease(
        pool: &Arc<Self>,
        checkout: HboneInnerH1Checkout,
    ) -> Box<dyn crate::proxy::body::PooledBackendLease> {
        Box::new(HboneInnerH1StreamingLease {
            pool: Arc::clone(pool),
            checkout: Some(checkout),
        })
    }

    /// Clone the shared inner HTTP/2 sender for `parts`, or `None` on a miss.
    ///
    /// A sender that reports `is_closed()` — GOAWAY received and drained, the
    /// tunnel cut by a fence sweep, a transport error — is EVICTED here rather
    /// than skipped, so it can never be handed out again. That is the same
    /// liveness predicate `Http2PoolManager::is_healthy` applies to a direct
    /// HTTP/2 carrier; a busy-but-live multiplexed sender is deliberately kept,
    /// since retiring one for transient stream backpressure would replace
    /// multiplexing with a connection per RPC.
    ///
    /// The dispatch's effective `pool_enable_http_keep_alive` gates this
    /// exactly as it gates [`Self::checkout_h1`] (issue #5042 step 2
    /// re-review). With it off nothing is ever published under this key, so
    /// there is nothing to find — and, more importantly, an entry that DID
    /// exist would be retired on every publication, because
    /// `collect_live_hbone_inner_routes` skips a keep-alive-off proxy and
    /// [`Self::retain_live_routes`] fences every outstanding lease POOL-WIDE
    /// each time it retires anything.
    pub fn checkout_h2(&self, parts: &HboneInnerKeyParts<'_>) -> Option<HboneInnerH2Checkout> {
        if !parts.pool_config.enable_http_keep_alive {
            self.record_miss(HboneInnerProtocol::H2);
            return None;
        }
        self.maybe_prune();
        let now = unix_secs();
        let now_mono = tokio::time::Instant::now();
        let width = Self::shared_h2_width(parts.pool_config);
        let mut evicted = 0usize;
        let mut taken: Option<(HboneInnerH2Sender, HboneInnerH2Load)> = None;
        with_hbone_inner_pool_key(parts, |key, _| {
            let mut emptied = false;
            if let Some(mut slot) = self.entries.get_mut(key) {
                // The ENTRY retirement generation, read INSIDE the shard guard
                // for the reason `take_idle_h1` states: a carrier a whole-pool
                // drain has superseded is evicted here rather than cloned out
                // of a shard the drain's walk has not reached yet.
                let entry_generation = self.entry_drain_generation();
                let before = slot.h2.len();
                slot.h2.retain(|entry| {
                    entry.entry_generation == entry_generation
                        && Self::entry_live(
                            entry.sender.is_closed(),
                            entry.last_used_at.load(Ordering::Relaxed),
                            entry.idle_timeout_seconds,
                            // The ENTRY's own bound, deliberately not folded
                            // with the current request's. The two answer
                            // different questions: whether this carrier may
                            // still exist (the pool's job), and whether this
                            // request may still be served (the request
                            // authorization lifetime's job, decided before
                            // dispatch). Folding them would evict a healthy
                            // multiplexed carrier — and every other RPC on
                            // it — because ONE caller arrived with a
                            // short-lived JWT.
                            entry.credential_deadline,
                            now,
                            now_mono,
                        )
                });
                evicted = before.saturating_sub(slot.h2.len());
                // Least-loaded with room under the nested peer's stream cap,
                // mirroring the outer pool's `select_least_loaded`. A carrier
                // at its cap is NOT retired — retiring one for transient
                // stream backpressure would replace multiplexing with a
                // connection per RPC — it just stops being selectable while a
                // sibling can still be opened.
                let with_room = slot
                    .h2
                    .iter()
                    .filter(|entry| !entry.load.is_saturated())
                    .min_by_key(|entry| entry.load.active_rpcs());
                // Every live carrier at the peer's cap: widen while the key has
                // room, otherwise queue on the least loaded, which `h2` parks
                // pending-open behind a sibling stream exactly as the outer
                // pool's saturated branch does.
                let chosen = if with_room.is_some() {
                    with_room
                } else if slot.h2.len() >= width {
                    slot.h2.iter().min_by_key(|entry| entry.load.active_rpcs())
                } else {
                    None
                };
                if let Some(entry) = chosen {
                    entry.last_used_at.store(now, Ordering::Relaxed);
                    taken = Some((entry.sender.clone(), entry.load.clone()));
                }
                emptied = slot.is_empty();
            }
            if emptied {
                self.entries.remove_if(key, |_, slot| slot.is_empty());
            }
        });
        self.record_evictions(HboneInnerProtocol::H2, evicted);
        let Some((sender, load)) = taken else {
            self.record_miss(HboneInnerProtocol::H2);
            return None;
        };
        let lease = load.lease();
        self.record_hit(HboneInnerProtocol::H2);
        Some(HboneInnerH2Checkout { sender, lease })
    }

    /// Publish a freshly established nested inner HTTP/2 sender and account for
    /// the dispatch that is about to use it.
    ///
    /// Never an error and never a refusal to the CALLER: it already owns the
    /// sender and serves its RPC on it either way, and the returned lease is
    /// its accounting hold whether or not the carrier was pooled. A peer that
    /// did not advertise the fence, a dispatch with keep-alive off, source TLS
    /// material that moved during the dial, a retirement that landed during
    /// the dial, an elapsed credential deadline, the global ceiling, and a key
    /// already at its [`Self::shared_h2_width`] all leave the sender
    /// UNPOOLED — which is exactly the per-request behaviour this module
    /// replaces.
    ///
    /// [`HboneInnerH2Publication::source_material_unchanged`] mirrors the
    /// refusal `HboneConnectionPool::get_tunnel_via` applies to the OUTER
    /// transport: a gateway SVID slot, CRL slot, or current leaf fingerprint
    /// that moved while this dial was in flight means pooling under this key
    /// would resurrect a connection AFTER its one-shot drain already ran. The
    /// nested sender rides the very transport the outer pool declined to pool,
    /// so it must decline for the same reason.
    ///
    /// [`HboneInnerH2Publication::generation`] is [`Self::drain_generation`]
    /// read BEFORE the dial; see [`Self::checkin_h1`] for why the fence is read
    /// again after the insert.
    pub fn publish_h2(
        &self,
        parts: &HboneInnerKeyParts<'_>,
        sender: &HboneInnerH2Sender,
        publication: HboneInnerH2Publication,
    ) -> HboneInnerH2StreamLease {
        let HboneInnerH2Publication {
            peer_advertises_fence,
            source_material_unchanged,
            load,
            credential_deadline,
            generation,
        } = publication;
        // The caller's own hold on the carrier, taken whether or not the
        // publication is accepted. The cap inside `load` is maintained by the
        // carrier's connection driver, so it is already current here and stays
        // current for as long as the carrier lives.
        let lease = load.lease();
        if !peer_advertises_fence
            || !parts.pool_config.enable_http_keep_alive
            || !source_material_unchanged
            || sender.is_closed()
            || credential_deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            self.record_discard(HboneInnerProtocol::H2);
            return lease;
        }
        // Fence, first read.
        if self.drain_generation() != generation {
            self.record_fenced_checkin(HboneInnerProtocol::H2);
            return lease;
        }
        if !self.reserve_pooled() {
            self.record_discard(HboneInnerProtocol::H2);
            return lease;
        }
        let idle_timeout_seconds = Self::idle_timeout_seconds(parts.pool_config);
        let width = Self::shared_h2_width(parts.pool_config);
        // The ENTRY fence, stamped at insert; see `checkin_h1`.
        let entry_generation = self.entry_drain_generation();
        let (key, published, evicted) = with_hbone_inner_pool_key(parts, |key, spans| {
            let key = key.to_string();
            let mut pending = Some(SharedH2 {
                sender: sender.clone(),
                load: load.clone(),
                entry_generation,
                last_used_at: AtomicU64::new(unix_secs()),
                idle_timeout_seconds,
                credential_deadline,
            });
            let mut evicted = 0usize;
            // Fast path: a key that is already resident needs no second copy of
            // the key string. Only a genuine first insert pays
            // `entry(key.clone())`.
            let mut resident = false;
            if let Some(mut slot) = self.entries.get_mut(key.as_str()) {
                resident = true;
                evicted = slot.retire_closed_h2();
                if let Some(entry) = pending.take() {
                    pending = slot.try_push_h2(entry, width);
                }
                // The shard guard is released HERE, before the second fence read.
            }
            if !resident {
                let mut slot = self
                    .entries
                    .entry(key.clone())
                    .or_insert_with(|| KeySlot::new(spans));
                evicted = slot.retire_closed_h2();
                if let Some(entry) = pending.take() {
                    pending = slot.try_push_h2(entry, width);
                }
                // The shard guard is released HERE, before the second fence read.
            }
            (key, pending.is_none(), evicted)
        });
        self.record_evictions(HboneInnerProtocol::H2, evicted);
        if !published {
            self.release_pooled(1);
            self.record_discard(HboneInnerProtocol::H2);
            return lease;
        }
        // Fence, second read.
        if self.drain_generation() != generation && self.withdraw_h2_entry(&key, &load) {
            self.record_fenced_checkin(HboneInnerProtocol::H2);
        }
        lease
    }

    /// Remove the nested HTTP/2 carrier identified by `load` from `key`,
    /// releasing its residency slot. Returns whether it was still there.
    ///
    /// Matched by load identity (`Arc::ptr_eq`) rather than by key alone so a
    /// retirement-fenced publication never withdraws a NEWER carrier a
    /// concurrent dispatch published under the same key.
    fn withdraw_h2_entry(&self, key: &str, load: &HboneInnerH2Load) -> bool {
        let mut withdrawn = false;
        let mut emptied = false;
        if let Some(mut slot) = self.entries.get_mut(key) {
            let before = slot.h2.len();
            slot.h2.retain(|entry| !Arc::ptr_eq(&entry.load.0, &load.0));
            withdrawn = slot.h2.len() < before;
            emptied = slot.is_empty();
        }
        if emptied {
            self.entries.remove_if(key, |_, slot| slot.is_empty());
        }
        if withdrawn {
            self.release_pooled(1);
        }
        withdrawn
    }

    /// Retire every inner connection whose key embeds one of the `retired`
    /// gateway SVID leaf fingerprints.
    ///
    /// Driven by the outer pool's SVID rotation drain, so an inner connection
    /// established under a rotated-out leaf stops being reachable at exactly
    /// the moment the outer sessions built from it do.
    ///
    /// BOTH retirement generations are advanced FIRST, deliberately for the
    /// WHOLE pool rather than for the retired fingerprints alone.
    ///
    /// The LEASE generation ([`Self::drain_generation`]) because a lease that
    /// is checked out right now is not in `entries` for this pass to examine,
    /// and there is nothing on the pool side to compare it against without
    /// re-deriving its key. The ENTRY generation
    /// ([`Self::entry_drain_generation`]) because this pass takes each shard
    /// lock in turn, so a concurrent checkout can win a shard the pass has not
    /// reached yet; without the stamp it would take a pre-retirement entry,
    /// serve a request on it, and file it back under its old key.
    ///
    /// A rotation is rare, and the cost of the over-broad fence is that
    /// concurrently-outstanding leases AND resident entries under OTHER
    /// fingerprints pay one extra CONNECT each. Resident entries under another
    /// fingerprint are left in the map by the retain below — nothing scans them
    /// eagerly — and are evicted the next time a checkout examines them.
    pub fn retire_svid_fingerprints(&self, retired: &[Arc<str>]) {
        if retired.is_empty() {
            return;
        }
        self.advance_drain_generation();
        self.advance_entry_drain_generation();
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|key, slot| {
            let drain = hbone_inner_key_svid_fingerprint(key)
                .is_some_and(|fingerprint| retired.iter().any(|fp| fp.as_ref() == fingerprint));
            if drain {
                h1_dropped = h1_dropped.saturating_add(slot.h1_idle.len());
                h2_dropped = h2_dropped.saturating_add(slot.h2.len());
            }
            !drain
        });
        if h1_dropped + h2_dropped > 0 {
            debug!(
                h1_dropped,
                h2_dropped,
                "hbone_inner_pool: retired inner application connections for rotated SVID leaves"
            );
        }
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }

    /// Retire every pooled inner connection whose route-generation identity is
    /// absent from `live` (issue #5042 step 2 review).
    ///
    /// Called from every publication that becomes current, never on the request
    /// path. The cases it closes are the ones a key CHANGE makes unreachable
    /// but nothing retires: a proxy deleted or re-bound (a new lifecycle
    /// generation is a new key) and an effective `pool_enable_http_keep_alive`
    /// flipped off (the leading `write_pool_config_key` field is a new key).
    /// Such entries hold an outer HTTP/2 stream, a destination `accept(2)`, and
    /// a destination fence-registry entry until the amortised idle sweep
    /// notices them, which needs `max(pool idle_timeout, 15s)` AND a checkout
    /// on some other key to fire. This is the synchronous half, mirroring
    /// `unix_backend_pool::retain_live_targets_for_publication`.
    ///
    /// `live` holds route identities rendered by
    /// [`write_hbone_inner_route_identity`] for every proxy the published
    /// configuration declares WITH keep-alive reuse on. It is deliberately a
    /// SUPERSET of the routes that could own a pooled connection — an upstream
    /// re-pointed under an unchanged proxy is not caught here, because a route
    /// override can resolve an effective upstream the published proxy does not
    /// declare and comparing on it would retire live routes on every
    /// publication.
    ///
    /// A pooled entry whose route carries NO lifecycle generation is EXEMPT:
    /// its proxy was not resolvable in any published generation when the lease
    /// was created (a synthesized relay proxy is absent from every generation
    /// by design), so the published configuration cannot speak about it and
    /// treating its absence as a withdrawal would retire it on every
    /// publication. Those stay bounded by the idle timeout.
    ///
    /// This pass advances the LEASE generation only, never
    /// [`Self::entry_drain_generation`]. It removes the keys it retires by
    /// name, so it has no shard-walk race to close — and stamping entries
    /// against a counter a publication advances would evict every RESIDENT
    /// entry, on every key, each time any route was withdrawn.
    pub fn retain_live_routes(&self, live: &std::collections::HashSet<String>) {
        // Read-only first pass: a publication that withdraws nothing must not
        // advance the generation and fence every outstanding lease.
        let mut retire: Vec<String> = Vec::new();
        for entry in self.entries.iter() {
            let Some(route) = entry.value().spans.route(entry.key()) else {
                continue;
            };
            // Absent lifecycle generation: the empty trailing segment.
            if route.ends_with('|') {
                continue;
            }
            if !live.contains(route) {
                retire.push(entry.key().clone());
            }
        }
        if retire.is_empty() {
            return;
        }
        self.advance_drain_generation();
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        for key in &retire {
            if let Some((_, slot)) = self.entries.remove(key) {
                h1_dropped = h1_dropped.saturating_add(slot.h1_idle.len());
                h2_dropped = h2_dropped.saturating_add(slot.h2.len());
            }
        }
        debug!(
            retired_keys = retire.len(),
            h1_dropped,
            h2_dropped,
            "hbone_inner_pool: retired inner application connections the published \
             configuration no longer declares as reusable"
        );
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }

    /// Retire EVERY pooled inner connection.
    ///
    /// The transitive half of the outer pool's whole-pool retirements: a CRL
    /// reload, a committed gateway trust withdrawal, and a forced drain all
    /// clear the outer HBONE transports whole, and an inner connection is only
    /// ever as trustworthy as the tunnel it rides.
    ///
    /// BOTH retirement generations are advanced FIRST, and that is what makes
    /// the drain terminal. Clearing the map is only half of it, on both sides:
    ///
    /// * **Lease side.** In-flight exchanges are NOT in `entries` — an
    ///   exclusive H1 lease is checked out precisely so that it is not — so
    ///   clearing the map cannot reach them. Every lease outstanding at the
    ///   instant of the bump is bound to a superseded
    ///   [`Self::drain_generation`], so its check-in is refused whether it
    ///   lands before or after the clear.
    /// * **Entry side.** The clear takes each DashMap shard lock in turn, so a
    ///   checkout that reads the lease generation after the bump can still win
    ///   a shard the clear has not reached and take a PRE-DRAIN entry. It would
    ///   then serve a request on material the drain retired and stamp its
    ///   check-in with the CURRENT generation, which both fence reads accept —
    ///   re-pooling it under its old key, with every later hit refreshing its
    ///   idle clock. Nothing else catches that: a CRL reload changes neither
    ///   the key's leaf fingerprint nor its recorded credential deadline. The
    ///   per-entry [`Self::entry_drain_generation`] stamp does, inside the
    ///   shard guard, by evicting rather than serving.
    pub fn drain_all(&self) {
        self.advance_drain_generation();
        self.advance_entry_drain_generation();
        let mut h1_dropped = 0usize;
        let mut h2_dropped = 0usize;
        self.entries.retain(|_, slot| {
            h1_dropped = h1_dropped.saturating_add(slot.h1_idle.len());
            h2_dropped = h2_dropped.saturating_add(slot.h2.len());
            false
        });
        self.record_evictions(HboneInnerProtocol::Http1, h1_dropped);
        self.record_evictions(HboneInnerProtocol::H2, h2_dropped);
    }
}

impl Default for HboneInnerConnectionPool {
    fn default() -> Self {
        Self::new(8)
    }
}

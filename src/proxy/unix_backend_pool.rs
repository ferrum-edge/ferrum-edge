//! Bounded connection pool for sidecar-ingress Unix-domain backends
//! (issue #3731).
//!
//! Complements [`super::unix_backend`]: every **new physical connection** still
//! runs the full admission gate — canonical containment, directory-chain
//! ownership, socket file type/owner/mode, the post-connect `(dev, ino)`
//! identity re-check, and peer-UID verification — under ONE end-to-end
//! establishment deadline. Pooling only removes the repeated `connect(2)` +
//! protocol handshake, never a check.
//!
//! ## One establishment deadline, opened before admission
//!
//! `connect_deadline` is the FIRST thing every checkout does — before the
//! amortized idle sweep (which scans the pool's maps and `stat`s socket paths),
//! before `admit_and_reconcile`, before the h2c creation-lock wait, before
//! `connect(2)`, before the protocol handshake and the peer's SETTINGS preface,
//! and (for WebSocket) before the RFC 6455 upgrade exchange the caller drives.
//! Every one of those stages is awaited through `timeout_at` on that SAME
//! absolute `Instant`. No stage derives a second budget from
//! `backend_connect_timeout_ms`, so an establishment can never consume two (or
//! three) full setup budgets. A synchronous admission `stat` cannot be
//! preempted while it executes, but the time it costs is charged all the same:
//! the next `timeout_at` resolves `Err` immediately once the deadline has
//! passed. An unreasonable operator duration — one past
//! `MAX_UNIX_CONNECT_TIMEOUT_MS` (the same 24h ceiling config validation
//! enforces), or one the platform clock cannot represent — still fails closed in
//! `connect_deadline` rather than becoming an effectively unbounded wait.
//!
//! ## The per-target physical-connection bound
//!
//! Issue #3731's pooling must not become a way to open unbounded physical
//! connections into the co-located application, so the pool enforces its own
//! INBOUND transport ceiling:
//! `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS` (default
//! [`super::DEFAULT_UNIX_INGRESS_MAX_CONNECTIONS`]; `0` disables it).
//!
//! It is deliberately NOT Istio's `connectionPool.tcp.maxConnections`. A
//! `DestinationRule` is OUTBOUND, client-side policy about a destination
//! service this workload calls; sidecar ingress is the opposite direction —
//! traffic the mesh already accepted, being handed to the local app over a
//! socket that has no network authority, no dial host, and no service port to
//! resolve a rule against. Reinterpreting an outbound rule as an inbound
//! ceiling would silently apply policy the operator wrote for a different
//! direction, and (because the materialized ingress upstream's target is a
//! placeholder `127.0.0.1:<listener_port>` under a synthetic
//! `__mesh-ingress-unix-*` id) it would in practice resolve to no rule at all.
//!
//! The bound is keyed by the COMPLETE [`UnixPoolKey`] — namespace, proxy id,
//! effective upstream id, configured and canonical socket path, the admitted
//! `(dev, ino, owner_uid)`, and the wire protocol. Sibling ingress listeners on
//! one workload, an `http`/`http2` protocol flip, and a replaced socket object
//! therefore each get their own lane and can neither steal nor accidentally
//! share one.
//!
//! One slot is one PHYSICAL connection. It is acquired at the single point a
//! new connection is about to be constructed — never on a pool hit, and never
//! per multiplexed h2c stream — and the guard is moved into that connection's
//! own driver task, so the slot is held for exactly the connection's lifetime
//! (idle residence included) and released on handshake failure, close,
//! eviction, withdrawal, drain, shutdown, and driver panic. An over-cap refusal
//! is the typed
//! [`crate::proxy::unix_backend::UnixBackendError::BackendConnectionLimit`]:
//! decided before `connect(2)`, so no socket is opened and no application byte
//! is written, and classified pre-wire and health-neutral.
//!
//! ## Driver ownership
//!
//! Every physical connection's driver future is REGISTERED with the pool
//! (`UnixDriverTracker`) instead of being detached with a bare
//! `tokio::spawn`. Dropping the sender maps is not equivalent to the bounded
//! close/await contract: a carrier checked out into an in-flight exchange, or
//! cloned into a multiplexed h2c request, is deliberately absent from those
//! maps and keeps its connection open. `shutdown_drain` therefore latches the
//! pool closed, drops every pooled carrier, awaits the remaining drivers under
//! one bounded budget, then aborts AND JOINS whatever is left under a second
//! bounded budget. The wait cannot be unbounded: a cancelled driver is reaped
//! before return when it drops within that budget, while an expired reap budget
//! is logged rather than silently presented as a completed join. The "physical
//! connections open" gauge and the
//! per-target connection slot are both released by a guard the driver FUTURE
//! owns, so they are exact on the graceful path, on the forced-abort path
//! (including a future aborted before its first poll), and on a driver panic
//! alike. Registration is also the shutdown boundary: after the latch, no
//! further driver is created at all — see "The shutdown boundary is terminal
//! in BOTH directions" below.
//!
//! ## Metrics
//!
//! [`UnixBackendConnectionPool::stats`] is the pool's bounded, fixed-cardinality
//! export: hits, misses, physical connects, identity retirements, setup
//! failures, gateway-side checkout refusals, and the idle / shared-carrier / open
//! physical-connection gauges. There are no per-target labels, and every field
//! is one atomic load — the gauges are maintained at each insert/removal and at
//! each driver spawn/completion, so producing the snapshot never scans a map.
//! The runtime metrics endpoint publishes it under
//! `connections.unix_backend_pool`.
//!
//! ## Identity is the key
//!
//! [`UnixPoolKey`] is a STRUCTURED key, not a formatted string: namespace,
//! proxy id, effective upstream id, canonical resolved path, the admitted
//! `(dev, ino, owner_uid)` of the socket object, and the wire protocol. Every
//! retirement is an exact field comparison — there is deliberately no substring
//! matching anywhere in this module, because a substring rule on a
//! security-sensitive retirement can both under-retire (a prefix that does not
//! align on a path segment) and over-retire.
//!
//! ## Config lifecycle
//!
//! The pool is owned by `ProxyState`, which SURVIVES a config reload (the
//! config itself is swapped through an `ArcSwap`), so publication has to retire
//! withdrawn carriers explicitly.
//!
//! EVERY successfully published request epoch reconciles the pool through
//! [`UnixBackendConnectionPool::retain_live_targets_for_publication`], with the
//! exact set of reusable `mesh.unix_socket` target identities THE CONFIG THAT
//! WAS ACTUALLY PUBLISHED declares. That is all three publication paths —
//! `ProxyState::update_config`'s
//! initial full rebuild, its incremental delta branch, and
//! `ProxyState::apply_incremental`'s separate database/CP-DP path — and the
//! call happens immediately after the epoch swap, BEFORE any early return for a
//! delta-free (mesh-only / MMDB-only / projected-route-only) republication. A
//! candidate that was REJECTED, and one the epoch swap reported as genuinely
//! unchanged (`Ok(None)`, which never becomes current), do not reconcile and do
//! not advance the generation.
//!
//! Every pooled carrier whose
//! `(namespace, proxy id, upstream id, configured path, wire protocol)` tuple is
//! not in that set is retired before it can serve another request. The
//! comparison is exact tuple equality — there is no substring, prefix, or
//! path-containment rule anywhere in this module, because such a rule on a
//! security-sensitive retirement both under-retires (a prefix that does not
//! align on a path segment) and over-retires.
//!
//! That covers a withdrawn target, a deleted proxy or upstream, a namespace or
//! upstream re-binding, a changed socket path, an `http` ⇄ `http2`
//! protocol flip, and an HTTP/1.1 target whose effective keep-alive/reuse
//! setting flipped off (so idle H1 carriers cannot pin the physical-connection
//! cap while new traffic must dial fresh). A change to the socket OBJECT (a
//! replaced inode or a new owner uid) is caught on the checkout path instead,
//! by `admit_and_reconcile`, because it is invisible to config. The containment
//! allowlist and UID allowlist are process env
//! (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` / `_ALLOWED_UIDS`) and cannot change
//! without a restart.
//!
//! ## The withdrawal fence
//!
//! Retiring the idle maps is NOT sufficient on its own. An HTTP/1.1 lease that
//! is checked out is deliberately absent from `h1_idle`, so a publication
//! cannot see it, and its exchange may finish long AFTER the target it belongs
//! to was withdrawn. Nothing about a socket that is still open and still names
//! the same inode would stop that late check-in from repopulating the idle set
//! under a config-declared identity that no longer exists.
//!
//! Every retirement bumps a monotonic PUBLICATION GENERATION
//! (`retain_live_targets`, `force_drain_all`, and hence `shutdown_drain`)
//! BEFORE its retirement pass runs. Three rules hang off that one counter, and
//! together they make a carrier NON-LAUNDERABLE: there is no instant, however
//! brief, at which a request can be handed a carrier that a publication has
//! already superseded.
//!
//! 1. **The lease token.** Every lease records the generation current when it
//!    was acquired, and a check-in is refused unless that is still the current
//!    generation. This generational test closes same-key ABA: a target
//!    withdrawn and re-added under the exact same tuple is a NEW incarnation,
//!    and a lease from the previous one must not re-enter it. The cost is that
//!    a lease outstanding across ANY publication is conservatively retired
//!    rather than reused — one connection per in-flight exchange per
//!    publication, paid off the hot path.
//! 2. **The entry token.** Every idle H1 entry and every shared h2c carrier
//!    also carries the generation it was PUBLISHED INTO THE MAP under, and a
//!    checkout refuses any entry whose token is not the current generation,
//!    reading both under the same shard guard. A two-read check-in fence alone
//!    was NOT enough: it makes an old-generation entry briefly VISIBLE between
//!    its insert and its withdrawal, and a concurrent checkout could pop it in
//!    that window and re-stamp it with the caller's own generation — laundering
//!    a carrier out of a withdrawn incarnation into a new request. With the
//!    token on the entry, that pop refuses instead.
//!
//!    So that an unrelated publication does not throw away every idle carrier
//!    in the pool, `retain_live_targets` ADVANCES the token of each retained
//!    entry to the new generation while it holds that entry's shard. Being
//!    observed under a still-declared identity is NOT on its own enough to earn
//!    that: an identity can be withdrawn and re-added under a byte-identical
//!    tuple, and a superseded check-in can insert into the gap. The pass
//!    therefore keeps the PREVIOUS publication's live set and restamps only
//!    identities declared by BOTH — the continuously-live intersection. An
//!    identity absent then and declared now is a re-added incarnation, and its
//!    slot is emptied rather than restamped. A token can never run ahead of the
//!    counter, so a lost update between two concurrent passes only ever refuses
//!    reuse.
//! 3. **The live-set snapshot.** Publication installs
//!    a lock-free snapshot of the exact identities it declares. A check-in or
//!    h2c publish compares the identity already owned by its pool key against
//!    that snapshot, without constructing strings, before it can become
//!    reusable. This covers a withdrawn identity even when the retirement pass
//!    found no existing slot. Empty withdrawn slots are not retained: the
//!    pre/post generation reads close the concurrent-insert window, while the
//!    previous/current live-set intersection closes same-tuple re-add ABA.
//!    Keeping one empty key until a long-lived socket inode disappeared would
//!    instead make logical config churn an unbounded memory input.
//!
//! ### The interleavings
//!
//! Publication is ordered "bump, install live snapshot, THEN retire"; a
//! check-in reads the generation, inserts a UNIQUELY IDENTIFIED entry, releases
//! the shard, and re-reads.
//!
//! * *Publication sees the insert.* The retirement pass finds the entry: it
//!   removes it (withdrawn identity, or an identity re-added after an absence)
//!   or advances its token (an identity live across both publications).
//! * *Publication completes before the insert.* The check-in's post-insert
//!   re-read observes the bump — the shard release/acquire pair orders it — and
//!   withdraws exactly the entry it inserted, by id, so a losing cleanup can
//!   never delete a newer sibling carrier for the same key.
//! * *A checkout races that window.* The entry is visible but still carries the
//!   OLD token, and the checkout compares the token against the generation it
//!   reads under the same shard guard. It refuses and drops it; it cannot be
//!   re-stamped into a new request.
//! * *Same-key withdraw/re-add ABA.* Rule 1 keeps the outstanding lease out
//!   (its token is two generations stale). Rule 3 keeps a stale-epoch dial's
//!   late check-in out for as long as the identity is withdrawn. The one
//!   interleaving those two do not cover on their own is a withdrawal with NO
//!   existing slot, so a check-in that already passed
//!   its live-set read can still create a fresh slot and insert its
//!   pre-withdrawal carrier before its own post-insert fence read runs. The
//!   re-add is what would have laundered it: the identity tuple is
//!   byte-identical, so a continuity rule based only on "declared now" would
//!   restamp that entry to the current generation and a racing checkout would
//!   accept it before the losing cleanup ran. Rule 2's continuity is therefore
//!   defined against the PREVIOUS live set: a re-add is a discontinuity even
//!   when the tuple is unchanged, and it empties the slot instead, so the new
//!   incarnation cannot inherit a carrier from the old one.
//! * *Late h2c publish.* `checkout_h2c` publishes its carrier into a shared map
//!   after a dial that can straddle a publication, so it runs the identical
//!   sequence: live-set check, insert with a token, post-insert re-read,
//!   exact-id withdrawal. `take_shared_h2c` refuses non-current tokens.
//! * *Shutdown.* `shutdown_drain` latches the pool closed AND bumps the
//!   generation, so a check-in that read the latch unset a moment earlier is
//!   still refused by rule 1.
//!
//! [`UnixBackendConnectionPool::force_drain_all`] retires everything but leaves
//! the pool usable; [`UnixBackendConnectionPool::shutdown_drain`] additionally
//! latches the pool closed so a late check-in racing graceful shutdown cannot
//! repopulate it.
//!
//! ## The shutdown boundary is terminal in BOTH directions
//!
//! The latch is not only a check-in fence; it is also a checkout refusal
//! (issue #3764). Every checkout — `checkout_h1`, `checkout_fresh_h1`, and the
//! h2c cold path — runs `refuse_if_shutting_down` as its FIRST act, before the
//! establishment deadline, the idle sweep, path admission, and any
//! `connect(2)`. A request that arrives after the drain therefore fails closed
//! with `UnixBackendError::PoolShuttingDown` without opening a socket or
//! reserving a slot on the target's bound, and that refusal is health-neutral:
//! the application is not implicated by the gateway shutting down.
//!
//! A checkout that passed that gate while the pool was still open can still
//! reach driver registration after the drain latches. `shutdown_drain` sets
//! both latches — the tracker's own `closed` flag under the tracker's map lock,
//! and then the pool's `shutting_down` flag — before it retires anything. They
//! are independent state and do NOT land atomically; what the boundary
//! guarantees is their ORDER. The tracker is closed strictly FIRST, so from the
//! instant the pool reads as closed to anyone, driver registration has already
//! been closed and no registration can succeed afterwards. The reverse interval
//! is the deliberate one: between the tracker close and the pool store a
//! checkout can still pass the entry gate and dial, which is the same bounded
//! in-flight-establishment case as a checkout that passed the gate a moment
//! earlier, and it settles the same way.
//! `UnixDriverTracker` resolves the remaining race atomically — it reads the
//! latch, spawns, and inserts under ONE acquisition of that map lock — so the
//! losing side spawns NOTHING:
//! no task to abort, no detached handle, no gauge or connection slot charged
//! and released later. The un-spawned driver future is dropped (which closes
//! the freshly established socket), the target's slot is released, and the
//! checkout returns the same `PoolShuttingDown` refusal rather than a sender
//! backed by a connection nobody drives.
//!
//! What that does and does NOT guarantee, stated exactly:
//!
//! * when `shutdown_drain` returns, every driver it OWNED has ended and
//!   released its gauge share and connection slot, or the bounded reap budget
//!   expired — the budget bounds the wait, it cannot force a task that ignores
//!   cancellation points to be dropped sooner, and an expired reap budget is
//!   logged;
//! * an establishment that was already in flight when the latch was set — or
//!   that started inside the short interval between the tracker close and the
//!   pool store, and therefore still passed the entry gate — is not owned by
//!   that drain and may still hold its target's connection slot for the
//!   remainder of its own bounded establishment deadline. It settles
//!   exactly — slot released, gauge untouched, socket closed — before its own
//!   checkout call returns, and it can never publish a carrier or leave a task
//!   behind.
//!
//! ## Before every checkout
//!
//! A checkout re-runs `admit_socket_for_connect` (which stats the path afresh)
//! and compares the resulting `(dev, ino, owner_uid)` against the entry's
//! admitted identity. A mismatch retires **every** pooled connection for that
//! canonical path — across protocols and proxies — before any request byte is
//! written, and the caller re-admits and re-dials.
//!
//! ## Per-protocol lease semantics
//!
//! * **HTTP/1.1** — an EXCLUSIVE lease, returned to the idle set only after the
//!   ENTIRE response body has been read, for BOTH the buffered and the
//!   streaming response path.
//!
//!   The buffered path reads the body inside the dispatch function and calls
//!   [`UnixBackendConnectionPool::checkin_h1_when_idle`] directly. The streaming
//!   path cannot: the body leaves the dispatch function. It therefore hands the
//!   lease to the `ProxyBody` that OWNS the backend `hyper::body::Incoming`, as
//!   a [`crate::proxy::body::PooledBackendLease`] (see
//!   [`UnixBackendConnectionPool::streaming_lease`]), which returns it only
//!   after `ProxyBody::poll_frame` proves a clean end: either its own
//!   `Poll::Ready(None)`, or a successful terminal frame after the `Incoming`
//!   beneath it has already yielded EOF and `Body::is_end_stream()` reflects
//!   that fact. The anchor is
//!   deliberately the backend-facing body rather than whatever the client ends
//!   up polling: the response-inspector bridge replaces the client-visible body
//!   with a channel-fed one whose EOF also fires on a policy `Terminate` and on
//!   task cancellation, neither of which is a backend EOF.
//!   Everything else (body error, backend close, client cancellation, an early
//!   body drop, a read timeout, an aborted request, a fired client deadline,
//!   shutdown) leaves the lease in place and its `Drop` retires the connection.
//!
//!   Receiving response headers is never sufficient, and neither is hyper's own
//!   `SendRequest::ready()`: h1 `can_write_head()` is already true while a
//!   response body is still being read, so readiness alone would re-pool a
//!   connection mid-body and pipeline the next request onto it. Readiness is
//!   used only as the SECOND half of the check-in, after the caller has already
//!   proven the body is complete, to close the dispatcher re-arm gap —
//!   `SendRequest::try_send_request` does not wait for readiness, so a sender
//!   pooled before its dispatcher re-arms would bounce the next request.
//! * **h2c / native gRPC** — the multiplexable [`MeshMtlsSender`] is cloned per
//!   request and shared. A closed or GOAWAY-drained carrier fails `is_closed()`
//!   and is EVICTED (not merely skipped) on the next checkout, then replaced;
//!   `is_ready()` is deliberately not consulted, because on an h2 sender it also
//!   reports transient `MAX_CONCURRENT_STREAMS` backpressure and would discard a
//!   healthy busy carrier. Concurrent misses for one key are coalesced behind a
//!   creation lock whose wait draws on the same establishment deadline, so one
//!   burst opens one connection rather than N.
//!
//! ## Keep-alive
//!
//! `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` / `Proxy.pool_enable_http_keep_alive` is
//! honored literally for HTTP/1.1: with it off, a carrier is neither taken from
//! nor returned to the idle set, so every request gets a freshly admitted
//! connection. Publication treats the same effective setting as part of the
//! reusable live-identity set: an H1 target whose keep-alive/reuse is off is
//! omitted from the published live set so resident idle H1 carriers are
//! retired synchronously before reconciliation returns — otherwise a full idle
//! set (defaults: physical cap 64 and idle cap 64) would keep every physical
//! slot occupied while new traffic must dial fresh and could receive
//! `BackendConnectionLimit` until idle expiry. h2c is unaffected — HTTP/2 has
//! no keep-alive negotiation and stream multiplexing is the transport's
//! defining behavior. See `UnixBackendConnectionPool::keep_alive_enabled`.
//!
//! ## Not pooled: WebSocket
//!
//! An RFC 6455 upgrade consumes its HTTP/1.1 carrier for the whole session, so
//! [`UnixBackendConnectionPool::dial_websocket_stream`] performs a dedicated
//! admitted dial that never enters the idle set (issue #3732). The dedicated
//! carrier still reserves the same per-target physical-connection lane and is
//! counted in the fixed-cardinality open-connections gauge. Its session-owned
//! lease releases both when the WebSocket relay ends, and shutdown closes its
//! registration gate before publishing the pool latch and then waits a bounded
//! interval for existing relays to release their carriers.

/// Default `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`: the most concurrently
/// open PHYSICAL connections the Unix backend manager holds per admitted
/// ingress target, including dedicated WebSockets.
///
/// Matches the pool's own `max_idle_per_host` default, so the bound and the
/// idle ceiling agree: every admitted carrier can be pooled, and a target
/// cannot accumulate more physical connections than the idle set could hold.
/// The bound is enforced by default rather than opt-in — an unbounded local
/// transport is exactly the regression issue #3731 asks to prevent — and `0`
/// is the explicit operator opt-out.
pub const DEFAULT_UNIX_INGRESS_MAX_CONNECTIONS: u32 = 64;

/// Largest accepted `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`.
///
/// A higher value could not be reached before the process file-descriptor
/// limit, so accepting it would advertise a bound that is not one. Enforced at
/// the config boundary (`EnvConfig::validate`).
pub const MAX_UNIX_INGRESS_MAX_CONNECTIONS: u32 = 65_536;

#[cfg(unix)]
mod imp {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use arc_swap::ArcSwapOption;
    use dashmap::DashMap;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::sync::{Mutex, Notify};
    use tracing::debug;

    use crate::backend_conn_limit::BackendConnectionLimitExceeded;
    use crate::config::PoolConfig;
    use crate::config::types::Proxy;
    use crate::proxy::body::{ReplayableRequestBody, SizeLimitedIncoming};
    use crate::proxy::hbone_pool::{entry_idle_expired, unix_secs};
    use crate::proxy::mesh_mtls_pool::MeshMtlsSender;
    use crate::proxy::unix_backend::{
        UnixBackendError, UnixConnectionDriver, connect_admitted, connect_deadline,
        handshake_unix_h2c_sender,
    };
    use crate::runtime_metrics::PoolKind;
    use crate::util::unix_socket::AdmittedUnixSocket;

    /// Bounded budget the graceful shutdown gives Unix connection drivers to
    /// finish after the pool has been latched closed and every pooled carrier
    /// dropped.
    ///
    /// Reached only by a driver whose sender is still held by in-flight work
    /// that outlived the gateway's own `FERRUM_SHUTDOWN_DRAIN_SECONDS` budget;
    /// the ordinary case resolves immediately because dropping the last sender
    /// closes the connection. Anything still running when the budget expires is
    /// ABORTED and then joined within the separate reap budget below. An abort
    /// request cannot synchronously drop a task that is not reaching a runtime
    /// cancellation point, so expiry of that second budget is logged rather
    /// than described as a completed reap. Deliberately not an operator knob:
    /// it runs strictly after the operator-configured drain and is a backstop,
    /// not a policy.
    const DRIVER_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    /// Bounded budget for JOINING the drivers the graceful phase had to cancel.
    ///
    /// Cancelling a task does not end it synchronously: the runtime drops the
    /// task at its next scheduling point, and that drop is what releases the
    /// connection's slot on its target's bound and its share of the
    /// open-physical-connections gauge. The drain therefore joins every handle
    /// it aborted, and this budget is what stops a driver that ignores
    /// cancellation from making shutdown unbounded. Short on purpose: a
    /// cancelled future is dropped at its next poll, so anything that outlives
    /// this is pathological and is detached with a debug record rather than
    /// waited on.
    const DRIVER_ABORT_REAP_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);

    /// Request body carried by the pooled HTTP/1.1 Unix sender.
    ///
    /// Identical to the shape the unpooled dispatch used, so the pooled sender's
    /// concrete `SendRequest<B>` type is fixed without changing what the
    /// dispatch path builds: `Left` is the streaming, size-limited frontend
    /// body; `Right` is the retry-replayable buffered body.
    pub type UnixH1RequestBody = http_body_util::Either<SizeLimitedIncoming, ReplayableRequestBody>;

    /// Concrete pooled HTTP/1.1 sender type.
    pub type UnixH1Sender = http1::SendRequest<UnixH1RequestBody>;

    /// Wire protocol spoken on an admitted Unix socket. Part of the pool key:
    /// an `http`-declared and an `http2`-declared listener on the same socket
    /// path must never share a physical connection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum UnixWireProtocol {
        Http1,
        H2c,
    }

    /// The CONFIG-declared identity of a Unix ingress target, independent of
    /// any filesystem observation.
    ///
    /// This is the half of [`UnixPoolKey`] that a published `GatewayConfig` can
    /// reproduce without touching the filesystem, and it is what
    /// [`UnixBackendConnectionPool::retain_live_targets`] compares on reload.
    /// Equality is exact on every field; nothing here is matched by substring
    /// or prefix.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixTargetIdentity {
        pub namespace: String,
        pub proxy_id: String,
        pub upstream_id: Option<String>,
        /// The socket path exactly as the `mesh.unix_socket` tag declares it,
        /// BEFORE symlink resolution. Config can only reproduce this form.
        pub configured_path: String,
        pub protocol: UnixWireProtocol,
    }

    /// Complete transport/security identity of a pooled Unix connection.
    ///
    /// Included: namespace, proxy id, effective upstream id, the CONFIGURED
    /// socket path, the canonical resolved path, admitted device/inode/owner,
    /// and wire protocol.
    ///
    /// The configured path is carried in addition to the resolved one so config
    /// publication can retire withdrawn targets by exact tuple equality without
    /// re-resolving symlinks (see [`UnixTargetIdentity`]). Two configured paths
    /// that resolve to the same object still key separately, which is the
    /// conservative direction: it costs one extra connection and never shares
    /// one across declarations.
    ///
    /// Deliberately EXCLUDED: `backend_connect_timeout_ms` and
    /// `backend_read_timeout_ms` are request-only policy applied per dispatch
    /// (repo pool-key rule), and the connection carries no TLS/DNS/SNI identity
    /// at all — a Unix socket has no network authority. Nothing else configures
    /// the H1 or h2c client handshake for this transport, so there is no further
    /// client-behavior segment to encode.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixPoolKey {
        /// Config-reproducible identity, stored once so publication and
        /// check-in liveness tests never allocate or rebuild it.
        target: UnixTargetIdentity,
        path: PathBuf,
        dev: u64,
        ino: u64,
        owner_uid: u32,
    }

    impl UnixPoolKey {
        fn new(
            proxy: &Proxy,
            configured_path: &str,
            admitted: &AdmittedUnixSocket,
            protocol: UnixWireProtocol,
        ) -> Self {
            Self {
                target: UnixTargetIdentity {
                    namespace: proxy.namespace.clone(),
                    proxy_id: proxy.id.clone(),
                    upstream_id: proxy.upstream_id.clone(),
                    configured_path: configured_path.to_string(),
                    protocol,
                },
                path: admitted.resolved_path().to_path_buf(),
                dev: admitted.device_id(),
                ino: admitted.inode(),
                owner_uid: admitted.owner_uid(),
            }
        }

        /// Canonical socket path this key was admitted against. Retirement
        /// compares this by exact path equality, never by substring.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// The config-reproducible identity of this key.
        fn target_identity(&self) -> &UnixTargetIdentity {
            &self.target
        }
    }

    /// An exclusive HTTP/1.1 lease.
    ///
    /// Dropping the lease retires the physical connection. Only
    /// [`UnixBackendConnectionPool::checkin_h1`] returns it to the idle set, and
    /// only after the response body has been fully read.
    pub struct UnixH1Checkout {
        key: UnixPoolKey,
        admitted: AdmittedUnixSocket,
        /// `true` when this lease came from the idle set rather than a fresh
        /// dial. The dispatch path uses it to decide whether a pre-wire send
        /// failure is an idle keep-alive race worth replaying once on a fresh
        /// connection.
        reused: bool,
        /// The pool's publication generation at the moment this lease was
        /// acquired. The check-in fence admits the carrier back into the idle
        /// set only while this is still the current generation, which is what
        /// stops an exchange that outlived a withdrawal — or a withdrawal
        /// followed by a same-identity re-add — from repopulating the pool.
        generation: u64,
        /// The effective `pool_enable_http_keep_alive` for the dispatch that
        /// took this lease, captured at checkout so the check-in (which has no
        /// `Proxy`) applies the same decision the checkout did.
        keep_alive: bool,
        pub sender: UnixH1Sender,
    }

    impl UnixH1Checkout {
        #[inline]
        pub fn reused(&self) -> bool {
            self.reused
        }

        /// Whether this lease may re-enter the idle set at all. `false` when
        /// the effective `pool_enable_http_keep_alive` is off.
        #[inline]
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn keep_alive(&self) -> bool {
            self.keep_alive
        }

        /// The publication generation this lease is bound to.
        #[inline]
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn generation(&self) -> u64 {
            self.generation
        }
    }

    /// EOF-anchored owner of an exclusive HTTP/1.1 lease for a STREAMING
    /// response (issue #3731).
    ///
    /// Constructed by [`UnixBackendConnectionPool::streaming_lease`] and stored
    /// on the `ProxyBody` that owns the backend stream. Two exits, and only two:
    ///
    /// * `release_on_clean_eof` — the body yielded `Ready(None)`, or a successful
    ///   terminal frame after `Body::is_end_stream()` proved that the whole
    ///   `hyper::body::Incoming` was consumed. Hand the carrier to
    ///   `checkin_h1_when_idle`, which additionally waits for hyper's h1
    ///   dispatcher to re-arm and re-checks liveness and socket identity.
    /// * `Drop` with the lease still present — every abnormal terminal. The
    ///   `UnixH1Checkout` drops, its `SendRequest` drops, and hyper closes the
    ///   connection. Nothing is pooled, so it can never be reused.
    struct UnixH1StreamingLease {
        pool: Arc<UnixBackendConnectionPool>,
        /// `Some` until one of the two exits fires.
        checkout: Option<UnixH1Checkout>,
    }

    impl crate::proxy::body::PooledBackendLease for UnixH1StreamingLease {
        fn release_on_clean_eof(mut self: Box<Self>) {
            if let Some(checkout) = self.checkout.take() {
                UnixBackendConnectionPool::checkin_h1_when_idle(&self.pool, checkout);
            }
        }
    }

    struct IdleH1 {
        /// Process-unique id, so a check-in that loses the publication race can
        /// withdraw EXACTLY the entry it inserted and no other — including a
        /// concurrently pooled carrier for the same key.
        id: u64,
        /// Publication generation this entry is REUSABLE under (fence rule 2).
        /// Set to the inserting lease's generation, and advanced by a
        /// retirement pass that observes the entry under a still-live identity.
        generation: AtomicU64,
        sender: UnixH1Sender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    struct SharedH2c {
        /// See [`IdleH1::id`].
        id: u64,
        /// See [`IdleH1::generation`].
        generation: AtomicU64,
        sender: MeshMtlsSender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    /// The parts of a pooled entry the shared slot maintenance needs, so the
    /// H1 and h2c maps cannot drift in how they are retired, pruned, fenced,
    /// or withdrawn.
    trait PooledEntry {
        fn id(&self) -> u64;
        fn generation(&self) -> &AtomicU64;
        fn admitted(&self) -> &AdmittedUnixSocket;
        fn last_used_at(&self) -> u64;
        fn is_closed(&self) -> bool;
    }

    impl PooledEntry for IdleH1 {
        fn id(&self) -> u64 {
            self.id
        }
        fn generation(&self) -> &AtomicU64 {
            &self.generation
        }
        fn admitted(&self) -> &AdmittedUnixSocket {
            &self.admitted
        }
        fn last_used_at(&self) -> u64 {
            self.last_used_at.load(Ordering::Relaxed)
        }
        fn is_closed(&self) -> bool {
            self.sender.is_closed()
        }
    }

    impl PooledEntry for SharedH2c {
        fn id(&self) -> u64 {
            self.id
        }
        fn generation(&self) -> &AtomicU64 {
            &self.generation
        }
        fn admitted(&self) -> &AdmittedUnixSocket {
            &self.admitted
        }
        fn last_used_at(&self) -> u64 {
            self.last_used_at.load(Ordering::Relaxed)
        }
        fn is_closed(&self) -> bool {
            self.sender.is_closed()
        }
    }

    /// Everything one pool key owns: its carriers.
    ///
    /// Config liveness deliberately does NOT live in an empty per-key
    /// tombstone. The lock-free live-set snapshot plus the pre/post generation
    /// fence reject late insertions; retaining an empty slot until a long-lived
    /// socket inode disappears would otherwise leak one structured key for
    /// every logical target identity ever withdrawn against that socket.
    struct KeySlot<T> {
        entries: Vec<T>,
    }

    impl<T> Default for KeySlot<T> {
        fn default() -> Self {
            Self {
                entries: Vec::new(),
            }
        }
    }

    /// Retire, remove, or re-stamp every slot of one map against the newly
    /// published live set. Returns how many carriers were dropped.
    ///
    /// `generation` is the value the publication just bumped to. Advancing a
    /// retained entry's token happens under the shard guard `retain` holds, so
    /// a concurrent checkout either sees the old token (and refuses) or the new
    /// one (and the entry really was CONTINUOUSLY live across this pass).
    ///
    /// Observing an entry under a currently-declared identity is NOT by itself
    /// proof that the carrier is continuously live. An identity can be
    /// withdrawn and re-added under a byte-identical tuple, and a check-in (or
    /// h2c publish) that captured its generation before the withdrawal can land
    /// its insertion in between: when the withdrawal pass found no slot for that
    /// key, the inserter's own post-insert fence read has not run yet.
    /// Re-stamping that entry would republish a PRE-WITHDRAWAL carrier at the
    /// current generation,
    /// and a racing checkout would then see a current token and reuse it — the
    /// exact laundering the fence exists to prevent.
    ///
    /// `previously_live` is the live set the PREVIOUS publication installed, so
    /// this pass can tell continuity from a same-tuple re-add:
    ///
    /// * declared in both sets → continuously live. Re-stamp, so an unrelated
    ///   publication does not empty the whole pool.
    /// * absent then, declared now → a RE-ADDED incarnation. The tuple is
    ///   identical but the lifetime is not, so every entry under it necessarily
    ///   predates the re-add: drop them and remove the empty slot, which is what
    ///   makes the new incarnation start from a freshly admitted dial.
    /// * absent now → drop the carriers and remove the slot.
    ///
    /// `previously_live` is `None` only before the first publication, where
    /// there is no predecessor absence for an entry to be discontinuous with.
    fn retain_live_slots<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        live: &std::collections::HashSet<UnixTargetIdentity>,
        previously_live: Option<&std::collections::HashSet<UnixTargetIdentity>>,
        generation: u64,
    ) -> u64 {
        let mut retired = 0u64;
        map.retain(|key, slot| {
            let identity = key.target_identity();
            if live.contains(identity) {
                if previously_live.is_none_or(|previous| previous.contains(identity)) {
                    for entry in &slot.entries {
                        entry.generation().store(generation, Ordering::Release);
                    }
                    !slot.entries.is_empty()
                } else {
                    retired = retired.saturating_add(slot.entries.len() as u64);
                    false
                }
            } else {
                retired = retired.saturating_add(slot.entries.len() as u64);
                false
            }
        });
        retired
    }

    /// Amortized sweep of one map: drop closed, expired, and
    /// identity-changed carriers, then reclaim slots that can no longer be
    /// reached. Returns how many carriers were evicted.
    ///
    /// Empty slots are always reclaimed. Config liveness is held once in the
    /// live-set snapshot, not repeated in an unbounded per-key tombstone map;
    /// generation fencing makes a late insertion safe even after its old slot
    /// has been reclaimed.
    fn prune_slots<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        idle_timeout: u64,
        now: u64,
    ) -> u64 {
        let mut evicted = 0u64;
        map.retain(|_key, slot| {
            let before = slot.entries.len();
            slot.entries.retain(|entry| {
                !entry.is_closed()
                    && !entry_idle_expired(entry.last_used_at(), idle_timeout, now)
                    && entry
                        .admitted()
                        .still_names_checked_object()
                        .unwrap_or(false)
            });
            evicted = evicted.saturating_add(before.saturating_sub(slot.entries.len()) as u64);
            !slot.entries.is_empty()
        });
        evicted
    }

    /// Remove EXACTLY entry `entry_id` under `key`, if it is still there.
    ///
    /// Used only by the losing side of the check-in fence, so it may find
    /// nothing (the retirement pass already removed the slot). Matching on the
    /// process-unique id is what keeps a losing cleanup from deleting a NEWER
    /// sibling carrier pooled under the same key.
    fn withdraw_slot_entry<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        key: &UnixPoolKey,
        entry_id: u64,
    ) -> bool {
        let (removed, became_empty) = {
            let Some(mut slot) = map.get_mut(key) else {
                return false;
            };
            let before = slot.entries.len();
            slot.entries.retain(|entry| entry.id() != entry_id);
            (slot.entries.len() != before, slot.entries.is_empty())
        };
        if became_empty {
            // The entry guard above and `remove_if` take the same shard lock.
            // A newer sibling inserted in between makes the predicate false,
            // so reclaiming the losing fence's empty slot cannot delete it.
            map.remove_if(key, |_, slot| slot.entries.is_empty());
        }
        removed
    }

    /// Refcounted per-target open-physical-connection counter.
    ///
    /// Owns its own map key so [`TargetConnSlot`]'s `Drop` can evict the entry
    /// under the same shard lock admission takes.
    struct TargetConnCounter {
        key: UnixPoolKey,
        count: AtomicU64,
    }

    /// One reserved physical-connection slot on a target's lane.
    ///
    /// Held for exactly the physical connection's lifetime: it is moved into
    /// that connection's driver future (see [`DriverLifetime`]), so it is
    /// released on clean close, handshake failure, eviction, withdrawal, drain,
    /// shutdown, cancellation, and driver panic alike.
    pub(crate) struct TargetConnSlot {
        counters: Arc<DashMap<UnixPoolKey, Arc<TargetConnCounter>>>,
        counter: Arc<TargetConnCounter>,
    }

    impl Drop for TargetConnSlot {
        fn drop(&mut self) {
            // Release and, if this was the last slot, evict the lane — both in
            // ONE shard-locked `remove_if`, so an acquirer can never observe the
            // counter between the decrement and the removal and resurrect an
            // orphan (which would split the count and admit past the bound).
            // Straight `fetch_sub`: a double release would be a bug that must
            // underflow loudly rather than be masked into an unbounded target.
            // The key is always present here — the lane lives for at least this
            // slot's lifetime, because it is only evicted at zero.
            self.counters.remove_if(&self.counter.key, |_, current| {
                current.count.fetch_sub(1, Ordering::AcqRel) == 1
            });
        }
    }

    /// The pool's INBOUND per-target ceiling on concurrently open physical
    /// connections (issue #3731), from
    /// `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`.
    ///
    /// Not a `DestinationRule`: see the module-level "per-target
    /// physical-connection bound" section for why outbound client-side policy
    /// must not be reinterpreted as an inbound ceiling. The lane key is the
    /// COMPLETE [`UnixPoolKey`], so two ingress listeners on one workload, an
    /// `http` ⇄ `http2` flip, and a replaced socket object each count
    /// separately.
    ///
    /// `max == 0` disables the bound: [`Self::acquire`] returns before touching
    /// the map, so an unbounded deployment pays nothing — no lock, no
    /// allocation, one integer compare on the cold connection-establishment
    /// path.
    struct UnixConnBound {
        max: u32,
        counters: Arc<DashMap<UnixPoolKey, Arc<TargetConnCounter>>>,
    }

    impl UnixConnBound {
        fn new(max: u32, shards: usize) -> Self {
            Self {
                max,
                counters: Arc::new(DashMap::with_shard_amount(shards)),
            }
        }

        /// Reserve one physical-connection slot for `key`, or refuse.
        ///
        /// The check and the increment happen under the same `DashMap` shard
        /// write guard that [`TargetConnSlot`]'s `Drop` takes, so concurrent
        /// dials for one target cannot both observe "under the bound" and both
        /// admit.
        fn acquire(
            &self,
            key: &UnixPoolKey,
        ) -> Result<Option<TargetConnSlot>, BackendConnectionLimitExceeded> {
            if self.max == 0 {
                return Ok(None);
            }
            let cap = u64::from(self.max);
            // Bound this guard to a NAMED binding, not a temporary: the shard
            // write lock must still be held across the load and the store, or
            // two concurrent dials for one target could both read "under the
            // bound" and both admit.
            let lane = self.counters.entry(key.clone()).or_insert_with(|| {
                Arc::new(TargetConnCounter {
                    key: key.clone(),
                    count: AtomicU64::new(0),
                })
            });
            // A freshly inserted lane is at 0 and `cap >= 1`, so an admission
            // that refuses never leaves an empty lane behind.
            let current = lane.count.load(Ordering::Relaxed);
            if current >= cap {
                return Err(BackendConnectionLimitExceeded { current, cap });
            }
            lane.count.fetch_add(1, Ordering::Relaxed);
            let counter = lane.clone();
            drop(lane);
            Ok(Some(TargetConnSlot {
                counters: Arc::clone(&self.counters),
                counter,
            }))
        }

        /// Slots currently held for one target. Diagnostics and tests only.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        fn current(&self, key: &UnixPoolKey) -> u64 {
            self.counters
                .get(key)
                .map(|counter| counter.count.load(Ordering::Relaxed))
                .unwrap_or(0)
        }

        /// Targets with a resident lane. Tests/diagnostics: proves the map
        /// drains rather than retaining a zero-count lane per socket ever
        /// dialed.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        fn resident_lanes(&self) -> usize {
            self.counters.len()
        }
    }

    /// Everything ONE physical connection charges the pool for, owned by that
    /// connection's driver future.
    ///
    /// Constructed by [`UnixDriverTracker::register`] and CAPTURED by the spawned
    /// future rather than created inside it, which is what makes the accounting
    /// exact under cancellation: a future the runtime drops before its first
    /// poll still drops this, so an abort that wins the race with scheduling
    /// cannot leak the gauge or strand a target's connection slot.
    struct DriverLifetime {
        tracker: Arc<UnixDriverTracker>,
        id: u64,
        /// The target's physical-connection slot, released with the connection.
        /// `None` when the bound is disabled.
        _conn_slot: Option<TargetConnSlot>,
    }

    impl Drop for DriverLifetime {
        fn drop(&mut self) {
            self.tracker.finish(self.id);
        }
    }

    /// The tracker refused to adopt a driver because shutdown has already
    /// latched it closed. Nothing was spawned and nothing was charged: the
    /// caller's `conn_slot` and the un-spawned driver future were released by
    /// [`UnixDriverTracker::register`] before it returned.
    struct DriverRegistrationClosed;

    /// Structured ownership of every physical Unix backend connection driver
    /// (issue #3764).
    ///
    /// A detached `tokio::spawn` is unreachable: shutdown cannot close it,
    /// cannot await it, and cannot prove it ended. Dropping the sender maps is
    /// not equivalent either, because a carrier CHECKED OUT into an in-flight
    /// exchange — or cloned into a multiplexed h2c request — is deliberately
    /// absent from those maps and keeps its connection open.
    ///
    /// Every driver is therefore registered here at spawn and removed when it
    /// completes, so [`UnixBackendConnectionPool::shutdown_drain`] can await
    /// them all under one bounded deadline and then cancel AND REAP whatever is
    /// left.
    ///
    /// The lock is a plain `std::sync::Mutex` held only for map mutation, and
    /// it is taken exactly twice per PHYSICAL connection (register, finish) —
    /// never per request. `live` is the O(1) "physical connections currently
    /// open" gauge, so the metrics surface never scans a map; it is decremented
    /// by [`DriverLifetime`]'s `Drop`, i.e. by the driver future's own release,
    /// which is the only event that is common to a clean end, a panic, and a
    /// cancellation.
    ///
    /// ## Spawn and registration are ONE decision
    ///
    /// [`Self::register`] holds the map lock across the `tokio::spawn` AND the
    /// insert, and it reads `closed` under that same lock. That is what makes
    /// the shutdown boundary terminal rather than eventually-consistent:
    ///
    /// * a registration that acquires the lock before [`Self::close`] latches
    ///   is fully in the map when the later drain reads it, so the drain owns
    ///   it;
    /// * a registration that acquires the lock after the latch spawns NOTHING —
    ///   there is no task to abort, no handle to detach, and no gauge to
    ///   release later. It refuses, and the caller fails its checkout closed.
    ///
    /// The latch is set by [`Self::close`], which
    /// [`UnixBackendConnectionPool::shutdown_drain`] performs FIRST — before its
    /// own `shutting_down` store and before any retirement work — so there is no
    /// interval in which the pool is latched closed but the tracker still adopts
    /// new drivers.
    ///
    /// Because the insert cannot be preempted by the driver's own completion
    /// (`finish` needs the same lock), there is no registration sentinel and no
    /// state in which the map describes a driver that has already released its
    /// accounting.
    struct UnixDriverTracker {
        next_id: AtomicU64,
        drivers: std::sync::Mutex<HashMap<u64, tokio::task::JoinHandle<()>>>,
        live: AtomicU64,
        /// Latched by [`Self::close`] UNDER the map lock. Once set, every
        /// handle already in the map belongs to the drain that follows and
        /// [`Self::register`] refuses to create any more.
        closed: AtomicBool,
    }

    impl UnixDriverTracker {
        fn new() -> Self {
            Self {
                next_id: AtomicU64::new(0),
                drivers: std::sync::Mutex::new(HashMap::new()),
                live: AtomicU64::new(0),
                closed: AtomicBool::new(false),
            }
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, tokio::task::JoinHandle<()>>> {
            // No panic is reachable inside the critical section (map insert and
            // remove on integer keys), but the production rule forbids
            // `unwrap()`, and recovering the map is the correct behavior even if
            // a future edit did panic: the tracker keeps reaping.
            self.drivers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn live(&self) -> u64 {
            self.live.load(Ordering::Relaxed)
        }

        /// Drivers currently tracked. Diagnostics/tests only; never on the
        /// request path.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        fn entries(&self) -> usize {
            self.lock().len()
        }

        /// Spawn `driver` under tracking, holding `conn_slot` — the target's
        /// physical-connection slot — for the connection's whole lifetime, or
        /// REFUSE because shutdown already latched the tracker closed.
        ///
        /// The `closed` read, the spawn, and the insert all happen under ONE
        /// acquisition of the map lock, so there is no window in which a task
        /// exists that the drain does not own. On the refusal side nothing is
        /// spawned at all: the guard is released and then `conn_slot` and the
        /// un-polled `driver` future are dropped on the way out, which releases
        /// the target's physical-connection slot and closes the freshly
        /// established socket before this returns. The gauge is incremented only
        /// on the side that actually spawns, so a refusal cannot leave a
        /// transient count behind for a later reader to observe.
        ///
        /// This is one cold-path lock acquisition per NEW physical connection —
        /// the same registration boundary that already existed — not a
        /// per-request one.
        ///
        /// An associated function rather than a method because `&Arc<Self>` is
        /// not a permitted method receiver on stable Rust.
        fn register(
            tracker: &Arc<Self>,
            driver: UnixConnectionDriver,
            conn_slot: Option<TargetConnSlot>,
        ) -> Result<(), DriverRegistrationClosed> {
            let mut drivers = tracker.lock();
            if tracker.closed.load(Ordering::Acquire) {
                // Release the map lock BEFORE dropping the slot: the slot's
                // `Drop` takes a `DashMap` shard lock, and no path takes these
                // two in the other order.
                drop(drivers);
                drop(conn_slot);
                drop(driver);
                return Err(DriverRegistrationClosed);
            }
            let id = tracker.next_id.fetch_add(1, Ordering::Relaxed);
            tracker.live.fetch_add(1, Ordering::Relaxed);
            let lifetime = DriverLifetime {
                tracker: Arc::clone(tracker),
                id,
                _conn_slot: conn_slot,
            };
            let handle = tokio::spawn(async move {
                // Moved into the future's captured state, so dropping the future
                // — polled or not — releases the gauge and the target slot.
                let _lifetime = lifetime;
                driver.await;
            });
            // The spawned task cannot have completed and called `finish` yet:
            // `finish` needs this same lock, which is still held here. So the
            // insert can never be undone by a completion that ran first, and no
            // registration sentinel is needed.
            drivers.insert(id, handle);
            Ok(())
        }

        /// Release one driver's accounting. Called from [`DriverLifetime`], so
        /// it runs exactly once per physical connection on every termination
        /// path — completion, panic unwind, and cancellation included.
        fn finish(&self, id: u64) {
            // Same saturating discipline as the pooled-carrier gauges: a gauge
            // is a diagnostic, and an accounting slip must not underflow into a
            // nonsensical `u64::MAX` on an operator's dashboard.
            UnixBackendConnectionPool::note_pooled_removed(&self.live, 1);
            // A miss is the ordinary shutdown case: the drain already took this
            // handle out of the map to await or cancel it.
            self.lock().remove(&id);
        }

        fn take_next_running(&self) -> Option<tokio::task::JoinHandle<()>> {
            let mut drivers = self.lock();
            let id = *drivers.keys().next()?;
            drivers.remove(&id)
        }

        /// Empty the map, returning every still-running handle.
        fn take_all_running(&self) -> Vec<tokio::task::JoinHandle<()>> {
            let mut drivers = self.lock();
            drivers.drain().map(|(_, handle)| handle).collect()
        }

        /// Latch the tracker closed: synchronous, idempotent, and taken UNDER
        /// the map lock so it linearizes against [`Self::register`].
        ///
        /// Every registration either wins that lock first — and is therefore
        /// fully inserted, so the drain that follows owns it — or acquires it
        /// after this store and spawns nothing at all. Because this is
        /// synchronous and lock-scoped, [`UnixBackendConnectionPool`] sets it
        /// BEFORE its own `shutting_down` store and before any retirement work
        /// runs, leaving no interval in which the pool reads as closed while a
        /// registration could still succeed.
        ///
        /// Nothing is awaited and no other lock is taken, so this cannot
        /// deadlock against `register`/`finish` and holds the map lock across no
        /// suspension point.
        fn close(&self) {
            let _guard = self.lock();
            self.closed.store(true, Ordering::Release);
        }

        /// Terminal, bounded shutdown of every tracked driver.
        ///
        /// `budget` bounds the GRACEFUL wait for drivers to end on their own;
        /// `reap_budget` bounds the join that follows cancellation. Cancelling
        /// is not the same as ending: the task's future — and with it the live
        /// gauge and the target's connection slot — is released when the runtime
        /// DROPS the task, which is exactly what joining the handle observes.
        /// Awaiting the cancelled handles is therefore what makes the gauge
        /// reach zero before this returns, and the second budget is what keeps
        /// that wait from being unbounded.
        ///
        /// Never panics: a `JoinError` (a panicked or cancelled driver) is
        /// ignored, and an unrepresentable deadline degrades to immediate
        /// cancellation rather than to an infinite wait.
        async fn drain(&self, budget: std::time::Duration, reap_budget: std::time::Duration) {
            // Idempotent defense in depth. The pool's shutdown entry points
            // already closed the tracker — before their own latch store and
            // before they retired anything — so by the time this runs the latch
            // is set; re-closing keeps this function terminal on its own terms
            // for any future caller.
            self.close();
            let deadline = tokio::time::Instant::now().checked_add(budget);
            if let Some(deadline) = deadline {
                while let Some(mut handle) = self.take_next_running() {
                    let joined = tokio::time::timeout_at(deadline, &mut handle).await;
                    if joined.is_err() {
                        // The budget is spent. `timeout_at` borrowed the handle,
                        // so this one is still ours to cancel and reap along
                        // with everything still tracked.
                        self.cancel_and_reap(Some(handle), reap_budget).await;
                        return;
                    }
                }
            }
            // Either every driver ended inside the budget (leaving the map
            // empty, which this observes) or the deadline was unrepresentable
            // and nothing was waited for at all.
            self.cancel_and_reap(None, reap_budget).await;
        }

        /// Cancel every remaining driver and JOIN it, bounded by `budget`.
        async fn cancel_and_reap(
            &self,
            first: Option<tokio::task::JoinHandle<()>>,
            budget: std::time::Duration,
        ) {
            let mut handles: Vec<tokio::task::JoinHandle<()>> = first.into_iter().collect();
            handles.extend(self.take_all_running());
            if handles.is_empty() {
                return;
            }
            for handle in &handles {
                handle.abort();
            }
            let reap = async {
                for handle in handles {
                    // A cancelled task joins as `Err(JoinError::cancelled)`, a
                    // panicked one as `Err(JoinError::panic)`. Neither is a
                    // shutdown failure; what matters is that the task is gone.
                    let _ = handle.await;
                }
            };
            if tokio::time::timeout(budget, reap).await.is_err() {
                debug!(
                    "unix_backend_pool: shutdown left cancelled connection drivers unreaped after \
                     the abort budget"
                );
            }
        }
    }

    /// An admitted, connected WebSocket carrier plus the REMAINING share of the
    /// one establishment budget its upgrade handshake must complete inside.
    pub struct UnixWebSocketDial {
        /// The admitted socket identity the connection is bound to. Held by the
        /// caller for the session; a WebSocket carrier is never pooled.
        #[allow(dead_code)]
        // Identity is proven at dial; retained for caller diagnostics/parity.
        pub admitted: AdmittedUnixSocket,
        pub stream: tokio::net::UnixStream,
        /// Absolute end of the ONE `backend_connect_timeout_ms` establishment
        /// budget. The upgrade exchange must be bounded by this, not by a fresh
        /// full timeout.
        pub deadline: tokio::time::Instant,
        /// The effective millisecond value behind `deadline`, so a timeout can
        /// be reported with the same number the rest of the transport uses.
        pub timeout_ms: u64,
        /// Per-target physical-connection admission and fixed-cardinality
        /// accounting for this dedicated carrier. The caller must retain this
        /// for the complete WebSocket session; dropping it releases the lane.
        pub(crate) conn_lease: UnixWebSocketConnLease,
    }

    /// Lifetime guard for one dedicated Unix WebSocket carrier.
    ///
    /// WebSockets do not have a hyper connection-driver task for
    /// [`UnixDriverTracker`] to own: the session relay owns the `UnixStream`
    /// directly. This guard supplies the equivalent lifetime accounting. It is
    /// moved beside that relay and dropped only after the relay ends (or on any
    /// pre-session handshake failure), so the per-target slot and the exported
    /// open-physical-connections gauge describe the real socket lifetime.
    pub(crate) struct UnixWebSocketConnLease {
        _conn_slot: Option<TargetConnSlot>,
        live: Arc<AtomicU64>,
        drained: Arc<Notify>,
    }

    impl Drop for UnixWebSocketConnLease {
        fn drop(&mut self) {
            drop(self._conn_slot.take());
            UnixBackendConnectionPool::note_pooled_removed(&self.live, 1);
            self.drained.notify_waiters();
        }
    }

    /// Bounded, lock-free-on-hit Unix backend connection manager.
    pub struct UnixBackendConnectionPool {
        pool_config: PoolConfig,
        /// Idle HTTP/1.1 senders per identity. A checked-out sender is NOT in
        /// this map, which is what makes the H1 lease exclusive.
        h1_idle: DashMap<UnixPoolKey, KeySlot<IdleH1>>,
        /// Shared multiplexable h2c carriers per identity.
        h2c_carriers: DashMap<UnixPoolKey, KeySlot<SharedH2c>>,
        /// Coalesces concurrent h2c misses for one identity.
        h2c_creation_locks: DashMap<UnixPoolKey, Arc<Mutex<()>>>,
        /// Last admitted `(dev, ino, owner_uid)` observed for a canonical path.
        ///
        /// This is the O(1) replacement detector: a checkout re-admits the path
        /// and compares against this entry, so a socket swap is caught even
        /// though the swap also changes the pool KEY (which would otherwise
        /// simply miss and leave the old connections pooled and live).
        path_identities: DashMap<PathBuf, (u64, u64, u32)>,
        /// Latched by [`UnixBackendConnectionPool::shutdown_drain`]. Once set,
        /// no check-in may repopulate the pool, so the drain is terminal even
        /// against a response body that reaches EOF while shutdown is running.
        ///
        /// The latch alone is a single read, so it does not by itself order a
        /// check-in that observed it unset against the drain that follows;
        /// `shutdown_drain` also bumps `publication_generation`, and the
        /// two-step check-in fence is what makes the drain terminal against
        /// that interleaving.
        shutting_down: AtomicBool,
        /// Monotonic publication generation. Bumped by EVERY retirement
        /// (`retain_live_targets`, `force_drain_all`, `shutdown_drain`) BEFORE
        /// the retirement pass runs. A lease records the value current when it
        /// was checked out; the check-in fence compares it twice, around the
        /// insert. See the module-level "withdrawal fence" section.
        publication_generation: AtomicU64,
        /// Exact config-declared identities from the newest reconciled request
        /// epoch. `None` exists only before the first post-construction
        /// publication; the initial config has no stale predecessor to fence.
        /// Check-in reads this lock-free and compares against the identity
        /// already owned by its key.
        live_targets: ArcSwapOption<std::collections::HashSet<UnixTargetIdentity>>,
        /// Highest request-epoch config generation reconciled into this pool.
        ///
        /// Config swaps are serialized, but their post-swap maintenance can
        /// overlap. Keep the comparison and full retirement pass under this
        /// off-hot-path lock so an older publisher that resumes late cannot
        /// overwrite the live-set verdict of a newer published epoch.
        last_config_reconcile_generation: std::sync::Mutex<u64>,
        /// Allocator for [`IdleH1::id`] / [`SharedH2c::id`].
        next_entry_id: AtomicU64,
        last_prune_unix_secs: AtomicU64,
        /// Owns every physical connection driver this pool spawned.
        drivers: Arc<UnixDriverTracker>,
        /// Per-target ceiling on concurrently open PHYSICAL connections
        /// (`FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`). Inbound transport
        /// capacity toward the co-located app — deliberately NOT a
        /// `DestinationRule`, which is outbound client-side policy.
        conn_bound: UnixConnBound,
        /// Dedicated Unix WebSocket carriers have no separately spawned hyper
        /// driver, so their session-owned leases maintain this share of the
        /// open-physical-connections gauge.
        live_websocket_connections: Arc<AtomicU64>,
        /// Linearizes dedicated WebSocket publication against shutdown. The
        /// gate is taken once per new WebSocket, never per frame.
        websocket_registration_closed: std::sync::Mutex<bool>,
        websocket_drained: Arc<Notify>,
        hits: AtomicU64,
        misses: AtomicU64,
        physical_connects: AtomicU64,
        identity_retirements: AtomicU64,
        setup_failures: AtomicU64,
        checkout_failures: AtomicU64,
        withdrawal_fenced_checkins: AtomicU64,
        /// O(1) gauge of idle HTTP/1.1 carriers resident in [`Self::h1_idle`].
        /// Maintained at every insert/removal so the metrics surface never
        /// scans the map. See `Self::note_pooled_removed`.
        idle_h1_gauge: AtomicU64,
        /// O(1) gauge of shared h2c carriers resident in
        /// [`Self::h2c_carriers`].
        h2c_carrier_gauge: AtomicU64,
    }

    /// The pool's complete, bounded, FIXED-CARDINALITY accounting surface.
    ///
    /// This is what the runtime metrics endpoint exports (issue #3731's
    /// "export bounded metrics" requirement) and what the external unit and
    /// bench suites assert. There are deliberately NO per-target labels: one
    /// snapshot describes the whole pool, so socket churn, pod-IP churn, and
    /// wildcard routing cannot grow the metric surface.
    ///
    /// Every field is an O(1) atomic read. The counters are monotonic; the
    /// three connection fields are gauges maintained at each insert/removal
    /// (idle/active carriers), at each driver spawn/completion, and at each
    /// dedicated WebSocket lease acquire/release, so no map is ever scanned to
    /// produce this.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
    pub struct UnixPoolStats {
        /// Checkouts served by an already-admitted pooled carrier.
        pub hits: u64,
        /// Checkouts that had to establish a new physical connection.
        pub misses: u64,
        /// Physical connections established (admitted, connected, handshaken).
        pub physical_connects: u64,
        /// Carriers retired because their identity no longer exists: a replaced
        /// socket object, or a config withdrawal.
        pub identity_retirements: u64,
        /// Establishment failures: connect, protocol handshake, or the
        /// establishment deadline expiring.
        pub setup_failures: u64,
        /// Checkouts refused by GATEWAY-side policy rather than by the
        /// application: path admission, the target's physical-connection bound,
        /// and the shutdown latch. The first two are decided before any dial,
        /// as is the shutdown latch at the checkout gate; only the shutdown
        /// latch/registration race is counted after a connection was
        /// established (and that connection is closed again, undriven).
        pub checkout_failures: u64,
        /// Idle HTTP/1.1 carriers currently resident in the pool.
        pub idle_h1_connections: u64,
        /// Shared h2c carriers currently resident in the pool.
        pub active_h2c_connections: u64,
        /// Physical connections currently open — pooled carrier drivers plus
        /// dedicated WebSocket session leases. This includes a carrier checked
        /// out into an in-flight exchange (which is absent from the idle maps).
        pub open_physical_connections: u64,
        /// Carriers the withdrawal fence refused to (re)pool because their
        /// lease was bound to an older publication generation — counted both
        /// for a refusal before the insert and for an entry withdrawn after it.
        pub withdrawal_fenced_checkins: u64,
    }

    impl UnixBackendConnectionPool {
        /// Build a pool.
        ///
        /// `max_connections_per_target` is the effective
        /// `FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`: the most concurrently
        /// open PHYSICAL connections one admitted target identity may hold.
        /// `0` disables the bound. `ProxyState` passes the operator value;
        /// focused tests and benches pass their own.
        pub fn new(
            pool_config: PoolConfig,
            shard_amount: usize,
            max_connections_per_target: u32,
        ) -> Self {
            let shards = crate::util::sharding::pool_shard_amount(shard_amount);
            Self {
                pool_config,
                h1_idle: DashMap::with_shard_amount(shards),
                h2c_carriers: DashMap::with_shard_amount(shards),
                h2c_creation_locks: DashMap::with_shard_amount(shards),
                path_identities: DashMap::with_shard_amount(shards),
                shutting_down: AtomicBool::new(false),
                publication_generation: AtomicU64::new(0),
                live_targets: ArcSwapOption::empty(),
                last_config_reconcile_generation: std::sync::Mutex::new(0),
                next_entry_id: AtomicU64::new(0),
                last_prune_unix_secs: AtomicU64::new(0),
                drivers: Arc::new(UnixDriverTracker::new()),
                conn_bound: UnixConnBound::new(max_connections_per_target, shards),
                live_websocket_connections: Arc::new(AtomicU64::new(0)),
                websocket_registration_closed: std::sync::Mutex::new(false),
                websocket_drained: Arc::new(Notify::new()),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                physical_connects: AtomicU64::new(0),
                identity_retirements: AtomicU64::new(0),
                setup_failures: AtomicU64::new(0),
                checkout_failures: AtomicU64::new(0),
                withdrawal_fenced_checkins: AtomicU64::new(0),
                idle_h1_gauge: AtomicU64::new(0),
                h2c_carrier_gauge: AtomicU64::new(0),
            }
        }

        /// Reserve one physical-connection slot for `key`, or refuse pre-wire.
        ///
        /// Called at the ONE point a new physical connection is about to be
        /// constructed, so reuse of a pooled carrier — an idle H1 hit or another
        /// stream on a shared h2c carrier — never consumes a slot. The refusal
        /// is decided BEFORE `connect(2)`: no socket is opened and no
        /// application byte is written.
        ///
        /// The lane is the complete pool key, not the proxy's placeholder dial
        /// `host:port`: a materialized Unix ingress proxy points at
        /// `127.0.0.1:<listener_port>` under a synthetic upstream id that names
        /// no destination service, so a host/port-keyed lane would neither
        /// isolate sibling listeners nor mean anything to an operator.
        fn acquire_conn_slot(
            &self,
            key: &UnixPoolKey,
        ) -> Result<Option<TargetConnSlot>, UnixBackendError> {
            match self.conn_bound.acquire(key) {
                Ok(slot) => Ok(slot),
                Err(limit) => {
                    self.record_checkout_failure();
                    Err(UnixBackendError::BackendConnectionLimit(limit))
                }
            }
        }

        /// Physical connections currently held for one target identity.
        /// Diagnostics and external tests only; never on the request path.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn open_connections_for_target(
            &self,
            proxy: &Proxy,
            configured_path: &str,
            admitted: &AdmittedUnixSocket,
            protocol: UnixWireProtocol,
        ) -> u64 {
            let key = UnixPoolKey::new(proxy, configured_path, admitted, protocol);
            self.conn_bound.current(&key)
        }

        /// Targets with a resident connection lane. Diagnostics and external
        /// tests: proves the bound's map drains instead of retaining a
        /// zero-count lane per socket the gateway has ever dialed.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn resident_connection_lanes(&self) -> usize {
            self.conn_bound.resident_lanes()
        }

        /// Resident H1 + h2c key slots. Diagnostics and external tests: proves
        /// config churn cannot retain one empty structured key per withdrawn
        /// logical identity while a shared application socket stays alive.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn resident_key_slots(&self) -> (usize, usize) {
            (self.h1_idle.len(), self.h2c_carriers.len())
        }

        /// Entries currently held by the driver tracker. Diagnostics and
        /// external tests: proves a drain leaves no registration sentinel and
        /// no orphaned handle behind.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn tracked_drivers(&self) -> usize {
            self.drivers.entries()
        }

        /// Whether the pool's checkout/check-in shutdown latch is PUBLISHED yet.
        /// Diagnostics and external tests: the ordering regression test reads it
        /// from inside the inter-latch interval to prove the tracker's
        /// registration latch was closed strictly first.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn shutdown_latch_published(&self) -> bool {
            self.is_shutting_down()
        }

        /// The exported metric snapshot. O(1): every field is one atomic load,
        /// so the metrics endpoint never walks the pool's maps.
        pub fn stats(&self) -> UnixPoolStats {
            let fenced = self.withdrawal_fenced_checkins.load(Ordering::Relaxed);
            UnixPoolStats {
                hits: self.hits.load(Ordering::Relaxed),
                misses: self.misses.load(Ordering::Relaxed),
                physical_connects: self.physical_connects.load(Ordering::Relaxed),
                identity_retirements: self.identity_retirements.load(Ordering::Relaxed),
                setup_failures: self.setup_failures.load(Ordering::Relaxed),
                checkout_failures: self.checkout_failures.load(Ordering::Relaxed),
                idle_h1_connections: self.idle_h1_gauge.load(Ordering::Relaxed),
                active_h2c_connections: self.h2c_carrier_gauge.load(Ordering::Relaxed),
                open_physical_connections: self
                    .drivers
                    .live()
                    .saturating_add(self.live_websocket_connections.load(Ordering::Relaxed)),
                withdrawal_fenced_checkins: fenced,
            }
        }

        /// Account for `count` entities leaving one of the pool's O(1) gauges.
        ///
        /// Every removal path funnels through here — checkout pop, idle-ceiling
        /// eviction, periodic sweep, socket-replacement retirement, config
        /// withdrawal, fence cleanup, and a connection driver releasing its
        /// share of the open-physical-connections gauge — so a gauge cannot
        /// drift from what it describes. `saturating_sub` rather than
        /// `fetch_sub`: a gauge is a diagnostic, and an accounting slip must not
        /// underflow into a nonsensical `u64::MAX` on an operator's dashboard.
        #[inline]
        fn note_pooled_removed(gauge: &AtomicU64, count: u64) {
            if count == 0 {
                return;
            }
            let _ = gauge.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(count))
            });
        }

        #[inline]
        fn note_pooled_added(gauge: &AtomicU64) {
            gauge.fetch_add(1, Ordering::Relaxed);
        }

        /// The current publication generation. Exposed for diagnostics and for
        /// the external fence regression tests.
        #[inline]
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn publication_generation(&self) -> u64 {
            self.publication_generation.load(Ordering::Acquire)
        }

        /// Invalidate every OUTSTANDING lease and every pooled entry token by
        /// advancing the publication generation. Called BEFORE each retirement
        /// pass, never on the request path. Returns the new generation, which
        /// is the value the pass re-stamps retained live entries with.
        #[inline]
        fn advance_publication_generation(&self) -> u64 {
            self.publication_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
        }

        #[inline]
        fn record_withdrawal_fenced_checkin(&self) {
            self.withdrawal_fenced_checkins
                .fetch_add(1, Ordering::Relaxed);
        }

        /// Whether the newest published request epoch still declares `key`.
        ///
        /// Before the first post-construction publication the initial config
        /// has no stale predecessor to fence, and focused pool tests
        /// intentionally exercise standalone checkout/check-in, so an absent
        /// snapshot is treated as live. Every later production publication
        /// installs `Some`, including an empty set.
        #[inline]
        fn target_is_live(&self, key: &UnixPoolKey) -> bool {
            let snapshot = self.live_targets.load();
            match snapshot.as_ref() {
                Some(live) => live.contains(key.target_identity()),
                None => true,
            }
        }

        /// Attribute `count` carriers the fence refused to reuse or retain.
        /// Fixed cardinality: one counter and one pool-kind eviction metric,
        /// never a per-target label.
        #[inline]
        fn record_fenced_carriers(&self, count: u64) {
            if count == 0 {
                return;
            }
            self.withdrawal_fenced_checkins
                .fetch_add(count, Ordering::Relaxed);
            crate::runtime_metrics::global_ref()
                .record_pool_evictions(PoolKind::UnixBackend, count);
        }

        /// Drop every pooled connection, leaving the pool usable.
        ///
        /// A dropped sender ends its driver task once the connection closes, so
        /// this retires the whole idle set. It does NOT wait for those drivers:
        /// they stay tracked (see `UnixDriverTracker`) and only
        /// [`Self::shutdown_drain`] awaits and reaps them, under a bounded
        /// deadline.
        ///
        /// In-flight exchanges are NOT in these maps — an HTTP/1.1 lease is
        /// checked out precisely so that it is not — so clearing the maps
        /// cannot reach them. The generation bump is what does: it is performed
        /// FIRST, so every lease outstanding right now is already bound to a
        /// superseded generation and its check-in is fenced out, whether it
        /// lands before or after the clear.
        ///
        pub fn force_drain_all(&self) {
            self.advance_publication_generation();
            self.h1_idle.clear();
            self.h2c_carriers.clear();
            self.h2c_creation_locks.clear();
            self.path_identities.clear();
            // Both maps are now empty, so the gauges are exactly zero. Storing
            // rather than decrementing is what keeps them exact across a
            // wholesale `clear()`, which cannot report how much it removed.
            self.idle_h1_gauge.store(0, Ordering::Relaxed);
            self.h2c_carrier_gauge.store(0, Ordering::Relaxed);
        }

        /// Graceful-shutdown drain: retire everything, latch the pool closed,
        /// and REAP every physical connection driver under a bounded deadline.
        ///
        /// Called from the bounded shutdown drain of every serving mode, after
        /// accept loops have stopped and in-flight requests have been given
        /// their `FERRUM_SHUTDOWN_DRAIN_SECONDS` budget. Three things happen, in
        /// this order, and all three are load-bearing:
        ///
        /// 1. The latch makes the drain terminal: a streaming response that
        ///    reaches EOF during the final moments of the drain would otherwise
        ///    check its carrier back into a pool nobody will ever drain again.
        ///    `force_drain_all`'s generation bump closes the interleaving the
        ///    latch alone cannot — a check-in that read the latch unset a moment
        ///    before it was set. The tracker's registration latch is closed
        ///    FIRST ([`Self::latch_shutdown`]), before this store and before any
        ///    retirement runs. The two are independent state, so they are
        ///    ordered rather than simultaneous, and the order is the guarantee:
        ///    there is no interval during which the pool reads as closed but a
        ///    racing establishment could still register a driver and go on to
        ///    return a sender. A checkout that slips through the entry gate in
        ///    the reverse interval — after the tracker closed, before this store
        ///    — may still dial, but it is refused at registration and settles
        ///    exactly, as described below.
        /// 2. `force_drain_all` drops every pooled carrier, which closes each
        ///    connection whose only remaining sender was the pooled one.
        /// 3. The tracker awaits every driver task that is still running —
        ///    which, after (2), is exactly the set whose carriers are still held
        ///    by in-flight work — for up to `DRIVER_DRAIN_BUDGET`, then CANCELS
        ///    and JOINS whatever is left within `DRIVER_ABORT_REAP_BUDGET`.
        ///    Joining is not ceremony: a cancelled task releases its connection
        ///    slot and its share of the open-connections gauge when the runtime
        ///    drops it, and joining the handle is what observes that. Drivers
        ///    that reach cancellation inside the reap budget are gone and
        ///    accounted before return. If one does not, expiry is logged rather
        ///    than presented as a completed join; the overall wait remains
        ///    bounded by construction (issue #3764).
        ///
        /// Terminal by design, in both directions: after the latch is set, a
        /// new checkout is refused before it can dial
        /// ([`Self::refuse_if_shutting_down`]) and the tracker refuses to adopt
        /// any further driver, so an establishment that raced the latch spawns
        /// no task at all and fails its own checkout closed instead of handing
        /// back an undriven carrier.
        ///
        /// The bound is honest about its limits: the reap budget bounds how long
        /// this waits for CANCELLED drivers to be dropped, and an expired budget
        /// is logged rather than papered over. It does not, and cannot, retract
        /// a connection slot held by an establishment that is still inside its
        /// own connect deadline elsewhere; that one settles when it returns.
        pub async fn shutdown_drain(&self) {
            self.shutdown_drain_seamed(
                DRIVER_DRAIN_BUDGET,
                DRIVER_ABORT_REAP_BUDGET,
                || std::future::ready(()),
                || std::future::ready(()),
            )
            .await;
        }

        /// Drain the driver tracker with explicit budgets. External
        /// shutdown-path tests use this to exercise the forced-cancellation
        /// branch deterministically instead of waiting out the production
        /// budget; production goes through [`Self::shutdown_drain`].
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub async fn shutdown_drain_with_budgets(
            &self,
            driver_budget: std::time::Duration,
            reap_budget: std::time::Duration,
        ) {
            self.shutdown_drain_seamed(
                driver_budget,
                reap_budget,
                || std::future::ready(()),
                || std::future::ready(()),
            )
            .await;
        }

        /// Set the shutdown latches in the ONE order that is safe: close both
        /// physical-connection registration gates FIRST, under their locks, and
        /// only THEN publish the pool's own `shutting_down` Release store.
        ///
        /// These are independent pieces of state and cannot land atomically.
        /// What the boundary needs is not simultaneity but a direction: from the
        /// instant ANY thread can observe the pool latched closed, driver
        /// registration must ALREADY be closed. Storing the pool flag last is
        /// exactly that guarantee — the tracker's `close()` completes, releasing
        /// the map lock a concurrent [`UnixDriverTracker::register`] contends
        /// for, before the flag this method publishes is visible to anyone. So
        /// there is no interval in which the pool reads as shutting down while
        /// the tracker would still adopt a driver.
        ///
        /// The converse interval DOES exist, and is deliberate: between the
        /// tracker close and the pool store, a checkout can still pass
        /// [`Self::refuse_if_shutting_down`] and go on to `connect(2)`. That is
        /// the same bounded in-flight-establishment limitation
        /// [`Self::shutdown_drain`] already documents for a checkout that passed
        /// the gate a moment earlier, and it is harmless for the same reason:
        /// its registration is already fail-closed, so it spawns nothing,
        /// publishes nothing, charges no gauge, releases its target's connection
        /// slot, and returns `PoolShuttingDown`.
        ///
        /// `between_latches` is a test seam awaited in precisely that interval;
        /// production passes a ready future. Nothing is awaited while a lock is
        /// held — `close()` releases the map lock before it returns.
        async fn latch_shutdown<B, BFut>(&self, between_latches: B)
        where
            B: FnOnce() -> BFut,
            BFut: std::future::Future<Output = ()>,
        {
            self.drivers.close();
            *self
                .websocket_registration_closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            between_latches().await;
            self.shutting_down.store(true, Ordering::Release);
        }

        /// The production shutdown-drain body, with two test seams.
        ///
        /// `between_latches` is awaited BETWEEN the tracker's registration latch
        /// and the pool's `shutting_down` store — the one interval that can tell
        /// the required ordering apart from its reverse. A registration released
        /// there must already be refused even though the pool flag is not yet
        /// published; under the reverse (pool-first) order the same point would
        /// find the pool closed and the tracker still adopting.
        ///
        /// `after_latch` is awaited after BOTH latches are set and BEFORE any
        /// retirement or driver draining runs — the former force-drain interval.
        ///
        /// Neither can be produced by timing alone. Production passes ready
        /// futures for both, so a test through here exercises the production
        /// ordering rather than a parallel one.
        pub(crate) async fn shutdown_drain_seamed<B, BFut, F, Fut>(
            &self,
            driver_budget: std::time::Duration,
            reap_budget: std::time::Duration,
            between_latches: B,
            after_latch: F,
        ) where
            B: FnOnce() -> BFut,
            BFut: std::future::Future<Output = ()>,
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            self.latch_shutdown(between_latches).await;
            after_latch().await;
            self.force_drain_all();
            self.drivers.drain(driver_budget, reap_budget).await;
            self.drain_websocket_connections(driver_budget).await;
        }

        #[inline]
        fn is_shutting_down(&self) -> bool {
            self.shutting_down.load(Ordering::Acquire)
        }

        /// The one shutdown gate every checkout runs FIRST.
        ///
        /// A checkout that starts after [`Self::shutdown_drain`] latched the
        /// pool is refused here — before the establishment deadline is opened,
        /// before path admission, and therefore before any `connect(2)`. So a
        /// post-drain request opens no socket, reserves no slot on the target's
        /// bound, and cannot hand back a carrier the drain has no way to reap.
        ///
        /// Typed and health-neutral: shutdown is the gateway's own decision, so
        /// the application must not be circuit-broken, passively ejected, or
        /// LB-penalized for it (see `UnixBackendError::error_class`).
        #[inline]
        fn refuse_if_shutting_down(&self) -> Result<(), UnixBackendError> {
            if self.is_shutting_down() {
                self.record_checkout_failure();
                return Err(UnixBackendError::PoolShuttingDown);
            }
            Ok(())
        }

        /// Hand one freshly established physical connection's driver to the
        /// tracker, or fail the checkout closed.
        ///
        /// The SINGLE registration boundary for both wire protocols: the H1
        /// dial and the h2c cold path both land here, so the shutdown race is
        /// decided once, in one place, and the two paths cannot drift.
        ///
        /// A refusal means shutdown latched the tracker while this connection
        /// was being established. `register` has already released the target's
        /// physical-connection slot and dropped the un-spawned driver future
        /// (closing the socket), so nothing is charged and nothing is left
        /// running; the caller must NOT return its sender, because that sender
        /// is backed by a connection with no driver.
        fn register_driver(
            &self,
            driver: UnixConnectionDriver,
            conn_slot: Option<TargetConnSlot>,
        ) -> Result<(), UnixBackendError> {
            if UnixDriverTracker::register(&self.drivers, driver, conn_slot).is_err() {
                self.record_checkout_failure();
                return Err(UnixBackendError::PoolShuttingDown);
            }
            self.physical_connects.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_handshake(PoolKind::UnixBackend);
            Ok(())
        }

        /// Publish one dedicated WebSocket connection, atomically with respect
        /// to the shutdown registration gate.
        fn register_websocket_connection(
            &self,
            conn_slot: Option<TargetConnSlot>,
        ) -> Result<UnixWebSocketConnLease, UnixBackendError> {
            let closed = self
                .websocket_registration_closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *closed {
                drop(closed);
                drop(conn_slot);
                self.record_checkout_failure();
                return Err(UnixBackendError::PoolShuttingDown);
            }
            self.live_websocket_connections
                .fetch_add(1, Ordering::Relaxed);
            let lease = UnixWebSocketConnLease {
                _conn_slot: conn_slot,
                live: Arc::clone(&self.live_websocket_connections),
                drained: Arc::clone(&self.websocket_drained),
            };
            drop(closed);
            self.physical_connects.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_handshake(PoolKind::UnixBackend);
            Ok(lease)
        }

        /// Wait for session-owned Unix WebSocket carriers after the gateway's
        /// WebSocket shutdown signal has asked their relays to finish. The
        /// caller supplies the same bounded graceful budget used for drivers;
        /// unlike a hyper driver there is no task handle for this pool to abort.
        async fn drain_websocket_connections(&self, budget: std::time::Duration) {
            let Some(deadline) = tokio::time::Instant::now().checked_add(budget) else {
                return;
            };
            loop {
                if self.live_websocket_connections.load(Ordering::Acquire) == 0 {
                    return;
                }
                let notified = self.websocket_drained.notified();
                if self.live_websocket_connections.load(Ordering::Acquire) == 0 {
                    return;
                }
                if tokio::time::timeout_at(deadline, notified).await.is_err() {
                    debug!(
                        live = self.live_websocket_connections.load(Ordering::Relaxed),
                        "unix_backend_pool: shutdown left WebSocket carriers open after the drain budget"
                    );
                    return;
                }
            }
        }

        /// Retire every pooled carrier whose config-declared identity is not in
        /// `live`.
        ///
        /// Called from EVERY successful publication on both of `ProxyState`'s
        /// swap paths (`update_config`'s full and incremental branches, and
        /// `apply_incremental`), against the config that publication actually
        /// made current. `live` is built from that config, so a withdrawn
        /// target, a deleted proxy or upstream, a re-bound namespace/upstream,
        /// a changed `mesh.unix_socket` path, an `http` ⇄ `http2` protocol
        /// flip, and an HTTP/1.1 target whose effective keep-alive/reuse is now
        /// off all fall out of the set and are retired here — before the next
        /// request can be handed a carrier that belongs to configuration that
        /// no longer exists as reusable.
        ///
        /// Exact tuple equality on [`UnixTargetIdentity`]; never a substring or
        /// prefix test. One pass over the idle maps per publication, not per
        /// request.
        ///
        /// The idle maps are only PART of the retirement. A checked-out
        /// HTTP/1.1 lease is deliberately absent from `h1_idle`, so this pass
        /// cannot see it and a comment claiming such an exchange "fails its own
        /// check-in revalidation" would be false — nothing about a still-open
        /// socket that still names the same inode expresses a config
        /// withdrawal. The generation bump below is what reaches it, and it
        /// happens BEFORE the pass so that a check-in racing this call either
        /// has its entry removed by the pass or observes the new generation on
        /// its post-insert re-read and withdraws exactly its own entry.
        ///
        /// What the pass does per key is therefore three-way, not two-way, and
        /// the split turns on the PREVIOUS publication's live set as well as
        /// this one's (see `retain_live_slots`):
        ///
        /// * identity live now AND live at the previous publication → keep the
        ///   slot and ADVANCE each retained entry's token to the new generation
        ///   under the shard guard. Only these are continuously-live idle
        ///   carriers, and they stay reusable — an unrelated publication must
        ///   not empty the pool.
        /// * identity live now but ABSENT at the previous publication → a
        ///   re-added incarnation under the same tuple. Drop the carriers and
        ///   remove the empty slot: a withdraw/re-add is a discontinuity, so
        ///   anything pooled under the key was inserted by a superseded
        ///   generation racing the absence and must not be restamped into the
        ///   new incarnation.
        /// * identity withdrawn → drop the carriers and remove the empty slot.
        ///   A request routed by a superseded epoch is refused at check-in by
        ///   the lock-free live-set snapshot; a publication racing the insert
        ///   is handled by the post-insert generation read.
        pub fn retain_live_targets_for_publication(
            &self,
            config_generation: u64,
            live: &std::collections::HashSet<UnixTargetIdentity>,
        ) {
            let mut last_generation = self
                .last_config_reconcile_generation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if config_generation <= *last_generation {
                return;
            }
            // The retirement body runs with this lock still held: it reads the
            // PREVIOUS live snapshot and installs the new one, and those two
            // steps have to be one step with respect to any other publication,
            // or two concurrent passes could each see the other's snapshot as
            // "the previous one" and disagree about which identities were
            // continuously live.
            self.retain_live_targets_locked(live);
            *last_generation = config_generation;
        }

        /// Unordered retirement entry point retained for focused pool tests and
        /// explicit drains that do not correspond to a request-epoch publish.
        ///
        /// Production config swaps call [`Self::retain_live_targets_for_publication`]
        /// so an older/out-of-order publication cannot resurrect withdrawn
        /// carriers. This unordered form is the external unit-test seam that
        /// exercises the same retirement body without minting a request epoch.
        #[allow(dead_code)] // External unit tests call this; production uses the generation-ordered entry point.
        pub fn retain_live_targets(&self, live: &std::collections::HashSet<UnixTargetIdentity>) {
            // Same serialization as the ordered entry point: the previous-set
            // read and the new-set store are one step against another
            // publication. This seam never nests inside the ordered one.
            let _reconcile = self
                .last_config_reconcile_generation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            self.retain_live_targets_locked(live);
        }

        /// The retirement body. The caller MUST hold
        /// `last_config_reconcile_generation`, which is what linearizes the
        /// previous-snapshot read against the new-snapshot store.
        fn retain_live_targets_locked(&self, live: &std::collections::HashSet<UnixTargetIdentity>) {
            let generation = self.advance_publication_generation();
            // What the LAST publication declared. An identity missing here but
            // present in `live` is a re-added incarnation, not a continuously
            // live one, and the slot walk below must not carry its pre-absence
            // carriers forward. `None` is the pre-first-publication state.
            let previous_snapshot = self.live_targets.load();
            let previously_live = previous_snapshot.as_deref();
            // Install the liveness verdict before walking existing slots. A
            // stale-epoch dial that starts after the bump is therefore refused
            // even if no slot existed for the retirement pass to inspect.
            // If a check-in races the tiny bump/store window, the slot walk
            // that follows observes and removes its insertion.
            self.live_targets.store(Some(Arc::new(live.clone())));
            let retired_h1 = retain_live_slots(&self.h1_idle, live, previously_live, generation);
            Self::note_pooled_removed(&self.idle_h1_gauge, retired_h1);
            let retired_h2c =
                retain_live_slots(&self.h2c_carriers, live, previously_live, generation);
            Self::note_pooled_removed(&self.h2c_carrier_gauge, retired_h2c);
            let retired = retired_h1.saturating_add(retired_h2c);
            self.h2c_creation_locks
                .retain(|key, _| live.contains(key.target_identity()));
            // `path_identities` is the replacement memo, not a connection
            // holder. Keep it only for canonical paths that still have a pooled
            // carrier to protect. Forgetting a path with nothing pooled is
            // harmless — the next checkout re-admits from scratch and records a
            // fresh first observation, and there is no stale carrier left for a
            // swap detection to retire.
            let mut retained_paths: std::collections::HashSet<PathBuf> =
                std::collections::HashSet::new();
            for entry in self.h1_idle.iter() {
                if !entry.value().entries.is_empty() {
                    retained_paths.insert(entry.key().path().to_path_buf());
                }
            }
            for entry in self.h2c_carriers.iter() {
                if !entry.value().entries.is_empty() {
                    retained_paths.insert(entry.key().path().to_path_buf());
                }
            }
            self.path_identities
                .retain(|path, _| retained_paths.contains(path));
            if retired > 0 {
                self.identity_retirements
                    .fetch_add(retired, Ordering::Relaxed);
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, retired);
            }
        }

        /// Retire every pooled connection admitted against `path`, across
        /// protocols and proxies.
        ///
        /// Exact canonical-path equality — never a substring or prefix test.
        /// Called when a live re-admission proves the filesystem object at that
        /// path was replaced, BEFORE any further request byte is written to a
        /// connection that may now be talking to a different peer.
        ///
        /// Unlike a config withdrawal this needs no generation bump: an
        /// outstanding lease admitted against the replaced object fails its own
        /// `still_names_checked_object` re-check at check-in, which is a real
        /// filesystem observation rather than a claim about config.
        ///
        /// It drops the carriers and their now-empty slots. Config withdrawal
        /// is enforced independently by the live-set snapshot and generation
        /// fence, so filesystem replacement does not retain per-key config
        /// state.
        pub fn retire_socket_path(&self, path: &Path) {
            let mut retired_h1 = 0u64;
            let mut retired_h2c = 0u64;
            self.h1_idle.retain(|key, slot| {
                if key.path() == path {
                    retired_h1 = retired_h1.saturating_add(slot.entries.len() as u64);
                    false
                } else {
                    true
                }
            });
            self.h2c_carriers.retain(|key, slot| {
                if key.path() == path {
                    retired_h2c = retired_h2c.saturating_add(slot.entries.len() as u64);
                    false
                } else {
                    true
                }
            });
            Self::note_pooled_removed(&self.idle_h1_gauge, retired_h1);
            Self::note_pooled_removed(&self.h2c_carrier_gauge, retired_h2c);
            self.h2c_creation_locks.retain(|key, _| key.path() != path);
            self.path_identities.remove(path);
            let retired = retired_h1.saturating_add(retired_h2c);
            if retired > 0 {
                self.identity_retirements
                    .fetch_add(retired, Ordering::Relaxed);
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, retired);
            }
        }

        /// Process-lifetime HTTP keep-alive / H1 reuse default
        /// (`FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE`).
        ///
        /// Publication collection passes this into
        /// `collect_live_unix_target_identities` so per-proxy
        /// `pool_enable_http_keep_alive` can override it with the same
        /// precedence checkout uses. The global value itself does not change
        /// across reloads.
        #[inline]
        pub fn default_http_keep_alive(&self) -> bool {
            self.pool_config.enable_http_keep_alive
        }

        #[inline]
        fn idle_timeout_seconds(&self, proxy: &Proxy) -> u64 {
            proxy
                .pool_idle_timeout_seconds
                .unwrap_or(self.pool_config.idle_timeout_seconds)
        }

        /// Whether HTTP/1.1 connection reuse is enabled for this dispatch.
        ///
        /// `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` (globally) and
        /// `Proxy.pool_enable_http_keep_alive` (per proxy, taking precedence —
        /// the same precedence `idle_timeout_seconds` uses) are documented as
        /// "enable HTTP keep-alive for backend connection reuse". On this
        /// transport that is applied literally: with keep-alive OFF an HTTP/1.1
        /// carrier is never taken from the idle set and never returned to it, so
        /// every request gets a freshly admitted connection that is closed when
        /// its exchange ends.
        ///
        /// Scope is HTTP/1.1 only, deliberately. "Keep-alive" is an HTTP/1.1
        /// concept: on the reqwest transport this same flag installs a TCP
        /// keepalive socket option and never disables reuse, and a Unix-domain
        /// socket has no TCP keepalive to configure — so honoring the documented
        /// reuse meaning is the only reading that gives the flag any effect
        /// here. h2c is NOT affected: HTTP/2 has no keep-alive/close negotiation
        /// and multiplexing an RPC onto an existing connection is the
        /// transport's defining behavior, not a keep-alive optimization. See
        /// `docs/configuration.md`.
        #[inline]
        fn keep_alive_enabled(&self, proxy: &Proxy) -> bool {
            proxy
                .pool_enable_http_keep_alive
                .unwrap_or(self.pool_config.enable_http_keep_alive)
        }

        /// Idle-connection ceiling per identity. Concurrency is bounded
        /// separately and earlier by the per-target physical-connection bound,
        /// so this caps only what the pool RETAINS.
        #[inline]
        fn max_idle_per_key(&self) -> usize {
            self.pool_config.max_idle_per_host.max(1)
        }

        /// Whether a pooled connection's admitted identity still IS the identity
        /// the caller just re-admitted.
        ///
        /// `expected` comes from a FRESH `admit_socket_for_connect` performed on
        /// this checkout, so comparing against it is strictly stronger than
        /// re-stating `still_names_checked_object` here — and it costs no extra
        /// `stat`. The periodic sweep does call `still_names_checked_object`,
        /// because it has no caller-supplied live identity to compare against.
        #[inline]
        fn identity_intact(admitted: &AdmittedUnixSocket, expected: &AdmittedUnixSocket) -> bool {
            admitted.device_id() == expected.device_id()
                && admitted.inode() == expected.inode()
                && admitted.owner_uid() == expected.owner_uid()
        }

        /// Amortized idle sweep. Runs at most once per `interval` seconds
        /// process-wide (CAS-guarded), never per request.
        fn maybe_prune_idle(&self) {
            let now = unix_secs();
            // A disabled idle timeout still needs a periodic closed-connection /
            // identity sweep, just not a per-second one.
            let interval = match self.pool_config.idle_timeout_seconds {
                0 => 60,
                seconds => seconds.clamp(1, 60),
            };
            let last = self.last_prune_unix_secs.load(Ordering::Relaxed);
            if now.saturating_sub(last) < interval {
                return;
            }
            if self
                .last_prune_unix_secs
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                return;
            }

            let idle_timeout = self.pool_config.idle_timeout_seconds;
            let evicted_h1 = prune_slots(&self.h1_idle, idle_timeout, now);
            Self::note_pooled_removed(&self.idle_h1_gauge, evicted_h1);
            let evicted_h2c = prune_slots(&self.h2c_carriers, idle_timeout, now);
            Self::note_pooled_removed(&self.h2c_carrier_gauge, evicted_h2c);
            let evicted = evicted_h1.saturating_add(evicted_h2c);
            if evicted > 0 {
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, evicted);
            }
            // Only retain locks that are still contended or still name a live
            // carrier, so the lock map cannot grow without bound.
            self.h2c_creation_locks.retain(|key, lock| {
                Arc::strong_count(lock) > 1
                    || self
                        .h2c_carriers
                        .get(key)
                        .is_some_and(|slot| !slot.entries.is_empty())
            });
        }

        /// Re-admit `socket_path` and, when the resulting identity differs from
        /// anything pooled for that canonical path, retire those connections
        /// before returning.
        fn admit_and_reconcile(
            &self,
            socket_path: &str,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<AdmittedUnixSocket, UnixBackendError> {
            let admitted = crate::util::unix_socket::admit_socket_for_connect(
                socket_path,
                allowed_roots,
                allowed_uids,
            )
            .inspect_err(|_| self.record_checkout_failure())
            .map_err(UnixBackendError::InadmissiblePath)?;
            let live = (admitted.device_id(), admitted.inode(), admitted.owner_uid());
            let path = admitted.resolved_path();
            let previous = self.path_identities.get(path).map(|entry| *entry.value());
            match previous {
                Some(previous) if previous != live => {
                    // The filesystem object at this canonical path was replaced.
                    // Retire every connection admitted against the old identity
                    // BEFORE the caller can write a request byte, then record
                    // the new identity so the next checkout is a clean miss.
                    let owned = path.to_path_buf();
                    self.retire_socket_path(&owned);
                    self.path_identities.insert(owned, live);
                }
                Some(_) => {}
                None => {
                    self.path_identities.insert(path.to_path_buf(), live);
                }
            }
            Ok(admitted)
        }

        /// Acquire an exclusive HTTP/1.1 lease for `socket_path`.
        ///
        /// Cancellation-safe: there is no queueing wait. A hit returns
        /// immediately; a miss dials and handshakes inside ONE establishment
        /// deadline that is created BEFORE the idle sweep and BEFORE admission,
        /// so pool maintenance, path admission, connect, and the client
        /// handshake all draw on the same budget rather than any of them being
        /// free (issue #3764).
        ///
        /// A MISS additionally admits against this target's physical-connection
        /// bound (`FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`); a hit never does,
        /// so a target at its bound still serves every request that can ride an
        /// already-admitted connection.
        ///
        /// Refused immediately, before any of that, once the pool is latched
        /// closed by [`Self::shutdown_drain`] (see
        /// [`Self::refuse_if_shutting_down`]).
        pub async fn checkout_h1(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            self.checkout_h1_seamed(
                proxy,
                socket_path,
                connect_timeout_ms,
                allowed_roots,
                allowed_uids,
                || std::future::ready(()),
            )
            .await
        }

        /// The production HTTP/1.1 checkout body, with one test seam: an async
        /// hook awaited after the client handshake and BEFORE the driver is
        /// registered.
        ///
        /// That is the exact interleaving the shutdown boundary has to survive —
        /// a checkout that passed the entry gate while the pool was open and
        /// reaches registration after the drain latched — and it cannot be
        /// produced by timing alone. Production passes a ready future, so a test
        /// through here exercises the production path rather than a parallel
        /// one.
        pub(crate) async fn checkout_h1_seamed<F, Fut>(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
            before_register: F,
        ) -> Result<UnixH1Checkout, UnixBackendError>
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            // Fail closed before the budget, the sweep, admission, and the dial:
            // a checkout that starts after the drain opens no socket at all.
            self.refuse_if_shutting_down()?;
            // ONE budget for the whole establishment, opened at the OUTERMOST
            // entry — before the amortized idle sweep, which scans the pool's
            // maps and `stat`s socket paths, and before the synchronous
            // admission `stat`s. Neither can be preempted mid-syscall, but the
            // time they cost is charged here and every later await is bounded by
            // this same absolute deadline, so no maintenance work is free
            // (issue #3764).
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            self.maybe_prune_idle();
            // Read the generation BEFORE admission and the dial, so a
            // publication that lands anywhere between here and the check-in
            // fences this lease out of the pool.
            let generation = self.publication_generation.load(Ordering::Acquire);
            let keep_alive = self.keep_alive_enabled(proxy);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::Http1);

            // With keep-alive disabled there is nothing to reuse by contract,
            // so do not even look: the idle set is empty for this identity
            // because no lease of it is ever checked back in.
            if keep_alive
                && let Some(checkout) = self.take_idle_h1(&key, &admitted, proxy, keep_alive)
            {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(checkout);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(
                key,
                admitted,
                deadline,
                timeout_ms,
                generation,
                keep_alive,
                before_register,
            )
            .await
        }

        /// Force a fresh physical HTTP/1.1 connection, bypassing the idle set.
        ///
        /// Used for exactly one replay when a REUSED lease failed pre-wire — the
        /// classic idle keep-alive race, where the backend closed the connection
        /// between check-in and the next request. The admission gate runs again
        /// in full, inside its own single establishment deadline, and the new
        /// physical connection takes its own slot on the target's bound.
        pub async fn checkout_fresh_h1(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            self.refuse_if_shutting_down()?;
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            let generation = self.publication_generation.load(Ordering::Acquire);
            let keep_alive = self.keep_alive_enabled(proxy);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::Http1);
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(
                key,
                admitted,
                deadline,
                timeout_ms,
                generation,
                keep_alive,
                || std::future::ready(()),
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn dial_h1<F, Fut>(
            &self,
            key: UnixPoolKey,
            admitted: AdmittedUnixSocket,
            deadline: tokio::time::Instant,
            timeout_ms: u64,
            generation: u64,
            keep_alive: bool,
            before_register: F,
        ) -> Result<UnixH1Checkout, UnixBackendError>
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            // The per-target physical-connection bound is decided BEFORE
            // `connect(2)`: an over-bound refusal opens no socket and writes no
            // application byte, and it is typed so the dispatch path answers
            // with a pre-wire, health-neutral refusal rather than charging the
            // app.
            let conn_slot = self.acquire_conn_slot(&key)?;
            let connect = connect_admitted(&admitted, deadline, timeout_ms);
            let stream = match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result.inspect_err(|_| self.record_setup_failure())?,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };

            let handshake =
                http1::Builder::new().handshake::<_, UnixH1RequestBody>(TokioIo::new(stream));
            let (sender, connection) = match tokio::time::timeout_at(deadline, handshake).await {
                Ok(Ok(parts)) => parts,
                Ok(Err(err)) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::Http1Handshake(err));
                }
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };
            // The driver future OWNS the connection's whole lifetime, and with
            // it the target's physical-connection slot: the guard is handed to
            // the tracker, which moves it into the spawned future, so it is
            // released exactly when the physical connection ends — idle
            // residence, in-flight use, close, eviction, withdrawal, drain,
            // shutdown, cancellation, and a driver panic all included. Every
            // failure arm above returns with `conn_slot` still on the stack, so
            // a handshake failure releases it too.
            //
            // The driver is registered with the pool's tracker rather than
            // detached, so shutdown can close and reap it under a bounded
            // deadline (issue #3764). A registration REFUSED by an already
            // latched tracker fails this checkout closed: `sender` is dropped
            // here rather than handed back, because the connection behind it
            // has no driver and never will.
            before_register().await;
            self.register_driver(
                Box::pin(async move {
                    if let Err(e) = connection.await {
                        debug!("unix_backend_pool: h1 connection closed: {}", e);
                    }
                }),
                conn_slot,
            )?;

            Ok(UnixH1Checkout {
                key,
                admitted,
                reused: false,
                generation,
                keep_alive,
                sender,
            })
        }

        /// Pop a reusable idle HTTP/1.1 carrier, or nothing.
        ///
        /// The publication generation is read HERE, under the shard guard, and
        /// compared against each candidate entry's own token (fence rule 2).
        /// That ordering is what makes the fence non-launderable: a publication
        /// that has already bumped the generation is visible to this read, and
        /// one that has not yet bumped cannot have started its retirement pass,
        /// so an entry whose token equals the value read here was current at
        /// the instant it was handed out. An entry from a superseded generation
        /// is dropped rather than re-stamped with the caller's generation.
        fn take_idle_h1(
            &self,
            key: &UnixPoolKey,
            expected: &AdmittedUnixSocket,
            proxy: &Proxy,
            keep_alive: bool,
        ) -> Option<UnixH1Checkout> {
            let idle_timeout = self.idle_timeout_seconds(proxy);
            let now = unix_secs();
            let mut fenced = 0u64;
            let mut taken = None;
            {
                let mut slot = self.h1_idle.get_mut(key)?;
                let generation = self.publication_generation.load(Ordering::Acquire);
                while let Some(entry) = slot.entries.pop() {
                    // Every `pop` removes a resident carrier, whether it is
                    // taken, fenced out, or dropped as unusable.
                    Self::note_pooled_removed(&self.idle_h1_gauge, 1);
                    if !Self::identity_intact(&entry.admitted, expected) {
                        // The path no longer names the admitted object. Drop
                        // this guard first, then retire everything for the
                        // path — no request byte has been written on any of
                        // them.
                        drop(slot);
                        let path = expected.resolved_path().to_path_buf();
                        self.retire_socket_path(&path);
                        self.record_fenced_carriers(fenced);
                        return None;
                    }
                    if entry.generation.load(Ordering::Acquire) != generation {
                        // Published under an incarnation this pool has already
                        // superseded — including one still sitting in the
                        // window between a fenced check-in's insert and its own
                        // cleanup. Never hand it out, and never launder it by
                        // adopting the caller's generation.
                        fenced = fenced.saturating_add(1);
                        continue;
                    }
                    // `is_closed()` (not `is_ready()`) is the reuse gate.
                    // hyper's `is_ready()` reports "the dispatcher has already
                    // asked for the next request", which is a scheduling
                    // artifact, not a liveness fact — a perfectly good
                    // connection reads as not-ready until its driver task next
                    // polls. The genuine idle keep-alive race (the peer reaped
                    // the socket after check-in) is caught by the dispatch
                    // path's `try_send_request` replay, which recovers the
                    // unsent request and redials.
                    if entry.sender.is_closed()
                        || entry_idle_expired(
                            entry.last_used_at.load(Ordering::Relaxed),
                            idle_timeout,
                            now,
                        )
                    {
                        continue;
                    }
                    taken = Some(UnixH1Checkout {
                        key: key.clone(),
                        admitted: entry.admitted,
                        reused: true,
                        generation,
                        keep_alive,
                        sender: entry.sender,
                    });
                    break;
                }
            }
            self.record_fenced_carriers(fenced);
            taken
        }

        /// Return an HTTP/1.1 lease to the idle set.
        ///
        /// The dispatch path MUST NOT call this directly for a connection that
        /// carried a request — use [`Self::checkin_h1_when_idle`], which waits
        /// for hyper to report the exchange complete. This entry point is for a
        /// lease whose request was ABANDONED before it was ever sent (an invalid
        /// backend URL, an unparseable method) and for tests.
        ///
        /// A sender that is closed, whose socket identity changed, or whose
        /// lease is bound to a superseded publication generation is dropped
        /// instead of pooled.
        pub fn checkin_h1(&self, checkout: UnixH1Checkout) {
            self.checkin_h1_fenced(checkout, || {}, || {});
        }

        /// The check-in body, with the two seams the fence's regression tests
        /// need. Production passes empty closures, so this monomorphizes to the
        /// same code with no branch and no allocation.
        ///
        /// * `between_fence_reads` runs after the pre-insert generation check
        ///   and before the insert — the window a publication has to win for
        ///   the post-insert half of the fence to be the thing that saves us.
        /// * `after_insert` runs after the insert and after the shard guard is
        ///   released, but before the post-insert cleanup — the window in which
        ///   an old-generation entry is VISIBLE, and in which a concurrent
        ///   checkout must refuse it rather than launder it.
        pub(crate) fn checkin_h1_fenced(
            &self,
            checkout: UnixH1Checkout,
            between_fence_reads: impl FnOnce(),
            after_insert: impl FnOnce(),
        ) {
            let UnixH1Checkout {
                key,
                admitted,
                reused: _,
                generation,
                keep_alive,
                sender,
            } = checkout;
            // Keep-alive off: the carrier served its one exchange and is
            // retired here. Dropping the sender closes the connection, which
            // ends its driver and releases its slot on the target's bound.
            if !keep_alive || sender.is_closed() || self.is_shutting_down() {
                return;
            }
            // Fence, first read. A publication that already completed retired
            // this lease's incarnation; the carrier must not be pooled even if
            // the socket object is untouched and the connection is healthy.
            if self.publication_generation.load(Ordering::Acquire) != generation {
                drop(sender);
                self.record_withdrawal_fenced_checkin();
                return;
            }
            if !admitted.still_names_checked_object().unwrap_or(false) {
                let path = admitted.resolved_path().to_path_buf();
                drop(sender);
                self.retire_socket_path(&path);
                return;
            }
            if !self.target_is_live(&key) {
                drop(sender);
                self.record_withdrawal_fenced_checkin();
                return;
            }
            between_fence_reads();
            let entry_id = self.next_entry_id.fetch_add(1, Ordering::Relaxed);
            let max_idle = self.max_idle_per_key();
            {
                let mut slot = self.h1_idle.entry(key.clone()).or_default();
                if slot.entries.len() >= max_idle {
                    // Bound the idle set: drop the OLDEST idle connection,
                    // which is the one most likely to have been reaped by
                    // the peer.
                    slot.entries.remove(0);
                    Self::note_pooled_removed(&self.idle_h1_gauge, 1);
                    crate::runtime_metrics::global_ref()
                        .record_pool_eviction(PoolKind::UnixBackend);
                }
                Self::note_pooled_added(&self.idle_h1_gauge);
                slot.entries.push(IdleH1 {
                    id: entry_id,
                    generation: AtomicU64::new(generation),
                    sender,
                    admitted,
                    last_used_at: AtomicU64::new(unix_secs()),
                });
                // The shard guard is released HERE, before the second fence
                // read: the release/acquire pair on that shard is what orders a
                // concurrent publication's generation bump ahead of the read
                // when the retirement pass ran before this insert.
            }
            after_insert();
            // Fence, second read. Either the publication's retirement pass saw
            // this entry and removed it, or it did not — in which case it
            // released the shard before we took it and the bump is visible now.
            // In the gap between the insert and this cleanup the entry is
            // visible but still carries the OLD token, so a concurrent checkout
            // refuses it (fence rule 2) rather than laundering it.
            if self.publication_generation.load(Ordering::Acquire) != generation
                && withdraw_slot_entry(&self.h1_idle, &key, entry_id)
            {
                Self::note_pooled_removed(&self.idle_h1_gauge, 1);
                self.record_fenced_carriers(1);
            }
        }

        /// Return an HTTP/1.1 lease whose response body has ALREADY been read in
        /// full, once hyper's dispatcher has also re-armed for the next request.
        ///
        /// The caller establishes the safety precondition (the body is
        /// complete); this only closes the scheduling gap. Reading the last body
        /// byte does not synchronously make the sender usable again — the
        /// connection driver has to poll once more before its `want` channel
        /// re-arms — so a synchronous check-in would pool a sender that the very
        /// next `try_send_request` would bounce, and the pool would never
        /// actually reuse anything.
        ///
        /// It is therefore ONLY correct for a fully-read body. Do not reuse it to
        /// pool a streaming response: h1 `can_write_head()` is true while a
        /// response body is still being read, so `ready()` would resolve mid-body.
        ///
        /// If the connection died instead, `ready()` resolves `Err` and the lease
        /// is dropped. The waiter therefore lives exactly as long as the
        /// connection it owns — it cannot outlive it or leak.
        ///
        /// An associated function rather than a method because `&Arc<Self>` is
        /// not a permitted method receiver on stable Rust.
        pub fn checkin_h1_when_idle(pool: &Arc<Self>, mut checkout: UnixH1Checkout) {
            // Keep-alive off retires the carrier here rather than parking a
            // waiter task for a connection that may never be pooled.
            if !checkout.keep_alive || checkout.sender.is_closed() || pool.is_shutting_down() {
                return;
            }
            // Fence early so a lease whose incarnation is already retired is
            // dropped here rather than parked in a waiter task. `checkin_h1`
            // re-evaluates the fence in full; this is only a fast path.
            if pool.publication_generation.load(Ordering::Acquire) != checkout.generation {
                pool.record_withdrawal_fenced_checkin();
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
                }
            });
        }

        /// Wrap an exclusive HTTP/1.1 lease as a
        /// [`crate::proxy::body::PooledBackendLease`] for a STREAMING response.
        ///
        /// This is the EOF-anchored handoff. The returned guard owns the lease
        /// for as long as the `ProxyBody` holding the backend stream lives; that
        /// body releases it only after a proven clean end (`Poll::Ready(None)`,
        /// or a successful terminal frame after backend EOF), and drops it on
        /// every other terminal. Because the guard owns the only
        /// `UnixH1Checkout`, the connection cannot be handed to another request
        /// while the body is still streaming — the sender is not in `h1_idle`
        /// and there is no second reference to it.
        ///
        /// The guard is not "detached": it has no task of its own and no pool
        /// registry entry. Its lifetime is exactly the response body's.
        pub fn streaming_lease(
            pool: &Arc<Self>,
            checkout: UnixH1Checkout,
        ) -> Box<dyn crate::proxy::body::PooledBackendLease> {
            Box::new(UnixH1StreamingLease {
                pool: Arc::clone(pool),
                checkout: Some(checkout),
            })
        }

        /// Acquire a multiplexable h2c sender for `socket_path`.
        ///
        /// Concurrent misses for one identity are coalesced behind a creation
        /// lock whose wait is bounded by the same establishment deadline as the
        /// dial itself, so a wedged local app cannot pin queued requests past
        /// the budget the caller already committed to.
        pub async fn checkout_h2c(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            self.checkout_h2c_fenced(
                proxy,
                socket_path,
                connect_timeout_ms,
                allowed_roots,
                allowed_uids,
                (|| {}, || {}),
            )
            .await
        }

        /// The h2c checkout body, with the same two seams
        /// [`Self::checkin_h1_fenced`] exposes, as one `(before, after)` pair:
        /// `before` runs after the dial and before the carrier enters the
        /// shared map, and `after` runs once it is in the map and before the
        /// fence's cleanup — the window in which a superseded carrier is
        /// visible. Production passes empty closures.
        pub(crate) async fn checkout_h2c_fenced(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
            publish_seams: (impl FnOnce(), impl FnOnce()),
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            self.checkout_h2c_inner(
                proxy,
                socket_path,
                connect_timeout_ms,
                allowed_roots,
                allowed_uids,
                publish_seams,
                || std::future::ready(()),
            )
            .await
        }

        /// The same production h2c checkout with the H1 path's registration
        /// seam: an async hook awaited after the handshake and BEFORE the driver
        /// is registered, so the shutdown latch/registration race is reproducible
        /// on this wire protocol too (issue #3764).
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests reach it there.
        pub(crate) async fn checkout_h2c_with_registration_seam<F, Fut>(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
            before_register: F,
        ) -> Result<MeshMtlsSender, UnixBackendError>
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            self.checkout_h2c_inner(
                proxy,
                socket_path,
                connect_timeout_ms,
                allowed_roots,
                allowed_uids,
                (|| {}, || {}),
                before_register,
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn checkout_h2c_inner<F, Fut>(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
            publish_seams: (impl FnOnce(), impl FnOnce()),
            before_register: F,
        ) -> Result<MeshMtlsSender, UnixBackendError>
        where
            F: FnOnce() -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            let (before_publish, after_publish) = publish_seams;
            // Same fail-closed entry gate as the H1 checkout: after the drain
            // latched the pool, no h2c checkout admits, dials, or handshakes.
            self.refuse_if_shutting_down()?;
            // ONE budget, opened at the OUTERMOST entry — before the amortized
            // idle sweep, before admission, and therefore before the creation-
            // lock wait too, so neither pool maintenance nor a queue behind a
            // wedged app is charged outside the budget the caller committed to
            // (issue #3764).
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            self.maybe_prune_idle();
            // Same fence as the H1 lease: a dial can straddle a publication, so
            // the generation is captured before admission and re-checked after
            // the carrier is published into the shared map.
            let generation = self.publication_generation.load(Ordering::Acquire);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::H2c);

            if let Some(sender) = self.take_shared_h2c(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(sender);
            }

            let lock = self
                .h2c_creation_locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone();
            let _guard = match tokio::time::timeout_at(deadline, lock.lock()).await {
                Ok(guard) => guard,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };

            // The winner of the lock may have published a carrier while we
            // waited; re-check before spending another connect.
            if let Some(sender) = self.take_shared_h2c(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(sender);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);

            // Pre-`connect(2)` bound, exactly as on the H1 cold path. Reuse of
            // a shared carrier returned above without reaching this line, so an
            // arbitrary number of multiplexed RPCs still ride one admitted slot.
            let conn_slot = self.acquire_conn_slot(&key)?;
            let connect = connect_admitted(&admitted, deadline, timeout_ms);
            let stream = match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result.inspect_err(|_| self.record_setup_failure())?,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };
            let (sender, driver) = handshake_unix_h2c_sender(stream, deadline, timeout_ms)
                .await
                .inspect_err(|_| self.record_setup_failure())?;
            // Structured ownership of the h2c driver, and with it the target's
            // physical-connection slot, for the physical connection's whole
            // life. A tracker latched closed by a concurrent drain refuses it,
            // and this checkout then fails closed with `sender` dropped and
            // never published — exactly as on the H1 path.
            before_register().await;
            self.register_driver(driver, conn_slot)?;

            let max_idle = self.max_idle_per_key();
            let entry_id = self.next_entry_id.fetch_add(1, Ordering::Relaxed);
            if !self.target_is_live(&key) {
                self.record_withdrawal_fenced_checkin();
                return Ok(sender);
            }
            // Placed AFTER the live-set read and before the insert, exactly
            // where `checkin_h1_fenced` places `between_fence_reads`: that is
            // the window a publication has to win for the post-insert half of
            // the fence to be the thing that saves us, and the only one in
            // which a superseded carrier can still reach the shared map.
            before_publish();
            {
                let mut slot = self.h2c_carriers.entry(key.clone()).or_default();
                while slot.entries.len() >= max_idle {
                    slot.entries.remove(0);
                    Self::note_pooled_removed(&self.h2c_carrier_gauge, 1);
                    crate::runtime_metrics::global_ref()
                        .record_pool_eviction(PoolKind::UnixBackend);
                }
                Self::note_pooled_added(&self.h2c_carrier_gauge);
                slot.entries.push(SharedH2c {
                    id: entry_id,
                    generation: AtomicU64::new(generation),
                    sender: sender.clone(),
                    admitted,
                    last_used_at: AtomicU64::new(unix_secs()),
                });
                // Shard guard released before the second fence read, as in
                // `checkin_h1_fenced`.
            }
            // The caller keeps this sender for the request it is already
            // authorized to make; the fence only decides whether the carrier
            // stays REUSABLE. A publication that landed during the dial retires
            // it immediately.
            after_publish();
            if self.publication_generation.load(Ordering::Acquire) != generation
                && withdraw_slot_entry(&self.h2c_carriers, &key, entry_id)
            {
                Self::note_pooled_removed(&self.h2c_carrier_gauge, 1);
                self.record_fenced_carriers(1);
            }
            Ok(sender)
        }

        /// Whether the PRODUCTION shared-h2c selector would hand a pooled
        /// carrier to a request for this identity right now.
        ///
        /// A read-only observation of `take_shared_h2c`, the exact hot-path
        /// predicate, so a test can inspect the after-publish window without
        /// re-entering `checkout_h2c` (which would block on the creation lock
        /// its caller still holds). It re-admits the path exactly as a checkout
        /// does and never dials.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests reach it there.
        pub(crate) fn shared_h2c_selector_yields_carrier(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> bool {
            let Ok(admitted) = crate::util::unix_socket::admit_socket_for_connect(
                socket_path,
                allowed_roots,
                allowed_uids,
            ) else {
                return false;
            };
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::H2c);
            self.take_shared_h2c(&key, &admitted, proxy).is_some()
        }

        /// Pick a live shared h2c carrier for `key`, or nothing.
        ///
        /// Carries the same entry-token rule as [`Self::take_idle_h1`]: the
        /// generation is read under the map guard and a carrier published under
        /// a superseded generation is never multiplexed onto, even in the
        /// window between a fenced publish and its own cleanup.
        ///
        /// ## GOAWAY and closed carriers
        ///
        /// `is_closed()` is the liveness gate — `is_ready()` is deliberately NOT
        /// consulted, because on an HTTP/2 sender it also reports transient
        /// `MAX_CONCURRENT_STREAMS` backpressure, so a healthy but busy carrier
        /// would be discarded and replaced with a second physical connection
        /// under exactly the load the pool exists to serve. A GOAWAY does reach
        /// `is_closed()`: hyper's client dispatcher stops accepting new requests
        /// once the h2 connection refuses to open further streams, which closes
        /// the dispatch channel the flag reads.
        ///
        /// A carrier observed closed is REMOVED here rather than merely skipped
        /// (issue #3764). Skipping alone left the dead entry resident until the
        /// next periodic sweep, so every checkout in between re-walked it and
        /// the shared slot could stay permanently occupied by corpses while the
        /// per-identity ceiling refused to admit a replacement.
        fn take_shared_h2c(
            &self,
            key: &UnixPoolKey,
            expected: &AdmittedUnixSocket,
            proxy: &Proxy,
        ) -> Option<MeshMtlsSender> {
            let idle_timeout = self.idle_timeout_seconds(proxy);
            let now = unix_secs();
            let mut retire = false;
            let mut evicted = 0u64;
            let mut selected = None;
            {
                let mut slot = self.h2c_carriers.get_mut(key)?;
                let generation = self.publication_generation.load(Ordering::Acquire);
                for entry in slot.entries.iter() {
                    if !Self::identity_intact(&entry.admitted, expected) {
                        retire = true;
                        break;
                    }
                    if entry.generation.load(Ordering::Acquire) != generation
                        || entry.sender.is_closed()
                        || entry_idle_expired(
                            entry.last_used_at.load(Ordering::Relaxed),
                            idle_timeout,
                            now,
                        )
                    {
                        continue;
                    }
                    entry.last_used_at.store(now, Ordering::Relaxed);
                    selected = Some(entry.sender.clone());
                    break;
                }
                if !retire {
                    // Reclaim carriers that can never serve another RPC. A
                    // superseded-generation entry is left alone: the withdrawal
                    // fence owns that lifecycle and its own cleanup withdraws it
                    // by id, so removing it here would race that.
                    let before = slot.entries.len();
                    slot.entries.retain(|entry| {
                        !entry.sender.is_closed()
                            && !entry_idle_expired(
                                entry.last_used_at.load(Ordering::Relaxed),
                                idle_timeout,
                                now,
                            )
                    });
                    evicted = before.saturating_sub(slot.entries.len()) as u64;
                }
            }
            if evicted > 0 {
                Self::note_pooled_removed(&self.h2c_carrier_gauge, evicted);
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, evicted);
            }
            if retire {
                let path = expected.resolved_path().to_path_buf();
                self.retire_socket_path(&path);
                return None;
            }
            selected
        }

        #[inline]
        fn record_setup_failure(&self) {
            self.setup_failures.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_failure(PoolKind::UnixBackend);
        }

        /// A checkout refused by GATEWAY-side policy rather than by the
        /// application: path admission, the target's physical-connection bound,
        /// or the shutdown latch. Distinct from a setup failure, which is a
        /// connection that was attempted and failed on the app's side.
        ///
        /// The first two are decided before any dial. The shutdown latch is too
        /// when it refuses at the checkout gate; the registration race is the
        /// one case where a connection was established first, and it is counted
        /// here rather than as a setup failure because nothing about the
        /// application failed.
        #[inline]
        fn record_checkout_failure(&self) {
            self.checkout_failures.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_failure(PoolKind::UnixBackend);
        }

        /// Dedicated admitted dial for an RFC 6455 WebSocket upgrade
        /// (issue #3732).
        ///
        /// NEVER pooled and never returned to the idle set: the upgrade consumes
        /// the connection for the whole session. It still reserves the same
        /// per-target physical-connection lane as every cold H1 connection,
        /// and the returned lease must be held for the full session. Admission,
        /// containment,
        /// owner/mode/type, inode identity, and peer-UID verification all
        /// complete inside the single establishment deadline and BEFORE the
        /// caller writes the first upgrade byte.
        ///
        /// The REMAINDER of that one deadline is returned with the stream, and
        /// the caller must bound the RFC 6455 upgrade exchange with it rather
        /// than starting a second timer (issue #3764): admission + connect +
        /// upgrade is one establishment, so it gets one `connect_timeout_ms`
        /// budget in total, not one per stage.
        pub async fn dial_websocket_stream(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<UnixWebSocketDial, UnixBackendError> {
            // Dedicated WebSockets bypass the reusable carrier maps, not the
            // pool's shutdown gate or its per-target physical-connection
            // ceiling. Refuse and reserve before `connect(2)`, exactly like a
            // cold H1 checkout.
            self.refuse_if_shutting_down()?;
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            self.maybe_prune_idle();
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::Http1);
            let conn_slot = self.acquire_conn_slot(&key)?;
            let connect = connect_admitted(&admitted, deadline, timeout_ms);
            let stream = match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result.inspect_err(|_| self.record_setup_failure())?,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };

            self.misses.fetch_add(1, Ordering::Relaxed);
            // A WebSocket has no separately spawned hyper driver. Register its
            // directly owned stream under the dedicated gate instead; this is
            // the linearization point against shutdown, and the returned lease
            // carries both the target slot and fixed-cardinality gauge.
            let conn_lease = self.register_websocket_connection(conn_slot)?;
            Ok(UnixWebSocketDial {
                admitted,
                stream,
                deadline,
                timeout_ms,
                conn_lease,
            })
        }
    }
}

/// Non-Unix build: there is no Unix-domain socket to pool, so the surface
/// exists only so `ProxyState` can always carry the type and every dispatch
/// path keeps its fail-closed refusal at compile time.
#[cfg(not(unix))]
mod imp {
    use crate::config::PoolConfig;
    use crate::config::types::Proxy;
    use crate::proxy::mesh_mtls_pool::MeshMtlsSender;
    use crate::proxy::unix_backend::UnixBackendError;

    pub struct UnixH1Checkout;

    /// Wire protocol a Unix ingress target declares. Mirrors the Unix build's
    /// type so `ProxyState`'s reload reconciliation compiles everywhere.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum UnixWireProtocol {
        Http1,
        H2c,
    }

    /// Config-declared identity of a Unix ingress target. Never populated on a
    /// platform without Unix-domain sockets, but the type must exist so the
    /// shared reload path is not itself `cfg`-gated.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixTargetIdentity {
        pub namespace: String,
        pub proxy_id: String,
        pub upstream_id: Option<String>,
        pub configured_path: String,
        pub protocol: UnixWireProtocol,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
    pub struct UnixPoolStats {
        pub hits: u64,
        pub misses: u64,
        pub physical_connects: u64,
        pub identity_retirements: u64,
        pub setup_failures: u64,
        pub checkout_failures: u64,
        pub idle_h1_connections: u64,
        pub active_h2c_connections: u64,
        pub open_physical_connections: u64,
        pub withdrawal_fenced_checkins: u64,
    }

    pub struct UnixBackendConnectionPool {
        pool_config: PoolConfig,
    }

    impl UnixBackendConnectionPool {
        pub fn new(
            pool_config: PoolConfig,
            _shard_amount: usize,
            _max_connections_per_target: u32,
        ) -> Self {
            Self { pool_config }
        }

        /// Parity with the Unix build: process-lifetime keep-alive / H1 reuse
        /// default used by publication collection.
        #[inline]
        pub fn default_http_keep_alive(&self) -> bool {
            self.pool_config.enable_http_keep_alive
        }

        /// Parity with the Unix build. Nothing is ever dialed here, so no
        /// target ever holds a connection lane and no driver is ever tracked.
        #[allow(dead_code)] // Parity with the Unix build; no Unix sockets to pool here.
        pub fn resident_connection_lanes(&self) -> usize {
            0
        }

        #[allow(dead_code)] // Parity with the Unix build; no Unix pool keys exist here.
        pub fn resident_key_slots(&self) -> (usize, usize) {
            (0, 0)
        }

        #[allow(dead_code)] // Parity with the Unix build; no drivers to track here.
        pub fn tracked_drivers(&self) -> usize {
            0
        }

        /// Mirrors the Unix build's shutdown-latch accessor. There is no pool
        /// state to latch on this platform, so it never reads as published.
        #[allow(dead_code)] // Parity with the Unix build; nothing to latch here.
        pub fn shutdown_latch_published(&self) -> bool {
            false
        }

        /// Mirrors the Unix build's accessor. Nothing is ever pooled here, so
        /// the generation never advances.
        #[allow(dead_code)] // Parity with the Unix build; no Unix sockets to pool here.
        pub fn publication_generation(&self) -> u64 {
            0
        }

        pub fn force_drain_all(&self) {}

        /// Parity with the Unix build's bounded driver reap. There are no
        /// drivers on this platform, so it completes immediately.
        pub async fn shutdown_drain(&self) {}

        /// Parity with the Unix build's explicit-budget drain seam.
        #[allow(dead_code)] // Parity with the Unix build; nothing to drain here.
        pub async fn shutdown_drain_with_budgets(
            &self,
            _driver_budget: std::time::Duration,
            _reap_budget: std::time::Duration,
        ) {
        }

        pub fn retain_live_targets_for_publication(
            &self,
            _config_generation: u64,
            _live: &std::collections::HashSet<UnixTargetIdentity>,
        ) {
        }

        pub fn retain_live_targets(&self, _live: &std::collections::HashSet<UnixTargetIdentity>) {}

        pub fn stats(&self) -> UnixPoolStats {
            UnixPoolStats::default()
        }

        pub async fn checkout_h1(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }

        pub async fn checkout_fresh_h1(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }

        pub fn checkin_h1(&self, _checkout: UnixH1Checkout) {}

        pub fn checkin_h1_when_idle(_pool: &std::sync::Arc<Self>, _checkout: UnixH1Checkout) {}

        pub async fn checkout_h2c(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }
    }
}

pub use imp::*;

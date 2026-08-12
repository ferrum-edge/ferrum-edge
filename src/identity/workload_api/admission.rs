//! Transport admission for the SPIFFE Workload API listener (issue #3758).
//!
//! The Workload API socket is a *local* trust boundary: anything permitted to
//! connect may attempt attestation. That authorizes an identity **request** — it
//! must not also grant one workload the ability to deny identity service to
//! every other workload sharing the node. Without a bound at the transport, a
//! process with socket access can hold arbitrarily many idle Unix connections,
//! open arbitrarily many HTTP/2 streams on each, and drive arbitrarily many
//! concurrent RPC producers. The per-RPC rotation protections
//! ([`super::latest_wins`], the entitlement recheck) all begin *after* an RPC has
//! been admitted, so none of them cover that shape.
//!
//! ## Where the bound is applied
//!
//! Admission runs **before the accepted socket is yielded to tonic**, so a
//! refused connection never allocates an HTTP/2 connection, a service clone, or
//! a producer task:
//!
//! 1. **Kernel peer credentials first.** `SO_PEERCRED` is read off the accepted
//!    socket ([`ConnectionAdmission::admit`]). It is kernel-attested and cannot
//!    be spoofed by the caller, unlike anything in gRPC metadata, and it is the
//!    only trustworthy key for a per-principal quota. A socket whose credentials
//!    cannot be read is **refused** — fail-closed, because an unattributable
//!    connection cannot be charged to any quota.
//! 2. **Per-UID quota first, then total connections** — as **one** decision
//!    taken under a single lock. Both halves are non-blocking: a bounded
//!    counter and `try_acquire`, never a wait. The order is load-bearing rather
//!    than incidental: taking the global permit first would let a burst from an
//!    already-saturated UID each hold a global slot while queued on the per-UID
//!    lock, transiently emptying the whole shared pool and refusing an
//!    *innocent* second UID — which is precisely the fair-share property the
//!    per-UID quota exists to provide. A caller over either limit is shed
//!    immediately by closing the socket, so no backlog of would-be connections
//!    accumulates behind the ceiling.
//! 3. The admitted socket is wrapped in [`AdmittedUnixStream`], which **owns**
//!    the permit and the connection's watchdog task. Release is therefore tied
//!    to the connection object's lifetime rather than to any particular code
//!    path: a clean close, a transport error, a handshake that never completes,
//!    a cancelled task, and a panic unwind all drop the wrapper, all release
//!    the permit, and all cancel the watchdog immediately rather than leaving a
//!    detached task asleep until its next tick.
//!
//! HTTP/2 stream and RPC ceilings are applied on top of that, in
//! [`super::listener`] (`max_concurrent_streams` + a per-connection concurrency
//! limit with load shedding) and in [`super::server`] (an [`RpcAdmission`]
//! permit taken at the top of every RPC, before attestation, CA work, or any
//! spawned producer). Both reject rather than queue.
//!
//! ## Fair share applies twice, not once
//!
//! A per-UID *connection* quota alone does not bound a UID's share of the
//! *service*. At the shipped defaults one socket-group UID may hold 32
//! connections × 64 streams = 2048 concurrent RPCs, which is more than the
//! service-wide ceiling — and the two bundle RPCs (`FetchX509Bundles`,
//! `FetchJWTBundles`) require only the mandatory `workload.spiffe.io` metadata
//! header, so occupying every permit costs an attacker no attestation and no
//! entitlement. Every other workload's SVID renewal would then be shed with
//! `RESOURCE_EXHAUSTED`.
//!
//! So [`RpcAdmission`] applies the identical two-level decision one layer up,
//! keyed on the same kernel-attested peer UID (read from `UdsConnectInfo`,
//! which tonic populates from the accepted socket): the per-UID quota is judged
//! first, then the service-wide ceiling, as one non-blocking decision under one
//! lock (one shared helper implements that ordering for both gates, so the
//! invariant has exactly one implementation). A refused RPC creates **no** map
//! entry, so a shed flood cannot grow per-UID state, and an entry is removed
//! when its last permit drops, so the map is bounded by peers *currently
//! holding* permits. An RPC whose peer UID cannot be established is refused:
//! the connection gate already refuses an unattributable socket, so this is
//! defence in depth rather than a reachable path, and it fails closed.
//!
//! The permit rides the **response stream**, not the method future, so it is
//! held for exactly as long as the producer task, rotation subscription, and
//! pending private-key slot exist — which is what a Workload API client
//! actually occupies.
//!
//! ## Lifetime bounds
//!
//! Two deadlines are enforced by a per-connection watchdog:
//!
//! - the **initial** deadline runs from admission until the first byte is read.
//!   A peer that connects and then says nothing is the cheapest possible flood,
//!   and it is the shape a per-request timeout cannot see;
//! - the **idle** deadline runs from the last byte *read from the peer*. Reads,
//!   not writes, are the liveness evidence: the server's own HTTP/2 keepalive
//!   PINGs are writes, so counting writes would make the deadline unreachable.
//!   A live peer answers those PINGs with PING ACKs — which are reads — so a
//!   deliberately long-lived `FetchX509SVID` stream that is byte-idle at the
//!   application level still refreshes the deadline, while a peer that has
//!   stopped participating does not. [`super::listener`] derives the keepalive
//!   interval from the idle deadline so that relationship always holds.
//!
//! Expiry, and the forced close at the end of shutdown, are delivered by
//! flipping a flag on shared per-connection state and waking the parked I/O
//! waker. The next `poll_read`/`poll_write` then fails with
//! `ConnectionAborted`, which ends the connection deterministically from
//! *inside* the transport rather than depending on tonic's per-connection tasks
//! being reachable from outside (they are detached, and aborting the accept loop
//! does not disturb them).
//!
//! ## Ceilings
//!
//! Every limit has a finite default *and* a hard ceiling. The ceilings are
//! enforced twice: [`WorkloadApiAdmissionConfig::validate`] refuses an
//! over-ceiling value loudly at configuration time, and
//! [`WorkloadApiAdmissionConfig::clamped`] — applied by the admission
//! constructor — clamps whatever it is handed, so a value that reaches the
//! runtime through some other path still cannot raise the ceiling. `0` is not a
//! "disabled" spelling for any of them: an unbounded Workload API transport is
//! the defect this module exists to remove.
//!
//! Each per-UID quota is additionally required to be **strictly below** its
//! shared ceiling, by both gates, for connections and for RPCs alike. A quota
//! equal to the shared ceiling is not a fair share at all — one UID may then
//! hold every slot, which is exactly the posture the per-UID bound is
//! documented to prevent — so a fair configuration necessarily has room for at
//! least two. Those are the finite floors: [`MIN_MAX_CONNECTIONS`] and
//! [`MIN_MAX_CONCURRENT_RPCS`] are `2`, and `clamped` never produces equality,
//! for zero, one, or over-ceiling input.
//!
//! The RPC defaults are derived rather than picked:
//! [`LONG_LIVED_RPCS_PER_CONNECTION`] states how many streams a *legitimate*
//! client holds open at once, and both RPC defaults are at least that many per
//! default connection. A service-wide ceiling below that would make the shipped
//! configuration contradict itself — the connection ceiling would admit peers
//! the RPC ceiling had to shed, and the shed would land on SVID renewal.
//!
//! ## Metrics
//!
//! Counters and gauges are **fixed-cardinality**: an aggregate active-connection
//! gauge, and rejection/close counters keyed only by a closed set of
//! `&'static str` reasons. Peer UID, PID, SPIFFE ID, and token material are
//! attacker-influenced or credential-adjacent and are never metric labels.
//! Rejection `debug!` logs carry only fixed reason/limit context — never raw
//! caller identifiers or credential metadata — and are off by default so they
//! cannot themselves be flooded into a disk-exhaustion primitive.
//!
//! The RPC gauge and shed counter are the closest thing here to a stream-level
//! observation, and the relationship is **one-way**: every admitted Workload API
//! RPC occupies exactly one HTTP/2 stream for its whole lifetime, but not every
//! live HTTP/2 stream is an admitted Workload API RPC. A stream refused by
//! HTTP/2's own advertised `SETTINGS_MAX_CONCURRENT_STREAMS` is refused inside
//! h2 before any Ferrum code runs, and an unknown or malformed route is rejected
//! before service dispatch; neither is counted. So `active_rpcs` is the count of
//! **service-dispatched** Workload API RPC streams, not the live stream count,
//! and `rpcs_rejected_total` counts RPCs shed *after* their stream was already
//! opened and accepted by h2 — a `RESOURCE_EXHAUSTED` gRPC result on a live
//! stream, not a protocol-level stream refusal. It is deliberately **unlabelled**
//! and covers both RPC bounds together: splitting it by which bound refused would
//! be useful, but the only honest key for the per-UID half is the peer UID, and
//! a synthetic stand-in label that operators would learn to map back to a
//! principal is the same disclosure with extra steps. Which of the two bounds
//! refused is stated only in the (off-by-default, UID-free) `debug!`. The help
//! text says exactly that rather than the stronger converse, and there is
//! deliberately no *second* stream family: transport-level excess streams are
//! not observable from this layer, so a counter claiming them would claim
//! coverage that does not exist.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::task::AtomicWaker;
use pin_project_lite::pin_project;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;
use tokio_stream::Stream;
use tracing::{debug, error, warn};

use crate::plugins::mesh::prometheus_helpers as mesh_metrics;

use super::listener::WorkloadApiListenerError;

/// Default number of simultaneously accepted Workload API connections.
///
/// A node's workloads hold one Workload API connection each in the steady
/// state, so this is generous for a single node while still being a finite,
/// pre-allocated bound on file descriptors and HTTP/2 connection state.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Hard ceiling on total connections. An operator may raise the soft limit up to
/// here and no further.
pub const MAX_CONNECTIONS_CEILING: usize = 4096;

/// Smallest total-connection ceiling a *fair* configuration can express.
///
/// The per-UID quota must be strictly below the global ceiling, or one UID may
/// hold the whole pool and the fair-share promise is empty. A quota is at least
/// `1`, so the global ceiling is at least `2`: a globally fair transport
/// necessarily has room for a second connection. This is a finite floor, not a
/// "disabled" spelling — `1` is refused by [`WorkloadApiAdmissionConfig::validate`]
/// and raised to `2` by [`WorkloadApiAdmissionConfig::clamped`].
pub const MIN_MAX_CONNECTIONS: usize = 2;

/// Default per-peer-UID connection quota.
///
/// Sized so a normal workload (one connection, plus reconnect overlap and a few
/// sidecar helpers sharing a uid) is never affected, while a single uid cannot
/// approach [`DEFAULT_MAX_CONNECTIONS`].
pub const DEFAULT_MAX_CONNECTIONS_PER_UID: usize = 32;

/// Hard ceiling on the per-UID quota.
pub const MAX_CONNECTIONS_PER_UID_CEILING: usize = 1024;

/// Default HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per connection.
///
/// The Workload API has five RPCs and a workload keeps at most a handful of
/// them open; the headroom absorbs rotation overlap without admitting a
/// stream-fanout flood.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 64;

/// Hard ceiling on per-connection HTTP/2 streams.
pub const MAX_CONCURRENT_STREAMS_CEILING: u32 = 1024;

/// Long-lived Workload API streams a *legitimate* client holds at once.
///
/// A normal workload keeps `FetchX509SVID` open for SVID rotation,
/// `FetchX509Bundles` open for X.509 trust-material rotation, and — when it uses
/// JWT-SVIDs — `FetchJWTBundles` open as well. Each of those occupies its RPC
/// permit for the whole life of its response stream, so the *steady state* of
/// one connection is three permits, not one. Both RPC defaults below are sized
/// from this number rather than guessed, so the shipped configuration cannot
/// shed a workload that is behaving exactly as the SPIFFE Workload API
/// specification describes.
pub const LONG_LIVED_RPCS_PER_CONNECTION: usize = 3;

/// Default service-wide ceiling on concurrently admitted RPCs.
///
/// At least [`LONG_LIVED_RPCS_PER_CONNECTION`] per default connection
/// (`256 * 3 = 768`), rounded up to a power of two. Sizing it below that would
/// make the *default* configuration internally contradictory: the connection
/// ceiling would admit peers the RPC ceiling then had to shed, and the shed
/// would land on SVID renewal rather than on anything abusive.
pub const DEFAULT_MAX_CONCURRENT_RPCS: usize = 1024;

/// Hard ceiling on service-wide concurrent RPCs.
pub const MAX_CONCURRENT_RPCS_CEILING: usize = 8192;

/// Smallest service-wide RPC ceiling a *fair* configuration can express.
///
/// Same reasoning as [`MIN_MAX_CONNECTIONS`]: the per-UID RPC quota must stay
/// strictly below the service-wide ceiling, and a quota is at least `1`.
pub const MIN_MAX_CONCURRENT_RPCS: usize = 2;

/// Default per-peer-UID ceiling on concurrently admitted RPCs.
///
/// At least [`LONG_LIVED_RPCS_PER_CONNECTION`] per default per-UID connection
/// (`32 * 3 = 96`), rounded up to a power of two, and comfortably below
/// [`DEFAULT_MAX_CONCURRENT_RPCS`]. Without this bound the connection quota is
/// not actually a fair share of the *service*: one UID may hold 32 connections
/// × 64 streams and take every service-wide RPC permit, and the bundle RPCs
/// need only the mandatory metadata header to do it — no attestation, no
/// entitlement — so a single socket-group member could deny SVID renewal to
/// every other workload on the node.
pub const DEFAULT_MAX_CONCURRENT_RPCS_PER_UID: usize = 128;

/// Hard ceiling on the per-UID RPC quota.
pub const MAX_CONCURRENT_RPCS_PER_UID_CEILING: usize = 4096;

/// Default deadline from admission to the first byte read from the peer.
pub const DEFAULT_INITIAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard ceiling on the initial-connection deadline.
pub const INITIAL_CONNECTION_TIMEOUT_CEILING: Duration = Duration::from_secs(300);

/// Default deadline since the last byte read from the peer.
///
/// Comfortably above the keepalive interval derived from it, so an established
/// long-lived stream is refreshed by PING ACKs rather than closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

/// Hard ceiling on the idle deadline.
pub const IDLE_TIMEOUT_CEILING: Duration = Duration::from_secs(86_400);

/// Default bounded graceful-drain deadline at shutdown.
pub const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Hard ceiling on the graceful-drain deadline.
pub const SHUTDOWN_GRACE_CEILING: Duration = Duration::from_secs(300);

/// How long the serve future is given to finish *after* connections have been
/// force-closed, before it is abandoned entirely.
///
/// Not operator-configurable: it bounds only the interval between "every live
/// connection has been made to fail" and "the transport noticed", which is a
/// property of the runtime rather than of the deployment.
pub const FORCE_CLOSE_SETTLE: Duration = Duration::from_secs(5);

/// Fraction of the shorter deadline one watchdog tick covers.
///
/// Detection latency is therefore at most a quarter of the deadline being
/// enforced, whatever that deadline is — a *relative* bound rather than an
/// absolute one, which is what keeps the wakeup rate proportional to the
/// configuration instead of to the connection count.
pub const WATCHDOG_TICK_DIVISOR: u32 = 4;

/// Longest a watchdog sleeps between deadline checks.
///
/// The deadline itself is evaluated against a monotonic clock, so this only
/// bounds detection latency, never accuracy. It is deliberately far above one
/// second: the tick is *per connection*, so a fixed one-second floor would cost
/// one wakeup per second per admitted connection — 4096 wakeups a second at the
/// hard connection ceiling — to notice a deadline that is measured in minutes.
pub const WATCHDOG_MAX_TICK: Duration = Duration::from_secs(30);

/// Shortest watchdog tick, so a very small configured deadline cannot turn the
/// watchdog into a busy loop.
pub const WATCHDOG_MIN_TICK: Duration = Duration::from_millis(25);

/// First backoff step after a resource-exhaustion accept error.
///
/// `EMFILE`/`ENFILE`/`ENOBUFS` persist until a descriptor is released, and
/// retrying immediately would spin a runtime worker at full speed for as long as
/// the condition lasted.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Longest the accept loop pauses between retries. The backoff doubles from
/// [`ACCEPT_BACKOFF`] up to this, so a condition that persists costs a bounded,
/// small fraction of one runtime worker rather than a spin.
pub const ACCEPT_MAX_BACKOFF: Duration = Duration::from_secs(1);

/// Consecutive *transient* accept failures tolerated without a pause.
///
/// `ECONNABORTED`/`EINTR` are per-connection events an accept loop is expected
/// to retry at once; a run of them long enough to look like a spin is treated
/// like exhaustion and backed off instead.
const TRANSIENT_RETRY_BURST: u32 = 8;

/// Rejection reasons. A closed set of `&'static str`, so the metric dimension
/// they key is fixed regardless of what any caller does.
pub mod reject_reason {
    /// `SO_PEERCRED` could not be read, so the connection cannot be charged to
    /// any principal's quota.
    pub const PEER_CREDENTIALS: &str = "peer_credentials";
    /// The total connection ceiling is saturated.
    pub const MAX_CONNECTIONS: &str = "max_connections";
    /// The peer UID is at its per-UID quota.
    pub const MAX_CONNECTIONS_PER_UID: &str = "max_connections_per_uid";
    /// The listener has stopped admitting because shutdown was requested.
    pub const SHUTTING_DOWN: &str = "shutting_down";
}

/// Reasons the listener itself closed an established connection.
pub mod close_reason {
    /// No first byte arrived before the initial-connection deadline.
    pub const INITIAL_TIMEOUT: &str = "initial_timeout";
    /// No byte was read from the peer before the idle deadline.
    pub const IDLE_TIMEOUT: &str = "idle_timeout";
    /// The bounded graceful-drain deadline expired at shutdown.
    pub const SHUTDOWN_DEADLINE: &str = "shutdown_deadline";
}

/// Operator-facing transport admission limits for the Workload API listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadApiAdmissionConfig {
    /// Simultaneously accepted connections across all peers.
    pub max_connections: usize,
    /// Simultaneously accepted connections per kernel-attested peer UID.
    pub max_connections_per_uid: usize,
    /// HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised per connection, and
    /// the per-connection request concurrency limit paired with load shedding.
    pub max_concurrent_streams: u32,
    /// Service-wide concurrently admitted RPCs.
    ///
    /// A streaming RPC holds its permit for the **whole life of its response
    /// stream**, not for the duration of the method call, so this is a bound on
    /// concurrently *open* Workload API streams rather than on request rate.
    pub max_concurrent_rpcs: usize,
    /// Concurrently admitted RPCs per kernel-attested peer UID. Must be
    /// strictly below `max_concurrent_rpcs`.
    pub max_concurrent_rpcs_per_uid: usize,
    /// Deadline from admission to the first byte read from the peer.
    pub initial_connection_timeout: Duration,
    /// Deadline since the last byte read from the peer.
    pub idle_timeout: Duration,
    /// Bounded graceful-drain deadline at shutdown.
    pub shutdown_grace: Duration,
}

impl Default for WorkloadApiAdmissionConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_uid: DEFAULT_MAX_CONNECTIONS_PER_UID,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            max_concurrent_rpcs: DEFAULT_MAX_CONCURRENT_RPCS,
            max_concurrent_rpcs_per_uid: DEFAULT_MAX_CONCURRENT_RPCS_PER_UID,
            initial_connection_timeout: DEFAULT_INITIAL_CONNECTION_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl WorkloadApiAdmissionConfig {
    /// Build from the parsed `FERRUM_MESH_WORKLOAD_API_*` admission settings.
    ///
    /// Deliberately a plain constructor with no validation: `validate` is the
    /// single place a value is judged, so `EnvConfig::validate` and mesh startup
    /// cannot disagree about what is acceptable.
    // These arguments intentionally mirror the eight independently parsed
    // admission settings. Keeping the mapping explicit makes it possible for
    // EnvConfig validation and listener construction to share this one type.
    #[allow(clippy::too_many_arguments)]
    pub fn from_settings(
        max_connections: usize,
        max_connections_per_uid: usize,
        max_concurrent_streams: u32,
        max_concurrent_rpcs: usize,
        max_concurrent_rpcs_per_uid: usize,
        initial_connection_timeout_seconds: u64,
        idle_timeout_seconds: u64,
        shutdown_grace_seconds: u64,
    ) -> Self {
        Self {
            max_connections,
            max_connections_per_uid,
            max_concurrent_streams,
            max_concurrent_rpcs,
            max_concurrent_rpcs_per_uid,
            initial_connection_timeout: Duration::from_secs(initial_connection_timeout_seconds),
            idle_timeout: Duration::from_secs(idle_timeout_seconds),
            shutdown_grace: Duration::from_secs(shutdown_grace_seconds),
        }
    }

    /// Refuse a configuration that is unbounded, over a hard ceiling, or
    /// internally contradictory.
    ///
    /// Refusal rather than silent clamping: a limit an operator set and a limit
    /// the process enforces must be the same number, or the deployment's
    /// documented posture is not the one running. [`Self::clamped`] still
    /// applies the ceilings defensively at construction, so the two together
    /// give a loud failure *and* an enforced bound.
    pub fn validate(&self) -> Result<(), WorkloadApiListenerError> {
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS",
            self.max_connections,
            MAX_CONNECTIONS_CEILING,
        )?;
        if self.max_connections < MIN_MAX_CONNECTIONS {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS ({}) must be at least \
                 {MIN_MAX_CONNECTIONS}: the per-UID quota has to stay strictly below it, so a \
                 globally fair Workload API transport needs room for at least two connections",
                self.max_connections
            )));
        }
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID",
            self.max_connections_per_uid,
            MAX_CONNECTIONS_PER_UID_CEILING,
        )?;
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_STREAMS",
            self.max_concurrent_streams as usize,
            MAX_CONCURRENT_STREAMS_CEILING as usize,
        )?;
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS",
            self.max_concurrent_rpcs,
            MAX_CONCURRENT_RPCS_CEILING,
        )?;
        if self.max_concurrent_rpcs < MIN_MAX_CONCURRENT_RPCS {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS ({}) must be at least \
                 {MIN_MAX_CONCURRENT_RPCS}: the per-UID RPC quota has to stay strictly below it, \
                 so a fair Workload API service needs room for at least two concurrent RPCs",
                self.max_concurrent_rpcs
            )));
        }
        check_range(
            "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS_PER_UID",
            self.max_concurrent_rpcs_per_uid,
            MAX_CONCURRENT_RPCS_PER_UID_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS",
            self.initial_connection_timeout,
            INITIAL_CONNECTION_TIMEOUT_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS",
            self.idle_timeout,
            IDLE_TIMEOUT_CEILING,
        )?;
        check_duration(
            "FERRUM_MESH_WORKLOAD_API_SHUTDOWN_GRACE_SECONDS",
            self.shutdown_grace,
            SHUTDOWN_GRACE_CEILING,
        )?;

        // A per-UID quota at or above the global ceiling is not an error the
        // operator would notice at runtime — it simply never leaves a slot for
        // anyone else — so it is reported as the misconfiguration it is rather
        // than silently ignored. Equality is refused as firmly as excess: a
        // quota equal to the global ceiling lets one UID hold every connection,
        // which is exactly the denial of identity service to the rest of the
        // node that the per-UID bound is documented to prevent.
        if self.max_connections_per_uid >= self.max_connections {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS_PER_UID ({}) must be strictly below \
                 FERRUM_MESH_WORKLOAD_API_MAX_CONNECTIONS ({}); at or above it one peer UID may \
                 hold the whole pool and no other workload on the node can obtain or renew an \
                 identity",
                self.max_connections_per_uid, self.max_connections
            )));
        }
        // The same fair-share rule, one layer up. A per-UID RPC quota at or
        // above the service-wide ceiling lets one peer UID occupy every RPC
        // permit — and because the bundle RPCs require only the mandatory
        // metadata header, doing so costs an attacker no attestation and no
        // entitlement. Every other workload's SVID renewal is then shed.
        if self.max_concurrent_rpcs_per_uid >= self.max_concurrent_rpcs {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS_PER_UID ({}) must be strictly below \
                 FERRUM_MESH_WORKLOAD_API_MAX_CONCURRENT_RPCS ({}); at or above it one peer UID \
                 may hold every concurrent RPC permit and no other workload on the node can \
                 obtain or renew an identity",
                self.max_concurrent_rpcs_per_uid, self.max_concurrent_rpcs
            )));
        }
        if self.idle_timeout <= self.initial_connection_timeout {
            return Err(WorkloadApiListenerError::Admission(format!(
                "FERRUM_MESH_WORKLOAD_API_IDLE_TIMEOUT_SECONDS ({}s) must be greater than \
                 FERRUM_MESH_WORKLOAD_API_INITIAL_CONNECTION_TIMEOUT_SECONDS ({}s); an idle \
                 deadline at or below the initial one closes established connections on the \
                 same schedule as connections that never spoke",
                self.idle_timeout.as_secs(),
                self.initial_connection_timeout.as_secs()
            )));
        }
        Ok(())
    }

    /// This configuration with every hard ceiling applied.
    ///
    /// The runtime belt to `validate`'s braces: whatever the admission layer is
    /// handed, it enforces at most the ceiling. A zero is raised to a finite
    /// floor for the same reason — the admission layer has no representation for
    /// "unbounded".
    ///
    /// The fair-share invariant survives here too, which is the whole point of
    /// the belt: the total is floored at [`MIN_MAX_CONNECTIONS`] and the per-UID
    /// quota is capped at `max_connections - 1`, so no input — `0`, `1`, or a
    /// value far over either ceiling — can produce a quota equal to the global
    /// ceiling and hand one UID the entire pool. The RPC pair is clamped by the
    /// identical rule ([`MIN_MAX_CONCURRENT_RPCS`], then
    /// `max_concurrent_rpcs - 1`), because a per-UID RPC quota equal to the
    /// service-wide ceiling is the same denial of identity service one level up.
    pub fn clamped(&self) -> Self {
        let max_connections = self
            .max_connections
            .clamp(MIN_MAX_CONNECTIONS, MAX_CONNECTIONS_CEILING);
        let max_concurrent_rpcs = self
            .max_concurrent_rpcs
            .clamp(MIN_MAX_CONCURRENT_RPCS, MAX_CONCURRENT_RPCS_CEILING);
        Self {
            max_connections,
            max_connections_per_uid: self
                .max_connections_per_uid
                .clamp(1, MAX_CONNECTIONS_PER_UID_CEILING.min(max_connections - 1)),
            max_concurrent_streams: self
                .max_concurrent_streams
                .clamp(1, MAX_CONCURRENT_STREAMS_CEILING),
            max_concurrent_rpcs,
            max_concurrent_rpcs_per_uid: self.max_concurrent_rpcs_per_uid.clamp(
                1,
                MAX_CONCURRENT_RPCS_PER_UID_CEILING.min(max_concurrent_rpcs - 1),
            ),
            initial_connection_timeout: clamp_duration(
                self.initial_connection_timeout,
                INITIAL_CONNECTION_TIMEOUT_CEILING,
            ),
            idle_timeout: clamp_duration(self.idle_timeout, IDLE_TIMEOUT_CEILING),
            shutdown_grace: clamp_duration(self.shutdown_grace, SHUTDOWN_GRACE_CEILING),
        }
    }

    /// HTTP/2 keepalive interval derived from the idle deadline.
    ///
    /// A third of the deadline, so a responsive peer refreshes it twice over
    /// before it can expire, floored so a small deadline does not turn into a
    /// ping storm.
    pub fn keepalive_interval(&self) -> Duration {
        let derived = self.idle_timeout / 3;
        derived.max(Duration::from_secs(1))
    }

    /// How long a keepalive PING may go unanswered before HTTP/2 closes the
    /// connection itself. Kept strictly below the idle deadline so the protocol
    /// notices a dead peer at least as early as the watchdog does.
    pub fn keepalive_timeout(&self) -> Duration {
        self.keepalive_interval()
            .min(Duration::from_secs(20))
            .max(Duration::from_secs(1))
    }
}

fn clamp_duration(value: Duration, ceiling: Duration) -> Duration {
    value.clamp(Duration::from_secs(1), ceiling)
}

fn check_range(
    setting: &str,
    value: usize,
    ceiling: usize,
) -> Result<(), WorkloadApiListenerError> {
    if value == 0 {
        return Err(WorkloadApiListenerError::Admission(format!(
            "{setting} must be at least 1; `0` is not a disabled spelling, because an unbounded \
             Workload API transport lets one local process deny identity issuance to every other \
             workload on the node"
        )));
    }
    if value > ceiling {
        return Err(WorkloadApiListenerError::Admission(format!(
            "{setting} ({value}) exceeds the hard safety ceiling of {ceiling}"
        )));
    }
    Ok(())
}

fn check_duration(
    setting: &str,
    value: Duration,
    ceiling: Duration,
) -> Result<(), WorkloadApiListenerError> {
    check_range(
        setting,
        value.as_secs() as usize,
        ceiling.as_secs() as usize,
    )
}

/// High bit of the packed read word: set once a byte has been read from the
/// peer.
const FIRST_READ_BIT: u64 = 1 << 63;

/// The remaining 63 bits hold milliseconds since [`ConnectionActivity::base`].
/// 63 bits of milliseconds is ~292 million years, so the saturation below is a
/// formality rather than a reachable case.
const READ_MILLIS_MASK: u64 = FIRST_READ_BIT - 1;

/// What a watchdog observed about one connection at a single instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivitySnapshot {
    /// Whether any byte has ever been read from the peer. Selects which of the
    /// two deadlines applies.
    pub saw_first_read: bool,
    /// Time since the last byte read from the peer, or since admission when
    /// there has not been one.
    pub since_last_read: Duration,
}

/// Shared per-connection state the watchdog and the I/O wrapper both hold.
///
/// The liveness half is **one** atomic word, not two. Split `saw_first_read` and
/// `last_read_millis` atomics can be observed incoherently on a weakly ordered
/// CPU: a watchdog could see "the peer has spoken" without the timestamp that
/// says *when*, evaluate the long idle deadline against a stale `0`, and close a
/// connection that is actively being read. Packing the flag into the high bit of
/// the timestamp makes the pair indivisible by construction, and the update is a
/// `fetch_max` — the encoded word is monotonically non-decreasing (the flag only
/// ever goes `0 -> 1` and the timestamp only ever grows), so concurrent reads
/// can never move the deadline backwards either.
#[derive(Debug)]
pub struct ConnectionActivity {
    /// Set once the connection has been force-closed. Every subsequent I/O poll
    /// fails, which is what actually ends the connection.
    closed: AtomicBool,
    /// `FIRST_READ_BIT | milliseconds-since-base-of-the-last-read`.
    read_state: AtomicU64,
    /// Monotonic base for the packed timestamp.
    base: Instant,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

impl Default for ConnectionActivity {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionActivity {
    /// Fresh state for a connection admitted now.
    pub fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            read_state: AtomicU64::new(0),
            base: Instant::now(),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }
    }

    fn now_millis(&self) -> u64 {
        self.base
            .elapsed()
            .as_millis()
            .min(u128::from(READ_MILLIS_MASK)) as u64
    }

    /// Record a byte read from the peer, refreshing the idle deadline.
    ///
    /// `fetch_max` rather than a store: two threads reading concurrently must
    /// not be able to publish an older timestamp last, and the first-read flag
    /// must not be able to be cleared by a racing update that read the clock a
    /// moment earlier.
    pub fn mark_read(&self) {
        let encoded = FIRST_READ_BIT | self.now_millis();
        self.read_state.fetch_max(encoded, Ordering::AcqRel);
    }

    /// The first-read flag and the idle age, read coherently from one word.
    pub fn snapshot(&self) -> ActivitySnapshot {
        let raw = self.read_state.load(Ordering::Acquire);
        ActivitySnapshot {
            saw_first_read: raw & FIRST_READ_BIT != 0,
            since_last_read: Duration::from_millis(
                self.now_millis().saturating_sub(raw & READ_MILLIS_MASK),
            ),
        }
    }

    /// Whether the connection has been force-closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Flip the flag and wake whichever half is parked, so the close is observed
    /// on the next poll rather than whenever the peer happens to write next.
    ///
    /// Returns `true` for the caller that actually performed the close, so the
    /// close is counted exactly once however many paths reach it.
    pub fn force_close(&self) -> bool {
        if self.closed.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.read_waker.wake();
        self.write_waker.wake();
        true
    }
}

/// The permit an admitted connection owns for its exact lifetime.
///
/// Both halves of the accounting are released in `Drop`, which is the whole
/// point: there is no close path — clean, error, cancelled, or panicking — that
/// can return the connection object to the allocator without also returning its
/// capacity.
pub struct ConnectionPermit {
    _total: OwnedSemaphorePermit,
    per_uid: PerUidCounts,
    uid: u32,
}

impl std::fmt::Debug for ConnectionPermit {
    /// Deliberately **non-identifying**, and hand-written rather than derived.
    ///
    /// A derived `Debug` renders `uid` — a kernel-attested principal identifier
    /// — and, through the `Arc<Mutex<HashMap<..>>>`, the live per-UID map of
    /// *every* peer currently connected. `{:?}` on a permit inside an unrelated
    /// diagnostic would then disclose the node's whole Workload API client
    /// census, which is exactly what the metric-label and log rules forbid. The
    /// same discipline applies to [`RpcPermit`] and to the two admission gates.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPermit").finish_non_exhaustive()
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        release_uid(&self.per_uid, self.uid);
        mesh_metrics::decrement_workload_api_active_connections();
    }
}

/// Live per-UID occupancy for one accounting dimension.
///
/// A plain map behind a `Mutex` on purpose: every critical section below is a
/// lookup and an integer update with no `.await` in it, and the map is bounded
/// by the number of UIDs currently *holding* a permit rather than by the number
/// that have ever asked for one.
type PerUidCounts = Arc<Mutex<HashMap<u32, usize>>>;

/// Which half of a two-level admission decision refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaRefusal {
    /// The peer UID is at its own quota; no global capacity was taken.
    PerUid,
    /// The shared ceiling is saturated.
    Total,
}

/// Take one unit of a two-level (per-UID quota, then shared ceiling) bound.
///
/// **One decision, one lock**, and the order is load-bearing rather than
/// incidental: the per-UID quota is judged *before* any shared capacity is
/// taken, and the shared permit and the per-UID increment are published
/// together, so an over-quota caller can never hold a shared slot even
/// transiently.
///
/// Taking the shared permit first — the obvious ordering — is a fair-share
/// defect. A burst of concurrent reservations from an already-saturated UID
/// would each acquire a shared permit and then queue on this lock, and for as
/// long as that queue drained the shared pool would read as empty and a
/// *different*, innocent UID would be refused for the wrong reason. The per-UID
/// bound exists to make that impossible.
///
/// Nothing inside the critical section can block: `try_acquire_owned` is
/// non-blocking by definition and there is no `.await` here, so the lock is
/// held for a few instructions and never across a suspension point. A refused
/// UID leaves **no** map entry behind, so a probing flood cannot grow the map.
fn reserve_per_uid_then_total(
    per_uid: &PerUidCounts,
    total: &Arc<Semaphore>,
    uid: u32,
    max_per_uid: usize,
) -> Result<OwnedSemaphorePermit, QuotaRefusal> {
    let mut guard = match per_uid.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let current = guard.get(&uid).copied().unwrap_or(0);
    if current >= max_per_uid {
        return Err(QuotaRefusal::PerUid);
    }
    let permit = match Arc::clone(total).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(QuotaRefusal::Total),
    };
    guard.insert(uid, current + 1);
    Ok(permit)
}

fn release_uid(per_uid: &PerUidCounts, uid: u32) {
    // A poisoned lock would mean a panic inside the few statements below, none
    // of which can panic; recovering the guard keeps a single unrelated panic
    // from wedging admission for the whole process.
    let mut guard = match per_uid.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(count) = guard.get_mut(&uid) {
        *count = count.saturating_sub(1);
        // Removed at zero so the map is bounded by *live* peers rather than by
        // every uid that has ever connected.
        if *count == 0 {
            guard.remove(&uid);
        }
    }
}

/// The RPC permit, held for an RPC's full lifetime — including a streaming
/// RPC's response stream, which is where a Workload API caller actually
/// consumes resources.
///
/// It carries **both** halves of the two-level bound: the service-wide permit
/// is released when `_total` drops, and the peer UID's own occupancy is
/// decremented in `Drop`. Exactly once, on every path — a clean end, a client
/// disconnect, a cancelled task, or a panic unwind — because the release is
/// tied to the object's lifetime rather than to any code path.
pub struct RpcPermit {
    _total: OwnedSemaphorePermit,
    per_uid: PerUidCounts,
    uid: u32,
}

impl std::fmt::Debug for RpcPermit {
    /// Non-identifying for the same reason as [`ConnectionPermit`]'s: the peer
    /// UID and the live per-UID occupancy map are both credential-adjacent and
    /// belong in no diagnostic rendering.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcPermit").finish_non_exhaustive()
    }
}

impl Drop for RpcPermit {
    fn drop(&mut self) {
        release_uid(&self.per_uid, self.uid);
        mesh_metrics::decrement_workload_api_active_rpcs();
    }
}

/// Non-blocking RPC admission: a service-wide ceiling and a per-peer-UID quota,
/// taken as one decision before any RPC work begins.
///
/// The transport gate above bounds connections and per-connection streams; this
/// bounds their *product*, and bounds it **per principal** as well as in total.
/// Without the per-UID half, one socket-group UID at the default limits may hold
/// `32 × 64 = 2048` streams and occupy every service-wide permit — and the
/// bundle RPCs need only the mandatory metadata header to do it, so the attack
/// requires neither attestation nor entitlement. The result would be that no
/// other workload on the node can renew its SVID.
#[derive(Clone)]
pub struct RpcAdmission {
    total: Arc<Semaphore>,
    per_uid: PerUidCounts,
    max_concurrent_rpcs: usize,
    max_concurrent_rpcs_per_uid: usize,
}

impl std::fmt::Debug for RpcAdmission {
    /// Limits and live occupancy only — never the per-UID map, for the same
    /// reason [`ConnectionAdmission`]'s rendering withholds it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcAdmission")
            .field("max_concurrent_rpcs", &self.max_concurrent_rpcs)
            .field(
                "max_concurrent_rpcs_per_uid",
                &self.max_concurrent_rpcs_per_uid,
            )
            .field("available", &self.total.available_permits())
            .finish_non_exhaustive()
    }
}

impl RpcAdmission {
    /// Build an RPC gate from already-[`WorkloadApiAdmissionConfig::clamped`]
    /// limits, clamping again defensively so no caller can construct one that
    /// exceeds a ceiling or hands a single UID every permit.
    pub fn new(limits: &WorkloadApiAdmissionConfig) -> Self {
        let limits = limits.clamped();
        Self {
            total: Arc::new(Semaphore::new(limits.max_concurrent_rpcs)),
            per_uid: Arc::new(Mutex::new(HashMap::new())),
            max_concurrent_rpcs: limits.max_concurrent_rpcs,
            max_concurrent_rpcs_per_uid: limits.max_concurrent_rpcs_per_uid,
        }
    }

    /// The effective service-wide ceiling.
    pub fn max_concurrent_rpcs(&self) -> usize {
        self.max_concurrent_rpcs
    }

    /// The effective per-peer-UID quota.
    pub fn max_concurrent_rpcs_per_uid(&self) -> usize {
        self.max_concurrent_rpcs_per_uid
    }

    /// RPCs currently admitted, across every peer.
    pub fn active_rpcs(&self) -> usize {
        self.max_concurrent_rpcs
            .saturating_sub(self.total.available_permits())
    }

    /// Reserve one RPC for `uid`, or return `None` when either bound is
    /// saturated.
    ///
    /// **Never waits.** An over-limit caller is refused immediately so it cannot
    /// grow a queue of pending identity requests behind the ceiling — the queue
    /// is itself the resource exhaustion this exists to prevent, and an identity
    /// request served far too late is worse than a refusal the client can retry.
    ///
    /// Public so the policy — service ceiling, per-UID quota, fair availability
    /// to a second UID, release on drop — can be exercised directly, which a
    /// single-uid test process cannot do through real sockets.
    pub fn reserve(&self, uid: u32) -> Option<RpcPermit> {
        match reserve_per_uid_then_total(
            &self.per_uid,
            &self.total,
            uid,
            self.max_concurrent_rpcs_per_uid,
        ) {
            Ok(total) => {
                mesh_metrics::increment_workload_api_active_rpcs();
                Some(RpcPermit {
                    _total: total,
                    per_uid: Arc::clone(&self.per_uid),
                    uid,
                })
            }
            Err(refusal) => {
                mesh_metrics::increment_workload_api_rpc_rejected();
                // Fixed context only: a limit the operator configured, and which
                // of the two bounds refused. Never the peer UID.
                match refusal {
                    QuotaRefusal::PerUid => debug!(
                        limit = self.max_concurrent_rpcs_per_uid,
                        "SPIFFE Workload API RPC shed: peer UID is at its concurrent-RPC quota"
                    ),
                    QuotaRefusal::Total => debug!(
                        limit = self.max_concurrent_rpcs,
                        "SPIFFE Workload API RPC shed: service-wide concurrency ceiling saturated"
                    ),
                }
                None
            }
        }
    }
}

pin_project! {
    /// A response stream that keeps its RPC permit alive until the stream ends
    /// or is dropped.
    ///
    /// Attaching the permit to the *stream* rather than to the RPC method's
    /// future is deliberate: `fetch_x509svid` returns as soon as the first
    /// response is staged, while the resources the caller is actually holding —
    /// the producer task, the rotation subscription, the pending private-key
    /// slot — live for as long as the stream does.
    ///
    /// The inner stream is stored **inline** and pin-projected rather than
    /// boxed. Every call site immediately boxes the wrapper for tonic's
    /// `Pin<Box<dyn Stream>>` associated type, so an inner `Pin<Box<S>>` was a
    /// second heap allocation and a second pointer indirection on every
    /// admitted RPC, for nothing.
    pub struct PermitStream<S> {
        #[pin]
        inner: S,
        _permit: Option<RpcPermit>,
    }
}

impl<S> PermitStream<S> {
    pub fn new(inner: S, permit: Option<RpcPermit>) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<S: Stream> Stream for PermitStream<S> {
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

/// Non-blocking connection admission shared by the accept loop.
#[derive(Clone)]
pub struct ConnectionAdmission {
    limits: WorkloadApiAdmissionConfig,
    total: Arc<Semaphore>,
    per_uid: PerUidCounts,
    force_close: watch::Receiver<bool>,
    /// Retained only by [`ConnectionAdmission::detached`], and cloned into every
    /// watchdog it starts.
    ///
    /// A watchdog treats a *closed* force-close channel as the shutdown it
    /// precedes, which is correct when a real listener's sender goes away — but
    /// a detached gate has no listener, and dropping the sender at the end of
    /// the constructor would force-close every connection the gate ever admits
    /// the instant its watchdog first polled. Holding a sender for as long as
    /// any watchdog exists means a detached gate never force-closes, which is
    /// exactly what its contract says.
    force_close_retainer: Option<Arc<watch::Sender<bool>>>,
}

impl std::fmt::Debug for ConnectionAdmission {
    /// Limits and live occupancy only. Never the per-UID map: a peer UID is a
    /// principal identifier and does not belong in a diagnostic rendering any
    /// more than it belongs in a metric label.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionAdmission")
            .field("limits", &self.limits)
            .field("available", &self.total.available_permits())
            .finish_non_exhaustive()
    }
}

impl ConnectionAdmission {
    /// Build an admission gate. The limits are [`WorkloadApiAdmissionConfig::clamped`]
    /// on the way in, so no caller can construct one that exceeds a ceiling.
    pub fn new(limits: WorkloadApiAdmissionConfig, force_close: watch::Receiver<bool>) -> Self {
        let limits = limits.clamped();
        Self {
            total: Arc::new(Semaphore::new(limits.max_connections)),
            per_uid: Arc::new(Mutex::new(HashMap::new())),
            limits,
            force_close,
            force_close_retainer: None,
        }
    }

    /// Build an admission gate with no force-close channel attached.
    ///
    /// For callers (and tests) that exercise the accounting policy without a
    /// listener lifecycle. The returned gate **never** force-closes: the sender
    /// is retained by the gate and by every watchdog it starts, so the channel
    /// it is signalled on stays open for as long as anything could observe it.
    /// Dropping it here instead would close the channel immediately, and a
    /// closed channel is precisely the shutdown signal the watchdog acts on —
    /// so a real socket admitted through a detached gate would be force-closed
    /// because its constructor returned.
    pub fn detached(limits: WorkloadApiAdmissionConfig) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            force_close_retainer: Some(Arc::new(tx)),
            ..Self::new(limits, rx)
        }
    }

    /// The effective (clamped) limits this gate enforces.
    pub fn limits(&self) -> &WorkloadApiAdmissionConfig {
        &self.limits
    }

    /// Connections currently admitted.
    pub fn active_connections(&self) -> usize {
        self.limits
            .max_connections
            .saturating_sub(self.total.available_permits())
    }

    /// Reserve capacity for one connection from `uid`, or return `None` when
    /// either ceiling is saturated.
    ///
    /// Never waits. A caller over the limit is told so immediately and the
    /// socket is closed, so there is no queue of would-be connections holding
    /// descriptors behind the ceiling — the queue *is* the resource exhaustion
    /// this exists to prevent.
    ///
    /// Public so the *policy* — total ceiling, per-UID quota, fair availability
    /// to a second UID, release on drop — can be exercised directly, which a
    /// single-uid test process cannot do through real sockets.
    pub fn reserve(&self, uid: u32) -> Option<ConnectionPermit> {
        // One decision, one lock, per-UID quota first — see
        // `reserve_per_uid_then_total`, which owns that ordering invariant for
        // both this gate and the RPC gate.
        let permit = match reserve_per_uid_then_total(
            &self.per_uid,
            &self.total,
            uid,
            self.limits.max_connections_per_uid,
        ) {
            Ok(permit) => permit,
            Err(QuotaRefusal::PerUid) => {
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::MAX_CONNECTIONS_PER_UID,
                );
                debug!(
                    limit = self.limits.max_connections_per_uid,
                    "SPIFFE Workload API connection refused: peer UID is at its connection quota"
                );
                return None;
            }
            Err(QuotaRefusal::Total) => {
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::MAX_CONNECTIONS,
                );
                debug!(
                    limit = self.limits.max_connections,
                    "SPIFFE Workload API connection refused: total connection ceiling saturated"
                );
                return None;
            }
        };

        mesh_metrics::increment_workload_api_active_connections();
        Some(ConnectionPermit {
            _total: permit,
            per_uid: Arc::clone(&self.per_uid),
            uid,
        })
    }

    /// Start a connection watchdog against fresh activity state.
    ///
    /// The socketless half of `Self::admit`: it returns the shared state the
    /// I/O wrapper marks reads on, together with the guard whose drop **cancels**
    /// the watchdog task. Public because the lifetime contract — prompt
    /// cancellation when the connection goes away, a deadline close counted
    /// exactly once, a detached gate that never force-closes — is not otherwise
    /// observable without waiting out a wall-clock tick against a real socket.
    ///
    /// Must be called from within a Tokio runtime, as every accept-loop path is.
    pub fn start_watchdog(&self) -> (Arc<ConnectionActivity>, ConnectionWatchdog) {
        let activity = Arc::new(ConnectionActivity::new());
        let watchdog = spawn_connection_watchdog(
            Arc::downgrade(&activity),
            self.limits.clone(),
            self.force_close.clone(),
            self.force_close_retainer.clone(),
        );
        (activity, watchdog)
    }

    /// Admit an accepted socket, or refuse it and close it.
    ///
    /// Runs entirely before the socket is handed to tonic, so a refused peer
    /// costs one `accept(2)` and one `close(2)` and never an HTTP/2 connection,
    /// a service clone, or a producer task.
    #[cfg(unix)]
    pub fn admit(&self, stream: tokio::net::UnixStream) -> Option<AdmittedUnixStream> {
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(error) => {
                // Fail closed. An unattributable connection cannot be charged to
                // a quota, so admitting it would be a hole in the per-UID bound
                // rather than a lenient default.
                mesh_metrics::increment_workload_api_connection_rejected(
                    reject_reason::PEER_CREDENTIALS,
                );
                warn!(
                    error = %error,
                    "SPIFFE Workload API connection refused: kernel peer credentials unavailable"
                );
                return None;
            }
        };
        self.admit_io(uid, stream)
    }

    /// Charge `uid` for one connection and wrap `stream` in the permit- and
    /// watchdog-owning transport.
    ///
    /// The transport half of `Self::admit`, separated from the
    /// `SO_PEERCRED` read because the principal is not always established the
    /// same way — and because the poll-level behaviour of the wrapper (waking a
    /// parked write on force close, failing every subsequent poll) is a property
    /// of the wrapper rather than of Unix sockets, so it is exercised against an
    /// inner I/O whose readiness the caller controls.
    pub fn admit_io<S>(&self, uid: u32, stream: S) -> Option<AdmittedStream<S>> {
        let permit = self.reserve(uid)?;
        let (activity, watchdog) = self.start_watchdog();
        Some(AdmittedStream {
            inner: stream,
            activity,
            _watchdog: watchdog,
            _permit: permit,
        })
    }
}

/// A running connection watchdog, owned by the connection it watches.
///
/// Dropping it **aborts** the task. That is what makes the watchdog's lifetime
/// connection-owned rather than tick-owned: connection concurrency is bounded by
/// the admission ceiling, but connection *churn* is not, so a watchdog that
/// merely noticed its `Weak` had expired on the next tick would leave
/// arbitrarily many detached tasks asleep for up to one watchdog tick each.
/// The close paths stay exactly-once regardless: a deadline or force close is
/// published through [`ConnectionActivity::force_close`], whose swap admits one
/// winner, and the counter is incremented only by that winner.
#[derive(Debug)]
pub struct ConnectionWatchdog {
    handle: tokio::task::JoinHandle<()>,
}

impl ConnectionWatchdog {
    /// A handle that observes this watchdog's cancellation after the guard —
    /// and therefore the connection — has been dropped.
    pub fn abort_handle(&self) -> tokio::task::AbortHandle {
        self.handle.abort_handle()
    }

    /// Whether the watchdog task has already finished.
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

impl Drop for ConnectionWatchdog {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// How often one connection's watchdog wakes, derived from the deadlines it
/// enforces.
///
/// The derivation is exactly
/// `clamp(min(initial_connection_timeout, idle_timeout) / WATCHDOG_TICK_DIVISOR,
/// WATCHDOG_MIN_TICK, WATCHDOG_MAX_TICK)`, and each of the three parts is
/// load-bearing:
///
/// - **the shorter of the two deadlines**, because a connection that has not
///   spoken yet is judged against the initial one and a connection that has is
///   judged against the idle one, and the same task enforces both;
/// - **a quarter of it**, so detection latency is a bounded *fraction* of the
///   deadline rather than a fixed interval. At the shipped defaults
///   (`min(10s, 900s) / 4`) that is a 2.5-second tick, so a deadline is noticed
///   within 2.5 seconds of expiring — while a fixed one-second tick would have
///   woken every admitted connection once a second regardless, which at the
///   4096-connection hard ceiling is 4096 wakeups a second to enforce deadlines
///   measured in seconds and minutes. The tick is per connection, so the cost of
///   the floor is multiplied by the connection count; the accuracy of the
///   deadline is not affected either way, because expiry is evaluated against a
///   monotonic clock rather than counted in ticks;
/// - **the floor and the ceiling**, so a one-second compressed test deadline
///   still ticks fast enough to be observable (250ms) without a sub-25ms
///   deadline turning the watchdog into a busy loop, and a
///   deliberately long idle deadline does not stretch detection past
///   [`WATCHDOG_MAX_TICK`].
pub fn watchdog_tick(limits: &WorkloadApiAdmissionConfig) -> Duration {
    let deadline = limits.initial_connection_timeout.min(limits.idle_timeout);
    (deadline / WATCHDOG_TICK_DIVISOR).clamp(WATCHDOG_MIN_TICK, WATCHDOG_MAX_TICK)
}

/// Watch a single connection's deadlines and the listener's force-close signal.
///
/// Holds only a [`Weak`] reference, so it can never keep the connection alive,
/// and its [`ConnectionWatchdog`] guard cancels it the moment the connection is
/// dropped. The number of live watchdogs is therefore bounded by the number of
/// live connections, which is bounded by the connection ceiling.
fn spawn_connection_watchdog(
    activity: Weak<ConnectionActivity>,
    limits: WorkloadApiAdmissionConfig,
    mut force_close: watch::Receiver<bool>,
    force_close_retainer: Option<Arc<watch::Sender<bool>>>,
) -> ConnectionWatchdog {
    let tick = watchdog_tick(&limits);

    let handle = tokio::spawn(async move {
        // Held for the task's whole life. In detached mode this is what keeps
        // the force-close channel open, so `changed()` never resolves with the
        // `Err` the loop below reads as shutdown.
        let _force_close_retainer = force_close_retainer;
        loop {
            let forced = tokio::select! {
                _ = tokio::time::sleep(tick) => false,
                changed = force_close.changed() => {
                    // A closed channel means the listener is gone; treat it like
                    // the force-close it precedes rather than parking forever.
                    changed.is_err() || *force_close.borrow()
                }
            };
            let Some(activity) = activity.upgrade() else {
                return;
            };
            if activity.is_closed() {
                return;
            }
            if forced {
                if activity.force_close() {
                    mesh_metrics::increment_workload_api_connection_closed(
                        close_reason::SHUTDOWN_DEADLINE,
                    );
                }
                return;
            }
            // One coherent observation of the packed liveness word: the flag
            // that selects the deadline and the age it is compared against are
            // read together, so a connection being actively read can never be
            // judged against a timestamp that predates its first read.
            let observed = activity.snapshot();
            let (deadline, reason) = if observed.saw_first_read {
                (limits.idle_timeout, close_reason::IDLE_TIMEOUT)
            } else {
                (
                    limits.initial_connection_timeout,
                    close_reason::INITIAL_TIMEOUT,
                )
            };
            if observed.since_last_read >= deadline {
                if activity.force_close() {
                    mesh_metrics::increment_workload_api_connection_closed(reason);
                    debug!(
                        reason,
                        deadline_secs = deadline.as_secs(),
                        "SPIFFE Workload API connection closed on its transport deadline"
                    );
                }
                return;
            }
        }
    });
    ConnectionWatchdog { handle }
}

/// An accepted Workload API connection that owns its admission permit and its
/// watchdog.
///
/// Both are private fields with no accessor precisely so they cannot be
/// separated from the connection: dropping the stream is the only way to end the
/// connection, and it is therefore also the only way to release capacity and the
/// only way to cancel the watchdog.
pub struct AdmittedStream<S> {
    inner: S,
    activity: Arc<ConnectionActivity>,
    _watchdog: ConnectionWatchdog,
    _permit: ConnectionPermit,
}

/// The accepted Workload API connection as the listener serves it.
#[cfg(unix)]
pub type AdmittedUnixStream = AdmittedStream<tokio::net::UnixStream>;

impl<S> AdmittedStream<S> {
    /// The shared per-connection state the watchdog publishes closes through.
    ///
    /// Read-only in effect for the transport: the wrapper marks reads on it and
    /// consults [`ConnectionActivity::is_closed`], and a caller can observe the
    /// same state — but the permit and watchdog remain inaccessible, so the
    /// connection's lifetime accounting cannot be detached from the connection.
    pub fn activity(&self) -> &Arc<ConnectionActivity> {
        &self.activity
    }
}

impl<S> std::fmt::Debug for AdmittedStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedStream").finish_non_exhaustive()
    }
}

fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "SPIFFE Workload API connection closed by the listener's transport admission policy",
    )
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for AdmittedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.activity.mark_read();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                this.activity.read_waker.register(cx.waker());
                // Re-checked after registering: a force-close that landed
                // between the check above and the registration would otherwise
                // have woken nobody and the connection would park until the peer
                // spoke again — which, for the idle peer this deadline exists
                // for, is never.
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for AdmittedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
            other => other,
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
            other => other,
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    /// Same register-then-recheck discipline as the write polls, and for the
    /// same reason: a connection parked in `poll_flush` on an inner socket whose
    /// buffer is full is exactly a connection the force close has to reach, and
    /// delegating a bare `Pending` here would register only the *inner*
    /// socket's waker — which nothing wakes when the peer has stopped reading.
    /// The bounded settle at shutdown would then have to wait out the settle
    /// window instead of being observed immediately.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            return Poll::Ready(Err(aborted()));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                if this.activity.is_closed() {
                    return Poll::Ready(Err(aborted()));
                }
                Poll::Pending
            }
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.activity.is_closed() {
            // Already torn down; report success so the caller's shutdown path
            // completes rather than looping on an error it cannot act on.
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Pending => {
                this.activity.write_waker.register(cx.waker());
                // The post-close result is deliberately the same `Ok(())` the
                // fast path above returns: a shutdown racing the force close
                // must complete, not fail, or the caller loops on an error it
                // cannot act on.
                if this.activity.is_closed() {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            }
            other => other,
        }
    }
}

/// Preserve the kernel-attested peer credentials tonic exposes to the service.
///
/// Delegated to the wrapped `UnixStream` rather than reconstructed: `PeerInfo`
/// extraction and every `SO_PEERCRED` attestor read `UdsConnectInfo`, so the
/// admission wrapper must be transparent to them or it would silently disable
/// peer-credential attestation.
#[cfg(unix)]
impl tonic::transport::server::Connected for AdmittedUnixStream {
    type ConnectInfo = tonic::transport::server::UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

/// The channel a **fatal** accept failure is published on, as a handle.
///
/// A fatal accept is not just "stop yielding connections". Ending the incoming
/// stream is, to tonic, indistinguishable from a *graceful* end of input: with a
/// shutdown future attached, `serve_with_incoming_shutdown` broadcasts graceful
/// shutdown and then waits for every established connection to finish on its
/// own. A Workload API rotation stream is designed to stay open indefinitely, so
/// that wait has no bound — the serve future would never complete, the exit
/// guard would never publish termination, and mesh mode would never learn its
/// identity surface is gone.
///
/// So the fatal condition is published *explicitly* instead. The outer serve
/// task selects on this signal and runs the same bounded drain a requested
/// shutdown runs: the configured graceful budget, then a force close of whatever
/// is left, then a bounded settle, then socket cleanup and termination. The
/// accept loop watches it too, so admission stops at the same instant however
/// the signal was raised.
///
/// Cloneable and shared rather than a bare `watch::Sender`, because several
/// holders — the accept loop, the serve task, and the listener handle — must all
/// keep the channel open: a closed channel is not a fatal accept, and treating
/// it as one would terminate a healthy listener the moment one holder went away.
#[derive(Debug, Clone)]
pub struct FatalAcceptSignal {
    tx: Arc<watch::Sender<bool>>,
}

impl FatalAcceptSignal {
    /// A fresh, unraised signal together with its first observer.
    pub fn new() -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = watch::channel(false);
        (Self { tx: Arc::new(tx) }, rx)
    }

    /// Publish the fatal accept condition.
    ///
    /// `send_replace` rather than `send`: publication must not depend on a
    /// receiver currently existing, or a fatal accept raced against a dropped
    /// observer would be silently lost.
    pub fn raise(&self) {
        self.tx.send_replace(true);
    }

    /// Whether the fatal condition has been published.
    pub fn is_raised(&self) -> bool {
        *self.tx.borrow()
    }

    /// A new observer of this signal.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }
}

/// The accept loop, as a stream of admitted connections.
///
/// Yields only admitted connections — a refused or failed accept never becomes
/// a stream item, so the transport below it cannot observe an error it would
/// react to by tearing down the listener. Yielding `Err` would not help either:
/// tonic logs an incoming-item error and keeps serving, so an error item is not
/// a termination path at all.
///
/// Ends immediately when `stop` flips, so shutdown stops admission at once
/// rather than admitting one more connection per accept the runtime happens to
/// have already completed. On a **fatal** listener error it raises `fatal`
/// *before* ending, so a socket that can never accept again enters the bounded
/// drain in [`super::listener`] — graceful budget, force close, settle — rather
/// than leaving the serve future waiting on connections that never end. The loop
/// also watches `fatal`, so admission stops at once however the signal was
/// raised.
#[cfg(unix)]
pub fn admission_stream(
    listener: tokio::net::UnixListener,
    admission: ConnectionAdmission,
    stop: watch::Receiver<bool>,
    fatal: FatalAcceptSignal,
) -> impl Stream<Item = Result<AdmittedUnixStream, io::Error>> + Send {
    struct AcceptState {
        listener: tokio::net::UnixListener,
        admission: ConnectionAdmission,
        stop: watch::Receiver<bool>,
        fatal_rx: watch::Receiver<bool>,
        fatal: FatalAcceptSignal,
        retry: AcceptRetryPolicy,
    }

    let fatal_rx = fatal.subscribe();
    futures_util::stream::unfold(
        AcceptState {
            listener,
            admission,
            stop,
            fatal_rx,
            fatal,
            retry: AcceptRetryPolicy::new(),
        },
        |mut state| async move {
            loop {
                if *state.stop.borrow() || *state.fatal_rx.borrow() {
                    return None;
                }
                let accepted = tokio::select! {
                    biased;
                    _ = wait_until_set(&mut state.stop) => return None,
                    // `state.fatal` keeps the channel open for as long as this
                    // loop exists, so this arm only ever resolves on a real
                    // publication, never on a dropped sender.
                    _ = wait_until_set(&mut state.fatal_rx) => return None,
                    accepted = state.listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, _addr)) => {
                        if *state.stop.borrow() {
                            // Shutdown was requested while this accept was in
                            // flight. Admission stops at that instant rather
                            // than one connection later, so the bounded drain
                            // never has to cover a peer taken on after the
                            // listener was told to stop.
                            mesh_metrics::increment_workload_api_connection_rejected(
                                reject_reason::SHUTTING_DOWN,
                            );
                            drop(stream);
                            return None;
                        }
                        state.retry.on_accepted();
                        if let Some(admitted) = state.admission.admit(stream) {
                            return Some((Ok(admitted), state));
                        }
                        // Refused: the socket is dropped here, so the peer sees
                        // an immediate EOF instead of a connection that lingers.
                    }
                    Err(error) => {
                        let failure = classify_accept_error(&error);
                        match state.retry.on_error(failure) {
                            AcceptDecision::Terminate => {
                                error!(
                                    error = %error,
                                    "SPIFFE Workload API accept failed fatally; raising the fatal \
                                     accept signal so the listener enters its bounded drain and \
                                     mesh mode observes the loss of the surface"
                                );
                                // Raised *before* the stream ends. Ending it
                                // alone is only a graceful end of input to
                                // tonic, which then waits out every established
                                // connection — and a Workload API rotation
                                // stream never ends on its own.
                                state.fatal.raise();
                                return None;
                            }
                            AcceptDecision::Retry { backoff, log } => {
                                if log {
                                    warn!(
                                        error = %error,
                                        failure = ?failure,
                                        consecutive_failures = state.retry.consecutive_failures(),
                                        backoff_ms = backoff.as_millis() as u64,
                                        "SPIFFE Workload API accept failed; retrying"
                                    );
                                }
                                if backoff.is_zero() {
                                    // Always a suspension point, even with no
                                    // backoff, so a burst of per-connection
                                    // failures can never become a non-yielding
                                    // loop on a runtime worker.
                                    tokio::task::yield_now().await;
                                } else {
                                    tokio::time::sleep(backoff).await;
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// How an `accept(2)` failure should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptFailure {
    /// A per-connection failure an accept loop is expected to retry at once:
    /// the peer went away, or the call was interrupted. The listener is fine.
    Transient,
    /// A condition that may persist until something unrelated changes — a
    /// resource exhaustion, or any errno not positively identified as one of
    /// the other two classes. Retryable, but only behind a bounded backoff.
    Resource,
    /// The listener itself is unusable — a closed or invalid descriptor, a
    /// descriptor that is not a socket, a socket that cannot accept, or an
    /// error with no OS code to reason about. Retrying is a spin that can never
    /// succeed, so admission ends and [`FatalAcceptSignal`] is raised, which is
    /// what actually drives the bounded drain and the serve task's termination
    /// guard. Deliberately a closed list rather than the default arm: this
    /// class costs the node its identity surface.
    Fatal,
}

/// Classify an `accept(2)` failure.
///
/// `Fatal` is deliberately a **short, closed list plus one fail-closed case**,
/// not the default arm. Terminating the accept loop tears down the whole mesh
/// runtime's identity surface, so it is reserved for errors that say the
/// *listener itself* is unusable — a closed or invalid descriptor
/// (`EBADF`/`EINVAL`), a descriptor that is not a socket (`ENOTSOCK`), or a
/// socket that does not implement `accept` (`EOPNOTSUPP`/`ENOTSUP`) — and for
/// an error carrying no OS code at all, which cannot be reasoned about and so
/// surfaces through mesh mode's termination path rather than hiding in a retry
/// loop.
///
/// Every other errno is `Resource`: retryable behind the bounded, doubling
/// backoff. That covers the exhaustion set explicitly, and it is also the right
/// answer for the unenumerated remainder. `EPERM` is the concrete example — a
/// firewall or LSM hook can make `accept(2)` return it *per connection* while
/// the listener stays perfectly valid, so classifying it `Fatal` would let one
/// rejected peer terminate identity service for the whole node. An unknown
/// errno is far more likely to be that shape than a broken descriptor, and the
/// bounded backoff makes being wrong cheap: a persistent condition costs a small
/// fraction of one runtime worker and a rate-limited warning, rather than the
/// surface.
#[cfg(unix)]
pub fn classify_accept_error(error: &io::Error) -> AcceptFailure {
    let Some(code) = error.raw_os_error() else {
        return AcceptFailure::Fatal;
    };
    // Compared rather than matched: several of these constants are equal on
    // Linux (`EAGAIN`/`EWOULDBLOCK`, `ENOTSUP`/`EOPNOTSUPP`), and two equal
    // constants in one match are an unreachable pattern.
    if code == libc::EBADF
        || code == libc::ENOTSOCK
        || code == libc::EINVAL
        || code == libc::EOPNOTSUPP
        || code == libc::ENOTSUP
    {
        return AcceptFailure::Fatal;
    }
    if code == libc::ECONNABORTED
        || code == libc::EINTR
        || code == libc::EAGAIN
        || code == libc::EWOULDBLOCK
        || code == libc::EPROTO
        || code == libc::ECONNRESET
        || code == libc::ETIMEDOUT
    {
        return AcceptFailure::Transient;
    }
    // `EMFILE`/`ENFILE`/`ENOBUFS`/`ENOMEM` and every unenumerated errno alike.
    AcceptFailure::Resource
}

/// What the accept loop should do about one failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptDecision {
    /// Try again after `backoff`, logging this occurrence only when `log`.
    Retry { backoff: Duration, log: bool },
    /// Stop accepting. The accept loop raises [`FatalAcceptSignal`] and then
    /// ends the incoming stream; the signal — not the end of the stream — is
    /// what puts the serve task into its bounded drain.
    Terminate,
}

/// The accept loop's bounded retry and log-rate state machine.
///
/// Separated from the loop so the policy is exercised directly: a state machine
/// driven by injected failure classes is deterministic, while a real listener
/// cannot be made to return `EMFILE` on demand from a test.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptRetryPolicy {
    consecutive: u32,
}

impl AcceptRetryPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// A successful accept clears the run, so an isolated failure never inherits
    /// an old backoff.
    pub fn on_accepted(&mut self) {
        self.consecutive = 0;
    }

    /// Consecutive failures since the last successful accept.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive
    }

    /// Decide what one failure means.
    ///
    /// Backoff doubles from [`ACCEPT_BACKOFF`] and saturates at
    /// [`ACCEPT_MAX_BACKOFF`], so a condition that persists costs a bounded
    /// fraction of one worker. Logging is deliberately *not* per occurrence:
    /// a persistent `EMFILE` retried every second would otherwise emit a warn
    /// per retry for as long as the node stayed exhausted, which is itself a
    /// disk-exhaustion primitive. The first three are logged, then powers of
    /// two, so the run stays visible without flooding.
    pub fn on_error(&mut self, failure: AcceptFailure) -> AcceptDecision {
        if failure == AcceptFailure::Fatal {
            return AcceptDecision::Terminate;
        }
        self.consecutive = self.consecutive.saturating_add(1);
        let attempt = self.consecutive;
        let backoff = if failure == AcceptFailure::Transient && attempt <= TRANSIENT_RETRY_BURST {
            Duration::ZERO
        } else {
            let steps = attempt.saturating_sub(1).min(5);
            ACCEPT_BACKOFF
                .saturating_mul(1u32 << steps)
                .min(ACCEPT_MAX_BACKOFF)
        };
        AcceptDecision::Retry {
            backoff,
            log: attempt <= 3 || attempt.is_power_of_two(),
        }
    }
}

/// Resolve once a `watch::Sender<bool>` has published `true`, or once the sender
/// is gone.
pub(crate) async fn wait_until_set(rx: &mut watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

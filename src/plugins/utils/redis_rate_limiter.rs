//! Shared Redis-backed rate limiting client for plugins.
//!
//! When a rate limiting plugin is configured with `"sync_mode": "redis"`, it uses
//! this shared client to store counters in Redis instead of in-memory DashMaps.
//! This enables centralized rate limiting across multiple data plane instances.
//!
//! # Redis protocol compatibility
//!
//! Uses the standard Redis protocol (RESP), so it works with Redis, Valkey,
//! DragonflyDB, KeyDB, Garnet, or any RESP-compatible server running in
//! **single-endpoint (non-Cluster) topology**.
//!
//! # Topology: Redis Cluster is NOT supported
//!
//! This client builds a plain single-node [`redis::Client`]; the crate's
//! Cluster features are deliberately not enabled, so it cannot follow `MOVED` /
//! `ASK` redirections. Pointing a Redis-backed policy at a Cluster endpoint
//! would make every misdirected command fail, and an enforcement plugin that
//! silently treats those failures as "Redis is down" degrades a distributed
//! security policy into one independent budget per gateway process.
//!
//! The client therefore screens topology instead of hoping for the best:
//!
//! 1. **Proactively**, right after each connection is established, it issues
//!    `INFO CLUSTER` and refuses the connection when the server reports
//!    `cluster_enabled:1` ([`parse_cluster_enabled`]). Servers that do not
//!    implement `INFO` (or omit the field) are not rejected — they fall through
//!    to the reactive screen so ordinary RESP-compatible servers keep working.
//! 2. **Reactively**, any command answered with a Cluster-only error code
//!    (`MOVED`, `ASK`, `CROSSSLOT`, `CLUSTERDOWN`, `TRYAGAIN` — see
//!    [`is_cluster_topology_code`]) marks the endpoint permanently unusable.
//!    Enforcement primitives send `MULTI`/`EXEC` pipelines, so the redirection
//!    usually arrives as a per-command server error inside an aborted
//!    transaction rather than as the outer error's own code
//!    ([`is_cluster_topology_error`]).
//!
//! Clients whose retained record *is* the control
//! (`RedisRateLimitClient::for_replay_authority`, and
//! `RedisRateLimitClient::for_retention_authority` for `request_deduplication`)
//! additionally prove the server will not evict a still-live `SET NX EX`
//! marker. After a usable topology screen they issue bounded `INFO MEMORY` and
//! accept the connection only when `maxmemory` is `0` (no memory limit, so
//! eviction cannot run) or `maxmemory_policy` is `noeviction`. An `allkeys-*`
//! or `volatile-*` policy is terminal for that client generation — the same
//! sticky refusal as Redis Cluster. ACL denial, malformed or missing fields,
//! timeout, or a protocol error leave the authority unavailable and
//! recoverable (`memory_policy_unproven`). The requirement is
//! [`RedisRetentionRequirement`], carried independently of the diagnostic
//! [`RedisClientLogPolicy`]: an idempotency authority needs the retention
//! proof while keeping ordinary operational diagnostics. Cache and budget
//! clients (`RedisRateLimitClient::new`) never run this screen and keep their
//! existing topology-only behavior, because eviction there degrades a counter
//! or a cache rather than voiding a guarantee.
//!
//! Screening therefore carries three independent per-consumer requirements —
//! [`RedisClientLogPolicy`], [`RedisRetentionRequirement`], and
//! [`ServerClockRequirement`] — and each is chosen by the constructor the
//! consumer calls. Request-quota admission
//! (`RedisRateLimitClient::for_request_quota`) is the only one that additionally
//! proves `TIME`; see the clock contract below.
//!
//! The proactive probe is bounded by the configured
//! `redis_connect_timeout_seconds` (no separate knob): a server can accept and
//! authenticate a connection and then never answer `INFO`, and an unbounded
//! screen would hang the first enforcement operation instead of refusing it. A
//! probe that times out (or fails at the transport) is an ordinary retryable
//! outage — **not** proof of Cluster topology — and the connection is discarded
//! unscreened rather than carrying a policy command
//! ([`TopologyScreen::ProbeFailed`]).
//!
//! The same bound covers the background recovery checker's `PING` and, for
//! clients that require the retention proof, the `INFO MEMORY` screen. That
//! checker is single-flight (`health_checker_started`): an accepted socket that never
//! answers `PING` must time out and retry rather than wedging the only
//! recovery task, or fail-closed consumers could never recover even after the
//! backend became healthy.
//!
//! `redis_connect_timeout_seconds` is likewise the documented bound for a
//! *server-side reply* on a security-critical single-use claim
//! ([`RedisRateLimitClient::set_bytes_nx_with_expire_bounded`]): the same
//! "connected, authenticated, and then silent" endpoint that the screen refuses
//! must not be able to hold an in-flight protected request open once the
//! connection has been screened. Reusing this bound keeps one admitted,
//! range-validated Redis timeout knob instead of adding a second one.
//!
//! Topology rejection is **terminal for the life of the client**: unlike an
//! outage it is not something a `PING` can clear (a Cluster node answers `PING`
//! happily while still redirecting every key), so the recovery checker never
//! restores availability. A configuration change rebuilds the client. The
//! terminal state is sticky *under concurrency* too: availability lives in one
//! `EnforcementAvailability` atomic whose "reachable" transition cannot win
//! against a rejection, so a connection, command, or recovery probe that
//! completes successfully after another task proved Cluster topology can neither
//! be published nor reported as success.
//!
//! Every key that one atomic operation touches is additionally placed in a
//! shared hash slot via [`RedisRateLimitClient::make_slot_key`], so the
//! multi-key sliding-window and datagram/byte transactions are slot-stable if
//! they are ever run against a sharded deployment.
//!
//! # Algorithm
//!
//! Two counting schemes share this client, and they are deliberately not
//! interchangeable.
//!
//! **Request quotas** (`rate_limiting`, `graphql`, `grpc_method_router`) use a
//! **sub-bucketed trailing window**. Each configured window is split into
//! [`REDIS_WINDOW_SUB_BUCKETS`] equal sub-buckets, and the effective count is
//! the FULL sum of the sub-bucket a request lands in, the `K + 1` sub-buckets
//! before it ([`REDIS_WINDOW_TRAILING_SUB_BUCKETS`]), and the one after it —
//! every bucket at face value, never decayed
//! ([`redis_trailing_window_count`]). The trailing `K + 2` of those counters
//! span `window + (1 + f) * (window / K)` of wall clock, where `f` is how far
//! into its own sub-bucket the request arrived, so the sum covers the exact
//! trailing window in full and over-counts by at most two sub-buckets of older
//! history. (The forward counter is empty except under reordering or clock
//! skew; see [`REDIS_WINDOW_SUB_BUCKET_KEYS`].)
//!
//! The `K + 1`-th old counter is structural, not padding: a retained charge's
//! KEY can be one sub-bucket older than the bucket the server executed it in,
//! so a reader has to reach one bucket further back than its own window to be
//! sure it sees every charge executed inside it. See
//! [`REDIS_WINDOW_TRAILING_SUB_BUCKETS`] and [`sub_bucket_charge_is_settled`]
//! for the two halves of that argument.
//!
//! That bounds the error in BOTH directions, and the over-count side has a
//! real, quantifiable cost that is stated here rather than rounded away.
//! Counting the oldest sub-buckets in full means the ladder covers MORE than
//! the exact trailing window, so a client sending at EXACTLY its configured
//! rate is throttled. Measured from the instant the SERVER executes a decision
//! the ladder reaches back up to THREE sub-buckets past the window itself,
//! because settlement admits a reader whose ladder was built one sub-bucket
//! before the bucket it executes in while the charges it counts may have been
//! keyed at the bucket they executed in. The extra history is therefore up to
//! `ceil(3L / K)` requests for a limit of `L`, and the steady-state admitted
//! fraction at exactly the configured rate is AT LEAST
//! `L / (L + ceil(3L / K))`. For `K = 16` that is `1/2` at `L = 1`, `2/3` at
//! `L = 2`, `8/10` at `L = 8`, and about 84% at `L = 100`. A homogeneous stream
//! — every request carrying the same placement lag — does better,
//! `L / (L + ceil(2L / K))` (`8/9` at `L = 8`), because the widest coverage
//! needs the reader to straddle a boundary the charges it counts did not; the
//! documented figure is the BOUND. The quantisation hurts small quotas hardest, and it is
//! inherent to any bucketed counter that counts its oldest bucket at face
//! value. It is NOT a regression: the retired two-window weighted estimate had
//! the same small-quota behaviour (a `1/s` client polling every `1.05s` was
//! refused every other request there too, because `previous` still weighed
//! `0.95` at elapsed fraction `0.05`). It is deliberately NOT fixed by decaying
//! the oldest sub-bucket on a timestamp: that reopens exactly the
//! boundary-burst over-admission this layout exists to close, because a burst
//! clustered at the END of the oldest sub-bucket would be discounted while
//! every one of its requests is still live.
//!
//! What the sub-buckets DO fix is the other end of the same trade: a bare
//! `previous + current` sum counts up to two whole windows, which settles at
//! about half the configured rate for EVERY limit, large or small, instead of
//! only for small ones.
//!
//! **Token accounting** (`ai_rate_limiter`'s `INCRBY` budgets and
//! `ws_rate_limiting`'s frame budget) keeps the **two-window weighted
//! approximation** `prev_count * (1 - elapsed_fraction) + current_count`, with
//! index and `elapsed_fraction` derived from **one** epoch timestamp at
//! subsecond precision so even a one-second window decays continuously through
//! `[0, 1)`. Those paths reserve an estimate under one window index and
//! reconcile it against that same index after the response, so they are not a
//! drop-in for the sub-bucket ladder; their residual boundary-burst exposure is
//! documented rather than silently shared with the quota path.
//!
//! Neither scheme needs Lua: both are native `GET`/`INCR`/`INCRBY`/`EXPIRE`
//! commands pipelined into one transaction.
//!
//! HTTP, GraphQL, and gRPC-method quotas add **charge-then-compensate**
//! admission on top of the sub-bucket ladder
//! ([`RedisRateLimitClient::charge_rate_limit_windows`] /
//! [`RedisRateLimitClient::uncharge_rate_limit_windows`]): one atomic
//! `MULTI`/`EXEC` reads every configured window's `K + 1` older sub-buckets and
//! the one after its current one, and charges that current one, so the decision is
//! tied to the caller's own increment, and a refusal issues one compensating
//! `MULTI`/`EXEC` that hands the charge back on every window it touched. A
//! refused request therefore leaves no lasting charge and cannot re-arm its own
//! exhaustion (issue #5517), while the charge still precedes the decision so
//! racing gateways can never both admit against one stale read. Both
//! transactions run on the ordinary pooled multiplexed connections: no `WATCH`,
//! no per-request connection, no retry budget, and still no scripting.
//!
//! **The bucket clock is the Redis server's clock, not the gateway's.**
//! Sub-buckets are only as shared as the clock that selects them, and every
//! gateway's local wall clock drifts independently. Each charge transaction
//! therefore carries a `TIME` as its last command, inside the same
//! `MULTI`/`EXEC` and at no extra round trip, and the reply is the server's own
//! clock at `EXEC`. Every successful transaction updates a per-client offset
//! (`server_time − local_time_at_reply`, see [`RedisServerClock`]), and the
//! NEXT request selects its bucket from `local_now + offset`. Bucket selection
//! and settlement are therefore judged on the Redis server clock; the local
//! clock is used only through that continuously corrected offset. Before the
//! first selection of a client's life the connection — and therefore its `TIME`
//! probe — is established first
//! ([`RedisRateLimitClient::ensure_clock_seeded`]), so even the first request
//! selects on the server clock rather than charging a ladder nobody else
//! shares.
//!
//! **The correction is not exact, and nothing here claims it is.** The offset
//! is sampled one reply latency after the server read its clock, so each
//! gateway's corrected clock lags the server's by roughly its own reply
//! latency, and two gateways sharing a quota select on corrected clocks that
//! still differ by the DIFFERENCE of their latencies. Gateways are NOT "on the
//! same clock". What the correction buys is that the disagreement is bounded by
//! round-trip times instead of by NTP discipline; what makes the ladder correct
//! in spite of it is structural: settlement is two-sided, so every retained
//! charge is keyed within one sub-bucket of the bucket the server executed it
//! in, and the ladder reads one sub-bucket further back than its own window to
//! cover exactly that. NTP remains ordinary host hygiene (it keeps logs, TLS,
//! and the token-accounting `{tag}:{window_index}` layout honest); it is no
//! longer what the quota ladder's correctness rests on.
//!
//! **What the ladder guarantees, and what it does not.** No charge executed
//! inside a reader's trailing window is ever missing from that reader's
//! ladder, whatever the two gateways' reply latencies are. The residual
//! over-admission is one gateway's own concurrent in-flight requests during the
//! two-pass rebuild window. There is no second, weaker mode to fall into: a
//! gateway either selects on the Redis server clock or it does not enforce
//! centrally at all.
//!
//! **`TIME` is REQUIRED for request quotas, and there is no local-clock
//! fallback.** It is probed ONCE per established connection of a client built
//! with `RedisRateLimitClient::for_request_quota` — the consumers that charge a
//! sub-bucket ladder — with a plain `TIME` before the socket
//! carries a policy command. EVERY unsuccessful answer — a `NOPERM`, an
//! `ERR unknown command` from a server that does not implement `TIME`, a
//! malformed successful reply, a timeout, a transport failure — leaves the
//! connection unusable exactly like a failed `INFO CLUSTER` screen: the socket
//! is discarded unpublished, the client is marked unavailable, and the
//! consumer's `redis_failure_policy` decides
//! ([`RedisRateLimitClient::probe_server_time`]). A deployment whose ACL denies
//! `TIME` therefore gets the failure policy it configured —
//! `local_fallback` enforces the configured quota once per gateway process,
//! `fail_closed` refuses — and never a quieter, weaker centralized contract
//! that reads like enforcement but is not. Grant `+time`. The two recognised
//! refusals still pick the DIAGNOSTIC (so an operator is told to grant `+time`
//! rather than reading a generic failure); they do not pick an outcome.
//!
//! **The requirement is scoped to the consumers that read the clock**
//! ([`ServerClockRequirement`], chosen by the constructor the consumer calls).
//! It is a property of the computation, not of the socket: request-quota
//! admission charges a ladder every gateway must agree on, while the shared
//! replay authority and `request_deduplication` claim markers with `SET NX EX`,
//! `ai_semantic_cache` stores a blob, and the token/datagram accounting
//! limiters reserve under a window index they compute locally. None of those
//! order anything on sub-buckets, so their connections skip the probe entirely
//! and keep their previous screening, and a replay-only deployment on a
//! restrictive ACL that never granted `+time` stays in service. The scope is
//! enforced at both ends: the probe runs only for a
//! [`ServerClockRequirement::Required`] client, and
//! [`RedisRateLimitClient::charge_rate_limit_windows`] refuses outright on any
//! other, so a ladder can never be charged against an unseeded clock.
//!
//! **Bucket mis-settlement has a bounded rebuild, and it is not a retry
//! budget.** Bucket selection precedes connection acquisition, so a charge is
//! always slightly stale when it lands. One sub-bucket of that is covered by
//! the forward `GET`. Past that the transaction's own `TIME` reply settles it
//! ([`sub_bucket_charge_is_settled`]): if the server executed `EXEC` at
//! `b + 2` or later, a peer may have charged a bucket this ladder neither read
//! nor charged; if it executed BEFORE `b`, this charge was placed in the future
//! where no peer's trailing window reaches it. Either way the caller hands its
//! charge back and rebuilds the ladder from that server instant for exactly ONE
//! more transaction; a second mis-settlement fails closed with a sampled
//! warning. The rebuild first WAITS for its own hand-back to be confirmed,
//! because the rebuilt ladder reads the bucket the abandoned pass charged and
//! would otherwise count that charge against the request that abandoned it. A
//! compensation that cannot be confirmed refuses instead of rebuilding. That is
//! a settlement rebuild on a SUCCESSFUL transaction, not a retry of a failed
//! command — a Redis error still costs exactly one round trip and is never
//! retried.
//!
//! # DNS
//!
//! When the gateway's `DnsCache` is available, Redis hostnames are resolved through
//! it — sharing the pre-warmed cache, TTL management, stale-while-revalidate, and
//! background refresh with all other gateway DNS lookups. The resolved IP is used
//! for non-TLS connections; TLS connections keep the original hostname for SNI but
//! pre-warm the DNS cache entry.
//!
//! Gateway DNS screening/resolution runs **before** the Redis connection-attempt
//! timeout begins. The configured timeout covers TCP connect, TLS handshake (when
//! enabled), and the Redis protocol handshake against the screened URL. For TLS
//! hostnames the redis crate may re-resolve at dial time (see the accepted
//! limitation on [`RedisConfig::url_with_resolved_ip`]); that crate-internal
//! resolution is inside the connection timeout.
//!
//! # TLS
//!
//! Supports TLS via `rediss://` URL scheme (note the double-s). CA verification
//! and skip-verify are inherited from the gateway-level TLS settings
//! (`FERRUM_TLS_CA_BUNDLE_PATH`, `FERRUM_TLS_NO_VERIFY`). A `redis_url` fragment
//! (`#insecure` or any other) is rejected at plugin construction: redis-rs
//! treats `#insecure` as a verification opt-out, and Ferrum does not let that
//! bypass the gateway-wide gates. The only sanctioned skip-verify path is
//! `FERRUM_TLS_NO_VERIFY`, which Ferrum applies internally after the operator
//! URL has been admitted.
//!
//! A configured CA bundle is exclusive: it is the sole trust anchor, with no
//! mixing of redis-rs default (system/public) roots. The bundle is loaded once
//! at construction and stored for both the main connect path and the
//! background health-check reconnect, so neither path can later open a
//! downgraded client. If the path is set, verification is enabled, and the
//! bundle cannot be loaded, construction returns an error rather than
//! warning-and-continuing. An unset CA path still uses redis-rs default roots.
//! `FERRUM_TLS_NO_VERIFY` is the sanctioned skip-verify path; the CA is unused
//! there, so an unloadable bundle is not a construction error on that path.
//!
//! # Resilience
//!
//! If Redis becomes unreachable, the client marks itself unavailable. A
//! background task periodically pings Redis to detect recovery. That task is
//! owned by this client: dropping the client aborts it so retired plugin
//! generations do not retain connections or keep pinging obsolete endpoints.
//! Beyond the shared availability state it holds only a `Weak` handle to the
//! connection pool — never the client, its endpoint credentials, or unrelated
//! state — which is exactly enough to drop every cached socket when the probe
//! itself proves an unsupported Cluster topology.
//!
//! What a *consumer* does while the client is unavailable is the consumer's
//! policy, not this client's: rate-limit plugins choose between failing closed
//! and local fallback through `redis_failure_policy` (see
//! [`crate::plugins::utils::rate_limit::RedisFailurePolicy`]), and
//! `request_deduplication` through `on_redis_unavailable`. Local fallback means
//! one independent enforcement domain per gateway process. It is the default
//! for `rate_limiting` and an explicit opt-in for the other enforcement plugins.
//!
//! Every transition to unavailable arms that task, because
//! [`RedisRateLimitClient::mark_unavailable`] owns both halves. Not every
//! consumer of `is_available()` fails *open*: `soap_ws_security`'s
//! `replay_scope: shared` PasswordDigest claims and `request_deduplication`'s
//! exactly-once admission deliberately reject traffic while the shared backend
//! is unavailable, so an unarmed checker would convert one transient command
//! error into an outage lasting until the next config reload. The single
//! exception is a **literal-IP** egress-policy denial, which is static
//! configuration rather than a transient outage and uses
//! `mark_unavailable_without_recovery`. A **hostname** that currently resolves
//! to a denied address is different: DNS answers can change, so that denial
//! arms recovery and the checker re-screens every interval.
//!
//! # Connection pool
//!
//! `redis_pool_size` sizes a bounded set of
//! [`redis::aio::MultiplexedConnection`] slots. Slots are established lazily on
//! first use, selected round-robin on the hot path (lock-free atomic counter),
//! and cleared together on failure so TLS/DNS screening and availability state
//! stay coherent across the pool. A proven Cluster topology clears them too,
//! whichever path proves it — an operation, a fresh connect screen, or the
//! background recovery probe.
//!
//! The pooled type is deliberately *not* [`redis::aio::ConnectionManager`].
//! That type reconnects transparently inside redis-rs, so a screened endpoint
//! could disconnect and silently acquire a brand-new physical socket without
//! re-running Ferrum's DNS resolution, egress screen, `INFO CLUSTER`
//! topology screen, or — for replay-authority clients — the `INFO MEMORY`
//! no-eviction screen. A [`redis::aio::MultiplexedConnection`] surfaces the I/O
//! failure instead: the operation fails, `clear_connection` drops every cached
//! slot, and the next operation (or the recovery checker)
//! establishes a fresh connection through the full resolve → build → connect →
//! screen path. Every physical connection this client ever uses is therefore
//! screened before it can carry a policy command.

use crate::dns::DnsCache;
use crate::plugins::utils::log_sampling::warn_sampled;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use arc_swap::ArcSwap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::AbortHandle;
use tracing::{info, warn};
use url::{Host, Url};

/// Clamp a TTL into the signed range redis-rs sends for `EXPIRE`.
///
/// A raw `as i64` cast of a TTL above `i64::MAX` wraps negative, and Redis
/// treats a zero/negative `EXPIRE` as an immediate `DEL` — every increment
/// would then delete its own counter and silently remove rate enforcement.
/// Callers already bound the window (see
/// [`crate::plugins::utils::rate_limit::MAX_RATE_LIMIT_WINDOW_SECONDS`]); this
/// is the last-line conversion guard.
fn expire_seconds(ttl_seconds: u64) -> i64 {
    i64::try_from(ttl_seconds).unwrap_or(i64::MAX).max(1)
}

/// Operational upper bound for Redis multiplexed-connection pool slots per plugin.
///
/// Each slot owns an ArcSwap, a Tokio mutex, and may lazily establish one
/// multiplexed Redis TCP connection, so configuration must keep this value a
/// small operational cardinality rather than an unbounded allocation size.
pub const MAX_REDIS_POOL_SIZE: usize = 128;

/// Redis sliding-window index and elapsed fraction from a single epoch timestamp.
///
/// `elapsed_fraction` is always in `[0, 1)`: at an exact window boundary the
/// index advances and the fraction resets to `0.0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RedisWindowProgress {
    pub index: u64,
    pub elapsed_fraction: f64,
}

/// Equal sub-buckets each Redis request-quota window is split into.
///
/// A window of `W` seconds is divided into `K` sub-buckets of `W / K` each, and
/// one decision's ladder spans `[b - K - 1 ..= b + 1]`. See
/// [`REDIS_WINDOW_TRAILING_SUB_BUCKETS`] for why the OLD end reaches one
/// sub-bucket further back than the window itself, and
/// [`REDIS_WINDOW_SUB_BUCKET_KEYS`] for the forward counter.
///
/// `K` sets three things at once, and sixteen is the chosen point on that
/// trade:
///
/// - **Over-count.** Settlement admits a charge whose key is one sub-bucket
///   older than the bucket the server executed it in, so a reader executing at
///   server bucket `s` may have selected `s - 1` and its ladder then starts at
///   `s - K - 2`. Measured from the reader's own EXECUTION instant the ladder
///   therefore covers up to `W + 3 * (W / K)` of wall clock, and the limiter
///   over-refuses by at most `3 / K` of a window — three sixteenths at
///   `K = 16`. The `2 / K` figure this replaces measured from the reader's
///   SELECTION instant and so understated a reader that straddled a boundary.
/// - **Steady-state cost.** A client at exactly its configured rate `L` keeps
///   at least `L / (L + ceil(3 * L / K))` of it: `1/2` at `L = 1`, `2/3` at
///   `L = 2`, `8/10` at `L = 8`, about 84% at `L = 100`. A stream whose
///   requests all carry the same placement lag does better —
///   `L / (L + ceil(2 * L / K))`, so `8/9` at `L = 8` — because the widest
///   coverage needs the reader to straddle a boundary while the charges it
///   counts did not. The BOUND is what every document states.
/// - **Rollover threshold.** A transaction the server applies more than one
///   sub-bucket after its bucket was selected is rebuilt, so `K` also sets how
///   slow a store may be before the policy degrades into
///   `redis_failure_policy` territory: `W / K` to `2 * W / K`, i.e. 62.5–125ms
///   for a one-second window and 3.75–7.5s for a one-minute one.
///
/// Sixteen keeps the over-count and the steady-state cost close to where
/// `K = 8` held them with the narrower `K + 2`-key ladder, at the price of
/// halving the rollover threshold and widening the transaction to twenty
/// commands over nineteen keys per configured window — still ONE `MULTI`/`EXEC`
/// and one round trip for the widest policy
/// ([`MAX_REDIS_ADMISSION_WINDOWS`] windows).
///
/// It is deliberately NOT configurable. The value is part of the shared key
/// layout, so two gateways that disagreed about it would count two different
/// budgets against one identity while both believing they enforced the
/// configured one.
pub const REDIS_WINDOW_SUB_BUCKETS: usize = 16;

/// Older sub-bucket counters one decision reads BEFORE the bucket it charges:
/// `K + 1` of them, keyed `[b - K - 1 ..= b - 1]`.
///
/// `K + 1` rather than `K` is a correctness requirement, not padding. A
/// retained charge's KEY can be one whole sub-bucket older than the bucket the
/// server executed it in: bucket selection precedes connection acquisition, the
/// learned clock offset is itself one reply latency stale, and
/// [`sub_bucket_charge_is_settled`] deliberately admits a transaction the server
/// applied at `b + 1` rather than throttling ordinary Redis latency. Settlement
/// also refuses a charge placed in the FUTURE, so every charge that survives
/// satisfies `key ∈ {exec_bucket - 1, exec_bucket}`.
///
/// A reader that executes at server bucket `s` therefore has to reach back to
/// `s - K - 1` to be sure it counts every charge executed inside its own
/// trailing window: a peer that executed at `s - K` — the oldest bucket that
/// window touches — may legitimately have keyed its charge `s - K - 1`. With
/// only `K` older counters that charge drops off the old end while it is still
/// live and both requests are admitted, although both lie inside one trailing
/// window.
///
/// A learned offset cannot close that on its own, which is why the extra
/// counter is structural: `server_time - local_time_at_reply` carries each
/// gateway's own reply latency, so two gateways sharing one quota select on
/// corrected clocks that still differ by the difference of their latencies.
pub const REDIS_WINDOW_TRAILING_SUB_BUCKETS: usize = REDIS_WINDOW_SUB_BUCKETS + 1;

/// Every counter one window's admission decision touches: the `K + 1` older
/// sub-buckets ([`REDIS_WINDOW_TRAILING_SUB_BUCKETS`]), the one the request
/// charges, and the one immediately AFTER it — `K + 3` keys spanning
/// `[b - K - 1 ..= b + 1]`.
///
/// The forward counter makes the decision independent of the order two
/// concurrent transactions happen to reach the server in. Bucket selection
/// samples the clock before the connection is acquired, so a request that
/// selected bucket `b` can execute after a peer that selected `b + 1` has
/// already charged; without the forward read the later-executing request would
/// see a ladder that stops at `b` and both would be admitted although both lie
/// inside one trailing window. Reading `b + 1` as well means whichever
/// transaction executes SECOND always observes the other, and the direction is
/// conservative: in the ordinary case nothing has charged a bucket the clock
/// has not reached yet, so the forward counter is empty and costs nothing.
///
/// The two extra counters answer two different hazards and neither can stand in
/// for the other. The FORWARD one covers a peer whose charge is ordered after
/// this ladder was built; the extra OLD one
/// ([`REDIS_WINDOW_TRAILING_SUB_BUCKETS`]) covers a peer whose retained key is
/// one bucket older than the bucket it executed in. Together with the two-sided
/// settlement check ([`sub_bucket_charge_is_settled`]) they give the ladder its
/// actual guarantee: a reader executing at server bucket `s` reads
/// `[s - K - 1, s + 1]`, every retained charge is keyed in
/// `{exec_bucket - 1, exec_bucket}`, and therefore no charge executed inside
/// the reader's trailing window can fall outside its ladder — whatever each
/// gateway's reply latency is.
///
/// [`RedisServerClock`] is still what keeps the two ends narrow: without the
/// server-clock correction an arbitrarily skewed gateway charges arbitrarily
/// far away, and no fixed ladder covers it.
pub const REDIS_WINDOW_SUB_BUCKET_KEYS: usize = REDIS_WINDOW_TRAILING_SUB_BUCKETS + 2;

/// The sub-bucket one request falls in, derived from a single epoch timestamp.
///
/// `window_seconds` travels with the index because it is a key component: two
/// windows of one policy (per-second and per-minute, say) subdivide the epoch
/// differently, and naming the window in the key makes their ladders provably
/// disjoint instead of resting on the indexes never coinciding.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedisSubBucket {
    /// `floor(epoch_nanos / (window_nanos / REDIS_WINDOW_SUB_BUCKETS))`.
    pub index: u64,
    /// The window this ladder subdivides, in seconds (at least 1).
    pub window_seconds: u64,
}

/// Width of one sub-bucket of a `window_seconds` window, in nanoseconds.
///
/// `window_seconds` is clamped to at least one and [`REDIS_WINDOW_SUB_BUCKETS`]
/// is sixteen, so the result is at least 62.5ms; `max(1)` is the last-line
/// guard against a division by zero should that constant ever be narrowed to
/// the point where a one-second window rounds to nothing.
pub fn redis_sub_bucket_nanos(window_seconds: u64) -> u128 {
    let window_nanos = (window_seconds.max(1) as u128).saturating_mul(1_000_000_000);
    (window_nanos / REDIS_WINDOW_SUB_BUCKETS as u128).max(1)
}

/// The ONE local wall-clock sample this process can take.
///
/// It is never the bucket clock on its own: [`RedisServerClock`] shifts it onto
/// the Redis server's clock, which is the only instant every gateway sharing a
/// quota agrees on. A pre-epoch clock reads as the epoch rather than panicking;
/// admission never panics.
pub fn redis_epoch_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
}

/// Offset learned from one `TIME` reply: `server_time − local_time_at_reply`,
/// in nanoseconds.
///
/// The local sample is taken when the reply is decoded, one reply latency after
/// the server read its own clock, so the offset lags reality by about that
/// latency — and two gateways with different latencies therefore select on
/// clocks that differ by the difference between them. That is the residual the
/// whole server-clock design carries; it is bounded by round trips rather than
/// removed, and the ladder's shape plus two-sided settlement are what make the
/// count correct in spite of it.
///
/// Integer throughout (no `f64` ever reaches the quota path), and saturating:
/// a nonsense clock on either side clamps instead of wrapping into a
/// plausible-looking offset.
pub fn clock_offset_nanos(server_time: Duration, local_at_reply: Duration) -> i64 {
    let server = server_time.as_nanos() as i128;
    let local = local_at_reply.as_nanos() as i128;
    (server - local).clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Shift a local epoch instant onto the server clock by a learned offset.
///
/// Clamped at the epoch rather than wrapping: an offset large enough to push
/// the corrected instant negative is a broken clock, and a wrapped instant
/// would select a sub-bucket at the far end of the index space.
pub fn apply_clock_offset(local_now: Duration, offset_nanos: i64) -> Duration {
    let corrected = (local_now.as_nanos() as i128).saturating_add(offset_nanos as i128);
    if corrected <= 0 {
        return Duration::ZERO;
    }
    let corrected = corrected as u128;
    let seconds = (corrected / 1_000_000_000).min(u64::MAX as u128) as u64;
    // Strictly below one second, so `Duration::new` cannot carry and overflow.
    let subsec_nanos = (corrected % 1_000_000_000) as u32;
    Duration::new(seconds, subsec_nanos)
}

/// Parse a Redis `TIME` reply into an epoch instant.
///
/// `TIME` answers a two-element array: Unix seconds and the microseconds
/// elapsed inside the current second, both as decimal strings. Anything else —
/// a server that does not implement the command, a reply shape this code
/// cannot pair, a microsecond field outside `[0, 1_000_000)` — is `None`. The
/// caller never guesses at a partial reading: an unusable server clock is
/// handled as an unusable reply, not as a zero.
///
/// Takes the reply BY VALUE because redis-rs decodes a `Value` by value;
/// borrowing would cost a clone of each bulk string on the admission path.
pub fn parse_redis_server_time(value: redis::Value) -> Option<Duration> {
    let redis::Value::Array(items) = value else {
        return None;
    };
    let mut items = items.into_iter();
    let seconds_value = items.next()?;
    let micros_value = items.next()?;
    if items.next().is_some() {
        return None;
    }
    let seconds: u64 = redis::from_redis_value(seconds_value).ok()?;
    let micros: u64 = redis::from_redis_value(micros_value).ok()?;
    if micros >= 1_000_000 {
        return None;
    }
    Some(Duration::from_secs(seconds).saturating_add(Duration::from_micros(micros)))
}

/// One client's view of the shared bucket clock: the Redis server's own clock,
/// tracked as a continuously corrected offset from this process's wall clock.
///
/// Sub-buckets are only as shared as the clock that picks them. Two gateways
/// reading their own wall clocks can disagree by an unbounded amount while both
/// believe they enforce one budget, and no fixed-width ladder covers that.
/// Correcting onto the server's clock bounds the disagreement by round-trip
/// times instead: every gateway's charge is ordered on the clock of the process
/// that applies it.
///
/// It does NOT put two gateways on the same clock. The offset is learned from
/// the `TIME` that rides inside every charge transaction — no extra round trip,
/// refreshed on every admission — but it is sampled one reply latency AFTER the
/// server read its clock, so each gateway's corrected clock lags the server's
/// by about its own reply latency and two gateways differ by the difference of
/// theirs. Correctness does not rest on that residual being zero: it rests on
/// [`sub_bucket_charge_is_settled`] being two-sided, which pins every retained
/// charge's key within one sub-bucket of the bucket the server executed it in,
/// and on the ladder reading one sub-bucket further back than its own window
/// ([`REDIS_WINDOW_TRAILING_SUB_BUCKETS`]) to cover exactly that.
///
/// There is exactly ONE bucket base, and it is the server's. `TIME` is a hard
/// requirement of every client that charges a ladder
/// ([`ServerClockRequirement::Required`]; a consumer that reads no clock never
/// reaches this structure): a connection whose probe cannot answer a clock is discarded
/// unpublished and the consumer's `redis_failure_policy` governs, so this
/// structure never has to describe a second, weaker mode or a transition
/// between two bases. Before any sample is known `at()` is the identity, which
/// is only reachable when seeding failed; the two-sided settlement check is the
/// backstop for a selection that still happens there, and for one that happens
/// on a base a later server-side clock change invalidated.
///
/// A stale reply must not move the base. The offset is only updated from a
/// sample whose own reply latency is shorter than one sub-bucket of the
/// narrowest window that transaction charged ([`clock_sample_is_prompt`]): a
/// reply delayed past that is, by construction, a sample that would move the
/// next selection by more than the ladder's forward cover, and keeping the
/// previous offset is strictly better than adopting one this client already
/// knows is late. The charge that carried the late reply is still judged by
/// settlement, which reads the server instant itself rather than the offset.
#[derive(Debug, Default)]
pub struct RedisServerClock {
    /// `server_time − local_time_at_reply`, nanoseconds. Meaningless until
    /// `offset_known`.
    offset_nanos: AtomicI64,
    /// Whether any successful `TIME` reply has been folded in.
    offset_known: AtomicBool,
}

impl RedisServerClock {
    /// A clock with no sample yet: what every client starts as, until a
    /// request-quota client's screened connection probes `TIME`. It stays
    /// unseeded for the life of a client that reads no clock, which is why
    /// [`RedisRateLimitClient::charge_rate_limit_windows`] refuses on one.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one `TIME` reply into the offset.
    ///
    /// `local_at_reply` is this process's wall clock when the reply was
    /// decoded. It is bookkeeping for the offset only: no admission decision is
    /// judged against it.
    pub fn record_reply(&self, server_time: Duration, local_at_reply: Duration) {
        let offset = clock_offset_nanos(server_time, local_at_reply);
        self.offset_nanos.store(offset, Ordering::Relaxed);
        self.offset_known.store(true, Ordering::Release);
    }

    /// The learned offset, or `None` while no `TIME` reply has been seen.
    pub fn offset_nanos(&self) -> Option<i64> {
        if self.offset_known.load(Ordering::Acquire) {
            Some(self.offset_nanos.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Shift a captured local instant onto the server clock. Deterministic
    /// twin of [`Self::now`].
    ///
    /// With no known offset this is the identity. That is only reachable before
    /// a connection has been screened — [`RedisRateLimitClient::ensure_clock_seeded`]
    /// establishes one before the first selection — and settlement is what
    /// catches a selection that still happens there.
    pub fn at(&self, local_now: Duration) -> Duration {
        match self.offset_nanos() {
            Some(offset) => apply_clock_offset(local_now, offset),
            None => local_now,
        }
    }

    /// The instant a bucket is selected at: this process's wall clock,
    /// corrected onto the server's.
    ///
    /// Two lock-free atomic loads and no allocation, on the admission hot path.
    pub fn now(&self) -> Duration {
        self.at(redis_epoch_now())
    }
}

/// Whether a `TIME` sample may move the learned offset.
///
/// `reply_latency` is `local_at_reply − local_at_send` for the transaction that
/// carried the `TIME`, measured entirely on this process's own clock so no
/// clock comparison is involved. The sample is accepted only while that latency
/// is shorter than one sub-bucket of `narrowest_window_seconds` — the tightest
/// window the transaction charged, which is the window whose ladder a mis-timed
/// base would break first.
///
/// The offset a reply teaches is `server_time − local_time_at_reply`, so a
/// reply held for `d` teaches an offset `d` too small, and the NEXT selection
/// lands `d` earlier than the server's clock. While `d` is under one sub-bucket
/// the ladder's forward `GET` and the two-sided settlement band already cover
/// that placement. Past it they do not, and adopting the sample would let one
/// delayed reply — an `EXEC` whose response was held while the rest of the
/// process moved on — walk the base backwards. Keeping the previous offset is
/// the conservative answer: the charge that carried the late reply is judged by
/// settlement against the server instant itself, not against the offset.
///
/// A store whose replies are NEVER prompt therefore keeps the offset its
/// connection's probe seeded until a reconnect re-probes. Learning stops;
/// SETTLEMENT does not, and the two failures are not the same failure.
/// EXECUTION delay is what rolls a ladder over: a transaction the server
/// applied inside its own sub-bucket settles correctly however late its
/// RESPONSE arrives, because settlement is judged on the `TIME` that same
/// transaction carried. A connection that executes promptly and answers late
/// therefore keeps admitting indefinitely on a frozen offset, correctly, and
/// does NOT necessarily degrade through `redis_failure_policy`. Do not write
/// that it does.
///
/// What a frozen offset costs is real but deferred: the base stops tracking the
/// server, so a later server-side clock change — or a wall-clock step on this
/// host — is never learned. Once that drift passes the settlement band every
/// request mis-settles on its FIRST pass and hands its charge back, and nothing
/// can re-teach the offset while replies stay slow, so that is a steady state
/// rather than a transient.
///
/// The rebuild does not recover it either, and the reason is the same latency.
/// The rebuilt pass selects from the server instant the ABANDONED pass carried,
/// which is already stale by that pass's RESPONSE leg — plus the hand-back it
/// waits for and its own request leg — by the time the server applies it. The
/// latency that starves learning and the staleness the rebuild inherits are the
/// same quantity, so a reply held far enough past one sub-bucket to freeze
/// the base is also far enough to push the rebuilt pass past `b + 1`, and a
/// request whose REBUILT pass also mis-settles refuses through
/// `redis_failure_policy`. A frozen offset plus a drift past the band is
/// therefore an unavailable store, not a permanent double charge; a store slow
/// enough to stall EXECUTION past one sub-bucket reaches that same second pass
/// with no drift at all.
///
/// PROMPT replies are what make a rebuild a one-off: the instant it selects
/// from is still current when the server applies it, and the same sample that
/// settles it also teaches the drift, so the next request settles on its first
/// pass. A rebuild recovers a clock step only while replies are prompt — which
/// is exactly when learning would have recovered it anyway.
pub fn clock_sample_is_prompt(reply_latency: Duration, narrowest_window_seconds: u64) -> bool {
    reply_latency.as_nanos() < redis_sub_bucket_nanos(narrowest_window_seconds)
}

/// Whether a ladder built for `bucket` is still usable, judged against the
/// Redis server clock the transaction's own `TIME` returned.
///
/// The admissible band is TWO-SIDED: `b <= server_bucket <= b + 1`. Both ends
/// are load-bearing, and together they are what turns the ladder's shape into a
/// guarantee — every charge that survives settlement satisfies
/// `key ∈ {exec_bucket - 1, exec_bucket}`, so a reader executing at server
/// bucket `s` and reading `[s - K - 1, s + 1]` cannot miss a charge executed
/// inside its own trailing window.
///
/// **Late (`server_bucket > b + 1`).** Bucket selection necessarily precedes
/// connection acquisition and execution, so a charge is always slightly stale
/// by the time the server applies it. One sub-bucket of that is covered by
/// construction, because the ladder also reads the bucket immediately after the
/// charged one (see [`REDIS_WINDOW_SUB_BUCKET_KEYS`]): a peer that selected
/// `b + 1` is visible to a request that selected `b`, and vice versa. Past that
/// the cover is gone — a queueing stall longer than a whole sub-bucket, which
/// the 500ms screened response timeout still admits for a one-second window —
/// so a peer may have charged a bucket this ladder neither read nor charged and
/// the decision derived from it could over-admit.
///
/// **Early (`server_bucket < b`).** A charge placed in the FUTURE is invisible
/// to every peer reading its own trailing window, and it stays invisible for as
/// long as the placement error lasts. It happens when this process's clock runs
/// ahead of Redis and the correction has not caught up: the very first request
/// of a client whose connection (and therefore whose `TIME` probe) does not
/// exist yet, a wall-clock step, or an offset learned before a server-side
/// clock change. Accepting it was the hole that let a gateway 600s fast charge
/// bucket `5600` while the server ordered everything at `800`, and then admit
/// again on the corrected ladder against a `1/s` quota.
///
/// Both directions are reported the same way, so the caller hands its charge
/// back and rebuilds once from the server instant rather than publishing an
/// admission it cannot stand behind.
///
/// `now` is the server's clock at `EXEC`, not a local post-reply sample: reply
/// latency after `EXEC` is harmless (a peer that charges later reads this
/// request's own increment), while execution latency before it is exactly the
/// hazard. Every charge transaction carries that sample, because `TIME` is a
/// hard requirement — there is no mode in which a local instant stands in for
/// it.
pub fn sub_bucket_charge_is_settled(bucket: RedisSubBucket, now: Duration) -> bool {
    let fresh = RedisRateLimitClient::sub_bucket_at(now, bucket.window_seconds);
    bucket.index <= fresh.index && fresh.index <= bucket.index.saturating_add(1)
}

/// Fold ONE window's sub-bucket replies into its trailing-window count.
///
/// Every sub-bucket is added at face value — there is no decay term — so a
/// burst clustered anywhere inside the trailing window is counted whole. That
/// is deliberate and is what the boundary-burst fix rests on: decaying the
/// oldest bucket on a timestamp would discount a burst clustered at its END
/// while every one of those requests is still inside the exact trailing window.
/// Each
/// counter is floored at zero on its own first: a counter can only be negative
/// when a compensating `DECR` raced its key's expiry, and folding that negative
/// into the total would let one stale bucket cancel a live burst in another.
/// The sum saturates rather than wrapping, because a wrapped total reads as
/// spare budget.
pub fn redis_trailing_window_count(sub_buckets: &[Option<i64>]) -> u64 {
    sub_buckets.iter().copied().fold(0_u64, |total, value| {
        total.saturating_add(value.unwrap_or(0).max(0) as u64)
    })
}

/// Redis sync fields read from a plugin's root JSON object.
///
/// Callers that close their own root allowlist must include these keys (or an
/// equivalent union) so misspelled Redis/storage fields fail admission. This
/// shared parser intentionally does **not** reject unknown root keys itself:
/// every Redis-backed plugin mixes these fields with plugin-specific properties,
/// and an independent Redis-only allowlist would reject legitimate plugin keys
/// (for example `ttl_seconds` on `ai_semantic_cache` or `window_seconds` on
/// `rate_limiting`).
pub const REDIS_PLUGIN_CONFIG_KEYS: &[&str] = &[
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
];

/// Configuration parsed from a plugin's JSON config for Redis connectivity.
///
/// TLS verification uses the gateway-level settings (`FERRUM_TLS_CA_BUNDLE_PATH`,
/// `FERRUM_TLS_NO_VERIFY`) rather than per-plugin overrides, ensuring all outbound
/// connections share a single CA trust chain.
#[derive(Clone)]
pub struct RedisConfig {
    /// Redis connection URL (e.g., `redis://host:6379/0` or `rediss://host:6380/0` for TLS).
    ///
    /// Must not carry a URL fragment. redis-rs treats `#insecure` as a TLS
    /// verification opt-out; Ferrum rejects any fragment at admission so that
    /// skip-verify can only come from `FERRUM_TLS_NO_VERIFY`.
    pub url: String,
    /// Enable TLS for the Redis connection. When true and the URL uses `redis://`,
    /// it is automatically upgraded to `rediss://`.
    pub tls: bool,
    /// Key prefix for all Redis keys.
    ///
    /// Rate-limit consumers default to
    /// `{FERRUM_NAMESPACE}:{plugin_name}:{plugin-config-id}` (for example
    /// `ferrum:rate_limiting:rl-public-api`) so independent policies of one
    /// plugin type never share counters. An explicit `redis_key_prefix` is the
    /// documented opt-in for a deliberately shared budget.
    pub key_prefix: String,
    /// Bounded pool size: number of [`redis::aio::MultiplexedConnection`]
    /// instances established lazily and selected round-robin on the hot path.
    pub pool_size: usize,
    /// Effective Redis connection-attempt timeout in seconds.
    ///
    /// Passed into the redis-rs [`redis::AsyncConnectionConfig`] used by every
    /// connection path (not only an outer `tokio::time::timeout`)
    /// so values above the crate's one-second default take effect. Covers TCP
    /// connect, TLS handshake when enabled, and Redis protocol handshake on
    /// cached, dedicated, and health-check paths, and is the deadline for
    /// recovery `PING` plus the proactive `INFO CLUSTER` / `INFO MEMORY`
    /// screens. Gateway `DnsCache` screening happens before this timeout
    /// starts (see module-level DNS notes).
    pub connect_timeout_seconds: u64,
    /// Interval in seconds for health check pings when Redis is marked unavailable.
    pub health_check_interval_seconds: u64,
    /// Redis username for ACL-based authentication (Redis 6+).
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://user:pass@host`).
    pub username: Option<String>,
    /// Redis password for authentication.
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://:pass@host`).
    pub password: Option<String>,
}

/// Manual `Debug` so a stray `{:?}` of a config (or of any struct that embeds
/// one) cannot dump the ACL password or the URL-embedded userinfo into logs or
/// error text. The derived impl printed both verbatim.
impl std::fmt::Debug for RedisConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let marker = super::metadata_redaction::REDACTED_PLACEHOLDER;
        f.debug_struct("RedisConfig")
            .field("url", &self.redacted_url())
            .field("tls", &self.tls)
            .field("key_prefix", &self.key_prefix)
            .field("pool_size", &self.pool_size)
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .field(
                "health_check_interval_seconds",
                &self.health_check_interval_seconds,
            )
            .field("username", &self.username.as_ref().map(|_| marker))
            .field("password", &self.password.as_ref().map(|_| marker))
            .finish()
    }
}

impl RedisConfig {
    /// Log-safe rendering of [`RedisConfig::url`].
    ///
    /// `redis_url` is a documented place to encode Redis ACL credentials
    /// (`redis://user:pass@host`), so the raw string must never reach a tracing
    /// field, an error message, or an admin projection. Scheme, host, port, and
    /// database path are preserved because they are the diagnostics that make a
    /// connect failure actionable; userinfo is replaced and query/fragment data
    /// is removed.
    ///
    /// Cold path only (connect/health-check failure logging), so the allocation
    /// here never touches a proxy hot path.
    pub fn redacted_url(&self) -> String {
        redact_url_userinfo(&self.url)
    }

    /// Parse Redis configuration from a plugin's JSON config.
    ///
    /// Returns `Ok(None)` if `sync_mode` is absent or `"local"`, after
    /// validating every explicitly supplied Redis field.
    ///
    /// Unknown root keys are left for the calling plugin to reject against its
    /// own allowlist unioned with [`REDIS_PLUGIN_CONFIG_KEYS`]. This function
    /// only reads the Redis fields listed there and must not impose a
    /// caller-specific allowlist on unrelated plugins.
    pub fn from_plugin_config(
        config: &serde_json::Value,
        default_prefix: &str,
    ) -> Result<Option<Self>, String> {
        // Value-redacted: config objects can carry redis_url / redis_password, so
        // diagnostics name the accepted shape without echoing the rejected value.
        let object = config
            .as_object()
            .ok_or_else(|| "redis rate limiter config must be a JSON object".to_string())?;

        let sync_mode = parse_optional_string(object, "sync_mode")?
            .unwrap_or("local")
            .to_ascii_lowercase();
        let redis_enabled = match sync_mode.as_str() {
            "local" => false,
            "redis" => true,
            _ => {
                return Err(
                    "redis rate limiter: 'sync_mode' must be exactly 'local' or 'redis'"
                        .to_string(),
                );
            }
        };

        // Validate every explicitly supplied Redis field even in local mode.
        // This keeps latent configuration fail-closed: toggling sync_mode later
        // cannot suddenly activate a malformed URL, wrong scalar type, or zero
        // connection bound that admission previously ignored.
        let url = parse_optional_string(object, "redis_url")?;
        if let Some(url) = url {
            if url.is_empty() {
                return Err("redis rate limiter: 'redis_url' must be non-empty".to_string());
            }
            validate_redis_url(url)?;
        } else if redis_enabled {
            return Err(
                "redis rate limiter: 'redis_url' is required when sync_mode='redis'".to_string(),
            );
        }

        let tls = parse_optional_bool(object, "redis_tls")?.unwrap_or(false);
        let key_prefix = parse_optional_string(object, "redis_key_prefix")?
            .unwrap_or(default_prefix)
            .to_string();
        if key_prefix.is_empty() {
            return Err("redis rate limiter: 'redis_key_prefix' must be non-empty".to_string());
        }

        let pool_size = parse_optional_u64(object, "redis_pool_size")?.unwrap_or(4);
        if pool_size == 0 {
            return Err(
                "redis rate limiter: 'redis_pool_size' must be greater than zero".to_string(),
            );
        }
        let pool_size = usize::try_from(pool_size)
            .map_err(|_| "redis rate limiter: 'redis_pool_size' is too large".to_string())?;
        if pool_size > MAX_REDIS_POOL_SIZE {
            return Err(format!(
                "redis rate limiter: 'redis_pool_size' must be <= {MAX_REDIS_POOL_SIZE}"
            ));
        }

        let connect_timeout_seconds =
            parse_optional_u64(object, "redis_connect_timeout_seconds")?.unwrap_or(5);
        if connect_timeout_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_connect_timeout_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let health_check_interval_seconds =
            parse_optional_u64(object, "redis_health_check_interval_seconds")?.unwrap_or(5);
        if health_check_interval_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_health_check_interval_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let username = parse_optional_string(object, "redis_username")?.map(ToString::to_string);
        let password = parse_optional_string(object, "redis_password")?.map(ToString::to_string);

        if !redis_enabled {
            return Ok(None);
        }
        let url = url.ok_or_else(|| {
            "redis rate limiter: 'redis_url' is required when sync_mode='redis'".to_string()
        })?;

        Ok(Some(RedisConfig {
            url: url.to_string(),
            tls,
            key_prefix,
            pool_size,
            connect_timeout_seconds,
            health_check_interval_seconds,
            username,
            password,
        }))
    }

    /// Build the effective Redis URL, upgrading to TLS scheme if needed.
    fn effective_url(&self) -> String {
        if self.tls && self.url.starts_with("redis://") {
            self.url.replacen("redis://", "rediss://", 1)
        } else {
            self.url.clone()
        }
    }

    /// Extract the hostname from the Redis URL for DNS pre-warming.
    ///
    /// Parses the URL to extract just the hostname (no port, no scheme).
    /// Returns `None` if the URL cannot be parsed or uses an IP address directly.
    pub fn hostname(&self) -> Option<String> {
        let url = Url::parse(&self.effective_url()).ok()?;
        let host = normalized_url_hostname(&url)?;

        // Skip if it's already an IP address
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        Some(host)
    }

    /// Parse the Redis URL host as a literal IP — the dual of [`hostname`], which
    /// returns `None` for literals. Strips URI brackets; returns `None` for
    /// hostnames. Used to screen a literal `redis_url` at dial time, since the
    /// hostname-based DNS-cache screen never sees it.
    fn literal_host_ip(&self) -> Option<std::net::IpAddr> {
        let url = Url::parse(&self.effective_url()).ok()?;
        let host = normalized_url_hostname(&url)?;
        host.strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&host)
            .parse::<std::net::IpAddr>()
            .ok()
    }

    /// Build a Redis URL with a resolved IP address substituted for the hostname.
    ///
    /// For non-TLS connections, replacing the hostname with a resolved IP avoids
    /// the redis crate doing its own DNS resolution, ensuring all DNS goes through
    /// the gateway's shared cache.
    ///
    /// For TLS connections, the hostname must be preserved for SNI verification,
    /// so this returns the original URL unchanged.
    ///
    /// ACCEPTED LIMITATION (egress policy, `rediss://` hostnames): the resolved IP
    /// is NOT pinned for TLS hostnames because the `redis` crate derives the TLS
    /// server name from the URL host — pinning the IP would break SNI/cert
    /// verification, and the crate exposes no way to dial a chosen address while
    /// presenting a separate server name. `screen_redis_endpoint` has already
    /// screened the CURRENT resolution against the egress policy, but the Redis
    /// client re-resolves the hostname itself at connect/reconnect time outside
    /// the gateway DNS cache, so a hostname whose DNS rebinds to a blocked address
    /// between screen and dial could still be reached. This is a narrow TOCTOU
    /// that requires control of the operator's own Redis DNS (which already
    /// implies control of the gateway's resolver). Literal-IP `rediss://` and all
    /// `redis://` (plaintext) endpoints ARE pinned/screened. Closing the TLS-
    /// hostname gap requires a custom pinned TLS connector (abandoning the crate's
    /// own connection establishment) and is deliberately out of scope — see PR #1933.
    pub(crate) fn url_with_resolved_ip(&self, resolved_ip: std::net::IpAddr) -> String {
        let url = self.effective_url();

        // Don't replace hostname for TLS — SNI needs the original hostname (see
        // the ACCEPTED LIMITATION note above on the residual rebinding gap).
        if url.starts_with("rediss://") {
            return url;
        }

        let mut parsed = match Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(_) => return url,
        };

        if parsed.host_str().is_none() {
            return url;
        }

        if parsed.set_ip_host(resolved_ip).is_err() {
            return url;
        }

        parsed.to_string()
    }
}

/// Strip userinfo, query, and fragment from a connection URL, keeping
/// scheme/host/port/path.
///
/// Only `redis` / `rediss` URLs receive the diagnostic-preserving projection.
/// Any other parseable scheme (including opaque `data:` / `mailto:` values and
/// ordinary `http(s):` URLs that may carry secrets in the path) fails closed to
/// a bare marker — admin projections match by the `redis_url` key name, so a
/// non-Redis value must never be echoed as if it were a safe endpoint label.
///
/// Unparseable strings also fail closed: they cannot be proven credential-free,
/// and `redis_url` is only validated for `sync_mode: "redis"` plus explicitly
/// supplied values, so a caller can still hold a string this function has never
/// validated.
pub(crate) fn redact_url_userinfo(raw_url: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw_url) else {
        return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string();
    };
    match parsed.scheme() {
        "redis" | "rediss" => {}
        _ => return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string(),
    }
    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    let has_suffix = parsed.query().is_some() || parsed.fragment().is_some();
    if !has_userinfo && !has_suffix {
        // Return the original bytes rather than the parser's normalization, so
        // a credential-free value is never silently rewritten in an admin
        // projection or a log line.
        return raw_url.to_string();
    }
    if has_userinfo
        && (parsed.set_password(None).is_err() || parsed.set_username("redacted").is_err())
    {
        return super::metadata_redaction::REDACTED_PLACEHOLDER.to_string();
    }
    // Redis URLs may carry non-secret transport options in the query, but
    // arbitrary disabled/unvalidated plugin configs can also put credentials
    // there or in a fragment. Neither is needed to identify the destination.
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

fn validate_redis_url(raw_url: &str) -> Result<(), String> {
    // Never echo the rejected URL (or parse detail that might restate it): the
    // field can carry userinfo credentials, query tokens, or fragments.
    if raw_url.chars().any(char::is_whitespace) {
        // Same diagnostic family as the parse failure below: a whitespace-bearing
        // value is rejected before `Url::parse` can normalize it, and the text
        // still never echoes the value.
        return Err(
            "redis rate limiter: 'redis_url' must be a valid URL with scheme redis or rediss \
             and no whitespace"
                .to_string(),
        );
    }
    let parsed = Url::parse(raw_url).map_err(|_| {
        "redis rate limiter: 'redis_url' must be a valid URL with scheme redis or rediss"
            .to_string()
    })?;
    match parsed.scheme() {
        "redis" | "rediss" => {}
        _ => {
            return Err(
                "redis rate limiter: 'redis_url' scheme must be exactly 'redis' or 'rediss'"
                    .to_string(),
            );
        }
    }
    if !has_non_empty_authority(raw_url) || normalized_url_hostname(&parsed).is_none() {
        return Err("redis rate limiter: 'redis_url' must include a hostname".to_string());
    }
    // redis-rs treats `#insecure` as ConnectionAddr::TcpTls.insecure = true.
    // That is a verification opt-out that is not FERRUM_TLS_NO_VERIFY, so it
    // would escape production-mode, FIPS, and startup-warning gates. No
    // legitimate redis_url needs a fragment: Ferrum appends `#insecure` itself
    // on the sanctioned FERRUM_TLS_NO_VERIFY path after admission.
    if parsed.fragment().is_some() {
        return Err(
            "redis rate limiter: 'redis_url' must not carry a URL fragment; TLS certificate \
             verification cannot be disabled per URL"
                .to_string(),
        );
    }
    validate_redis_database_selector(raw_url)?;
    Ok(())
}

/// Ferrum's portable database-selector ceiling. redis-rs stores an i64, but
/// Redis SELECT and the server's database count use signed 32-bit indexes.
/// Admission therefore uses 0..=i32::MAX. An index inside this bound may exceed a
/// server's configured `databases` count; only the server can decide that, and
/// it does so on the `SELECT` issued during the connection handshake.
const MAX_REDIS_DATABASE_INDEX: i64 = i32::MAX as i64;

/// Validate the URL path as a Redis database selector at plugin admission.
///
/// redis-rs derives the database from `url.path().trim_matches('/')` and fails
/// with `Invalid database number` when it is not an integer — but only at
/// *client construction*, which every Redis-backed plugin defers to first use.
/// An unconstructible selector therefore passed `validate`, left the gateway
/// unready, and turned every otherwise-correct request into a fail-closed
/// refusal with no diagnostic naming the field. Every consumer of
/// [`RedisConfig::from_plugin_config`] reaches this check, so the
/// misconfiguration is now an admission error instead.
///
/// Never echoes the value: `redis_url` may carry userinfo credentials.
fn validate_redis_database_selector(raw_url: &str) -> Result<(), String> {
    // Inspect the original path: URL parsing normalizes dot segments, whereas
    // the published schema admits only an absent path, '/', or '/<integer>'.
    let selector = raw_url
        .split(['?', '#'])
        .next()
        .and_then(|base| base.split_once("://"))
        .and_then(|(_, authority)| authority.split_once('/'))
        .map_or("", |(_, path)| path);
    if selector.is_empty() {
        return Ok(());
    }
    if !selector.bytes().all(|byte| byte.is_ascii_digit())
        || (selector.len() > 1 && selector.starts_with('0'))
    {
        return Err(
            "redis rate limiter: 'redis_url' path must be a canonical database number \
             (for example '/0'), without a sign, zero-padding, or extra path segments"
                .to_string(),
        );
    }
    let database = selector.parse::<i64>().map_err(|_| {
        "redis rate limiter: 'redis_url' path must be a database number (for example '/0')"
            .to_string()
    })?;
    if !(0..=MAX_REDIS_DATABASE_INDEX).contains(&database) {
        return Err(format!(
            "redis rate limiter: 'redis_url' database number must be between 0 and \
             {MAX_REDIS_DATABASE_INDEX}"
        ));
    }
    Ok(())
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

fn normalized_url_hostname(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) if !host.is_empty() => Some(host.to_string()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
        _ => None,
    }
}

/// Build a redis-rs client with Ferrum's TLS verification policy applied.
///
/// redis-rs treats a `#insecure` URL fragment as
/// `ConnectionAddr::TcpTls.insecure = true`. Caller-supplied fragments are
/// stripped first; the fragment is re-appended only when `tls_no_verify` is
/// set from `FERRUM_TLS_NO_VERIFY`. This is the single construction path for
/// both the main client and the background health-check reconnect.
fn open_screened_redis_client(
    url: &str,
    tls_no_verify: bool,
    tls_ca_bundle_pem: Option<&[u8]>,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<redis::Client, redis::RedisError> {
    use redis::IntoConnectionInfo;

    let is_tls = url.starts_with("rediss://");
    let without_fragment = url.split_once('#').map(|(base, _)| base).unwrap_or(url);
    let conn_info_url = if is_tls && tls_no_verify {
        format!("{without_fragment}#insecure")
    } else {
        without_fragment.to_string()
    };

    let mut conn_info = conn_info_url.as_str().into_connection_info()?;
    if username.is_some() || password.is_some() {
        let mut redis_settings = conn_info.redis_settings().clone();
        if let Some(username) = username {
            redis_settings = redis_settings.set_username(username);
        }
        if let Some(password) = password {
            redis_settings = redis_settings.set_password(password);
        }
        conn_info = conn_info.set_redis_settings(redis_settings);
    }

    if is_tls && (tls_ca_bundle_pem.is_some() || tls_no_verify) {
        redis::Client::build_with_tls(
            conn_info,
            redis::TlsCertificates {
                client_tls: None,
                root_cert: tls_ca_bundle_pem.map(|pem| pem.to_vec()),
            },
        )
    } else {
        redis::Client::open(conn_info)
    }
}

fn parse_optional_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a string"))
        })
        .transpose()
}

fn parse_optional_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be an integer"))
        })
        .transpose()
}

/// Outcome of screening + resolving the Redis endpoint through the gateway DNS
/// cache. The client NEVER dials an address the egress policy hasn't cleared, so
/// any screen failure leaves centralized Redis unavailable — the consumer's
/// configured failure policy then decides — rather than handing an unscreened
/// host to the Redis crate's own resolver.
enum RedisEndpoint {
    /// A policy-screened URL to dial.
    Url(String),
    /// A configured hostname currently resolves to an address the backend egress
    /// policy denies. Fail closed for this attempt, but arm the recovery checker:
    /// DNS answers are not static, so a later re-screen may land on an allowed
    /// address without a config reload.
    HostnameEgressDenied,
    /// A literal-IP `redis_url` is blocked by the backend egress policy. Fail
    /// closed and do NOT start the recovery checker — the denied address is
    /// configuration, not a transient outage, so a config change (which rebuilds
    /// the client) is the only recovery.
    LiteralIpEgressDenied,
    /// The DNS cache could not resolve the host (resolver outage / misconfigured
    /// gateway DNS). Fail closed rather than dialing an unscreened address, but
    /// the background recovery checker may re-screen successfully later.
    ResolveFailed,
}

/// Failure classifying a Redis connection attempt after DNS screening succeeded.
enum ConnectAttemptError {
    Redis(redis::RedisError),
    Timeout,
}

/// Redis error codes that only a Cluster-mode server ever returns.
///
/// This client is not Cluster-aware (see the module-level topology notes), so
/// any of these proves the configured endpoint is a topology it cannot enforce
/// against — not a transient outage. Matching on the wire code rather than a
/// `redis::ErrorKind` variant keeps the check stable across crate versions and
/// also catches RESP-compatible servers that return the code as an extension
/// error.
///
/// `MASTERDOWN` is deliberately excluded: plain replication returns it too, and
/// it is a genuine (recoverable) availability failure.
pub fn is_cluster_topology_code(code: Option<&str>) -> bool {
    matches!(
        code,
        Some("MOVED" | "ASK" | "CROSSSLOT" | "CLUSTERDOWN" | "TRYAGAIN")
    )
}

/// Whether a failed command proves the endpoint is a Cluster, including
/// redirections that only appear *inside* an aggregated pipeline error.
///
/// The top-level code is not sufficient. Every enforcement primitive here sends
/// a `MULTI`/`EXEC` pipeline, and a Cluster node answers `MULTI` with `+OK` and
/// only then redirects the keyed commands at queue time. The client surfaces
/// that as one aborted-transaction error whose own code is `EXECABORT`, with the
/// `MOVED`/`ASK`/… replies carried as the per-command server errors. Classifying
/// on the outer code alone would read a proven Cluster as an ordinary outage —
/// recoverable, and a Cluster node answers recovery `PING`s perfectly well — so
/// the endpoint would never reach the terminal state the advisory requires.
pub fn is_cluster_topology_error(error: &redis::RedisError) -> bool {
    if is_cluster_topology_code(error.code()) {
        return true;
    }
    // `into_server_errors` consumes the error; `RedisError` is `Clone` and the
    // aggregated variants are `Arc`-backed, so this is a refcount bump.
    let Some(errors) = error.clone().into_server_errors() else {
        return false;
    };
    errors
        .iter()
        .any(|(_, err)| is_cluster_topology_code(Some(err.code())))
}

/// Whether a failed command was refused by the server's ACL rather than by the
/// transport.
///
/// Read with the same care as [`is_cluster_topology_error`]: `TIME` rides
/// inside the admission `MULTI`, and a Redis that revokes it between the
/// connection's probe and a later transaction answers the queued command with
/// `NOPERM` and aborts the whole `EXEC` under an `EXECABORT` outer code. Only
/// the per-command server errors carry the real reason, so admission would
/// otherwise read a permanent ACL change as an endless outage.
pub fn is_permission_denied_error(error: &redis::RedisError) -> bool {
    if matches!(error.code(), Some("NOPERM")) {
        return true;
    }
    // `into_server_errors` consumes the error; `RedisError` is `Clone` and the
    // aggregated variants are `Arc`-backed, so this is a refcount bump.
    let Some(errors) = error.clone().into_server_errors() else {
        return false;
    };
    errors.iter().any(|(_, err)| err.code() == "NOPERM")
}

/// Whether a failed command was refused because the server does not implement
/// it.
///
/// Redis answers an unimplemented command with a plain `ERR unknown command
/// '<name>'`, and RESP-compatible servers that omit `TIME` answer the same
/// shape. That, and a `NOPERM`, are permanent statements about what this
/// endpoint offers rather than transport trouble, so they select the
/// DIAGNOSTIC a failed `TIME` probe publishes — an operator is told to grant
/// `+time`, or that this server has no `TIME` at all, instead of reading a
/// generic command failure. They do NOT select an outcome: every unsuccessful
/// probe leaves the connection unusable
/// ([`RedisRateLimitClient::probe_server_time`]).
///
/// Matched on the message rather than a code because `ERR` is the generic
/// server-error code; the prefix is stable across Redis, Valkey, DragonflyDB,
/// KeyDB, and Garnet, and it is compared case-insensitively over the leading
/// words only, so no caller-controlled text can reach it.
pub fn is_unknown_command_error(error: &redis::RedisError) -> bool {
    fn says_unknown_command(detail: &str) -> bool {
        detail
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("unknown command")
    }
    if error.code() == Some("ERR") && error.detail().is_some_and(says_unknown_command) {
        return true;
    }
    // `into_server_errors` consumes the error; `RedisError` is `Clone` and the
    // aggregated variants are `Arc`-backed, so this is a refcount bump.
    let Some(errors) = error.clone().into_server_errors() else {
        return false;
    };
    errors
        .iter()
        .any(|(_, err)| err.code() == "ERR" && err.details().is_some_and(says_unknown_command))
}

/// Read `cluster_enabled` out of an `INFO CLUSTER` reply.
///
/// Returns `None` when the field is absent — the server may be a
/// RESP-compatible implementation that does not report it, and an absent field
/// must never be treated as proof of either topology. `Some(true)` is the only
/// value that rejects an endpoint, so the "unknown" case stays compatible.
pub fn parse_cluster_enabled(info: &str) -> Option<bool> {
    for line in info.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("cluster_enabled:") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        return Some(value != "0");
    }
    None
}

/// Encoded length of one logical Redis hash-tag component.
///
/// `%`, `{`, `}`, and `:` are escaped so the outer tag cannot be truncated by
/// caller-controlled braces and the `prefix:rate_key` boundary is injective.
fn slot_tag_component_len(value: &str) -> usize {
    value.chars().fold(0usize, |len, ch| {
        len.saturating_add(if matches!(ch, '%' | '{' | '}' | ':') {
            3
        } else {
            ch.len_utf8()
        })
    })
}

fn push_slot_tag_component(key: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '%' => key.push_str("%25"),
            '{' => key.push_str("%7B"),
            '}' => key.push_str("%7D"),
            ':' => key.push_str("%3A"),
            _ => key.push(ch),
        }
    }
}

/// Screen + resolve the Redis endpoint through the gateway DNS cache, NEVER
/// returning an unscreened address. Shared by the hot-path connect (`resolve_url`)
/// AND the background recovery checker so neither can hand an unscreened host to
/// the Redis crate's own resolver.
async fn screen_redis_endpoint(
    config: &RedisConfig,
    dns_cache: Option<&DnsCache>,
    log_policy: RedisClientLogPolicy,
) -> RedisEndpoint {
    if let Some(dns_cache) = dns_cache
        && let Some(hostname) = config.hostname()
    {
        match dns_cache.resolve(&hostname, None, None).await {
            Ok(ip) => return RedisEndpoint::Url(config.url_with_resolved_ip(ip)),
            Err(e) => {
                if crate::dns::is_egress_policy_denial(&e) {
                    match log_policy {
                        RedisClientLogPolicy::Operational => {
                            warn!(
                                hostname = %hostname,
                                error = %e,
                                "Redis hostname currently resolves to an address blocked by backend egress \
                                 policy — centralized Redis unavailable; will re-screen"
                            );
                        }
                        RedisClientLogPolicy::ClassificationOnly => {
                            warn_replay_backend(
                                &config.redacted_url(),
                                "connection_failed",
                                "Redis single-use claim backend failed",
                            );
                        }
                    }
                    return RedisEndpoint::HostnameEgressDenied;
                }
                // Fail CLOSED on ANY screen failure (resolver outage / misconfigured
                // gateway DNS), not just policy denials: handing the unscreened
                // hostname to the Redis client would let it re-resolve outside the
                // egress policy and possibly dial a denied address.
                match log_policy {
                    RedisClientLogPolicy::Operational => {
                        warn!(
                            hostname = %hostname,
                            error = %e,
                            "DNS cache resolution failed for Redis host — centralized Redis unavailable; will retry"
                        );
                    }
                    RedisClientLogPolicy::ClassificationOnly => {
                        warn_replay_backend(
                            &config.redacted_url(),
                            "connection_failed",
                            "Redis single-use claim backend failed",
                        );
                    }
                }
                return RedisEndpoint::ResolveFailed;
            }
        }
    }
    // A literal-IP `redis_url` never reaches the hostname screen above
    // (`hostname()` is None for literals), and the config-load Redis screen is
    // warning-only in database mode — so screen the literal here too.
    if let Some(dns_cache) = dns_cache
        && let Some(ip) = config.literal_host_ip()
        && let Some(reason) = dns_cache.backend_allow_ips().deny_reason(&ip)
    {
        match log_policy {
            RedisClientLogPolicy::Operational => {
                warn!(
                    redis_ip = %ip,
                    reason,
                    "Redis literal host blocked by backend egress policy — centralized Redis unavailable \
                     until configuration changes"
                );
            }
            RedisClientLogPolicy::ClassificationOnly => {
                warn_replay_backend(
                    &config.redacted_url(),
                    "connection_failed",
                    "Redis single-use claim backend failed",
                );
            }
        }
        return RedisEndpoint::LiteralIpEgressDenied;
    }
    RedisEndpoint::Url(config.effective_url())
}

/// Verdict of the proactive `INFO CLUSTER` topology screen.
///
/// Three states, not a `bool`: "not proven to be a Cluster" and "could not be
/// screened at all" have opposite safety properties. The first keeps ordinary
/// RESP-compatible servers working; the second must never let a policy command
/// run on the unscreened connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyScreen {
    /// Not proven to be a Cluster: the connection may serve policy operations.
    /// The reactive per-command screen still catches redirections.
    Usable,
    /// Provably an unsupported Cluster topology. Terminal for the client.
    ClusterProven,
    /// The probe itself did not complete — it timed out against the configured
    /// connect timeout, or the transport failed. This is an ordinary retryable
    /// availability failure and is **not** evidence of either topology, so the
    /// connection is discarded rather than used unscreened.
    ProbeFailed,
}

/// Classify an `INFO CLUSTER` payload. Only a reported `cluster_enabled` of
/// non-zero rejects; absent/unparseable stays [`TopologyScreen::Usable`] so a
/// RESP-compatible server that does not report the field keeps working.
fn screen_from_info_text(text: &str) -> TopologyScreen {
    match parse_cluster_enabled(text) {
        Some(true) => TopologyScreen::ClusterProven,
        _ => TopologyScreen::Usable,
    }
}

/// Classify a successful `INFO CLUSTER` reply of any RESP shape.
///
/// Queried as [`redis::Value`] rather than `String` so a server whose reply is
/// not a plain bulk string produces the compatible "unknown topology" verdict
/// instead of a client-side type error that the caller would have to interpret.
fn screen_from_info_value(value: &redis::Value) -> TopologyScreen {
    match value {
        redis::Value::BulkString(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => screen_from_info_text(text),
            // Non-UTF-8 INFO payload: unknown, not proof of either topology.
            Err(_) => TopologyScreen::Usable,
        },
        redis::Value::SimpleString(text) => screen_from_info_text(text),
        redis::Value::VerbatimString { text, .. } => screen_from_info_text(text),
        // An error carried inline as a value still proves topology by its code.
        redis::Value::ServerError(error) => {
            if is_cluster_topology_code(Some(error.code())) {
                TopologyScreen::ClusterProven
            } else {
                TopologyScreen::Usable
            }
        }
        // Any other reply shape is not proof of either topology.
        _ => TopologyScreen::Usable,
    }
}

/// Issue `PING` under a hard `probe_timeout` deadline.
///
/// Connection establishment is bounded separately. A server that accepts and
/// authenticates and then never answers `PING` would otherwise stall the
/// single-flight recovery checker forever, so fail-closed consumers could
/// never recover even after the backend became healthy. Timeout is an
/// ordinary retryable outage: the client stays unpublished and the loop
/// retries on the next interval.
///
/// redis-rs 1.2.1 defaults `AsyncConnectionConfig.response_timeout` to 500ms.
/// The recovery checker disables that inner cap so this admitted bound is
/// what fires. An inner I/O timeout is still rewritten to the same classified
/// error: otherwise a silent PING consumes the first unproven diagnostic as
/// generic `connection_failed` before Ferrum's admitted bound can publish the
/// correct class.
async fn ping_connection(
    conn: &mut impl redis::aio::ConnectionLike,
    probe_timeout: Duration,
) -> Result<String, redis::RedisError> {
    match tokio::time::timeout(
        probe_timeout,
        redis::cmd("PING").query_async::<String>(conn),
    )
    .await
    {
        Ok(Ok(pong)) => Ok(pong),
        Ok(Err(error)) if error.is_timeout() => Err(incomplete_ping_probe_error()),
        Ok(Err(error)) => Err(error),
        Err(_elapsed) => Err(incomplete_ping_probe_error()),
    }
}

/// Screening connection config: Ferrum's connect timeout, without redis-rs'
/// default 500ms command response timeout.
///
/// `PING` / `INFO` replies are bounded by the caller's `tokio::time::timeout`
/// so a silent backend is classified against the admitted connect-timeout
/// bound rather than the crate's shorter command cap. Used by the recovery
/// checker *and* by the pooled/dedicated connect paths, whose `INFO` screens
/// carry the same admitted deadline; those paths arm the ordinary per-command
/// response bound afterwards through [`RedisRateLimitClient::screen_and_arm`].
fn screened_async_connection_config(connect_timeout: Duration) -> redis::AsyncConnectionConfig {
    redis::AsyncConnectionConfig::new()
        .set_connection_timeout(Some(connect_timeout))
        .set_response_timeout(None)
}

/// Per-command response deadline installed on pooled and dedicated connections
/// once they are screened.
///
/// This is redis-rs' own default (`DEFAULT_RESPONSE_TIMEOUT`), retained
/// explicitly rather than inherited: the connection is established with the
/// inner cap disabled so the `INFO CLUSTER` / memory screens are bounded by the
/// configured `redis_connect_timeout_seconds`, and ordinary command execution
/// must still be bounded afterwards.
const SCREENED_COMMAND_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// Ask a freshly established connection whether it belongs to a Cluster-mode
/// server, under a hard `probe_timeout` deadline.
///
/// A server that rejects or does not implement `INFO` (restricted ACL, minimal
/// RESP implementation) yields [`TopologyScreen::Usable`]: the endpoint is not
/// *proven* to be a Cluster, and the reactive per-command screen still catches
/// redirections. An `INFO` answered with a Cluster-only error code is itself
/// proof. A server that accepts and authenticates the connection but never
/// answers `INFO`, or whose transport fails mid-probe, yields
/// [`TopologyScreen::ProbeFailed`] — bounded by `probe_timeout` so the first
/// enforcement operation refuses instead of hanging.
async fn screen_connection_topology(
    conn: &mut impl redis::aio::ConnectionLike,
    probe_timeout: Duration,
) -> TopologyScreen {
    let mut probe = redis::cmd("INFO");
    probe.arg("CLUSTER");
    match tokio::time::timeout(probe_timeout, probe.query_async::<redis::Value>(conn)).await {
        Ok(Ok(value)) => screen_from_info_value(&value),
        Ok(Err(error)) => {
            if is_cluster_topology_error(&error) {
                TopologyScreen::ClusterProven
            } else if error.code().is_some() {
                // The server *answered* with an error reply (unknown command,
                // restricted ACL, …). Retain compatibility: not proven Cluster.
                TopologyScreen::Usable
            } else {
                // No server error code: an I/O, protocol, or parse failure. The
                // endpoint was never screened, so it must not carry a command.
                TopologyScreen::ProbeFailed
            }
        }
        // Accepted and authenticated but never answered INFO.
        Err(_elapsed) => TopologyScreen::ProbeFailed,
    }
}

/// Verdict of one standalone `TIME` screen on an established connection.
///
/// Shared by the connect-path probe
/// ([`RedisRateLimitClient::probe_server_time`]) and by the background recovery
/// checker, so the two cannot drift apart: a client whose admission selects
/// sub-buckets on the Redis server's clock must never be republished as
/// recovered on a weaker screen than the one its own connections have to pass.
enum ServerClockScreen {
    /// A well-formed clock. `server_time` is the instant the server reported;
    /// `sampled_at` is this process's clock when the reply landed, which is the
    /// other half of the offset the connect path learns.
    Clock {
        server_time: Duration,
        sampled_at: Duration,
    },
    /// The command was ALLOWED and answered something that is not a clock — a
    /// server replying `+OK` to `TIME`. An endpoint this code cannot pair with
    /// a clock cannot order one budget across gateways.
    Unreadable,
    /// `NOPERM`: the ACL withholds `+time`.
    Denied,
    /// `ERR unknown command`: this RESP server has no `TIME` at all.
    Unimplemented,
    /// A timeout, a transport failure, or any other server error.
    Failed(redis::RedisError),
}

/// Ask a connection for the Redis server's clock under a hard `probe_timeout`.
///
/// Deliberately a STANDALONE command rather than a trial `TIME` inside a real
/// transaction: a denied command queued in `MULTI` aborts the whole `EXEC`, so
/// a probe that guessed wrong would fail an admission instead of rejecting a
/// socket. The reply goes through [`parse_redis_server_time`] — the one parser
/// — and the local sample is taken immediately after it lands, because the
/// offset a caller may learn from it is `server_time − local_time_at_reply`.
///
/// The two recognised refusals are separated here only so a caller can pick the
/// DIAGNOSTIC an operator can act on; neither changes an outcome.
async fn screen_connection_server_clock(
    conn: &mut impl redis::aio::ConnectionLike,
    probe_timeout: Duration,
) -> ServerClockScreen {
    let probed = tokio::time::timeout(
        probe_timeout,
        redis::cmd("TIME").query_async::<redis::Value>(conn),
    )
    .await;
    let sampled_at = redis_epoch_now();
    match probed {
        Ok(Ok(value)) => match parse_redis_server_time(value) {
            Some(server_time) => ServerClockScreen::Clock {
                server_time,
                sampled_at,
            },
            None => ServerClockScreen::Unreadable,
        },
        Ok(Err(error)) if is_permission_denied_error(&error) => ServerClockScreen::Denied,
        Ok(Err(error)) if is_unknown_command_error(&error) => ServerClockScreen::Unimplemented,
        Ok(Err(error)) => ServerClockScreen::Failed(error),
        // Accepted, authenticated, and silent past the admitted bound.
        Err(_elapsed) => ServerClockScreen::Failed(incomplete_clock_probe_error()),
    }
}

const CLOCK_PROBE_UNPROVEN_DETAIL: &str = "Redis TIME probe did not complete";

fn incomplete_clock_probe_error() -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::Io, CLOCK_PROBE_UNPROVEN_DETAIL))
}

fn is_incomplete_clock_probe_error(error: &redis::RedisError) -> bool {
    error.kind() == redis::ErrorKind::Io && error.to_string().contains(CLOCK_PROBE_UNPROVEN_DETAIL)
}

/// Recovery-probe failure for an endpoint that answered `TIME` with something
/// this code cannot read as a clock.
fn unreadable_clock_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::Io,
        "Redis endpoint answered TIME with something that is not a clock",
    ))
}

/// Recovery-probe failure for an endpoint that refuses or does not implement
/// `TIME`.
///
/// Classified as I/O, not as a client-config fault: an ACL can be granted under
/// a live gateway, so this must stay retryable rather than terminal the way a
/// proven Cluster topology is.
fn denied_clock_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::Io,
        "Redis endpoint does not permit or implement TIME",
    ))
}

/// Recovery-probe failure for an endpoint proven to be an unsupported topology.
///
/// The recovery loop reports its outcome as a `RedisResult`, so a topology
/// rejection needs an error value. It is never surfaced to a client.
fn cluster_topology_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::InvalidClientConfig,
        "Redis endpoint reports an unsupported topology (Redis Cluster)",
    ))
}

/// Recovery-probe failure for a topology screen that never completed — an
/// ordinary retryable outage, classified as I/O rather than a config fault.
const REPLAY_CLUSTER_UNPROVEN_DETAIL: &str =
    "Redis topology screen did not complete during recovery";

fn incomplete_topology_probe_error() -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::Io, REPLAY_CLUSTER_UNPROVEN_DETAIL))
}

fn is_incomplete_topology_probe_error(error: &redis::RedisError) -> bool {
    error.kind() == redis::ErrorKind::Io
        && error.to_string().contains(REPLAY_CLUSTER_UNPROVEN_DETAIL)
}

const RECOVERY_PING_TIMEOUT_DETAIL: &str =
    "Redis health-check PING did not complete during recovery";

fn incomplete_ping_probe_error() -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::Io, RECOVERY_PING_TIMEOUT_DETAIL))
}

fn is_incomplete_ping_probe_error(error: &redis::RedisError) -> bool {
    error.kind() == redis::ErrorKind::Io && error.to_string().contains(RECOVERY_PING_TIMEOUT_DETAIL)
}

const REPLAY_MEMORY_UNPROVEN_DETAIL: &str = "Redis replay memory-policy screen did not complete";

fn unsafe_eviction_probe_error() -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::InvalidClientConfig,
        "Redis endpoint reports an unsafe maxmemory eviction policy",
    ))
}

fn unproven_memory_probe_error() -> redis::RedisError {
    redis::RedisError::from((redis::ErrorKind::Io, REPLAY_MEMORY_UNPROVEN_DETAIL))
}

fn is_unproven_memory_probe_error(error: &redis::RedisError) -> bool {
    error.kind() == redis::ErrorKind::Io
        && error.to_string().contains(REPLAY_MEMORY_UNPROVEN_DETAIL)
}

/// Verdict of the proactive `INFO MEMORY` eviction-policy screen used only by
/// Redis clients that declare [`RedisRetentionRequirement::NoEviction`].
///
/// Distinct from [`TopologyScreen`]: an absent `cluster_enabled` field is
/// compatible (not proven Cluster), but an absent memory-policy proof cannot
/// be treated as "eviction is disabled". Unproven stays fail-closed and
/// recoverable; a proven `allkeys-*` / `volatile-*` policy is terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPolicyScreen {
    /// `maxmemory == 0` or `maxmemory_policy == noeviction`.
    Usable,
    /// Proven evicting policy while a memory limit is in force. Terminal.
    UnsafeEviction,
    /// ACL denial, timeout, protocol error, or malformed/missing fields.
    Unproven,
}

/// Read `maxmemory` and `maxmemory_policy` out of an `INFO MEMORY` reply.
///
/// Neither field is assumed present. `maxmemory_human` and similar prefixed
/// keys are ignored. Values are trimmed; empty values are treated as absent.
pub fn parse_memory_policy_fields(info: &str) -> (Option<u64>, Option<&str>) {
    let mut maxmemory = None;
    let mut policy = None;
    for line in info.lines() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key {
            "maxmemory" => {
                if let Ok(parsed) = value.parse() {
                    maxmemory = Some(parsed);
                }
            }
            "maxmemory_policy" => policy = Some(value),
            _ => {}
        }
    }
    (maxmemory, policy)
}

fn policy_is_noeviction(policy: &str) -> bool {
    policy.eq_ignore_ascii_case("noeviction")
}

fn policy_is_evicting(policy: &str) -> bool {
    let lowered = policy.to_ascii_lowercase();
    lowered.starts_with("allkeys-") || lowered.starts_with("volatile-")
}

/// Classify an `INFO MEMORY` payload for retention-authority use.
///
/// Usable only when the server proves either unlimited memory (`maxmemory` is
/// present and `0`) or `noeviction`. A reported `allkeys-*` / `volatile-*`
/// policy with a non-zero limit (or with `maxmemory` absent, so a limit cannot
/// be disproven) is unsafe. Everything else is unproven.
pub fn classify_memory_info(info: &str) -> MemoryPolicyScreen {
    let (maxmemory, policy) = parse_memory_policy_fields(info);
    if maxmemory == Some(0) {
        return MemoryPolicyScreen::Usable;
    }
    if let Some(policy) = policy {
        if policy_is_noeviction(policy) {
            return MemoryPolicyScreen::Usable;
        }
        if policy_is_evicting(policy) {
            return MemoryPolicyScreen::UnsafeEviction;
        }
    }
    MemoryPolicyScreen::Unproven
}

fn memory_screen_from_info_value(value: &redis::Value) -> MemoryPolicyScreen {
    match value {
        redis::Value::BulkString(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => classify_memory_info(text),
            Err(_) => MemoryPolicyScreen::Unproven,
        },
        redis::Value::SimpleString(text) => classify_memory_info(text),
        redis::Value::VerbatimString { text, .. } => classify_memory_info(text),
        _ => MemoryPolicyScreen::Unproven,
    }
}

/// Ask a freshly topology-screened connection whether it will evict live keys,
/// under a hard `probe_timeout` deadline. Only clients that declare
/// [`RedisRetentionRequirement::NoEviction`] run it.
async fn screen_connection_memory_policy(
    conn: &mut impl redis::aio::ConnectionLike,
    probe_timeout: Duration,
) -> MemoryPolicyScreen {
    let mut probe = redis::cmd("INFO");
    probe.arg("MEMORY");
    match tokio::time::timeout(probe_timeout, probe.query_async::<redis::Value>(conn)).await {
        Ok(Ok(value)) => memory_screen_from_info_value(&value),
        Ok(Err(_error)) => MemoryPolicyScreen::Unproven,
        Err(_elapsed) => MemoryPolicyScreen::Unproven,
    }
}

/// Packed `(shared_authorities << 32) | shared_authorities_unavailable`.
///
/// Published on shared-replay lifecycle transitions and read by `/health`,
/// `/status`, and `/metrics/runtime` as a single acquire-load. The read path
/// has no registry to scan, no mutex, and no work proportional to configured
/// or historical authorities; writers serialize their transitions behind
/// [`SHARED_REPLAY_TRANSITION_LOCK`].
static SHARED_REPLAY_HEALTH: AtomicU64 = AtomicU64::new(0);

/// Serializes each registration's per-state transition with its corresponding
/// global packed-count update.
///
/// Registration, availability transitions, and Drop/retirement are all cold
/// (plugin commit, backend flap, config reload), while `/health`, `/status`,
/// and `/metrics/runtime` still read [`SHARED_REPLAY_HEALTH`] with a single
/// lock-free acquire-load. Holding this mutex across both the per-registration
/// word store and the packed delta closes the tear between them: a newer
/// transition cannot publish its delta before an older transition's delta (out
/// of epoch order), and a retired generation cannot resurrect because its
/// retirement delta and the competing transition are serialized.
static SHARED_REPLAY_TRANSITION_LOCK: Mutex<()> = Mutex::new(());

/// Test-only `armed`/`entered` pair for the apply pause gate below. `armed`
/// forces the pause; `entered` lets an external test observe deterministically
/// that a transition reached the tear point (and is therefore holding the
/// transition lock while its global delta is still unapplied).
static REPLAY_HEALTH_APPLY_PAUSE_ARMED: AtomicBool = AtomicBool::new(false);
static REPLAY_HEALTH_APPLY_PAUSE_ENTERED: AtomicUsize = AtomicUsize::new(0);

/// Pause an in-flight [`SharedReplayHealthRegistration`] transition exactly
/// between publishing its per-registration word and applying the global packed
/// delta — the tear point that [`SHARED_REPLAY_TRANSITION_LOCK`] closes.
///
/// Production never arms the gate and it is consulted only on the cold
/// transition path, so the lock-free read path is unaffected.
fn pause_shared_replay_apply_for_test() {
    if !REPLAY_HEALTH_APPLY_PAUSE_ARMED.load(Ordering::Acquire) {
        return;
    }
    REPLAY_HEALTH_APPLY_PAUSE_ENTERED.fetch_add(1, Ordering::AcqRel);
    while REPLAY_HEALTH_APPLY_PAUSE_ARMED.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
}

/// Arm the apply-pause gate, resetting the reached-tear-point counter. External
/// unit tests use this to deterministically reproduce the previously dangerous
/// transition/global-publish reordering.
#[doc(hidden)]
#[allow(dead_code)]
pub fn arm_shared_replay_apply_pause_for_test() {
    REPLAY_HEALTH_APPLY_PAUSE_ENTERED.store(0, Ordering::Release);
    REPLAY_HEALTH_APPLY_PAUSE_ARMED.store(true, Ordering::Release);
}

/// Disarm the apply-pause gate so a paused transition can proceed.
#[doc(hidden)]
#[allow(dead_code)]
pub fn disarm_shared_replay_apply_pause_for_test() {
    REPLAY_HEALTH_APPLY_PAUSE_ARMED.store(false, Ordering::Release);
}

/// Number of transitions currently (or previously) paused at the tear point.
#[doc(hidden)]
#[allow(dead_code)]
pub fn shared_replay_apply_pause_entered_for_test() -> usize {
    REPLAY_HEALTH_APPLY_PAUSE_ENTERED.load(Ordering::Acquire)
}

/// Whether the shared-replay transition lock is currently held. External tests
/// use this to prove a transition spans the tear point under the lock.
#[doc(hidden)]
#[allow(dead_code)]
pub fn shared_replay_transition_lock_held_for_test() -> bool {
    SHARED_REPLAY_TRANSITION_LOCK.try_lock().is_err()
}

const SHARED_REPLAY_COUNT_SHIFT: u64 = 32;
const SHARED_REPLAY_COUNT_MASK: u64 = 0xFFFF_FFFF;

/// Packed `(epoch << 8) | state` for availability and for the health
/// registration word. One acquire-load returns a consistent generation and
/// semantic state, so a stale registration sample cannot tear across a
/// concurrent transition.
const SHARED_REPLAY_EPOCH_SHIFT: u64 = 8;
const SHARED_REPLAY_STATE_MASK: u64 = 0xFF;

fn pack_epoch_state(state: u8, epoch: u64) -> u64 {
    (epoch << SHARED_REPLAY_EPOCH_SHIFT) | u64::from(state)
}

fn unpack_epoch_state(raw: u64) -> (u8, u64) {
    (
        (raw & SHARED_REPLAY_STATE_MASK) as u8,
        raw >> SHARED_REPLAY_EPOCH_SHIFT,
    )
}

fn pack_shared_replay_health(authorities: u64, unavailable: u64) -> u64 {
    (authorities << SHARED_REPLAY_COUNT_SHIFT) | (unavailable & SHARED_REPLAY_COUNT_MASK)
}

fn unpack_shared_replay_health(raw: u64) -> (u64, u64) {
    (
        raw >> SHARED_REPLAY_COUNT_SHIFT,
        raw & SHARED_REPLAY_COUNT_MASK,
    )
}

/// Current `(shared_authorities, shared_authorities_unavailable)` pair.
///
/// One acquire-load of the packed word published on registration, availability
/// transitions, terminal topology, and retirement. The `/health` + `/status`
/// probe path and `/metrics/runtime` both consume this exact pair.
pub(crate) fn shared_replay_health_counts() -> (u64, u64) {
    unpack_shared_replay_health(SHARED_REPLAY_HEALTH.load(Ordering::Acquire))
}

fn bump_shared_replay_health(authorities_delta: i8, unavailable_delta: i8) {
    let _ = SHARED_REPLAY_HEALTH.fetch_update(Ordering::AcqRel, Ordering::Acquire, |raw| {
        let (mut authorities, mut unavailable) = unpack_shared_replay_health(raw);
        match authorities_delta {
            1 => authorities = authorities.saturating_add(1),
            -1 => authorities = authorities.saturating_sub(1),
            _ => {}
        }
        match unavailable_delta {
            1 => unavailable = unavailable.saturating_add(1),
            -1 => unavailable = unavailable.saturating_sub(1),
            _ => {}
        }
        Some(pack_shared_replay_health(authorities, unavailable))
    });
}

/// Lifecycle registration for one distinct shared replay Redis client.
///
/// Holds only the local state machine that publishes into
/// [`SHARED_REPLAY_HEALTH`]. It does not retain the Redis client, cached
/// connections, endpoints, credentials, or any other secret-bearing data.
/// Drop retires this generation's contribution immediately.
///
/// Every transition (registration, availability change, Drop) runs its
/// per-registration `(epoch, state)` word update and its corresponding global
/// packed-count delta inside [`SHARED_REPLAY_TRANSITION_LOCK`]. The packed
/// `(epoch, state)` word still rejects a stale registration sample that cannot
/// overwrite a newer notification, and the lock guarantees those rejects are
/// evaluated in the same critical section as the delta, so a drop cannot
/// underflow, double-count, or resurrect a retired generation while another
/// transition is mid-publish.
struct SharedReplayHealthRegistration {
    /// Packed `(applied_epoch << 8) | state`.
    word: AtomicU64,
}

impl SharedReplayHealthRegistration {
    const UNREGISTERED: u8 = 0;
    const AVAILABLE: u8 = 1;
    const UNAVAILABLE: u8 = 2;
    const RETIRED: u8 = 3;

    fn new() -> Self {
        Self {
            word: AtomicU64::new(pack_epoch_state(Self::UNREGISTERED, 0)),
        }
    }

    /// Publish `available` at `epoch` if this is the first count or `epoch` is
    /// strictly newer than the last applied generation.
    ///
    /// Linearizability: [`EnforcementAvailability`] increments `epoch` in the
    /// same CAS that changes semantic state, and notifies with that new epoch
    /// after the health `Weak` is attached. A sample taken before a transition
    /// therefore carries a smaller epoch than the notification, and the epoch
    /// check below rejects it. Equivalent-provider re-registration is
    /// idempotent: the same epoch is a no-op. No resample loop is required, and
    /// this path never waits on backend flapping — a stale apply returns, a
    /// newer notify wins.
    ///
    /// The epoch check and the global packed delta run together inside
    /// [`SHARED_REPLAY_TRANSITION_LOCK`], so once a transition's word update
    /// wins, its delta is published before any newer (or retiring) transition
    /// can touch the shared word. Deltas therefore cannot execute out of epoch
    /// order and a retired registration cannot resurrect.
    fn apply_availability(&self, available: bool, epoch: u64) {
        let _guard = SHARED_REPLAY_TRANSITION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let target = if available {
            Self::AVAILABLE
        } else {
            Self::UNAVAILABLE
        };
        let raw = self.word.load(Ordering::Acquire);
        let (current_state, current_epoch) = unpack_epoch_state(raw);
        if current_state == Self::RETIRED {
            return;
        }
        if current_state != Self::UNREGISTERED && epoch <= current_epoch {
            return;
        }
        self.word
            .store(pack_epoch_state(target, epoch), Ordering::Release);
        pause_shared_replay_apply_for_test();
        match (current_state, target) {
            (Self::UNREGISTERED, Self::AVAILABLE) => bump_shared_replay_health(1, 0),
            (Self::UNREGISTERED, Self::UNAVAILABLE) => bump_shared_replay_health(1, 1),
            (Self::AVAILABLE, Self::UNAVAILABLE) => bump_shared_replay_health(0, 1),
            (Self::UNAVAILABLE, Self::AVAILABLE) => bump_shared_replay_health(0, -1),
            _ => {}
        }
    }

    fn is_live(&self) -> bool {
        let (state, _) = unpack_epoch_state(self.word.load(Ordering::Acquire));
        matches!(state, Self::AVAILABLE | Self::UNAVAILABLE)
    }
}

impl Drop for SharedReplayHealthRegistration {
    fn drop(&mut self) {
        // Serialize retirement against any in-flight apply so a concurrent
        // transition cannot publish its word or delta after we have already
        // subtracted, and cannot resurrect this generation.
        let _guard = SHARED_REPLAY_TRANSITION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Swap to RETIRED first so a concurrent apply's store cannot land
        // after we have already subtracted, and cannot resurrect this
        // generation.
        let (previous, _) = unpack_epoch_state(
            self.word
                .swap(pack_epoch_state(Self::RETIRED, 0), Ordering::AcqRel),
        );
        match previous {
            Self::AVAILABLE => bump_shared_replay_health(-1, 0),
            Self::UNAVAILABLE => bump_shared_replay_health(-1, -1),
            _ => {}
        }
    }
}

/// Availability of centralized enforcement for one Redis client generation,
/// shared with the client's recovery checker and with failover health observers.
///
/// Deliberately **one** packed atomic rather than an `available: AtomicBool`
/// plus a separate `topology_unsupported: AtomicBool`. With two flags, every
/// "reachable" publication is a check-then-store: a connection, command, or
/// recovery probe that completed successfully can observe a not-yet-terminal
/// topology, then store `available = true` after another task proved Cluster
/// topology — resurrecting enforcement that must stay dead, and making a
/// failover observer advertise a false recovery. Folding both into one state
/// makes publishing "reachable" a single read-modify-write that simply cannot
/// win against a rejection, so terminal really is terminal.
///
/// The same word also carries a monotonic epoch, incremented in the CAS that
/// changes semantic state. Shared-replay registration samples that pair in one
/// load and fences stale applies against notifications of a later epoch, so a
/// bounded resample loop cannot leave `/health` permanently inconsistent with
/// this word.
///
/// Every read is one atomic load, so hot-path callers keep their O(1) check with
/// no locks. Shared-replay health is notified only on a real state change, via
/// a `Weak` handle that cannot keep a retired client (or its credentials)
/// alive.
pub(crate) struct EnforcementAvailability {
    /// Packed `(epoch << 8) | state`. Hot-path [`Self::is_available`] masks
    /// the low byte of one acquire-load.
    state: AtomicU64,
    /// Weak: the recovery checker holds this `Arc<EnforcementAvailability>`,
    /// and must not retain a retired generation's health contribution.
    shared_replay_health: OnceLock<Weak<SharedReplayHealthRegistration>>,
}

impl EnforcementAvailability {
    /// Reachable: enforcement may be consulted.
    const REACHABLE: u8 = 0;
    /// Unreachable, but recoverable — the recovery checker may clear this.
    const UNREACHABLE: u8 = 1;
    /// Proven to be an unsupported topology. Sticky for this generation.
    const TOPOLOGY_TERMINAL: u8 = 2;

    fn new() -> Self {
        Self::with_state(Self::REACHABLE)
    }

    /// Unproven: no connection or topology screen has succeeded.
    ///
    /// Replay-authority clients start here so `/health` fails closed until a
    /// screened probe proves the backend. Operational rate-limiter clients keep
    /// [`Self::new`] (historical "reachable until an error is observed").
    fn unproven() -> Self {
        Self::with_state(Self::UNREACHABLE)
    }

    fn with_state(state: u8) -> Self {
        Self {
            state: AtomicU64::new(pack_epoch_state(state, 0)),
            shared_replay_health: OnceLock::new(),
        }
    }

    fn semantic_state(raw: u64) -> u8 {
        unpack_epoch_state(raw).0
    }

    fn notify_shared_replay_health(&self, available: bool, epoch: u64) {
        let Some(weak) = self.shared_replay_health.get() else {
            return;
        };
        let Some(registration) = weak.upgrade() else {
            return;
        };
        registration.apply_availability(available, epoch);
    }

    /// Semantic availability: enforcement may be consulted. False whenever the
    /// topology is terminal, by construction — a caller cannot forget to pair
    /// this load with a separate terminal check.
    pub(crate) fn is_available(&self) -> bool {
        Self::semantic_state(self.state.load(Ordering::Acquire)) == Self::REACHABLE
    }

    /// Whether the endpoint was rejected as an unsupported topology.
    fn is_topology_terminal(&self) -> bool {
        Self::semantic_state(self.state.load(Ordering::Acquire)) == Self::TOPOLOGY_TERMINAL
    }

    /// One acquire-load of `(is_available, epoch)` for shared-replay
    /// registration. The pair is consistent because epoch and semantic state
    /// live in the same word.
    fn health_snapshot(&self) -> (bool, u64) {
        let (state, epoch) = unpack_epoch_state(self.state.load(Ordering::Acquire));
        (state == Self::REACHABLE, epoch)
    }

    /// Atomically move to `target` unless the topology is already terminal.
    ///
    /// Returns the previous semantic state and the epoch stored in the word
    /// afterwards. A real change increments the epoch in the same CAS that
    /// writes `target`, which is what makes a later registration sample of the
    /// old state strictly stale against the notification. `None` means the
    /// topology is (or concurrently became) terminal and nothing was written.
    fn transition_unless_terminal(&self, target: u8) -> Option<(u8, u64)> {
        loop {
            let raw = self.state.load(Ordering::Acquire);
            let (current, epoch) = unpack_epoch_state(raw);
            if current == Self::TOPOLOGY_TERMINAL {
                return None;
            }
            if current == target {
                return Some((current, epoch));
            }
            let new_epoch = epoch.wrapping_add(1);
            if self
                .state
                .compare_exchange(
                    raw,
                    pack_epoch_state(target, new_epoch),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some((current, new_epoch));
            }
        }
    }

    /// Publish "reachable" — but only if the topology is not terminal.
    ///
    /// Returns `false` when the state is (or concurrently became) terminal, in
    /// which case nothing was written. Callers treat `false` as a failed
    /// operation: a command that already mutated Redis is reported as an error
    /// so the consumer's failure policy applies, because over-counting one
    /// operation is safer than admitting traffic against a topology this client
    /// cannot enforce on. A terminal state cannot resurrect shared-replay
    /// health: this path never notifies "available" after a topology rejection.
    fn publish_reachable(&self) -> bool {
        match self.transition_unless_terminal(Self::REACHABLE) {
            Some((previous, epoch)) => {
                if previous != Self::REACHABLE {
                    self.notify_shared_replay_health(true, epoch);
                }
                true
            }
            None => false,
        }
    }

    /// Mark enforcement unreachable, preserving a terminal topology rejection.
    fn mark_unreachable(&self) {
        if let Some((Self::REACHABLE, epoch)) = self.transition_unless_terminal(Self::UNREACHABLE) {
            self.notify_shared_replay_health(false, epoch);
        }
    }

    /// Reject the endpoint permanently. Returns `true` the first time only, so
    /// the operator diagnostic is emitted once per client generation rather than
    /// once per request. Reachable → terminal publishes unavailable exactly
    /// once; an already-unavailable generation is already counted. The epoch
    /// still advances from unreachable so a stale reachable sample cannot
    /// overwrite the terminal word.
    fn reject_topology(&self) -> bool {
        loop {
            let raw = self.state.load(Ordering::Acquire);
            let (previous, epoch) = unpack_epoch_state(raw);
            if previous == Self::TOPOLOGY_TERMINAL {
                return false;
            }
            let new_epoch = epoch.wrapping_add(1);
            if self
                .state
                .compare_exchange(
                    raw,
                    pack_epoch_state(Self::TOPOLOGY_TERMINAL, new_epoch),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            if previous == Self::REACHABLE {
                self.notify_shared_replay_health(false, new_epoch);
            }
            return true;
        }
    }

    /// Log-safe rendering for `Debug` (never carries endpoint or credentials).
    fn describe(&self) -> &'static str {
        match Self::semantic_state(self.state.load(Ordering::Acquire)) {
            Self::REACHABLE => "reachable",
            Self::TOPOLOGY_TERMINAL => "topology_unsupported",
            _ => "unreachable",
        }
    }
}

/// One lazily-established [`redis::aio::MultiplexedConnection`] slot in the pool.
///
/// Hot-path reads are lock-free via [`ArcSwap`]. Slow-path establishment is
/// serialized per slot so distinct slots can connect in parallel without a
/// global mutex, while same-slot racers still double-check under the lock.
///
/// The stored type must stay a non-reconnecting multiplexed connection: a
/// [`redis::aio::ConnectionManager`] would replace its physical socket inside
/// redis-rs, publishing an unscreened connection into this cache.
struct ConnectionSlot {
    connection: ArcSwap<Option<redis::aio::MultiplexedConnection>>,
    connect_mutex: tokio::sync::Mutex<()>,
}

/// The bounded pool of cached connections, split out of
/// [`RedisRateLimitClient`] so a background task can be handed *only* the
/// ability to drop cached sockets.
///
/// The background recovery checker can prove an unsupported Cluster topology on
/// its own. Rejecting the topology while previously cached slots stay retained
/// would keep sockets to a refused endpoint open until the whole client
/// generation drops, so the checker needs to clear the pool — but it must not
/// keep the client, its endpoint credentials, or any unrelated state alive. It
/// therefore holds a [`std::sync::Weak`] to this holder and nothing else: no
/// strong reference, so a retired generation is still released promptly, and
/// the client's `Drop` still aborts the task.
struct ConnectionPool {
    slots: Box<[ConnectionSlot]>,
    /// Round-robin counter for deterministic, low-overhead slot selection.
    /// `fetch_add` + `% slots.len()` — no locks, no hashing on the hot path.
    next_slot: AtomicUsize,
}

impl ConnectionPool {
    fn new(size: usize) -> Self {
        Self {
            slots: (0..size.max(1))
                .map(|_| ConnectionSlot {
                    connection: ArcSwap::from_pointee(None),
                    connect_mutex: tokio::sync::Mutex::new(()),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            next_slot: AtomicUsize::new(0),
        }
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Drop every cached connection. Lock-free stores only — the hot path's
    /// `ArcSwap` reads are unaffected, and a slot being established concurrently
    /// re-screens before it can publish.
    fn clear(&self) {
        for slot in self.slots.iter() {
            slot.connection.store(Arc::new(None));
        }
    }
}

/// Outcome of a size-bounded Redis fetch ([`RedisRateLimitClient::get_bytes_bounded`]).
#[derive(Debug)]
pub enum BoundedRedisValue {
    /// Key is absent.
    Missing,
    /// Key exists but holds an empty value. Callers must quarantine rather than
    /// treating this as a permanent miss that leaves the empty key in place.
    Empty,
    /// Value present and within the requested byte cap.
    Found(Vec<u8>),
    /// Value present but its true length exceeds the cap; only a bounded prefix
    /// was transferred. Callers should treat it as invalid and quarantine it.
    Oversized { length: usize },
}

/// Why a Redis `GETRANGE` inclusive end index cannot be derived from a byte cap.
///
/// Callers must fail closed on either variant: Redis treats a negative end as
/// "read to the end of the string", so an unrepresentable or zero cap must never
/// be cast into a sentinel that would transfer an attacker-controlled value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisGetrangeEndIndexError {
    /// Cap was zero (no positive inclusive end index).
    ZeroCap,
    /// Cap cannot be represented as a non-negative `isize` on this platform.
    Overflow,
}

/// Convert a Redis `GETRANGE` inclusive end index from a byte cap.
///
/// Redis treats a negative end index as an offset from the end of the string
/// (`-1` = last byte / whole value). Casting an unbounded `usize` cap with
/// `as isize` can therefore saturate to `-1` and ask Redis for the entire
/// attacker-controlled value. Fail closed before dispatch when the cap cannot
/// be represented as a non-negative `isize`.
pub fn redis_getrange_end_index(max_bytes: usize) -> Result<isize, RedisGetrangeEndIndexError> {
    if max_bytes == 0 {
        return Err(RedisGetrangeEndIndexError::ZeroCap);
    }
    isize::try_from(max_bytes).map_err(|_| RedisGetrangeEndIndexError::Overflow)
}

/// A Redis-backed limiter/store client shared across plugin instances.
///
/// Provides atomic counter and key-value operations using native Redis commands
/// (no Lua scripts). It does NOT fall back on its own: an unreachable endpoint
/// simply reports unavailable, and each consumer's `redis_failure_policy` (or
/// `request_deduplication`'s `on_redis_unavailable`) decides between failing
/// closed and an explicit local fallback (`rate_limiting` defaults to the
/// fallback; every other consumer defaults to failing closed).
///
/// When a `DnsCache` is provided, Redis hostnames are resolved through the
/// gateway's shared DNS cache. On any connection or command failure, every pool
/// slot is cleared so the next attempt re-resolves DNS (handling IP changes
/// gracefully), re-screens egress, and re-runs the `INFO CLUSTER` topology
/// screen before a command can reach the new socket.
pub struct RedisRateLimitClient {
    /// Bounded pool of non-reconnecting multiplexed connections
    /// (`redis_pool_size`). Each slot is established lazily on first selection
    /// and only through the screened establishment path.
    ///
    /// Held behind an `Arc` so the background recovery checker can be given a
    /// `Weak` handle to it — enough to drop cached sockets when it proves an
    /// unsupported topology, and nothing more.
    pool: Arc<ConnectionPool>,
    /// Configuration for connecting to Redis.
    config: RedisConfig,
    /// The gateway's shared DNS cache for resolving Redis hostnames.
    dns_cache: Option<DnsCache>,
    /// Whether centralized enforcement is reachable, and whether the configured
    /// endpoint was proven to be an unsupported topology (Redis Cluster).
    ///
    /// One atomic so a topology rejection is terminal even when a successful
    /// connection, command, or recovery probe completes concurrently: a Cluster
    /// node answers `PING` while still redirecting every key, so nothing may
    /// restore availability afterwards. See [`EnforcementAvailability`].
    ///
    /// Replay-authority clients start **unproven** (unreachable) until a
    /// topology-screened connection or recovery probe succeeds. Operational
    /// rate-limiter clients keep the historical initial reachable state.
    availability: Arc<EnforcementAvailability>,
    /// Whether the background health checker has been started.
    health_checker_started: AtomicBool,
    /// Abort handle for the background recovery checker (set once on start).
    health_checker_abort: Mutex<Option<AbortHandle>>,
    /// Gateway-level TLS no-verify setting (`FERRUM_TLS_NO_VERIFY`).
    tls_no_verify: bool,
    /// Pre-read exclusive CA bundle PEM bytes from `FERRUM_TLS_CA_BUNDLE_PATH`.
    ///
    /// Loaded once at construction so the main connect path and the background
    /// health-check reconnect share the same trust policy. `None` means no
    /// exclusive CA was configured, or verification is skipped via
    /// `FERRUM_TLS_NO_VERIFY`. A configured path that failed to load never
    /// produces this client — construction fails closed instead of storing
    /// `None` and falling back to default roots.
    tls_ca_bundle_pem: Option<Vec<u8>>,
    /// How this client publishes operational diagnostics.
    ///
    /// Rate-limit / cache / dedup consumers keep historical fields (`error`,
    /// `key_prefix`). Replay-authority clients publish only a fixed
    /// classification beside the already-redacted endpoint.
    log_policy: RedisClientLogPolicy,
    /// Whether this client must prove the endpoint will not evict live keys.
    ///
    /// Deliberately independent of [`RedisClientLogPolicy`]: the diagnostic
    /// posture and the retention prerequisite are different questions, and
    /// `request_deduplication` needs the second without the first
    /// (`GHSA-26gf-943w-w5x8`).
    retention: RedisRetentionRequirement,
    /// Whether this client's consumer selects sub-buckets on the Redis server's
    /// clock, and therefore whether a connection must prove `TIME` before it is
    /// published.
    ///
    /// Chosen by the constructor the consumer calls, because it is a property
    /// of what the consumer computes rather than of the endpoint: only
    /// request-quota admission
    /// ([`Self::charge_rate_limit_windows`]) orders one budget across gateways
    /// on the server clock. A replay, idempotency, cache, or token-accounting
    /// consumer reads no clock at all, so requiring `+time` of it would refuse
    /// deployments that are perfectly safe.
    server_clock_requirement: ServerClockRequirement,
    /// Lifecycle registration for shared-replay readiness/metrics. Present
    /// only after [`Self::register_as_shared_replay_authority`]; independent of
    /// connections, endpoints, and credentials. Drop of this client drops the
    /// registration and retires the precomputed counts immediately.
    shared_replay_health: OnceLock<Arc<SharedReplayHealthRegistration>>,
    /// Detached rate-limit compensations issued but not yet completed.
    ///
    /// Bounded by the in-flight refusals of this client's policies. Read only
    /// by coverage that must observe a hand-back landing instead of racing it;
    /// admission never reads it.
    pending_compensations: AtomicUsize,
    /// The shared bucket clock: this endpoint's server clock, tracked as a
    /// correction to the local one.
    ///
    /// Owned by the client rather than by a caller because it is a property of
    /// the endpoint, not of one policy: every window, every plugin instance,
    /// and every pooled connection sharing this client must select buckets on
    /// the same clock, or they would count one identity against two ladders.
    server_clock: RedisServerClock,
}

/// Logging policy for one Redis client.
///
/// The single-use replay authority must never publish raw backend text, key
/// material, marker material, credentials, or the operator key prefix. Generic
/// rate-limiter clients retain their existing operational diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RedisClientLogPolicy {
    Operational,
    ClassificationOnly,
}

/// Whether a client's retained records may be evicted by the server.
///
/// Availability and atomic ownership transitions do not establish that an
/// acknowledged record survives its lease: an `allkeys-*` / `volatile-*` Redis
/// under memory pressure drops live keys, TTL or not. For a limiter or a cache
/// that only degrades a budget or forces a miss; for an idempotency or
/// single-use authority the record *is* the control, so a silent eviction lets
/// a retried non-idempotent operation execute twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RedisRetentionRequirement {
    /// Counters and caches: eviction degrades accuracy, never correctness.
    BestEffort,
    /// The retained record is the control. Every connection must prove
    /// `maxmemory == 0` or `maxmemory_policy == noeviction` before it may carry
    /// a command, and a proven evicting endpoint is terminal.
    NoEviction,
}

/// Whether a client's consumer selects sub-buckets on the Redis server's clock.
///
/// `TIME` is a hard requirement for the consumers that do — a ladder selected
/// on an uncorrected local clock is not a shared budget — but it is a
/// requirement of the *computation*, not of the socket. Request-quota admission
/// charges a sub-bucket ladder that every gateway must agree on; a replay or
/// idempotency authority claims a marker with `SET NX EX`, a cache stores a
/// blob, and the token-accounting limiters reserve under a window index they
/// compute locally. None of those read the clock, so a restrictive ACL that
/// withholds `+time` must not take them out of service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerClockRequirement {
    /// Request-quota admission. Every established connection proves `TIME`
    /// during screening ([`RedisRateLimitClient::probe_server_time`]) and every
    /// charge transaction queues one.
    Required,
    /// The consumer never reads the server clock. No probe runs, and
    /// [`RedisRateLimitClient::charge_rate_limit_windows`] refuses outright.
    NotUsed,
}

/// Why an endpoint is permanently refused for this client generation.
///
/// Both faults are configuration, not outage: no amount of recovery pinging
/// can make the next policy operation correct, so they latch through
/// [`EnforcementAvailability::reject_topology`] and the consumer's failure
/// policy governs from there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EndpointTerminalFault {
    /// The server reports Redis Cluster topology.
    UnsupportedTopology,
    /// The server proves an evicting `maxmemory` policy under a memory limit.
    UnsafeEviction,
}

impl EndpointTerminalFault {
    /// Fixed classification published beside the redacted endpoint. Closed set,
    /// never interpolated from backend text.
    fn classification(self) -> &'static str {
        match self {
            Self::UnsupportedTopology => "unsupported_topology",
            Self::UnsafeEviction => "unsafe_eviction_policy",
        }
    }
}

/// Classification-only diagnostic for a Redis client owned by the replay
/// authority. Never interpolates backend text, keys, prefixes, or credentials.
fn warn_replay_backend(redacted_url: &str, classification: &'static str, message: &'static str) {
    warn!(
        redis_url = %redacted_url,
        classification,
        "{message}"
    );
}

/// Terminal no-eviction rejection. Operational clients keep the historical
/// `key_prefix` + `reason` fields; replay clients publish only the fixed
/// classification beside the redacted endpoint.
fn warn_unsafe_eviction(
    redacted_url: &str,
    key_prefix: &str,
    reason: &str,
    log_policy: RedisClientLogPolicy,
) {
    match log_policy {
        RedisClientLogPolicy::Operational => {
            warn!(
                redis_url = %redacted_url,
                key_prefix = %key_prefix,
                reason,
                "Redis endpoint reports an evicting maxmemory policy and cannot retain \
                 idempotency records for their full lease — centralized Redis access is \
                 disabled for this configuration until the endpoint is set to noeviction"
            );
        }
        RedisClientLogPolicy::ClassificationOnly => {
            warn_replay_backend(
                redacted_url,
                EndpointTerminalFault::UnsafeEviction.classification(),
                "Redis single-use claim failed",
            );
        }
    }
}

/// Terminal Cluster rejection. Operational clients keep the historical
/// `key_prefix` + `reason` fields; replay clients publish only the fixed
/// classification beside the redacted endpoint.
fn warn_topology_unsupported(
    redacted_url: &str,
    key_prefix: &str,
    reason: &str,
    log_policy: RedisClientLogPolicy,
) {
    match log_policy {
        RedisClientLogPolicy::Operational => {
            warn!(
                redis_url = %redacted_url,
                key_prefix = %key_prefix,
                reason,
                "Redis endpoint reports an unsupported topology (Redis Cluster is not supported) \
                 — centralized Redis access is disabled for this configuration until it is changed"
            );
        }
        RedisClientLogPolicy::ClassificationOnly => {
            warn_replay_backend(
                redacted_url,
                "unsupported_topology",
                "Redis single-use claim failed",
            );
        }
    }
}

/// Pure floor-at-zero decision for [`RedisRateLimitClient::incrby_with_expire_floor_zero`].
///
/// Given the value observed after the primary `INCRBY`, return the compensating
/// `INCRBY` delta needed to bring the counter back up to exactly zero, or `None`
/// when the value is already non-negative (no compensation needed). The
/// compensation is exactly `-new_total` so the corrective write fails only in
/// the conservative (over-count) direction if a concurrent increment raced
/// between our write and read — a rate limiter must never under-count usage.
///
/// Extracted as a free function so the floor logic is unit-testable without a
/// live Redis server (the surrounding method is pure I/O).
fn floor_zero_compensation(new_total: i64) -> Option<i64> {
    if new_total >= 0 {
        None
    } else {
        Some(new_total.saturating_neg())
    }
}

/// Clamp the post-compensation total so callers never observe a negative usage,
/// even if a concurrent decrement drove the counter back below zero between the
/// compensating write and its read-back.
fn clamp_floored_total(floored: i64) -> i64 {
    floored.max(0)
}

/// Captured `(available, epoch)` pair from
/// [`RedisRateLimitClient::capture_shared_replay_registration_sample_for_test`].
///
/// Used to deterministically replay a stale registration apply after a newer
/// availability notification. The epoch is opaque so tests cannot forge a
/// newer generation than the one they sampled.
#[derive(Clone, Copy, Debug)]
pub struct SharedReplayRegistrationSample {
    available: bool,
    epoch: u64,
}

impl SharedReplayRegistrationSample {
    /// Whether this sample observed a reachable backend.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn available(self) -> bool {
        self.available
    }
}

/// Load the exclusive Redis TLS CA bundle, or `None` when the operator named
/// no custom CA (or disabled verification).
///
/// `FERRUM_TLS_CA_BUNDLE_PATH` is exclusive: a client built after a failed
/// load would verify against redis-rs's default (system/public) roots, which
/// is a weaker trust policy than the one configured. Fail closed instead of
/// warning-and-continuing. Both `build_client` and the background health-check
/// reconnect consume the bytes stored on the client, so neither can reopen a
/// downgraded connection later.
///
/// When `tls_no_verify` is set (`FERRUM_TLS_NO_VERIFY`), verification is
/// already off by explicit operator choice. The CA is unused on that path
/// (Ferrum appends `#insecure` internally), so an unloadable bundle is not a
/// construction error — matching `PluginHttpClient`'s skip-verify posture.
/// Do not load the file just to discard it, and do not change that sanctioned
/// path's semantics.
fn load_redis_tls_ca_bundle(
    tls_no_verify: bool,
    tls_ca_bundle_path: Option<&str>,
) -> Result<Option<Vec<u8>>, String> {
    if tls_no_verify {
        return Ok(None);
    }
    let Some(path) = tls_ca_bundle_path else {
        return Ok(None);
    };
    let source = CertSource::parse(path, MaterialKind::CaBundle);
    match load_material_blocking(&source, MaterialKind::CaBundle) {
        Ok(material) => Ok(Some(material.bytes.expose_secret().to_vec())),
        Err(error) => Err(format!(
            "redis rate limiter: failed to load exclusive CA bundle; \
             refusing to fall back to default TLS roots: {error}"
        )),
    }
}

/// Interpret the semantic reply to the replay authority's `SET ... NX EX`.
///
/// Redis returns exactly `OK` when it stored the marker and a nil reply when
/// `NX` found an existing marker. Any other string is an invalid claim reply:
/// treating mere string presence as success would let a malformed or
/// non-conforming backend admit a request without proving that the marker was
/// persisted.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySetNxReplyError {
    InvalidClaimReply,
}

#[doc(hidden)]
pub fn classify_replay_set_nx_reply(reply: Option<&str>) -> Result<bool, ReplaySetNxReplyError> {
    match reply {
        Some("OK") => Ok(true),
        None => Ok(false),
        Some(_) => Err(ReplaySetNxReplyError::InvalidClaimReply),
    }
}

/// The sub-bucket counters of ONE configured rate-limit window: the `K + 1`
/// older buckets the decision reads, the bucket this charge increments, and the
/// one bucket AFTER it that the decision also reads (see
/// [`REDIS_WINDOW_SUB_BUCKET_KEYS`] for why both extra counters are there).
///
/// The `K + 3` keys are packed end to end into a SINGLE allocation instead of
/// one `String` each. Admission is a proxy hot path, and the retired two-bucket
/// layout already paid two allocations per window here, so widening the ladder
/// to [`REDIS_WINDOW_SUB_BUCKET_KEYS`] keys costs strictly fewer allocations
/// than it replaces. Every key carries the same
/// `{escaped-prefix:escaped-rate-key}` hash tag (see
/// [`RedisRateLimitClient::make_slot_key`]), so a charge covering several
/// windows is still a single-slot transaction.
///
/// The TTL is per window rather than one value for the whole charge: a policy
/// mixing a one-second and a one-hour window would otherwise retain every
/// per-second counter for the longest window's lifetime, which grows the key
/// space with the request rate instead of with the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedisWindowCharge {
    /// `{tag}:{window_seconds}:{sub_index}` keys, packed oldest first: the
    /// `K + 1` older buckets, then the charged bucket, then the one after it.
    keys: String,
    /// `(start, end)` byte range of each key inside [`Self::keys`].
    ///
    /// Both ends are `keys.len()` snapshots taken around one whole key in
    /// [`RedisRateLimitClient::window_charge`], so every range is UTF-8 aligned
    /// by construction. That is the invariant the accessors slice on.
    ranges: [(usize, usize); REDIS_WINDOW_SUB_BUCKET_KEYS],
    /// Previous/current keys used by pre-sub-bucket releases.  New releases
    /// keep charging these counters so a rolling deployment has one shared
    /// budget rather than one budget per key-layout generation.
    legacy_ranges: [(usize, usize); 2],
    /// Retention asserted on [`Self::charged_key`] by both transactions.
    ttl_seconds: u64,
    /// The sub-bucket this charge selected, kept so the caller can judge after
    /// `EXEC` whether the ladder is still usable
    /// ([`sub_bucket_charge_is_settled`]).
    bucket: RedisSubBucket,
}

impl RedisWindowCharge {
    /// The `K + 1` older sub-bucket counters, oldest first; read, never
    /// written. The oldest of them is one sub-bucket further back than the
    /// window itself — see [`REDIS_WINDOW_TRAILING_SUB_BUCKETS`].
    pub fn trailing_keys(&self) -> impl Iterator<Item = &str> {
        let keys = self.keys.as_str();
        self.ranges[..REDIS_WINDOW_TRAILING_SUB_BUCKETS]
            .iter()
            .map(move |(start, end)| &keys[*start..*end])
    }

    /// The sub-bucket counter this charge increments, and the ONLY key its
    /// compensation decrements.
    pub fn charged_key(&self) -> &str {
        let (start, end) = self.ranges[REDIS_WINDOW_TRAILING_SUB_BUCKETS];
        &self.keys[start..end]
    }

    /// The sub-bucket immediately AFTER the charged one; read, never written.
    ///
    /// Empty unless a peer's transaction that selected the next bucket reached
    /// the server first, or a peer's clock runs ahead of this one. Reading it
    /// is what makes the pair of decisions order-independent; see
    /// [`REDIS_WINDOW_SUB_BUCKET_KEYS`].
    pub fn next_key(&self) -> &str {
        let (start, end) = self.ranges[REDIS_WINDOW_TRAILING_SUB_BUCKETS + 1];
        &self.keys[start..end]
    }

    /// Previous whole-window key retained for mixed-version enforcement.
    pub fn legacy_previous_key(&self) -> &str {
        let (start, end) = self.legacy_ranges[0];
        &self.keys[start..end]
    }

    /// Current whole-window key retained for mixed-version enforcement.
    pub fn legacy_current_key(&self) -> &str {
        let (start, end) = self.legacy_ranges[1];
        &self.keys[start..end]
    }

    /// Whether the server executed in the whole-window bucket whose legacy
    /// counter this charge selected. A rollover rebuild is required otherwise.
    pub fn legacy_bucket_is_settled(&self, now: Duration) -> bool {
        let window_nanos =
            (self.bucket.window_seconds.max(1) as u128).saturating_mul(1_000_000_000);
        let server_index = now.as_nanos() / window_nanos;
        server_index == (self.bucket.index / REDIS_WINDOW_SUB_BUCKETS as u64) as u128
    }

    /// Retention asserted on [`Self::charged_key`] by both transactions.
    pub fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// The sub-bucket this charge selected, for the post-`EXEC` staleness
    /// judgement in [`sub_bucket_charge_is_settled`].
    pub fn bucket(&self) -> RedisSubBucket {
        self.bucket
    }
}

/// Hard ceiling on the windows one atomic rate-limit charge may cover.
///
/// Three is the widest shape the HTTP-family limiters produce: `rate_limiting`
/// presets top out at per-second + per-minute + per-hour, and `graphql` and
/// `grpc_method_router` are single-window. The bound lives on the transaction
/// helpers themselves — not only in each caller's config validation — so a
/// caller whose own bound is relaxed, bypassed, or newly added cannot silently
/// widen an atomic operation past the fixed-capacity buffers the admission hot
/// path is built on. Over the ceiling both helpers fail closed.
pub const MAX_REDIS_ADMISSION_WINDOWS: usize = 3;

/// Fixed-capacity inline list of the windows one atomic charge covers.
///
/// The admission path is a proxy hot path, so the per-request window list is
/// carried inline rather than in a `Vec`: at most [`MAX_REDIS_ADMISSION_WINDOWS`]
/// entries by construction, and therefore at most
/// `MAX_REDIS_ADMISSION_WINDOWS * REDIS_WINDOW_SUB_BUCKET_KEYS` keys in one
/// transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedisWindowCharges {
    charges: [RedisWindowCharge; MAX_REDIS_ADMISSION_WINDOWS],
    len: usize,
}

impl RedisWindowCharges {
    /// Append one window, or report that the fixed capacity is full.
    ///
    /// `false` is a fail-closed signal, never a silent truncation: charging a
    /// subset of the configured windows would admit against a budget nobody
    /// configured.
    pub fn push(&mut self, charge: RedisWindowCharge) -> bool {
        if self.len >= MAX_REDIS_ADMISSION_WINDOWS {
            return false;
        }
        self.charges[self.len] = charge;
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[RedisWindowCharge] {
        &self.charges[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Per-window trailing-window counts returned by one
/// [`RedisRateLimitClient::charge_rate_limit_windows`]: for each configured
/// window, the FULL sum of the sub-bucket this request charged, the `K`
/// sub-buckets before it, and the one after it.
///
/// The fold happens here rather than at the caller so the decision surface is
/// one number per window and no caller can reintroduce a decay term on its own.
/// Held inline for the same reason as [`RedisWindowCharges`]: the reply is
/// bounded by [`MAX_REDIS_ADMISSION_WINDOWS`], so the decision the caller reads
/// off it costs no allocation of its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedisWindowCounts {
    counts: [u64; MAX_REDIS_ADMISSION_WINDOWS],
    len: usize,
}

impl RedisWindowCounts {
    /// Append one window's trailing count. `false` when capacity is full.
    fn push(&mut self, trailing_count: u64) -> bool {
        if self.len >= MAX_REDIS_ADMISSION_WINDOWS {
            return false;
        }
        self.counts[self.len] = trailing_count;
        self.len += 1;
        true
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.counts[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Everything one atomic charge transaction told the caller: each configured
/// window's trailing-window count, and the instant the SERVER applied the
/// transaction.
///
/// The two travel together because a count is only meaningful paired with the
/// instant its ladder was built for. Judging settlement on a separate local
/// sample taken after the reply arrived conflated reply latency (harmless — a
/// later peer reads this request's own increment) with execution latency (the
/// actual hazard), and it reintroduced the local clock into a decision the
/// whole sub-bucket layout exists to take on one shared clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RedisChargeOutcome {
    counts: RedisWindowCounts,
    settled_at: Option<Duration>,
}

impl RedisChargeOutcome {
    /// Per-window trailing counts, in the order the windows were charged.
    pub fn as_slice(&self) -> &[u64] {
        self.counts.as_slice()
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// The Redis server's own clock at `EXEC`, from the `TIME` that rode inside
    /// this transaction.
    ///
    /// `None` only for a charge over an EMPTY window list, which performs no
    /// transaction at all. Every real charge carries the sample, because a
    /// connection that could not answer `TIME` is never published.
    pub fn settled_at(&self) -> Option<Duration> {
        self.settled_at
    }
}

/// Completion handle for a detached compensation.
///
/// The spawned task owns the compensation outright, so dropping this handle
/// never cancels it: a quota refusal drops it and pays no second round trip
/// inline, exactly as before. The staleness rebuild is the one caller that
/// AWAITS it, because the rebuilt ladder reads the sub-bucket the abandoned
/// pass charged — dispatching the hand-back is not the same as landing it, and
/// a rebuild that raced ahead of its own `DECR` would count that abandoned
/// charge and refuse a request the quota admits.
pub struct RedisCompensationHandle {
    /// `None` when there was nothing to compensate.
    completed: Option<tokio::sync::oneshot::Receiver<bool>>,
}

impl RedisCompensationHandle {
    /// Nothing was charged, so nothing is outstanding.
    fn resolved() -> Self {
        Self { completed: None }
    }

    /// Whether the hand-back's `DECR` actually landed.
    ///
    /// Bounded by the same screened per-command deadline every other Redis
    /// command on this path carries, so a store that went silent cannot hold an
    /// admission decision open. `false` means the charge is still on its
    /// windows and the caller must not build a ladder that reads them.
    pub async fn confirmed(self) -> bool {
        let Some(completed) = self.completed else {
            return true;
        };
        // Without a Tokio runtime the compensation already ran inline, so the
        // value is waiting; `tokio::time::timeout` needs a timer driver and
        // must not be reached there.
        if tokio::runtime::Handle::try_current().is_err() {
            return completed.await.unwrap_or(false);
        }
        let bound = SCREENED_COMMAND_RESPONSE_TIMEOUT;
        match tokio::time::timeout(bound, completed).await {
            // A dropped sender cannot happen (the task always sends), but it
            // would mean the hand-back's fate is unknown — same answer.
            Ok(landed) => landed.unwrap_or(false),
            Err(_elapsed) => false,
        }
    }
}

impl RedisRateLimitClient {
    /// Create a new Redis rate limit client.
    ///
    /// The connection is established lazily on first use to avoid blocking
    /// the plugin constructor (which is synchronous).
    ///
    /// TLS settings are inherited from the gateway's global configuration
    /// (`FERRUM_TLS_CA_BUNDLE_PATH`, `FERRUM_TLS_NO_VERIFY`) so all outbound
    /// connections share a single CA trust chain.
    ///
    /// When `dns_cache` is provided, Redis hostnames are resolved through the
    /// gateway's shared DNS cache instead of the system resolver.
    ///
    /// Returns `Err` when a CA bundle path is configured, verification is
    /// enabled, and the bundle cannot be loaded. That is fail-closed exclusive
    /// trust: the client is never built against redis-rs default roots.
    ///
    /// The consumer is assumed NOT to read the Redis server clock, so no `TIME`
    /// probe runs and [`Self::charge_rate_limit_windows`] refuses. Caches,
    /// `SET NX EX` markers, and the token/datagram accounting limiters all
    /// belong here; request-quota admission must use [`Self::for_request_quota`].
    pub fn new(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Result<Self, String> {
        Self::construct(
            config,
            dns_cache,
            tls_no_verify,
            tls_ca_bundle_path,
            RedisClientLogPolicy::Operational,
            RedisRetentionRequirement::BestEffort,
            ServerClockRequirement::NotUsed,
        )
    }

    /// Redis client for centralized request-quota admission — the consumers
    /// that charge a sub-bucket ladder (`rate_limiting`, `graphql`,
    /// `grpc_method_router`, through `check_http_windows_redis`).
    ///
    /// Identical to [`Self::new`] except that the server clock is a hard
    /// prerequisite: every established connection proves `TIME` with a plain
    /// standalone command during screening ([`Self::probe_server_time`]) before
    /// the socket may carry a policy command, and every charge transaction
    /// queues one `TIME` inside its own `MULTI`/`EXEC`. Sub-buckets are only as
    /// shared as the clock that selects them, so a connection that cannot
    /// answer a clock is discarded unpublished and `redis_failure_policy`
    /// governs.
    ///
    /// The requirement is deliberately NOT a property of the socket. Screening
    /// is shared with every other consumer of this client, and the replay,
    /// idempotency, cache and token-accounting consumers read no clock at all —
    /// making them prove `TIME` would take a replay-only deployment on a
    /// restrictive ACL out of service for a command it never sends.
    ///
    /// Returns `Err` under the same exclusive-CA load failure as [`Self::new`].
    pub fn for_request_quota(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Result<Self, String> {
        Self::construct(
            config,
            dns_cache,
            tls_no_verify,
            tls_ca_bundle_path,
            RedisClientLogPolicy::Operational,
            RedisRetentionRequirement::BestEffort,
            ServerClockRequirement::Required,
        )
    }

    /// Redis client for a consumer whose retained record IS the control
    /// (`request_deduplication`'s idempotency records today).
    ///
    /// Identical to [`Self::new`] except that every connection — first dial,
    /// dedicated transaction connection, and background recovery probe — must
    /// prove the endpoint will not evict live keys (`maxmemory == 0` or
    /// `maxmemory_policy == noeviction`) before it may carry a command. A
    /// proven `allkeys-*` / `volatile-*` policy is terminal for this client
    /// generation and an unproven query is a recoverable outage, so the
    /// consumer's failure policy (`on_redis_unavailable`, fail-closed by
    /// default) governs instead of an endpoint that can silently drop an
    /// acknowledged operation record mid-lease (`GHSA-26gf-943w-w5x8`).
    ///
    /// Diagnostics stay [`RedisClientLogPolicy::Operational`]: retention safety
    /// and log redaction are independent choices, and this consumer is an
    /// ordinary plugin whose operators need the historical `key_prefix` /
    /// `reason` fields. Counter and cache clients must keep [`Self::new`] —
    /// eviction only degrades a budget or forces a miss there, and requiring
    /// `INFO MEMORY` of them would refuse deployments that are perfectly safe.
    ///
    /// Returns `Err` under the same exclusive-CA load failure as [`Self::new`].
    pub fn for_retention_authority(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Result<Self, String> {
        Self::construct(
            config,
            dns_cache,
            tls_no_verify,
            tls_ca_bundle_path,
            RedisClientLogPolicy::Operational,
            RedisRetentionRequirement::NoEviction,
            ServerClockRequirement::NotUsed,
        )
    }

    /// Redis client owned by the single-use replay authority.
    ///
    /// Starts unproven (not available) until a topology-screened **and**
    /// no-eviction-screened connection or recovery probe succeeds, so a
    /// configured `shared` policy cannot publish `/health` ready before Redis
    /// has been proven safe to retain live markers. A connection is usable only
    /// when `INFO MEMORY` proves `maxmemory == 0` or
    /// `maxmemory_policy == noeviction`; an evicting policy is terminal for this
    /// generation, and an unproven query fails closed and recoverable.
    /// Connection, authentication, command, topology, memory-policy, and
    /// recovery diagnostics publish only a fixed classification beside the
    /// already-redacted endpoint — never raw backend text, `INFO` payloads, key
    /// material, marker material, credentials, or the operator key prefix.
    /// Generic rate-limiter clients must keep [`Self::new`].
    ///
    /// Returns `Err` under the same exclusive-CA load failure as [`Self::new`].
    pub fn for_replay_authority(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Result<Self, String> {
        Self::construct(
            config,
            dns_cache,
            tls_no_verify,
            tls_ca_bundle_path,
            RedisClientLogPolicy::ClassificationOnly,
            RedisRetentionRequirement::NoEviction,
            ServerClockRequirement::NotUsed,
        )
    }

    fn construct(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
        log_policy: RedisClientLogPolicy,
        retention: RedisRetentionRequirement,
        server_clock_requirement: ServerClockRequirement,
    ) -> Result<Self, String> {
        let tls_ca_bundle_pem = load_redis_tls_ca_bundle(tls_no_verify, tls_ca_bundle_path)?;

        Ok(Self {
            pool: Arc::new(ConnectionPool::new(config.pool_size)),
            config,
            dns_cache,
            availability: Arc::new(match log_policy {
                RedisClientLogPolicy::ClassificationOnly => EnforcementAvailability::unproven(),
                RedisClientLogPolicy::Operational => EnforcementAvailability::new(),
            }),
            health_checker_started: AtomicBool::new(false),
            health_checker_abort: Mutex::new(None),
            tls_no_verify,
            tls_ca_bundle_pem,
            log_policy,
            retention,
            server_clock_requirement,
            shared_replay_health: OnceLock::new(),
            pending_compensations: AtomicUsize::new(0),
            server_clock: RedisServerClock::new(),
        })
    }

    /// Count this distinct Redis client as one shared replay authority.
    ///
    /// Idempotent: several equivalent `jwks_auth` providers sharing one client
    /// Arc register once. HMAC and JWKS clients remain distinct authorities
    /// where they are distinct clients. Generic rate-limiter clients never
    /// call this, so their availability transitions do not move replay health.
    ///
    /// The health `Weak` is attached before the first count so a concurrent
    /// outage, recovery, or terminal topology notifies with a strictly newer
    /// epoch than the sample taken here. The registration then publishes the
    /// newest epoch; a stale sampled apply cannot overwrite that notification,
    /// so the packed `/health` word cannot remain permanently inconsistent with
    /// [`EnforcementAvailability`] after the race settles.
    ///
    /// A replay-authority client starts unproven, so this sample publishes
    /// unavailable until a screened probe proves the backend. The bounded
    /// readiness probe is armed here when a Tokio runtime is present; without
    /// one this is panic-free and a later call (or a protected-request miss)
    /// retries the arm.
    pub(crate) fn register_as_shared_replay_authority(&self) {
        let registration = self.ensure_shared_replay_health();
        self.attach_shared_replay_health(&registration);
        let (available, epoch) = self.availability.health_snapshot();
        registration.apply_availability(available, epoch);
        self.start_health_checker_if_needed();
    }

    /// Whether this client currently contributes to packed shared-replay health.
    ///
    /// False until [`Self::register_as_shared_replay_authority`] publishes the
    /// first count, and false again after retirement. An unpublished candidate
    /// must not admit, dial, or move readiness.
    pub(crate) fn is_live_shared_replay_registration(&self) -> bool {
        self.shared_replay_health
            .get()
            .is_some_and(|registration| registration.is_live())
    }

    fn ensure_shared_replay_health(&self) -> Arc<SharedReplayHealthRegistration> {
        Arc::clone(
            self.shared_replay_health
                .get_or_init(|| Arc::new(SharedReplayHealthRegistration::new())),
        )
    }

    fn attach_shared_replay_health(&self, registration: &Arc<SharedReplayHealthRegistration>) {
        let _ = self
            .availability
            .shared_replay_health
            .set(Arc::downgrade(registration));
    }

    fn classification_only(&self) -> bool {
        matches!(self.log_policy, RedisClientLogPolicy::ClassificationOnly)
    }

    /// Whether every connection must prove a non-evicting endpoint before it
    /// may carry a command.
    fn requires_no_eviction(&self) -> bool {
        matches!(self.retention, RedisRetentionRequirement::NoEviction)
    }

    /// Whether this client's consumer selects sub-buckets on the Redis server's
    /// clock, and therefore whether every connection must prove `TIME`.
    fn requires_server_clock(&self) -> bool {
        matches!(
            self.server_clock_requirement,
            ServerClockRequirement::Required
        )
    }

    /// Whether this client declared the server-clock requirement at
    /// construction (test support).
    ///
    /// The probe itself needs a live server, so this is how coverage proves a
    /// consumer asked for the prerequisite — the exact distinction between a
    /// deployment that must grant `+time` and one that must not be forced to.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn requires_server_clock_for_test(&self) -> bool {
        self.requires_server_clock()
    }

    /// Whether this client requires the no-eviction retention proof
    /// (test support).
    ///
    /// The screen itself needs a live server, so this is how coverage proves a
    /// consumer asked for the prerequisite at construction — the exact
    /// distinction `GHSA-26gf-943w-w5x8` turned on.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn requires_no_eviction_screen_for_test(&self) -> bool {
        self.requires_no_eviction()
    }

    /// Apply a memory-policy verdict exactly as a freshly established
    /// connection would (test support), so admission coverage can exercise
    /// acceptance, terminal refusal, and recoverable refusal without a live
    /// server that can be reconfigured mid-test.
    ///
    /// Carries the same requirement gate as [`Self::screen_memory_policy`], so
    /// a cache/counter client reports "usable" without publishing a verdict —
    /// otherwise this helper would prove something the production path does
    /// not do.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn apply_memory_policy_screen_for_test(&self, screen: MemoryPolicyScreen) -> bool {
        if !self.requires_no_eviction() {
            return true;
        }
        self.apply_memory_policy_screen(screen)
    }

    fn warn_connect_failure(
        &self,
        pool_slot: Option<usize>,
        error: &redis::RedisError,
        operational_message: &'static str,
    ) {
        if self.classification_only() {
            warn_replay_backend(
                &self.config.redacted_url(),
                "connection_failed",
                "Redis single-use claim backend failed",
            );
            return;
        }
        match pool_slot {
            Some(idx) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    pool_slot = idx,
                    error = %error,
                    "{operational_message}"
                );
            }
            None => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    error = %error,
                    "{operational_message}"
                );
            }
        }
    }

    fn warn_connect_timeout(&self, pool_slot: Option<usize>) {
        if self.classification_only() {
            warn_replay_backend(
                &self.config.redacted_url(),
                "connection_timeout",
                "Redis single-use claim backend failed",
            );
            return;
        }
        match pool_slot {
            Some(idx) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    pool_slot = idx,
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Timed out connecting to Redis for rate limiting"
                );
            }
            None => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Timed out connecting dedicated Redis client"
                );
            }
        }
    }

    fn info_connected(&self, pool_slot: usize) {
        if self.classification_only() {
            info!(
                redis_url = %self.config.redacted_url(),
                pool_slot,
                pool_size = self.pool.len(),
                "Redis single-use claim backend connected"
            );
            return;
        }
        info!(
            redis_url = %self.config.redacted_url(),
            key_prefix = %self.config.key_prefix,
            pool_slot,
            pool_size = self.pool.len(),
            "Redis rate limiting connected"
        );
    }

    /// Whether Redis is currently available.
    ///
    /// This is an O(1) atomic load — safe to call on every request. An endpoint
    /// proven to be an unsupported topology is never available again, so a
    /// consumer's failure policy applies for the life of the client.
    ///
    /// For a request-quota client, an endpoint that cannot answer `TIME`
    /// reaches this the ordinary way: the probe leaves the connection
    /// unpublished and marks the client unavailable, so there is no second gate
    /// to consult and no mode in which this reads `true` while the bucket clock
    /// is not the server's. A client that reads no clock never probes, so its
    /// availability is unaffected by the endpoint's `TIME` ACL.
    pub fn is_available(&self) -> bool {
        self.availability.is_available()
    }

    /// Whether the configured endpoint was rejected as an unsupported topology.
    pub fn is_topology_unsupported(&self) -> bool {
        self.availability.is_topology_terminal()
    }

    /// Shared availability signal for failover observers that must not retain
    /// the full client (and its cached connections / credentials) after Drop.
    ///
    /// Semantic, not raw: [`EnforcementAvailability::is_available`] cannot read
    /// `true` while the topology is terminal, so an observer can never advertise
    /// a recovery for an endpoint this client refused.
    pub(crate) fn availability_signal(&self) -> Arc<EnforcementAvailability> {
        Arc::clone(&self.availability)
    }

    /// Mark Redis unavailable (test support). Arming the recovery checker is
    /// part of [`Self::mark_unavailable`] itself, so this exercises the same
    /// transition production error paths take.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn mark_unavailable_for_test(&self) {
        self.mark_unavailable();
    }

    /// Prove an unsupported Cluster topology the way a racing task would
    /// (test support), so concurrency coverage can land the rejection at an
    /// exact point in another operation's lifecycle.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn mark_topology_unsupported_for_test(&self) {
        self.mark_topology_unsupported("test-injected cluster topology proof");
    }

    /// Publish "reachable" exactly the way a successful recovery probe does
    /// (test support), so admission coverage can land a recovery at a chosen
    /// point without a live server. Returns `false` when the topology is
    /// terminal and nothing was written.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn publish_reachable_for_test(&self) -> bool {
        self.availability.publish_reachable()
    }

    /// Attach the shared-replay health handle and capture the current
    /// `(available, epoch)` pair **without** publishing it (test support).
    ///
    /// Reproduces the registration window where a concurrent transition can
    /// notify first and a stale sampled apply would otherwise overwrite it.
    /// Attaching does not move the packed health word; only a later
    /// [`Self::publish_shared_replay_registration_sample_for_test`] or a
    /// transition notify publishes counts.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn capture_shared_replay_registration_sample_for_test(
        &self,
    ) -> SharedReplayRegistrationSample {
        let registration = self.ensure_shared_replay_health();
        self.attach_shared_replay_health(&registration);
        let (available, epoch) = self.availability.health_snapshot();
        SharedReplayRegistrationSample { available, epoch }
    }

    /// Apply a previously captured registration sample (test support).
    ///
    /// A sample whose epoch is older than a notification that already landed
    /// is rejected, which is the proof that the packed health word cannot stay
    /// permanently stale after the last registration/availability race settles.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn publish_shared_replay_registration_sample_for_test(
        &self,
        sample: SharedReplayRegistrationSample,
    ) {
        let Some(registration) = self.shared_replay_health.get() else {
            return;
        };
        registration.apply_availability(sample.available, sample.epoch);
    }

    /// What a failover health observer reads from this client's shared
    /// availability signal — the same `Arc` the observer holds (test support).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn observer_sees_available_for_test(&self) -> bool {
        self.availability_signal().is_available()
    }

    /// Whether construction stored exclusive CA bundle bytes (test support).
    ///
    /// True only when verification is on and a configured bundle loaded. False
    /// when no CA path was set or when `tls_no_verify` skipped the load.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn uses_exclusive_ca_bundle_for_test(&self) -> bool {
        self.tls_ca_bundle_pem.is_some()
    }

    /// Whether the background recovery checker has been started (test support).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn health_checker_started_for_test(&self) -> bool {
        self.health_checker_started.load(Ordering::Relaxed)
    }

    /// Abort handle for the background recovery checker, when started (tests).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn health_checker_abort_for_test(&self) -> Option<AbortHandle> {
        self.health_checker_abort
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Configured pool cardinality (`redis_pool_size`).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn pool_size_for_test(&self) -> usize {
        self.pool.len()
    }

    /// Number of pool slots that currently hold an established connection.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn cached_pool_cardinality_for_test(&self) -> usize {
        self.pool
            .slots
            .iter()
            .filter(|slot| slot.connection.load().is_some())
            .count()
    }

    /// Round-robin slot indexes that the next `count` hot-path selections would use.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn select_slot_indexes_for_test(&self, count: usize) -> Vec<usize> {
        (0..count).map(|_| self.select_slot_index()).collect()
    }

    /// Lazily establish every pool slot. Returns how many slots connected.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub async fn warm_pool_for_test(&self) -> usize {
        let mut established = 0usize;
        for idx in 0..self.pool.len() {
            if self.get_or_connect_slot(idx).await.is_some() {
                established += 1;
            }
        }
        established
    }

    /// Clear every cached pool slot (same path as reconnect clearing).
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn clear_pool_for_test(&self) {
        self.clear_connection();
    }

    /// Establish (or reuse) one round-robin pooled connection for tests.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn connect_cached_for_test(&self) -> bool {
        self.get_connection().await.is_some()
    }

    /// Type name of the concrete connection cached in the hot-path pool.
    ///
    /// External tests assert this equals
    /// `type_name::<redis::aio::MultiplexedConnection>()` and does not name
    /// `ConnectionManager`. The pooled helper's return type is the compile-time
    /// pin; reintroducing a transparently reconnecting manager fails either this
    /// string check or the `slot.connection.store(..)` assignment.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn cached_pool_connection_type_name_for_test() -> &'static str {
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    }

    /// Establish a dedicated non-reconnecting multiplexed connection for tests.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn connect_dedicated_for_test(&self) -> bool {
        self.get_dedicated_connection().await.is_some()
    }

    /// Type name of the concrete connection used by WATCH/MULTI/EXEC helpers.
    ///
    /// External tests assert this equals
    /// `type_name::<redis::aio::MultiplexedConnection>()` and does not name
    /// `ConnectionManager`. The production helper's return type is the
    /// compile-time pin; changing it to a reconnecting manager fails either
    /// this string check or the assignment in `get_dedicated_connection`.
    #[allow(dead_code)] // public support used by the external unit-test target
    pub fn dedicated_watch_connection_type_name_for_test() -> &'static str {
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    }

    /// Run one health-check-style multiplexed connect+PING for tests.
    ///
    /// Uses the same Ferrum timeout wiring as the background recovery checker
    /// (inner `AsyncConnectionConfig` + defensive outer connect bound, then a
    /// `PING` bounded by the same `connect_timeout`). DNS screening still
    /// happens first and remains outside the connection timeout.
    #[allow(dead_code)] // public support used by the external integration-test target
    pub async fn health_check_connect_for_test(&self) -> bool {
        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::HostnameEgressDenied
            | RedisEndpoint::LiteralIpEgressDenied
            | RedisEndpoint::ResolveFailed => return false,
        };
        let client = match self.build_client(&url) {
            Ok(client) => client,
            Err(_) => return false,
        };
        let connect_timeout = self.connect_timeout();
        let async_config = screened_async_connection_config(connect_timeout);
        let mut conn = match tokio::time::timeout(
            connect_timeout,
            client.get_multiplexed_async_connection_with_config(&async_config),
        )
        .await
        {
            Ok(Ok(conn)) => conn,
            Ok(Err(_)) | Err(_) => return false,
        };
        ping_connection(&mut conn, connect_timeout).await.is_ok()
    }

    /// Connection-timeout duration installed into redis-rs configs (tests).
    #[allow(dead_code)] // public support used by the external integration-test target
    pub fn connection_timeout_for_test(&self) -> Duration {
        self.connect_timeout()
    }

    /// Deterministic round-robin index into the connection pool.
    fn select_slot_index(&self) -> usize {
        let len = self.pool.len();
        // pool.len() is always >= 1 (ConnectionPool::new uses size.max(1);
        // admission rejects zero). Wrapping fetch_add keeps selection lock-free.
        self.pool.next_slot.fetch_add(1, Ordering::Relaxed) % len
    }

    /// Resolve the Redis endpoint through the gateway DNS cache.
    ///
    /// A usable endpoint carries a screened URL. Egress-policy denials and DNS
    /// failures remain distinct unavailable outcomes so neither can fall back to
    /// the Redis crate's unscreened resolver.
    async fn resolve_url(&self) -> RedisEndpoint {
        screen_redis_endpoint(&self.config, self.dns_cache.as_ref(), self.log_policy).await
    }

    /// Build a Redis client with proper TLS configuration.
    ///
    /// When TLS is enabled (`rediss://` URL), applies:
    /// - Custom CA bundle from `FERRUM_TLS_CA_BUNDLE_PATH` via `build_with_tls`
    /// - Skip-verify from `FERRUM_TLS_NO_VERIFY` via an internally appended
    ///   `#insecure` fragment, never from a caller-supplied URL fragment
    ///
    /// ACL credentials from [`RedisConfig::username`] / [`RedisConfig::password`]
    /// are injected into the parsed [`redis::ConnectionInfo`] so that both the
    /// plain and TLS code paths perform `AUTH` / `HELLO` with the configured
    /// principal. When set, these fields override any user-info already encoded
    /// in [`RedisConfig::url`].
    pub(crate) fn build_client(&self, url: &str) -> Result<redis::Client, redis::RedisError> {
        open_screened_redis_client(
            url,
            self.tls_no_verify,
            self.tls_ca_bundle_pem.as_deref(),
            self.config.username.as_deref(),
            self.config.password.as_deref(),
        )
    }

    /// Duration used as the effective Redis connection-attempt timeout.
    fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_seconds)
    }

    /// redis-rs async connection config carrying Ferrum's connection-attempt
    /// timeout, with the crate's 500ms command response cap disabled.
    ///
    /// The crate connect default is one second; without this, outer
    /// `tokio::time::timeout` wrappers cannot extend attempts past that inner
    /// cap. The response cap is disabled for the same reason the recovery probe
    /// disables it: the very first commands on a new pooled or dedicated
    /// connection are the `INFO CLUSTER` / memory screens, which the operator
    /// bounded with `redis_connect_timeout_seconds`. A healthy server that
    /// answers `INFO` in 750ms must fit a configured 2s screen instead of being
    /// refused after 500ms and re-refused on every subsequent connection.
    /// [`Self::screen_and_arm`] installs
    /// [`SCREENED_COMMAND_RESPONSE_TIMEOUT`] before the connection can carry a
    /// policy command, so ordinary execution stays bounded.
    fn async_connection_config(&self) -> redis::AsyncConnectionConfig {
        screened_async_connection_config(self.connect_timeout())
    }

    /// Establish a non-reconnecting multiplexed connection with Ferrum's timeout
    /// on both the inner redis-rs config and a defensive outer bound.
    ///
    /// This connection cannot transparently replace its physical TCP session, so
    /// connection-local `WATCH` state remains bound to the socket that observed
    /// it, and a broken pooled connection surfaces its I/O error to Ferrum
    /// instead of being silently replaced by an unscreened socket.
    async fn connect_multiplexed(
        &self,
        client: redis::Client,
    ) -> Result<redis::aio::MultiplexedConnection, ConnectAttemptError> {
        let connect_timeout = self.connect_timeout();
        let async_config = self.async_connection_config();
        match tokio::time::timeout(
            connect_timeout,
            client.get_multiplexed_async_connection_with_config(&async_config),
        )
        .await
        {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(error)) => Err(ConnectAttemptError::Redis(error)),
            Err(_) => Err(ConnectAttemptError::Timeout),
        }
    }

    /// Get or create a Redis connection from the pool, establishing it lazily.
    ///
    /// Fast path (hot): round-robin slot pick + lock-free `ArcSwap::load()`.
    /// Slow path (cold): per-slot `Mutex`-guarded establishment with double-check.
    ///
    /// The returned connection never reconnects on its own: when it breaks, the
    /// command fails, [`Self::note_command_failure`] clears every slot, and the
    /// next call re-runs the full resolve/build/connect/screen path.
    async fn get_connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        let idx = self.select_slot_index();
        self.get_or_connect_slot(idx).await
    }

    /// Establish (or reuse) the multiplexed connection for a specific pool slot.
    async fn get_or_connect_slot(&self, idx: usize) -> Option<redis::aio::MultiplexedConnection> {
        // A rejected topology is terminal: never redial it, so no command can
        // succeed against an endpoint this client cannot enforce against.
        if self.is_topology_unsupported() {
            return None;
        }
        let slot = &self.pool.slots[idx];

        // Fast path: lock-free read via ArcSwap
        let guard = slot.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        // Slow path: serialize connection establishment for this slot only
        let _lock = slot.connect_mutex.lock().await;

        // Double-check after acquiring mutex
        let guard = slot.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::HostnameEgressDenied => {
                // Hostname currently maps to a denied address: fail closed, but
                // arm recovery so a later DNS answer can restore connectivity
                // without a config reload.
                self.mark_unavailable();
                return None;
            }
            RedisEndpoint::LiteralIpEgressDenied => {
                // Static literal-IP denial: fail closed with NO recovery
                // checker — re-screening the same IP stays denied forever. A
                // config change rebuilds the client.
                self.mark_unavailable_without_recovery();
                return None;
            }
            RedisEndpoint::ResolveFailed => {
                // Transient DNS failure: never dial an unscreened host. Leave
                // centralized Redis unavailable and let the recovery checker
                // re-screen later; the consumer's failure policy applies.
                self.mark_unavailable();
                return None;
            }
        };
        let client = match self.build_client(&url) {
            Ok(c) => c,
            Err(e) => {
                self.warn_connect_failure(
                    Some(idx),
                    &e,
                    "Failed to create Redis client for rate limiting",
                );
                self.mark_unavailable();
                return None;
            }
        };

        match self.connect_multiplexed(client).await {
            Ok(mut conn) => {
                // Screen topology (and, for replay-authority clients, the
                // no-eviction memory policy) before the connection is published
                // to the hot path: a Cluster endpoint or an evicting Redis must
                // never serve a policy operation.
                if !self.screen_and_arm(&mut conn).await {
                    return None;
                }
                // Re-check at the publication boundary: another task may have
                // proven Cluster topology while this slot was being screened.
                // Publishing the connection (or availability) afterwards would
                // let a policy operation run against a refused endpoint.
                if !self.availability.publish_reachable() {
                    return None;
                }
                self.info_connected(idx);
                self.start_health_checker_if_needed();
                slot.connection.store(Arc::new(Some(conn.clone())));
                // Publication race, other direction: a rejection proven between
                // the check above and this store would have cleared an empty
                // slot. Re-read the terminal state and drop the freshly cached
                // socket so no slot can retain a connection to a refused
                // endpoint.
                if self.is_topology_unsupported() {
                    self.clear_connection();
                    return None;
                }
                Some(conn)
            }
            Err(ConnectAttemptError::Redis(e)) => {
                self.warn_connect_failure(
                    Some(idx),
                    &e,
                    "Failed to connect to Redis for rate limiting",
                );
                self.note_command_failure(&e);
                None
            }
            Err(ConnectAttemptError::Timeout) => {
                self.warn_connect_timeout(Some(idx));
                self.mark_unavailable();
                None
            }
        }
    }

    /// Create a one-off non-reconnecting multiplexed connection that is not
    /// stored in the shared hot-path cache.
    ///
    /// Redis transactions that rely on connection-local state (`WATCH`/`MULTI`/
    /// `EXEC`) must:
    /// 1. Not share a pooled connection with unrelated concurrent commands
    ///    (another sequence multiplexed onto that socket can interleave
    ///    `UNWATCH`/`EXEC` and break the optimistic transaction boundary).
    /// 2. Not use [`redis::aio::ConnectionManager`] at all for the sequence —
    ///    that type owns an `ArcSwap`-backed connection and can transparently
    ///    reconnect (including after a RESP3 disconnect push). A reconnect
    ///    between `WATCH` and `EXEC` yields a fresh physical socket with no
    ///    watch state, so `EXEC` can become unconditional. (The hot-path pool
    ///    avoids that type for the same reason, plus the screening invariant.)
    ///
    /// This helper therefore returns a freshly dialed
    /// [`redis::aio::MultiplexedConnection`] against the already
    /// screened/redacted endpoint, using the same timeout/TLS/egress policy as
    /// other connection creation. Callers must not clone or share it during the
    /// transaction, and must fail closed on any I/O error rather than retrying
    /// a partial transaction on a new connection.
    async fn get_dedicated_connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        // A rejected topology is terminal: never redial it (see
        // `get_or_connect_slot`).
        if self.is_topology_unsupported() {
            return None;
        }
        let url = match self.resolve_url().await {
            RedisEndpoint::Url(url) => url,
            RedisEndpoint::HostnameEgressDenied => {
                // Hostname currently maps to a denied address: fail closed, but
                // arm recovery so a later DNS answer can restore connectivity
                // without a config reload.
                self.mark_unavailable();
                return None;
            }
            RedisEndpoint::LiteralIpEgressDenied => {
                // Static literal-IP denial: fail closed with NO recovery
                // checker — re-screening the same IP stays denied forever. A
                // config change rebuilds the client.
                self.mark_unavailable_without_recovery();
                return None;
            }
            RedisEndpoint::ResolveFailed => {
                // Transient DNS failure: never dial an unscreened host. Leave
                // centralized Redis unavailable and let the recovery checker
                // re-screen later; the consumer's failure policy applies.
                self.mark_unavailable();
                return None;
            }
        };
        let client = match self.build_client(&url) {
            Ok(client) => client,
            Err(e) => {
                self.warn_connect_failure(None, &e, "Failed to create dedicated Redis client");
                self.mark_unavailable();
                return None;
            }
        };

        match self.connect_multiplexed(client).await {
            Ok(mut conn) => {
                // Screen topology (and replay no-eviction policy) before any
                // WATCH/MULTI sequence runs on it.
                if !self.screen_and_arm(&mut conn).await {
                    return None;
                }
                // Same publication boundary as the pooled path: a concurrent
                // topology rejection wins over this dedicated connection.
                if !self.availability.publish_reachable() {
                    return None;
                }
                Some(conn)
            }
            Err(ConnectAttemptError::Redis(e)) => {
                self.warn_connect_failure(None, &e, "Failed to connect dedicated Redis client");
                self.note_command_failure(&e);
                None
            }
            Err(ConnectAttemptError::Timeout) => {
                self.warn_connect_timeout(None);
                self.mark_unavailable();
                None
            }
        }
    }

    /// Clear every cached pool slot so the next `get_connection()` call
    /// re-resolves DNS, re-screens egress, and re-runs the `INFO CLUSTER`
    /// topology screen before any command can run on a new physical socket.
    ///
    /// This is the *only* way a pooled connection is ever replaced — the cached
    /// [`redis::aio::MultiplexedConnection`] cannot re-dial by itself.
    fn clear_connection(&self) {
        self.pool.clear();
    }

    /// Mark Redis as unavailable, clear the connection for re-resolution, and
    /// guarantee the background recovery checker is running.
    ///
    /// Starting the checker here rather than at each call site is a security
    /// invariant, not a convenience. Callers fall into two classes:
    ///
    /// - Consumers configured for local fallback lose centralized accuracy
    ///   while `is_available()` is false.
    /// - **Fail-closed consumers** (`soap_ws_security`'s `replay_scope: shared`
    ///   PasswordDigest replay claims, `request_deduplication`'s exactly-once
    ///   admission) *reject* traffic while `is_available()` is false. For those,
    ///   a missing checker turns one transient error into an outage that only a
    ///   config reload can clear.
    ///
    /// Only the connect paths used to start it, so a client whose commands ran
    /// on [`Self::get_dedicated_connection`] (which does not start it on
    /// success) could be pinned unavailable forever by a single `WATCH`/`EXEC`
    /// I/O error. Owning the transition here makes "unavailable implies a live
    /// recovery task" hold for every present and future error path.
    ///
    /// The one transition that must *not* arm recovery is a **literal-IP**
    /// egress-policy denial — see [`Self::mark_unavailable_without_recovery`].
    /// A hostname egress denial is retryable (DNS may change) and uses this
    /// path so fail-closed consumers are not pinned unavailable forever.
    fn mark_unavailable(&self) {
        self.mark_unavailable_without_recovery();
        self.start_health_checker_if_needed();
    }

    /// Mark Redis unavailable **without** arming the recovery checker.
    ///
    /// Reserved for literal-IP egress-policy denials: re-screening the same
    /// denied address every interval would stay denied forever, so this is
    /// configuration rather than a transient outage and a config change (which
    /// rebuilds the client) is the recovery path. Hostname denials must not use
    /// this — they arm recovery via [`Self::mark_unavailable`].
    fn mark_unavailable_without_recovery(&self) {
        self.availability.mark_unreachable();
        self.clear_connection();
    }

    /// Permanently reject the configured endpoint as proven-bad configuration
    /// (unsupported Cluster topology, or — for replay-authority clients — an
    /// evicting `maxmemory` policy).
    ///
    /// Distinct from [`Self::mark_unavailable`] on purpose: this is a
    /// configuration fault, not an outage, so no amount of recovery pinging can
    /// make the next policy operation correct. Every later
    /// [`Self::is_available`] load stays false and the consumer's configured
    /// failure policy governs from here on.
    fn mark_topology_unsupported(&self, reason: &str) {
        self.mark_endpoint_terminal(EndpointTerminalFault::UnsupportedTopology, reason);
    }

    fn mark_endpoint_terminal(&self, fault: EndpointTerminalFault, reason: &str) {
        let first = self.availability.reject_topology();
        // Drop cached connections so no slot can keep serving the refused
        // endpoint. `reject_topology` already made the state terminal, so this
        // cannot be downgraded back to a plain outage.
        self.clear_connection();
        if first {
            let redacted = self.config.redacted_url();
            // Each warner owns both log policies, so an operational retention
            // authority reports the fault it actually hit rather than borrowing
            // the Cluster message.
            match fault {
                EndpointTerminalFault::UnsupportedTopology => warn_topology_unsupported(
                    &redacted,
                    &self.config.key_prefix,
                    reason,
                    self.log_policy,
                ),
                EndpointTerminalFault::UnsafeEviction => warn_unsafe_eviction(
                    &redacted,
                    &self.config.key_prefix,
                    reason,
                    self.log_policy,
                ),
            }
        }
    }

    /// Classify a failed Redis command: an unsupported topology is terminal,
    /// anything else is an ordinary (recoverable) availability failure.
    fn note_command_failure(&self, error: &redis::RedisError) {
        if is_cluster_topology_error(error) {
            self.mark_topology_unsupported("cluster redirection or cross-slot error");
        } else {
            self.mark_unavailable();
        }
    }

    /// Post-I/O success boundary for every Redis command.
    ///
    /// Publishes availability and reports whether the operation may be returned
    /// as a success. `Err(())` means another task proved an unsupported topology
    /// while this command was in flight: the command may already have mutated
    /// Redis, but reporting success would let admission proceed against an
    /// endpoint this client cannot enforce on. Failing the operation instead
    /// hands the decision to the consumer's `redis_failure_policy`, and a
    /// double-counted increment is the conservative direction for a limiter.
    fn note_command_success(&self) -> Result<(), ()> {
        if self.availability.publish_reachable() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Reject a freshly established connection whose server reports Cluster
    /// topology, or one that could not be screened at all. Returns `true` only
    /// when the connection may be used.
    async fn screen_topology(&self, conn: &mut impl redis::aio::ConnectionLike) -> bool {
        match screen_connection_topology(conn, self.connect_timeout()).await {
            TopologyScreen::Usable => true,
            TopologyScreen::ClusterProven => {
                self.mark_endpoint_terminal(
                    EndpointTerminalFault::UnsupportedTopology,
                    "server reported cluster_enabled",
                );
                false
            }
            TopologyScreen::ProbeFailed => {
                // Bounded by the configured connect timeout. Never proof of
                // Cluster topology, and never a licence to run a policy command
                // on the unscreened connection — an ordinary retryable outage.
                if self.classification_only() {
                    warn_replay_backend(
                        &self.config.redacted_url(),
                        "connection_timeout",
                        "Redis single-use claim backend failed",
                    );
                } else {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        timeout_seconds = self.config.connect_timeout_seconds,
                        "Redis topology screen did not complete — centralized Redis unavailable; \
                         will retry"
                    );
                }
                self.mark_unavailable();
                false
            }
        }
    }

    /// No-eviction screen for clients whose retained record is the control.
    /// Cache and counter clients skip this.
    ///
    /// Must run after a usable topology screen and before any claim command.
    /// A proven `allkeys-*` / `volatile-*` policy is terminal for this client
    /// generation; an unproven query is a recoverable outage.
    async fn screen_memory_policy(&self, conn: &mut impl redis::aio::ConnectionLike) -> bool {
        if !self.requires_no_eviction() {
            return true;
        }
        self.apply_memory_policy_screen(
            screen_connection_memory_policy(conn, self.connect_timeout()).await,
        )
    }

    /// Publish one memory-policy verdict. Split from the I/O so the gate and
    /// its coverage cannot drift, and so the recovery probe's identical
    /// classification stays comparable.
    fn apply_memory_policy_screen(&self, screen: MemoryPolicyScreen) -> bool {
        match screen {
            MemoryPolicyScreen::Usable => true,
            MemoryPolicyScreen::UnsafeEviction => {
                self.mark_endpoint_terminal(
                    EndpointTerminalFault::UnsafeEviction,
                    "server reported an evicting maxmemory policy",
                );
                false
            }
            MemoryPolicyScreen::Unproven => {
                if self.classification_only() {
                    warn_replay_backend(
                        &self.config.redacted_url(),
                        "memory_policy_unproven",
                        "Redis single-use claim backend failed",
                    );
                } else {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        key_prefix = %self.config.key_prefix,
                        timeout_seconds = self.config.connect_timeout_seconds,
                        "Redis memory-policy screen did not complete — cannot prove the endpoint \
                         retains records for their full lease; centralized Redis unavailable, \
                         will retry"
                    );
                }
                self.mark_unavailable();
                false
            }
        }
    }

    /// Topology plus, for clients that require the retention proof, the
    /// no-eviction memory screen. No command may run on an unscreened
    /// connection.
    async fn screen_established_connection(
        &self,
        conn: &mut impl redis::aio::ConnectionLike,
    ) -> bool {
        self.screen_topology(conn).await && self.screen_memory_policy(conn).await
    }

    /// Screen a freshly established connection and, when it is usable, install
    /// the ordinary per-command response deadline.
    ///
    /// The connection was dialled with redis-rs' inner response cap disabled so
    /// the screens above are bounded by the admitted
    /// `redis_connect_timeout_seconds` (see [`Self::async_connection_config`]).
    /// Arming here — before the socket is published to a pool slot or handed to
    /// a `WATCH`/`MULTI` sequence, and before it is cloned — restores a bounded
    /// command deadline for every policy operation that follows. A connection
    /// that fails the screen is dropped, so it is never armed.
    ///
    /// The `TIME` probe runs only for clients that declared
    /// [`ServerClockRequirement::Required`]. It is the one screen that belongs
    /// to the consumer rather than to the endpoint: only request-quota
    /// admission orders a shared ladder on the server's clock, so requiring the
    /// command of a replay, idempotency, cache, or token-accounting client
    /// would take a deployment out of service over a command it never sends.
    async fn screen_and_arm(&self, conn: &mut redis::aio::MultiplexedConnection) -> bool {
        if !self.screen_established_connection(conn).await {
            return false;
        }
        conn.set_response_timeout(SCREENED_COMMAND_RESPONSE_TIMEOUT);
        if !self.requires_server_clock() {
            return true;
        }
        self.probe_server_time(conn).await
    }

    /// The shared bucket clock for every policy on this endpoint.
    ///
    /// Admission reads it to select sub-buckets; nothing else may keep a second
    /// view of the same endpoint's clock.
    pub fn server_clock(&self) -> &RedisServerClock {
        &self.server_clock
    }

    /// Read the server clock on a freshly screened connection, seed the offset
    /// from it, and report whether the connection may be used at all.
    ///
    /// Run once per established connection of a
    /// [`ServerClockRequirement::Required`] client — at first use and after
    /// every reconnect — because the answer belongs to the server (its ACL, and
    /// its clock), which an operator can change under a live gateway. It is
    /// deliberately a STANDALONE command rather than a trial `TIME` inside a
    /// real transaction: a denied command queued in `MULTI` aborts the whole
    /// `EXEC`, so a probe that guessed wrong would fail an admission instead of
    /// rejecting a socket.
    ///
    /// **Every unsuccessful answer rejects the connection.** A `NOPERM`, an
    /// `ERR unknown command`, a malformed successful reply (a server answering
    /// `+OK` to `TIME`), a timeout, and a transport failure are all handled
    /// exactly like a failed `INFO CLUSTER` screen: the client is marked
    /// unavailable, the socket is never published, and the consumer's
    /// `redis_failure_policy` decides — `fail_closed` refuses, `local_fallback`
    /// enforces the configured quota once per gateway process. There is no
    /// local-clock mode to fall into: a ladder selected on an uncorrected local
    /// clock is not a shared budget, and quietly serving one under an explicit
    /// `fail_closed` policy would be enforcement in name only.
    ///
    /// The two recognised refusals still pick the DIAGNOSTIC, because they are
    /// the two an operator can act on: `NOPERM`
    /// ([`is_permission_denied_error`]) means grant `+time`, and an unknown
    /// command ([`is_unknown_command_error`]) means this RESP server has no
    /// `TIME` at all and cannot back a request quota. Neither changes the
    /// outcome.
    ///
    /// The reply is bounded twice over: by the per-command deadline armed just
    /// above, and by the same value passed explicitly to the shared screen, so
    /// a silent server costs one screened timeout at connect rather than
    /// hanging the slot.
    ///
    /// The wire work itself — the standalone command, the one parser, and the
    /// classification of each refusal — lives in
    /// [`screen_connection_server_clock`], which the background recovery
    /// checker calls with the same discipline. This method is only what a
    /// verdict means for THIS client: its offset, its diagnostics, and its
    /// availability.
    async fn probe_server_time(&self, conn: &mut impl redis::aio::ConnectionLike) -> bool {
        match screen_connection_server_clock(conn, SCREENED_COMMAND_RESPONSE_TIMEOUT).await {
            ServerClockScreen::Clock {
                server_time,
                sampled_at,
            } => {
                // Seeded before the connection is published, so the first
                // selection that follows already has a server offset. This
                // is the only sample not bounded by
                // [`clock_sample_is_prompt`]: it is the seed, there is no
                // previous offset to preserve, and the standalone command
                // is bounded by the screened per-command deadline.
                self.server_clock.record_reply(server_time, sampled_at);
                true
            }
            ServerClockScreen::Unreadable => {
                self.reject_unclocked_connection(
                    "server_clock_unreadable",
                    "Redis endpoint answered TIME with something that is not a clock; \
                     the connection cannot be screened, so redis_failure_policy governs",
                );
                self.mark_unavailable();
                false
            }
            ServerClockScreen::Denied => {
                self.reject_unclocked_connection(
                    "server_clock_denied",
                    "Redis endpoint does not permit TIME; centralized request quotas need the \
                     server clock, so grant +time — until then redis_failure_policy governs \
                     every decision on this endpoint",
                );
                self.mark_unavailable();
                false
            }
            ServerClockScreen::Unimplemented => {
                self.reject_unclocked_connection(
                    "server_clock_denied",
                    "Redis endpoint does not implement TIME; centralized request quotas need \
                     the server clock, so this endpoint cannot back them and \
                     redis_failure_policy governs every decision on it",
                );
                self.mark_unavailable();
                false
            }
            ServerClockScreen::Failed(e) => {
                // Timeout, transport failure, or any other server error: the
                // connection is not screened successfully, so it must not be
                // published. `note_command_failure` also keeps the Cluster
                // classification for a `MOVED`-style answer to the probe, and
                // it is the one arm that publishes the raw error — for
                // operational clients only.
                if self.classification_only() {
                    warn_replay_backend(
                        &self.config.redacted_url(),
                        "server_clock_unavailable",
                        "Redis single-use claim backend failed",
                    );
                } else {
                    warn_sampled!(
                        redis_url = %self.config.redacted_url(),
                        operation = "TIME",
                        error = %e,
                        "Redis TIME probe failed; the connection cannot be screened"
                    );
                }
                self.note_command_failure(&e);
                false
            }
        }
    }

    /// Publish one rejected-`TIME`-probe diagnostic.
    ///
    /// Replay-authority clients get a fixed classification beside the already
    /// redacted endpoint and nothing else — no backend text ever reaches their
    /// logs, and a probe failure is no exception. Operational clients get the
    /// actionable sentence. Neither arm interpolates the server's reply.
    ///
    /// No constructor currently pairs
    /// [`RedisClientLogPolicy::ClassificationOnly`] with
    /// [`ServerClockRequirement::Required`], so the classification arm is
    /// reachable only if one is added. It stays because the two are deliberately
    /// independent choices: a future clock-reading consumer that must not
    /// publish backend text would otherwise leak it from exactly this path.
    fn reject_unclocked_connection(
        &self,
        classification: &'static str,
        operational_message: &'static str,
    ) {
        if self.classification_only() {
            warn_replay_backend(
                &self.config.redacted_url(),
                classification,
                "Redis single-use claim backend failed",
            );
            return;
        }
        warn_sampled!(
            redis_url = %self.config.redacted_url(),
            operation = "TIME",
            "{operational_message}"
        );
    }

    /// Establish a connection — and therefore run its `TIME` probe — before the
    /// caller selects its first sub-bucket.
    ///
    /// Bucket selection otherwise precedes connection acquisition, so the FIRST
    /// request of a client's life would select on the raw local clock and, on a
    /// materially skewed gateway, charge a ladder nobody else shares. The probe
    /// already runs on every established connection; this only moves the
    /// establishment ahead of the selection, so the cost is one connection that
    /// the very next step would have made anyway, and nothing at all once an
    /// offset is known.
    ///
    /// Best effort by design: an endpoint that cannot be reached leaves the
    /// offset unknown and the charge below fails through the ordinary path.
    /// The two-sided settlement check remains the guarantee for every selection
    /// that still happens on a stale base — a wall-clock step, or an offset
    /// learned before a server-side clock change.
    ///
    /// Only a [`ServerClockRequirement::Required`] client's connections probe,
    /// so seeding a client that reads no clock would dial for nothing; it is
    /// skipped, and [`Self::charge_rate_limit_windows`] refuses on such a
    /// client anyway.
    pub async fn ensure_clock_seeded(&self) {
        if !self.requires_server_clock() || self.server_clock.offset_nanos().is_some() {
            return;
        }
        let _ = self.get_connection().await;
    }

    /// Start a background task that periodically probes Redis to detect recovery.
    ///
    /// The task is aborted when this client is dropped so retired plugin
    /// generations cannot keep dialing obsolete Redis endpoints.
    ///
    /// `tokio::spawn` panics without a reactor. Plugin construction, sync
    /// tests, and test-injected outages on ordinary threads can all reach
    /// [`Self::mark_unavailable`] outside a runtime. Do not latch the started
    /// flag until a runtime is present: a later request-path transition must
    /// still arm recovery so fail-closed consumers are not pinned unavailable.
    ///
    /// Replay-authority clients probe on the first iteration (no startup sleep)
    /// so `/health` can recover without protected traffic and without waiting
    /// a full `redis_health_check_interval_seconds`. That first probe also
    /// emits one closed-set `connection_failed` classification beside the
    /// redacted endpoint when authentication or connection fails while the
    /// client is still unproven — otherwise the unproven-to-unreachable
    /// transition is silent. Later genuine available-to-unavailable
    /// transitions keep the same diagnostic; retries while already
    /// unavailable stay silent. Operational clients keep the historical
    /// sleep-then-probe cadence and warn only on an availability drop.
    ///
    /// A probe proves everything the client's own connect path proves, because
    /// what it publishes is that client's availability: `PING`, the topology
    /// screen, the retention screen when the consumer requires one, and — for a
    /// [`ServerClockRequirement::Required`] client — a bounded, well-formed
    /// `TIME`. A recovery that skipped the last one would advertise a restored
    /// quota store on an endpoint that still cannot answer the clock its
    /// admission selects on.
    pub(crate) fn start_health_checker_if_needed(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.health_checker_started.swap(true, Ordering::Relaxed) {
            return; // Already started
        }

        let probe_immediately = self.classification_only();

        let availability = Arc::clone(&self.availability);
        // Weak, not strong: the checker may drop cached sockets when it proves
        // an unsupported topology, but a retired client generation must still be
        // released (and its pool dropped) the moment the client is dropped,
        // without waiting for the abort to be observed by the runtime.
        let pool = Arc::downgrade(&self.pool);
        let config = self.config.clone();
        let dns_cache = self.dns_cache.clone();
        let interval = Duration::from_secs(self.config.health_check_interval_seconds);
        let connect_timeout = self.connect_timeout();
        let tls_no_verify = self.tls_no_verify;
        let tls_ca_bundle_pem = self.tls_ca_bundle_pem.clone();
        let log_policy = self.log_policy;
        // Recovery must re-prove retention safety, not just reachability: an
        // operator can switch `maxmemory-policy` on a live endpoint, and a
        // cached-socket generation would otherwise never re-screen.
        let key_prefix = self.config.key_prefix.clone();
        let requires_no_eviction = self.requires_no_eviction();
        // And recovery must re-prove the SERVER CLOCK for the clients whose
        // admission selects on it. `PING` and the topology screen say nothing
        // about `TIME`, so a checker that stopped there would republish
        // availability — and log a recovery an observer relays — while the ACL
        // still withholds `+time`, the server still has no `TIME`, or the
        // command still does not answer; every request until the next interval
        // would then pay another failed connect-and-probe before reaching its
        // failure policy, and with no traffic at all the false healthy state
        // would simply persist. A `ServerClockRequirement::NotUsed` client
        // sends no clock probe here either, exactly as its connections do not.
        let requires_server_clock = self.requires_server_clock();

        let handle = runtime.spawn(async move {
            let mut delay_before_probe = !probe_immediately;
            // Consumed by the first probe that actually completes (Ok or Err),
            // not by a DNS-screen `continue`. Replay clients start unproven, so
            // `was_available` cannot distinguish that first failure from a
            // later retry while still unreachable.
            let mut log_unproven_probe_failure = probe_immediately;
            loop {
                if delay_before_probe {
                    tokio::time::sleep(interval).await;
                }
                delay_before_probe = true;

                // A rejected topology is a configuration fault, not an outage:
                // a Cluster node answers PING while still redirecting every
                // key, so recovery must never be reported for one. Checked
                // again at the publication boundary below, because a rejection
                // can also land while this probe is in flight.
                if availability.is_topology_terminal() {
                    continue;
                }

                // Screen + resolve through the shared DNS cache, fail-closed: the
                // recovery checker must NOT hand an unscreened host to the Redis
                // client either (a DNS-cache outage or a later rebind/policy denial
                // would otherwise let the background ping dial a denied address).
                let url = match screen_redis_endpoint(&config, dns_cache.as_ref(), log_policy).await
                {
                    RedisEndpoint::Url(url) => url,
                    // Still denied or unresolvable this interval — skip the ping
                    // and re-screen next interval (including hostname egress
                    // denials, whose DNS answer may change). Literal-IP denials
                    // never start this task.
                    RedisEndpoint::HostnameEgressDenied
                    | RedisEndpoint::LiteralIpEgressDenied
                    | RedisEndpoint::ResolveFailed => continue,
                };

                // Build the client with TLS settings matching the main connection.
                // ACL credentials from `config.username` / `config.password` are
                // injected via ConnectionInfo so health-check pings authenticate
                // with the same principal as the main connection.
                //
                // Connection attempts use the same Ferrum timeout as cached/
                // dedicated paths (inner AsyncConnectionConfig + defensive outer
                // bound). Gateway DNS screening above is outside that timeout.
                let result: Result<(), redis::RedisError> = async {
                    let client = open_screened_redis_client(
                        &url,
                        tls_no_verify,
                        tls_ca_bundle_pem.as_deref(),
                        config.username.as_deref(),
                        config.password.as_deref(),
                    )?;
                    let async_config = screened_async_connection_config(connect_timeout);
                    let mut conn = match tokio::time::timeout(
                        connect_timeout,
                        client.get_multiplexed_async_connection_with_config(&async_config),
                    )
                    .await
                    {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(error)) => return Err(error),
                        Err(_) => {
                            return Err(redis::RedisError::from((
                                redis::ErrorKind::Io,
                                "Redis health-check connection attempt timed out",
                            )));
                        }
                    };
                    // Bound PING by the same connect timeout as establishment
                    // and the INFO screens: an accepted socket that never
                    // answers would otherwise wedge this single-flight checker.
                    ping_connection(&mut conn, connect_timeout).await?;
                    // A PING alone proves nothing about topology, so screen the
                    // recovered endpoint before ever reporting it healthy. The
                    // probe is bounded by the same configured connect timeout as
                    // the connect paths, so an endpoint that accepts but never
                    // answers INFO cannot stall the recovery loop.
                    let screen = screen_connection_topology(&mut conn, connect_timeout).await;
                    match screen {
                        TopologyScreen::Usable => {}
                        TopologyScreen::ClusterProven => {
                            let first = availability.reject_topology();
                            // Terminal state first, cached sockets second — the
                            // same order as the client's own rejection path, so
                            // nothing can republish reachability and then keep a
                            // slot to a refused endpoint. The probe's own
                            // connection is local to this block and is dropped
                            // with it; the endpoint is never redialed again.
                            if let Some(pool) = pool.upgrade() {
                                pool.clear();
                            }
                            if first {
                                warn_topology_unsupported(
                                    &config.redacted_url(),
                                    &config.key_prefix,
                                    "server reported cluster topology during recovery",
                                    log_policy,
                                );
                            }
                            return Err(cluster_topology_probe_error());
                        }
                        TopologyScreen::ProbeFailed => {
                            return Err(incomplete_topology_probe_error());
                        }
                    }
                    if requires_no_eviction {
                        match screen_connection_memory_policy(&mut conn, connect_timeout).await {
                            MemoryPolicyScreen::Usable => {}
                            MemoryPolicyScreen::UnsafeEviction => {
                                let first = availability.reject_topology();
                                if let Some(pool) = pool.upgrade() {
                                    pool.clear();
                                }
                                if first {
                                    warn_unsafe_eviction(
                                        &config.redacted_url(),
                                        &key_prefix,
                                        "server reported an evicting maxmemory policy \
                                         during recovery",
                                        log_policy,
                                    );
                                }
                                return Err(unsafe_eviction_probe_error());
                            }
                            MemoryPolicyScreen::Unproven => {
                                return Err(unproven_memory_probe_error());
                            }
                        }
                    }
                    if requires_server_clock {
                        // Bounded by the same configured connect timeout as the
                        // screens above, because this connection is dialled
                        // with redis-rs' inner response cap disabled. The
                        // sample it returns is deliberately DISCARDED rather
                        // than seeded: a recovery reply is bounded only by that
                        // connect timeout, which is far past one sub-bucket, so
                        // adopting it would walk the base backwards exactly as
                        // `clock_sample_is_prompt` refuses to let a late
                        // transaction reply do. The next request establishes
                        // its own connection, and that probe seeds.
                        //
                        // None of these refusals is terminal: an ACL can be
                        // granted under a live gateway, so the endpoint is
                        // re-screened on the next interval.
                        match screen_connection_server_clock(&mut conn, connect_timeout).await {
                            ServerClockScreen::Clock { .. } => {}
                            ServerClockScreen::Unreadable => {
                                return Err(unreadable_clock_probe_error());
                            }
                            ServerClockScreen::Denied | ServerClockScreen::Unimplemented => {
                                return Err(denied_clock_probe_error());
                            }
                            ServerClockScreen::Failed(error) => return Err(error),
                        }
                    }
                    Ok::<(), redis::RedisError>(())
                }
                .await;

                let was_available = availability.is_available();
                match result {
                    Ok(()) => {
                        log_unproven_probe_failure = false;
                        // Publication boundary: a topology rejection proven by
                        // another task while this probe was in flight wins, so a
                        // successful PING/INFO can neither restore availability
                        // nor advertise a recovery an observer would relay.
                        if availability.publish_reachable() && !was_available {
                            match log_policy {
                                RedisClientLogPolicy::Operational => {
                                    info!(
                                        "Redis connection recovered — centralized Redis access restored"
                                    );
                                }
                                RedisClientLogPolicy::ClassificationOnly => {
                                    info!(
                                        redis_url = %config.redacted_url(),
                                        "Redis single-use claim backend recovered"
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let topology_terminal = availability.is_topology_terminal();
                        let log_operational_transition =
                            matches!(log_policy, RedisClientLogPolicy::Operational)
                                && was_available
                                && !topology_terminal;
                        let log_replay_probe_failure =
                            matches!(log_policy, RedisClientLogPolicy::ClassificationOnly)
                                && !topology_terminal
                                && (was_available || log_unproven_probe_failure);
                        log_unproven_probe_failure = false;
                        if log_operational_transition {
                            warn!("Redis health check failed — centralized Redis unavailable");
                        } else if log_replay_probe_failure {
                            let classification = if is_unproven_memory_probe_error(&error) {
                                "memory_policy_unproven"
                            } else if is_incomplete_topology_probe_error(&error)
                                || is_incomplete_ping_probe_error(&error)
                                || is_incomplete_clock_probe_error(&error)
                            {
                                "connection_timeout"
                            } else {
                                "connection_failed"
                            };
                            warn_replay_backend(
                                &config.redacted_url(),
                                classification,
                                "Redis single-use claim backend failed",
                            );
                        }
                        availability.mark_unreachable();
                    }
                }
            }
        });

        *self
            .health_checker_abort
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle.abort_handle());
    }

    /// Increment a counter and set expiry. Returns the new count.
    ///
    /// Uses a Redis pipeline to send `INCR` + `EXPIRE` in a single round-trip.
    /// This is the core primitive for fixed-window rate limiting.
    // Redis command failures are intentionally collapsed to () at this boundary.
    #[allow(clippy::result_unit_err)]
    pub async fn incr_with_expire(&self, key: &str, ttl_seconds: u64) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(key)
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.note_command_success()?;
                Ok(count)
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "INCR+EXPIRE",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Read the previous weighted-window bucket, charge the current bucket,
    /// and set its expiry in one Redis transaction.
    ///
    /// Used where one admission decision covers several units of work — the
    /// WebSocket frame limiter charges every physical fragment of a reassembled
    /// message in a single round trip rather than one round trip per fragment.
    /// `amount` must be positive; the caller owns the bound on how large it can
    /// grow.
    #[allow(clippy::result_unit_err)]
    pub async fn sliding_window_increment_by(
        &self,
        previous_key: &str,
        current_key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let amount = amount.max(1);
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg(previous_key)
            .cmd("INCRBY")
            .arg(current_key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(current_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((previous_count, current_count)) => {
                self.note_command_success()?;
                Ok((previous_count.unwrap_or(0), current_count))
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "GET+INCRBY+EXPIRE",
                    error = %e,
                    "Redis sliding-window transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Increment a counter by a specific amount and set expiry. Returns the new total.
    ///
    /// Uses a Redis pipeline to send `INCRBY` + `EXPIRE` in a single round-trip.
    /// Used by the AI token rate limiter where each request may consume a variable
    /// number of tokens.
    #[allow(clippy::result_unit_err)]
    pub async fn incrby_with_expire(
        &self,
        key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCRBY")
            .arg(key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.note_command_success()?;
                Ok(count)
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "INCRBY+EXPIRE",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Increment a counter by `amount`, set expiry, and floor the result at
    /// zero. Returns the new (floored) total, or `Err(())` if Redis is
    /// unreachable for *either* the increment or the compensating floor write.
    ///
    /// A failed compensating write is reported as `Err(())` (not `Ok(0)`): the
    /// key may be left negative on the server, and silently reporting success
    /// would let a recovered Redis read that negative counter as zero usage and
    /// bypass enforcement. Returning the error hands the decision to the
    /// consumer's configured failure policy; the default refuses rather than
    /// silently changing enforcement domains.
    ///
    /// This is the reconciliation-safe variant of [`incrby_with_expire`]. The
    /// AI token limiter applies reconciliation deltas (`actual - reserved`)
    /// that are usually *negative* (reserved estimates run high; non-2xx
    /// responses release the full reservation). A raw `INCRBY` can drive a
    /// missing or low window counter negative, and a negative counter later
    /// reads as zero usage — letting a consumer reserve the full limit again
    /// and bypassing centralized enforcement. The local in-memory path floors
    /// usage at zero (`TokenUsageWindow::adjust_usage`); this keeps the Redis
    /// path consistent.
    ///
    /// When the post-`INCRBY` value is negative we issue a *compensating*
    /// `INCRBY` of exactly `-new_total` to bring the key back to zero, rather
    /// than a blind `SET 0`. A blind `SET` would also discard any concurrent
    /// positive increment that landed between our write and read (a worse
    /// under-count); compensating by exactly the observed deficit only fails
    /// in the conservative direction (a concurrent add during the race can
    /// leave a transient over-count, which is safe for a rate limiter — it
    /// never under-counts usage).
    #[allow(clippy::result_unit_err)]
    pub async fn incrby_with_expire_floor_zero(
        &self,
        key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<i64, ()> {
        let new_total = self.incrby_with_expire(key, amount, ttl_seconds).await?;
        let Some(compensation) = floor_zero_compensation(new_total) else {
            return Ok(new_total);
        };

        // Bring the counter back up to exactly zero, preserving the TTL.
        match self
            .incrby_with_expire(key, compensation, ttl_seconds)
            .await
        {
            Ok(floored) => Ok(clamp_floored_total(floored)),
            // The compensating write failed (Redis went away mid-operation), so
            // the key is left *negative* on the server. Do NOT report success:
            // a negative counter reads as zero usage once Redis recovers within
            // the key TTL, letting a consumer re-reserve the full budget —
            // exactly the bypass the floor exists to prevent.
            // `incrby_with_expire` already marked the client unavailable, so
            // surface the failure for the caller's configured failure policy
            // and log the leaked-floor state rather than silently undercounting.
            Err(()) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "INCRBY floor compensation",
                    "Redis floor compensation failed after negative INCRBY accepted; \
                     window counter left negative until TTL — centralized enforcement unavailable"
                );
                Err(())
            }
        }
    }

    /// Increment one counter by 1 and another by a specific amount in a single
    /// pipelined round-trip. Returns `(new_count, new_total)`.
    #[allow(clippy::result_unit_err)]
    pub async fn incr_and_incrby_with_expire(
        &self,
        count_key: &str,
        total_key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(count_key)
            .cmd("INCRBY")
            .arg(total_key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(count_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .cmd("EXPIRE")
            .arg(total_key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count, total)) => {
                self.note_command_success()?;
                Ok((count, total))
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "INCR+INCRBY+EXPIRE",
                    error = %e,
                    "Redis pipeline failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get two counters in a single pipelined round-trip. Returns (0, 0) for missing keys.
    ///
    /// Used by the AI token rate limiter to fetch both the previous and current
    /// window counters without two separate round-trips.
    #[allow(clippy::result_unit_err)]
    pub async fn get_two_counters(&self, key1: &str, key2: &str) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, Option<i64>), redis::RedisError> = redis::pipe()
            .cmd("GET")
            .arg(key1)
            .cmd("GET")
            .arg(key2)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((v1, v2)) => {
                self.note_command_success()?;
                Ok((v1.unwrap_or(0), v2.unwrap_or(0)))
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "GET+GET",
                    error = %e,
                    "Redis pipeline failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get a raw byte value from Redis.
    ///
    /// Used by plugins that need arbitrary key-value storage (e.g., request
    /// deduplication, AI semantic cache) rather than rate limiting counters.
    #[allow(clippy::result_unit_err)]
    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;

        match result {
            Ok(val) => {
                self.note_command_success()?;
                Ok(val)
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "GET",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Get a raw byte value from Redis, bounded to `max_bytes` before
    /// allocation.
    ///
    /// A plain `GET` would allocate the full stored value regardless of size, so
    /// a compromised or oversized entry could force an unbounded allocation. This
    /// reads `EXISTS`, `STRLEN`, and `GETRANGE key 0 max_bytes` in one pipelined
    /// round-trip: the true length gates the outcome while the range read caps
    /// the transferred/allocated bytes at `max_bytes + 1`. The inclusive end
    /// index is converted with [`redis_getrange_end_index`] so an oversized cap
    /// cannot become Redis's "read to end" (`-1`) sentinel. Returned prefixes are
    /// independently verified against the bound before admission. Callers treat
    /// [`BoundedRedisValue::Oversized`] and [`BoundedRedisValue::Empty`] as
    /// invalid entries and quarantine them.
    #[allow(clippy::result_unit_err)]
    pub async fn get_bytes_bounded(
        &self,
        key: &str,
        max_bytes: usize,
    ) -> Result<BoundedRedisValue, ()> {
        // Fail closed before any Redis dispatch when the cap cannot be expressed
        // as a non-negative GETRANGE end index (for example `usize::MAX` → `-1`).
        let end = redis_getrange_end_index(max_bytes).map_err(|_| ())?;
        let mut conn = self.get_connection().await.ok_or(())?;

        // GETRANGE end index is inclusive, so `0..=max_bytes` reads at most
        // `max_bytes + 1` bytes — enough to confirm an over-cap value without
        // materializing it. EXISTS distinguishes a missing key from an empty
        // value so callers can quarantine empty poisoned keys. Pipelined in one
        // round-trip (non-transactional like `get_two_counters`); a concurrent
        // rewrite between the commands can only cause a benign spurious
        // quarantine/miss, never an unbounded allocation.
        let result: Result<(i64, usize, Vec<u8>), redis::RedisError> = redis::pipe()
            .cmd("EXISTS")
            .arg(key)
            .cmd("STRLEN")
            .arg(key)
            .cmd("GETRANGE")
            .arg(key)
            .arg(0)
            .arg(end)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((exists, length, prefix)) => {
                self.note_command_success()?;
                if exists == 0 {
                    return Ok(BoundedRedisValue::Missing);
                }
                if length == 0 {
                    return Ok(BoundedRedisValue::Empty);
                }
                // Independently verify Redis honored the bound. An over-cap probe
                // may return at most `max_bytes + 1` bytes; an in-cap value must
                // never exceed `max_bytes`.
                let max_prefix = if length > max_bytes {
                    max_bytes.saturating_add(1)
                } else {
                    max_bytes
                };
                if prefix.len() > max_prefix {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "GETRANGE",
                        prefix_len = prefix.len(),
                        max_bytes,
                        "Redis GETRANGE returned more bytes than the requested bound; failing closed"
                    );
                    return Err(());
                }
                if length > max_bytes {
                    Ok(BoundedRedisValue::Oversized { length })
                } else if prefix.len() != length {
                    // Length/prefix disagreement under the cap is treated as an
                    // invalid entry so callers quarantine rather than replay.
                    Ok(BoundedRedisValue::Oversized {
                        length: prefix.len().max(length),
                    })
                } else {
                    Ok(BoundedRedisValue::Found(prefix))
                }
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "EXISTS+STRLEN+GETRANGE",
                    error = %e,
                    "Redis pipeline failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Best-effort unconditional key deletion, used to quarantine a poisoned or
    /// invalid cache entry so it is not re-served on the next request.
    #[allow(clippy::result_unit_err)]
    pub async fn delete(&self, key: &str) -> Result<(), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<i64, redis::RedisError> =
            redis::cmd("DEL").arg(key).query_async(&mut conn).await;

        match result {
            Ok(_) => {
                self.note_command_success()?;
                Ok(())
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "DEL",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Set a raw byte value in Redis with a TTL.
    ///
    /// Uses a pipelined `SET` + `EXPIRE` in a single round-trip.
    /// Used by plugins that need arbitrary key-value storage.
    #[allow(clippy::result_unit_err)]
    pub async fn set_bytes_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<(), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(value)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(expire_seconds(ttl_seconds))
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok(()) => {
                self.note_command_success()?;
                Ok(())
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "SET+EXPIRE",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Set a raw byte value only if the key does not already exist, with a TTL.
    ///
    /// Returns `Ok(true)` when the caller acquired the key, `Ok(false)` when an
    /// existing key prevented the write, and `Err(())` when Redis is unavailable.
    #[allow(clippy::result_unit_err)]
    pub async fn set_bytes_nx_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(expire_seconds(ttl_seconds))
            .query_async(&mut conn)
            .await;

        match result {
            Ok(value) => {
                self.note_command_success()?;
                Ok(value.is_some())
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "SET NX EX",
                    error = %e,
                    "Redis command failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// [`Self::set_bytes_nx_with_expire`] with a **bounded response deadline**
    /// and **classification-only** logging.
    ///
    /// Two properties the general primitive does not provide, both required by
    /// the single-use replay authority
    /// ([`crate::plugins::utils::replay_authority`]):
    ///
    /// * **Bounded.** `get_connection()` bounds connection setup, but the reply
    ///   to an already-dispatched command is otherwise awaited forever. A peer
    ///   that completes the TCP/TLS handshake, passes the topology screen, and
    ///   then simply stops answering would hold an in-flight protected request
    ///   open for as long as it keeps the socket. The deadline reuses the
    ///   documented Redis timeout contract — `redis_connect_timeout_seconds`,
    ///   the same admitted bound the topology probe already applies to a
    ///   server-side reply — rather than adding an unbounded new knob.
    /// * **Redacted.** The claim path may not put backend error TEXT in a log
    ///   record. A `RedisError` renders server-supplied detail, and the key
    ///   itself is a replay marker. Only the fixed classification below and the
    ///   already-redacted endpoint are logged; the key, the value, the marker,
    ///   and the error text never are.
    ///
    /// Timeout, partition, connection failure, authentication rejection, and
    /// protocol/parse uncertainty all collapse to `Err(())` — the caller's
    /// fail-closed result. A timeout marks the client unavailable exactly like
    /// any other command failure, so the background recovery checker owns
    /// restoring it.
    #[allow(clippy::result_unit_err)]
    pub async fn set_bytes_nx_with_expire_bounded(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let mut command = redis::cmd("SET");
        command
            .arg(key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(expire_seconds(ttl_seconds));
        let response: Result<Option<String>, redis::RedisError> = match tokio::time::timeout(
            self.connect_timeout(),
            command.query_async(&mut conn),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                // Connected but unanswered. Never a licence to admit: an
                // executed-but-unacknowledged `SET NX` leaves the marker in
                // place, so the retry sees the existing key and stays
                // fail-closed.
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "SET NX EX",
                    classification = "response_timeout",
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Redis single-use claim did not answer within the bounded deadline"
                );
                self.mark_unavailable();
                return Err(());
            }
        };

        match response {
            Ok(value) => match classify_replay_set_nx_reply(value.as_deref()) {
                Ok(admitted) => {
                    self.note_command_success()?;
                    Ok(admitted)
                }
                Err(ReplaySetNxReplyError::InvalidClaimReply) => {
                    // Do not render the server-controlled reply. Only exact
                    // `OK` proves that Redis stored the marker; every other
                    // string is protocol uncertainty and must fail closed.
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "SET NX EX",
                        classification = "malformed_response",
                        "Redis single-use claim returned an invalid response"
                    );
                    self.mark_unavailable();
                    Err(())
                }
            },
            Err(e) => {
                // `is_cluster_topology_error` inspects the error; nothing it
                // reads is rendered. The published field is the fixed class.
                let classification = if is_cluster_topology_error(&e) {
                    "unsupported_topology"
                } else {
                    "command_failed"
                };
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "SET NX EX",
                    classification,
                    "Redis single-use claim failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Delete a key only when its current byte value exactly matches `expected`.
    ///
    /// Uses optimistic transactions (`WATCH` + `MULTI`/`EXEC`) instead of Lua so
    /// RESP-compatible Redis backends that do not support scripting can still
    /// use ownership-token lock release.
    ///
    /// The transaction runs on a freshly dialed, *dedicated* (never pooled,
    /// never shared) non-reconnecting [`redis::aio::MultiplexedConnection`] so
    /// connection-local `WATCH` state can neither be interleaved by another
    /// command nor silently dropped by a transparent reconnect. Any I/O failure
    /// at `WATCH`, `GET`, `UNWATCH`, or `EXEC` fails closed as `Err(())`.
    #[allow(clippy::result_unit_err)]
    pub async fn delete_if_value_matches(&self, key: &str, expected: &[u8]) -> Result<bool, ()> {
        // Owned for the duration of the transaction; never cloned or shared.
        let mut conn = self.get_dedicated_connection().await.ok_or(())?;

        let watch_result: Result<(), redis::RedisError> =
            redis::cmd("WATCH").arg(key).query_async(&mut conn).await;
        if let Err(e) = watch_result {
            warn!(
                redis_url = %self.config.redacted_url(),
                operation = "WATCH",
                error = %e,
                "Redis command failed"
            );
            self.note_command_failure(&e);
            return Err(());
        }

        let current: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;
        match current {
            Ok(Some(current)) if current == expected => {}
            Ok(_) => {
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(e) = unwatch {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "UNWATCH",
                        error = %e,
                        "Redis command failed"
                    );
                    self.note_command_failure(&e);
                    return Err(());
                }
                self.note_command_success()?;
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "compare-delete GET",
                    error = %e,
                    "Redis command failed"
                );
                // WATCH already succeeded: attempt UNWATCH before failing closed.
                // A failed UNWATCH is itself a failure; never retry on a new conn.
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(unwatch_err) = unwatch {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "UNWATCH",
                        error = %unwatch_err,
                        "Redis command failed"
                    );
                }
                self.note_command_failure(&e);
                return Err(());
            }
        }

        let result: Result<Option<(i64,)>, redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(Some((deleted,))) => {
                self.note_command_success()?;
                Ok(deleted > 0)
            }
            Ok(None) => {
                self.note_command_success()?;
                Ok(false)
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "compare-delete EXEC",
                    error = %e,
                    "Redis transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Charge one request against EVERY configured rate-limit window in a
    /// single atomic `MULTI`/`EXEC`, returning each window's trailing-window
    /// count (the charged sub-bucket, the `K` sub-buckets before it, and the one
    /// after it, summed in full).
    ///
    /// One round trip on the ordinary pooled multiplexed slots: no `WATCH`, no
    /// dedicated per-request connection, no optimistic-retry budget, and no
    /// server-side scripting — every command is plain RESP any Redis-compatible
    /// server accepts. Per window the transaction issues `GET` on each of the
    /// [`REDIS_WINDOW_TRAILING_SUB_BUCKETS`] older sub-buckets and on the one
    /// after the charged bucket, then `INCR` and `EXPIRE` on the sub-bucket this
    /// request lands in — twenty commands over nineteen keys — so the admission
    /// decision the caller derives is tied to its own mutation and can never be
    /// a stale read that two gateways both act on.
    ///
    /// The forward `GET` is what makes the pair of decisions independent of the
    /// order two concurrent transactions reach the server in, and the extra old
    /// `GET` is what keeps a peer's retained charge inside this ladder when its
    /// key is one bucket older than the bucket it executed in; see
    /// [`REDIS_WINDOW_SUB_BUCKET_KEYS`]. Neither covers a stall longer than one
    /// whole sub-bucket, nor a charge placed in the future — that is the
    /// caller's two-sided settlement check
    /// ([`sub_bucket_charge_is_settled`]), judged on the server clock this
    /// transaction returns.
    ///
    /// One `TIME` rides at the end of the same transaction (see
    /// [`RedisServerClock`]). It answers the server's own clock at `EXEC` — the
    /// instant every gateway's charge is ordered on — for no extra round trip,
    /// and it both settles this ladder and refreshes the offset the NEXT
    /// request selects its bucket with. It is unconditional: a connection whose
    /// probe could not answer `TIME` is never published, so there is no mode in
    /// which the command is omitted and no reply shape that depends on one. A
    /// `TIME` the ACL revokes between the probe and this transaction aborts the
    /// whole `EXEC`, which is an ordinary command failure and hands the next
    /// decision to `redis_failure_policy`.
    ///
    /// The offset the reply teaches is only adopted when the reply itself
    /// arrived inside one sub-bucket of the tightest window this transaction
    /// charged ([`clock_sample_is_prompt`]); otherwise the previous offset
    /// stands and only the settlement judgement uses the sample. A response
    /// held past that would teach a base already staler than the ladder's
    /// forward cover.
    ///
    /// Charging before deciding is what keeps concurrent gateways honest, and
    /// it is why a caller that then REFUSES must hand the charge back with
    /// [`Self::uncharge_rate_limit_windows`]; see that method for the
    /// visibility window this leaves open.
    ///
    /// An individual sub-bucket counter may be negative when a compensation
    /// raced a key expiry (see [`Self::uncharge_rate_limit_windows`]); each is
    /// floored at zero by [`redis_trailing_window_count`] before it is summed,
    /// rather than paying a round trip to normalize the key.
    ///
    /// More than [`MAX_REDIS_ADMISSION_WINDOWS`] windows fails closed here
    /// rather than at the caller: this helper is `pub`, so it carries its own
    /// bound instead of trusting every present and future caller's config
    /// validation to keep an atomic operation inside the fixed buffers.
    ///
    /// For the same reason it carries the server-clock prerequisite itself. A
    /// client built with anything but [`Self::for_request_quota`] declared
    /// [`ServerClockRequirement::NotUsed`], so its connections never proved
    /// `TIME` and its offset was never seeded; charging a ladder on it would
    /// select every sub-bucket from this gateway's raw local clock, which is
    /// the local-clock mode this layout exists to refuse. That is a wiring
    /// mistake rather than an operator's configuration, so it trips a debug
    /// assertion and refuses with `Err(())` in release.
    // Redis command failures are intentionally collapsed to () at this boundary.
    #[allow(clippy::result_unit_err)]
    pub async fn charge_rate_limit_windows(
        &self,
        windows: &[RedisWindowCharge],
    ) -> Result<RedisChargeOutcome, ()> {
        // A client built for a consumer that reads no clock never probed
        // `TIME`, so its connections carry no proof that this endpoint can
        // order one ladder across gateways — and its `RedisServerClock` offset
        // is unseeded, which would place every sub-bucket on this gateway's raw
        // local clock. That is exactly the local-clock mode this layout exists
        // to refuse, so fail closed rather than charge. Reaching here is a
        // wiring mistake in Ferrum itself, not an operator's configuration,
        // hence the debug assertion above the release refusal.
        debug_assert!(
            self.requires_server_clock(),
            "charge_rate_limit_windows requires a client built with \
             RedisRateLimitClient::for_request_quota"
        );
        if !self.requires_server_clock() {
            warn_sampled!(
                redis_url = %self.config.redacted_url(),
                operation = "GET+INCR+EXPIRE+TIME",
                "Redis rate-limit charge attempted on a client that did not declare the \
                 server-clock requirement"
            );
            return Err(());
        }
        if windows.is_empty() {
            return Ok(RedisChargeOutcome::default());
        }
        if windows.len() > MAX_REDIS_ADMISSION_WINDOWS {
            warn_sampled!(
                redis_url = %self.config.redacted_url(),
                operation = "GET+INCR+EXPIRE",
                windows = windows.len(),
                max_windows = MAX_REDIS_ADMISSION_WINDOWS,
                "Redis rate-limit charge exceeds the supported window count"
            );
            return Err(());
        }
        let mut conn = self.get_connection().await.ok_or(())?;
        // The tightest window this transaction charges. It bounds how late a
        // `TIME` reply may be and still move the learned offset
        // ([`clock_sample_is_prompt`]): the narrowest ladder is the one a
        // mis-timed base breaks first. Computed from THIS transaction's
        // windows, so nothing has to be remembered across requests.
        let narrowest_window_seconds = windows
            .iter()
            .map(|window| window.bucket().window_seconds)
            .min()
            .unwrap_or(1);

        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for window in windows {
            // The `K + 1` older sub-buckets and the one forward sub-bucket are
            // read-only; only the bucket this request lands in is mutated and
            // retained.
            for key in window.trailing_keys() {
                pipeline.cmd("GET").arg(key);
            }
            pipeline.cmd("GET").arg(window.next_key());
            pipeline
                .cmd("INCR")
                .arg(window.charged_key())
                .cmd("EXPIRE")
                .arg(window.charged_key())
                .arg(expire_seconds(window.ttl_seconds()))
                .ignore();
            // Dual-write the legacy whole-window counter and include its
            // weighted usage in admission. This is intentionally permanent:
            // an old replica has no generation handshake and may coexist for
            // longer than any configured quota window.
            pipeline
                .cmd("GET")
                .arg(window.legacy_previous_key())
                .cmd("INCR")
                .arg(window.legacy_current_key())
                .cmd("EXPIRE")
                .arg(window.legacy_current_key())
                .arg(expire_seconds(window.ttl_seconds()))
                .ignore();
        }
        // Last, and once per transaction rather than once per window: it is the
        // instant the SERVER applied this whole `EXEC`, which is what orders
        // this charge against every other gateway's. Unconditional — a
        // connection that could not answer `TIME` was never published.
        pipeline.cmd("TIME");

        // `GET` answers a bulk string or nil, `INCR` an integer, and `TIME` a
        // two-element array, so the reply is decoded one element at a time
        // rather than through a single scalar type. `Vec<redis::Value>` IS
        // redis-rs's own decode allocation, and it is consumed element by
        // element below — redis-rs decodes a `Value` by value, so borrowing
        // would add one clone per counter on the admission hot path.
        let values_per_window = REDIS_WINDOW_SUB_BUCKET_KEYS + 2;
        let expected_values = windows.len() * values_per_window + 1;
        // Both samples are this process's own clock, and their DIFFERENCE is
        // the only thing read from them besides the offset: it decides whether
        // the reply arrived promptly enough for its `TIME` to be worth
        // adopting. No admission decision is judged against either.
        let local_at_send = redis_epoch_now();
        let result: Result<Vec<redis::Value>, redis::RedisError> =
            pipeline.query_async(&mut conn).await;
        let local_at_reply = redis_epoch_now();
        match result {
            Ok(reply) if reply.len() == expected_values => {
                self.note_command_success()?;
                let mut trailing_counts = [0_u64; MAX_REDIS_ADMISSION_WINDOWS];
                let mut legacy_counts = [(0_i64, 0_i64); MAX_REDIS_ADMISSION_WINDOWS];
                let mut ladder = [None; REDIS_WINDOW_SUB_BUCKET_KEYS];
                let mut values = reply.into_iter();
                for index in 0..windows.len() {
                    for slot in ladder.iter_mut() {
                        let decoded = match values.next() {
                            Some(value) => redis::from_redis_value::<Option<i64>>(value).ok(),
                            None => None,
                        };
                        let Some(count) = decoded else {
                            // A counter this code cannot read is NOT a zero: it
                            // would under-count and over-admit. Same posture as
                            // the short-reply arm below — an unusable endpoint,
                            // with the `INCR`s already landed.
                            self.mark_unavailable();
                            warn_sampled!(
                                redis_url = %self.config.redacted_url(),
                                operation = "GET+INCR+EXPIRE",
                                "Redis rate-limit charge returned an unreadable sub-bucket \
                                 counter"
                            );
                            return Err(());
                        };
                        *slot = count;
                    }
                    trailing_counts[index] = redis_trailing_window_count(&ladder);
                    let previous = values
                        .next()
                        .and_then(|value| redis::from_redis_value::<Option<i64>>(value).ok());
                    let current = values
                        .next()
                        .and_then(|value| redis::from_redis_value::<i64>(value).ok());
                    let (Some(previous), Some(current)) = (previous, current) else {
                        self.mark_unavailable();
                        warn_sampled!(
                            redis_url = %self.config.redacted_url(),
                            operation = "GET+INCR+EXPIRE",
                            "Redis rate-limit charge returned an unreadable legacy counter"
                        );
                        return Err(());
                    };
                    legacy_counts[index] = (previous.unwrap_or(0), current);
                }
                let sampled = values.next().and_then(parse_redis_server_time);
                let Some(server_time) = sampled else {
                    // The server answered something this code cannot pair with
                    // a clock. Falling back to the local clock here would
                    // silently reinstate the skew term the whole layout exists
                    // to remove, so refuse instead.
                    self.mark_unavailable();
                    warn_sampled!(
                        redis_url = %self.config.redacted_url(),
                        operation = "GET+INCR+EXPIRE+TIME",
                        "Redis rate-limit charge returned an unreadable server clock"
                    );
                    return Err(());
                };
                let mut counts = RedisWindowCounts::default();
                for (index, window) in windows.iter().enumerate() {
                    let window_nanos = (window.bucket().window_seconds.max(1) as u128)
                        .saturating_mul(1_000_000_000);
                    let elapsed =
                        (server_time.as_nanos() % window_nanos) as f64 / window_nanos as f64;
                    let (previous, current) = legacy_counts[index];
                    let legacy = (previous.max(0) as f64 * (1.0 - elapsed) + current.max(0) as f64)
                        .ceil()
                        .min(u64::MAX as f64) as u64;
                    counts.push(trailing_counts[index].max(legacy));
                }
                // A reply held longer than one sub-bucket of the tightest
                // window this transaction charged teaches an offset that is
                // already stale by more than the ladder's forward cover, so the
                // previous offset stands. The charge itself is still judged by
                // the caller's settlement check against `server_time`, which is
                // the instant the SERVER applied it and owes nothing to the
                // offset.
                let reply_latency = local_at_reply.saturating_sub(local_at_send);
                if clock_sample_is_prompt(reply_latency, narrowest_window_seconds) {
                    self.server_clock.record_reply(server_time, local_at_reply);
                }
                Ok(RedisChargeOutcome {
                    counts,
                    settled_at: Some(server_time),
                })
            }
            Ok(reply) => {
                // A short reply would silently pair one window's counter with
                // another window's limit, so refuse instead of guessing.
                //
                // This is an unusable endpoint, not a quota decision, and the
                // `INCR`s have already landed. Mark the client unavailable
                // exactly as the `Err` arm's `note_command_failure` would: the
                // caller returns before it can reach its own refusal branch, so
                // nothing compensates the charge, and without this the counters
                // would climb to the key TTL while every request re-charged a
                // reply this code cannot pair. Unavailability hands the next
                // decision to `redis_failure_policy` and stops the hammering.
                self.mark_unavailable();
                warn_sampled!(
                    redis_url = %self.config.redacted_url(),
                    operation = "GET+INCR+EXPIRE",
                    fields = reply.len(),
                    "Redis rate-limit charge returned an unexpected reply shape"
                );
                Err(())
            }
            Err(e) => {
                // An ACL revoked under a live gateway lands here: the queued
                // `TIME` aborts the whole `EXEC`. It needs no special case —
                // `note_command_failure` marks the endpoint unavailable and
                // clears the pool, and the reconnect that follows re-probes
                // `TIME` and refuses to publish a connection that cannot answer
                // it. The store simply stays unavailable and
                // `redis_failure_policy` governs, which is the same answer a
                // revocation seen at connect time gets.
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "GET+INCR+EXPIRE",
                    error = %e,
                    "Redis rate-limit charge transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Hand back a charge [`Self::charge_rate_limit_windows`] made, in a single
    /// atomic `MULTI`/`EXEC`: `DECR` + `EXPIRE` on every sub-bucket counter the
    /// charge incremented — one per configured window, never the read-only
    /// older sub-buckets.
    ///
    /// This is the compensating half of charge-then-compensate admission. A
    /// refused request must leave no lasting charge — that is precisely what
    /// turned sustained overload into an indefinite lockout (issue #5517) — but
    /// the charge still has to precede the decision so that racing gateways
    /// cannot both admit against one stale read. The compensation therefore
    /// undoes ALL the windows the charge touched, including the ones that fit,
    /// so a tighter window's refusal never consumes a looser window's budget.
    ///
    /// Between the charge and this call the transient charge IS visible: a
    /// concurrent request for the same identity may be refused against a count
    /// that is about to be handed back. The error direction is conservative —
    /// the limiter refuses a little early under contention and never
    /// over-admits.
    ///
    /// `EXPIRE` rides along in the same transaction (no extra round trip)
    /// because `DECR` on a key whose TTL elapsed in between recreates it with
    /// no expiry at all; a per-second window would then leak one immortal key
    /// per second per identity. The recreated counter is negative, and readers
    /// clamp a negative count to zero usage.
    ///
    /// `Err(())` means the compensation did not land: the charge is still on
    /// the window until its TTL elapses. The failure is reported through the
    /// ordinary [`Self::note_command_failure`] path, so the caller's
    /// `redis_failure_policy` governs the NEXT decision; the refusal this
    /// compensation belongs to is already correct and is still returned.
    // Redis command failures are intentionally collapsed to () at this boundary.
    #[allow(clippy::result_unit_err)]
    pub async fn uncharge_rate_limit_windows(
        &self,
        windows: &[RedisWindowCharge],
    ) -> Result<(), ()> {
        if windows.is_empty() {
            return Ok(());
        }
        if windows.len() > MAX_REDIS_ADMISSION_WINDOWS {
            warn_sampled!(
                redis_url = %self.config.redacted_url(),
                operation = "DECR+EXPIRE",
                windows = windows.len(),
                max_windows = MAX_REDIS_ADMISSION_WINDOWS,
                "Redis rate-limit compensation exceeds the supported window count"
            );
            return Err(());
        }
        let mut conn = self.get_connection().await.ok_or(())?;

        let mut pipeline = redis::pipe();
        pipeline.atomic();
        for window in windows {
            pipeline
                .cmd("DECR")
                .arg(window.charged_key())
                .ignore()
                .cmd("EXPIRE")
                .arg(window.charged_key())
                .arg(expire_seconds(window.ttl_seconds()))
                .ignore();
            pipeline
                .cmd("DECR")
                .arg(window.legacy_current_key())
                .ignore()
                .cmd("EXPIRE")
                .arg(window.legacy_current_key())
                .arg(expire_seconds(window.ttl_seconds()))
                .ignore();
        }

        let result: Result<(), redis::RedisError> = pipeline.query_async(&mut conn).await;
        match result {
            Ok(()) => {
                self.note_command_success()?;
                Ok(())
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "DECR+EXPIRE",
                    error = %e,
                    "Redis rate-limit compensation failed; the refused request's charge \
                     stays on its windows until they expire"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Issue a refusal's compensation from a DETACHED task that owns a clone
    /// of this client's `Arc`, so cancelling the request cannot strand the
    /// charge.
    ///
    /// Plugin hooks are driven under `tokio::time::timeout_at`, and a gRPC
    /// deadline or a client disconnect drops the hook future outright. Awaiting
    /// the hand-back inline meant a drop between the charge and the `DECR` left
    /// the charge on its windows until their TTL elapsed, with no
    /// `note_command_failure`, no log, and no `redis_failure_policy`
    /// involvement — issue #5517's lockout shape re-entered through a different
    /// door, and worst where `limit_by: "ip"` collapses a whole ingress behind
    /// one key. The task holds the client `Arc`, so it outlives both the
    /// request future and a config reload that retires the plugin instance.
    /// Detaching also takes the second round trip off the refused request's
    /// latency; the refusal itself is already decided and is returned
    /// immediately.
    ///
    /// The failure accounting is unchanged: a compensation that cannot be
    /// delivered still goes through [`Self::note_command_failure`], so
    /// `redis_failure_policy` governs the NEXT decision.
    ///
    /// One exception remains, and it is the only one: a process exit between
    /// the charge and the compensation leaves the charge until its window's TTL
    /// elapses. Nothing in-process can close that — the increment is already on
    /// the server.
    ///
    /// Without a Tokio runtime (direct construction in tests, or a non-Tokio
    /// executor) the compensation is awaited inline rather than dropped;
    /// spawning would panic, and a proxy path never panics.
    ///
    /// The returned [`RedisCompensationHandle`] reports whether the `DECR`
    /// actually landed. Dropping it does not cancel anything — the task owns
    /// the compensation — so the refusal path keeps its fire-and-forget
    /// latency, while the staleness rebuild can wait for a hand-back it is
    /// about to read back through its own rebuilt ladder.
    pub async fn spawn_uncharge_rate_limit_windows(
        self: Arc<Self>,
        charges: RedisWindowCharges,
    ) -> RedisCompensationHandle {
        if charges.is_empty() {
            return RedisCompensationHandle::resolved();
        }
        self.pending_compensations.fetch_add(1, Ordering::AcqRel);
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let client = self;
        let compensate = async move {
            let landed = client
                .uncharge_rate_limit_windows(charges.as_slice())
                .await
                .is_ok();
            client.pending_compensations.fetch_sub(1, Ordering::AcqRel);
            // The refusal path drops its receiver, so a failed send is the
            // ordinary case and never affects the compensation itself.
            let _ = completed_tx.send(landed);
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(compensate);
            }
            Err(_) => compensate.await,
        }
        RedisCompensationHandle {
            completed: Some(completed_rx),
        }
    }

    /// Detached compensations issued by
    /// [`Self::spawn_uncharge_rate_limit_windows`] that have not completed yet.
    ///
    /// Test support only: coverage that asserts a counter after a refusal waits
    /// for this to reach zero instead of racing the detached task. Admission
    /// never reads it.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn pending_compensations_for_test(&self) -> usize {
        self.pending_compensations.load(Ordering::Acquire)
    }

    /// Replace a key's value with a TTL **only** when its current byte value
    /// exactly matches `expected` — a single-key compare-and-set.
    ///
    /// This is the fencing primitive for ownership-token protocols: the caller
    /// writes an ownership record, performs work, and then publishes its result
    /// into the same key. Because the compare and the write happen inside one
    /// `WATCH`/`MULTI`/`EXEC` transaction on a dedicated non-reconnecting
    /// [`redis::aio::MultiplexedConnection`], an owner whose record has since
    /// expired or been replaced by a successor can neither overwrite the
    /// successor's value nor resurrect a key that Redis already dropped:
    ///
    /// - `Ok(true)` — the caller still owned the key and the new value is live.
    /// - `Ok(false)` — the key is missing, holds a different value, or was
    ///   concurrently modified between `WATCH` and `EXEC`. Nothing was written.
    /// - `Err(())` — Redis is unavailable; the caller must not assume either
    ///   outcome.
    ///
    /// `WATCH`-based rather than Lua so RESP-compatible servers without
    /// scripting still fence correctly (same rationale as
    /// [`Self::delete_if_value_matches`]). Only one key is touched, so the
    /// transaction is also slot-safe on sharded deployments.
    ///
    /// Any I/O failure at `WATCH`, `GET`, `UNWATCH`, or `EXEC` fails closed;
    /// a partial transaction is never retried on a fresh connection.
    #[allow(clippy::result_unit_err)]
    pub async fn set_bytes_with_expire_if_value_matches(
        &self,
        key: &str,
        expected: &[u8],
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        // Owned for the duration of the transaction; never cloned or shared.
        let mut conn = self.get_dedicated_connection().await.ok_or(())?;

        let watch_result: Result<(), redis::RedisError> =
            redis::cmd("WATCH").arg(key).query_async(&mut conn).await;
        if let Err(e) = watch_result {
            warn!(
                redis_url = %self.config.redacted_url(),
                operation = "WATCH",
                error = %e,
                "Redis command failed"
            );
            self.note_command_failure(&e);
            return Err(());
        }

        let current: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;
        match current {
            Ok(Some(current)) if current == expected => {}
            Ok(_) => {
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(e) = unwatch {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "UNWATCH",
                        error = %e,
                        "Redis command failed"
                    );
                    self.note_command_failure(&e);
                    return Err(());
                }
                self.note_command_success()?;
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "compare-and-set GET",
                    error = %e,
                    "Redis command failed"
                );
                // WATCH already succeeded: attempt UNWATCH before failing closed.
                // A failed UNWATCH is itself a failure; never retry on a new conn.
                let unwatch: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                if let Err(unwatch_err) = unwatch {
                    warn!(
                        redis_url = %self.config.redacted_url(),
                        operation = "UNWATCH",
                        error = %unwatch_err,
                        "Redis command failed"
                    );
                }
                self.note_command_failure(&e);
                return Err(());
            }
        }

        // A `nil` EXEC reply means the watched key changed after the compare,
        // so the caller lost ownership in the race window. That is reported as
        // `Ok(false)`, never as a successful publication.
        let result: Result<Option<(String,)>, redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(expire_seconds(ttl_seconds))
            .query_async(&mut conn)
            .await;

        match result {
            Ok(Some(_)) => {
                self.note_command_success()?;
                Ok(true)
            }
            Ok(None) => {
                self.note_command_success()?;
                Ok(false)
            }
            Err(e) => {
                warn!(
                    redis_url = %self.config.redacted_url(),
                    operation = "compare-and-set EXEC",
                    error = %e,
                    "Redis transaction failed"
                );
                self.note_command_failure(&e);
                Err(())
            }
        }
    }

    /// Build a full Redis key whose prefix + logical rate key share one Redis
    /// Cluster hash slot: `{escaped-prefix:escaped-rate-key}:suffix…`.
    ///
    /// Redis hashes only the bytes between the first `{` and the following `}`,
    /// so every key produced for one `rate_key` — a request quota's whole
    /// sub-bucket ladder, the token-accounting sliding-window buckets, the
    /// datagram and byte counters — lands in the same slot and one multi-key
    /// transaction over them can never be a `CROSSSLOT` error. Different rate
    /// keys still spread across slots, so no single slot becomes the whole
    /// policy's hot spot. The tag components
    /// percent-escape `%`, braces, and `:` so caller-controlled identities
    /// cannot terminate the tag early or collide across the prefix/key
    /// boundary.
    ///
    /// This client refuses Cluster endpoints outright (see the module-level
    /// topology notes); the tag exists so the key layout is already correct if
    /// that ever changes, and it is inert on single-endpoint servers.
    pub fn make_slot_key(&self, rate_key: &str, suffix: &[&str]) -> String {
        let suffix_len: usize = suffix.iter().map(|component| component.len() + 1).sum();
        let prefix_len = slot_tag_component_len(&self.config.key_prefix);
        let rate_key_len = slot_tag_component_len(rate_key);
        let mut key = String::with_capacity(
            prefix_len
                .saturating_add(rate_key_len)
                .saturating_add(suffix_len)
                .saturating_add(3),
        );
        key.push('{');
        push_slot_tag_component(&mut key, &self.config.key_prefix);
        key.push(':');
        push_slot_tag_component(&mut key, rate_key);
        key.push('}');
        for component in suffix {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Build the `K + 3` sub-bucket keys of one trailing window, packed into a
    /// single allocation: the `K + 1` older buckets, the charged bucket, and
    /// the one after it.
    ///
    /// Key layout is
    /// `{escaped-prefix:escaped-rate-key}:{window_seconds}:{sub_index}`: the
    /// braces are the Redis Cluster hash tag (see [`Self::make_slot_key`]), so
    /// every key of one charge shares a slot, and naming the window makes two
    /// windows of one policy provably disjoint ladders rather than two index
    /// sequences that merely happen not to coincide.
    pub fn window_charge(
        &self,
        rate_key: &str,
        bucket: RedisSubBucket,
        ttl_seconds: u64,
    ) -> RedisWindowCharge {
        // One key is `{tag}` plus `:{window_seconds}:{sub_index}`; 20 digits is
        // the widest `u64`, so this reserves the whole packed buffer up front
        // and the loop below never reallocates.
        let key_len = slot_tag_component_len(&self.config.key_prefix)
            .saturating_add(slot_tag_component_len(rate_key))
            .saturating_add(45);
        let mut keys =
            String::with_capacity(key_len.saturating_mul(REDIS_WINDOW_SUB_BUCKET_KEYS + 2));
        let mut ranges = [(0_usize, 0_usize); REDIS_WINDOW_SUB_BUCKET_KEYS];
        for (slot, range) in ranges.iter_mut().enumerate() {
            // Oldest first: slot `K + 1` is the bucket this charge increments
            // and slot `K + 2` is the read-only bucket after it.
            // `saturating_sub` only clamps within the first `K + 1` sub-buckets
            // of the Unix epoch, and `saturating_add` only at the end of the
            // `u64` index space; both repeat a key, which double-counts and so
            // refuses conservatively.
            let index = if slot > REDIS_WINDOW_TRAILING_SUB_BUCKETS {
                bucket
                    .index
                    .saturating_add((slot - REDIS_WINDOW_TRAILING_SUB_BUCKETS) as u64)
            } else {
                bucket
                    .index
                    .saturating_sub((REDIS_WINDOW_TRAILING_SUB_BUCKETS - slot) as u64)
            };
            let start = keys.len();
            keys.push('{');
            push_slot_tag_component(&mut keys, &self.config.key_prefix);
            keys.push(':');
            push_slot_tag_component(&mut keys, rate_key);
            keys.push('}');
            // Formatting into a `String` cannot fail, and it appends the digits
            // without the per-index `to_string()` the two-bucket layout paid.
            let _ = write!(keys, ":{}:{}", bucket.window_seconds, index);
            *range = (start, keys.len());
        }
        let legacy_index = bucket.index / REDIS_WINDOW_SUB_BUCKETS as u64;
        let mut legacy_ranges = [(0_usize, 0_usize); 2];
        for (slot, index) in [legacy_index.saturating_sub(1), legacy_index]
            .into_iter()
            .enumerate()
        {
            let start = keys.len();
            keys.push('{');
            push_slot_tag_component(&mut keys, &self.config.key_prefix);
            keys.push(':');
            push_slot_tag_component(&mut keys, rate_key);
            keys.push('}');
            let _ = write!(keys, ":{index}");
            legacy_ranges[slot] = (start, keys.len());
        }
        RedisWindowCharge {
            keys,
            ranges,
            legacy_ranges,
            ttl_seconds,
            bucket,
        }
    }

    /// Build a full Redis key with the configured prefix.
    ///
    /// For keys that participate in a multi-key atomic operation use
    /// [`Self::make_slot_key`] instead so they share a hash slot.
    pub fn make_key(&self, components: &[&str]) -> String {
        let mut key = self.config.key_prefix.clone();
        for component in components {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Compute window index and elapsed fraction from the current wall clock.
    ///
    /// Both values come from **one** `SystemTime` sample so a boundary straddle
    /// cannot pair an index from one instant with a fraction from another.
    pub fn window_progress(window_seconds: u64) -> RedisWindowProgress {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::window_progress_at(now, window_seconds)
    }

    /// Deterministic window index / elapsed fraction for a captured epoch offset.
    ///
    /// `elapsed_fraction` preserves subsecond precision and stays in `[0, 1)`.
    pub fn window_progress_at(now: Duration, window_seconds: u64) -> RedisWindowProgress {
        let window = window_seconds.max(1);
        let total_nanos = now.as_nanos();
        let window_nanos = (window as u128).saturating_mul(1_000_000_000);
        // `window` is at least 1, so `window_nanos` is at least 1e9.
        let index = (total_nanos / window_nanos) as u64;
        let elapsed_nanos = total_nanos % window_nanos;
        let elapsed_fraction = elapsed_nanos as f64 / window_nanos as f64;
        RedisWindowProgress {
            index,
            elapsed_fraction,
        }
    }

    /// Compute the window index for a given epoch time and window duration.
    ///
    /// Window index = `floor(epoch_nanos / window_nanos)`. All gateway instances
    /// sharing the same Redis will use the same window boundaries since they
    /// share the system epoch clock.
    pub fn window_index(window_seconds: u64) -> u64 {
        Self::window_progress(window_seconds).index
    }

    /// Sub-bucket a request charges right now, from ONE wall-clock sample.
    ///
    /// One sample per window is what keeps the whole ladder internally
    /// consistent: a boundary straddle can shift which sub-bucket is charged,
    /// but it can never pair a charged bucket from one instant with older
    /// buckets read from another.
    pub fn sub_bucket(window_seconds: u64) -> RedisSubBucket {
        Self::sub_bucket_at(redis_epoch_now(), window_seconds)
    }

    /// Deterministic sub-bucket for a captured epoch offset.
    ///
    /// `index = floor(epoch_nanos / (window_nanos / REDIS_WINDOW_SUB_BUCKETS))`.
    /// Every gateway sharing one Redis derives the same ladder because they
    /// share the system epoch clock, exactly as the whole-window index did.
    pub fn sub_bucket_at(now: Duration, window_seconds: u64) -> RedisSubBucket {
        let window_seconds = window_seconds.max(1);
        let sub_bucket_nanos = redis_sub_bucket_nanos(window_seconds);
        let index = (now.as_nanos() / sub_bucket_nanos).min(u64::MAX as u128) as u64;
        RedisSubBucket {
            index,
            window_seconds,
        }
    }

    /// Return the Redis hostname for DNS pre-warming, if applicable.
    pub fn warmup_hostname(&self) -> Option<String> {
        self.config.hostname()
    }
}

impl Drop for RedisRateLimitClient {
    fn drop(&mut self) {
        let abort = match self.health_checker_abort.get_mut() {
            Ok(slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(abort) = abort {
            abort.abort();
        }
    }
}

impl std::fmt::Debug for RedisRateLimitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimitClient")
            .field("key_prefix", &self.config.key_prefix)
            .field("pool_size", &self.pool.len())
            .field("availability", &self.availability.describe())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RedisGetrangeEndIndexError, clamp_floored_total, floor_zero_compensation,
        redis_getrange_end_index,
    };

    #[test]
    fn redis_getrange_end_index_rejects_zero_and_platform_overflow() {
        assert_eq!(
            redis_getrange_end_index(0),
            Err(RedisGetrangeEndIndexError::ZeroCap)
        );
        assert_eq!(
            redis_getrange_end_index(usize::MAX),
            Err(RedisGetrangeEndIndexError::Overflow)
        );
        assert_eq!(redis_getrange_end_index(1).expect("1 fits"), 1);
        assert_eq!(redis_getrange_end_index(1024).expect("1 KiB fits"), 1024);
    }

    #[test]
    fn floor_zero_compensation_skips_non_negative_totals() {
        // A non-negative post-INCRBY value needs no correction: the floor
        // helper must return `None` so the wrapper keeps the value as-is.
        assert_eq!(floor_zero_compensation(0), None);
        assert_eq!(floor_zero_compensation(1), None);
        assert_eq!(floor_zero_compensation(i64::MAX), None);
    }

    #[test]
    fn floor_zero_compensation_returns_exact_deficit_for_negative_totals() {
        // A negative value must be compensated by exactly its negation so the
        // counter returns to zero — never a blind SET that could clobber a
        // concurrent positive increment.
        assert_eq!(floor_zero_compensation(-1), Some(1));
        assert_eq!(floor_zero_compensation(-500), Some(500));
    }

    #[test]
    fn floor_zero_compensation_saturates_at_min() {
        // `-i64::MIN` overflows; the helper must saturate to `i64::MAX` rather
        // than panic on overflow.
        assert_eq!(floor_zero_compensation(i64::MIN), Some(i64::MAX));
    }

    #[test]
    fn from_plugin_config_ignores_unrelated_plugin_root_keys() {
        use super::RedisConfig;
        use serde_json::json;

        // Shared Redis admission must not reject plugin-specific root keys;
        // each caller closes its own allowlist (unioned with REDIS_PLUGIN_CONFIG_KEYS).
        assert!(
            RedisConfig::from_plugin_config(
                &json!({
                    "sync_mode": "local",
                    "ttl_seconds": 60,
                    "cache_multimodal": "reject",
                    "window_seconds": 10,
                    "max_requests": 100,
                }),
                "test",
            )
            .expect("local mode with plugin keys must parse")
            .is_none()
        );

        let redis = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "ttl_seconds": 60,
                "window_seconds": 10,
                "max_requests": 100,
            }),
            "test",
        )
        .expect("redis mode with plugin keys must parse")
        .expect("redis mode must produce a config");
        assert_eq!(redis.url, "redis://127.0.0.1:6379/0");
    }

    #[test]
    fn from_plugin_config_validates_explicit_redis_fields_in_local_mode() {
        use super::RedisConfig;
        use serde_json::json;

        for config in [
            json!({"sync_mode": "local", "redis_url": "garbage"}),
            json!({"sync_mode": "local", "redis_tls": "yes"}),
            json!({"sync_mode": "local", "redis_key_prefix": ""}),
            json!({"sync_mode": "local", "redis_pool_size": 0}),
            json!({"sync_mode": "local", "redis_connect_timeout_seconds": 0}),
            json!({"sync_mode": "local", "redis_health_check_interval_seconds": 0}),
        ] {
            assert!(
                RedisConfig::from_plugin_config(&config, "test").is_err(),
                "malformed latent Redis config must be rejected: {config}"
            );
        }

        assert!(
            RedisConfig::from_plugin_config(
                &json!({
                    "sync_mode": "local",
                    "redis_url": "redis://127.0.0.1:6379/0",
                    "redis_tls": false,
                    "redis_key_prefix": "test",
                    "redis_pool_size": 1,
                    "redis_connect_timeout_seconds": 1,
                    "redis_health_check_interval_seconds": 1,
                    "redis_username": "user",
                    "redis_password": "secret",
                }),
                "test",
            )
            .expect("well-formed latent Redis config must parse")
            .is_none()
        );
    }

    #[test]
    fn literal_host_ip_and_hostname_are_duals() {
        use super::RedisConfig;
        use serde_json::json;

        let cfg = |url: &str| {
            RedisConfig::from_plugin_config(
                &json!({"sync_mode": "redis", "redis_url": url}),
                "test",
            )
            .unwrap()
            .unwrap()
        };

        // Literal-IP redis_url: `hostname()` returns None (so the hostname DNS
        // screen never sees it), which is exactly why `literal_host_ip()` must
        // surface the IP for the dial-time literal screen / fail-closed path.
        let metadata = cfg("redis://169.254.169.254:6379");
        assert_eq!(metadata.hostname(), None);
        assert_eq!(
            metadata.literal_host_ip(),
            Some("169.254.169.254".parse().unwrap())
        );

        let loopback = cfg("redis://127.0.0.1:6379");
        assert_eq!(
            loopback.literal_host_ip(),
            Some("127.0.0.1".parse().unwrap())
        );

        // Hostname redis_url: the dual — `hostname()` Some, `literal_host_ip()` None.
        let host = cfg("redis://cache.internal:6379");
        assert_eq!(host.hostname(), Some("cache.internal".to_string()));
        assert_eq!(host.literal_host_ip(), None);
    }

    #[test]
    fn clamp_floored_total_floors_negatives_at_zero() {
        // After the compensating write, a value that still reads negative (a
        // concurrent decrement raced the read-back) must clamp to zero so
        // callers never observe a negative usage; non-negative values pass
        // through unchanged.
        assert_eq!(clamp_floored_total(-7), 0);
        assert_eq!(clamp_floored_total(0), 0);
        assert_eq!(clamp_floored_total(42), 42);
    }
}

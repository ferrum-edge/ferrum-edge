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
//! Uses a **two-window weighted approximation** for sliding window rate limiting:
//!
//! 1. Two fixed windows are maintained: the current window and the previous window.
//! 2. The effective count = `prev_count * (1 - elapsed_fraction) + current_count`.
//! 3. Window index and `elapsed_fraction` are derived from **one** epoch timestamp
//!    with subsecond precision, so even a one-second window decays continuously
//!    through `[0, 1)` instead of staying stuck at `0.0`.
//! 4. This provides smooth rate limiting without boundary bursts.
//!
//! This is the same approach used by Cloudflare, Kong, and Nginx — no Lua scripts,
//! just native Redis `INCR`/`GET`/`EXPIRE` commands pipelined for efficiency.
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
//! one independent enforcement domain per gateway process, so it is an explicit
//! opt-in rather than the default.
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
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    validate_redis_database_selector(&parsed)?;
    Ok(())
}

/// Largest database index any Redis-family server can name.
///
/// The server's `databases` setting is a C `int` and `SELECT` refuses
/// `id >= server.dbnum`, so nothing above this bound can ever address a
/// database. A selector inside the bound may still exceed a particular
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
fn validate_redis_database_selector(url: &Url) -> Result<(), String> {
    let selector = url.path().trim_matches('/');
    if selector.is_empty() {
        return Ok(());
    }
    if selector.contains('/') {
        return Err(
            "redis rate limiter: 'redis_url' path must be a single database number \
             (for example '/0')"
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
/// closed — the default — and an explicit local fallback.
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
    /// Lifecycle registration for shared-replay readiness/metrics. Present
    /// only after [`Self::register_as_shared_replay_authority`]; independent of
    /// connections, endpoints, and credentials. Drop of this client drops the
    /// registration and retires the precomputed counts immediately.
    shared_replay_health: OnceLock<Arc<SharedReplayHealthRegistration>>,
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
        )
    }

    fn construct(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
        log_policy: RedisClientLogPolicy,
        retention: RedisRetentionRequirement,
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
            shared_replay_health: OnceLock::new(),
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
    async fn screen_and_arm(&self, conn: &mut redis::aio::MultiplexedConnection) -> bool {
        if !self.screen_established_connection(conn).await {
            return false;
        }
        conn.set_response_timeout(SCREENED_COMMAND_RESPONSE_TIMEOUT);
        true
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

    /// Read the previous sliding-window bucket, increment the current bucket,
    /// and set the current bucket expiry in one Redis transaction.
    ///
    /// The caller makes its allow/deny decision from the returned post-INCR
    /// current count, tying admission to the mutation even when many gateway
    /// instances race on the same key.
    #[allow(clippy::result_unit_err)]
    pub async fn sliding_window_increment(
        &self,
        previous_key: &str,
        current_key: &str,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        self.sliding_window_increment_by(previous_key, current_key, 1, ttl_seconds)
            .await
    }

    /// [`Self::sliding_window_increment`] with an explicit charge.
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
    /// so every key produced for one `rate_key` — the previous and current
    /// sliding-window buckets, the datagram and byte counters — lands in the
    /// same slot and one multi-key transaction over them can never be a
    /// `CROSSSLOT` error. Different rate keys still spread across slots, so no
    /// single slot becomes the whole policy's hot spot. The tag components
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

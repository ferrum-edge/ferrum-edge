//! DNS resolution cache with TTL, stale-while-revalidate, and background refresh.
//!
//! All gateway components (connection pool, health probes, service discovery,
//! plugin HTTP clients) share a single `DnsCache` instance so that:
//! - DNS lookups are off the hot request path (pre-warmed at startup)
//! - Answer data is shared per hostname while freshness is evaluated per caller
//!   (so distinct `dns_cache_ttl_seconds` values on shared backends stay isolated)
//! - IP literals are policy-screened but never occupy success-cache rows
//! - Stale-while-revalidate serves the old IP while refreshing in the background
//! - Background refresh keeps entries warm without per-request DNS query storms
//!
//! The cache also provides `DnsCacheResolver` — a `reqwest::dns::Resolve`
//! implementation that plugs into every `reqwest::Client` so all HTTP clients
//! automatically use the shared cache.

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use futures_util::stream::{self, StreamExt};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Wait for a shutdown signal on a watch channel.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return; // Sender dropped
        }
    }
}

/// Record type ordering for DNS queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordOrder {
    /// Use the record type that succeeded on the last lookup for this hostname.
    Cache,
    /// Query A records (IPv4).
    A,
    /// Query AAAA records (IPv6).
    Aaaa,
    /// Query SRV records (service discovery).
    Srv,
    /// Query CNAME records (canonical name).
    Cname,
}

/// Cached record type from a previous successful lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedRecordType {
    A,
    Aaaa,
    Srv,
    Cname,
}

/// Configuration for the DNS resolver and cache.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub global_overrides: HashMap<String, String>,
    /// Comma-separated nameserver addresses (ip[:port], IPv4 or IPv6).
    pub resolver_addresses: Option<String>,
    /// Path to a custom hosts file.
    pub hosts_file_path: Option<String>,
    /// Comma-separated DNS record type query order (e.g., "CACHE,SRV,A,CNAME").
    pub dns_order: Option<String>,
    /// Global TTL override (seconds) for positive DNS records. When set, ALL records
    /// use this TTL regardless of the DNS response. None = respect the record's native TTL.
    /// Disabled by default — the cache naturally respects each record's TTL.
    pub ttl_override_seconds: Option<u64>,
    /// Minimum TTL (seconds) floor for cached DNS records. Prevents extremely short
    /// TTLs (including 0) from causing excessive DNS queries. Default: 5.
    pub min_ttl_seconds: u64,
    /// How long stale data can be served while a background refresh is in
    /// progress. Also caps failed-entry lifetime and error-TTL exponential backoff.
    pub stale_ttl_seconds: u64,
    /// Base TTL (seconds) for caching DNS errors and empty responses. Doubles
    /// on consecutive failures up to the failed-entry lifetime cap.
    pub error_ttl_seconds: u64,
    /// Maximum number of entries in the DNS cache. Entries are evicted when this limit is reached.
    pub max_cache_size: usize,
    /// Percentage of TTL elapsed before background refresh triggers (1-99). Default: 90.
    /// At 90%, a 60s TTL entry refreshes after 54s (6s remaining).
    pub refresh_threshold_percent: u8,
    /// Threshold in milliseconds above which DNS resolutions are logged as slow.
    /// None = disabled (no slow resolution warnings). Default: None.
    pub slow_threshold_ms: Option<u64>,
    /// Maximum number of concurrent DNS warmup resolutions. Default: 500.
    pub warmup_concurrency: usize,
    /// Interval (seconds) for the background task that retries failed DNS lookups.
    /// Default: 10. Set to 0 to disable the retry task.
    pub failed_retry_interval_seconds: u64,
    /// Retry over TCP when UDP responses are truncated or fail. Default: true.
    pub try_tcp_on_error: bool,
    /// Number of nameservers to query concurrently per lookup. Default: 3.
    pub num_concurrent_reqs: usize,
    /// Maximum in-flight queries per multiplexed connection. Default: 512.
    pub max_active_requests: usize,
    /// Maximum number of concurrent stale-while-revalidate background refresh
    /// tasks system-wide, the per-cycle cap on proactive background refreshes
    /// (soonest-expiry selection and resolve concurrency), and the per-cycle
    /// cap on failed-DNS retries. Prevents unbounded task spawning when many
    /// distinct stale, near-expiry, or failed hostnames are hit simultaneously.
    /// Default: 64.
    pub max_concurrent_refreshes: usize,
    /// Backend egress policy for SSRF protection. Applied to every freshly
    /// resolved address before it is cached, on every insertion path (initial
    /// resolve, stale refresh, background refresh, failed-retry recovery) — so
    /// a hostname that re-resolves to a now-denied address (DNS rebinding) is
    /// rejected rather than served from cache. IP literals are screened on
    /// the same policy and never occupy a success-cache row.
    pub backend_allow_ips: crate::config::BackendEgressPolicy,
    /// DashMap shard count for the DNS cache and refresh-tracking maps.
    /// Sourced from `FERRUM_POOL_SHARD_AMOUNT` (same env var as connection
    /// pools) — both surfaces share the workload shape (high cardinality,
    /// multi-core write contention). `0` (default) auto-derives via
    /// [`crate::util::sharding::pool_shard_amount`].
    pub shard_amount: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            global_overrides: HashMap::new(),
            resolver_addresses: None,
            hosts_file_path: None,
            dns_order: None,
            ttl_override_seconds: None,
            min_ttl_seconds: 5,
            stale_ttl_seconds: 3600,
            error_ttl_seconds: 5,
            max_cache_size: 10_000,
            refresh_threshold_percent: 90,
            slow_threshold_ms: None,
            warmup_concurrency: 500,
            failed_retry_interval_seconds: 10,
            try_tcp_on_error: true,
            num_concurrent_reqs: 3,
            max_active_requests: 512,
            max_concurrent_refreshes: 64,
            backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
            shard_amount: 0,
        }
    }
}

fn normalize_global_overrides(
    global_overrides: HashMap<String, String>,
) -> HashMap<String, String> {
    global_overrides
        .into_iter()
        .map(|(hostname, ip)| (hostname.to_ascii_lowercase(), ip))
        .collect()
}

fn dns_hostname_key(hostname: &str) -> Cow<'_, str> {
    if hostname.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(hostname.to_ascii_lowercase())
    } else {
        Cow::Borrowed(hostname)
    }
}

/// Parse `hostname` as a dotted/colon IP literal without allocating.
///
/// Used to keep pod-IP / static-literal targets off the success cache so they
/// cannot displace short-TTL DNS hostnames under capacity eviction (issue #4293).
fn parse_ip_literal(hostname: &str) -> Option<IpAddr> {
    hostname.parse().ok()
}

fn dns_name_without_trailing_root(name: impl std::fmt::Display) -> String {
    let mut name = name.to_string();
    let len_without_root = name.trim_end_matches('.').len();
    name.truncate(len_without_root);
    name
}

/// RFC 2782 root target: a Target of "." means the service is decidedly not
/// available at this domain. After stripping the trailing root label the DNS
/// root is the empty name, so `"."`, `""`, and dotted-only names are all
/// treated as that unavailability signal.
pub(crate) fn is_rfc2782_root_target(host: &str) -> bool {
    host.trim_end_matches('.').is_empty()
}

/// Strip trailing root labels, reject the RFC 2782 `.` target, and ASCII-
/// lowercase so the host matches `UpstreamTarget` admission (`validate_host_entry`
/// requires lowercase; mixed-case DNS names must not be dropped as invalid).
pub(crate) fn normalize_srv_target_host(target: impl std::fmt::Display) -> Option<String> {
    let host = dns_name_without_trailing_root(target);
    if is_rfc2782_root_target(&host) {
        return None;
    }
    if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Some(host.to_ascii_lowercase())
    } else {
        Some(host)
    }
}

/// One RFC 2782 SRV answer as returned by [`DnsCache::resolve_srv`].
///
/// `resolve_srv` drops the root target (`.`) and port 0 before returning.
/// DNS-SD still re-runs `admit_registry_port`, then publishes EVERY remaining
/// priority tier with `priority` stamped into the reserved
/// `ferrum.srv.priority` tag. Choosing which tier serves traffic is a runtime,
/// health-aware decision made by the load balancer's shared candidate filter,
/// so a fully-unhealthy primary tier can actually fail over to the DR tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvAnswer {
    /// SRV target hostname with the trailing root label stripped and ASCII-lowercased.
    pub host: String,
    /// Dial port. `resolve_srv` never returns `0`.
    pub port: u16,
    /// RFC 2782 weight. DNS-SD remaps `0` to `default_weight` on publish.
    pub weight: u16,
    /// RFC 2782 priority. Lower values are preferred; DNS-SD publishes every
    /// retained tier up to `MAX_SRV_PRIORITY_TIERS`, and the load balancer
    /// selects the lowest healthy tier.
    pub priority: u16,
}

/// Admit one SRV RR into a dialable [`SrvAnswer`].
///
/// Discards the RFC 2782 root target and port 0, strips trailing root labels,
/// and ASCII-lowercases the host. SRV ports are already `u16`, so the only
/// `admit_registry_port` rejection that can occur here is `0`; DNS-SD still
/// routes the surviving port through that helper for contract parity with
/// Kubernetes and Consul.
pub(crate) fn try_srv_answer(
    target: impl std::fmt::Display,
    port: u16,
    weight: u16,
    priority: u16,
) -> Option<SrvAnswer> {
    let host = normalize_srv_target_host(target)?;
    if port == 0 {
        return None;
    }
    Some(SrvAnswer {
        host,
        port,
        weight,
        priority,
    })
}

/// Sentinel for [`DnsCacheEntry::shortest_per_proxy_ttl_secs`]: no per-proxy
/// override has been observed for this hostname yet.
const NO_PER_PROXY_TTL: u64 = u64::MAX;

/// Sentinel for [`DnsCacheEntry::longest_per_proxy_ttl_secs`]: no per-proxy
/// override has been observed yet (0 can never be a real observed TTL because
/// `effective_ttl` floors through `min_ttl`).
const NO_LONGEST_PER_PROXY_TTL: u64 = 0;

/// A cached DNS entry with TTL and stale-while-revalidate support.
///
/// Answer data (addresses, native TTL, publish time) is shared per hostname so
/// concurrent consumers deduplicate DNS queries. Freshness is evaluated per
/// caller against that shared publish time using the caller's own effective TTL
/// (`dns_cache_ttl_seconds` → global override → native), so proxy ordering and
/// warmup order cannot steal another proxy's TTL policy.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Arc<[IpAddr]>,
    /// Lock-free round-robin cursor shared by fresh and stale cache readers.
    /// Replacing an answer set on refresh resets the cursor to zero.
    next_start: Arc<AtomicU64>,
    /// When this answer (or error) was published into the cache.
    resolved_at: Instant,
    /// Native TTL from the DNS response at publish time (success entries).
    /// Caller freshness is `resolved_at + effective_ttl(native_ttl, caller_ttl)`.
    /// Unused for error entries (`Duration::ZERO`); error expiry uses
    /// `applied_ttl` instead.
    native_ttl: Duration,
    /// Absolute eviction deadline hint for the shared row. Success entries use
    /// [`DnsCache::shared_stale_deadline`] (longest effective TTL among
    /// policies actually observed for the hostname) so a short-TTL peer cannot
    /// evict data a longer-TTL peer still needs, while global/native short
    /// TTLs remain age-evictable only when a default consumer was observed.
    /// Error entries use the error backoff window (no stale-while-revalidate).
    /// Eviction recomputes success retention from observed consumer state so a
    /// later long-TTL or default note can extend the row without a rewrite.
    stale_deadline: Instant,
    /// Effective TTL used for proactive background-refresh thresholding.
    /// Success: shortest effective TTL among policies actually observed
    /// (default/global/native only when a `None` consumer was seen).
    /// Error: current error-backoff TTL. Recomputed on publish; scans also
    /// re-derive from observation atomics so a later short-TTL or default
    /// consumer can tighten refresh without waiting for the next resolve miss.
    applied_ttl: Duration,
    /// The record type that produced this result (for CACHE ordering).
    record_type_used: Option<CachedRecordType>,
    /// Whether this is a cached error/empty response.
    is_error: bool,
    /// Cooldown after a synchronous refresh of an expired success row failed.
    ///
    /// The shared answer must remain available to longer-TTL consumers that
    /// still consider it fresh. Callers already past their own stale window
    /// observe the cached refresh error until this deadline instead of
    /// hammering DNS or replacing the shared success with a hostname-wide
    /// error entry. The cooldown uses the same exponential error backoff as
    /// error rows (`consecutive_failures`), so a hostname whose DNS is down for
    /// the whole retention window of a long-TTL peer is not re-queried at a
    /// fixed `error_ttl` cadence for hours.
    refresh_error_deadline: Option<Instant>,
    /// Shortest observed explicit per-proxy `dns_cache_ttl_seconds` for this
    /// hostname. `NO_PER_PROXY_TTL` means no explicit override observed yet.
    /// Tightened atomically on cache hits so proactive refresh / failed-retry
    /// scheduling tracks the most aggressive explicit consumer without a
    /// DashMap write on the hot path. Never used to decide another caller's
    /// freshness.
    shortest_per_proxy_ttl_secs: Arc<AtomicU64>,
    /// Longest observed explicit per-proxy `dns_cache_ttl_seconds` for this
    /// hostname. `NO_LONGEST_PER_PROXY_TTL` means no explicit override observed
    /// yet. Raised atomically on hits so shared-row age eviction retains data
    /// for the most patient explicit consumer without shrinking when a
    /// short-TTL peer arrives later.
    longest_per_proxy_ttl_secs: Arc<AtomicU64>,
    /// Whether any caller with `dns_cache_ttl_seconds = None` (default /
    /// global / native policy) has been observed for this hostname. Set
    /// atomically on hits so retention and proactive refresh include that
    /// policy only when it was actually requested — never because native TTL
    /// exists on the shared answer. Shared across success refresh, error
    /// transitions, clones, and generation guards via the same `Arc`.
    default_consumer_observed: Arc<AtomicBool>,
    /// Consecutive failed resolutions for this hostname: error-entry failures,
    /// and refresh failures against a preserved success row (see
    /// `refresh_error_deadline`). Used to compute exponential error-TTL
    /// backoff. Reset to zero on every successful publication.
    consecutive_failures: u32,
    /// When the current failure streak began. `None` for success entries.
    /// Error entries older than the failed-entry lifetime cap (`stale_ttl`,
    /// or `MAX_TTL` when stale_ttl is zero) are evicted even when the
    /// failed-retry task is enabled, so decommissioned hostnames cannot
    /// occupy the cache forever.
    first_failed_at: Option<Instant>,
}

impl DnsCacheEntry {
    fn load_shortest_per_proxy_ttl(&self) -> Option<u64> {
        let secs = self.shortest_per_proxy_ttl_secs.load(Ordering::Relaxed);
        if secs == NO_PER_PROXY_TTL {
            None
        } else {
            Some(secs)
        }
    }

    fn load_longest_per_proxy_ttl(&self) -> Option<u64> {
        let secs = self.longest_per_proxy_ttl_secs.load(Ordering::Relaxed);
        if secs == NO_LONGEST_PER_PROXY_TTL {
            None
        } else {
            Some(secs)
        }
    }

    fn load_default_consumer_observed(&self) -> bool {
        self.default_consumer_observed.load(Ordering::Relaxed)
    }

    fn note_per_proxy_ttl(&self, per_proxy_ttl: Option<u64>) {
        let Some(secs) = per_proxy_ttl else {
            // A real default consumer was observed: retention / refresh must
            // include global/native effective policy for this hostname. Read
            // before writing — the flag is monotonic and most proxies carry no
            // `dns_cache_ttl_seconds`, so an unconditional store would dirty
            // this shared cache line on every cache hit for no state change.
            if !self.default_consumer_observed.load(Ordering::Relaxed) {
                self.default_consumer_observed
                    .store(true, Ordering::Relaxed);
            }
            return;
        };
        let mut cur = self.shortest_per_proxy_ttl_secs.load(Ordering::Relaxed);
        while secs < cur {
            match self.shortest_per_proxy_ttl_secs.compare_exchange_weak(
                cur,
                secs,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
        let mut longest = self.longest_per_proxy_ttl_secs.load(Ordering::Relaxed);
        while secs > longest {
            match self.longest_per_proxy_ttl_secs.compare_exchange_weak(
                longest,
                secs,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => longest = observed,
            }
        }
    }

    /// Absolute expiry instant for error entries (`resolved_at + applied_ttl`).
    fn error_expires_at(&self) -> Instant {
        self.resolved_at + self.applied_ttl
    }

    fn refresh_error_is_live(&self, now: Instant) -> bool {
        self.refresh_error_deadline
            .is_some_and(|deadline| deadline > now)
    }
}

/// A bounded, policy-approved DNS answer set in deterministic dial order.
///
/// Cloning this value only bumps an `Arc`; iterating it does not allocate. The
/// cache advances the start index atomically once per resolution so concurrent
/// callers distribute first attempts across the answer set while preserving
/// resolver order for failover.
#[derive(Clone, Debug)]
pub struct ResolvedAddresses {
    addresses: Arc<[IpAddr]>,
    start: usize,
}

impl ResolvedAddresses {
    fn single(address: IpAddr) -> Self {
        Self {
            addresses: Arc::from([address]),
            start: 0,
        }
    }

    fn rotated(addresses: Arc<[IpAddr]>, next_start: &AtomicU64) -> Self {
        let start = if addresses.len() > 1 {
            next_start.fetch_add(1, Ordering::Relaxed) as usize % addresses.len()
        } else {
            0
        };
        Self { addresses, start }
    }

    /// Keep only addresses in the same canonical family as `destination`.
    ///
    /// Session setup uses this so an IPv4 Service ClusterIP cannot dial an
    /// IPv6 backend (UDP `connect` succeeds, then ICMP refuses). Iteration
    /// order follows the already-rotated answer set; the result is not
    /// rotated again.
    pub fn matching_family(&self, destination: IpAddr) -> Self {
        let want_v4 = crate::util::client_identity::canonical_ip(destination).is_ipv4();
        let filtered: Vec<IpAddr> = self
            .iter()
            .filter(|ip| crate::util::client_identity::canonical_ip(*ip).is_ipv4() == want_v4)
            .collect();
        Self {
            addresses: Arc::from(filtered),
            start: 0,
        }
    }

    /// Build an answer set in the given dial order without rotating again.
    ///
    /// Used when a caller has already walked a rotated set and retained a
    /// subset (for example dropping inbound-relay loopback answers).
    pub(crate) fn from_dial_order(addresses: Vec<IpAddr>) -> Self {
        Self {
            addresses: Arc::from(addresses),
            start: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn first(&self) -> Option<IpAddr> {
        self.get(0)
    }

    pub fn get(&self, offset: usize) -> Option<IpAddr> {
        if offset >= self.addresses.len() {
            return None;
        }
        Some(self.addresses[(self.start + offset) % self.addresses.len()])
    }

    pub fn iter(&self) -> ResolvedAddressesIter<'_> {
        ResolvedAddressesIter {
            addresses: self,
            offset: 0,
        }
    }
}

#[derive(Clone)]
pub struct ResolvedAddressesIter<'a> {
    addresses: &'a ResolvedAddresses,
    offset: usize,
}

impl Iterator for ResolvedAddressesIter<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let address = self.addresses.get(self.offset)?;
        self.offset += 1;
        Some(address)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.addresses.len().saturating_sub(self.offset);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ResolvedAddressesIter<'_> {}

/// Failure returned after every DNS candidate was attempted.
#[derive(Debug)]
pub enum CandidateConnectError<E> {
    TimedOut { last_addr: SocketAddr },
    Failed { last_addr: SocketAddr, source: E },
}

/// Try a rotated DNS answer set sequentially within one wall-clock budget.
///
/// Each candidate receives an equal share of the budget remaining when its
/// attempt starts (`remaining / candidates_left`). An immediate failure moves
/// directly to the next address; a stalled attempt cannot consume a later
/// candidate's reserved share. The last candidate receives all remaining time.
pub async fn connect_candidates<T, E, F, Fut>(
    addresses: &ResolvedAddresses,
    port: u16,
    overall_budget: Duration,
    mut connect: F,
) -> Result<(T, SocketAddr), CandidateConnectError<E>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    debug_assert!(!addresses.is_empty());
    // Use Tokio's monotonic clock because the per-attempt deadlines are Tokio
    // timers too. This keeps budget accounting on one clock and makes the
    // invariant deterministic under paused-time tests.
    let started = tokio::time::Instant::now();
    let mut last_failure = None;

    for (index, ip) in addresses.iter().enumerate() {
        let addr = SocketAddr::new(ip, port);
        let elapsed = started.elapsed();
        let Some(remaining) = overall_budget.checked_sub(elapsed) else {
            return Err(CandidateConnectError::TimedOut { last_addr: addr });
        };
        let candidates_left = addresses.len() - index;
        let attempt_budget = remaining / u32::try_from(candidates_left).unwrap_or(u32::MAX);
        match tokio::time::timeout(attempt_budget, connect(addr)).await {
            Ok(Ok(value)) => return Ok((value, addr)),
            Ok(Err(source)) => last_failure = Some((addr, source)),
            Err(_) if candidates_left == 1 => {
                return Err(CandidateConnectError::TimedOut { last_addr: addr });
            }
            Err(_) => {}
        }
    }

    match last_failure {
        Some((last_addr, source)) => Err(CandidateConnectError::Failed { last_addr, source }),
        None => Err(CandidateConnectError::TimedOut {
            last_addr: SocketAddr::new(
                addresses
                    .first()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                port,
            ),
        }),
    }
}

/// Exact identity of an error-cache generation selected for a failed retry.
///
/// A background retry awaits DNS after selection; a foreground lookup/refresh
/// may replace the entry while that resolve is pending. Retry outcomes are
/// published only when the live cache entry still matches this snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FailedRetryGeneration {
    consecutive_failures: u32,
    first_failed_at: Instant,
    resolved_at: Instant,
    applied_ttl: Duration,
}

/// One hostname selected for a failed-retry cycle, with the error generation
/// that must still be present when the outcome is published.
#[derive(Clone, Debug)]
struct FailedRetryCandidate {
    hostname: String,
    per_proxy_ttl: Option<u64>,
    generation: FailedRetryGeneration,
}

/// Generation token for a success-cache row selected for background refresh
/// (stale-while-revalidate or proactive near-expiry).
///
/// `next_start` is replaced on every successful publish, so pointer equality
/// detects a newer foreground / SWR / competing refresh winner. `resolved_at`
/// is a second check so a recycled row cannot be mistaken for the same
/// generation. Vacant (evicted) keys never match.
#[derive(Clone, Debug)]
struct SuccessRefreshGeneration {
    next_start: Arc<AtomicU64>,
    resolved_at: Instant,
}

/// One hostname selected for a proactive refresh cycle.
#[derive(Clone, Debug)]
struct ProactiveRefreshCandidate {
    hostname: String,
    per_proxy_ttl: Option<u64>,
    generation: SuccessRefreshGeneration,
    expires_at: Instant,
    consecutive_failures: u32,
}

/// RAII ownership of one in-flight refresh (proactive or stale-while-revalidate).
///
/// Dropping this value — including on task abort / `select!` cancellation —
/// removes the per-hostname dedup marker and releases the system-wide refresh
/// semaphore permit. Never hold a DashMap guard across the resolve `.await`;
/// this struct owns only the dedup map Arc and the owned permit.
struct RefreshInFlight {
    hostname: String,
    refreshing: Arc<DashMap<String, ()>>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for RefreshInFlight {
    fn drop(&mut self) {
        self.refreshing.remove(&self.hostname);
    }
}

enum RefreshStart {
    Started(RefreshInFlight),
    AlreadyInProgress,
    ConcurrencyLimited,
}

/// Outcome of a generation-gated background success publish.
enum RefreshApply {
    /// The selected generation was still live and the success row was replaced.
    Published,
    /// Generation changed or the key was vacant. The last known good row is
    /// left untouched.
    Abandoned,
    /// `hostname` parsed as an IP literal. Any leftover success row was
    /// removed, matching [`DnsCache::cache_success_entry`] (issue #4293).
    /// Literals are never published as success entries.
    IpLiteral,
}

#[cfg(test)]
type BackgroundResolveOutput =
    Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error>;
#[cfg(test)]
type BackgroundResolveHook = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>> + Send + Sync,
>;

/// Asynchronous DNS resolver with in-memory caching, stale-while-revalidate,
/// error caching, configurable record type ordering, and hickory-resolver backend.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<DashMap<String, DnsCacheEntry>>,
    global_overrides: HashMap<String, String>,
    resolver: Arc<Resolver<TokioRuntimeProvider>>,
    /// Resolver dedicated to security-sensitive connection establishment.
    /// Its internal cache is disabled and it always queries A and AAAA so a
    /// caller cannot reuse a previously permitted answer after a DNS rebind.
    dial_resolver: Arc<Resolver<TokioRuntimeProvider>>,
    dns_order: Vec<DnsRecordOrder>,
    /// When set, ALL records use this fixed TTL regardless of DNS response.
    /// None = respect each record's native TTL (default).
    ttl_override: Option<Duration>,
    /// Minimum TTL floor — prevents 0-TTL or very short TTLs from causing
    /// excessive DNS queries. Default: 5s.
    min_ttl: Duration,
    stale_ttl: Duration,
    error_ttl: Duration,
    max_cache_size: usize,
    /// Tracks hostnames currently being refreshed in the background
    /// to prevent duplicate refresh tasks under concurrent load.
    refreshing: Arc<DashMap<String, ()>>,
    /// Bounds the total number of concurrent stale-while-revalidate refresh
    /// tasks system-wide. Without this, a storm of requests to many distinct
    /// stale hostnames would spawn unbounded tokio tasks.
    refresh_semaphore: Arc<Semaphore>,
    /// Threshold above which DNS resolutions are logged as slow. None = disabled.
    slow_threshold: Option<Duration>,
    /// Pre-computed label describing which nameservers are in use (for slow resolution logs).
    resolver_label: Arc<str>,
    /// Maximum number of concurrent DNS resolutions during config warmup.
    warmup_concurrency: usize,
    /// Backend egress policy for SSRF protection.
    backend_allow_ips: crate::config::BackendEgressPolicy,
    /// Percentage of TTL elapsed before background refresh triggers (1-99).
    refresh_threshold_percent: u8,
    /// Interval for the background task that retries failed DNS lookups.
    /// Duration::ZERO disables the retry task; clamped to `MAX_TTL` so the
    /// `tokio::time::interval` deadline arithmetic cannot overflow.
    failed_retry_interval: Duration,
    /// Maximum concurrent background DNS refresh / failed-retry work items.
    /// Caps the stale-while-revalidate semaphore, the number of near-expiry
    /// hostnames selected (and resolved concurrently) per proactive cycle,
    /// and the number of failed hostnames selected per retry cycle.
    max_concurrent_refreshes: usize,
    /// Test-only replacement for hickory during SWR and proactive background
    /// refresh. Compiled out of release builds; foreground `timed_resolve`
    /// never reads this field.
    #[cfg(test)]
    refresh_resolve_hook: Option<BackgroundResolveHook>,
}

impl DnsCache {
    /// Upper bound for every TTL-derived `Duration` (override, min, stale,
    /// error, and the effective record TTL). Matches the per-proxy
    /// `dns_cache_ttl` ceiling (1 day) so unbounded `FERRUM_DNS_*` env-var
    /// seconds cannot overflow the `Instant + Duration` / `Duration * u32`
    /// arithmetic on the resolution hot path (a reachable panic).
    const MAX_TTL: Duration = Duration::from_secs(86_400);
    /// Bound connector work and cache footprint for unusually large answers.
    /// Resolver order is preserved; duplicates and denied candidates do not
    /// consume a slot.
    const MAX_ADDRESSES_PER_ANSWER: usize = 32;

    /// Consecutive failure count below which failed-retry outcomes stay at
    /// `warn`. After this many prior failures, subsequent retry attempt /
    /// outcome logs demote to `debug` so a permanently dead hostname cannot
    /// spam the operator log every retry cycle.
    const FAILED_RETRY_WARN_FAILURES: u32 = 3;

    /// Cadence for proactive near-expiry refresh *and* independent
    /// `evict_expired` / `max_cache_size` enforcement. Both loops use
    /// `MissedTickBehavior::Delay` so a slow cycle cannot burst catch-up ticks.
    pub const BACKGROUND_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

    /// Wall-clock bound for one background (SWR, proactive or failed-retry)
    /// resolution.
    ///
    /// Hickory's default per-query timeout is 5s with 2 attempts (10s for one
    /// record type). This 15s ceiling covers one record type with margin while
    /// preventing a sequential `FERRUM_DNS_ORDER` walk (default
    /// `CACHE,SRV,A,CNAME`) from stalling a hostname for ~30s. A timeout is a
    /// failed refresh: the last known good success row is preserved and never
    /// rewritten or TTL-extended. The permit is released when the timeout
    /// elapses; `tokio::time::timeout` cancels the hung lookup future. For a
    /// failed-retry lookup a timeout is a failed retry: error backoff advances.
    pub const BACKGROUND_REFRESH_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

    /// Expose the configured backend egress policy for non-DNS backend target
    /// validation paths (for example, service discovery).
    pub fn backend_allow_ips(&self) -> crate::config::BackendEgressPolicy {
        self.backend_allow_ips.clone()
    }

    /// Clone this resolver while replacing only its dial-time egress policy.
    ///
    /// Security-sensitive helper clients such as ACME need the gateway's
    /// configured resolver, hosts file, and static overrides, but deliberately
    /// enforce a stricter address boundary than ordinary proxy backends. The
    /// resolver/cache internals stay shared; every fresh result is evaluated
    /// against the replacement policy before it is returned.
    #[cfg(feature = "acme")]
    pub(crate) fn with_backend_egress_policy(
        &self,
        backend_allow_ips: crate::config::BackendEgressPolicy,
    ) -> Self {
        let mut cloned = self.clone();
        cloned.backend_allow_ips = backend_allow_ips;
        cloned
    }

    pub fn new(config: DnsConfig) -> Self {
        let resolver_label: Arc<str> = match &config.resolver_addresses {
            Some(addrs) => Arc::from(addrs.as_str()),
            None => Arc::from("system"),
        };

        let resolver = build_resolver(&config);
        let dial_resolver = build_dial_resolver(&config);

        let dns_order = parse_dns_order(config.dns_order.as_deref());

        let shards = crate::util::sharding::pool_shard_amount(config.shard_amount);
        let global_overrides = normalize_global_overrides(config.global_overrides);

        Self {
            cache: Arc::new(DashMap::with_shard_amount(shards)),
            global_overrides,
            resolver: Arc::new(resolver),
            dial_resolver: Arc::new(dial_resolver),
            dns_order,
            ttl_override: config
                .ttl_override_seconds
                .map(|s| Duration::from_secs(s).min(Self::MAX_TTL)),
            min_ttl: Duration::from_secs(config.min_ttl_seconds).min(Self::MAX_TTL),
            stale_ttl: Duration::from_secs(config.stale_ttl_seconds).min(Self::MAX_TTL),
            error_ttl: Duration::from_secs(config.error_ttl_seconds).min(Self::MAX_TTL),
            max_cache_size: config.max_cache_size,
            refreshing: Arc::new(DashMap::with_shard_amount(shards)),
            refresh_semaphore: Arc::new(Semaphore::new(config.max_concurrent_refreshes.max(1))),
            slow_threshold: config.slow_threshold_ms.map(Duration::from_millis),
            resolver_label,
            warmup_concurrency: config.warmup_concurrency.max(1),
            backend_allow_ips: config.backend_allow_ips,
            refresh_threshold_percent: config.refresh_threshold_percent.clamp(1, 99),
            // Clamp like the other TTL-derived durations: an unbounded
            // FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS would otherwise overflow
            // tokio's `Instant::now() + period` deadline arithmetic inside
            // `tokio::time::interval` (a reachable panic, same class as F20).
            failed_retry_interval: Duration::from_secs(config.failed_retry_interval_seconds)
                .min(Self::MAX_TTL),
            max_concurrent_refreshes: config.max_concurrent_refreshes.max(1),
            #[cfg(test)]
            refresh_resolve_hook: None,
        }
    }

    /// Error-entry TTL after `consecutive_failures` prior failures.
    ///
    /// Starts at `error_ttl` (failures == 0) and doubles per consecutive
    /// failure, capped at the failed-entry lifetime (`stale_ttl`, or
    /// `MAX_TTL` when stale_ttl is zero). This keeps transient outages
    /// recoverable quickly while preventing a permanently dead hostname
    /// from being re-queried every retry interval forever.
    fn error_backoff_ttl(&self, consecutive_failures: u32) -> Duration {
        let shift = consecutive_failures.min(30);
        let ttl = self.error_ttl.saturating_mul(1u32 << shift);
        ttl.min(self.failed_entry_lifetime_cap())
    }

    /// Lifetime cap for failed DNS entries (backoff ceiling and age eviction).
    ///
    /// Uses `stale_ttl` when configured. When `stale_ttl` is zero (SWR
    /// disabled), falls back to `MAX_TTL` so error caching / retry still work
    /// instead of collapsing every error TTL to zero.
    fn failed_entry_lifetime_cap(&self) -> Duration {
        if self.stale_ttl > Duration::ZERO {
            self.stale_ttl.min(Self::MAX_TTL)
        } else {
            Self::MAX_TTL
        }
    }

    /// Whether an error entry has exceeded the failed-entry lifetime cap.
    fn error_entry_aged_out(entry: &DnsCacheEntry, now: Instant, max_age: Duration) -> bool {
        let Some(first_failed_at) = entry.first_failed_at else {
            // Incomplete error rows without a birth timestamp are treated as
            // immediately aged out so they cannot linger forever.
            return entry.is_error;
        };
        now.saturating_duration_since(first_failed_at) >= max_age
    }

    /// Check whether a resolved IP is allowed by the backend IP policy.
    /// Returns `Ok(addr)` if allowed, `Err` if denied.
    fn check_backend_ip_policy(
        &self,
        addr: IpAddr,
        hostname: &str,
    ) -> Result<IpAddr, anyhow::Error> {
        if let Some(reason) = self.backend_allow_ips.deny_reason(&addr) {
            anyhow::bail!(
                "Backend IP {} (resolved from '{}') denied by backend egress policy: {}",
                addr,
                hostname,
                reason
            );
        }
        Ok(addr)
    }

    fn screen_backend_addresses_policy(
        &self,
        addresses: Vec<IpAddr>,
        hostname: &str,
    ) -> Result<Arc<[IpAddr]>, anyhow::Error> {
        let mut approved = Vec::with_capacity(addresses.len().min(Self::MAX_ADDRESSES_PER_ANSWER));
        let mut first_denial = None;
        for addr in addresses {
            if approved.len() == Self::MAX_ADDRESSES_PER_ANSWER {
                break;
            }
            if approved.contains(&addr) {
                continue;
            }
            match self.check_backend_ip_policy(addr, hostname) {
                Ok(addr) => approved.push(addr),
                Err(error) => {
                    if first_denial.is_none() {
                        first_denial = Some(error);
                    }
                }
            }
        }
        if approved.is_empty() {
            return Err(first_denial.unwrap_or_else(|| {
                anyhow::anyhow!(
                    "DNS resolution returned no policy-approved addresses for {}",
                    hostname
                )
            }));
        }
        Ok(approved.into())
    }

    fn check_backend_addresses_policy(
        &self,
        addresses: &[IpAddr],
        hostname: &str,
    ) -> Result<(), anyhow::Error> {
        for &address in addresses {
            self.check_backend_ip_policy(address, hostname)?;
        }
        Ok(())
    }

    /// Per-caller fresh-until instant for a shared success entry.
    fn consumer_fresh_until(&self, entry: &DnsCacheEntry, per_proxy_ttl: Option<u64>) -> Instant {
        entry.resolved_at + self.effective_ttl(entry.native_ttl, per_proxy_ttl)
    }

    /// Per-caller stale-until instant (fresh window + `stale_ttl`).
    fn consumer_stale_until(&self, entry: &DnsCacheEntry, per_proxy_ttl: Option<u64>) -> Instant {
        self.consumer_fresh_until(entry, per_proxy_ttl) + self.stale_ttl
    }

    /// Shared-row retention TTL: longest effective TTL among policies actually
    /// observed for the hostname. Explicit-only rows use the longest explicit
    /// override even when native/global is longer; a default (`None`) consumer
    /// includes global/native so a shorter explicit peer cannot age-evict data
    /// still fresh for that default consumer. With no observations yet, fall
    /// back to global/native so brand-new rows stay coherent and reclaimable.
    fn shared_retention_ttl(
        &self,
        native_ttl: Duration,
        longest_per_proxy: Option<u64>,
        default_consumer_observed: bool,
    ) -> Duration {
        let mut retention = Duration::ZERO;
        if default_consumer_observed {
            retention = retention.max(self.effective_ttl(native_ttl, None));
        }
        if let Some(secs) = longest_per_proxy {
            retention = retention.max(self.effective_ttl(native_ttl, Some(secs)));
        }
        if retention.is_zero() {
            retention = self.effective_ttl(native_ttl, None);
        }
        retention.min(Self::MAX_TTL)
    }

    /// Absolute age-eviction deadline for a shared success answer.
    fn shared_stale_deadline(
        &self,
        resolved_at: Instant,
        native_ttl: Duration,
        longest_per_proxy: Option<u64>,
        default_consumer_observed: bool,
    ) -> Instant {
        resolved_at
            + self.shared_retention_ttl(native_ttl, longest_per_proxy, default_consumer_observed)
            + self.stale_ttl
    }

    /// Proactive-refresh TTL: shortest effective TTL among policies actually
    /// observed for this hostname. Include default/global/native only when a
    /// `None` consumer was observed; include the shortest explicit override
    /// when one was observed.
    fn observed_refresh_ttl(
        &self,
        native_ttl: Duration,
        shortest_per_proxy: Option<u64>,
        default_consumer_observed: bool,
    ) -> Duration {
        let mut refresh: Option<Duration> = None;
        if default_consumer_observed {
            let policy = self.effective_ttl(native_ttl, None);
            refresh = Some(match refresh {
                Some(prev) => prev.min(policy),
                None => policy,
            });
        }
        if let Some(secs) = shortest_per_proxy {
            let explicit = self.effective_ttl(native_ttl, Some(secs));
            refresh = Some(match refresh {
                Some(prev) => prev.min(explicit),
                None => explicit,
            });
        }
        refresh.unwrap_or_else(|| self.effective_ttl(native_ttl, None))
    }

    fn refresh_ttl_for_entry(&self, entry: &DnsCacheEntry) -> Duration {
        self.observed_refresh_ttl(
            entry.native_ttl,
            entry.load_shortest_per_proxy_ttl(),
            entry.load_default_consumer_observed(),
        )
    }

    fn cache_success_entry(
        &self,
        hostname: &str,
        addresses: Vec<IpAddr>,
        record_type: Option<CachedRecordType>,
        native_ttl: Duration,
        per_proxy_ttl: Option<u64>,
        consume_for_caller: bool,
    ) -> Result<ResolvedAddresses, anyhow::Error> {
        // This is the success insertion path for foreground resolves (including
        // vacant inserts). Stale-while-revalidate and proactive background
        // refresh publish through [`Self::apply_refresh_success`] so a stale
        // in-flight result cannot overwrite a newer winner or resurrect an
        // evicted hostname. Failed-retry recovery uses its own error-generation
        // helper. Cache reads intentionally trust entries accepted here.
        //
        // Clamp native TTL so unbounded record TTLs cannot overflow
        // `Instant + Duration` / `Duration * u32` arithmetic later.
        let native_ttl = native_ttl.min(Self::MAX_TTL);
        let addresses = self.screen_backend_addresses_policy(addresses, hostname)?;
        let cache_key = dns_hostname_key(hostname);

        // IP literals are policy-screened above but must not occupy a success
        // row. A 1-day native TTL would sort after short-TTL FQDNs in Phase-2
        // eviction, so discovered pod-IP churn would displace the hostnames the
        // cache exists to keep warm (issue #4293). Drop any leftover row so a
        // failed-retry of a pre-fix literal error cannot loop forever.
        if parse_ip_literal(cache_key.as_ref()).is_some() {
            self.cache.remove(cache_key.as_ref());
            return Ok(ResolvedAddresses {
                addresses,
                start: 0,
            });
        }

        let now = Instant::now();

        let next_start = Arc::new(AtomicU64::new(0));
        let build_entry =
            |shortest: Arc<AtomicU64>, longest: Arc<AtomicU64>, default_obs: Arc<AtomicBool>| {
                let shortest_ttl = {
                    let secs = shortest.load(Ordering::Relaxed);
                    if secs == NO_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let longest_ttl = {
                    let secs = longest.load(Ordering::Relaxed);
                    if secs == NO_LONGEST_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let default_consumer_observed = default_obs.load(Ordering::Relaxed);
                let applied_ttl =
                    self.observed_refresh_ttl(native_ttl, shortest_ttl, default_consumer_observed);
                DnsCacheEntry {
                    addresses: addresses.clone(),
                    next_start: next_start.clone(),
                    resolved_at: now,
                    native_ttl,
                    // Retain for the longest observed consumer policy; per-caller
                    // freshness is computed separately. Eviction recomputes from
                    // observation atomics so a later note can extend.
                    stale_deadline: self.shared_stale_deadline(
                        now,
                        native_ttl,
                        longest_ttl,
                        default_consumer_observed,
                    ),
                    applied_ttl,
                    record_type_used: record_type,
                    is_error: false,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: shortest,
                    longest_per_proxy_ttl_secs: longest,
                    default_consumer_observed: default_obs,
                    consecutive_failures: 0,
                    first_failed_at: None,
                }
            };

        // Preserve and tighten observation atomics under the DashMap entry
        // guard. A check-then-insert sequence lets two cold concurrent resolvers
        // each create independent atomics and makes the last writer reintroduce
        // order-dependent refresh/retention policy.
        match self.cache.entry(cache_key.into_owned()) {
            Entry::Occupied(mut occupied) => {
                occupied.get().note_per_proxy_ttl(per_proxy_ttl);
                let shortest = occupied.get().shortest_per_proxy_ttl_secs.clone();
                let longest = occupied.get().longest_per_proxy_ttl_secs.clone();
                let default_obs = occupied.get().default_consumer_observed.clone();
                occupied.insert(build_entry(shortest, longest, default_obs));
            }
            Entry::Vacant(vacant) => {
                let shortest = Arc::new(AtomicU64::new(per_proxy_ttl.unwrap_or(NO_PER_PROXY_TTL)));
                let longest = Arc::new(AtomicU64::new(
                    per_proxy_ttl.unwrap_or(NO_LONGEST_PER_PROXY_TTL),
                ));
                // Vacant insert observes this caller's policy: None marks the
                // default consumer; Some records only the explicit override.
                let default_obs = Arc::new(AtomicBool::new(per_proxy_ttl.is_none()));
                vacant.insert(build_entry(shortest, longest, default_obs));
            }
        }

        if consume_for_caller {
            Ok(ResolvedAddresses::rotated(addresses, &next_start))
        } else {
            Ok(ResolvedAddresses {
                addresses,
                start: 0,
            })
        }
    }

    /// Resolution priority:
    /// 1. Per-proxy static override (highest priority)
    /// 2. Global static overrides
    /// 3. IP literal (policy-screened, never cached)
    /// 4. Cache (fresh → return immediately; stale → return + background refresh)
    /// 5. Actual DNS resolution via hickory-resolver
    pub async fn resolve_candidates(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
        per_proxy_ttl: Option<u64>,
    ) -> Result<ResolvedAddresses, anyhow::Error> {
        let cache_key = dns_hostname_key(hostname);
        let cache_hostname = cache_key.as_ref();

        // 1. Check per-proxy static override first
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(ResolvedAddresses::single(
                self.check_backend_ip_policy(addr, hostname)?,
            ));
        }

        // 2. Check global overrides
        if let Some(ip_str) = self.global_overrides.get(cache_hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(ResolvedAddresses::single(
                self.check_backend_ip_policy(addr, hostname)?,
            ));
        }

        // 3. IP literals need no DNS and must not occupy a success-cache row.
        // Screen against backend IP policy here so warmup skipping literals
        // cannot become a divergent policy bypass (issue #4293).
        if let Some(addr) = parse_ip_literal(cache_hostname) {
            return Ok(ResolvedAddresses::single(
                self.check_backend_ip_policy(addr, hostname)?,
            ));
        }

        // 4. Check cache with per-consumer freshness + shared stale-while-revalidate
        let mut expired_success_generation = None;
        if let Some(entry) = self.cache.get(cache_hostname) {
            let now = Instant::now();
            // Track this caller's TTL for proactive refresh scheduling only —
            // never apply another consumer's TTL to this caller's freshness.
            entry.note_per_proxy_ttl(per_proxy_ttl);

            if !entry.is_error && !entry.addresses.is_empty() {
                let fresh_until = self.consumer_fresh_until(&entry, per_proxy_ttl);
                if fresh_until > now {
                    crate::runtime_metrics::global_ref().record_dns_hit();
                    return Ok(ResolvedAddresses::rotated(
                        entry.addresses.clone(),
                        &entry.next_start,
                    ));
                }

                // Stale for this consumer but within their SWR window — serve
                // shared data and trigger one deduplicated background refresh.
                if self.consumer_stale_until(&entry, per_proxy_ttl) > now {
                    let host = cache_hostname.to_string();
                    // Refresh publishes shared data; scheduling uses the
                    // shortest observed per-proxy (including this caller) so
                    // short-TTL peers keep getting updates.
                    let refresh_ttl = per_proxy_ttl.or_else(|| entry.load_shortest_per_proxy_ttl());
                    // Capture the served generation before spawning. Foreground
                    // synchronous resolves are not serialized by `refreshing`,
                    // so a later winner must be able to reject this result.
                    let generation = SuccessRefreshGeneration {
                        next_start: entry.next_start.clone(),
                        resolved_at: entry.resolved_at,
                    };
                    match self.try_begin_refresh(host) {
                        RefreshStart::Started(guard) => {
                            let cache = self.clone();
                            tokio::spawn(async move {
                                cache
                                    .refresh_entry(&guard.hostname, refresh_ttl, generation)
                                    .await;
                                drop(guard);
                            });
                            debug!(
                                "DNS serving stale entry for {} (background refresh triggered)",
                                hostname
                            );
                        }
                        RefreshStart::ConcurrencyLimited => {
                            debug!(
                                "DNS serving stale entry for {} (refresh skipped, concurrency limit reached)",
                                hostname
                            );
                        }
                        RefreshStart::AlreadyInProgress => {
                            debug!(
                                "DNS serving stale entry for {} (refresh already in progress)",
                                hostname
                            );
                        }
                    }
                    crate::runtime_metrics::global_ref().record_dns_stale();
                    return Ok(ResolvedAddresses::rotated(
                        entry.addresses.clone(),
                        &entry.next_start,
                    ));
                }
                if entry.refresh_error_is_live(now) {
                    // A shorter-TTL peer's failed synchronous refresh must not
                    // replace this shared answer and invalidate a longer-TTL
                    // peer that still considers it fresh. This caller is past
                    // its own stale window, so return the bounded cached error
                    // while leaving the shared success row intact.
                    crate::runtime_metrics::global_ref().record_dns_error();
                    anyhow::bail!(
                        "DNS resolution failed for {} (cached refresh error)",
                        hostname
                    );
                }
                // Past this consumer's stale window — fall through to sync resolve.
                // Shared row may still be fresh for longer-TTL peers; leave it.
                expired_success_generation = Some(entry.next_start.clone());
            } else if entry.is_error && entry.error_expires_at() > now {
                // Cached error that hasn't expired — return error immediately
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution failed for {} (cached error)", hostname);
            }
        }

        // 5. Perform actual DNS resolution.
        // Do not inherit another consumer's per-proxy TTL on miss — each caller
        // supplies its own policy (or falls through to global/native).
        match self.timed_resolve(cache_hostname).await {
            Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    addrs,
                    record_type,
                    native_ttl,
                    per_proxy_ttl,
                    true,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };

                debug!(
                    "DNS resolved {} -> {:?} (native_ttl={:?}, per_proxy_ttl={:?})",
                    hostname,
                    addrs
                        .first()
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                    native_ttl,
                    per_proxy_ttl
                );
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs)
            }
            Ok(_) | Err(_) if cache_hostname == "localhost" => {
                // Fallback for localhost — hickory-resolver may not read
                // /etc/hosts, so DNS lookup can fail.  Respect dns_order:
                // if AAAA appears before A, prefer IPv6 loopback.
                let addr = self.localhost_addr();
                let native_ttl = Duration::from_secs(3600);
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    vec![addr],
                    None,
                    native_ttl,
                    per_proxy_ttl,
                    true,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };
                debug!("DNS resolved localhost -> {} (built-in fallback)", addr);
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs)
            }
            Ok(_) => {
                self.cache_error(
                    cache_hostname,
                    per_proxy_ttl,
                    expired_success_generation.as_ref(),
                );
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
            }
            Err(e) => {
                self.cache_error(
                    cache_hostname,
                    per_proxy_ttl,
                    expired_success_generation.as_ref(),
                );
                crate::runtime_metrics::global_ref().record_dns_error();
                Err(e)
            }
        }
    }

    /// Resolve one address using the same rotating answer-set semantics as
    /// production connectors. New connection code should use
    /// [`Self::resolve_candidates`] so it can fail over.
    pub async fn resolve(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
        per_proxy_ttl: Option<u64>,
    ) -> Result<IpAddr, anyhow::Error> {
        self.resolve_candidates(hostname, per_proxy_override, per_proxy_ttl)
            .await?
            .first()
            .ok_or_else(|| anyhow::anyhow!("DNS resolution returned no addresses for {}", hostname))
    }

    /// Resolve a hostname to all known IP addresses (not just the first).
    ///
    /// Uses the same cache, overrides, and TTL logic as [`resolve`]. This is
    /// used by the database polling loop to detect when a FQDN's IP set has
    /// changed and trigger a pool reconnect.
    pub async fn resolve_all(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
        per_proxy_ttl: Option<u64>,
    ) -> Result<Vec<IpAddr>, anyhow::Error> {
        Ok(self
            .resolve_candidates(hostname, per_proxy_override, per_proxy_ttl)
            .await?
            .iter()
            .collect())
    }

    /// Resolve every A/AAAA address for security-sensitive connection setup.
    ///
    /// Unlike [`Self::resolve`] and [`Self::resolve_all`], this method never
    /// consults either DNS cache layer. It honors configured static overrides
    /// and the hosts file, but hostname lookups go to the configured resolver
    /// on every call. Every returned address is policy-screened as one atomic
    /// set: if any candidate is denied, the entire lookup fails before callers
    /// can dial an allowed decoy from a mixed answer.
    ///
    /// Callers must still apply their own wall-clock timeout and should recheck
    /// each candidate immediately before opening its socket. The latter keeps
    /// the policy decision adjacent to the dial and protects callers whose
    /// active policy is stricter than the policy carried by this cache.
    pub(crate) async fn resolve_all_fresh(
        &self,
        hostname: &str,
    ) -> Result<Vec<IpAddr>, anyhow::Error> {
        self.resolve_all_fresh_with_override(hostname, None).await
    }

    /// [`Self::resolve_all_fresh`] that also honors a per-proxy `dns_override`.
    ///
    /// The override has the same precedence as in [`Self::resolve_candidates`]
    /// — highest, above the global overrides and the resolver — so a dial-time,
    /// all-candidates lookup cannot silently reach a different address than
    /// ordinary backend dispatch for the same proxy. The override is still
    /// screened by the backend IP policy, so a denied literal fails the lookup
    /// instead of becoming an unscreened dial.
    ///
    /// `pub` rather than `pub(crate)` so the override/deny contract can be
    /// asserted directly from the external unit-test crate; the no-override
    /// projection stays crate-private.
    pub async fn resolve_all_fresh_with_override(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
    ) -> Result<Vec<IpAddr>, anyhow::Error> {
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
        }
        let cache_key = dns_hostname_key(hostname);
        let lookup_hostname = cache_key.as_ref();

        if let Some(ip_str) = self.global_overrides.get(lookup_hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
        }

        if let Some(addr) = parse_ip_literal(lookup_hostname) {
            return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
        }

        let lookup = match self.dial_resolver.lookup_ip(lookup_hostname).await {
            Ok(lookup) => lookup,
            Err(_) if lookup_hostname == "localhost" => {
                let addr = self.localhost_addr();
                return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
            }
            Err(error) => {
                anyhow::bail!("DNS dial-time resolution failed for {hostname}: {error}")
            }
        };

        let mut seen = HashSet::new();
        let addresses: Vec<IpAddr> = lookup.iter().filter(|addr| seen.insert(*addr)).collect();
        if addresses.is_empty() {
            anyhow::bail!("DNS dial-time resolution returned no addresses for {hostname}");
        }
        self.check_backend_addresses_policy(&addresses, hostname)?;
        Ok(addresses)
    }

    /// Refresh a single stale-while-revalidate cache entry in the background.
    ///
    /// Publication is generation-safe: a newer foreground/proactive winner or
    /// an eviction that removed the key causes this result to be abandoned.
    /// The DashMap guard is not held across the resolve `.await`. A hanging
    /// lookup is bounded by [`Self::BACKGROUND_REFRESH_RESOLVE_TIMEOUT`] so
    /// it cannot retain a shared refresh permit indefinitely.
    async fn refresh_entry(
        &self,
        hostname: &str,
        per_proxy_ttl: Option<u64>,
        generation: SuccessRefreshGeneration,
    ) {
        match self.refresh_resolve_with_timeout(hostname).await {
            Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                match self.apply_refresh_success(
                    hostname,
                    &generation,
                    addrs,
                    record_type,
                    native_ttl,
                    per_proxy_ttl,
                ) {
                    Ok(RefreshApply::Published) => {
                        debug!(
                            "DNS background refresh: {} refreshed (native_ttl={:?}, per_proxy_ttl={:?})",
                            hostname, native_ttl, per_proxy_ttl
                        );
                    }
                    Ok(RefreshApply::Abandoned) => {
                        debug!(
                            "DNS stale refresh: abandoning stale success for '{}' (cache generation changed during resolve)",
                            hostname
                        );
                    }
                    Ok(RefreshApply::IpLiteral) => {
                        debug!(
                            "DNS stale refresh: dropping leftover IP-literal row for '{}'",
                            hostname
                        );
                    }
                    Err(e) => {
                        warn!(
                            "DNS stale refresh: '{}' resolved but denied by IP policy: {}",
                            hostname, e
                        );
                    }
                }
            }
            Ok(_) => {
                warn!("DNS stale refresh: {} returned no addresses", hostname);
            }
            Err(e) => {
                warn!("DNS stale refresh failed for {}: {}", hostname, e);
            }
        }
    }

    /// Return the loopback address for localhost, respecting `dns_order`.
    /// If AAAA appears before A in the configured order, return `::1` (IPv6);
    /// otherwise return `127.0.0.1` (IPv4).  This mirrors what a real resolver
    /// would return for localhost on a dual-stack host.
    fn localhost_addr(&self) -> IpAddr {
        for order in &self.dns_order {
            match order {
                DnsRecordOrder::Aaaa => return IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                DnsRecordOrder::A => return IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                _ => continue,
            }
        }
        // Default to IPv4 if dns_order has no A/AAAA entries
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    }

    /// Cache a DNS error to prevent hammering DNS for known-bad hostnames.
    fn cache_error(
        &self,
        hostname: &str,
        per_proxy_ttl: Option<u64>,
        expired_success_generation: Option<&Arc<AtomicU64>>,
    ) {
        let cache_key = dns_hostname_key(hostname);
        let cache_hostname = cache_key.as_ref();
        let now = Instant::now();

        match self.cache.entry(cache_hostname.to_string()) {
            Entry::Occupied(mut occupied) if !occupied.get().is_error => {
                occupied.get().note_per_proxy_ttl(per_proxy_ttl);
                if expired_success_generation
                    .is_some_and(|generation| Arc::ptr_eq(generation, &occupied.get().next_start))
                {
                    // A short-TTL caller may be expired while a long-TTL peer
                    // still owns a fresh view of this shared answer. Preserve
                    // the answer and cache only a bounded refresh-error
                    // cooldown for callers past their own stale window.
                    if occupied.get().refresh_error_is_live(now) {
                        // A concurrent expired caller already armed this round's
                        // cooldown. Every racer passed the liveness gate before
                        // the first failure landed, so advancing the backoff per
                        // caller would slam a busy hostname straight to the cap
                        // on its first failed round.
                        debug!(
                            "DNS refresh error for {} already covered by a live cooldown",
                            hostname
                        );
                    } else {
                        // Back off like an error row: the shared row survives
                        // for the longest observed consumer, which can be far
                        // longer than the expired caller's own window, so a
                        // fixed `error_ttl` cooldown would re-query a dead
                        // hostname at that cadence for the whole retention
                        // period. `cache_success_entry` resets the streak on the
                        // next successful publication.
                        let mut preserved = occupied.get().clone();
                        let ttl = self.error_backoff_ttl(preserved.consecutive_failures);
                        let failures = preserved.consecutive_failures.saturating_add(1);
                        preserved.consecutive_failures = failures;
                        preserved.refresh_error_deadline = Some(now + ttl);
                        occupied.insert(preserved);
                        debug!(
                            "DNS cached refresh error for {} without replacing shared success (ttl={:?}, consecutive_failures={})",
                            hostname, ttl, failures
                        );
                    }
                } else {
                    // A successful refresh won the race while this lookup was
                    // in flight. Never taint that newer generation with a stale
                    // failure.
                    debug!(
                        "DNS ignored stale refresh error for {} after a newer success",
                        hostname
                    );
                }
            }
            Entry::Occupied(mut occupied) => {
                let current = occupied.get();
                current.note_per_proxy_ttl(per_proxy_ttl);
                let shortest = current.shortest_per_proxy_ttl_secs.clone();
                let longest = current.longest_per_proxy_ttl_secs.clone();
                let default_obs = current.default_consumer_observed.clone();
                let consecutive_failures = current.consecutive_failures.saturating_add(1);
                let first_failed_at = current.first_failed_at.or(Some(now));
                let ttl = self.error_backoff_ttl(consecutive_failures);
                occupied.insert(DnsCacheEntry {
                    addresses: Arc::from([]),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: now,
                    native_ttl: Duration::ZERO,
                    stale_deadline: now + ttl,
                    applied_ttl: ttl,
                    record_type_used: None,
                    is_error: true,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: shortest,
                    longest_per_proxy_ttl_secs: longest,
                    default_consumer_observed: default_obs,
                    consecutive_failures,
                    first_failed_at,
                });
                debug!(
                    "DNS cached error for {} (ttl={:?}, consecutive_failures={})",
                    hostname, ttl, consecutive_failures
                );
            }
            Entry::Vacant(vacant) => {
                let consecutive_failures = 0;
                let ttl = self.error_backoff_ttl(consecutive_failures);
                vacant.insert(DnsCacheEntry {
                    addresses: Arc::from([]),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: now,
                    native_ttl: Duration::ZERO,
                    stale_deadline: now + ttl,
                    applied_ttl: ttl,
                    record_type_used: None,
                    is_error: true,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                        per_proxy_ttl.unwrap_or(NO_PER_PROXY_TTL),
                    )),
                    longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                        per_proxy_ttl.unwrap_or(NO_LONGEST_PER_PROXY_TTL),
                    )),
                    default_consumer_observed: Arc::new(AtomicBool::new(per_proxy_ttl.is_none())),
                    consecutive_failures,
                    first_failed_at: Some(now),
                });
                debug!(
                    "DNS cached error for {} (ttl={:?}, consecutive_failures={})",
                    hostname, ttl, consecutive_failures
                );
            }
        }
    }

    /// Wraps `do_resolve` with timing instrumentation. When the configured
    /// slow threshold is exceeded, emits a warning log with the elapsed time.
    /// When no threshold is configured, delegates directly to `do_resolve`
    /// with zero overhead (no `Instant::now()` call).
    async fn timed_resolve(
        &self,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error> {
        let threshold = match self.slow_threshold {
            Some(t) => t,
            None => return self.do_resolve(hostname).await,
        };
        let start = Instant::now();
        let result = self.do_resolve(hostname).await;
        let elapsed = start.elapsed();
        if elapsed > threshold {
            warn!(
                "DNS slow resolution for {} took {:.1}ms (threshold: {}ms, nameservers: {})",
                hostname,
                elapsed.as_secs_f64() * 1000.0,
                threshold.as_millis(),
                self.resolver_label,
            );
        }
        result
    }

    /// Compute the effective TTL for a cache entry.
    ///
    /// Priority order:
    /// 1. Per-proxy TTL override (highest priority)
    /// 2. Global TTL override (`FERRUM_DNS_TTL_OVERRIDE_SECONDS`)
    /// 3. Native record TTL from the DNS response
    ///
    /// The result is clamped to `min_ttl` to prevent 0-TTL or very short TTLs
    /// from causing excessive DNS queries.
    fn effective_ttl(&self, record_ttl: Duration, per_proxy_ttl: Option<u64>) -> Duration {
        let base = per_proxy_ttl
            .map(Duration::from_secs)
            .or(self.ttl_override)
            .unwrap_or(record_ttl);
        base.max(self.min_ttl)
    }

    /// Perform DNS resolution using hickory-resolver with configurable record type ordering.
    ///
    /// Returns (addresses, record_type, native_ttl) where native_ttl is the TTL
    /// from the DNS response's `valid_until()` deadline. When `valid_until` is in
    /// the past (hickory-resolver clamped it), falls back to `min_ttl`.
    async fn do_resolve(
        &self,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error> {
        // Resolver-level bypass so leftover/test-seeded literal keys do not
        // hit hickory. `resolve_candidates` and `cache_success_entry` refuse to
        // persist these as success rows (issue #4293).
        if let Some(addr) = parse_ip_literal(hostname) {
            return Ok((vec![addr], None, Duration::from_secs(86400)));
        }

        // Determine the cached record type (for CACHE ordering)
        let cached_record_type = if self.dns_order.contains(&DnsRecordOrder::Cache) {
            self.cache.get(hostname).and_then(|e| e.record_type_used)
        } else {
            None
        };

        // Build the query order based on dns_order config
        let mut query_types: Vec<CachedRecordType> = Vec::new();
        for order in &self.dns_order {
            match order {
                DnsRecordOrder::Cache => {
                    if let Some(rt) = cached_record_type
                        && !query_types.contains(&rt)
                    {
                        query_types.push(rt);
                    }
                }
                DnsRecordOrder::A => {
                    if !query_types.contains(&CachedRecordType::A) {
                        query_types.push(CachedRecordType::A);
                    }
                }
                DnsRecordOrder::Aaaa => {
                    if !query_types.contains(&CachedRecordType::Aaaa) {
                        query_types.push(CachedRecordType::Aaaa);
                    }
                }
                DnsRecordOrder::Srv => {
                    if !query_types.contains(&CachedRecordType::Srv) {
                        query_types.push(CachedRecordType::Srv);
                    }
                }
                DnsRecordOrder::Cname => {
                    if !query_types.contains(&CachedRecordType::Cname) {
                        query_types.push(CachedRecordType::Cname);
                    }
                }
            }
        }

        // If no query types were produced (e.g., only CACHE with no cached type), use defaults
        if query_types.is_empty() {
            query_types = vec![CachedRecordType::A, CachedRecordType::Aaaa];
        }

        // Helper: extract the remaining TTL from a lookup's valid_until deadline.
        // Returns min_ttl if the deadline is already in the past.
        let extract_ttl = |valid_until: Instant| -> Duration {
            let now = Instant::now();
            if valid_until > now {
                valid_until.duration_since(now)
            } else {
                self.min_ttl
            }
        };

        // Try each record type in order
        for record_type in &query_types {
            match record_type {
                CachedRecordType::A => match self.resolver.ipv4_lookup(hostname).await {
                    Ok(lookup) => {
                        let addrs: Vec<IpAddr> = lookup
                            .answers()
                            .iter()
                            .filter_map(|r| match &r.data {
                                RData::A(a) => Some(IpAddr::V4(a.0)),
                                _ => None,
                            })
                            .collect();
                        if !addrs.is_empty() {
                            let native_ttl = extract_ttl(lookup.valid_until());
                            return Ok((addrs, Some(CachedRecordType::A), native_ttl));
                        }
                    }
                    Err(_) => continue,
                },
                CachedRecordType::Aaaa => match self.resolver.ipv6_lookup(hostname).await {
                    Ok(lookup) => {
                        let addrs: Vec<IpAddr> = lookup
                            .answers()
                            .iter()
                            .filter_map(|r| match &r.data {
                                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                                _ => None,
                            })
                            .collect();
                        if !addrs.is_empty() {
                            let native_ttl = extract_ttl(lookup.valid_until());
                            return Ok((addrs, Some(CachedRecordType::Aaaa), native_ttl));
                        }
                    }
                    Err(_) => continue,
                },
                CachedRecordType::Srv => {
                    match self.resolver.srv_lookup(hostname).await {
                        Ok(srv_lookup) => {
                            let srv_ttl = extract_ttl(srv_lookup.valid_until());
                            // ADDRESS-ONLY SRV mode. This resolver path answers
                            // "what IPs back this hostname"; the caller dials
                            // the proxy's own configured backend port, so the
                            // RR's `port` is never used. It therefore
                            // deliberately does NOT apply the DNS-SD
                            // registry-port admission that `resolve_srv` (the
                            // service-availability path) applies: a port-0 RR
                            // still carries a perfectly usable target address
                            // here, and dropping it would blackhole a resolvable
                            // host for a field this mode ignores. See
                            // `docs/dns_resolver.md` → "Address-only SRV mode".
                            //
                            // The RFC 2782 signals that ARE about availability
                            // still apply: the root target `.` means "decidedly
                            // not available" and is skipped, and answers are
                            // walked in ascending `priority` so the lowest
                            // reachable tier wins instead of whatever order the
                            // resolver happened to return. Sorting also makes
                            // the chosen address independent of answer order.
                            let mut ordered: Vec<_> = srv_lookup.answers().iter().collect();
                            ordered.sort_by_key(|record| match &record.data {
                                RData::SRV(srv) => srv.priority,
                                _ => u16::MAX,
                            });
                            for record in ordered {
                                let RData::SRV(ref srv) = record.data else {
                                    continue;
                                };
                                let target = dns_name_without_trailing_root(&srv.target);
                                if is_rfc2782_root_target(&target) {
                                    continue;
                                }
                                if let Ok(ip_lookup) = self.resolver.lookup_ip(&target).await {
                                    let addrs: Vec<IpAddr> = ip_lookup.iter().collect();
                                    if !addrs.is_empty() {
                                        // Use the shorter of SRV TTL and A/AAAA TTL
                                        let a_ttl = extract_ttl(ip_lookup.valid_until());
                                        let native_ttl = srv_ttl.min(a_ttl);
                                        return Ok((
                                            addrs,
                                            Some(CachedRecordType::Srv),
                                            native_ttl,
                                        ));
                                    }
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
                CachedRecordType::Cname => {
                    // For CNAME, use lookup_ip which follows CNAME chains automatically
                    match self.resolver.lookup_ip(hostname).await {
                        Ok(lookup) => {
                            let addrs: Vec<IpAddr> = lookup.iter().collect();
                            if !addrs.is_empty() {
                                let native_ttl = extract_ttl(lookup.valid_until());
                                return Ok((addrs, Some(CachedRecordType::Cname), native_ttl));
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
    }

    /// Returns the number of entries currently in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Whether a success or error row currently occupies this hostname.
    pub fn is_cached(&self, hostname: &str) -> bool {
        let cache_key = dns_hostname_key(hostname);
        self.cache.contains_key(cache_key.as_ref())
    }

    /// Check if a cached entry exists and is a cached error.
    #[allow(dead_code)]
    pub fn is_cached_error(&self, hostname: &str) -> bool {
        let cache_key = dns_hostname_key(hostname);
        self.cache
            .get(cache_key.as_ref())
            .map(|e| e.is_error && e.error_expires_at() > Instant::now())
            .unwrap_or(false)
    }

    /// Resolve a DNS SRV record to dialable [`SrvAnswer`] values.
    ///
    /// Used by DNS-SD service discovery. Does not use the cache — callers
    /// manage their own polling intervals. Reuses the configured resolver
    /// so custom nameservers from `FERRUM_DNS_RESOLVER_ADDRESS` are respected.
    ///
    /// Each answer carries RFC 2782 `priority`. The root target (`.`) and port
    /// 0 are discarded here: they are the RFC 2782 "service decidedly not
    /// available" signal and are not dialable. Surviving records keep their
    /// original weights. Tier FORMATION happens in DNS-SD after this filter, so
    /// a poisoned tier never becomes a tier (see
    /// `service_discovery::dns_sd::targets_from_srv_records`); tier SELECTION
    /// happens per request in the load balancer's candidate filter.
    ///
    /// Distinct from the address-only SRV mode in `do_resolve`, which
    /// answers "what IPs back this hostname", never dials the RR's port, and
    /// therefore deliberately does not reject port 0.
    pub async fn resolve_srv(&self, service_name: &str) -> Result<Vec<SrvAnswer>, anyhow::Error> {
        let srv_lookup = self
            .resolver
            .srv_lookup(service_name)
            .await
            .map_err(|e| anyhow::anyhow!("SRV lookup failed for {}: {}", service_name, e))?;

        let mut results = Vec::new();
        let mut dropped = 0usize;
        for record in srv_lookup.answers() {
            let RData::SRV(ref srv) = record.data else {
                continue;
            };
            let Some(answer) = try_srv_answer(&srv.target, srv.port, srv.weight, srv.priority)
            else {
                dropped += 1;
                continue;
            };
            results.push(answer);
        }

        if dropped > 0 {
            debug!(
                service = %service_name,
                dropped,
                admitted = results.len(),
                "SRV lookup discarded RFC 2782 unavailability records"
            );
        }

        Ok(results)
    }

    /// Evict expired entries and enforce max cache size.
    /// Removes entries past their lifetime first, then — if still over capacity —
    /// prefers error entries for eviction over live success entries (oldest
    /// logical expiry within each class) so failed hostnames cannot displace
    /// working cache rows.
    ///
    /// Error entries are retained past their per-attempt error TTL so the
    /// failed-retry task can re-attempt them, but they are still age-capped
    /// at `stale_ttl` from `first_failed_at` — even when the retry task is
    /// enabled — so decommissioned hostnames cannot occupy the cache forever.
    /// When the retry task is disabled, error entries follow the normal
    /// stale-deadline eviction path.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let retry_enabled = self.failed_retry_interval > Duration::ZERO;
        let error_max_age = self.failed_entry_lifetime_cap();

        // Phase 1: Remove entries past their lifetime.
        // - Success entries: past recomputed shared retention from policies
        //   actually observed for the hostname (+ stale_ttl).
        // - Error entries with retry enabled: past first_failed_at + stale_ttl.
        // - Error entries with retry disabled: past stale_deadline (same as
        //   success), so they cannot accumulate unbounded without a consumer.
        self.cache.retain(|_, entry| {
            if entry.is_error {
                if Self::error_entry_aged_out(entry, now, error_max_age) {
                    return false;
                }
                if retry_enabled {
                    return true;
                }
                return entry.stale_deadline > now;
            }
            self.shared_stale_deadline(
                entry.resolved_at,
                entry.native_ttl,
                entry.load_longest_per_proxy_ttl(),
                entry.load_default_consumer_observed(),
            ) > now
        });

        // Phase 2: If still over capacity, evict to 75%. Prefer error entries
        // over live success entries so a backlog of failed hostnames cannot
        // displace working cache rows; within each class, oldest logical expiry
        // first (backed-off error TTLs sort later among errors).
        if self.cache.len() > self.max_cache_size {
            let target_size = self.max_cache_size * 3 / 4; // Evict to 75% capacity
            let mut entries: Vec<(String, bool, Instant)> = self
                .cache
                .iter()
                .map(|e| {
                    let expires = if e.is_error {
                        e.error_expires_at()
                    } else {
                        self.shared_stale_deadline(
                            e.resolved_at,
                            e.native_ttl,
                            e.load_longest_per_proxy_ttl(),
                            e.load_default_consumer_observed(),
                        )
                    };
                    (e.key().clone(), e.is_error, expires)
                })
                .collect();
            entries.sort_by(|a, b| match (a.1, b.1) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.2.cmp(&b.2),
            });

            let to_remove = self.cache.len().saturating_sub(target_size);
            for (hostname, _, _) in entries.into_iter().take(to_remove) {
                self.cache.remove(&hostname);
            }

            debug!(
                "DNS cache eviction: trimmed to {} entries (max: {})",
                self.cache.len(),
                self.max_cache_size
            );
        }
    }

    /// Select error entries eligible for a failed-retry cycle.
    ///
    /// Returns at most `max_concurrent_refreshes` hostnames whose error TTL
    /// has expired and whose failure streak is still within `stale_ttl`.
    /// Aged-out error entries are removed immediately. Candidates are ordered
    /// by `first_failed_at` (oldest first) so a large backlog cannot starve
    /// long-lived failures behind a burst of newer ones.
    ///
    /// Each candidate carries an exact error-generation snapshot so the later
    /// publish path can refuse stale outcomes if a foreground lookup/refresh
    /// replaced the entry while DNS was in flight.
    fn select_failed_retry_candidates(&self, now: Instant) -> Vec<FailedRetryCandidate> {
        let error_max_age = self.failed_entry_lifetime_cap();
        let mut aged_out: Vec<String> = Vec::new();
        let mut candidates: Vec<FailedRetryCandidate> = Vec::new();

        for entry in self.cache.iter() {
            if !entry.is_error {
                continue;
            }
            if Self::error_entry_aged_out(entry.value(), now, error_max_age) {
                aged_out.push(entry.key().clone());
                continue;
            }
            if entry.error_expires_at() <= now {
                let first_failed_at = entry.first_failed_at.unwrap_or(entry.error_expires_at());
                candidates.push(FailedRetryCandidate {
                    hostname: entry.key().clone(),
                    per_proxy_ttl: entry.load_shortest_per_proxy_ttl(),
                    generation: FailedRetryGeneration {
                        consecutive_failures: entry.consecutive_failures,
                        first_failed_at,
                        resolved_at: entry.resolved_at,
                        applied_ttl: entry.applied_ttl,
                    },
                });
            }
        }

        for hostname in aged_out {
            self.remove_aged_out_failed_retry_candidate(&hostname, now, error_max_age);
        }

        candidates.sort_by_key(|c| c.generation.first_failed_at);
        candidates.truncate(self.max_concurrent_refreshes);
        candidates
    }

    /// Whether `entry` is still the exact error generation selected for retry.
    fn matches_failed_retry_generation(
        entry: &DnsCacheEntry,
        generation: &FailedRetryGeneration,
    ) -> bool {
        entry.is_error
            && entry.consecutive_failures == generation.consecutive_failures
            && entry.first_failed_at == Some(generation.first_failed_at)
            && entry.resolved_at == generation.resolved_at
            && entry.applied_ttl == generation.applied_ttl
    }

    /// Remove an aged-out retry candidate only when the current map entry is
    /// still an aged error. Selection releases its DashMap guard before this
    /// cleanup runs, so an unconditional remove by hostname could otherwise
    /// delete a newer foreground success published in that interval.
    fn remove_aged_out_failed_retry_candidate(
        &self,
        hostname: &str,
        now: Instant,
        max_age: Duration,
    ) {
        if let Entry::Occupied(occupied) = self.cache.entry(hostname.to_string())
            && occupied.get().is_error
            && Self::error_entry_aged_out(occupied.get(), now, max_age)
        {
            occupied.remove();
        }
    }

    /// Publish a failed-retry success only if the selected error generation is
    /// still live. IP-policy validation runs before any map mutation; the
    /// generation check and replacement are atomic under the DashMap entry
    /// guard (no check-then-insert TOCTOU). The guard is never held across
    /// await — callers resolve DNS before invoking this.
    ///
    /// Returns `Ok(Some(addrs))` when published, `Ok(None)` when the generation
    /// changed or the key was removed, and `Err` when addresses are denied by
    /// IP policy (nothing is written).
    fn apply_failed_retry_success(
        &self,
        hostname: &str,
        generation: &FailedRetryGeneration,
        addresses: Vec<IpAddr>,
        record_type: Option<CachedRecordType>,
        native_ttl: Duration,
        per_proxy_ttl: Option<u64>,
    ) -> Result<Option<Vec<IpAddr>>, anyhow::Error> {
        let native_ttl = native_ttl.min(Self::MAX_TTL);
        // Validate before taking the shard lock so a denied answer is never
        // published and the guard is not held across policy work.
        let addresses = self.screen_backend_addresses_policy(addresses, hostname)?;
        let cache_key = dns_hostname_key(hostname);
        let now = Instant::now();

        match self.cache.entry(cache_key.into_owned()) {
            Entry::Occupied(mut occupied) => {
                if !Self::matches_failed_retry_generation(occupied.get(), generation) {
                    return Ok(None);
                }
                let shortest = occupied.get().shortest_per_proxy_ttl_secs.clone();
                let longest = occupied.get().longest_per_proxy_ttl_secs.clone();
                let default_obs = occupied.get().default_consumer_observed.clone();
                occupied.get().note_per_proxy_ttl(per_proxy_ttl);
                let shortest_ttl = {
                    let secs = shortest.load(Ordering::Relaxed);
                    if secs == NO_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let longest_ttl = {
                    let secs = longest.load(Ordering::Relaxed);
                    if secs == NO_LONGEST_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let default_consumer_observed = default_obs.load(Ordering::Relaxed);
                let applied_ttl =
                    self.observed_refresh_ttl(native_ttl, shortest_ttl, default_consumer_observed);
                occupied.insert(DnsCacheEntry {
                    addresses: addresses.clone(),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: now,
                    native_ttl,
                    stale_deadline: self.shared_stale_deadline(
                        now,
                        native_ttl,
                        longest_ttl,
                        default_consumer_observed,
                    ),
                    applied_ttl,
                    record_type_used: record_type,
                    is_error: false,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: shortest,
                    longest_per_proxy_ttl_secs: longest,
                    default_consumer_observed: default_obs,
                    consecutive_failures: 0,
                    first_failed_at: None,
                });
                Ok(Some(addresses.as_ref().to_vec()))
            }
            Entry::Vacant(_) => Ok(None),
        }
    }

    /// Re-cache a failed-retry error only if the selected error generation is
    /// still live. Check and replacement are atomic under the DashMap entry
    /// guard. If the generation is live but already past the failed-entry age
    /// cap (e.g. a slow resolve crossed the boundary), the entry is removed
    /// instead of being extended. Returns `true` when a new error was published.
    fn apply_failed_retry_error(
        &self,
        hostname: &str,
        generation: &FailedRetryGeneration,
        per_proxy_ttl: Option<u64>,
    ) -> bool {
        let cache_key = dns_hostname_key(hostname);
        let now = Instant::now();
        let error_max_age = self.failed_entry_lifetime_cap();

        match self.cache.entry(cache_key.into_owned()) {
            Entry::Occupied(mut occupied) => {
                let current = occupied.get();
                if !Self::matches_failed_retry_generation(current, generation) {
                    return false;
                }
                // Do not let a slow in-flight retry re-extend residency past the
                // lifetime cap — drop the entry so decommissioned names leave.
                if Self::error_entry_aged_out(current, now, error_max_age) {
                    occupied.remove();
                    return false;
                }
                let shortest = current.shortest_per_proxy_ttl_secs.clone();
                let longest = current.longest_per_proxy_ttl_secs.clone();
                let default_obs = current.default_consumer_observed.clone();
                current.note_per_proxy_ttl(per_proxy_ttl);
                let consecutive_failures = current.consecutive_failures.saturating_add(1);
                let first_failed_at = current.first_failed_at.or(Some(now));
                let ttl = self.error_backoff_ttl(consecutive_failures);
                occupied.insert(DnsCacheEntry {
                    addresses: Arc::from([]),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: now,
                    native_ttl: Duration::ZERO,
                    stale_deadline: now + ttl,
                    applied_ttl: ttl,
                    record_type_used: None,
                    is_error: true,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: shortest,
                    longest_per_proxy_ttl_secs: longest,
                    default_consumer_observed: default_obs,
                    consecutive_failures,
                    first_failed_at,
                });
                debug!(
                    "DNS cached error for {} (ttl={:?}, consecutive_failures={})",
                    hostname, ttl, consecutive_failures
                );
                true
            }
            Entry::Vacant(_) => false,
        }
    }

    /// Run one failed-retry cycle: select eligible error entries, re-resolve
    /// them with bounded concurrency, and re-cache / promote outcomes only
    /// when the selected error generation is still current.
    async fn run_failed_retry_cycle(&self) {
        let now = Instant::now();
        let to_retry = self.select_failed_retry_candidates(now);
        if to_retry.is_empty() {
            return;
        }

        debug!(
            "DNS failed retry: attempting re-resolution for {} hostname(s)",
            to_retry.len()
        );

        let concurrency = self.max_concurrent_refreshes;
        stream::iter(to_retry)
            .for_each_concurrent(concurrency, |candidate| {
                let cache = self.clone();
                async move {
                    let hostname = candidate.hostname;
                    let per_proxy_ttl = candidate.per_proxy_ttl;
                    let generation = candidate.generation;
                    let noisy =
                        generation.consecutive_failures < Self::FAILED_RETRY_WARN_FAILURES;
                    if noisy {
                        warn!(
                            "DNS failed retry: re-attempting resolution for '{}'",
                            hostname
                        );
                    } else {
                        debug!(
                            "DNS failed retry: re-attempting resolution for '{}'",
                            hostname
                        );
                    }

                    // Same wall-clock bound as SWR/proactive refresh: a hung
                    // lookup is a failed retry (backoff advances) instead of
                    // stalling the whole cycle on hickory's per-type timeouts.
                    match cache.refresh_resolve_with_timeout(&hostname).await {
                        Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                            let applied_ttl =
                                cache.effective_ttl(native_ttl, per_proxy_ttl);
                            match cache.apply_failed_retry_success(
                                &hostname,
                                &generation,
                                addrs,
                                record_type,
                                native_ttl,
                                per_proxy_ttl,
                            ) {
                                Ok(Some(addrs)) => {
                                    // Successful recovery is always worth a warn
                                    // so operators notice the outage ended.
                                    warn!(
                                        "DNS failed retry: '{}' resolved successfully -> {:?} (ttl={:?})",
                                        hostname, addrs[0], applied_ttl
                                    );
                                }
                                Ok(None) => {
                                    debug!(
                                        "DNS failed retry: abandoning stale success for '{}' (cache generation changed during resolve)",
                                        hostname
                                    );
                                }
                                Err(e) => {
                                    // Policy denial is a failed retry outcome:
                                    // advance backoff (or drop if aged out) so
                                    // the expired error is not re-selected every
                                    // cycle until the age cap alone clears it.
                                    let published = cache.apply_failed_retry_error(
                                        &hostname,
                                        &generation,
                                        per_proxy_ttl,
                                    );
                                    if noisy {
                                        warn!(
                                            "DNS failed retry: '{}' resolved but denied by IP policy: {}",
                                            hostname, e
                                        );
                                    } else {
                                        debug!(
                                            "DNS failed retry: '{}' resolved but denied by IP policy: {}",
                                            hostname, e
                                        );
                                    }
                                    if !published {
                                        debug!(
                                            "DNS failed retry: abandoning policy-denied result for '{}' (cache generation changed or aged out during resolve)",
                                            hostname
                                        );
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            if cache.apply_failed_retry_error(
                                &hostname,
                                &generation,
                                per_proxy_ttl,
                            ) {
                                if noisy {
                                    warn!(
                                        "DNS failed retry: '{}' still returning no addresses",
                                        hostname
                                    );
                                } else {
                                    debug!(
                                        "DNS failed retry: '{}' still returning no addresses",
                                        hostname
                                    );
                                }
                            } else {
                                debug!(
                                    "DNS failed retry: abandoning stale empty result for '{}' (cache generation changed during resolve)",
                                    hostname
                                );
                            }
                        }
                        Err(e) => {
                            if cache.apply_failed_retry_error(
                                &hostname,
                                &generation,
                                per_proxy_ttl,
                            ) {
                                if noisy {
                                    warn!(
                                        "DNS failed retry: '{}' still failing: {}",
                                        hostname, e
                                    );
                                } else {
                                    debug!(
                                        "DNS failed retry: '{}' still failing: {}",
                                        hostname, e
                                    );
                                }
                            } else {
                                debug!(
                                    "DNS failed retry: abandoning stale failure for '{}' (cache generation changed during resolve)",
                                    hostname
                                );
                            }
                        }
                    }
                }
            })
            .await;
    }

    /// Claim one system-wide refresh slot for `hostname`.
    ///
    /// The hostname is claimed first so two racers for the same name cannot
    /// both consume a scarce semaphore permit before discovering they are
    /// duplicates. The permit is taken only after that claim; both are owned
    /// by [`RefreshInFlight`] so abort/cancellation cannot leak either.
    /// Sync: never called while holding a cache-map guard across `.await`.
    fn try_begin_refresh(&self, hostname: String) -> RefreshStart {
        match self.refreshing.entry(hostname) {
            Entry::Occupied(_) => RefreshStart::AlreadyInProgress,
            Entry::Vacant(vacant) => match self.refresh_semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    let hostname = vacant.key().clone();
                    vacant.insert(());
                    RefreshStart::Started(RefreshInFlight {
                        hostname,
                        refreshing: Arc::clone(&self.refreshing),
                        _permit: permit,
                    })
                }
                Err(_) => RefreshStart::ConcurrencyLimited,
            },
        }
    }

    /// Whether `entry` is still the success generation selected for background
    /// refresh. Pointer equality on `next_start` detects a newer publisher;
    /// `resolved_at` rejects a recycled row. Error rows belong to the
    /// failed-retry task and never match.
    fn matches_success_refresh_generation(
        entry: &DnsCacheEntry,
        generation: &SuccessRefreshGeneration,
    ) -> bool {
        !entry.is_error
            && Arc::ptr_eq(&entry.next_start, &generation.next_start)
            && entry.resolved_at == generation.resolved_at
    }

    /// Select success entries eligible for a proactive refresh cycle.
    ///
    /// Returns at most `max_concurrent_refreshes` hostnames whose remaining
    /// refresh TTL is inside the configured threshold window, ordered by
    /// soonest logical expiry. Error entries are owned by the failed-retry
    /// task and are never selected. DashMap guards are dropped before return.
    fn select_proactive_refresh_candidates(&self, now: Instant) -> Vec<ProactiveRefreshCandidate> {
        let refresh_remaining_pct = (100 - self.refresh_threshold_percent as u32).max(1);
        let mut candidates: Vec<ProactiveRefreshCandidate> = Vec::new();

        for entry in self.cache.iter() {
            if entry.is_error {
                continue;
            }
            let refresh_ttl = self.refresh_ttl_for_entry(entry.value());
            let expires_at = entry.resolved_at + refresh_ttl;
            let remaining = expires_at.saturating_duration_since(now);
            let threshold = refresh_ttl * refresh_remaining_pct / 100;
            if remaining < threshold && remaining > Duration::ZERO {
                candidates.push(ProactiveRefreshCandidate {
                    hostname: entry.key().clone(),
                    per_proxy_ttl: entry.load_shortest_per_proxy_ttl(),
                    generation: SuccessRefreshGeneration {
                        next_start: entry.next_start.clone(),
                        resolved_at: entry.resolved_at,
                    },
                    expires_at,
                    consecutive_failures: entry.consecutive_failures,
                });
            }
        }

        candidates.sort_by_key(|c| c.expires_at);
        candidates.truncate(self.max_concurrent_refreshes);
        candidates
    }

    /// Publish a background-refresh success only if the selected generation is
    /// still live. Used by stale-while-revalidate and proactive near-expiry
    /// refresh. IP-policy validation runs before any map mutation. Vacant keys
    /// are not resurrected. The DashMap entry guard is never held across
    /// await — callers resolve DNS before invoking this.
    ///
    /// Returns `Ok(RefreshApply::Published)` when published,
    /// `Ok(RefreshApply::Abandoned)` when the generation changed or the key
    /// was removed, `Ok(RefreshApply::IpLiteral)` after dropping a leftover
    /// IP-literal row (issue #4293; not a live success generation), and `Err`
    /// when addresses are denied by IP policy (nothing is written).
    fn apply_refresh_success(
        &self,
        hostname: &str,
        generation: &SuccessRefreshGeneration,
        addresses: Vec<IpAddr>,
        record_type: Option<CachedRecordType>,
        native_ttl: Duration,
        per_proxy_ttl: Option<u64>,
    ) -> Result<RefreshApply, anyhow::Error> {
        let native_ttl = native_ttl.min(Self::MAX_TTL);
        let addresses = self.screen_backend_addresses_policy(addresses, hostname)?;
        let cache_key = dns_hostname_key(hostname);
        if parse_ip_literal(cache_key.as_ref()).is_some() {
            self.cache.remove(cache_key.as_ref());
            return Ok(RefreshApply::IpLiteral);
        }
        let now = Instant::now();

        match self.cache.entry(cache_key.into_owned()) {
            Entry::Occupied(mut occupied) => {
                if !Self::matches_success_refresh_generation(occupied.get(), generation) {
                    return Ok(RefreshApply::Abandoned);
                }
                occupied.get().note_per_proxy_ttl(per_proxy_ttl);
                let shortest = occupied.get().shortest_per_proxy_ttl_secs.clone();
                let longest = occupied.get().longest_per_proxy_ttl_secs.clone();
                let default_obs = occupied.get().default_consumer_observed.clone();
                let shortest_ttl = {
                    let secs = shortest.load(Ordering::Relaxed);
                    if secs == NO_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let longest_ttl = {
                    let secs = longest.load(Ordering::Relaxed);
                    if secs == NO_LONGEST_PER_PROXY_TTL {
                        None
                    } else {
                        Some(secs)
                    }
                };
                let default_consumer_observed = default_obs.load(Ordering::Relaxed);
                let applied_ttl =
                    self.observed_refresh_ttl(native_ttl, shortest_ttl, default_consumer_observed);
                occupied.insert(DnsCacheEntry {
                    addresses,
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: now,
                    native_ttl,
                    stale_deadline: self.shared_stale_deadline(
                        now,
                        native_ttl,
                        longest_ttl,
                        default_consumer_observed,
                    ),
                    applied_ttl,
                    record_type_used: record_type,
                    is_error: false,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: shortest,
                    longest_per_proxy_ttl_secs: longest,
                    default_consumer_observed: default_obs,
                    consecutive_failures: 0,
                    first_failed_at: None,
                });
                Ok(RefreshApply::Published)
            }
            Entry::Vacant(_) => Ok(RefreshApply::Abandoned),
        }
    }

    /// Resolve for SWR, proactive background refresh or the failed-retry
    /// task. The test hook is compiled out of release builds and is consulted
    /// only here — never on the foreground `timed_resolve` path — so a
    /// hanging background future cannot stall a synchronous lookup.
    async fn refresh_resolve(
        &self,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error> {
        #[cfg(test)]
        if let Some(hook) = self.refresh_resolve_hook.as_ref() {
            return hook(hostname.to_string()).await;
        }
        self.timed_resolve(hostname).await
    }

    /// Apply the shared wall-clock bound to one background lookup.
    ///
    /// Timeout is a failed refresh: callers must not rewrite the last known
    /// good success row and must emit the single operational warning from the
    /// returned error. Dropping the caller’s [`RefreshInFlight`] after this
    /// returns releases the shared permit even when the resolver hung.
    async fn refresh_resolve_with_timeout(
        &self,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error> {
        match tokio::time::timeout(
            Self::BACKGROUND_REFRESH_RESOLVE_TIMEOUT,
            self.refresh_resolve(hostname),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => anyhow::bail!(
                "DNS background refresh timed out for {} after {:?}",
                hostname,
                Self::BACKGROUND_REFRESH_RESOLVE_TIMEOUT
            ),
        }
    }

    async fn refresh_proactive_candidate(&self, candidate: ProactiveRefreshCandidate) {
        let hostname = &candidate.hostname;
        let per_proxy_ttl = candidate.per_proxy_ttl;
        let noisy = candidate.consecutive_failures < Self::FAILED_RETRY_WARN_FAILURES;
        match self.refresh_resolve_with_timeout(hostname).await {
            Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                match self.apply_refresh_success(
                    hostname,
                    &candidate.generation,
                    addrs,
                    record_type,
                    native_ttl,
                    per_proxy_ttl,
                ) {
                    Ok(RefreshApply::Published) => {
                        debug!(
                            "DNS background refresh: {} refreshed (native_ttl={:?}, per_proxy_ttl={:?})",
                            hostname, native_ttl, per_proxy_ttl
                        );
                    }
                    Ok(RefreshApply::Abandoned) => {
                        debug!(
                            "DNS background refresh: abandoning stale success for '{}' (cache generation changed during resolve)",
                            hostname
                        );
                    }
                    Ok(RefreshApply::IpLiteral) => {
                        debug!(
                            "DNS background refresh: dropping leftover IP-literal row for '{}'",
                            hostname
                        );
                    }
                    Err(e) => {
                        warn!(
                            "DNS background refresh: '{}' resolved but denied by IP policy: {}",
                            hostname, e
                        );
                    }
                }
            }
            Ok(_) => {
                if noisy {
                    warn!("DNS background refresh: {} returned no addresses", hostname);
                } else {
                    debug!("DNS background refresh: {} returned no addresses", hostname);
                }
                self.note_preserved_success_refresh_failure(hostname, &candidate.generation);
            }
            Err(e) => {
                if noisy {
                    warn!("DNS background refresh failed for {}: {}", hostname, e);
                } else {
                    debug!("DNS background refresh failed for {}: {}", hostname, e);
                }
                self.note_preserved_success_refresh_failure(hostname, &candidate.generation);
            }
        }
    }

    /// Count a failed proactive refresh against a still-live success row
    /// without converting it to an error, so later cycles can demote `warn`
    /// to `debug` after [`Self::FAILED_RETRY_WARN_FAILURES`]. DashMap guard
    /// is dropped before return; never called across `.await`.
    fn note_preserved_success_refresh_failure(
        &self,
        hostname: &str,
        generation: &SuccessRefreshGeneration,
    ) {
        let cache_key = dns_hostname_key(hostname);
        if let Some(mut entry) = self.cache.get_mut(cache_key.as_ref())
            && Self::matches_success_refresh_generation(&entry, generation)
        {
            entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        }
    }

    /// Run one proactive refresh cycle: select soonest-expiry success entries
    /// up to `max_concurrent_refreshes`, resolve them concurrently through the
    /// shared `refresh_semaphore` + `refreshing` dedup map, and publish only
    /// when the selected generation is still current. A candidate whose
    /// generation died after selection is skipped before the upstream query.
    /// Skipped starts (already in progress, concurrency limited, or dead
    /// generation) emit one `debug!` per cycle when non-zero.
    async fn run_proactive_refresh_cycle(&self) {
        let now = Instant::now();
        let to_refresh = self.select_proactive_refresh_candidates(now);
        if to_refresh.is_empty() {
            return;
        }

        let skipped = Arc::new(AtomicUsize::new(0));
        let concurrency = self.max_concurrent_refreshes;
        stream::iter(to_refresh)
            .for_each_concurrent(concurrency, |candidate| {
                let cache = self.clone();
                let skipped = Arc::clone(&skipped);
                async move {
                    match cache.try_begin_refresh(candidate.hostname.clone()) {
                        RefreshStart::Started(guard) => {
                            let generation_live = cache
                                .cache
                                .get(guard.hostname.as_str())
                                .is_some_and(|entry| {
                                    Self::matches_success_refresh_generation(
                                        entry.value(),
                                        &candidate.generation,
                                    )
                                });
                            if generation_live {
                                cache.refresh_proactive_candidate(candidate).await;
                            } else {
                                skipped.fetch_add(1, Ordering::Relaxed);
                            }
                            drop(guard);
                        }
                        RefreshStart::AlreadyInProgress | RefreshStart::ConcurrencyLimited => {
                            skipped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .await;

        let skipped = skipped.load(Ordering::Relaxed);
        if skipped > 0 {
            debug!("DNS proactive refresh: skipped {skipped} selected hostname(s)");
        }
    }

    async fn proactive_refresh_loop(self) {
        let mut interval = tokio::time::interval(Self::BACKGROUND_MAINTENANCE_INTERVAL);
        // Issue #4270: a slow proactive cycle must not Burst catch-up ticks
        // that re-issue the full near-expiry sweep back-to-back.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.run_proactive_refresh_cycle().await;
        }
    }

    async fn cache_eviction_loop(self) {
        let mut interval = tokio::time::interval(Self::BACKGROUND_MAINTENANCE_INTERVAL);
        // Independent of refresh resolution so a dead resolver cannot starve
        // `max_cache_size` / age enforcement (issue #4270).
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.evict_expired();
        }
    }

    /// Start a background task that proactively refreshes cache entries before
    /// they expire. Entries are refreshed when the configured percentage of their
    /// TTL has elapsed (default 90%), keeping DNS resolution off the hot request path.
    ///
    /// When `shutdown_rx` is provided, the task will exit cleanly when the
    /// shutdown signal is received. Without it, the task runs until aborted.
    ///
    /// Proactive refresh and `evict_expired` run as sibling loops on the same
    /// 5s `Delay` cadence so resolver latency cannot starve capacity
    /// enforcement. The proactive/eviction task is cancelled by the shutdown
    /// watch; RAII releases that task's semaphore permits and `refreshing`
    /// markers. Detached stale-while-revalidate `tokio::spawn` tasks are not
    /// joined here; they release their own permits on lookup completion,
    /// timeout, or runtime teardown.
    /// SWR and proactive success publication share one generation token so a
    /// stale in-flight result cannot overwrite a newer winner or resurrect an
    /// evicted hostname.
    ///
    /// Returns the task handle so callers can await graceful completion.
    pub fn start_background_refresh_with_shutdown(
        &self,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let cache = self.clone();
        tokio::spawn(async move {
            let refresh = cache.clone().proactive_refresh_loop();
            let eviction = cache.cache_eviction_loop();
            if let Some(rx) = shutdown_rx {
                tokio::select! {
                    _ = refresh => {}
                    _ = eviction => {}
                    _ = wait_for_shutdown(rx) => {
                        info!("DNS background refresh shutting down");
                    }
                }
            } else {
                tokio::select! {
                    _ = refresh => {}
                    _ = eviction => {}
                }
            }
        })
    }

    /// Start a background task that periodically retries resolution for failed
    /// DNS entries. Failed lookups are cached with a short error TTL that grows
    /// exponentially on consecutive failures (capped at `stale_ttl`), and error
    /// entries older than `stale_ttl` are eventually evicted.
    ///
    /// Each cycle selects at most `max_concurrent_refreshes` eligible entries
    /// and resolves them concurrently (same bound). Outcomes are published
    /// only when the selected error generation is still current, so a stale
    /// background resolve cannot overwrite a newer foreground success/failure.
    /// Missed interval ticks use `Delay` so a slow cycle cannot burst catch-up
    /// ticks. Retry attempt / failure logs start at `warn` and demote to
    /// `debug` after the first few consecutive failures; successful recovery
    /// always logs at `warn`.
    ///
    /// Returns `None` if the retry interval is zero (disabled).
    pub fn start_failed_retry_task(
        &self,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if self.failed_retry_interval == Duration::ZERO {
            debug!("DNS failed retry task disabled (interval=0)");
            return None;
        }

        let cache = self.clone();
        let retry_interval = self.failed_retry_interval;

        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(retry_interval);
            // A slow cycle (many dead hostnames × resolver timeout) must not
            // fire back-to-back catch-up ticks afterward.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                if let Some(ref rx) = shutdown_rx {
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = wait_for_shutdown(rx.clone()) => {
                            info!("DNS failed retry task shutting down");
                            return;
                        }
                    }
                } else {
                    interval.tick().await;
                }

                cache.run_failed_retry_cycle().await;
            }
        }))
    }

    /// Warmup: resolve all hostnames from the config at startup.
    ///
    /// Hostnames are deduplicated before resolution — if multiple proxies or
    /// plugins share the same hostname, only one DNS lookup is performed.
    /// Per-proxy TTL policies are NOT first-writer-wins: warmup still issues a
    /// single shared lookup (and keeps the first static override seen), but
    /// each later `resolve` evaluates freshness with that caller's own
    /// `dns_cache_ttl_seconds`. Unique hostnames are resolved concurrently up
    /// to the configured limit.
    ///
    /// IP literals are skipped: they need no DNS, must not occupy success-cache
    /// rows, and remain policy-screened at request-time `resolve`.
    pub async fn warmup(&self, hostnames: Vec<(String, Option<String>, Option<u64>)>) {
        let total_hostnames = hostnames.len();

        // Empty backend hosts are placeholders on upstream-backed proxies, not
        // DNS names. Passing one to hickory applies the system search domain
        // and can consume the full resolver retry window before listeners bind.
        // Ignore them at this shared boundary so every startup/reload caller is
        // protected even if its hostname collector includes placeholders.
        //
        // Deduplicate by hostname for query coalescing. Keep the first override
        // plus the full observed TTL-policy range. The one lookup uses the
        // shortest explicit TTL for proactive refresh, then records the longest
        // explicit and default/global/native policies on the shared row so
        // age eviction cannot discard data still fresh for a warmup consumer
        // that has not sent its first request yet.
        struct WarmupPolicy {
            override_ip: Option<String>,
            shortest_explicit_ttl: Option<u64>,
            longest_explicit_ttl: Option<u64>,
            default_consumer_observed: bool,
        }

        let mut seen: HashMap<String, WarmupPolicy> = HashMap::new();
        for (host, override_ip, ttl) in hostnames {
            if host.trim().is_empty() {
                continue;
            }
            // IP literals need no DNS warmup. Skipping here must not become a
            // policy bypass: `resolve_candidates` still screens literals at use,
            // and service-discovery admission already applied egress policy.
            if parse_ip_literal(&host).is_some() {
                continue;
            }
            let key = dns_hostname_key(&host).into_owned();
            match seen.entry(key) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(WarmupPolicy {
                        override_ip,
                        shortest_explicit_ttl: ttl,
                        longest_explicit_ttl: ttl,
                        default_consumer_observed: ttl.is_none(),
                    });
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let policy = slot.get_mut();
                    if policy.override_ip.is_none() && override_ip.is_some() {
                        policy.override_ip = override_ip;
                    }
                    if let Some(ttl) = ttl {
                        policy.shortest_explicit_ttl = Some(
                            policy
                                .shortest_explicit_ttl
                                .map_or(ttl, |existing| existing.min(ttl)),
                        );
                        policy.longest_explicit_ttl = Some(
                            policy
                                .longest_explicit_ttl
                                .map_or(ttl, |existing| existing.max(ttl)),
                        );
                    } else {
                        policy.default_consumer_observed = true;
                    }
                }
            }
        }
        let unique: Vec<_> = seen.into_iter().collect();

        if unique.is_empty() {
            debug!("DNS warmup: no hostnames to resolve");
            return;
        }

        info!(
            "DNS warmup: resolving {} unique hostnames ({} before dedup, concurrency={})",
            unique.len(),
            total_hostnames,
            self.warmup_concurrency,
        );

        stream::iter(unique)
            .for_each_concurrent(self.warmup_concurrency, |(host, policy)| {
                let cache = self.clone();
                async move {
                    match cache
                        .resolve(
                            &host,
                            policy.override_ip.as_deref(),
                            policy.shortest_explicit_ttl,
                        )
                        .await
                    {
                        Ok(addr) => {
                            let cache_key = dns_hostname_key(&host);
                            if let Some(entry) = cache.cache.get(cache_key.as_ref()) {
                                if let Some(longest) = policy.longest_explicit_ttl {
                                    entry.note_per_proxy_ttl(Some(longest));
                                }
                                if policy.default_consumer_observed {
                                    entry.note_per_proxy_ttl(None);
                                }
                            }
                            debug!("DNS warmup: {} -> {}", host, addr);
                        }
                        Err(e) => warn!("DNS warmup failed for {}: {}", host, e),
                    }
                }
            })
            .await;

        info!("DNS warmup complete");
    }
}

/// Whether a [`DnsCache::resolve`] / [`DnsCache::resolve_all`] error is a
/// backend-egress-policy denial (the resolved or literal address was blocked by
/// [`check_backend_ip_policy`]) rather than a transport DNS failure.
///
/// reqwest paths classify this via `classify_reqwest_error` (the resolver wraps
/// the message into an io error). Direct stream-proxy callers — TCP/UDP setup,
/// denied `dns_override` construction — instead call this so they keep circuit-
/// breaker / adaptive-concurrency accounting NEUTRAL: no backend was dialed, so
/// a policy denial must not be recorded as a connect-class failure that could
/// trip the breaker for an otherwise-reachable target. Matches the stable
/// `denied by backend egress policy` marker emitted by `check_backend_ip_policy`.
pub fn is_egress_policy_denial(err: &anyhow::Error) -> bool {
    err.to_string().contains("denied by backend egress policy")
}

/// Build a hickory-resolver `Resolver` from a `DnsConfig`.
fn build_resolver(config: &DnsConfig) -> Resolver<TokioRuntimeProvider> {
    build_resolver_with_cache_mode(config, true)
}

/// Build the resolver used immediately before security-sensitive dials.
/// Hickory's own lookup cache is disabled so this resolver cannot hide a DNS
/// rebind behind a still-valid prior answer. A and AAAA are always queried in
/// parallel, with the resolver's preferred connection ordering preserved by
/// the returned iterator.
fn build_dial_resolver(config: &DnsConfig) -> Resolver<TokioRuntimeProvider> {
    build_resolver_with_cache_mode(config, false)
}

fn build_resolver_with_cache_mode(
    config: &DnsConfig,
    cache_enabled: bool,
) -> Resolver<TokioRuntimeProvider> {
    // Start with system configuration as the base
    let (mut resolver_config, mut resolver_opts) =
        match hickory_resolver::system_conf::read_system_conf() {
            Ok((rc, ro)) => {
                debug!(
                    "DNS: loaded system resolv.conf ({} nameservers)",
                    rc.name_servers().len()
                );
                (rc, ro)
            }
            Err(e) => {
                warn!(
                    "DNS: failed to read system resolv.conf: {}. Using default (Google DNS)",
                    e
                );
                (ResolverConfig::default(), ResolverOpts::default())
            }
        };

    // Override nameservers if FERRUM_DNS_RESOLVER_ADDRESS is set
    if let Some(ref addr_str) = config.resolver_addresses {
        let nameservers = parse_nameserver_addresses(addr_str);
        if !nameservers.is_empty() {
            // Preserve system search/domain settings but replace nameservers
            resolver_config = ResolverConfig::from_parts(
                resolver_config.domain().cloned(),
                resolver_config.search().to_vec(),
                nameservers,
            );
            info!("DNS: using custom nameservers from FERRUM_DNS_RESOLVER_ADDRESS");
        } else {
            warn!(
                "DNS: FERRUM_DNS_RESOLVER_ADDRESS set but no valid addresses parsed, using system default"
            );
        }
    }

    // When a global TTL override is set, clamp hickory's internal cache to match
    // so the resolver doesn't serve records beyond the override lifetime. Bound
    // it by MAX_TTL first: hickory clamps each record's TTL up to
    // positive_max_ttl and computes `valid_until = Instant::now() + ttl`, so an
    // unbounded FERRUM_DNS_TTL_OVERRIDE_SECONDS would overflow that addition
    // inside hickory — before DnsCache::cache_success_entry's own clamp can run.
    if let Some(override_secs) = config.ttl_override_seconds {
        let d = Duration::from_secs(override_secs).min(DnsCache::MAX_TTL);
        resolver_opts.positive_min_ttl = Some(d);
        resolver_opts.positive_max_ttl = Some(d);
    }

    // Apply error/negative TTL (same MAX_TTL bound: the negative-response path
    // also does `Instant::now() + ttl` inside hickory, so an unbounded
    // FERRUM_DNS_ERROR_TTL would overflow on the first failed lookup).
    let neg_ttl = Duration::from_secs(config.error_ttl_seconds).min(DnsCache::MAX_TTL);
    resolver_opts.negative_min_ttl = Some(neg_ttl);
    resolver_opts.negative_max_ttl = Some(neg_ttl);

    // Always check hosts file
    resolver_opts.use_hosts_file = ResolveHosts::Always;

    // Retry over TCP when UDP responses are truncated or fail
    resolver_opts.try_tcp_on_error = config.try_tcp_on_error;

    // Race queries against multiple nameservers in parallel to reduce P99 latency
    resolver_opts.num_concurrent_reqs = config.num_concurrent_reqs;

    // Allow more in-flight queries per connection during bulk warmup
    resolver_opts.max_active_requests = config.max_active_requests;

    if !cache_enabled {
        resolver_opts.cache_size = 0;
        resolver_opts.ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
        // The dial resolver never consumes its cache, so negative TTL bounds
        // must not turn a resolver error into a cached reconnect decision.
        resolver_opts.negative_min_ttl = None;
        resolver_opts.negative_max_ttl = None;
    }

    // Build the resolver
    let mut builder =
        Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default());
    *builder.options_mut() = resolver_opts;
    let mut resolver = builder.build().expect("failed to build DNS resolver");

    // Load custom hosts file if specified. A read error (for example a
    // directory or a non-UTF-8 line) leaves a partial table, so it is
    // reported and the resolver keeps its default hosts instead of a
    // silently truncated replacement (issue #7204).
    if let Some(ref hosts_path) = config.hosts_file_path {
        match File::open(hosts_path) {
            Ok(file) => {
                let mut hosts = hickory_resolver::Hosts::default();
                match hosts.read_hosts_conf(BufReader::new(file)) {
                    Ok(()) => {
                        resolver.set_hosts(Arc::new(hosts));
                        info!("DNS: loaded custom hosts file from {}", hosts_path);
                    }
                    Err(e) => {
                        warn!(
                            "DNS: failed to read custom hosts file '{}', not applied: {}",
                            hosts_path, e
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    "DNS: failed to open custom hosts file '{}': {}",
                    hosts_path, e
                );
            }
        }
    }

    resolver
}

/// Parse comma-separated nameserver addresses into NameServerConfig entries.
/// Each address can be ip[:port], with port defaulting to 53.
/// Supports both IPv4 and IPv6 (IPv6 brackets optional: [::1]:53 or ::1).
fn parse_nameserver_addresses(addr_str: &str) -> Vec<NameServerConfig> {
    let mut configs = Vec::new();

    for entry in addr_str.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }

        let socket_addr = parse_addr_with_port(entry, 53);
        match socket_addr {
            Some(addr) => {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                configs.push(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
                debug!("DNS: added nameserver {}", addr);
            }
            None => {
                warn!("DNS: failed to parse nameserver address '{}'", entry);
            }
        }
    }

    configs
}

/// Parse an address string with optional port into a SocketAddr.
/// Supports: "1.2.3.4", "1.2.3.4:5353", "[::1]", "[::1]:5353", "::1"
fn parse_addr_with_port(s: &str, default_port: u16) -> Option<SocketAddr> {
    // Try direct SocketAddr parse first (handles "1.2.3.4:53" and "[::1]:53")
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }

    // Try as bare IP address (add default port)
    // Handle bracketed IPv6 without port: "[::1]"
    let ip_str = s.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, default_port));
    }

    None
}

/// Parse a DNS order string into a Vec of DnsRecordOrder.
/// Input is comma-separated, case-insensitive. Default: "CACHE,SRV,A,CNAME".
fn parse_dns_order(order_str: Option<&str>) -> Vec<DnsRecordOrder> {
    let s = order_str.unwrap_or("CACHE,SRV,A,CNAME");

    let mut result = Vec::new();
    for part in s.split(',') {
        match part.trim().to_uppercase().as_str() {
            "CACHE" => result.push(DnsRecordOrder::Cache),
            "A" => result.push(DnsRecordOrder::A),
            "AAAA" => result.push(DnsRecordOrder::Aaaa),
            "SRV" => result.push(DnsRecordOrder::Srv),
            "CNAME" => result.push(DnsRecordOrder::Cname),
            other => {
                warn!("DNS: ignoring unknown record type '{}' in dns_order", other);
            }
        }
    }

    if result.is_empty() {
        warn!("DNS: dns_order produced empty list, using default");
        result = vec![
            DnsRecordOrder::Cache,
            DnsRecordOrder::Srv,
            DnsRecordOrder::A,
            DnsRecordOrder::Cname,
        ];
    }

    result
}

/// A custom DNS resolver for `reqwest` that delegates all hostname lookups
/// to our [`DnsCache`]. This ensures that **all** `reqwest::Client` instances
/// — for both single-backend and load-balanced proxies — transparently use
/// the DNS cache with warmup, background refresh, and stale-while-revalidate.
///
/// By setting this as the `dns_resolver` on every `reqwest::Client`, DNS
/// resolution is kept completely off the hot request path: the cache is
/// pre-warmed at startup and continuously refreshed in the background.
///
/// When a proxy carries a static [`dns_override`](crate::config::types::Proxy::dns_override),
/// the connection pool installs that override on this resolver (not via
/// reqwest's hostname-specific `ClientBuilder::resolve()` map). The override
/// therefore applies to **every** hostname the shared client dials — including
/// load-balanced upstream targets whose host differs from `proxy.backend_host`
/// — matching direct connectors that call
/// [`DnsCache::resolve_candidates`] with the same per-proxy override.
pub struct DnsCacheResolver {
    cache: DnsCache,
    /// Per-proxy static IP override. `None` for shared plugin/health clients
    /// and proxies without `dns_override`. When `Some`, every hostname this
    /// resolver answers returns that address (policy-screened), independent of
    /// the requested name. The immutable snapshot is reference-counted so a
    /// resolver call does not allocate a fresh override string.
    dns_override: Option<Arc<str>>,
    /// Name this resolver answers with, regardless of the name it is asked for.
    ///
    /// Used where the URL authority is deliberately NOT the dial target — the
    /// backend TLS server-name override on the active HTTP health probe, whose
    /// URL host is the overridden server name so reqwest presents it as SNI.
    /// Pinning the *name* rather than a single address keeps the probe's full
    /// candidate set, rotation, and egress screening identical to an ordinary
    /// probe, while guaranteeing the server name itself is never resolved.
    hostname_pin: Option<Arc<str>>,
}

impl DnsCacheResolver {
    pub fn new(cache: DnsCache) -> Self {
        Self {
            cache,
            dns_override: None,
            hostname_pin: None,
        }
    }

    /// Build a resolver that pins every dial to a per-proxy `dns_override`.
    ///
    /// Used by the reqwest connection pool so load-balanced target hostnames
    /// that differ from the route template's `backend_host` still dial the
    /// override IP. Pool keys already partition by `dns_override`, so a shared
    /// upstream-keyed client cannot freeze one proxy's override onto another.
    pub fn with_dns_override(cache: DnsCache, dns_override: Option<String>) -> Self {
        Self {
            cache,
            dns_override: dns_override.map(Arc::from),
            hostname_pin: None,
        }
    }

    /// Build a resolver that answers EVERY requested name by resolving
    /// `hostname_pin` instead. See the field docs for why this exists.
    pub fn with_hostname_pin(cache: DnsCache, hostname_pin: &str) -> Self {
        Self {
            cache,
            dns_override: None,
            hostname_pin: Some(Arc::from(hostname_pin)),
        }
    }
}

impl reqwest::dns::Resolve for DnsCacheResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let cache = self.cache.clone();
        let hostname = match self.hostname_pin.as_deref() {
            Some(pin) => pin.to_string(),
            None => name.as_str().to_string(),
        };
        let dns_override = self.dns_override.clone();

        Box::pin(async move {
            let addresses = cache
                .resolve_candidates(&hostname, dns_override.as_deref(), None)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(e.to_string()))
                })?;

            // reqwest expects an iterator of SocketAddr. The port is ignored
            // (reqwest uses the port from the URL), but SocketAddr requires one.
            let addrs: reqwest::dns::Addrs = Box::new(ReqwestAddrs {
                addresses,
                offset: 0,
            });
            Ok(addrs)
        })
    }
}

struct ReqwestAddrs {
    addresses: ResolvedAddresses,
    offset: usize,
}

impl Iterator for ReqwestAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let ip = self.addresses.get(self.offset)?;
        self.offset += 1;
        Some(SocketAddr::new(ip, 0))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.addresses.len().saturating_sub(self.offset);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ReqwestAddrs {}

#[cfg(test)]
mod tests {
    //! Inline tests for private internals of the DNS cache. Public-API tests
    //! live in `tests/unit/gateway_core/dns_tests.rs`.
    //!
    //! These tests verify per-consumer TTL isolation on shared hostnames and that
    //! the shortest observed per-proxy `dns_cache_ttl_seconds` is preserved across
    //! proactive background refresh and failed-retry re-resolution. Issue
    //! #4270 concurrency, timeout, and generation-fence coverage lives in
    //! [`background_refresh_hardening`] so the resolve hook is not a
    //! production-visible API. The hook is `#[cfg(test)]` and therefore
    //! invisible to the external `tests/` crate (which compiles the library
    //! without `cfg(test)`); a `test-hooks` cargo feature or a `pub` seam
    //! would be worse, so that module is the intentional exception to the
    //! usual "no new inline source tests" policy.
    use super::*;
    use crate::config::{BackendAllowIps, BackendEgressPolicy};
    use std::collections::HashMap;

    fn config_with_global_override(global_ttl_secs: Option<u64>) -> DnsConfig {
        DnsConfig {
            global_overrides: HashMap::new(),
            ttl_override_seconds: global_ttl_secs,
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ..DnsConfig::default()
        }
    }

    fn success_entry(
        addresses: Arc<[IpAddr]>,
        resolved_at: Instant,
        native_ttl: Duration,
        per_proxy_ttl: Option<u64>,
        stale_deadline: Instant,
    ) -> DnsCacheEntry {
        let applied_ttl = per_proxy_ttl
            .map(Duration::from_secs)
            .unwrap_or(native_ttl)
            .max(Duration::from_secs(1));
        DnsCacheEntry {
            addresses,
            next_start: Arc::new(AtomicU64::new(0)),
            resolved_at,
            native_ttl,
            stale_deadline,
            applied_ttl,
            record_type_used: Some(CachedRecordType::A),
            is_error: false,
            refresh_error_deadline: None,
            shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                per_proxy_ttl.unwrap_or(NO_PER_PROXY_TTL),
            )),
            longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                per_proxy_ttl.unwrap_or(NO_LONGEST_PER_PROXY_TTL),
            )),
            // Test helper `None` means "no consumers noted yet", not "default
            // consumer observed" — callers that need the default flag note it.
            default_consumer_observed: Arc::new(AtomicBool::new(false)),
            consecutive_failures: 0,
            first_failed_at: None,
        }
    }

    fn seed_answer(cache: &DnsCache, hostname: &str, addresses: Vec<IpAddr>, stale: bool) {
        let now = Instant::now();
        let native_ttl = Duration::from_secs(60);
        let resolved_at = if stale {
            now - native_ttl - Duration::from_secs(1)
        } else {
            now
        };
        cache.cache.insert(
            hostname.to_string(),
            success_entry(
                addresses.into(),
                resolved_at,
                native_ttl,
                None,
                now + Duration::from_secs(3600),
            ),
        );
    }

    #[tokio::test]
    async fn fresh_and_stale_cache_hits_rotate_without_reordering_failover() {
        let cache = DnsCache::new(DnsConfig::default());
        let a = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
        seed_answer(&cache, "rotate.test", vec![a, b], false);

        let first: Vec<_> = cache
            .resolve_candidates("rotate.test", None, None)
            .await
            .unwrap()
            .iter()
            .collect();
        let second: Vec<_> = cache
            .resolve_candidates("rotate.test", None, None)
            .await
            .unwrap()
            .iter()
            .collect();
        assert_eq!(first, vec![a, b]);
        assert_eq!(second, vec![b, a]);

        seed_answer(&cache, "stale.test", vec![a, b], true);
        let stale_first: Vec<_> = cache
            .resolve_candidates("stale.test", None, None)
            .await
            .unwrap()
            .iter()
            .collect();
        let stale_second: Vec<_> = cache
            .resolve_candidates("stale.test", None, None)
            .await
            .unwrap()
            .iter()
            .collect();
        assert_eq!(stale_first, vec![a, b]);
        assert_eq!(stale_second, vec![b, a]);

        cache
            .cache_success_entry(
                "refreshed.test",
                vec![a, b],
                Some(CachedRecordType::A),
                Duration::from_secs(60),
                None,
                false,
            )
            .unwrap();
        let after_refresh: Vec<_> = cache
            .resolve_candidates("refreshed.test", None, None)
            .await
            .unwrap()
            .iter()
            .collect();
        assert_eq!(after_refresh, vec![a, b]);
    }

    #[test]
    fn policy_screens_each_candidate_and_fails_when_none_remain() {
        let cache = DnsCache::new(DnsConfig {
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });
        let denied = IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254));
        let approved = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));

        let screened = cache
            .screen_backend_addresses_policy(vec![denied, approved], "mixed.test")
            .unwrap();
        assert_eq!(screened.as_ref(), &[approved]);
        assert!(
            cache
                .screen_backend_addresses_policy(vec![denied], "denied.test")
                .is_err()
        );
    }

    #[tokio::test]
    async fn tcp_candidates_fail_over_for_a_and_aaaa_answers() {
        async fn exercise(listener: tokio::net::TcpListener, failed_ip: IpAddr) {
            let live = listener.local_addr().unwrap();
            let addresses = ResolvedAddresses {
                addresses: Arc::from([failed_ip, live.ip()]),
                start: 0,
            };
            let accepted = tokio::spawn(async move { listener.accept().await });
            let (stream, selected) = connect_candidates(
                &addresses,
                live.port(),
                Duration::from_secs(2),
                tokio::net::TcpStream::connect,
            )
            .await
            .unwrap();
            assert_eq!(selected.ip(), live.ip());
            drop(stream);
            accepted.await.unwrap().unwrap();
        }

        let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        exercise(v4, "127.0.0.2".parse().unwrap()).await;

        if let Ok(v6) = tokio::net::TcpListener::bind("[::1]:0").await {
            exercise(v6, "::2".parse().unwrap()).await;
        }
    }

    #[tokio::test]
    async fn failover_order_covers_a_and_aaaa_answer_sets() {
        for (first, second) in [
            (
                "192.0.2.40".parse::<IpAddr>().unwrap(),
                "192.0.2.41".parse::<IpAddr>().unwrap(),
            ),
            (
                "2001:db8::40".parse::<IpAddr>().unwrap(),
                "2001:db8::41".parse::<IpAddr>().unwrap(),
            ),
        ] {
            let addresses = ResolvedAddresses {
                addresses: Arc::from([first, second]),
                start: 0,
            };
            let ((), selected) =
                connect_candidates(&addresses, 443, Duration::from_secs(1), |addr| async move {
                    if addr.ip() == first {
                        Err(std::io::Error::other("first candidate unavailable"))
                    } else {
                        Ok(())
                    }
                })
                .await
                .unwrap();
            assert_eq!(selected.ip(), second);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn candidate_attempts_share_one_overall_budget() {
        let addresses = ResolvedAddresses {
            addresses: Arc::from([
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
            ]),
            start: 0,
        };
        let started = tokio::time::Instant::now();
        let result = connect_candidates(&addresses, 443, Duration::from_millis(40), |_| async {
            std::future::pending::<()>().await;
            Ok::<(), std::io::Error>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(CandidateConnectError::TimedOut { .. })
        ));
        assert_eq!(started.elapsed(), Duration::from_millis(40));
    }

    #[tokio::test]
    async fn candidate_failover_keeps_hostname_connector_identity() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct ConnectorIdentity {
            authority: &'static str,
            tls_server_name: &'static str,
        }

        let identity = ConnectorIdentity {
            authority: "backend.internal:443",
            tls_server_name: "backend.internal",
        };
        let first = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 30));
        let second = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 31));
        let addresses = ResolvedAddresses {
            addresses: Arc::from([first, second]),
            start: 0,
        };
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_attempts = seen.clone();

        let (selected_identity, selected_addr) =
            connect_candidates(&addresses, 443, Duration::from_secs(1), |addr| {
                let seen_attempts = seen_attempts.clone();
                async move {
                    seen_attempts.lock().unwrap().push((addr, identity));
                    if addr.ip() == first {
                        Err(std::io::Error::other("first candidate unavailable"))
                    } else {
                        Ok(identity)
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(selected_addr.ip(), second);
        assert_eq!(selected_identity, identity);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[
                (SocketAddr::new(first, 443), identity),
                (SocketAddr::new(second, 443), identity),
            ]
        );
    }

    #[tokio::test]
    async fn reqwest_resolver_exposes_the_entire_rotated_answer_set() {
        use reqwest::dns::Resolve;

        let cache = DnsCache::new(DnsConfig::default());
        let a = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20));
        let b = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 21));
        seed_answer(&cache, "reqwest.test", vec![a, b], false);
        let resolver = DnsCacheResolver::new(cache);
        let first: Vec<_> = resolver
            .resolve("reqwest.test".parse().unwrap())
            .await
            .unwrap()
            .collect();
        let second: Vec<_> = resolver
            .resolve("reqwest.test".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert_eq!(first, vec![SocketAddr::new(a, 0), SocketAddr::new(b, 0)]);
        assert_eq!(second, vec![SocketAddr::new(b, 0), SocketAddr::new(a, 0)]);
    }

    #[test]
    fn dns_name_without_trailing_root_strips_root_label() {
        assert_eq!(
            dns_name_without_trailing_root("service.example.com."),
            "service.example.com"
        );
        assert_eq!(
            dns_name_without_trailing_root("service.example.com"),
            "service.example.com"
        );
    }

    #[test]
    fn cache_success_entry_rejects_denied_addresses_without_caching() {
        let cache = DnsCache::new(DnsConfig {
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });

        let result = cache.cache_success_entry(
            "metadata.internal",
            vec!["169.254.169.254".parse().unwrap()],
            Some(CachedRecordType::A),
            Duration::from_secs(60),
            Some(60),
            true,
        );

        assert!(result.is_err());
        assert!(
            cache.cache.get("metadata.internal").is_none(),
            "Denied DNS answers must not be inserted for foreground or background refresh paths"
        );
    }

    #[test]
    fn cache_success_entry_does_not_persist_ip_literals() {
        let cache = DnsCache::new(DnsConfig::default());
        let addr: IpAddr = "192.0.2.10".parse().unwrap();

        let result = cache
            .cache_success_entry(
                "192.0.2.10",
                vec![addr],
                None,
                Duration::from_secs(86400),
                Some(600),
                true,
            )
            .expect("approved literal must still return");

        assert_eq!(result.first(), Some(addr));
        assert!(
            cache.cache.get("192.0.2.10").is_none(),
            "IP literals must not occupy a success-cache row"
        );
    }

    #[test]
    fn cache_success_entry_still_denies_literals_under_policy() {
        let cache = DnsCache::new(DnsConfig {
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });

        let result = cache.cache_success_entry(
            "169.254.169.254",
            vec!["169.254.169.254".parse().unwrap()],
            None,
            Duration::from_secs(86400),
            None,
            true,
        );

        assert!(result.is_err());
        assert!(
            cache.cache.get("169.254.169.254").is_none(),
            "denied literals must not be cached"
        );
    }

    #[test]
    fn cache_success_entry_clamps_unbounded_ttl_without_panicking() {
        // F20: huge TTLs (from an unbounded FERRUM_DNS_* env var, or an absurd
        // record TTL) must not overflow the `Instant + Duration` /
        // `Duration * u32` arithmetic on the resolution path. Build a cache
        // whose env-derived TTLs are enormous AND pass an enormous per-call
        // TTL; the call must succeed (no panic) and the stored TTL must be
        // clamped to the 1-day ceiling.
        let cache = DnsCache::new(DnsConfig {
            ttl_override_seconds: Some(u64::MAX),
            stale_ttl_seconds: u64::MAX,
            min_ttl_seconds: u64::MAX,
            error_ttl_seconds: u64::MAX,
            ..DnsConfig::default()
        });

        let result = cache.cache_success_entry(
            "example.internal",
            vec!["8.8.8.8".parse().unwrap()],
            Some(CachedRecordType::A),
            Duration::from_secs(u64::MAX),
            None,
            true,
        );

        assert!(
            result.is_ok(),
            "an unbounded TTL must not panic the resolution path"
        );
        let entry = cache
            .cache
            .get("example.internal")
            .expect("entry should be cached");
        assert!(
            entry.applied_ttl <= DnsCache::MAX_TTL,
            "stored TTL must be clamped to the ceiling"
        );
    }

    #[test]
    fn failed_retry_interval_is_clamped_to_max_ttl() {
        // F20 follow-up: FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS is an
        // unbounded u64 fed into `tokio::time::interval(Duration::from_secs(..))`.
        // tokio computes the next deadline as `Instant::now() + period`, which
        // panics on overflow — the same overflow class as the DNS TTLs. An
        // enormous value must therefore be clamped to the 1-day ceiling. Assert
        // at the value level (no runtime/interval needed for determinism).
        let cache = DnsCache::new(DnsConfig {
            failed_retry_interval_seconds: u64::MAX,
            ..DnsConfig::default()
        });
        assert!(
            cache.failed_retry_interval <= DnsCache::MAX_TTL,
            "failed_retry_interval must be clamped to the ceiling to keep \
             tokio's interval deadline arithmetic overflow-safe"
        );
        assert_eq!(cache.failed_retry_interval, DnsCache::MAX_TTL);
    }

    #[test]
    fn build_resolver_clamps_unbounded_ttls_into_hickory_opts() {
        // F20: build_resolver feeds positive/negative TTL bounds into hickory's
        // ResolverOpts. hickory clamps each record's TTL up to positive_max_ttl
        // and computes `valid_until = Instant::now() + ttl`, so an unbounded
        // FERRUM_DNS_TTL_OVERRIDE_SECONDS / FERRUM_DNS_ERROR_TTL would overflow
        // that addition INSIDE hickory, before cache_success_entry's clamp ever
        // runs. The bounds handed to hickory must therefore be capped at MAX_TTL
        // (the original PR clamped only DnsCache's own fields, not these).
        let resolver = build_resolver(&DnsConfig {
            ttl_override_seconds: Some(u64::MAX),
            error_ttl_seconds: u64::MAX,
            ..DnsConfig::default()
        });
        let opts = resolver.options();
        assert_eq!(opts.positive_min_ttl, Some(DnsCache::MAX_TTL));
        assert_eq!(opts.positive_max_ttl, Some(DnsCache::MAX_TTL));
        assert_eq!(opts.negative_min_ttl, Some(DnsCache::MAX_TTL));
        assert_eq!(opts.negative_max_ttl, Some(DnsCache::MAX_TTL));
    }

    #[tokio::test]
    async fn resolve_policy_denied_answer_counts_runtime_dns_error() {
        let before_total = crate::runtime_metrics::global_ref()
            .dns_lookups_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let before_errors = crate::runtime_metrics::global_ref()
            .dns_lookup_errors
            .load(std::sync::atomic::Ordering::Relaxed);
        let cache = DnsCache::new(DnsConfig {
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });

        let result = cache.resolve("localhost", None, None).await;

        assert!(result.is_err());
        assert!(
            crate::runtime_metrics::global_ref()
                .dns_lookups_total
                .load(std::sync::atomic::Ordering::Relaxed)
                > before_total
        );
        assert!(
            crate::runtime_metrics::global_ref()
                .dns_lookup_errors
                .load(std::sync::atomic::Ordering::Relaxed)
                > before_errors
        );
    }

    #[tokio::test]
    async fn resolve_all_policy_denied_answer_counts_runtime_dns_error() {
        let before_total = crate::runtime_metrics::global_ref()
            .dns_lookups_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let before_errors = crate::runtime_metrics::global_ref()
            .dns_lookup_errors
            .load(std::sync::atomic::Ordering::Relaxed);
        let cache = DnsCache::new(DnsConfig {
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });

        let result = cache.resolve_all("localhost", None, None).await;

        assert!(result.is_err());
        assert!(
            crate::runtime_metrics::global_ref()
                .dns_lookups_total
                .load(std::sync::atomic::Ordering::Relaxed)
                > before_total
        );
        assert!(
            crate::runtime_metrics::global_ref()
                .dns_lookup_errors
                .load(std::sync::atomic::Ordering::Relaxed)
                > before_errors
        );
    }

    /// Resolving with a per-proxy TTL stores it in the cache entry so that
    /// downstream refresh paths can re-thread it through `effective_ttl`.
    #[tokio::test]
    async fn original_per_proxy_ttl_is_recorded_on_resolve() {
        let cache = DnsCache::new(config_with_global_override(None));
        let _ = cache.resolve("localhost", None, Some(600)).await.unwrap();

        let entry = cache.cache.get("localhost").expect("entry should exist");
        assert_eq!(
            entry.load_shortest_per_proxy_ttl(),
            Some(600),
            "per-proxy TTL must be stored on the cache entry"
        );
        assert_eq!(
            entry.applied_ttl,
            Duration::from_secs(600),
            "applied_ttl should reflect the per-proxy TTL, not native TTL"
        );
    }

    /// Same contract for `resolve_all`.
    #[tokio::test]
    async fn original_per_proxy_ttl_is_recorded_on_resolve_all() {
        let cache = DnsCache::new(config_with_global_override(None));
        let _ = cache
            .resolve_all("localhost", None, Some(450))
            .await
            .unwrap();

        let entry = cache.cache.get("localhost").expect("entry should exist");
        assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(450));
        assert_eq!(entry.applied_ttl, Duration::from_secs(450));
    }

    /// Regression test for the silent-drop bug: an entry originally inserted
    /// with `dns_cache_ttl_seconds: 600` must NOT be downgraded to the global
    /// TTL override (3600s) or native TTL on proactive background refresh.
    ///
    /// Simulates the proactive refresh code path by inserting a near-expiring
    /// entry tagged with `original_per_proxy_ttl: Some(600)` and re-resolving
    /// via the same `effective_ttl(native_ttl, entry.load_shortest_per_proxy_ttl())`
    /// call the background task uses.
    #[tokio::test]
    async fn proactive_refresh_preserves_per_proxy_ttl() {
        // Global TTL override of 3600s would win if the bug regresses.
        let cache = DnsCache::new(config_with_global_override(Some(3600)));

        // Seed a near-expiring entry tagged with the originating per-proxy TTL.
        // This mirrors what `resolve()` would have stored.
        cache.cache.insert(
            "127.0.0.1".to_string(),
            DnsCacheEntry {
                addresses: Arc::from([IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() + Duration::from_secs(1);
                    exp.checked_sub(Duration::from_secs(600)).unwrap_or(exp)
                },
                native_ttl: Duration::from_secs(600),
                stale_deadline: Instant::now() + Duration::from_secs(1),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: None,
            },
        );

        // Drive the same code path the background refresh task takes:
        // (1) read the originating per-proxy TTL off the entry,
        // (2) re-resolve, (3) compute effective_ttl with that TTL.
        let captured = cache
            .cache
            .get("127.0.0.1")
            .expect("seeded entry")
            .load_shortest_per_proxy_ttl();
        assert_eq!(captured, Some(600));

        let (addrs, record_type, native_ttl) = cache.timed_resolve("127.0.0.1").await.unwrap();
        assert!(!addrs.is_empty());

        let refresh_ttl = cache.effective_ttl(native_ttl, captured);
        assert_eq!(
            refresh_ttl,
            Duration::from_secs(600),
            "proactive refresh must apply the originating per-proxy TTL, \
             NOT the 3600s global override or native 24h TTL"
        );

        // Insert as the background task would.
        cache.cache.insert(
            "127.0.0.1".to_string(),
            DnsCacheEntry {
                addresses: addrs.into(),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() + refresh_ttl;
                    exp.checked_sub(refresh_ttl).unwrap_or(exp)
                },
                native_ttl: refresh_ttl,
                stale_deadline: Instant::now() + refresh_ttl + cache.stale_ttl,
                applied_ttl: refresh_ttl,
                record_type_used: record_type,
                is_error: false,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                    (captured).unwrap_or(NO_PER_PROXY_TTL),
                )),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                    (captured).unwrap_or(NO_LONGEST_PER_PROXY_TTL),
                )),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: None,
            },
        );

        let refreshed = cache.cache.get("127.0.0.1").expect("refreshed entry");
        assert_eq!(refreshed.applied_ttl, Duration::from_secs(600));
        assert_eq!(refreshed.load_shortest_per_proxy_ttl(), Some(600));
    }

    /// End-to-end: spinning up the actual background task on a near-expiring
    /// per-proxy-tagged entry must produce a refreshed entry whose TTL still
    /// reflects the per-proxy preference.
    ///
    /// The background task scans every 5s. The first `interval.tick()` fires
    /// immediately, so we seed an entry with `remaining < threshold` but
    /// `remaining > 0` so it's eligible on the first scan, and use `localhost`
    /// so refresh is a real hostname lookup (IP literals are not cached).
    #[tokio::test]
    async fn background_refresh_task_preserves_per_proxy_ttl() {
        // Global TTL override = 3600s — would win if the bug regresses.
        let mut cfg = config_with_global_override(Some(3600));
        // 99% threshold = entries with up to 1% TTL remaining are refreshed
        // (1% of 600s = 6s window).
        cfg.refresh_threshold_percent = 99;
        let cache = DnsCache::new(cfg);

        // Seed an entry within the refresh window: applied_ttl=600s, threshold=6s,
        // remaining≈4s. Stale-deadline 60s in the future so evict_expired does
        // NOT remove it before the refresh scan picks it up.
        cache.cache.insert(
            "localhost".to_string(),
            DnsCacheEntry {
                addresses: Arc::from([IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() + Duration::from_secs(4);
                    exp.checked_sub(Duration::from_secs(600)).unwrap_or(exp)
                },
                native_ttl: Duration::from_secs(600),
                stale_deadline: Instant::now() + Duration::from_secs(60),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: None,
            },
        );

        // Spawn the refresh task. The first `interval.tick()` fires at t≈0,
        // so the refresh should happen almost immediately.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = cache.start_background_refresh_with_shutdown(Some(shutdown_rx));

        // Poll for evidence of a refresh — applied_ttl jumps from 600s back to
        // 600s but expires_at jumps from now+4s to now+600s. Detect by checking
        // `expires_at - now > 100s` (much greater than the seeded 4s).
        let deadline = Instant::now() + Duration::from_secs(7);
        let mut observed_applied = Duration::ZERO;
        let mut observed_per_proxy = None;
        let mut observed_remaining = Duration::ZERO;
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some(entry) = cache.cache.get("localhost") {
                let remaining = (entry.resolved_at + entry.applied_ttl)
                    .saturating_duration_since(Instant::now());
                // Refresh has happened when remaining is significantly larger
                // than the seeded 4s (i.e., the entry was re-inserted).
                if remaining > Duration::from_secs(60) {
                    observed_applied = entry.applied_ttl;
                    observed_per_proxy = entry.load_shortest_per_proxy_ttl();
                    observed_remaining = remaining;
                    break;
                }
            }
        }

        // Shut down cleanly before asserting.
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        assert!(
            observed_remaining > Duration::from_secs(60),
            "background refresh did not run within 7s (remaining={:?})",
            observed_remaining
        );
        assert_eq!(
            observed_applied,
            Duration::from_secs(600),
            "background refresh must preserve per-proxy TTL (600s), got {:?} \
             (would be 3600s global override if regressed)",
            observed_applied
        );
        assert_eq!(
            observed_per_proxy,
            Some(600),
            "refreshed entry must retain original_per_proxy_ttl"
        );
    }

    /// First failed lookups must record the request's per-proxy TTL immediately
    /// so the failed-retry task can preserve it on later success.
    #[tokio::test]
    async fn cache_error_records_first_failure_per_proxy_ttl() {
        let cache = DnsCache::new(config_with_global_override(None));

        cache.cache_error("example.invalid", Some(600), None);

        let err_entry = cache
            .cache
            .get("example.invalid")
            .expect("error entry exists");
        assert!(err_entry.is_error);
        assert_eq!(
            err_entry.load_shortest_per_proxy_ttl(),
            Some(600),
            "first failed lookup must keep the request's per-proxy TTL"
        );
    }

    /// A refresh failure over an existing success must preserve both the
    /// shared answer and its shortest observed per-proxy TTL. Only callers
    /// already past their own stale window observe the bounded error cooldown.
    #[tokio::test]
    async fn cache_error_preserves_prior_success_and_per_proxy_ttl() {
        let cache = DnsCache::new(config_with_global_override(None));

        // Seed a successful entry with a per-proxy TTL.
        cache.cache.insert(
            "example.invalid".to_string(),
            DnsCacheEntry {
                addresses: Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() + Duration::from_secs(60);
                    exp.checked_sub(Duration::from_secs(600)).unwrap_or(exp)
                },
                native_ttl: Duration::from_secs(600),
                stale_deadline: Instant::now() + Duration::from_secs(60),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: None,
            },
        );

        // Now cache an error for the same hostname (simulating a transient
        // resolve failure picked up by the on-demand path).
        let generation = cache
            .cache
            .get("example.invalid")
            .expect("success generation")
            .next_start
            .clone();
        cache.cache_error("example.invalid", None, Some(&generation));

        let preserved = cache
            .cache
            .get("example.invalid")
            .expect("success entry remains");
        assert!(!preserved.is_error);
        assert_eq!(
            preserved.addresses.as_ref(),
            &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))]
        );
        assert!(preserved.refresh_error_is_live(Instant::now()));
        assert_eq!(
            preserved.load_shortest_per_proxy_ttl(),
            Some(600),
            "cache_error must preserve the prior per-proxy TTL without \
             replacing the shared success row"
        );
    }

    /// If a cached error expires and the next `resolve()` call has no explicit
    /// TTL, the shortest observed per-proxy TTL is retained for refresh
    /// scheduling (`applied_ttl`) while the caller's freshness still uses
    /// global/native policy (not another proxy's override).
    #[tokio::test]
    async fn resolve_preserves_prior_ttl_from_expired_error() {
        let cache = DnsCache::new(config_with_global_override(Some(3600)));
        cache.cache.insert(
            "localhost".to_string(),
            DnsCacheEntry {
                addresses: Arc::from([]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() - Duration::from_secs(1);
                    exp.checked_sub(Duration::from_secs(5)).unwrap_or(exp)
                },
                native_ttl: Duration::ZERO,
                stale_deadline: Instant::now() - Duration::from_secs(1),
                applied_ttl: Duration::from_secs(5),
                record_type_used: None,
                is_error: true,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(600)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: Some(Instant::now() - Duration::from_secs(1)),
            },
        );

        let _ = cache.resolve("localhost", None, None).await.unwrap();

        {
            let entry = cache.cache.get("localhost").expect("entry should exist");
            assert!(!entry.is_error);
            assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(600));
            assert_eq!(
                entry.applied_ttl,
                Duration::from_secs(600),
                "refresh scheduling must keep the shortest observed per-proxy TTL"
            );
            // Caller with no per-proxy override evaluates freshness under global 3600s.
            assert!(
                cache.consumer_fresh_until(&entry, None) > Instant::now(),
                "None-TTL caller uses global/native freshness, independent of shortest=600 refresh hint"
            );
        }
    }

    /// Same prior-TTL preservation contract for `resolve_all()`.
    #[tokio::test]
    async fn resolve_all_preserves_prior_ttl_from_expired_error() {
        let cache = DnsCache::new(config_with_global_override(Some(3600)));
        cache.cache.insert(
            "localhost".to_string(),
            DnsCacheEntry {
                addresses: Arc::from([]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at: {
                    let exp = Instant::now() - Duration::from_secs(1);
                    exp.checked_sub(Duration::from_secs(5)).unwrap_or(exp)
                },
                native_ttl: Duration::ZERO,
                stale_deadline: Instant::now() - Duration::from_secs(1),
                applied_ttl: Duration::from_secs(5),
                record_type_used: None,
                is_error: true,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(450)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(450)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures: 0,
                first_failed_at: Some(Instant::now() - Duration::from_secs(1)),
            },
        );

        let _ = cache.resolve_all("localhost", None, None).await.unwrap();

        let entry = cache.cache.get("localhost").expect("entry should exist");
        assert!(!entry.is_error);
        assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(450));
        assert_eq!(
            entry.applied_ttl,
            Duration::from_secs(450),
            "resolve_all must reuse the expired error entry's per-proxy TTL"
        );
    }

    fn insert_error_entry(
        cache: &DnsCache,
        hostname: &str,
        expires_offset: i64,
        consecutive_failures: u32,
        age: Duration,
    ) {
        let now = Instant::now();
        let expires_at = if expires_offset >= 0 {
            now + Duration::from_secs(expires_offset as u64)
        } else {
            now - Duration::from_secs((-expires_offset) as u64)
        };
        let ttl = cache.error_backoff_ttl(consecutive_failures);
        let resolved_at = expires_at.checked_sub(ttl).unwrap_or(expires_at);
        cache.cache.insert(
            hostname.to_string(),
            DnsCacheEntry {
                addresses: Arc::from([]),
                next_start: Arc::new(AtomicU64::new(0)),
                resolved_at,
                native_ttl: Duration::ZERO,
                stale_deadline: expires_at,
                applied_ttl: ttl,
                record_type_used: None,
                is_error: true,
                refresh_error_deadline: None,
                shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_PER_PROXY_TTL)),
                longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_LONGEST_PER_PROXY_TTL)),
                default_consumer_observed: Arc::new(AtomicBool::new(false)),
                consecutive_failures,
                first_failed_at: Some(now - age),
            },
        );
    }

    #[test]
    fn error_backoff_ttl_doubles_until_stale_cap() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 40,
            ..DnsConfig::default()
        });

        assert_eq!(cache.error_backoff_ttl(0), Duration::from_secs(5));
        assert_eq!(cache.error_backoff_ttl(1), Duration::from_secs(10));
        assert_eq!(cache.error_backoff_ttl(2), Duration::from_secs(20));
        assert_eq!(cache.error_backoff_ttl(3), Duration::from_secs(40));
        // Further failures stay capped at stale_ttl.
        assert_eq!(cache.error_backoff_ttl(10), Duration::from_secs(40));
    }

    #[test]
    fn cache_error_applies_exponential_backoff_across_re_caches() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 3600,
            ..DnsConfig::default()
        });

        cache.cache_error("dead.invalid", None, None);
        {
            let entry = cache.cache.get("dead.invalid").expect("error entry");
            assert_eq!(entry.consecutive_failures, 0);
            assert_eq!(entry.applied_ttl, Duration::from_secs(5));
            assert!(entry.first_failed_at.is_some());
        }

        cache.cache_error("dead.invalid", None, None);
        {
            let entry = cache.cache.get("dead.invalid").expect("error entry");
            assert_eq!(entry.consecutive_failures, 1);
            assert_eq!(entry.applied_ttl, Duration::from_secs(10));
        }

        cache.cache_error("dead.invalid", None, None);
        {
            let entry = cache.cache.get("dead.invalid").expect("error entry");
            assert_eq!(entry.consecutive_failures, 2);
            assert_eq!(entry.applied_ttl, Duration::from_secs(20));
        }
    }

    #[test]
    fn evict_expired_removes_error_entries_past_stale_age_cap() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 30,
            failed_retry_interval_seconds: 10, // retry enabled
            ..DnsConfig::default()
        });

        // Young error — still within age cap; must survive even with expired TTL.
        insert_error_entry(&cache, "young.invalid", -1, 0, Duration::from_secs(5));
        // Aged error — past stale_ttl from first_failed_at; must be evicted.
        insert_error_entry(&cache, "aged.invalid", -1, 3, Duration::from_secs(31));

        assert_eq!(cache.cache_len(), 2);
        cache.evict_expired();
        assert!(
            cache.cache.get("young.invalid").is_some(),
            "young error entries must be retained for the retry task"
        );
        assert!(
            cache.cache.get("aged.invalid").is_none(),
            "error entries older than stale_ttl must be evicted even with retry enabled"
        );
    }

    #[test]
    fn select_failed_retry_candidates_respects_expiry_age_and_cycle_bound() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 60,
            max_concurrent_refreshes: 2,
            failed_retry_interval_seconds: 10,
            ..DnsConfig::default()
        });

        let now = Instant::now();
        // Not yet expired — ineligible.
        insert_error_entry(&cache, "fresh.invalid", 30, 0, Duration::from_secs(1));
        // Expired and young — eligible (oldest).
        insert_error_entry(&cache, "old-a.invalid", -1, 0, Duration::from_secs(20));
        // Expired and younger — eligible.
        insert_error_entry(&cache, "old-b.invalid", -1, 1, Duration::from_secs(10));
        // Expired and youngest — eligible but truncated by cycle bound.
        insert_error_entry(&cache, "old-c.invalid", -1, 2, Duration::from_secs(5));
        // Aged out — pruned, not selected.
        insert_error_entry(&cache, "aged.invalid", -1, 5, Duration::from_secs(61));

        let selected = cache.select_failed_retry_candidates(now);
        assert!(
            cache.cache.get("aged.invalid").is_none(),
            "selection must prune aged-out error entries"
        );
        assert_eq!(selected.len(), 2, "cycle work must be bounded");
        assert_eq!(selected[0].hostname, "old-a.invalid");
        assert_eq!(selected[1].hostname, "old-b.invalid");
        assert!(
            !selected.iter().any(|c| c.hostname == "fresh.invalid"),
            "unexpired error entries must not be selected"
        );
        assert_eq!(selected[0].generation.consecutive_failures, 0);
        assert_eq!(selected[1].generation.consecutive_failures, 1);
    }

    #[test]
    fn aged_out_retry_cleanup_preserves_newer_foreground_success() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 30,
            failed_retry_interval_seconds: 10,
            ..DnsConfig::default()
        });
        let hostname = "recovered.example";
        let cleanup_now = Instant::now();

        insert_error_entry(&cache, hostname, -1, 4, Duration::from_secs(31));

        let recovered = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 40));
        cache
            .cache_success_entry(
                hostname,
                vec![recovered],
                None,
                Duration::from_secs(60),
                None,
                true,
            )
            .expect("foreground success");

        cache.remove_aged_out_failed_retry_candidate(
            hostname,
            cleanup_now,
            cache.failed_entry_lifetime_cap(),
        );

        let entry = cache
            .cache
            .get(hostname)
            .expect("cleanup must retain the newer success generation");
        assert!(!entry.is_error);
        assert_eq!(entry.addresses.as_ref(), &[recovered]);
    }

    fn snapshot_error_generation(cache: &DnsCache, hostname: &str) -> FailedRetryGeneration {
        let entry = cache.cache.get(hostname).expect("error entry");
        assert!(entry.is_error, "expected error generation for {hostname}");
        FailedRetryGeneration {
            consecutive_failures: entry.consecutive_failures,
            first_failed_at: entry
                .first_failed_at
                .expect("error entries record first_failed_at"),
            resolved_at: entry.resolved_at,
            applied_ttl: entry.applied_ttl,
        }
    }

    #[test]
    fn apply_failed_retry_error_advances_backoff_when_generation_matches() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 3600,
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "dead.example", -1, 0, Duration::from_secs(1));
        let generation = snapshot_error_generation(&cache, "dead.example");

        assert!(cache.apply_failed_retry_error("dead.example", &generation, None));
        {
            let entry = cache.cache.get("dead.example").expect("error entry");
            assert_eq!(entry.consecutive_failures, 1);
            assert_eq!(entry.applied_ttl, Duration::from_secs(10));
            assert_eq!(entry.first_failed_at, Some(generation.first_failed_at));
        }
    }

    /// A stale retry success must not overwrite a newer foreground success
    /// that replaced the selected error generation while DNS was in flight.
    #[test]
    fn failed_retry_success_does_not_overwrite_newer_foreground_success() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 60,
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "svc.example", -1, 1, Duration::from_secs(2));
        let stale_generation = snapshot_error_generation(&cache, "svc.example");

        // Foreground recovery while the background retry resolve is pending.
        let foreground_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
        cache
            .cache_success_entry(
                "svc.example",
                vec![foreground_ip],
                None,
                Duration::from_secs(30),
                Some(30),
                true,
            )
            .expect("foreground success");

        let stale_ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));
        let applied = cache
            .apply_failed_retry_success(
                "svc.example",
                &stale_generation,
                vec![stale_ip],
                None,
                Duration::from_secs(30),
                None,
            )
            .expect("policy allows documentation addresses");
        assert!(
            applied.is_none(),
            "stale retry success must abandon when generation changed"
        );

        let entry = cache.cache.get("svc.example").expect("foreground entry");
        assert!(!entry.is_error);
        assert_eq!(entry.addresses.as_ref(), &[foreground_ip]);
        assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(30));
        assert_eq!(entry.consecutive_failures, 0);
    }

    /// Inverse generation change: a stale retry failure must not re-error a
    /// recovered entry, and must not advance backoff on a newer error streak.
    #[test]
    fn failed_retry_error_does_not_overwrite_newer_generation() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 60,
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "svc.example", -1, 0, Duration::from_secs(1));
        let stale_generation = snapshot_error_generation(&cache, "svc.example");

        // Newer foreground success — stale retry failure must not restore error.
        let foreground_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20));
        cache
            .cache_success_entry(
                "svc.example",
                vec![foreground_ip],
                None,
                Duration::from_secs(45),
                None,
                true,
            )
            .expect("foreground success");
        assert!(!cache.apply_failed_retry_error("svc.example", &stale_generation, None));
        {
            let entry = cache.cache.get("svc.example").expect("success entry");
            assert!(!entry.is_error);
            assert_eq!(entry.addresses.as_ref(), &[foreground_ip]);
        }

        // Re-seed an error, then advance the failure streak (as a concurrent
        // request-path cache_error would) so the original generation is stale.
        insert_error_entry(&cache, "svc.example", -1, 0, Duration::from_secs(1));
        let older_generation = snapshot_error_generation(&cache, "svc.example");
        cache.cache_error("svc.example", None, None);
        {
            let entry = cache.cache.get("svc.example").expect("newer error");
            assert_eq!(entry.consecutive_failures, 1);
            assert_eq!(entry.applied_ttl, Duration::from_secs(10));
        }
        assert!(
            !cache.apply_failed_retry_error("svc.example", &older_generation, None),
            "stale retry must not advance a newer error generation's backoff"
        );
        {
            let entry = cache
                .cache
                .get("svc.example")
                .expect("newer error retained");
            assert!(entry.is_error);
            assert_eq!(entry.consecutive_failures, 1);
            assert_eq!(entry.applied_ttl, Duration::from_secs(10));
        }
    }

    #[test]
    fn apply_failed_retry_success_publishes_when_generation_matches() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 60,
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "svc.example", -1, 2, Duration::from_secs(3));
        let generation = snapshot_error_generation(&cache, "svc.example");
        let recovered = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 30));

        let applied = cache
            .apply_failed_retry_success(
                "svc.example",
                &generation,
                vec![recovered],
                None,
                Duration::from_secs(60),
                Some(60),
            )
            .expect("policy allows documentation addresses")
            .expect("matching generation must publish");
        assert_eq!(applied, vec![recovered]);

        let entry = cache.cache.get("svc.example").expect("recovered entry");
        assert!(!entry.is_error);
        assert_eq!(entry.addresses.as_ref(), &[recovered]);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.first_failed_at.is_none());
        assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(60));
    }

    #[test]
    fn apply_failed_retry_success_rejects_denied_addresses_without_publishing() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 60,
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "metadata.internal", -1, 0, Duration::from_secs(1));
        let generation = snapshot_error_generation(&cache, "metadata.internal");

        let result = cache.apply_failed_retry_success(
            "metadata.internal",
            &generation,
            vec!["169.254.169.254".parse().unwrap()],
            Some(CachedRecordType::A),
            Duration::from_secs(60),
            None,
        );
        assert!(result.is_err());

        let entry = cache
            .cache
            .get("metadata.internal")
            .expect("denied retry must leave the selected error generation intact");
        assert!(entry.is_error);
        assert_eq!(entry.consecutive_failures, generation.consecutive_failures);
        assert_eq!(entry.resolved_at, generation.resolved_at);
        assert_eq!(entry.applied_ttl, generation.applied_ttl);
    }

    /// A slow retry that crosses the failed-entry age cap must drop the entry
    /// rather than re-extending residency past the lifetime bound.
    #[test]
    fn apply_failed_retry_error_drops_aged_out_generation() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 30,
            ..DnsConfig::default()
        });
        // Still within cap at insert time, but age == 30s so apply sees aged-out.
        insert_error_entry(&cache, "aged.example", -1, 1, Duration::from_secs(30));
        let generation = snapshot_error_generation(&cache, "aged.example");

        assert!(
            !cache.apply_failed_retry_error("aged.example", &generation, None),
            "aged-out error must not be re-extended by a late retry outcome"
        );
        assert!(
            cache.cache.get("aged.example").is_none(),
            "aged-out error must be removed under the entry guard"
        );
    }

    /// Over-capacity Phase 2 must evict error entries before live success rows,
    /// even when the error has a farther-future expires_at (backed-off TTL).
    #[test]
    fn evict_expired_prefers_error_entries_over_live_on_capacity() {
        let cache = DnsCache::new(DnsConfig {
            max_cache_size: 4,
            error_ttl_seconds: 5,
            stale_ttl_seconds: 3600,
            failed_retry_interval_seconds: 10,
            ..DnsConfig::default()
        });

        let now = Instant::now();
        // Live success entries expire sooner than the backed-off errors.
        for (host, offset) in [("live-a", 10u64), ("live-b", 20), ("live-c", 30)] {
            cache.cache.insert(
                host.to_string(),
                DnsCacheEntry {
                    addresses: Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))]),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at: {
                        let exp = now + Duration::from_secs(offset);
                        exp.checked_sub(Duration::from_secs(offset)).unwrap_or(exp)
                    },
                    native_ttl: Duration::from_secs(offset),
                    stale_deadline: now + Duration::from_secs(offset + 60),
                    applied_ttl: Duration::from_secs(offset),
                    record_type_used: None,
                    is_error: false,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_PER_PROXY_TTL)),
                    longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_LONGEST_PER_PROXY_TTL)),
                    default_consumer_observed: Arc::new(AtomicBool::new(false)),
                    consecutive_failures: 0,
                    first_failed_at: None,
                },
            );
        }
        // Two young errors with far-future expires_at (would sort after lives
        // if Phase 2 used expires_at alone).
        insert_error_entry(&cache, "err-a.invalid", 600, 3, Duration::from_secs(1));
        insert_error_entry(&cache, "err-b.invalid", 600, 3, Duration::from_secs(2));

        assert_eq!(cache.cache_len(), 5);
        cache.evict_expired();

        // target_size = max(4) * 3/4 = 3; remove 2. Both removals must be errors.
        assert!(
            cache.cache_len() <= 4,
            "capacity eviction must trim to max_cache_size"
        );
        assert!(
            cache.cache.get("live-a").is_some()
                && cache.cache.get("live-b").is_some()
                && cache.cache.get("live-c").is_some(),
            "live success entries must not be displaced by error backlog"
        );
        let errors_remaining = ["err-a.invalid", "err-b.invalid"]
            .iter()
            .filter(|h| cache.cache.get(**h).is_some())
            .count();
        assert!(
            errors_remaining <= 1,
            "Phase 2 must prefer error entries for eviction; remaining errors={errors_remaining}"
        );
    }

    /// Capacity trimming must rank live rows by the longest observed consumer
    /// deadline, not the shortest proactive-refresh TTL. Otherwise a short-TTL
    /// peer can make a shared row the first live answer evicted while a
    /// long-TTL peer still considers it fresh.
    #[test]
    fn capacity_eviction_preserves_row_fresh_for_longest_consumer() {
        let cache = DnsCache::new(DnsConfig {
            max_cache_size: 2,
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ..DnsConfig::default()
        });
        let now = Instant::now();
        let address: Arc<[IpAddr]> =
            Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 80))]);

        let shared = success_entry(
            address.clone(),
            now - Duration::from_secs(10),
            Duration::from_secs(600),
            Some(5),
            now + Duration::from_secs(590),
        );
        shared.note_per_proxy_ttl(Some(600));
        cache.cache.insert("shared.example".to_string(), shared);
        cache.cache.insert(
            "short.example".to_string(),
            success_entry(
                address.clone(),
                now,
                Duration::from_secs(30),
                Some(30),
                now + Duration::from_secs(30),
            ),
        );
        cache.cache.insert(
            "medium.example".to_string(),
            success_entry(
                address,
                now,
                Duration::from_secs(60),
                Some(60),
                now + Duration::from_secs(60),
            ),
        );

        cache.evict_expired();

        assert_eq!(cache.cache_len(), 1, "capacity target is 75% of max");
        assert!(
            cache.cache.get("shared.example").is_some(),
            "the 600s consumer's shared row must outlive 30s/60s rows even though \
             its shortest refresh policy is already expired"
        );
    }

    /// Policy-denied retry success must advance error backoff (via the same
    /// generation-guarded apply path) so the expired entry is not selected
    /// again on every subsequent cycle.
    #[test]
    fn policy_denied_retry_advances_backoff_like_failed_resolve() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 5,
            stale_ttl_seconds: 3600,
            backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
            ..DnsConfig::default()
        });
        insert_error_entry(&cache, "metadata.internal", -1, 0, Duration::from_secs(1));
        let generation = snapshot_error_generation(&cache, "metadata.internal");

        // Simulate the cycle's Err(policy) branch: apply_failed_retry_error.
        assert!(cache.apply_failed_retry_error("metadata.internal", &generation, None));
        {
            let entry = cache
                .cache
                .get("metadata.internal")
                .expect("error retained");
            assert_eq!(entry.consecutive_failures, 1);
            assert_eq!(entry.applied_ttl, Duration::from_secs(10));
            assert!(entry.error_expires_at() > Instant::now());
        }
    }

    /// Acceptance fixture from issue #2415: shared hostname, 5s vs 600s, both
    /// note orders. Freshness is evaluated from a shared `resolved_at` without
    /// sleeping wall-clock time.
    #[test]
    fn shared_hostname_5s_600s_freshness_both_note_orders() {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 3600,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });
        let now = Instant::now();
        let resolved_at = now - Duration::from_secs(10);
        let entry = success_entry(
            Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10))]),
            resolved_at,
            Duration::from_secs(3600),
            None,
            now + Duration::from_secs(7200),
        );

        for note_order in [[5u64, 600u64], [600u64, 5u64]] {
            for ttl in note_order {
                entry.note_per_proxy_ttl(Some(ttl));
            }
            assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(5));
            assert_eq!(entry.load_longest_per_proxy_ttl(), Some(600));
            assert!(
                cache.consumer_fresh_until(&entry, Some(600)) > now,
                "600s consumer must still be fresh 10s after publish (order={note_order:?})"
            );
            assert!(
                cache.consumer_fresh_until(&entry, Some(5)) <= now,
                "5s consumer must be past fresh 10s after publish (order={note_order:?})"
            );
            assert!(
                cache.consumer_stale_until(&entry, Some(5)) > now,
                "5s consumer must still be inside the shared SWR window"
            );
            assert_eq!(
                cache.shared_retention_ttl(
                    entry.native_ttl,
                    entry.load_longest_per_proxy_ttl(),
                    entry.load_default_consumer_observed(),
                ),
                Duration::from_secs(600),
                "shared-row age eviction must retain for the longest peer, not the shortest"
            );
        }
    }

    /// Shared-row age eviction must honor global/native short TTLs when a
    /// default consumer was observed (so `evict_expired` can reclaim) while a
    /// later long per-proxy note extends retention without letting a short peer
    /// shrink it. Explicit-only rows must not keep native TTL as an implicit
    /// consumer.
    #[test]
    fn shared_row_retention_tracks_longest_consumer_and_global_override() {
        let short_global = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 1,
            ttl_override_seconds: Some(1),
            ..DnsConfig::default()
        });
        assert_eq!(
            short_global.shared_retention_ttl(Duration::from_secs(86_400), None, true),
            Duration::from_secs(1),
            "global override alone must remain age-evictable"
        );
        assert_eq!(
            short_global.shared_retention_ttl(Duration::from_secs(86_400), Some(600), true),
            Duration::from_secs(600),
            "longest per-proxy must extend retention past a short global override"
        );

        let no_global = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 1,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });
        let now = Instant::now();
        let resolved_at = now - Duration::from_secs(30);
        let entry = success_entry(
            Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 51))]),
            resolved_at,
            Duration::from_secs(60),
            None,
            now + Duration::from_secs(3600),
        );
        entry.note_per_proxy_ttl(Some(5));
        entry.note_per_proxy_ttl(Some(600));
        let deadline = no_global.shared_stale_deadline(
            entry.resolved_at,
            entry.native_ttl,
            entry.load_longest_per_proxy_ttl(),
            entry.load_default_consumer_observed(),
        );
        assert!(
            deadline > now + Duration::from_secs(500),
            "30s after publish, a 600s peer must still keep the shared row"
        );
        assert!(
            no_global.shared_stale_deadline(entry.resolved_at, entry.native_ttl, Some(5), false,)
                < now,
            "explicit-only 5s retention must already be past deadline; native 60s must not dominate"
        );
    }

    /// Order-independent coverage: explicit-only consumers control retention and
    /// refresh without inventing a default/native consumer; mixed default +
    /// explicit consumers fold both policies into the max/min.
    #[test]
    fn shared_row_observation_state_drives_retention_and_refresh() {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 1,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });
        let native = Duration::from_secs(60);

        for note_order in [vec![Some(5u64), Some(30u64)], vec![Some(30u64), Some(5u64)]] {
            let entry = success_entry(
                Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 71))]),
                Instant::now(),
                native,
                None,
                Instant::now() + Duration::from_secs(3600),
            );
            for ttl in &note_order {
                entry.note_per_proxy_ttl(*ttl);
            }
            assert!(
                !entry.load_default_consumer_observed(),
                "explicit-only notes must not invent a default consumer (order={note_order:?})"
            );
            assert_eq!(
                cache.shared_retention_ttl(
                    native,
                    entry.load_longest_per_proxy_ttl(),
                    entry.load_default_consumer_observed(),
                ),
                Duration::from_secs(30),
                "explicit-only retention uses longest override, not native 60s"
            );
            assert_eq!(
                cache.refresh_ttl_for_entry(&entry),
                Duration::from_secs(5),
                "explicit-only refresh uses shortest override, not native 60s"
            );
        }

        for note_order in [
            vec![None, Some(600u64)],
            vec![Some(600u64), None],
            vec![None, Some(5u64), Some(600u64)],
            vec![Some(600u64), Some(5u64), None],
        ] {
            let entry = success_entry(
                Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 72))]),
                Instant::now(),
                native,
                None,
                Instant::now() + Duration::from_secs(3600),
            );
            for ttl in &note_order {
                entry.note_per_proxy_ttl(*ttl);
            }
            assert!(
                entry.load_default_consumer_observed(),
                "a None note must mark the default consumer (order={note_order:?})"
            );
            assert_eq!(
                cache.shared_retention_ttl(
                    native,
                    entry.load_longest_per_proxy_ttl(),
                    entry.load_default_consumer_observed(),
                ),
                Duration::from_secs(600),
                "mixed retention is max(native, longest explicit)"
            );
            let expected_refresh = if note_order.contains(&Some(5)) {
                Duration::from_secs(5)
            } else {
                // default native 60s is shorter than explicit 600s
                Duration::from_secs(60)
            };
            assert_eq!(
                cache.refresh_ttl_for_entry(&entry),
                expected_refresh,
                "mixed refresh is min among observed policies (order={note_order:?})"
            );
        }

        // Explicit-only 5s consumer must expire under native 60s wall time.
        let now = Instant::now();
        let short_only = success_entry(
            Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 73))]),
            now - Duration::from_secs(30),
            native,
            None,
            now + Duration::from_secs(3600),
        );
        short_only.note_per_proxy_ttl(Some(5));
        assert!(
            cache.shared_stale_deadline(
                short_only.resolved_at,
                short_only.native_ttl,
                short_only.load_longest_per_proxy_ttl(),
                short_only.load_default_consumer_observed(),
            ) < now,
            "explicit-only 5s row must be age-evictable despite native 60s"
        );
    }

    /// A short-TTL caller's failed synchronous refresh must not replace the
    /// shared success row while a longer-TTL peer still considers that answer
    /// fresh. The failed caller gets a bounded cached-error cooldown instead.
    #[test]
    fn short_ttl_refresh_failure_preserves_long_ttl_fresh_answer() {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            error_ttl_seconds: 10,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });
        let now = Instant::now();
        cache.cache.insert(
            "shared.example".to_string(),
            success_entry(
                Arc::from([IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 44))]),
                now - Duration::from_secs(10),
                Duration::from_secs(600),
                Some(5),
                now + Duration::from_secs(86_400),
            ),
        );

        let generation = cache
            .cache
            .get("shared.example")
            .expect("success generation")
            .next_start
            .clone();
        cache.cache_error("shared.example", Some(5), Some(&generation));

        let entry = cache.cache.get("shared.example").expect("shared answer");
        assert!(
            !entry.is_error,
            "refresh failure must preserve the answer row"
        );
        assert_eq!(
            entry.addresses.as_ref(),
            &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 44))]
        );
        assert!(
            cache.consumer_fresh_until(&entry, Some(600)) > now,
            "600s peer must retain its still-fresh shared answer"
        );
        assert!(
            cache.consumer_stale_until(&entry, Some(5)) <= now,
            "5s peer is past its own stale window"
        );
        assert!(
            entry.refresh_error_is_live(Instant::now()),
            "expired peer must receive a bounded cached refresh error"
        );
    }

    /// Repeated refresh rounds against a preserved shared answer must back off
    /// exponentially. A shared row survives for its longest observed consumer,
    /// so a fixed `error_ttl` cooldown would re-query a dead hostname every few
    /// seconds for that entire window while the long-TTL peer keeps serving the
    /// cached answer. Callers racing inside one live cooldown must not each
    /// advance the streak.
    #[test]
    fn preserved_refresh_error_cooldown_backs_off_exponentially() {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 3600,
            error_ttl_seconds: 5,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });
        let address = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 47));
        let now = Instant::now();
        cache.cache.insert(
            "shared.example".to_string(),
            success_entry(
                Arc::from([address]),
                now - Duration::from_secs(10),
                Duration::from_secs(600),
                Some(5),
                now + Duration::from_secs(86_400),
            ),
        );
        // The 600s peer's row stays live across every failed 5s-peer refresh.
        cache
            .cache
            .get("shared.example")
            .expect("seeded row")
            .note_per_proxy_ttl(Some(600));
        let generation = cache
            .cache
            .get("shared.example")
            .expect("success generation")
            .next_start
            .clone();

        for (attempt, expected_secs) in [(1u32, 5u64), (2, 10), (3, 20)] {
            let before = Instant::now();
            cache.cache_error("shared.example", Some(5), Some(&generation));
            let after = Instant::now();
            let (is_error, deadline, failures) = {
                let entry = cache
                    .cache
                    .get("shared.example")
                    .expect("shared answer must survive every failed refresh");
                (
                    entry.is_error,
                    entry.refresh_error_deadline.expect("cooldown armed"),
                    entry.consecutive_failures,
                )
            };
            let expected = Duration::from_secs(expected_secs);
            assert!(!is_error, "attempt {attempt}: answer row must be preserved");
            assert_eq!(
                failures, attempt,
                "attempt {attempt}: refresh failures must accumulate on the shared row"
            );
            assert!(
                deadline >= before + expected && deadline <= after + expected,
                "attempt {attempt}: cooldown must be {expected:?}, not a fixed error_ttl"
            );

            // A caller racing inside the live cooldown must not advance the
            // streak — otherwise one failed round on a busy hostname jumps
            // straight to the backoff cap.
            cache.cache_error("shared.example", Some(5), Some(&generation));
            {
                let entry = cache.cache.get("shared.example").expect("still preserved");
                assert_eq!(
                    entry.consecutive_failures, attempt,
                    "attempt {attempt}: a racing caller must not advance the backoff"
                );
                assert_eq!(
                    entry.refresh_error_deadline,
                    Some(deadline),
                    "attempt {attempt}: a racing caller must not extend the cooldown"
                );
            }

            // Let the cooldown lapse so the next iteration is a new round.
            if let Some(mut entry) = cache.cache.get_mut("shared.example") {
                entry.refresh_error_deadline = Some(before);
            }
        }

        // A successful republication clears both the cooldown and the streak.
        cache
            .cache_success_entry(
                "shared.example",
                vec![address],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                Some(5),
                false,
            )
            .expect("republish");
        let entry = cache.cache.get("shared.example").expect("republished row");
        assert!(entry.refresh_error_deadline.is_none());
        assert_eq!(entry.consecutive_failures, 0);
    }

    /// Success publication must preserve shared observation atomics under the
    /// DashMap entry guard; replacing them with new atomics would let cold
    /// concurrent insertion order choose proactive-refresh / retention policy
    /// again.
    #[test]
    fn success_republication_preserves_and_tightens_shortest_ttl_atomic() {
        let cache = DnsCache::new(config_with_global_override(None));
        let address = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 45));

        cache
            .cache_success_entry(
                "shared.example",
                vec![address],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                Some(600),
                false,
            )
            .expect("first publish");
        let first = cache
            .cache
            .get("shared.example")
            .expect("first row")
            .shortest_per_proxy_ttl_secs
            .clone();
        let first_longest = cache
            .cache
            .get("shared.example")
            .expect("first row")
            .longest_per_proxy_ttl_secs
            .clone();
        let first_default = cache
            .cache
            .get("shared.example")
            .expect("first row")
            .default_consumer_observed
            .clone();

        cache
            .cache_success_entry(
                "shared.example",
                vec![address],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                Some(5),
                false,
            )
            .expect("second publish");
        // A default consumer hit after the explicit publishers must stick on the
        // same Arc so later retention/refresh include native/global policy.
        cache
            .cache
            .get("shared.example")
            .expect("second row")
            .note_per_proxy_ttl(None);
        cache
            .cache_success_entry(
                "shared.example",
                vec![address],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                None,
                false,
            )
            .expect("third publish with default consumer");
        let entry = cache.cache.get("shared.example").expect("third row");
        assert!(Arc::ptr_eq(&first, &entry.shortest_per_proxy_ttl_secs));
        assert!(Arc::ptr_eq(
            &first_longest,
            &entry.longest_per_proxy_ttl_secs
        ));
        assert!(Arc::ptr_eq(
            &first_default,
            &entry.default_consumer_observed
        ));
        assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(5));
        assert_eq!(entry.load_longest_per_proxy_ttl(), Some(600));
        assert!(entry.load_default_consumer_observed());
    }

    /// A failed lookup from an older success generation must not attach a
    /// refresh-error cooldown to a newer answer that won the in-flight race.
    #[test]
    fn stale_refresh_failure_does_not_taint_newer_success() {
        let cache = DnsCache::new(DnsConfig {
            error_ttl_seconds: 10,
            ..DnsConfig::default()
        });
        cache
            .cache_success_entry(
                "shared.example",
                vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 45))],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                Some(5),
                false,
            )
            .expect("old success");
        let old_generation = cache
            .cache
            .get("shared.example")
            .expect("old generation")
            .next_start
            .clone();

        cache
            .cache_success_entry(
                "shared.example",
                vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 46))],
                Some(CachedRecordType::A),
                Duration::from_secs(600),
                Some(5),
                false,
            )
            .expect("new success");
        cache.cache_error("shared.example", Some(5), Some(&old_generation));

        let entry = cache.cache.get("shared.example").expect("new success row");
        assert_eq!(
            entry.addresses.as_ref(),
            &[IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 46))]
        );
        assert!(
            entry.refresh_error_deadline.is_none(),
            "stale failure must not taint a newer success generation"
        );
    }

    /// Two proxies sharing one hostname must each honor their own TTL regardless
    /// of which consumer populated the shared answer first.
    #[tokio::test]
    async fn shared_hostname_per_proxy_ttl_isolation_both_insertion_orders() {
        for (first_ttl, second_ttl) in [(1u64, 600u64), (600u64, 1u64)] {
            let cache = DnsCache::new(DnsConfig {
                min_ttl_seconds: 1,
                stale_ttl_seconds: 0,
                ttl_override_seconds: None,
                ..DnsConfig::default()
            });
            let host = "localhost";

            cache
                .resolve(host, None, Some(first_ttl))
                .await
                .expect("first consumer resolve");
            cache
                .resolve(host, None, Some(second_ttl))
                .await
                .expect("second consumer resolve");
            assert_eq!(cache.cache_len(), 1, "shared hostname must stay one row");
            assert_eq!(
                cache
                    .cache
                    .get(host)
                    .expect("shared row")
                    .load_shortest_per_proxy_ttl(),
                Some(1),
                "shortest observed per-proxy TTL must be tracked for refresh scheduling"
            );

            // Past the 1s consumer window; still inside the 600s window.
            tokio::time::sleep(Duration::from_secs(2)).await;
            {
                let now = Instant::now();
                let entry = cache.cache.get(host).expect("shared row after sleep");
                assert!(
                    cache.consumer_fresh_until(&entry, Some(600)) > now,
                    "order=({first_ttl},{second_ttl}): 600s consumer must remain fresh"
                );
                assert!(
                    cache.consumer_fresh_until(&entry, Some(1)) <= now,
                    "order=({first_ttl},{second_ttl}): 1s consumer must be past fresh"
                );
            }

            // Short-TTL re-resolve publishes a new shared row; still one entry.
            let _ = cache.resolve(host, None, Some(1)).await.unwrap();
            assert_eq!(cache.cache_len(), 1);
            {
                let refreshed = cache.cache.get(host).expect("re-resolved row");
                assert!(
                    cache.consumer_fresh_until(&refreshed, Some(1)) > Instant::now(),
                    "short-TTL re-resolve must publish a fresh shared answer"
                );
            }
        }
    }

    /// Warmup / reload reordering must not change per-consumer freshness.
    #[tokio::test]
    async fn warmup_reload_reordering_preserves_per_proxy_ttl_isolation() {
        for hostnames in [
            vec![
                ("localhost".to_string(), None, Some(1u64)),
                ("localhost".to_string(), None, Some(600u64)),
            ],
            vec![
                ("localhost".to_string(), None, Some(600u64)),
                ("localhost".to_string(), None, Some(1u64)),
            ],
        ] {
            let cache = DnsCache::new(DnsConfig {
                min_ttl_seconds: 1,
                stale_ttl_seconds: 0,
                ..DnsConfig::default()
            });
            cache.warmup(hostnames).await;
            assert_eq!(cache.cache_len(), 1);
            assert_eq!(
                cache
                    .cache
                    .get("localhost")
                    .expect("warmed")
                    .load_shortest_per_proxy_ttl(),
                Some(1)
            );
            assert_eq!(
                cache
                    .cache
                    .get("localhost")
                    .expect("warmed")
                    .load_longest_per_proxy_ttl(),
                Some(600),
                "warmup must retain the longest advertised policy before first traffic"
            );

            tokio::time::sleep(Duration::from_secs(2)).await;
            let now = Instant::now();
            let entry = cache.cache.get("localhost").expect("warmed row");
            assert!(cache.consumer_fresh_until(&entry, Some(600)) > now);
            assert!(cache.consumer_fresh_until(&entry, Some(1)) <= now);
        }

        for hostnames in [
            vec![
                ("localhost".to_string(), None, Some(1u64)),
                ("localhost".to_string(), None, None),
            ],
            vec![
                ("localhost".to_string(), None, None),
                ("localhost".to_string(), None, Some(1u64)),
            ],
        ] {
            let cache = DnsCache::new(DnsConfig {
                ttl_override_seconds: Some(3600),
                min_ttl_seconds: 1,
                stale_ttl_seconds: 0,
                ..DnsConfig::default()
            });
            cache.warmup(hostnames).await;
            let entry = cache.cache.get("localhost").expect("warmed");
            assert_eq!(entry.load_shortest_per_proxy_ttl(), Some(1));
            assert!(
                entry.load_default_consumer_observed(),
                "warmup must retain a default/global/native consumer in either order"
            );
            assert_eq!(
                cache.shared_retention_ttl(
                    entry.native_ttl,
                    entry.load_longest_per_proxy_ttl(),
                    entry.load_default_consumer_observed(),
                ),
                Duration::from_secs(3600),
                "default/global retention must be known before first traffic"
            );
        }
    }

    /// Per-proxy TTL still beats global override and native TTL for that caller.
    #[tokio::test]
    async fn per_proxy_ttl_precedence_over_global_and_native_with_shared_row() {
        let cache = DnsCache::new(DnsConfig {
            ttl_override_seconds: Some(3600),
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ..DnsConfig::default()
        });
        // Per-proxy 1s vs global 3600s on a shared hostname row.
        cache.resolve("localhost", None, Some(1)).await.unwrap();
        // A peer without per-proxy override uses the global 3600s policy on the
        // same shared row.
        cache.resolve("localhost", None, None).await.unwrap();

        tokio::time::sleep(Duration::from_secs(2)).await;
        let now = Instant::now();
        let entry = cache.cache.get("localhost").expect("shared row");
        assert!(
            cache.consumer_fresh_until(&entry, None) > now,
            "global-policy consumer must remain fresh"
        );
        assert!(
            cache.consumer_fresh_until(&entry, Some(1)) <= now,
            "per-proxy 1s consumer must expire despite global 3600s override"
        );
    }

    /// Private seams for issue #4270. Compiled only with the library test
    /// target so release `DnsCache` has no hook field or public test API.
    mod background_refresh_hardening {
        use super::*;
        use std::sync::atomic::AtomicUsize;
        use tokio::sync::Notify;

        type BackgroundTestResolve =
            Result<(Vec<IpAddr>, Option<CachedRecordType>, Duration), anyhow::Error>;

        fn testnet_addr(octet: u8) -> IpAddr {
            IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet))
        }

        fn near_expiry_cache(max_concurrent_refreshes: usize, max_cache_size: usize) -> DnsCache {
            DnsCache::new(DnsConfig {
                min_ttl_seconds: 1,
                stale_ttl_seconds: 3600,
                refresh_threshold_percent: 90,
                max_concurrent_refreshes,
                max_cache_size,
                ..DnsConfig::default()
            })
        }

        fn seed_success_entry(
            cache: &DnsCache,
            hostname: &str,
            addresses: Vec<IpAddr>,
            resolved_at: Instant,
            native_ttl: Duration,
            per_proxy_ttl: Option<u64>,
        ) {
            let default_consumer_observed = per_proxy_ttl.is_none();
            let applied_ttl =
                cache.observed_refresh_ttl(native_ttl, per_proxy_ttl, default_consumer_observed);
            let stale_deadline = cache.shared_stale_deadline(
                resolved_at,
                native_ttl,
                per_proxy_ttl,
                default_consumer_observed,
            );
            cache.cache.insert(
                dns_hostname_key(hostname).into_owned(),
                DnsCacheEntry {
                    addresses: addresses.into(),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at,
                    native_ttl,
                    stale_deadline,
                    applied_ttl,
                    record_type_used: Some(CachedRecordType::A),
                    is_error: false,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                        per_proxy_ttl.unwrap_or(NO_PER_PROXY_TTL),
                    )),
                    longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(
                        per_proxy_ttl.unwrap_or(NO_LONGEST_PER_PROXY_TTL),
                    )),
                    default_consumer_observed: Arc::new(AtomicBool::new(default_consumer_observed)),
                    consecutive_failures: 0,
                    first_failed_at: None,
                },
            );
        }

        fn seed_error_entry(
            cache: &DnsCache,
            hostname: &str,
            resolved_at: Instant,
            applied_ttl: Duration,
        ) {
            cache.cache.insert(
                dns_hostname_key(hostname).into_owned(),
                DnsCacheEntry {
                    addresses: Arc::from([]),
                    next_start: Arc::new(AtomicU64::new(0)),
                    resolved_at,
                    native_ttl: Duration::ZERO,
                    stale_deadline: resolved_at + applied_ttl,
                    applied_ttl,
                    record_type_used: None,
                    is_error: true,
                    refresh_error_deadline: None,
                    shortest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_PER_PROXY_TTL)),
                    longest_per_proxy_ttl_secs: Arc::new(AtomicU64::new(NO_LONGEST_PER_PROXY_TTL)),
                    default_consumer_observed: Arc::new(AtomicBool::new(false)),
                    consecutive_failures: 0,
                    first_failed_at: Some(resolved_at),
                },
            );
        }

        fn seed_near_expiry(cache: &DnsCache, hostname: &str, remaining: Duration, addr: IpAddr) {
            let native_ttl = Duration::from_secs(100);
            let resolved_at = Instant::now() + remaining - native_ttl;
            seed_success_entry(cache, hostname, vec![addr], resolved_at, native_ttl, None);
        }

        fn seed_stale_swr(cache: &DnsCache, hostname: &str, addr: IpAddr) {
            let per_proxy_ttl = 5u64;
            let resolved_at = Instant::now() - Duration::from_secs(per_proxy_ttl + 1);
            seed_success_entry(
                cache,
                hostname,
                vec![addr],
                resolved_at,
                Duration::from_secs(100),
                Some(per_proxy_ttl),
            );
        }

        fn success_addresses(cache: &DnsCache, hostname: &str) -> Option<Vec<IpAddr>> {
            let cache_key = dns_hostname_key(hostname);
            cache.cache.get(cache_key.as_ref()).and_then(|entry| {
                if entry.is_error {
                    None
                } else {
                    Some(entry.addresses.as_ref().to_vec())
                }
            })
        }

        fn success_resolved_at(cache: &DnsCache, hostname: &str) -> Option<Instant> {
            let cache_key = dns_hostname_key(hostname);
            cache.cache.get(cache_key.as_ref()).and_then(|entry| {
                if entry.is_error {
                    None
                } else {
                    Some(entry.resolved_at)
                }
            })
        }

        fn install_hanging_refresh_hook(
            cache: &mut DnsCache,
            in_flight: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
            started: Arc<Notify>,
            notify_at: usize,
        ) {
            cache.refresh_resolve_hook = Some(Arc::new(move |_hostname: String| {
                let in_flight = in_flight.clone();
                let max_seen = max_seen.clone();
                let started = started.clone();
                Box::pin(async move {
                    let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(n, Ordering::SeqCst);
                    if n == notify_at {
                        started.notify_one();
                    }
                    std::future::pending::<BackgroundTestResolve>().await
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
        }

        fn install_gated_refresh_hook(
            cache: &mut DnsCache,
            gate: Arc<tokio::sync::Semaphore>,
            stale_addr: IpAddr,
            entered: Arc<Notify>,
            released: Arc<Notify>,
        ) {
            cache.refresh_resolve_hook = Some(Arc::new(move |_hostname: String| {
                let gate = gate.clone();
                let entered = entered.clone();
                let released = released.clone();
                Box::pin(async move {
                    entered.notify_one();
                    let _permit = gate.acquire().await.expect("refresh-test gate");
                    released.notify_one();
                    Ok((
                        vec![stale_addr],
                        Some(CachedRecordType::A),
                        Duration::from_secs(30),
                    ))
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
        }

        fn install_immediate_refresh_hook(
            cache: &mut DnsCache,
            addr: IpAddr,
            queries: Arc<AtomicUsize>,
        ) {
            cache.refresh_resolve_hook = Some(Arc::new(move |_hostname: String| {
                let queries = queries.clone();
                Box::pin(async move {
                    queries.fetch_add(1, Ordering::SeqCst);
                    Ok((
                        vec![addr],
                        Some(CachedRecordType::A),
                        Duration::from_secs(30),
                    ))
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
        }

        async fn wait_until_refresh_idle(cache: &DnsCache) {
            for _ in 0..64 {
                if cache.refreshing.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }

        /// Wait until the refresh path actually holds `expected` in-flight
        /// slots — both the `refreshing` dedup markers and every permit of a
        /// `max_concurrent_refreshes == expected` semaphore.
        ///
        /// Issue #4485: the hanging hook's `started` notification is keyed on
        /// a cumulative `in_flight` counter bumped from *inside* the resolve
        /// future, which is neither of the structures the assertions read.
        /// Candidate eligibility also reads the real `std::time::Instant`
        /// clock, which `start_paused` does not freeze, so under `llvm-cov`
        /// instrumentation a near-expiry row can age out of the selection
        /// window and the counter can instead reach `expected` across two
        /// successive cycles that each held a single slot. Synchronizing on
        /// the observed state removes that gap; the bound makes a genuine
        /// regression fail with the observed values rather than hang.
        async fn wait_for_refresh_slots(cache: &DnsCache, expected: usize) {
            for _ in 0..256 {
                if cache.refreshing.len() == expected
                    && cache.refresh_semaphore.available_permits() == 0
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
            panic!(
                "timed out waiting for {expected} in-flight refresh slot(s): refreshing={}, available_permits={}",
                cache.refreshing.len(),
                cache.refresh_semaphore.available_permits()
            );
        }

        #[test]
        fn proactive_refresh_selection_is_soonest_expiry_and_capped() {
            let cache = near_expiry_cache(2, 10_000);
            seed_near_expiry(
                &cache,
                "later-window.test",
                Duration::from_secs(7),
                testnet_addr(3),
            );
            seed_near_expiry(
                &cache,
                "soonest.test",
                Duration::from_secs(1),
                testnet_addr(1),
            );
            seed_near_expiry(
                &cache,
                "second.test",
                Duration::from_secs(3),
                testnet_addr(2),
            );
            seed_near_expiry(
                &cache,
                "fresh.test",
                Duration::from_secs(50),
                testnet_addr(4),
            );
            seed_error_entry(
                &cache,
                "error.test",
                Instant::now() - Duration::from_secs(1),
                Duration::from_secs(5),
            );
            seed_near_expiry(
                &cache,
                "already-expired.test",
                Duration::ZERO,
                testnet_addr(5),
            );

            let selected: Vec<String> = cache
                .select_proactive_refresh_candidates(Instant::now())
                .into_iter()
                .map(|c| c.hostname)
                .collect();
            assert_eq!(
                selected,
                vec!["soonest.test".to_string(), "second.test".to_string()],
                "selection must be soonest-expiry first and capped at max_concurrent_refreshes"
            );
            assert!(
                !selected.iter().any(|h| h == "error.test"),
                "error rows belong to the failed-retry task"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_refresh_concurrency_never_exceeds_configured_maximum() {
            let in_flight = Arc::new(AtomicUsize::new(0));
            let max_seen = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(2, 10_000);
            install_hanging_refresh_hook(
                &mut cache,
                in_flight.clone(),
                max_seen.clone(),
                started.clone(),
                2,
            );
            let cache = cache;

            for i in 1..=5 {
                // Seconds, not milliseconds: selection reads the real
                // `std::time::Instant` clock, which `start_paused` does not
                // freeze, so a slow instrumented run must not age these rows
                // out of the near-expiry window before the cycle runs.
                seed_near_expiry(
                    &cache,
                    &format!("host-{i}.test"),
                    Duration::from_secs(i as u64),
                    testnet_addr(i),
                );
            }

            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_proactive_refresh_cycle().await }
            });
            wait_for_refresh_slots(&cache, 2).await;
            assert!(
                max_seen.load(Ordering::SeqCst) <= 2,
                "in-flight resolves must not exceed max_concurrent_refreshes, saw {}",
                max_seen.load(Ordering::SeqCst)
            );
            assert_eq!(cache.refreshing.len(), 2);
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);

            handle.abort();
            let _ = handle.await;
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 2);
        }

        #[tokio::test(start_paused = true)]
        async fn eviction_trims_over_capacity_while_refreshes_are_blocked() {
            let in_flight = Arc::new(AtomicUsize::new(0));
            let max_seen = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(2, 4);
            install_hanging_refresh_hook(
                &mut cache,
                in_flight.clone(),
                max_seen.clone(),
                started.clone(),
                2,
            );
            let cache = cache;

            // Seconds, not milliseconds: selection reads the real
            // `std::time::Instant` clock, which `start_paused` does not
            // freeze, so a slow instrumented run must not age either row out
            // of the near-expiry window before the first cycle runs.
            seed_near_expiry(
                &cache,
                "hang-1.test",
                Duration::from_secs(2),
                testnet_addr(1),
            );
            seed_near_expiry(
                &cache,
                "hang-2.test",
                Duration::from_secs(3),
                testnet_addr(2),
            );
            assert_eq!(cache.cache_len(), 2);

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let handle = cache.start_background_refresh_with_shutdown(Some(shutdown_rx));
            wait_for_refresh_slots(&cache, 2).await;
            assert_eq!(cache.refreshing.len(), 2);
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);

            for i in 3..=12 {
                seed_near_expiry(
                    &cache,
                    &format!("fresh-{i}.test"),
                    Duration::from_secs(50),
                    testnet_addr(i),
                );
            }
            assert!(
                cache.cache_len() > 4,
                "over-capacity rows must exist while refresh futures stay blocked"
            );

            tokio::time::advance(DnsCache::BACKGROUND_MAINTENANCE_INTERVAL).await;
            for _ in 0..64 {
                if cache.cache_len() <= 4 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                cache.cache_len() <= 4,
                "eviction sibling must trim max_cache_size while refreshes hang, len={}",
                cache.cache_len()
            );
            assert_eq!(
                cache.refreshing.len(),
                2,
                "eviction must not wait for hanging refreshes to finish"
            );

            shutdown_tx.send(true).expect("shutdown watch");
            handle
                .await
                .expect("shutdown must complete the refresh task");
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 2);
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_refresh_timeout_preserves_last_known_good() {
            let started = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(2, 10_000);
            install_hanging_refresh_hook(
                &mut cache,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                started.clone(),
                1,
            );
            let cache = cache;

            let original = testnet_addr(10);
            seed_near_expiry(&cache, "timeout.test", Duration::from_secs(2), original);
            let resolved_at = success_resolved_at(&cache, "timeout.test").expect("seeded");

            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_proactive_refresh_cycle().await }
            });
            started.notified().await;

            tokio::time::advance(
                DnsCache::BACKGROUND_REFRESH_RESOLVE_TIMEOUT + Duration::from_millis(1),
            )
            .await;
            handle.await.expect("cycle must return after timeout");

            assert_eq!(
                success_addresses(&cache, "timeout.test"),
                Some(vec![original]),
                "a timed-out refresh must preserve the last known good row"
            );
            assert_eq!(
                success_resolved_at(&cache, "timeout.test"),
                Some(resolved_at),
                "a timed-out refresh must not extend or rewrite the success row"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 2);
        }

        #[tokio::test(start_paused = true)]
        async fn swr_refresh_timeout_preserves_last_known_good_and_releases_permit() {
            let started = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(1, 10_000);
            install_hanging_refresh_hook(
                &mut cache,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                started.clone(),
                1,
            );
            let cache = cache;

            let original = testnet_addr(10);
            seed_stale_swr(&cache, "swr-timeout.test", original);
            let resolved_at = success_resolved_at(&cache, "swr-timeout.test").expect("seeded");

            let served = cache
                .resolve("swr-timeout.test", None, Some(5))
                .await
                .expect("SWR must serve the stale row");
            assert_eq!(served, original);
            started.notified().await;
            assert_eq!(cache.refreshing.len(), 1);
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);

            tokio::time::advance(
                DnsCache::BACKGROUND_REFRESH_RESOLVE_TIMEOUT + Duration::from_millis(1),
            )
            .await;
            wait_until_refresh_idle(&cache).await;

            assert_eq!(
                success_addresses(&cache, "swr-timeout.test"),
                Some(vec![original]),
                "a timed-out SWR lookup must preserve the last known good row"
            );
            assert_eq!(
                success_resolved_at(&cache, "swr-timeout.test"),
                Some(resolved_at),
                "a timed-out SWR lookup must not extend or rewrite the success row"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(
                cache.refresh_semaphore.available_permits(),
                1,
                "SWR timeout must release the shared refresh permit"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_refresh_shutdown_releases_dedup_and_permits() {
            let started = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(1, 10_000);
            install_hanging_refresh_hook(
                &mut cache,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                started.clone(),
                1,
            );
            let cache = cache;
            seed_near_expiry(
                &cache,
                "shutdown.test",
                Duration::from_secs(2),
                testnet_addr(11),
            );

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let handle = cache.start_background_refresh_with_shutdown(Some(shutdown_rx));
            started.notified().await;
            assert_eq!(cache.refreshing.len(), 1);
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);

            shutdown_tx.send(true).expect("shutdown watch");
            handle
                .await
                .expect("shutdown must complete the refresh task");
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn stale_proactive_result_cannot_overwrite_or_resurrect_generation() {
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let entered = Arc::new(Notify::new());
            let released = Arc::new(Notify::new());
            let stale_addr = testnet_addr(99);
            let mut cache = near_expiry_cache(1, 10_000);
            install_gated_refresh_hook(
                &mut cache,
                gate.clone(),
                stale_addr,
                entered.clone(),
                released,
            );
            let cache = cache;

            let original = testnet_addr(1);
            seed_near_expiry(&cache, "gen.test", Duration::from_secs(2), original);
            let overwrite = testnet_addr(2);

            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_proactive_refresh_cycle().await }
            });
            entered.notified().await;

            seed_success_entry(
                &cache,
                "gen.test",
                vec![overwrite],
                Instant::now(),
                Duration::from_secs(100),
                None,
            );
            gate.add_permits(1);
            handle.await.expect("cycle");
            assert_eq!(
                success_addresses(&cache, "gen.test"),
                Some(vec![overwrite]),
                "a stale proactive result must not overwrite a newer generation"
            );

            let gate2 = Arc::new(tokio::sync::Semaphore::new(0));
            let entered2 = Arc::new(Notify::new());
            let released2 = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(1, 10_000);
            install_gated_refresh_hook(
                &mut cache,
                gate2.clone(),
                stale_addr,
                entered2.clone(),
                released2,
            );
            let cache = cache;
            seed_near_expiry(&cache, "gone.test", Duration::from_secs(2), original);
            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_proactive_refresh_cycle().await }
            });
            entered2.notified().await;
            cache.cache.remove(dns_hostname_key("gone.test").as_ref());
            gate2.add_permits(1);
            handle.await.expect("cycle");
            assert!(
                !cache.is_cached("gone.test"),
                "a stale proactive result must not resurrect an evicted hostname"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn stale_swr_result_cannot_overwrite_or_resurrect_generation() {
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let entered = Arc::new(Notify::new());
            let released = Arc::new(Notify::new());
            let stale_addr = testnet_addr(99);
            let mut cache = near_expiry_cache(1, 10_000);
            install_gated_refresh_hook(
                &mut cache,
                gate.clone(),
                stale_addr,
                entered.clone(),
                released.clone(),
            );
            let cache = cache;

            let original = testnet_addr(1);
            seed_stale_swr(&cache, "swr-gen.test", original);
            let overwrite = testnet_addr(2);

            let served = cache
                .resolve("swr-gen.test", None, Some(5))
                .await
                .expect("SWR must serve the stale row");
            assert_eq!(served, original);
            entered.notified().await;
            assert_eq!(cache.refreshing.len(), 1);

            seed_success_entry(
                &cache,
                "swr-gen.test",
                vec![overwrite],
                Instant::now(),
                Duration::from_secs(100),
                Some(5),
            );
            gate.add_permits(1);
            released.notified().await;
            wait_until_refresh_idle(&cache).await;
            assert_eq!(
                success_addresses(&cache, "swr-gen.test"),
                Some(vec![overwrite]),
                "a stale SWR result must not overwrite a newer generation"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 1);

            let gate2 = Arc::new(tokio::sync::Semaphore::new(0));
            let entered2 = Arc::new(Notify::new());
            let released2 = Arc::new(Notify::new());
            let mut cache = near_expiry_cache(1, 10_000);
            install_gated_refresh_hook(
                &mut cache,
                gate2.clone(),
                stale_addr,
                entered2.clone(),
                released2.clone(),
            );
            let cache = cache;
            seed_stale_swr(&cache, "swr-gone.test", original);
            cache
                .resolve("swr-gone.test", None, Some(5))
                .await
                .expect("SWR must serve the stale row");
            entered2.notified().await;
            cache
                .cache
                .remove(dns_hostname_key("swr-gone.test").as_ref());
            gate2.add_permits(1);
            released2.notified().await;
            wait_until_refresh_idle(&cache).await;
            assert!(
                !cache.is_cached("swr-gone.test"),
                "a stale SWR result must not resurrect an evicted hostname"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_skips_dead_generation_before_resolve() {
            let first_entered = Arc::new(Notify::new());
            let second_queries = Arc::new(AtomicUsize::new(0));
            let mut cache = near_expiry_cache(1, 10_000);
            let first_entered_hook = first_entered.clone();
            let second_queries_hook = second_queries.clone();
            let refreshed_addr = testnet_addr(50);
            cache.refresh_resolve_hook = Some(Arc::new(move |hostname: String| {
                let first_entered_hook = first_entered_hook.clone();
                let second_queries_hook = second_queries_hook.clone();
                Box::pin(async move {
                    if hostname == "first.test" {
                        first_entered_hook.notify_one();
                        std::future::pending::<BackgroundTestResolve>().await
                    } else {
                        second_queries_hook.fetch_add(1, Ordering::SeqCst);
                        Ok((
                            vec![refreshed_addr],
                            Some(CachedRecordType::A),
                            Duration::from_secs(30),
                        ))
                    }
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
            let cache = cache;

            let first_addr = testnet_addr(1);
            let second_addr = testnet_addr(2);
            let overwrite = testnet_addr(3);
            seed_near_expiry(&cache, "first.test", Duration::from_secs(1), first_addr);
            seed_near_expiry(&cache, "second.test", Duration::from_secs(3), second_addr);

            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_proactive_refresh_cycle().await }
            });
            first_entered.notified().await;

            seed_success_entry(
                &cache,
                "second.test",
                vec![overwrite],
                Instant::now(),
                Duration::from_secs(100),
                None,
            );

            tokio::time::advance(
                DnsCache::BACKGROUND_REFRESH_RESOLVE_TIMEOUT + Duration::from_millis(1),
            )
            .await;
            handle.await.expect("cycle must return after timeout");

            assert_eq!(
                second_queries.load(Ordering::SeqCst),
                0,
                "a candidate whose generation died after selection must not issue an upstream query"
            );
            assert_eq!(
                success_addresses(&cache, "second.test"),
                Some(vec![overwrite]),
                "the republished generation must be left untouched"
            );
            assert_eq!(cache.refreshing.len(), 0);
            assert_eq!(cache.refresh_semaphore.available_permits(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_skips_when_hostname_already_in_progress() {
            let queries = Arc::new(AtomicUsize::new(0));
            let mut cache = near_expiry_cache(1, 10_000);
            install_immediate_refresh_hook(&mut cache, testnet_addr(9), queries.clone());
            let cache = cache;

            let original = testnet_addr(1);
            seed_near_expiry(&cache, "busy.test", Duration::from_secs(2), original);
            let _guard = match cache.try_begin_refresh("busy.test".to_string()) {
                RefreshStart::Started(guard) => guard,
                RefreshStart::AlreadyInProgress => {
                    panic!("test setup must claim a free hostname")
                }
                RefreshStart::ConcurrencyLimited => {
                    panic!("test setup must have a free permit")
                }
            };

            cache.run_proactive_refresh_cycle().await;
            assert_eq!(
                queries.load(Ordering::SeqCst),
                0,
                "AlreadyInProgress must skip the upstream query"
            );
            assert_eq!(
                success_addresses(&cache, "busy.test"),
                Some(vec![original]),
                "a skipped proactive start must not rewrite the success row"
            );
            assert_eq!(cache.refreshing.len(), 1);
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_skips_when_swr_saturates_the_refresh_pool() {
            let started = Arc::new(Notify::new());
            let swr_queries = Arc::new(AtomicUsize::new(0));
            let proactive_queries = Arc::new(AtomicUsize::new(0));
            let mut cache = near_expiry_cache(1, 10_000);
            let started_hook = started.clone();
            let swr_queries_hook = swr_queries.clone();
            let proactive_queries_hook = proactive_queries.clone();
            let fallback_addr = testnet_addr(9);
            cache.refresh_resolve_hook = Some(Arc::new(move |hostname: String| {
                let started_hook = started_hook.clone();
                let swr_queries_hook = swr_queries_hook.clone();
                let proactive_queries_hook = proactive_queries_hook.clone();
                Box::pin(async move {
                    if hostname == "swr-busy.test" {
                        swr_queries_hook.fetch_add(1, Ordering::SeqCst);
                        started_hook.notify_one();
                        std::future::pending::<BackgroundTestResolve>().await
                    } else {
                        proactive_queries_hook.fetch_add(1, Ordering::SeqCst);
                        Ok((
                            vec![fallback_addr],
                            Some(CachedRecordType::A),
                            Duration::from_secs(30),
                        ))
                    }
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
            let cache = cache;

            let swr_addr = testnet_addr(1);
            let proactive_addr = testnet_addr(2);
            seed_stale_swr(&cache, "swr-busy.test", swr_addr);
            seed_near_expiry(
                &cache,
                "proactive.test",
                Duration::from_secs(2),
                proactive_addr,
            );

            let served = cache
                .resolve("swr-busy.test", None, Some(5))
                .await
                .expect("SWR must serve the stale row");
            assert_eq!(served, swr_addr);
            started.notified().await;
            assert_eq!(cache.refresh_semaphore.available_permits(), 0);

            cache.run_proactive_refresh_cycle().await;
            assert_eq!(swr_queries.load(Ordering::SeqCst), 1);
            assert_eq!(
                proactive_queries.load(Ordering::SeqCst),
                0,
                "a saturated SWR pool must not let the proactive cycle issue another query"
            );
            assert_eq!(
                success_addresses(&cache, "proactive.test"),
                Some(vec![proactive_addr])
            );
            assert_eq!(cache.refreshing.len(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn proactive_picks_up_hostname_skipped_by_per_cycle_cap() {
            let queries = Arc::new(AtomicUsize::new(0));
            let refreshed = testnet_addr(9);
            let mut cache = near_expiry_cache(1, 10_000);
            install_immediate_refresh_hook(&mut cache, refreshed, queries.clone());
            let cache = cache;

            let soonest_addr = testnet_addr(1);
            let later_addr = testnet_addr(2);
            seed_near_expiry(&cache, "soonest.test", Duration::from_secs(1), soonest_addr);
            seed_near_expiry(&cache, "later.test", Duration::from_secs(3), later_addr);

            cache.run_proactive_refresh_cycle().await;
            assert_eq!(queries.load(Ordering::SeqCst), 1);
            assert_eq!(
                success_addresses(&cache, "soonest.test"),
                Some(vec![refreshed]),
                "the soonest-expiry hostname must be refreshed in the first cycle"
            );
            assert_eq!(
                success_addresses(&cache, "later.test"),
                Some(vec![later_addr]),
                "the per-cycle cap must leave the later hostname for a subsequent cycle"
            );

            cache.run_proactive_refresh_cycle().await;
            assert_eq!(queries.load(Ordering::SeqCst), 2);
            assert_eq!(
                success_addresses(&cache, "later.test"),
                Some(vec![refreshed]),
                "a hostname skipped by the per-cycle cap must be picked up later"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn slow_proactive_cycle_does_not_burst_catch_up_ticks() {
            let first = Arc::new(Notify::new());
            let invocations = Arc::new(AtomicUsize::new(0));
            let mut cache = near_expiry_cache(1, 10_000);
            let first_hook = first.clone();
            let invocations_hook = invocations.clone();
            cache.refresh_resolve_hook = Some(Arc::new(move |_hostname: String| {
                let n = invocations_hook.fetch_add(1, Ordering::SeqCst) + 1;
                let first_hook = first_hook.clone();
                Box::pin(async move {
                    if n == 1 {
                        first_hook.notify_one();
                    }
                    std::future::pending::<BackgroundTestResolve>().await
                }) as Pin<Box<dyn Future<Output = BackgroundResolveOutput> + Send>>
            }));
            let cache = cache;
            seed_near_expiry(
                &cache,
                "delay.test",
                Duration::from_secs(2),
                testnet_addr(1),
            );

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let handle = cache.start_background_refresh_with_shutdown(Some(shutdown_rx));
            first.notified().await;
            assert_eq!(invocations.load(Ordering::SeqCst), 1);

            tokio::time::advance(
                DnsCache::BACKGROUND_REFRESH_RESOLVE_TIMEOUT + Duration::from_millis(1),
            )
            .await;
            assert_eq!(
                invocations.load(Ordering::SeqCst),
                1,
                "Delay must not Burst catch-up ticks after a slow cycle"
            );

            shutdown_tx.send(true).expect("shutdown watch");
            handle
                .await
                .expect("shutdown must complete the refresh task");
        }

        /// Issue #7204: a hung failed-retry lookup is bounded by the same
        /// wall-clock timeout as SWR/proactive refresh and counts as a failed
        /// retry, so the cycle returns and error backoff advances.
        #[tokio::test(start_paused = true)]
        async fn failed_retry_timeout_advances_backoff_and_returns() {
            let started = Arc::new(Notify::new());
            let mut cache = DnsCache::new(DnsConfig {
                error_ttl_seconds: 5,
                stale_ttl_seconds: 3600,
                max_concurrent_refreshes: 2,
                failed_retry_interval_seconds: 10,
                ..DnsConfig::default()
            });
            install_hanging_refresh_hook(
                &mut cache,
                Arc::new(AtomicUsize::new(0)),
                Arc::new(AtomicUsize::new(0)),
                started.clone(),
                1,
            );
            let cache = cache;
            insert_error_entry(&cache, "hung.test", -1, 0, Duration::from_secs(1));

            let handle = tokio::spawn({
                let cache = cache.clone();
                async move { cache.run_failed_retry_cycle().await }
            });
            started.notified().await;

            tokio::time::advance(
                DnsCache::BACKGROUND_REFRESH_RESOLVE_TIMEOUT + Duration::from_millis(1),
            )
            .await;
            handle
                .await
                .expect("failed-retry cycle must return after the timeout");

            let entry = cache.cache.get("hung.test").expect("error entry kept");
            assert!(entry.is_error, "a timed-out retry must stay an error row");
            assert_eq!(
                entry.consecutive_failures, 1,
                "a timed-out retry must advance error backoff"
            );
        }
    }
}

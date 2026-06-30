//! DNS resolution cache with TTL, stale-while-revalidate, and background refresh.
//!
//! All gateway components (connection pool, health probes, service discovery,
//! plugin HTTP clients) share a single `DnsCache` instance so that:
//! - DNS lookups are off the hot request path (pre-warmed at startup)
//! - TTL-based expiration prevents stale entries from persisting
//! - Stale-while-revalidate serves the old IP while refreshing in the background
//! - Background refresh keeps entries warm without per-request DNS queries
//!
//! The cache also provides `DnsCacheResolver` — a `reqwest::dns::Resolve`
//! implementation that plugs into every `reqwest::Client` so all HTTP clients
//! automatically use the shared cache.

use dashmap::DashMap;
use futures_util::stream::{self, StreamExt};
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
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
    /// How long stale data can be served while a background refresh is in progress.
    pub stale_ttl_seconds: u64,
    /// TTL (seconds) for caching DNS errors and empty responses.
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
    /// tasks system-wide. Prevents unbounded task spawning when many distinct
    /// hostnames go stale simultaneously. Default: 64.
    pub max_concurrent_refreshes: usize,
    /// Backend egress policy for SSRF protection. Applied to every freshly
    /// resolved address before it is cached, on every insertion path (initial
    /// resolve, stale refresh, background refresh, failed-retry recovery) — so
    /// a hostname that re-resolves to a now-denied address (DNS rebinding) is
    /// rejected rather than served from cache.
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

fn dns_name_without_trailing_root(name: impl std::fmt::Display) -> String {
    let mut name = name.to_string();
    let len_without_root = name.trim_end_matches('.').len();
    name.truncate(len_without_root);
    name
}

/// A cached DNS entry with TTL and stale-while-revalidate support.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
    /// Deadline after which stale data is no longer served.
    stale_deadline: Instant,
    /// The total TTL duration that was applied when this entry was inserted.
    /// Stored so background refresh can compute per-entry refresh thresholds
    /// (since each record may have a different native TTL).
    applied_ttl: Duration,
    /// The record type that produced this result (for CACHE ordering).
    record_type_used: Option<CachedRecordType>,
    /// Whether this is a cached error/empty response.
    is_error: bool,
    /// The originating per-proxy `dns_cache_ttl_seconds` (if any) that produced
    /// this entry. Stored so proactive background refresh and failed-retry
    /// re-resolution can re-thread it through `effective_ttl`, preserving the
    /// per-proxy TTL preference across refreshes instead of silently falling
    /// back to the global override or the native record TTL.
    ///
    /// Note: when two proxies resolve the same hostname with different
    /// `dns_cache_ttl_seconds`, only one TTL wins (whichever request populated
    /// the entry first). See `warmup` deduplication notes.
    original_per_proxy_ttl: Option<u64>,
}

/// Asynchronous DNS resolver with in-memory caching, stale-while-revalidate,
/// error caching, configurable record type ordering, and hickory-resolver backend.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<DashMap<String, DnsCacheEntry>>,
    global_overrides: HashMap<String, String>,
    resolver: Arc<Resolver<TokioRuntimeProvider>>,
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
}

impl DnsCache {
    /// Upper bound for every TTL-derived `Duration` (override, min, stale,
    /// error, and the effective record TTL). Matches the per-proxy
    /// `dns_cache_ttl` ceiling (1 day) so unbounded `FERRUM_DNS_*` env-var
    /// seconds cannot overflow the `Instant + Duration` / `Duration * u32`
    /// arithmetic on the resolution hot path (a reachable panic).
    const MAX_TTL: Duration = Duration::from_secs(86_400);

    /// Expose the configured backend egress policy for non-DNS backend target
    /// validation paths (for example, service discovery).
    pub fn backend_allow_ips(&self) -> crate::config::BackendEgressPolicy {
        self.backend_allow_ips.clone()
    }

    pub fn new(config: DnsConfig) -> Self {
        let resolver_label: Arc<str> = match &config.resolver_addresses {
            Some(addrs) => Arc::from(addrs.as_str()),
            None => Arc::from("system"),
        };

        let resolver = build_resolver(&config);

        let dns_order = parse_dns_order(config.dns_order.as_deref());

        let shards = crate::util::sharding::pool_shard_amount(config.shard_amount);
        let global_overrides = normalize_global_overrides(config.global_overrides);

        Self {
            cache: Arc::new(DashMap::with_shard_amount(shards)),
            global_overrides,
            resolver: Arc::new(resolver),
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
        }
    }

    /// Resolve a hostname to an IP address, using cache, overrides, or actual DNS.
    ///
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

    fn check_backend_addresses_policy(
        &self,
        addresses: &[IpAddr],
        hostname: &str,
    ) -> Result<(), anyhow::Error> {
        for &addr in addresses {
            self.check_backend_ip_policy(addr, hostname)?;
        }
        Ok(())
    }

    fn cache_success_entry(
        &self,
        hostname: &str,
        addresses: Vec<IpAddr>,
        record_type: Option<CachedRecordType>,
        ttl: Duration,
        original_per_proxy_ttl: Option<u64>,
    ) -> Result<Vec<IpAddr>, anyhow::Error> {
        // This is the single success insertion path for foreground resolves,
        // stale refreshes, proactive background refreshes, and failed-retry
        // recovery. Cache reads intentionally trust entries accepted here.
        //
        // Clamp the effective TTL so an unbounded override / record TTL cannot
        // overflow the `Instant + Duration` arithmetic below (or the
        // `Duration * u32` threshold in the proactive refresh loop).
        let ttl = ttl.min(Self::MAX_TTL);
        self.check_backend_addresses_policy(&addresses, hostname)?;
        let cache_key = dns_hostname_key(hostname);

        self.cache.insert(
            cache_key.into_owned(),
            DnsCacheEntry {
                addresses: addresses.clone(),
                expires_at: Instant::now() + ttl,
                stale_deadline: Instant::now() + ttl + self.stale_ttl,
                applied_ttl: ttl,
                record_type_used: record_type,
                is_error: false,
                original_per_proxy_ttl,
            },
        );

        Ok(addresses)
    }

    /// Resolution priority:
    /// 1. Per-proxy static override (highest priority)
    /// 2. Global static overrides
    /// 3. Cache (fresh → return immediately; stale → return + background refresh)
    /// 4. Actual DNS resolution via hickory-resolver
    pub async fn resolve(
        &self,
        hostname: &str,
        per_proxy_override: Option<&str>,
        per_proxy_ttl: Option<u64>,
    ) -> Result<IpAddr, anyhow::Error> {
        let cache_key = dns_hostname_key(hostname);
        let cache_hostname = cache_key.as_ref();

        // 1. Check per-proxy static override first
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return self.check_backend_ip_policy(addr, hostname);
        }

        // 2. Check global overrides
        if let Some(ip_str) = self.global_overrides.get(cache_hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return self.check_backend_ip_policy(addr, hostname);
        }

        // 3. Check cache with stale-while-revalidate
        let mut prior_per_proxy_ttl = None;
        if let Some(entry) = self.cache.get(cache_hostname) {
            let now = Instant::now();
            prior_per_proxy_ttl = entry.original_per_proxy_ttl;

            // Fresh entry — return immediately
            if entry.expires_at > now && !entry.addresses.is_empty() && !entry.is_error {
                crate::runtime_metrics::global_ref().record_dns_hit();
                return Ok(entry.addresses[0]);
            }

            // Stale but within stale window — return stale data, trigger background refresh
            if entry.stale_deadline > now && !entry.addresses.is_empty() && !entry.is_error {
                let host = cache_hostname.to_string();
                // Deduplicate: only spawn a refresh if one isn't already in progress
                if self.refreshing.insert(host.clone(), ()).is_none() {
                    // Try to acquire a semaphore permit to bound concurrent refreshes.
                    // If all permits are taken, skip the refresh — the entry stays
                    // stale and the next request will retry the semaphore.
                    match self.refresh_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let cache = self.clone();
                            let ttl = per_proxy_ttl.or(prior_per_proxy_ttl);
                            tokio::spawn(async move {
                                if let Err(e) = cache.refresh_entry(&host, ttl).await {
                                    warn!("DNS stale refresh failed for {}: {}", host, e);
                                }
                                cache.refreshing.remove(&host);
                                drop(permit);
                            });
                            debug!(
                                "DNS serving stale entry for {} (background refresh triggered)",
                                hostname
                            );
                        }
                        Err(_) => {
                            // Concurrency limit reached — remove the dedup entry
                            // so a future request can retry when a permit frees up.
                            self.refreshing.remove(&host);
                            debug!(
                                "DNS serving stale entry for {} (refresh skipped, concurrency limit reached)",
                                hostname
                            );
                        }
                    }
                } else {
                    debug!(
                        "DNS serving stale entry for {} (refresh already in progress)",
                        hostname
                    );
                }
                crate::runtime_metrics::global_ref().record_dns_stale();
                return Ok(entry.addresses[0]);
            }

            // Cached error that hasn't expired — return error immediately
            if entry.is_error && entry.expires_at > now {
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution failed for {} (cached error)", hostname);
            }
        }

        let per_proxy_ttl = per_proxy_ttl.or(prior_per_proxy_ttl);

        // 4. Perform actual DNS resolution
        match self.timed_resolve(cache_hostname).await {
            Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                let ttl = self.effective_ttl(native_ttl, per_proxy_ttl);
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    addrs,
                    record_type,
                    ttl,
                    per_proxy_ttl,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };

                debug!(
                    "DNS resolved {} -> {:?} (native_ttl={:?}, effective_ttl={:?})",
                    hostname, addrs[0], native_ttl, ttl
                );
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs[0])
            }
            Ok(_) | Err(_) if cache_hostname == "localhost" => {
                // Fallback for localhost — hickory-resolver may not read
                // /etc/hosts, so DNS lookup can fail.  Respect dns_order:
                // if AAAA appears before A, prefer IPv6 loopback.
                let addr = self.localhost_addr();
                let ttl = self.effective_ttl(Duration::from_secs(3600), per_proxy_ttl);
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    vec![addr],
                    None,
                    ttl,
                    per_proxy_ttl,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };
                debug!("DNS resolved localhost -> {} (built-in fallback)", addr);
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs[0])
            }
            Ok(_) => {
                self.cache_error(cache_hostname, per_proxy_ttl);
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
            }
            Err(e) => {
                self.cache_error(cache_hostname, per_proxy_ttl);
                crate::runtime_metrics::global_ref().record_dns_error();
                Err(e)
            }
        }
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
        let cache_key = dns_hostname_key(hostname);
        let cache_hostname = cache_key.as_ref();

        // 1. Per-proxy static override
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
        }

        // 2. Global overrides
        if let Some(ip_str) = self.global_overrides.get(cache_hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(vec![self.check_backend_ip_policy(addr, hostname)?]);
        }

        // 3. Cache with stale-while-revalidate
        let mut prior_per_proxy_ttl = None;
        if let Some(entry) = self.cache.get(cache_hostname) {
            let now = Instant::now();
            prior_per_proxy_ttl = entry.original_per_proxy_ttl;

            if entry.expires_at > now && !entry.addresses.is_empty() && !entry.is_error {
                crate::runtime_metrics::global_ref().record_dns_hit();
                return Ok(entry.addresses.clone());
            }

            if entry.stale_deadline > now && !entry.addresses.is_empty() && !entry.is_error {
                let host = cache_hostname.to_string();
                if self.refreshing.insert(host.clone(), ()).is_none() {
                    match self.refresh_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => {
                            let cache = self.clone();
                            let ttl = per_proxy_ttl.or(prior_per_proxy_ttl);
                            tokio::spawn(async move {
                                if let Err(e) = cache.refresh_entry(&host, ttl).await {
                                    warn!("DNS stale refresh failed for {}: {}", host, e);
                                }
                                cache.refreshing.remove(&host);
                                drop(permit);
                            });
                        }
                        Err(_) => {
                            self.refreshing.remove(&host);
                        }
                    }
                }
                crate::runtime_metrics::global_ref().record_dns_stale();
                return Ok(entry.addresses.clone());
            }

            if entry.is_error && entry.expires_at > now {
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution failed for {} (cached error)", hostname);
            }
        }

        let per_proxy_ttl = per_proxy_ttl.or(prior_per_proxy_ttl);

        // 4. Actual DNS resolution
        match self.timed_resolve(cache_hostname).await {
            Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                let ttl = self.effective_ttl(native_ttl, per_proxy_ttl);
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    addrs,
                    record_type,
                    ttl,
                    per_proxy_ttl,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs)
            }
            Ok(_) | Err(_) if cache_hostname == "localhost" => {
                let addr = self.localhost_addr();
                let ttl = self.effective_ttl(Duration::from_secs(3600), per_proxy_ttl);
                let addrs = match self.cache_success_entry(
                    cache_hostname,
                    vec![addr],
                    None,
                    ttl,
                    per_proxy_ttl,
                ) {
                    Ok(addrs) => addrs,
                    Err(err) => {
                        crate::runtime_metrics::global_ref().record_dns_error();
                        return Err(err);
                    }
                };
                crate::runtime_metrics::global_ref().record_dns_miss();
                Ok(addrs)
            }
            Ok(_) => {
                self.cache_error(cache_hostname, per_proxy_ttl);
                crate::runtime_metrics::global_ref().record_dns_error();
                anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
            }
            Err(e) => {
                self.cache_error(cache_hostname, per_proxy_ttl);
                crate::runtime_metrics::global_ref().record_dns_error();
                Err(e)
            }
        }
    }

    /// Refresh a single cache entry in the background.
    async fn refresh_entry(
        &self,
        hostname: &str,
        per_proxy_ttl: Option<u64>,
    ) -> Result<(), anyhow::Error> {
        let (addrs, record_type, native_ttl) = self.timed_resolve(hostname).await?;
        if addrs.is_empty() {
            anyhow::bail!("DNS refresh returned no addresses for {}", hostname);
        }

        let ttl = self.effective_ttl(native_ttl, per_proxy_ttl);
        self.cache_success_entry(hostname, addrs, record_type, ttl, per_proxy_ttl)?;

        debug!(
            "DNS background refresh: {} refreshed (ttl={:?})",
            hostname, ttl
        );
        Ok(())
    }

    /// Cache a DNS error to prevent hammering DNS for known-bad hostnames.
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

    fn cache_error(&self, hostname: &str, per_proxy_ttl: Option<u64>) {
        let cache_key = dns_hostname_key(hostname);
        let cache_hostname = cache_key.as_ref();

        // Preserve any prior per-proxy TTL recorded for this hostname so that
        // when the failed-retry task promotes the entry back to success, it can
        // re-thread the original per-proxy TTL through `effective_ttl` rather
        // than silently falling back to the global override or native TTL.
        let prior_ttl = self
            .cache
            .get(cache_hostname)
            .and_then(|entry| entry.original_per_proxy_ttl);
        self.cache.insert(
            cache_hostname.to_string(),
            DnsCacheEntry {
                addresses: vec![],
                expires_at: Instant::now() + self.error_ttl,
                stale_deadline: Instant::now() + self.error_ttl, // no stale serving for errors
                applied_ttl: self.error_ttl,
                record_type_used: None,
                is_error: true,
                original_per_proxy_ttl: per_proxy_ttl.or(prior_ttl),
            },
        );
        debug!(
            "DNS cached error for {} (ttl={:?})",
            hostname, self.error_ttl
        );
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
        // Try parsing as IP first — bypass DNS entirely
        if let Ok(addr) = hostname.parse::<IpAddr>() {
            // Literal IPs get max TTL — they never change
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
                            // SRV records point to target hostnames -- resolve them to IPs
                            for record in srv_lookup.answers() {
                                let RData::SRV(ref srv) = record.data else {
                                    continue;
                                };
                                let target = dns_name_without_trailing_root(&srv.target);
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

    /// Check if a cached entry exists and is a cached error.
    #[allow(dead_code)]
    pub fn is_cached_error(&self, hostname: &str) -> bool {
        let cache_key = dns_hostname_key(hostname);
        self.cache
            .get(cache_key.as_ref())
            .map(|e| e.is_error && e.expires_at > Instant::now())
            .unwrap_or(false)
    }

    /// Resolve a DNS SRV record to a list of (hostname, port, weight) tuples.
    ///
    /// Used by DNS-SD service discovery. Does not use the cache — callers
    /// manage their own polling intervals. Reuses the configured resolver
    /// so custom nameservers from `FERRUM_DNS_RESOLVER_ADDRESS` are respected.
    pub async fn resolve_srv(
        &self,
        service_name: &str,
    ) -> Result<Vec<(String, u16, u16)>, anyhow::Error> {
        let srv_lookup = self
            .resolver
            .srv_lookup(service_name)
            .await
            .map_err(|e| anyhow::anyhow!("SRV lookup failed for {}: {}", service_name, e))?;

        let mut results = Vec::new();
        for record in srv_lookup.answers() {
            let RData::SRV(ref srv) = record.data else {
                continue;
            };
            results.push((
                dns_name_without_trailing_root(&srv.target),
                srv.port,
                srv.weight,
            ));
        }

        Ok(results)
    }

    /// Evict expired entries and enforce max cache size.
    /// Removes entries past their stale deadline first, then evicts oldest
    /// entries (by expiration time) if still over capacity.
    ///
    /// Error entries are preserved even past their stale deadline so that the
    /// failed retry task can find and re-attempt them. The retry task manages
    /// error entry lifecycle (re-caching on failure, promoting on success).
    /// Error entries are only evicted in Phase 2 if the cache exceeds max size.
    pub fn evict_expired(&self) {
        let now = Instant::now();

        // Phase 1: Remove non-error entries past their stale deadline.
        // Error entries are kept alive for the failed retry task — it manages
        // their lifecycle (re-caching on failure, promoting on success).
        // When the retry task is disabled (failed_retry_interval == ZERO),
        // error entries are evicted normally to prevent unbounded accumulation.
        let retry_enabled = self.failed_retry_interval > Duration::ZERO;
        self.cache
            .retain(|_, entry| (entry.is_error && retry_enabled) || entry.stale_deadline > now);

        // Phase 2: If still over capacity, evict oldest entries by expires_at
        if self.cache.len() > self.max_cache_size {
            let target_size = self.max_cache_size * 3 / 4; // Evict to 75% capacity
            let mut entries: Vec<(String, Instant)> = self
                .cache
                .iter()
                .map(|e| (e.key().clone(), e.expires_at))
                .collect();
            // Sort by expires_at ascending (oldest first)
            entries.sort_by_key(|(_, expires)| *expires);

            let to_remove = self.cache.len().saturating_sub(target_size);
            for (hostname, _) in entries.into_iter().take(to_remove) {
                self.cache.remove(&hostname);
            }

            debug!(
                "DNS cache eviction: trimmed to {} entries (max: {})",
                self.cache.len(),
                self.max_cache_size
            );
        }
    }

    /// Start a background task that proactively refreshes cache entries before
    /// they expire. Entries are refreshed when the configured percentage of their
    /// TTL has elapsed (default 90%), keeping DNS resolution off the hot request path.
    #[allow(dead_code)]
    pub fn start_background_refresh(&self) -> tokio::task::JoinHandle<()> {
        self.start_background_refresh_with_shutdown(None)
    }

    /// Start background refresh with an optional shutdown signal.
    ///
    /// When `shutdown_rx` is provided, the task will exit cleanly when the
    /// shutdown signal is received. Without it, the task runs until aborted.
    ///
    /// Returns the task handle so callers can await graceful completion.
    pub fn start_background_refresh_with_shutdown(
        &self,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let cache = self.clone();
        // Check interval: scan frequently enough to catch the shortest-lived entries.
        // With native TTL respect, entries may have wildly different TTLs (e.g., 30s vs 3600s).
        // We use a fixed 5s scan interval to handle short-TTL records promptly.
        let check_interval = 5u64;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(check_interval));

            loop {
                if let Some(ref rx) = shutdown_rx {
                    tokio::select! {
                        _ = interval.tick() => {}
                        _ = wait_for_shutdown(rx.clone()) => {
                            info!("DNS background refresh shutting down");
                            return;
                        }
                    }
                } else {
                    interval.tick().await;
                }

                // Evict expired entries and enforce max cache size
                cache.evict_expired();

                // Collect entries nearing expiration (past the configured refresh threshold).
                // Each entry uses its own applied_ttl for threshold computation since
                // native DNS TTLs vary per record. Capture each entry's
                // originating per-proxy TTL so the refresh re-threads it through
                // `effective_ttl` (otherwise refreshes silently downgrade to the
                // global override or native TTL).
                let now = Instant::now();
                let mut to_refresh: Vec<(String, Option<u64>)> = Vec::new();
                let refresh_remaining_pct = (100 - cache.refresh_threshold_percent as u32).max(1);

                for entry in cache.cache.iter() {
                    // Skip error entries — those are handled by the failed retry task
                    if entry.is_error {
                        continue;
                    }

                    let remaining = entry.expires_at.saturating_duration_since(now);
                    // Use this entry's own applied_ttl for threshold computation
                    let threshold = entry.applied_ttl * refresh_remaining_pct / 100;
                    if remaining < threshold && remaining > Duration::ZERO {
                        to_refresh.push((entry.key().clone(), entry.original_per_proxy_ttl));
                    }
                }

                // Refresh entries in the background
                for (hostname, per_proxy_ttl) in to_refresh {
                    match cache.timed_resolve(&hostname).await {
                        Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                            let refresh_ttl = cache.effective_ttl(native_ttl, per_proxy_ttl);
                            match cache.cache_success_entry(
                                &hostname,
                                addrs,
                                record_type,
                                refresh_ttl,
                                per_proxy_ttl,
                            ) {
                                Ok(_) => {
                                    debug!(
                                        "DNS background refresh: {} refreshed (ttl={:?})",
                                        hostname, refresh_ttl
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
                            warn!("DNS background refresh: {} returned no addresses", hostname);
                        }
                        Err(e) => {
                            warn!("DNS background refresh failed for {}: {}", hostname, e);
                        }
                    }
                }
            }
        })
    }

    /// Start a background task that periodically retries resolution for failed
    /// DNS entries. Failed lookups are cached with a short error TTL, but this
    /// task proactively re-attempts resolution so that transient DNS outages
    /// are recovered from without waiting for a request to trigger re-resolution.
    ///
    /// Logs at `warn` level for each retry attempt and result.
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

                // Collect all error entries whose error TTL has expired
                // (they're eligible for retry). Capture each entry's
                // originating per-proxy TTL so re-resolution re-threads it
                // through `effective_ttl` (otherwise a successful retry would
                // silently drop the per-proxy TTL preference recorded when the
                // original lookup failed).
                let now = Instant::now();
                let mut to_retry: Vec<(String, Option<u64>)> = Vec::new();

                for entry in cache.cache.iter() {
                    if entry.is_error && entry.expires_at <= now {
                        to_retry.push((entry.key().clone(), entry.original_per_proxy_ttl));
                    }
                }

                if to_retry.is_empty() {
                    continue;
                }

                debug!(
                    "DNS failed retry: attempting re-resolution for {} hostname(s)",
                    to_retry.len()
                );

                for (hostname, per_proxy_ttl) in to_retry {
                    warn!(
                        "DNS failed retry: re-attempting resolution for '{}'",
                        hostname
                    );

                    match cache.timed_resolve(&hostname).await {
                        Ok((addrs, record_type, native_ttl)) if !addrs.is_empty() => {
                            let ttl = cache.effective_ttl(native_ttl, per_proxy_ttl);
                            match cache.cache_success_entry(
                                &hostname,
                                addrs,
                                record_type,
                                ttl,
                                per_proxy_ttl,
                            ) {
                                Ok(addrs) => {
                                    warn!(
                                        "DNS failed retry: '{}' resolved successfully -> {:?} (ttl={:?})",
                                        hostname, addrs[0], ttl
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "DNS failed retry: '{}' resolved but denied by IP policy: {}",
                                        hostname, e
                                    );
                                }
                            }
                        }
                        Ok(_) => {
                            // Re-cache the error with fresh error TTL
                            cache.cache_error(&hostname, per_proxy_ttl);
                            warn!(
                                "DNS failed retry: '{}' still returning no addresses",
                                hostname
                            );
                        }
                        Err(e) => {
                            // Re-cache the error with fresh error TTL
                            cache.cache_error(&hostname, per_proxy_ttl);
                            warn!("DNS failed retry: '{}' still failing: {}", hostname, e);
                        }
                    }
                }
            }
        }))
    }

    /// Warmup: resolve all hostnames from the config at startup.
    ///
    /// Hostnames are deduplicated before resolution — if multiple proxies or
    /// plugins share the same hostname, only one DNS lookup is performed.
    /// Unique hostnames are resolved concurrently up to the configured limit.
    pub async fn warmup(&self, hostnames: Vec<(String, Option<String>, Option<u64>)>) {
        let total_hostnames = hostnames.len();

        // Deduplicate by hostname, keeping the first override/TTL seen for each.
        let mut seen = HashSet::new();
        let unique: Vec<_> = hostnames
            .into_iter()
            .filter(|(host, _, _)| seen.insert(dns_hostname_key(host).into_owned()))
            .collect();

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
            .for_each_concurrent(self.warmup_concurrency, |(host, override_ip, ttl)| {
                let cache = self.clone();
                async move {
                    match cache.resolve(&host, override_ip.as_deref(), ttl).await {
                        Ok(addr) => debug!("DNS warmup: {} -> {}", host, addr),
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

    // Build the resolver
    let mut builder =
        Resolver::builder_with_config(resolver_config, TokioRuntimeProvider::default());
    *builder.options_mut() = resolver_opts;
    let mut resolver = builder.build().expect("failed to build DNS resolver");

    // Load custom hosts file if specified
    if let Some(ref hosts_path) = config.hosts_file_path {
        match File::open(hosts_path) {
            Ok(file) => {
                let mut hosts = hickory_resolver::Hosts::default();
                let _ = hosts.read_hosts_conf(BufReader::new(file));
                resolver.set_hosts(Arc::new(hosts));
                info!("DNS: loaded custom hosts file from {}", hosts_path);
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
pub struct DnsCacheResolver {
    cache: DnsCache,
}

impl DnsCacheResolver {
    pub fn new(cache: DnsCache) -> Self {
        Self { cache }
    }
}

impl reqwest::dns::Resolve for DnsCacheResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let cache = self.cache.clone();
        let hostname = name.as_str().to_string();

        Box::pin(async move {
            let ip = cache.resolve(&hostname, None, None).await.map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(e.to_string()))
                },
            )?;

            // reqwest expects an iterator of SocketAddr. The port is ignored
            // (reqwest uses the port from the URL), but SocketAddr requires one.
            let addr: SocketAddr = SocketAddr::new(ip, 0);
            let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(addr));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for private internals of the DNS cache. Public-API tests
    //! live in `tests/unit/gateway_core/dns_tests.rs`.
    //!
    //! These tests verify that the originating per-proxy `dns_cache_ttl_seconds`
    //! is preserved across proactive background refresh and failed-retry
    //! re-resolution — two paths that previously called `effective_ttl(_, None)`
    //! and silently downgraded entries to the global TTL override / native TTL.
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
        );

        assert!(result.is_err());
        assert!(
            cache.cache.get("metadata.internal").is_none(),
            "Denied DNS answers must not be inserted for foreground or background refresh paths"
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
        // 127.0.0.1 takes the literal-IP fast path; native TTL = 24h.
        let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();

        let entry = cache.cache.get("127.0.0.1").expect("entry should exist");
        assert_eq!(
            entry.original_per_proxy_ttl,
            Some(600),
            "per-proxy TTL must be stored on the cache entry"
        );
        assert_eq!(
            entry.applied_ttl,
            Duration::from_secs(600),
            "applied_ttl should reflect the per-proxy TTL, not native 24h"
        );
    }

    /// Same contract for `resolve_all`.
    #[tokio::test]
    async fn original_per_proxy_ttl_is_recorded_on_resolve_all() {
        let cache = DnsCache::new(config_with_global_override(None));
        let _ = cache
            .resolve_all("127.0.0.1", None, Some(450))
            .await
            .unwrap();

        let entry = cache.cache.get("127.0.0.1").expect("entry should exist");
        assert_eq!(entry.original_per_proxy_ttl, Some(450));
        assert_eq!(entry.applied_ttl, Duration::from_secs(450));
    }

    /// Regression test for the silent-drop bug: an entry originally inserted
    /// with `dns_cache_ttl_seconds: 600` must NOT be downgraded to the global
    /// TTL override (3600s) or native TTL on proactive background refresh.
    ///
    /// Simulates the proactive refresh code path by inserting a near-expiring
    /// entry tagged with `original_per_proxy_ttl: Some(600)` and re-resolving
    /// via the same `effective_ttl(native_ttl, entry.original_per_proxy_ttl)`
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
                addresses: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                expires_at: Instant::now() + Duration::from_secs(1),
                stale_deadline: Instant::now() + Duration::from_secs(1),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                original_per_proxy_ttl: Some(600),
            },
        );

        // Drive the same code path the background refresh task takes:
        // (1) read the originating per-proxy TTL off the entry,
        // (2) re-resolve, (3) compute effective_ttl with that TTL.
        let captured = cache
            .cache
            .get("127.0.0.1")
            .expect("seeded entry")
            .original_per_proxy_ttl;
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
                addresses: addrs,
                expires_at: Instant::now() + refresh_ttl,
                stale_deadline: Instant::now() + refresh_ttl + cache.stale_ttl,
                applied_ttl: refresh_ttl,
                record_type_used: record_type,
                is_error: false,
                original_per_proxy_ttl: captured,
            },
        );

        let refreshed = cache.cache.get("127.0.0.1").expect("refreshed entry");
        assert_eq!(refreshed.applied_ttl, Duration::from_secs(600));
        assert_eq!(refreshed.original_per_proxy_ttl, Some(600));
    }

    /// End-to-end: spinning up the actual background task on a near-expiring
    /// per-proxy-tagged entry must produce a refreshed entry whose TTL still
    /// reflects the per-proxy preference.
    ///
    /// The background task scans every 5s. The first `interval.tick()` fires
    /// immediately, so we seed an entry with `remaining < threshold` but
    /// `remaining > 0` so it's eligible on the first scan, and use `127.0.0.1`
    /// so `timed_resolve` short-circuits to a literal-IP lookup with a 24h
    /// native TTL — no network required.
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
            "127.0.0.1".to_string(),
            DnsCacheEntry {
                addresses: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                expires_at: Instant::now() + Duration::from_secs(4),
                stale_deadline: Instant::now() + Duration::from_secs(60),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                original_per_proxy_ttl: Some(600),
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
            if let Some(entry) = cache.cache.get("127.0.0.1") {
                let remaining = entry.expires_at.saturating_duration_since(Instant::now());
                // Refresh has happened when remaining is significantly larger
                // than the seeded 4s (i.e., the entry was re-inserted).
                if remaining > Duration::from_secs(60) {
                    observed_applied = entry.applied_ttl;
                    observed_per_proxy = entry.original_per_proxy_ttl;
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

        cache.cache_error("example.invalid", Some(600));

        let err_entry = cache
            .cache
            .get("example.invalid")
            .expect("error entry exists");
        assert!(err_entry.is_error);
        assert_eq!(
            err_entry.original_per_proxy_ttl,
            Some(600),
            "first failed lookup must keep the request's per-proxy TTL"
        );
    }

    /// `cache_error` preserves any prior `original_per_proxy_ttl` so that when
    /// the failed-retry task later promotes the error back to a success, it
    /// can re-thread the original per-proxy TTL through `effective_ttl`.
    #[tokio::test]
    async fn cache_error_preserves_prior_per_proxy_ttl() {
        let cache = DnsCache::new(config_with_global_override(None));

        // Seed a successful entry with a per-proxy TTL.
        cache.cache.insert(
            "example.invalid".to_string(),
            DnsCacheEntry {
                addresses: vec![IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))],
                expires_at: Instant::now() + Duration::from_secs(60),
                stale_deadline: Instant::now() + Duration::from_secs(60),
                applied_ttl: Duration::from_secs(600),
                record_type_used: None,
                is_error: false,
                original_per_proxy_ttl: Some(600),
            },
        );

        // Now cache an error for the same hostname (simulating a transient
        // resolve failure picked up by the on-demand path).
        cache.cache_error("example.invalid", None);

        let err_entry = cache
            .cache
            .get("example.invalid")
            .expect("error entry exists");
        assert!(err_entry.is_error);
        assert_eq!(
            err_entry.original_per_proxy_ttl,
            Some(600),
            "cache_error must carry forward the prior per-proxy TTL so the \
             failed-retry task can preserve it on re-resolution success"
        );
    }

    /// If a cached error expires and the next `resolve()` call has no explicit
    /// TTL, the prior entry's TTL must still win over global/native TTLs.
    #[tokio::test]
    async fn resolve_preserves_prior_ttl_from_expired_error() {
        let cache = DnsCache::new(config_with_global_override(Some(3600)));
        cache.cache.insert(
            "127.0.0.1".to_string(),
            DnsCacheEntry {
                addresses: vec![],
                expires_at: Instant::now() - Duration::from_secs(1),
                stale_deadline: Instant::now() - Duration::from_secs(1),
                applied_ttl: Duration::from_secs(5),
                record_type_used: None,
                is_error: true,
                original_per_proxy_ttl: Some(600),
            },
        );

        let _ = cache.resolve("127.0.0.1", None, None).await.unwrap();

        let entry = cache.cache.get("127.0.0.1").expect("entry should exist");
        assert!(!entry.is_error);
        assert_eq!(entry.original_per_proxy_ttl, Some(600));
        assert_eq!(
            entry.applied_ttl,
            Duration::from_secs(600),
            "resolve must reuse the expired error entry's per-proxy TTL"
        );
    }

    /// Same prior-TTL preservation contract for `resolve_all()`.
    #[tokio::test]
    async fn resolve_all_preserves_prior_ttl_from_expired_error() {
        let cache = DnsCache::new(config_with_global_override(Some(3600)));
        cache.cache.insert(
            "127.0.0.1".to_string(),
            DnsCacheEntry {
                addresses: vec![],
                expires_at: Instant::now() - Duration::from_secs(1),
                stale_deadline: Instant::now() - Duration::from_secs(1),
                applied_ttl: Duration::from_secs(5),
                record_type_used: None,
                is_error: true,
                original_per_proxy_ttl: Some(450),
            },
        );

        let _ = cache.resolve_all("127.0.0.1", None, None).await.unwrap();

        let entry = cache.cache.get("127.0.0.1").expect("entry should exist");
        assert!(!entry.is_error);
        assert_eq!(entry.original_per_proxy_ttl, Some(450));
        assert_eq!(
            entry.applied_ttl,
            Duration::from_secs(450),
            "resolve_all must reuse the expired error entry's per-proxy TTL"
        );
    }
}

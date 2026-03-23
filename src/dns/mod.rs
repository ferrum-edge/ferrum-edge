use dashmap::DashMap;
use hickory_resolver::Resolver;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    pub default_ttl_seconds: u64,
    pub global_overrides: HashMap<String, String>,
    /// Comma-separated nameserver addresses (ip[:port], IPv4 or IPv6).
    pub resolver_addresses: Option<String>,
    /// Path to a custom hosts file.
    pub hosts_file_path: Option<String>,
    /// Comma-separated DNS record type query order (e.g., "CACHE,SRV,A,CNAME").
    pub dns_order: Option<String>,
    /// Override TTL (seconds) for positive DNS records. None = use response TTL.
    pub valid_ttl_override: Option<u64>,
    /// How long stale data can be served while a background refresh is in progress.
    pub stale_ttl_seconds: u64,
    /// TTL (seconds) for caching DNS errors and empty responses.
    pub error_ttl_seconds: u64,
    /// Maximum number of entries in the DNS cache. Entries are evicted when this limit is reached.
    pub max_cache_size: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 300,
            global_overrides: HashMap::new(),
            resolver_addresses: None,
            hosts_file_path: None,
            dns_order: None,
            valid_ttl_override: None,
            stale_ttl_seconds: 3600,
            error_ttl_seconds: 1,
            max_cache_size: 10_000,
        }
    }
}

/// A cached DNS entry with TTL and stale-while-revalidate support.
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
    /// Deadline after which stale data is no longer served.
    stale_deadline: Instant,
    /// The record type that produced this result (for CACHE ordering).
    record_type_used: Option<CachedRecordType>,
    /// Whether this is a cached error/empty response.
    is_error: bool,
}

/// Asynchronous DNS resolver with in-memory caching, stale-while-revalidate,
/// error caching, configurable record type ordering, and hickory-resolver backend.
#[derive(Clone)]
pub struct DnsCache {
    cache: Arc<DashMap<String, DnsCacheEntry>>,
    global_overrides: HashMap<String, String>,
    default_ttl: Duration,
    resolver: Arc<Resolver<TokioConnectionProvider>>,
    dns_order: Vec<DnsRecordOrder>,
    valid_ttl_override: Option<Duration>,
    stale_ttl: Duration,
    error_ttl: Duration,
    max_cache_size: usize,
}

impl DnsCache {
    pub fn new(config: DnsConfig) -> Self {
        let resolver = build_resolver(&config);

        let dns_order = parse_dns_order(config.dns_order.as_deref());

        Self {
            cache: Arc::new(DashMap::new()),
            global_overrides: config.global_overrides,
            default_ttl: Duration::from_secs(config.default_ttl_seconds),
            resolver: Arc::new(resolver),
            dns_order,
            valid_ttl_override: config.valid_ttl_override.map(Duration::from_secs),
            stale_ttl: Duration::from_secs(config.stale_ttl_seconds),
            error_ttl: Duration::from_secs(config.error_ttl_seconds),
            max_cache_size: config.max_cache_size,
        }
    }

    /// Resolve a hostname to an IP address, using cache, overrides, or actual DNS.
    ///
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
        // 1. Check per-proxy static override first
        if let Some(ip_str) = per_proxy_override {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(addr);
        }

        // 2. Check global overrides
        if let Some(ip_str) = self.global_overrides.get(hostname) {
            let addr: IpAddr = ip_str.parse()?;
            return Ok(addr);
        }

        // 3. Check cache with stale-while-revalidate
        if let Some(entry) = self.cache.get(hostname) {
            let now = Instant::now();

            // Fresh entry — return immediately
            if entry.expires_at > now && !entry.addresses.is_empty() && !entry.is_error {
                return Ok(entry.addresses[0]);
            }

            // Stale but within stale window — return stale data, trigger background refresh
            if entry.stale_deadline > now && !entry.addresses.is_empty() && !entry.is_error {
                let cache = self.clone();
                let host = hostname.to_string();
                let ttl = per_proxy_ttl;
                tokio::spawn(async move {
                    if let Err(e) = cache.refresh_entry(&host, ttl).await {
                        warn!("DNS stale refresh failed for {}: {}", host, e);
                    }
                });
                debug!(
                    "DNS serving stale entry for {} (background refresh triggered)",
                    hostname
                );
                return Ok(entry.addresses[0]);
            }

            // Cached error that hasn't expired — return error immediately
            if entry.is_error && entry.expires_at > now {
                anyhow::bail!("DNS resolution failed for {} (cached error)", hostname);
            }
        }

        // 4. Perform actual DNS resolution
        match self.do_resolve(hostname).await {
            Ok((addrs, record_type)) if !addrs.is_empty() => {
                let ttl = per_proxy_ttl
                    .map(Duration::from_secs)
                    .or(self.valid_ttl_override)
                    .unwrap_or(self.default_ttl);

                self.cache.insert(
                    hostname.to_string(),
                    DnsCacheEntry {
                        addresses: addrs.clone(),
                        expires_at: Instant::now() + ttl,
                        stale_deadline: Instant::now() + ttl + self.stale_ttl,
                        record_type_used: record_type,
                        is_error: false,
                    },
                );

                debug!(
                    "DNS resolved {} -> {:?} (ttl={:?})",
                    hostname, addrs[0], ttl
                );
                Ok(addrs[0])
            }
            Ok(_) => {
                self.cache_error(hostname);
                anyhow::bail!("DNS resolution returned no addresses for {}", hostname);
            }
            Err(e) => {
                self.cache_error(hostname);
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
        let (addrs, record_type) = self.do_resolve(hostname).await?;
        if addrs.is_empty() {
            anyhow::bail!("DNS refresh returned no addresses for {}", hostname);
        }

        let ttl = per_proxy_ttl
            .map(Duration::from_secs)
            .or(self.valid_ttl_override)
            .unwrap_or(self.default_ttl);

        self.cache.insert(
            hostname.to_string(),
            DnsCacheEntry {
                addresses: addrs,
                expires_at: Instant::now() + ttl,
                stale_deadline: Instant::now() + ttl + self.stale_ttl,
                record_type_used: record_type,
                is_error: false,
            },
        );

        debug!("DNS background refresh: {} refreshed", hostname);
        Ok(())
    }

    /// Cache a DNS error to prevent hammering DNS for known-bad hostnames.
    fn cache_error(&self, hostname: &str) {
        self.cache.insert(
            hostname.to_string(),
            DnsCacheEntry {
                addresses: vec![],
                expires_at: Instant::now() + self.error_ttl,
                stale_deadline: Instant::now() + self.error_ttl, // no stale serving for errors
                record_type_used: None,
                is_error: true,
            },
        );
        debug!(
            "DNS cached error for {} (ttl={:?})",
            hostname, self.error_ttl
        );
    }

    /// Perform DNS resolution using hickory-resolver with configurable record type ordering.
    async fn do_resolve(
        &self,
        hostname: &str,
    ) -> Result<(Vec<IpAddr>, Option<CachedRecordType>), anyhow::Error> {
        // Try parsing as IP first — bypass DNS entirely
        if let Ok(addr) = hostname.parse::<IpAddr>() {
            return Ok((vec![addr], None));
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

        // Try each record type in order
        for record_type in &query_types {
            match record_type {
                CachedRecordType::A => match self.resolver.ipv4_lookup(hostname).await {
                    Ok(lookup) => {
                        let addrs: Vec<IpAddr> = lookup.iter().map(|a| IpAddr::V4(a.0)).collect();
                        if !addrs.is_empty() {
                            return Ok((addrs, Some(CachedRecordType::A)));
                        }
                    }
                    Err(_) => continue,
                },
                CachedRecordType::Aaaa => match self.resolver.ipv6_lookup(hostname).await {
                    Ok(lookup) => {
                        let addrs: Vec<IpAddr> = lookup.iter().map(|a| IpAddr::V6(a.0)).collect();
                        if !addrs.is_empty() {
                            return Ok((addrs, Some(CachedRecordType::Aaaa)));
                        }
                    }
                    Err(_) => continue,
                },
                CachedRecordType::Srv => {
                    match self.resolver.srv_lookup(hostname).await {
                        Ok(srv_lookup) => {
                            // SRV records point to target hostnames — resolve them to IPs
                            for srv in srv_lookup.iter() {
                                let target = srv.target().to_string();
                                // Remove trailing dot if present
                                let target = target.trim_end_matches('.');
                                if let Ok(ip_lookup) = self.resolver.lookup_ip(target).await {
                                    let addrs: Vec<IpAddr> = ip_lookup.iter().collect();
                                    if !addrs.is_empty() {
                                        return Ok((addrs, Some(CachedRecordType::Srv)));
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
                                return Ok((addrs, Some(CachedRecordType::Cname)));
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
    #[allow(dead_code)]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Check if a cached entry exists and is a cached error.
    #[allow(dead_code)]
    pub fn is_cached_error(&self, hostname: &str) -> bool {
        self.cache
            .get(hostname)
            .map(|e| e.is_error && e.expires_at > Instant::now())
            .unwrap_or(false)
    }

    /// Evict expired entries and enforce max cache size.
    /// Removes entries past their stale deadline first, then evicts oldest
    /// entries (by expiration time) if still over capacity.
    pub fn evict_expired(&self) {
        let now = Instant::now();

        // Phase 1: Remove all entries past their stale deadline (fully expired)
        self.cache.retain(|_, entry| entry.stale_deadline > now);

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
    /// they expire. Entries are refreshed when they reach 75% of their TTL,
    /// keeping DNS resolution out of the hot request path.
    #[allow(dead_code)]
    pub fn start_background_refresh(&self) {
        self.start_background_refresh_with_shutdown(None);
    }

    /// Start background refresh with an optional shutdown signal.
    ///
    /// When `shutdown_rx` is provided, the task will exit cleanly when the
    /// shutdown signal is received. Without it, the task runs until aborted.
    pub fn start_background_refresh_with_shutdown(
        &self,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        let cache = self.clone();
        let check_interval = std::cmp::max(cache.default_ttl.as_secs() / 4, 5);

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

                // Collect entries that are nearing expiration (past 75% of TTL)
                let now = Instant::now();
                let mut to_refresh: Vec<(String, Option<u64>)> = Vec::new();

                for entry in cache.cache.iter() {
                    // Skip error entries
                    if entry.is_error {
                        continue;
                    }

                    let remaining = entry.expires_at.saturating_duration_since(now);
                    let total_ttl = cache.valid_ttl_override.unwrap_or(cache.default_ttl);
                    // Refresh if less than 25% of TTL remaining
                    if remaining < total_ttl / 4 && remaining > Duration::ZERO {
                        to_refresh.push((entry.key().clone(), None));
                    }
                }

                // Refresh entries in the background
                for (hostname, _ttl) in to_refresh {
                    match cache.do_resolve(&hostname).await {
                        Ok((addrs, record_type)) if !addrs.is_empty() => {
                            let refresh_ttl = cache.valid_ttl_override.unwrap_or(cache.default_ttl);
                            cache.cache.insert(
                                hostname.clone(),
                                DnsCacheEntry {
                                    addresses: addrs,
                                    expires_at: Instant::now() + refresh_ttl,
                                    stale_deadline: Instant::now() + refresh_ttl + cache.stale_ttl,
                                    record_type_used: record_type,
                                    is_error: false,
                                },
                            );
                            debug!("DNS background refresh: {} refreshed", hostname);
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
        });
    }

    /// Warmup: resolve all hostnames from the config at startup.
    ///
    /// Hostnames are deduplicated before resolution — if multiple proxies or
    /// plugins share the same hostname, only one DNS lookup is performed.
    /// Each unique hostname is resolved concurrently.
    pub async fn warmup(&self, hostnames: Vec<(String, Option<String>, Option<u64>)>) {
        // Deduplicate by hostname, keeping the first override/TTL seen for each.
        // Hostnames with a static override still go through resolve() to populate
        // the cache, but they won't trigger actual DNS queries.
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<_> = hostnames
            .into_iter()
            .filter(|(host, _, _)| seen.insert(host.clone()))
            .collect();

        if unique.is_empty() {
            debug!("DNS warmup: no hostnames to resolve");
            return;
        }

        info!(
            "DNS warmup: resolving {} unique hostnames ({} before dedup)",
            unique.len(),
            seen.len()
        );
        let mut handles = Vec::new();

        for (host, override_ip, ttl) in unique {
            let cache = self.clone();
            handles.push(tokio::spawn(async move {
                match cache.resolve(&host, override_ip.as_deref(), ttl).await {
                    Ok(addr) => debug!("DNS warmup: {} -> {}", host, addr),
                    Err(e) => warn!("DNS warmup failed for {}: {}", host, e),
                }
            }));
        }

        for handle in handles {
            let _ = handle.await;
        }

        info!("DNS warmup complete");
    }
}

/// Build a hickory-resolver `Resolver` from a `DnsConfig`.
fn build_resolver(config: &DnsConfig) -> Resolver<TokioConnectionProvider> {
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
            let ns_group = NameServerConfigGroup::from(nameservers);
            // Preserve system search/domain settings but replace nameservers
            resolver_config = ResolverConfig::from_parts(
                resolver_config.domain().cloned(),
                resolver_config.search().to_vec(),
                ns_group,
            );
            info!("DNS: using custom nameservers from FERRUM_DNS_RESOLVER_ADDRESS");
        } else {
            warn!(
                "DNS: FERRUM_DNS_RESOLVER_ADDRESS set but no valid addresses parsed, using system default"
            );
        }
    }

    // Apply TTL overrides
    if let Some(valid_ttl) = config.valid_ttl_override {
        let d = Duration::from_secs(valid_ttl);
        resolver_opts.positive_min_ttl = Some(d);
        resolver_opts.positive_max_ttl = Some(d);
    }

    // Apply error/negative TTL
    let neg_ttl = Duration::from_secs(config.error_ttl_seconds);
    resolver_opts.negative_min_ttl = Some(neg_ttl);
    resolver_opts.negative_max_ttl = Some(neg_ttl);

    // Always check hosts file
    resolver_opts.use_hosts_file = ResolveHosts::Always;

    // Build the resolver
    let mut builder =
        Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default());
    *builder.options_mut() = resolver_opts;
    let mut resolver = builder.build();

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
                // Add both UDP and TCP for each nameserver
                configs.push(NameServerConfig::new(addr, Protocol::Udp));
                configs.push(NameServerConfig::new(addr, Protocol::Tcp));
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

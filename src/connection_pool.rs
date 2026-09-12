//! Connection pool manager for HTTP/HTTPS/WebSocket backend clients.
//!
//! Provides `reqwest::Client` reuse keyed by connection identity (destination,
//! protocol, DNS override, TLS trust, mTLS credentials) plus the inspectable
//! `rcfg=…` client-behavior suffix for every setting baked into the shared
//! client. Each unique key gets one `reqwest::Client` which internally manages
//! its own TCP connection pool.
//!
//! All clients use the gateway's shared `DnsCache` as their resolver, keeping
//! DNS lookups off the hot request path. A shared pool shell in `src/pool/`
//! handles the DashMap, key-buffer fast path, and idle cleanup.

use crate::backend_conn_limit::ReqwestConnectionAdmission;
use crate::config::PoolConfig;
use crate::config::types::{GatewayConfig, Proxy};
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::pool::{GenericPool, PoolManager};
use crate::tls::TlsPolicy;
use crate::tls::backend::{
    BackendSvidGeneration, BackendTlsConfigBuilder, BackendTlsConfigCache, SvidGenerationMatcher,
    append_backend_tls_pool_key_fields, append_optional_pool_key_component,
    append_pool_key_component, backend_svid_generation_for_client_cert,
    backend_tls_config_cache_key,
};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Clone)]
struct ReqwestPoolManager {
    global_config: PoolConfig,
    global_env_config: crate::config::EnvConfig,
    dns_cache: DnsCache,
    tls_policy: Option<Arc<TlsPolicy>>,
    crls: crate::tls::SharedCrlList,
    backend_h3_tls_configs: BackendTlsConfigCache,
    backend_svid_generation: BackendSvidGeneration,
    workload_svid_cert_path: Option<String>,
    /// Shared DestinationRule `connectionPool.tcp.maxConnections` admission
    /// hook, installed on every client this manager builds.
    ///
    /// One hook for the whole gateway is what makes divergent reqwest pool
    /// keys (TLS material, `rcfg`, forced-H1 ALPN, subset) for the same
    /// destination share ONE physical-connection ceiling instead of getting one
    /// each. `OnceLock` because `ProxyState` attaches it right after
    /// construction; a pool built without it (focused tests, standalone
    /// callers) simply never enforces a cap.
    reqwest_conn_admission: std::sync::OnceLock<Arc<ReqwestConnectionAdmission>>,
}

impl ReqwestPoolManager {
    fn pool_key_owned(&self, proxy: &Proxy) -> String {
        // Capacity covers identity fields plus the inspectable `rcfg=…`
        // client-behavior suffix without a mid-build realloc on the common path.
        let mut key = String::with_capacity(192);
        self.build_key(proxy, &proxy.backend_host, proxy.backend_port, 0, &mut key);
        key
    }

    fn tls_config_cache_key_owned(&self, proxy: &Proxy) -> String {
        let verify = proxy.resolved_tls.verify_server_cert
            && (!self.global_env_config.tls_no_verify
                || !proxy.resolved_tls.allows_global_no_verify());
        let effective_client_cert_path = proxy.resolved_tls.client_cert_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_cert_path
            .as_deref());
        let effective_client_key_path = proxy.resolved_tls.client_key_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_key_path
            .as_deref());
        let svid_generation = backend_svid_generation_for_client_cert(
            effective_client_cert_path,
            self.workload_svid_cert_path.as_deref(),
            self.backend_svid_generation.load(Ordering::Acquire),
        );
        backend_tls_config_cache_key(
            &proxy.resolved_tls,
            effective_client_cert_path,
            effective_client_key_path,
            verify,
            svid_generation,
        )
    }

    async fn create_client(&self, proxy: &Proxy, config: &PoolConfig) -> Result<reqwest::Client> {
        // Install the per-proxy `dns_override` on the shared DnsCacheResolver so
        // every hostname this client dials — including load-balanced targets
        // whose host differs from `proxy.backend_host` — pins to the override
        // IP. Do NOT use reqwest's hostname-specific `ClientBuilder::resolve()`
        // map: an upstream-keyed pool entry is shared across targets, and a
        // single-host resolve hint would leave other targets on normal DNS
        // while telemetry still claimed the override (issue #2414).
        if let Some(ref dns_override) = proxy.dns_override
            && let Ok(ip) = dns_override.parse::<std::net::IpAddr>()
            && let Some(reason) = self.global_env_config.backend_allow_ips.deny_reason(&ip)
        {
            anyhow::bail!(
                "Proxy '{}': dns_override IP {} denied by backend egress policy: {}",
                proxy.id,
                ip,
                reason
            );
        }
        let dns_resolver = Arc::new(DnsCacheResolver::with_dns_override(
            self.dns_cache.clone(),
            proxy.dns_override.clone(),
        ));

        let crls = self.crls.load_full();
        let tls_builder = BackendTlsConfigBuilder {
            proxy,
            policy: self.tls_policy.as_deref(),
            global_ca: self
                .global_env_config
                .tls_ca_bundle_path
                .as_deref()
                .map(Path::new),
            global_no_verify: self.global_env_config.tls_no_verify,
            global_client_cert: self
                .global_env_config
                .backend_tls_client_cert_path
                .as_deref()
                .map(Path::new),
            global_client_key: self
                .global_env_config
                .backend_tls_client_key_path
                .as_deref()
                .map(Path::new),
            crls: crls.as_ref().as_slice(),
        };
        let reqwest_builder = if config.enable_http2 {
            tls_builder.build_reqwest()
        } else {
            tls_builder.build_reqwest_with_http2_enabled(false)
        };
        let mut client_builder = reqwest_builder
            .map_err(|e| anyhow::anyhow!("Failed to build reqwest backend TLS config: {}", e))?
            .dns_resolver(dns_resolver)
            .tcp_nodelay(true)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
            // Never auto-follow backend redirects from this shared client.
            // Proxy dispatch must surface 3xx to callers as-is, and warmup probes
            // must only touch configured backend targets (no redirected egress).
            .redirect(reqwest::redirect::Policy::none());

        // Request-only policy (connect/read timeouts) is NOT baked into this
        // shared client — those are applied per-request on the dispatch side via
        // `RequestBuilder::connect_timeout()` / `RequestBuilder::timeout()` (see
        // `docs/upstream-reqwest-patches/001-per-request-connect-timeout/`).
        //
        // Client-level settings below (idle timeout, TCP keepalive, H2 keepalive /
        // windows / adaptive / max frame) *are* baked into the Client and cannot
        // be overridden per request. They therefore enter the pool key via
        // `PoolConfig::append_reqwest_client_behavior_pool_key` so two proxies
        // with divergent values do not share a first-creator-wins client.
        // `max_idle_per_host` remains global-only by deliberate tradeoff.

        // DestinationRule `connectionPool.tcp.maxConnections`: admitted at
        // reqwest's connector, the one place a NEW physical socket is dialed.
        // Pooled reuse and multiplexed HTTP/2 streams never reach the hook, and
        // the token it hands back is owned by the connection object, so the
        // slot retires exactly when that socket closes — including while
        // reqwest keeps it idle after the request that opened it finished.
        // See `docs/upstream-reqwest-patches/003-connection-admission-hook/`.
        if let Some(admission) = self.reqwest_conn_admission.get() {
            let hook: Arc<dyn reqwest::ConnectionAdmission> = admission.clone();
            client_builder = client_builder.connection_admission(hook);
        }

        if config.enable_http_keep_alive {
            client_builder =
                client_builder.tcp_keepalive(Duration::from_secs(config.tcp_keepalive_seconds));
        }

        if config.enable_http2 {
            client_builder = client_builder
                .http2_keep_alive_interval(Duration::from_secs(
                    config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    config.http2_keep_alive_timeout_seconds,
                ))
                .http2_initial_stream_window_size(config.http2_initial_stream_window_size)
                .http2_initial_connection_window_size(config.http2_initial_connection_window_size)
                .http2_adaptive_window(config.http2_adaptive_window)
                .http2_max_frame_size(config.http2_max_frame_size)
                // Bound the response header block a backend may push back under
                // the operator's own `FERRUM_MAX_HEADER_SIZE_BYTES` policy
                // (floored at 16 KiB) instead of hyper's fixed constant. This is
                // a gateway-global `EnvConfig` value with no per-proxy override,
                // so it is identical for every client built in this process and
                // needs no `append_reqwest_client_behavior_pool_key` entry.
                .http2_max_header_list_size(crate::proxy::h2_parser_max_header_list_size(
                    self.global_env_config.max_header_size_bytes,
                ));
        }

        Ok(client_builder.build()?)
    }
}

#[async_trait]
impl PoolManager for ReqwestPoolManager {
    type Connection = reqwest::Client;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, _shard: usize, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();

        if let Some(ref upstream_id) = proxy.upstream_id {
            buf.push_str("u=");
            append_pool_key_component(buf, upstream_id);
            buf.push('|');
        } else {
            buf.push_str("d=");
            append_pool_key_component(buf, host);
            let _ = write!(buf, ":{port}|");
        }
        // Pool keys partition by scheme discriminant so two proxies with different
        // wire schemes (http vs https, tcp vs tcps, etc.) don't share a client.
        // `u8::MAX` is a stable sentinel for the rare "scheme not yet resolved"
        // case — `normalize_fields()` populates `backend_scheme` before any
        // request hits the pool, so this arm is defensive.
        debug_assert!(
            proxy.backend_scheme.is_some(),
            "backend_scheme should be resolved before HTTP pool key generation"
        );
        let scheme_disc = proxy.backend_scheme.map(|s| s as u8).unwrap_or(u8::MAX);
        let _ = write!(buf, "{}|", scheme_disc);
        // Force-H1 (`h2UpgradePolicy = DO_NOT_UPGRADE` or resolved
        // `pool_enable_http2=false` on a TLS backend) builds a reqwest client
        // with ALPN restricted to `http/1.1` (see
        // `BackendTlsConfigBuilder::build_reqwest_with_http2_enabled`). That is
        // a DIFFERENT, protocol-incompatible client from the default
        // (h2-capable) one, so it must NOT share a pool entry. This is a
        // protocol/ALPN distinction (legitimate pool-key content per
        // `.claude/rules/proxy-protocols.md`), NOT a policy-only field. `h1`
        // marks the force-H1 client; absent otherwise.
        let force_reqwest_http1 = proxy.forces_backend_http1_only()
            || (proxy
                .backend_scheme
                .is_some_and(|scheme| scheme.is_tls_backend())
                && !self.global_config.effective_enable_http2(proxy));
        if force_reqwest_http1 {
            buf.push_str("h1");
        }
        buf.push('|');
        append_optional_pool_key_component(buf, proxy.dns_override.as_deref());
        buf.push('|');
        // Subset name partitions backend pools so two proxies that share
        // `upstream_id` but select different DestinationRule subsets cannot
        // share a client even when their TLS material happens to be
        // byte-identical. Empty when the proxy has no `upstream_subset`.
        append_optional_pool_key_component(buf, proxy.upstream_subset.as_deref());
        buf.push('|');
        let verify = proxy.resolved_tls.verify_server_cert
            && (!self.global_env_config.tls_no_verify
                || !proxy.resolved_tls.allows_global_no_verify());
        let effective_client_cert_path = proxy.resolved_tls.client_cert_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_cert_path
            .as_deref());
        let effective_client_key_path = proxy.resolved_tls.client_key_path.as_deref().or(self
            .global_env_config
            .backend_tls_client_key_path
            .as_deref());
        let svid_generation = backend_svid_generation_for_client_cert(
            effective_client_cert_path,
            self.workload_svid_cert_path.as_deref(),
            self.backend_svid_generation.load(Ordering::Acquire),
        );
        append_backend_tls_pool_key_fields(
            buf,
            &proxy.resolved_tls,
            effective_client_cert_path,
            effective_client_key_path,
            verify,
            svid_generation,
        );
        // Client-baked pool settings (idle timeout, keepalive, H2 windows, …)
        // that `create_client` installs on the shared reqwest::Client. Request-
        // only timeouts stay out; `max_idle_per_host` stays global-only.
        self.global_config
            .for_proxy(proxy)
            .append_reqwest_client_behavior_pool_key(buf);
    }

    async fn create(&self, _key: &str, proxy: &Proxy) -> Result<reqwest::Client> {
        let config = self.global_config.for_proxy(proxy);
        self.create_client(proxy, &config).await
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        true
    }

    fn destroy(&self, conn: Self::Connection) {
        drop(conn);
    }

    fn runtime_metrics_kind(&self) -> Option<crate::runtime_metrics::PoolKind> {
        Some(crate::runtime_metrics::PoolKind::HttpReqwest)
    }
}

/// Connection pool manager for reusing HTTP clients.
pub struct ConnectionPool {
    pool: Arc<GenericPool<ReqwestPoolManager>>,
}

impl ConnectionPool {
    /// Create a new connection pool manager with global configuration.
    #[allow(dead_code)] // Used by focused tests and by callers that do not share SVID rotation state.
    pub fn new(
        global_config: PoolConfig,
        mtls_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        Self::new_with_svid_generation(
            global_config,
            mtls_config,
            dns_cache,
            tls_policy,
            crls,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    pub fn new_with_svid_generation(
        global_config: PoolConfig,
        mtls_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        Self::new_with_svid_generation_and_shared_crls(
            global_config,
            mtls_config,
            dns_cache,
            tls_policy,
            crate::tls::shared_crl_list(crls),
            backend_svid_generation,
        )
    }

    pub fn new_with_svid_generation_and_shared_crls(
        global_config: PoolConfig,
        mtls_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::SharedCrlList,
        backend_svid_generation: BackendSvidGeneration,
    ) -> Self {
        let cleanup_interval =
            Duration::from_secs(mtls_config.pool_cleanup_interval_seconds.max(1));
        let shards = crate::util::sharding::pool_shard_amount(mtls_config.pool_shard_amount);
        let workload_svid_cert_path = mtls_config.gateway_svid_cert_path.clone();
        let manager = Arc::new(ReqwestPoolManager {
            global_config: global_config.clone(),
            global_env_config: mtls_config,
            dns_cache,
            tls_policy,
            crls,
            backend_h3_tls_configs: BackendTlsConfigCache::with_shards(shards),
            backend_svid_generation,
            workload_svid_cert_path,
            reqwest_conn_admission: std::sync::OnceLock::new(),
        });

        Self {
            pool: GenericPool::new(manager, global_config, cleanup_interval, shards),
        }
    }

    /// Install the gateway-wide `maxConnections` admission hook.
    ///
    /// Additive and idempotent (`OnceLock::set`), called by `ProxyState`
    /// immediately after construction and before any client is built.
    pub fn attach_reqwest_connection_admission(&self, admission: Arc<ReqwestConnectionAdmission>) {
        let _ = self.pool.manager().reqwest_conn_admission.set(admission);
    }

    /// Get or create a client for the given proxy using global defaults + proxy overrides.
    pub async fn get_client(&self, proxy: &Proxy) -> Result<reqwest::Client> {
        self.pool
            .get(proxy, &proxy.backend_host, proxy.backend_port, 0)
            .await
    }

    /// Expose the pool key for warmup deduplication.
    ///
    /// `warmup_connection_pools` composes this with the per-target
    /// `host:port` to dedup reqwest HEAD warmup tasks. Including the
    /// pool key (which carries the TLS-aware client identity:
    /// `{dest}|{proto}|{dns_override}|{subset}|{ca}|{mtls_cert}|{verify}`)
    /// in the dedup means proxies that share `(scheme, host, port)` but
    /// have divergent TLS configs or different `upstream_subset` selectors
    /// each get their own warmup task — matching the fact that they end
    /// up with separate `reqwest::Client`s at runtime.
    pub fn pool_key_for_warmup(&self, proxy: &Proxy) -> String {
        self.pool.manager().pool_key_owned(proxy)
    }

    /// TLS-config cache key (no host/port / rcfg suffix). Used by unit tests
    /// to prove two endpoints sharing trust material reuse one `ClientConfig`.
    #[allow(dead_code)] // exercised from unit tests
    pub fn tls_config_cache_key_for_warmup(&self, proxy: &Proxy) -> String {
        self.pool.manager().tls_config_cache_key_owned(proxy)
    }

    /// Drop H3 TLS configs whose identity is no longer in `config`. Cold-path
    /// only (config publication); live TLS identities are retained.
    pub fn retain_live_tls_configs_from_config(&self, config: &GatewayConfig) {
        let mut live_tls_keys = HashSet::with_capacity(config.proxies.len());
        for proxy in &config.proxies {
            live_tls_keys.insert(self.pool.manager().tls_config_cache_key_owned(proxy));
        }
        self.pool
            .manager()
            .backend_h3_tls_configs
            .retain_keys(&live_tls_keys);
    }

    #[allow(dead_code)] // exercised from unit tests
    pub fn backend_tls_config_cache(&self) -> &BackendTlsConfigCache {
        &self.pool.manager().backend_h3_tls_configs
    }

    /// Get the global pool configuration.
    pub fn global_pool_config(&self) -> &PoolConfig {
        &self.pool.manager().global_config
    }

    /// Resident pool entries and the configured per-host idle ceiling.
    ///
    /// Scrape-path counterpart to [`Self::get_stats`], which additionally
    /// snapshots every pool key to build the per-host map. The `/metrics`
    /// surface never labels by pool key, so it does not pay for that snapshot.
    pub fn pool_gauges(&self) -> (usize, usize) {
        let stats = self.pool.stats();
        (stats.size, stats.max_idle_per_host)
    }

    /// Get pool statistics for monitoring.
    pub fn get_stats(&self) -> PoolStats {
        let stats = self.pool.stats();
        let entries_per_host = self
            .pool
            .keys_snapshot()
            .into_iter()
            .map(|key| (key, 1usize))
            .collect();

        PoolStats {
            total_pools: stats.size,
            entries_per_host,
            max_idle_per_host: stats.max_idle_per_host,
            idle_timeout_seconds: stats.idle_timeout_seconds,
        }
    }

    /// Get TLS configuration for HTTP/3 backend connections.
    pub fn get_tls_config_for_backend(
        &self,
        proxy: &Proxy,
    ) -> Result<Arc<rustls::ClientConfig>, anyhow::Error> {
        let manager = self.pool.manager();
        manager.backend_h3_tls_configs.get_or_try_build(
            manager.tls_config_cache_key_owned(proxy),
            || {
                let crls = manager.crls.load_full();
                let mut client_config = BackendTlsConfigBuilder {
                    proxy,
                    policy: manager.tls_policy.as_deref(),
                    global_ca: manager
                        .global_env_config
                        .tls_ca_bundle_path
                        .as_deref()
                        .map(Path::new),
                    global_no_verify: manager.global_env_config.tls_no_verify,
                    global_client_cert: manager
                        .global_env_config
                        .backend_tls_client_cert_path
                        .as_deref()
                        .map(Path::new),
                    global_client_key: manager
                        .global_env_config
                        .backend_tls_client_key_path
                        .as_deref()
                        .map(Path::new),
                    crls: crls.as_ref().as_slice(),
                }
                .build_rustls_quic()
                .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 backend TLS config: {}", e))?;

                client_config.alpn_protocols = vec![b"h3".to_vec()];
                Ok(client_config)
            },
        )
    }

    /// Clear all pooled connections.
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.pool.clear();
    }

    pub fn drain_backend_tls_config_cache_svid_generation(&self, generation: u64) {
        self.pool
            .manager()
            .backend_h3_tls_configs
            .drain_svid_generation(generation);
    }

    pub fn clear_backend_tls_config_cache(&self) {
        self.pool.manager().backend_h3_tls_configs.clear();
    }

    pub fn force_drain_svid_generation(&self, generation: u64) {
        let matcher = SvidGenerationMatcher::new(generation);
        self.pool.invalidate_matching(|key| matcher.matches(key));
    }

    pub fn force_drain_all(&self) {
        self.pool.clear();
    }
}

/// Connection pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_pools: usize,
    pub entries_per_host: HashMap<String, usize>,
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Connection Pool Statistics:")?;
        writeln!(f, "  Total pooled connections: {}", self.total_pools)?;
        writeln!(f, "  Max idle per host: {}", self.max_idle_per_host)?;
        writeln!(f, "  Idle timeout: {}s", self.idle_timeout_seconds)?;
        writeln!(f, "  Connections per host:")?;
        for (host, count) in &self.entries_per_host {
            writeln!(f, "    {}: {}", host, count)?;
        }
        Ok(())
    }
}

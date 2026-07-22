//! UDP datagram rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::warn;

use super::utils::rate_limit::{RateLimitBackend, UdpRateLimitAlgorithm, UdpRateLimitOp};
use super::{
    Plugin, PluginHttpClient, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext,
    UdpDatagramVerdict,
};

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_COOLDOWN_SECS: u64 = 1;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

pub struct UdpRateLimiting {
    check_counter: AtomicU64,
    epoch_base: Instant,
    last_eviction_secs: AtomicU64,
    limiter: RateLimitBackend<Arc<str>, UdpRateLimitAlgorithm>,
}

impl UdpRateLimiting {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        if !config.is_object() {
            return Err("udp_rate_limiting: config must be an object".to_string());
        }

        let datagrams_per_second = optional_positive_u64(config, "datagrams_per_second")?;
        let bytes_per_second = optional_positive_u64(config, "bytes_per_second")?;

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of 'datagrams_per_second' or 'bytes_per_second' must be set"
                    .to_string(),
            );
        }

        let window_seconds = optional_positive_u64(config, "window_seconds")?.unwrap_or(1);
        let datagrams_per_window = per_window_limit(datagrams_per_second, window_seconds)?;
        let bytes_per_window = per_window_limit(bytes_per_second, window_seconds)?;
        let epoch_base = Instant::now();

        Ok(Self {
            check_counter: AtomicU64::new(0),
            epoch_base,
            last_eviction_secs: AtomicU64::new(0),
            limiter: RateLimitBackend::from_plugin_config(
                "udp_rate_limiting",
                config,
                &http_client,
                UdpRateLimitAlgorithm::new(
                    datagrams_per_window,
                    bytes_per_window,
                    window_seconds,
                    epoch_base,
                ),
            )?,
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    fn redis_ip_key(client_ip: &str) -> String {
        let mut key = String::with_capacity(3 + client_ip.len());
        key.push_str("ip:");
        key.push_str(client_ip);
        key
    }

    fn secs_since_base(&self) -> u64 {
        Instant::now().duration_since(self.epoch_base).as_secs()
    }

    fn maybe_evict(&self) -> bool {
        let count = self.check_counter.fetch_add(1, Ordering::Relaxed);
        let len = self.limiter.tracked_keys_count();
        let over_capacity = len > MAX_STATE_ENTRIES;
        let periodic = count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && len > 0;

        if over_capacity || periodic {
            let now_secs = self.secs_since_base();
            let last_sweep = self.last_eviction_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last_sweep) >= EVICTION_COOLDOWN_SECS
                && self
                    .last_eviction_secs
                    .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                // `enforce_capacity` runs `retain_active_at` first and
                // then force-evicts down to the cap when active-only
                // pruning isn't enough. Under sustained per-IP UDP
                // traffic every window state keeps reporting active, so
                // plain `retain_active_at` would leave the map pinned
                // at `MAX_STATE_ENTRIES + 1` and the
                // `over_capacity && !contains_local_key` guard in
                // `on_udp_datagram` would drop every new client IP
                // indefinitely. Mirrors `ai_rate_limiter.rs` and
                // `rate_limiting.rs`.
                self.limiter
                    .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
            }
        }

        self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES
    }
}

#[async_trait]
impl Plugin for UdpRateLimiting {
    fn name(&self) -> &str {
        "udp_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::UDP_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        UDP_ONLY_PROTOCOLS
    }

    fn requires_udp_datagram_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        let over_capacity = self.maybe_evict();
        let key = Arc::clone(&ctx.client_ip);

        if over_capacity && !self.limiter.contains_local_key(&key) {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            return UdpDatagramVerdict::Drop;
        }

        let outcome = self
            .limiter
            .check_with_redis_key(
                Arc::clone(&key),
                || Self::redis_ip_key(key.as_ref()),
                &UdpRateLimitOp {
                    datagram_size: ctx.datagram_size as u64,
                },
            )
            .await;

        if outcome.allowed {
            return UdpDatagramVerdict::Forward;
        }
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();

        match outcome.metric {
            Some("bytes") => warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                bytes = outcome.usage.unwrap_or(0),
                limit = outcome.limit.unwrap_or(0),
                "UDP byte rate exceeded, dropping"
            ),
            _ => warn!(
                plugin = "udp_rate_limiting",
                proxy_id = %ctx.proxy_id,
                client_ip = %ctx.client_ip,
                count = outcome.usage.unwrap_or(0),
                limit = outcome.limit.unwrap_or(0),
                "UDP datagram rate exceeded, dropping"
            ),
        }

        UdpDatagramVerdict::Drop
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "udp_rate_limiting: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "udp_rate_limiting: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn per_window_limit(limit: Option<u64>, window_seconds: u64) -> Result<Option<u64>, String> {
    limit
        .map(|value| {
            value.checked_mul(window_seconds).ok_or_else(|| {
                "udp_rate_limiting: per-window limit overflows u64; reduce the rate or window"
                    .to_string()
            })
        })
        .transpose()
}

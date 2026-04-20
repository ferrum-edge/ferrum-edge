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
    #[allow(dead_code)]
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_http_client(config, PluginHttpClient::default())
    }

    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let datagrams_per_second = config["datagrams_per_second"].as_u64();
        let bytes_per_second = config["bytes_per_second"].as_u64();

        if datagrams_per_second.is_none() && bytes_per_second.is_none() {
            return Err(
                "udp_rate_limiting: at least one of 'datagrams_per_second' or 'bytes_per_second' must be set"
                    .to_string(),
            );
        }

        let window_seconds = config["window_seconds"].as_u64().unwrap_or(1).max(1);
        let datagrams_per_window = datagrams_per_second.map(|value| value * window_seconds);
        let bytes_per_window = bytes_per_second.map(|value| value * window_seconds);
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
            ),
        })
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
                self.limiter.retain_active_at(Instant::now());
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

    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext) -> UdpDatagramVerdict {
        let over_capacity = self.maybe_evict();
        let key = Arc::clone(&ctx.client_ip);

        if over_capacity && !self.limiter.contains_local_key(&key) {
            return UdpDatagramVerdict::Drop;
        }

        let redis_key = format!("ip:{}", ctx.client_ip);
        let outcome = self
            .limiter
            .check(
                Arc::clone(&key),
                &redis_key,
                &UdpRateLimitOp {
                    datagram_size: ctx.datagram_size as u64,
                },
            )
            .await;

        if outcome.allowed {
            return UdpDatagramVerdict::Forward;
        }

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

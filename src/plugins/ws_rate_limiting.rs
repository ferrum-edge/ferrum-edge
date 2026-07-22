//! WebSocket frame rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::warn;
use uuid::Uuid;

use super::utils::rate_limit::{RateLimitBackend, WsFrameRateAlgorithm, WsRateLimitOp};
use super::{Plugin, PluginHttpClient, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};

const MAX_STATE_ENTRIES: usize = 50_000;
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

pub struct WsRateLimiting {
    close_reason: String,
    frame_counter: AtomicU64,
    redis_instance_id: String,
    limiter: RateLimitBackend<u64, WsFrameRateAlgorithm>,
}

impl WsRateLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ws_rate_limiting: config must be an object".to_string());
        }

        let frames_per_second =
            optional_positive_u64(config, "frames_per_second")?.unwrap_or(100) as f64;

        let burst_size = optional_positive_u64(config, "burst_size")?
            .map_or(frames_per_second, |value| value as f64);

        // The Redis sliding-window approximation assumes burst >= fps so the
        // derived window length stays >= 1 second and the average sustained
        // rate matches frames_per_second. Without this, burst<fps configs
        // would diverge between local (token bucket refills independently of
        // capacity) and Redis (window floors to 1s, sustained = burst fps).
        if burst_size < frames_per_second {
            return Err(format!(
                "ws_rate_limiting: 'burst_size' ({}) must be >= 'frames_per_second' ({})",
                burst_size as u64, frames_per_second as u64
            ));
        }

        let mut close_reason = optional_string(config, "close_reason")?
            .unwrap_or("Frame rate exceeded")
            .to_string();
        if close_reason.len() > Self::MAX_CLOSE_REASON_BYTES {
            tracing::debug!(
                max_bytes = Self::MAX_CLOSE_REASON_BYTES,
                "ws_rate_limiting: 'close_reason' exceeds WebSocket control-frame limit — truncating"
            );
            close_reason.truncate(Self::truncate_utf8_boundary(
                &close_reason,
                Self::MAX_CLOSE_REASON_BYTES,
            ));
        }

        Ok(Self {
            close_reason,
            frame_counter: AtomicU64::new(0),
            redis_instance_id: Uuid::new_v4().simple().to_string(),
            limiter: RateLimitBackend::from_plugin_config(
                "ws_rate_limiting",
                config,
                &http_client,
                WsFrameRateAlgorithm::new(frames_per_second, burst_size),
            )?,
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    pub(crate) fn redis_connection_scope_key(&self, proxy_id: &str, connection_id: u64) -> String {
        let mut key = String::with_capacity(self.redis_instance_id.len() + proxy_id.len() + 22);
        key.push_str(&self.redis_instance_id);
        key.push(':');
        key.push_str(proxy_id);
        key.push(':');
        let _ = write!(&mut key, "{connection_id}");
        key
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }

    fn maybe_evict(&self) -> bool {
        let count = self.frame_counter.fetch_add(1, Ordering::Relaxed);
        let tracked_keys = self.limiter.tracked_keys_count();
        let over_capacity = tracked_keys > MAX_STATE_ENTRIES;
        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && tracked_keys > 0;

        if over_capacity || periodic {
            // `enforce_capacity` first calls `retain_active_at` to drop
            // inactive entries, then — if the map is still over the cap —
            // force-evicts remaining keys until it holds. Plain
            // `retain_active_at` isn't enough under sustained traffic:
            // every tracked connection's TokenBucket keeps reporting
            // active, so nothing gets evicted and the map stays pinned at
            // `MAX_STATE_ENTRIES + 1`. The `over_capacity &&
            // !contains_local_key` branch in `on_ws_frame` would then
            // reject every new WebSocket connection indefinitely — a
            // service-degradation bug. Mirrors `ai_rate_limiter.rs` and
            // `rate_limiting.rs`.
            self.limiter
                .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
        }

        self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES
    }
}

fn optional_positive_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!(
            "ws_rate_limiting: '{field}' must be an integer greater than zero"
        ));
    };
    if value == 0 {
        return Err(format!(
            "ws_rate_limiting: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ws_rate_limiting: '{field}' must be a string"))
}

#[async_trait]
impl Plugin for WsRateLimiting {
    fn name(&self) -> &str {
        "ws_rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        _message: &Message,
    ) -> Option<Message> {
        let over_capacity = self.maybe_evict();
        if over_capacity && !self.limiter.contains_local_key(&connection_id) {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            warn!(
                plugin = "ws_rate_limiting",
                proxy_id = %proxy_id,
                connection_id,
                max_state_entries = MAX_STATE_ENTRIES,
                "WebSocket rate-limit state capacity exceeded, closing new connection"
            );
            return Some(Message::Close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: self.close_reason.clone().into(),
            })));
        }

        let outcome = self
            .limiter
            .check_with_redis_key(
                connection_id,
                || self.redis_connection_scope_key(proxy_id, connection_id),
                &WsRateLimitOp,
            )
            .await;

        if outcome.allowed {
            return None;
        }
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();

        let dir_label = match direction {
            WebSocketFrameDirection::ClientToBackend => "client->backend",
            WebSocketFrameDirection::BackendToClient => "backend->client",
        };
        warn!(
            plugin = "ws_rate_limiting",
            proxy_id = %proxy_id,
            connection_id,
            direction = dir_label,
            "WebSocket frame rate exceeded, closing connection"
        );
        Some(Message::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: self.close_reason.clone().into(),
        })))
    }
}

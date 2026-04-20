//! WebSocket frame rate limiting with shared local/Redis/failover storage.

use async_trait::async_trait;
use serde_json::Value;
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
        let frames_per_second = config["frames_per_second"].as_u64().unwrap_or(100) as f64;
        if frames_per_second == 0.0 {
            return Err(
                "ws_rate_limiting: 'frames_per_second' must be greater than zero".to_string(),
            );
        }

        let burst_size = config["burst_size"]
            .as_u64()
            .map(|value| value as f64)
            .unwrap_or(frames_per_second);

        let mut close_reason = config["close_reason"]
            .as_str()
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
            ),
        })
    }

    pub(crate) fn redis_connection_scope_key(&self, proxy_id: &str, connection_id: u64) -> String {
        format!("{}:{}:{}", self.redis_instance_id, proxy_id, connection_id)
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }

    fn maybe_evict(&self) {
        let count = self.frame_counter.fetch_add(1, Ordering::Relaxed);
        let over_capacity = self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES;
        let periodic = count > 0
            && count.is_multiple_of(EVICTION_CHECK_INTERVAL)
            && self.limiter.tracked_keys_count() > 0;

        if over_capacity || periodic {
            self.limiter.retain_active_at(Instant::now());
        }
    }
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
        self.maybe_evict();

        let redis_key = self.redis_connection_scope_key(proxy_id, connection_id);
        let outcome = self
            .limiter
            .check(connection_id, &redis_key, &WsRateLimitOp)
            .await;

        if outcome.allowed {
            return None;
        }

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

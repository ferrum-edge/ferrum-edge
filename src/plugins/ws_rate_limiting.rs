//! WebSocket Frame Rate Limiting Plugin
//!
//! Rate limits WebSocket frames per-connection using a token bucket algorithm.
//! When a connection exceeds the configured frames-per-second, the WebSocket
//! is closed with close code 1008 (Policy Violation).
//!
//! Unlike the HTTP `rate_limiting` plugin which operates per-IP or per-consumer,
//! this plugin operates per-WebSocket-connection. Each connection gets its own
//! independent token bucket, identified by a monotonic connection ID.
//!
//! Config:
//! ```json
//! {
//!   "frames_per_second": 100,
//!   "burst_size": 150,
//!   "close_reason": "Frame rate exceeded"
//! }
//! ```
//!
//! If `burst_size` is not set, it defaults to `frames_per_second` (no extra burst).

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::warn;

use super::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection};

/// Maximum tracked connections before triggering forced eviction.
const MAX_STATE_ENTRIES: usize = 50_000;

/// Interval between periodic eviction sweeps (every N frames across all connections).
/// At 100 FPS across 100 connections, this triggers roughly every 10 seconds.
const EVICTION_CHECK_INTERVAL: u64 = 100_000;

/// Per-connection token bucket for frame rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn check_and_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns true if this bucket has had recent activity (within 2x the window).
    fn is_active(&self, now: Instant) -> bool {
        if self.refill_rate <= 0.0 || self.capacity <= 0.0 {
            // Zero-rate buckets can never refill — always consider stale for eviction
            return false;
        }
        let window_secs = self.capacity / self.refill_rate;
        now.duration_since(self.last_refill).as_secs_f64() < window_secs * 2.0
    }
}

pub struct WsRateLimiting {
    frames_per_second: f64,
    burst_size: f64,
    close_reason: String,
    /// Per-connection token buckets keyed by connection_id.
    state: Arc<DashMap<u64, TokenBucket>>,
    /// Monotonic frame counter for periodic eviction (not per-connection).
    frame_counter: std::sync::atomic::AtomicU64,
}

impl WsRateLimiting {
    pub fn new(config: &Value) -> Self {
        let frames_per_second = config["frames_per_second"].as_u64().unwrap_or(100) as f64;

        let burst_size = config["burst_size"]
            .as_u64()
            .map(|v| v as f64)
            .unwrap_or(frames_per_second);

        if frames_per_second == 0.0 {
            tracing::warn!(
                "ws_rate_limiting: 'frames_per_second' is zero — all frames will be rejected"
            );
        }

        let close_reason = config["close_reason"]
            .as_str()
            .unwrap_or("Frame rate exceeded")
            .to_string();

        Self {
            frames_per_second,
            burst_size,
            close_reason,
            state: Arc::new(DashMap::new()),
            frame_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Evict stale entries to prevent unbounded memory growth.
    ///
    /// Two triggers:
    /// 1. **Capacity**: always evict when exceeding MAX_STATE_ENTRIES
    /// 2. **Periodic**: every EVICTION_CHECK_INTERVAL frames, evict inactive buckets
    ///    even if under capacity (prevents slow accumulation in low-traffic deployments)
    fn maybe_evict(&self) {
        let count = self
            .frame_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let over_capacity = self.state.len() > MAX_STATE_ENTRIES;
        let periodic =
            count > 0 && count.is_multiple_of(EVICTION_CHECK_INTERVAL) && !self.state.is_empty();

        if over_capacity || periodic {
            let now = Instant::now();
            self.state.retain(|_, bucket| bucket.is_active(now));
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

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.state.len())
    }

    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        _message: &Message,
    ) -> Option<Message> {
        self.maybe_evict();

        let mut entry = self
            .state
            .entry(connection_id)
            .or_insert_with(|| TokenBucket::new(self.burst_size, self.frames_per_second));

        if !entry.value_mut().check_and_consume() {
            let dir_label = match direction {
                WebSocketFrameDirection::ClientToBackend => "client->backend",
                WebSocketFrameDirection::BackendToClient => "backend->client",
            };
            warn!(
                plugin = "ws_rate_limiting",
                proxy_id = %proxy_id,
                connection_id = connection_id,
                direction = dir_label,
                "WebSocket frame rate exceeded, closing connection"
            );
            return Some(Message::Close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: self.close_reason.clone().into(),
            })));
        }

        None
    }
}

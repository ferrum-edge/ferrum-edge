//! TCP-only concurrent connection throttling.
//!
//! Tracks active TCP connections per proxy and observed identity:
//! - authenticated consumer identity when a prior stream auth plugin set one
//! - otherwise the client IP address
//!
//! This keeps plaintext TCP proxies IP-scoped while allowing TCP+TLS proxies
//! to throttle by the Consumer established by `mtls_auth`.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Plugin, PluginResult, StreamConnectionContext, StreamTransactionSummary};

const METADATA_KEY: &str = "tcp_connection_throttle.key";

pub struct TcpConnectionThrottle {
    max_connections_per_key: u64,
    active_counts: DashMap<String, Arc<AtomicU64>>,
}

impl TcpConnectionThrottle {
    pub fn new(config: &Value) -> Result<Self, String> {
        let max_connections_per_key = config["max_connections_per_key"]
            .as_u64()
            .ok_or_else(|| {
                "tcp_connection_throttle: 'max_connections_per_key' is required and must be a positive integer".to_string()
            })?;

        if max_connections_per_key == 0 {
            return Err(
                "tcp_connection_throttle: 'max_connections_per_key' must be greater than 0"
                    .to_string(),
            );
        }

        Ok(Self {
            max_connections_per_key,
            active_counts: DashMap::new(),
        })
    }

    fn throttle_key(&self, ctx: &StreamConnectionContext) -> String {
        match ctx.effective_identity() {
            Some(identity) => format!("proxy:{}:consumer:{identity}", ctx.proxy_id),
            None => format!("proxy:{}:ip:{}", ctx.proxy_id, ctx.client_ip),
        }
    }

    fn decrement_key(&self, key: &str) {
        let Some(counter) = self
            .active_counts
            .get(key)
            .map(|entry| Arc::clone(entry.value()))
        else {
            return;
        };

        loop {
            let current = counter.load(Ordering::Relaxed);
            if current == 0 {
                return;
            }

            if counter
                .compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if current == 1 {
                    self.active_counts.remove_if(key, |_, value| {
                        Arc::ptr_eq(value, &counter) && value.load(Ordering::Relaxed) == 0
                    });
                }
                return;
            }
        }
    }
}

#[async_trait]
impl Plugin for TcpConnectionThrottle {
    fn name(&self) -> &str {
        "tcp_connection_throttle"
    }

    fn priority(&self) -> u16 {
        super::priority::TCP_CONNECTION_THROTTLE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::TCP_ONLY_PROTOCOLS
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.active_counts.len())
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let key = self.throttle_key(ctx);
        let counter = self
            .active_counts
            .entry(key.clone())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone();

        let previous = counter.fetch_add(1, Ordering::Relaxed);
        if previous >= self.max_connections_per_key {
            counter.fetch_sub(1, Ordering::Relaxed);
            self.active_counts.remove_if(&key, |_, value| {
                Arc::ptr_eq(value, &counter) && value.load(Ordering::Relaxed) == 0
            });
            return PluginResult::Reject {
                status_code: 429,
                body: serde_json::json!({
                    "error": "TCP connection limit exceeded"
                })
                .to_string(),
                headers: HashMap::new(),
            };
        }

        ctx.metadata.insert(METADATA_KEY.to_string(), key);
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if let Some(key) = summary.metadata.get(METADATA_KEY) {
            self.decrement_key(key);
        }
    }
}

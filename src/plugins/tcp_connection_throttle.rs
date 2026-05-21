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
use std::time::Duration;
use tokio::task::JoinHandle;

use super::{Plugin, PluginResult, StreamConnectionContext, StreamTransactionSummary};

const METADATA_KEY: &str = "tcp_connection_throttle.key";

pub struct TcpConnectionThrottle {
    max_connections_per_key: u64,
    active_counts: Arc<DashMap<String, Arc<AtomicU64>>>,
    cleanup_task: Option<JoinHandle<()>>,
}

impl TcpConnectionThrottle {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config.as_object().ok_or_else(|| {
            format!("tcp_connection_throttle: config must be an object, got: {config}")
        })?;
        let max_connections_per_key = parse_required_u64(object, "max_connections_per_key")?;

        if max_connections_per_key == 0 {
            return Err(
                "tcp_connection_throttle: 'max_connections_per_key' must be greater than 0"
                    .to_string(),
            );
        }

        let cleanup_interval_seconds =
            parse_optional_u64(object, "cleanup_interval_seconds")?.unwrap_or(60);

        let active_counts = Arc::new(DashMap::new());

        // Spawn background sweep to remove stale zero-count entries.
        // Normally entries are cleaned in decrement_key(), but this catches
        // edge cases where connections are dropped without on_stream_disconnect.
        // Guard with Handle::try_current() so new() works in non-tokio test contexts.
        let cleanup_task = if cleanup_interval_seconds > 0
            && tokio::runtime::Handle::try_current().is_ok()
        {
            let counts = active_counts.clone();
            Some(tokio::spawn(async move {
                let mut timer =
                    tokio::time::interval(Duration::from_secs(cleanup_interval_seconds));
                loop {
                    timer.tick().await;
                    counts
                        .retain(|_, count: &mut Arc<AtomicU64>| count.load(Ordering::Relaxed) > 0);
                }
            }))
        } else {
            None
        };

        Ok(Self {
            max_connections_per_key,
            active_counts,
            cleanup_task,
        })
    }

    fn throttle_key(&self, ctx: &StreamConnectionContext) -> String {
        match ctx.effective_identity() {
            Some(identity) => {
                let mut key = String::with_capacity(
                    "proxy::consumer:".len() + ctx.proxy_id.len() + identity.len(),
                );
                key.push_str("proxy:");
                key.push_str(&ctx.proxy_id);
                key.push_str(":consumer:");
                key.push_str(identity);
                key
            }
            None => {
                let mut key = String::with_capacity(
                    "proxy::ip:".len() + ctx.proxy_id.len() + ctx.client_ip.len(),
                );
                key.push_str("proxy:");
                key.push_str(&ctx.proxy_id);
                key.push_str(":ip:");
                key.push_str(&ctx.client_ip);
                key
            }
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

impl Drop for TcpConnectionThrottle {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.take() {
            handle.abort();
        }
    }
}

fn parse_required_u64(object: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        format!("tcp_connection_throttle: '{field}' is required and must be a positive integer")
    })
}

fn parse_optional_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("tcp_connection_throttle: '{field}' must be an integer"))
        })
        .transpose()
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
                body: r#"{"error":"TCP connection limit exceeded"}"#.into(),
                headers: HashMap::new(),
            };
        }

        ctx.insert_metadata(METADATA_KEY.to_string(), key);
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if let Some(key) = summary.metadata.get(METADATA_KEY) {
            self.decrement_key(key);
        }
    }
}

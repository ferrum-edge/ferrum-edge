//! TCP-only concurrent connection throttling.
//!
//! Tracks active TCP connections per proxy and observed identity:
//! - authenticated consumer identity when a prior stream auth plugin set one
//! - otherwise the canonical client IP address
//!
//! Accounting is process-local. Each admitted connection owns an opaque permit
//! for the exact map entry it incremented; dropping that permit releases the
//! count exactly once without consulting transaction metadata.

use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::task::JoinHandle;

use super::{Plugin, PluginResult, StreamAdmissionPermit, StreamConnectionContext};

const MAX_CLEANUP_INTERVAL_SECONDS: u64 = 86_400;

struct ConnectionCounter {
    active: AtomicU64,
}

struct CleanupTask {
    interval_seconds: u64,
    handle: Option<JoinHandle<()>>,
}

/// Stable accounting state shared by compatible plugin-cache generations.
pub(crate) struct TcpConnectionThrottleState {
    active_counts: DashMap<String, Arc<ConnectionCounter>>,
    cleanup_task: Mutex<CleanupTask>,
}

impl TcpConnectionThrottleState {
    fn new(pool_shard_amount: usize) -> Arc<Self> {
        let shard_amount = crate::util::sharding::pool_shard_amount(pool_shard_amount);
        Arc::new(Self {
            active_counts: DashMap::with_shard_amount(shard_amount),
            cleanup_task: Mutex::new(CleanupTask {
                interval_seconds: 0,
                handle: None,
            }),
        })
    }

    fn admit(
        &self,
        key: String,
        max_connections_per_key: u64,
    ) -> Option<(String, Arc<ConnectionCounter>)> {
        match self.active_counts.entry(key) {
            Entry::Occupied(entry) => {
                let counter = Arc::clone(entry.get());
                let active = counter.active.load(Ordering::Relaxed);
                if active >= max_connections_per_key {
                    return None;
                }
                // The DashMap entry guard serializes admission and release for
                // this key, so the increment cannot land on a detached entry.
                counter.active.store(active + 1, Ordering::Relaxed);
                Some((entry.key().clone(), counter))
            }
            Entry::Vacant(entry) => {
                let counter = Arc::new(ConnectionCounter {
                    active: AtomicU64::new(1),
                });
                let key = entry.key().clone();
                entry.insert(Arc::clone(&counter));
                Some((key, counter))
            }
        }
    }

    fn release(&self, key: String, counter: Arc<ConnectionCounter>) {
        let Entry::Occupied(entry) = self.active_counts.entry(key) else {
            return;
        };
        if !Arc::ptr_eq(entry.get(), &counter) {
            return;
        }

        let active = counter.active.load(Ordering::Relaxed);
        if active == 0 {
            tracing::warn!(
                plugin = "tcp_connection_throttle",
                "ignored an already-released TCP connection admission permit"
            );
            return;
        }
        if active == 1 {
            // Removal happens while the same shard entry is exclusively held.
            // A concurrent admission therefore observes either this entry
            // before removal or a fresh entry after removal, never both.
            entry.remove();
        } else {
            counter.active.store(active - 1, Ordering::Relaxed);
        }
    }

    fn sweep_residual_zero_entries(&self) {
        self.active_counts
            .retain(|_, counter| counter.active.load(Ordering::Relaxed) > 0);
    }

    pub(crate) fn set_cleanup_interval(self: &Arc<Self>, interval_seconds: u64) {
        let runtime = tokio::runtime::Handle::try_current().ok();
        let mut task = self
            .cleanup_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if task.interval_seconds == interval_seconds
            && (interval_seconds == 0 || task.handle.is_some() || runtime.is_none())
        {
            return;
        }
        if let Some(handle) = task.handle.take() {
            handle.abort();
        }
        task.interval_seconds = interval_seconds;
        let Some(runtime) = runtime.filter(|_| interval_seconds > 0) else {
            return;
        };

        let state: Weak<Self> = Arc::downgrade(self);
        task.handle = Some(runtime.spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(interval_seconds));
            timer.tick().await;
            loop {
                timer.tick().await;
                let Some(state) = state.upgrade() else {
                    return;
                };
                state.sweep_residual_zero_entries();
            }
        }));
    }
}

impl Drop for TcpConnectionThrottleState {
    fn drop(&mut self) {
        let task = self
            .cleanup_task
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = task.handle.take() {
            handle.abort();
        }
    }
}

pub struct TcpConnectionThrottle {
    max_connections_per_key: u64,
    cleanup_interval_seconds: u64,
    state: Arc<TcpConnectionThrottleState>,
}

impl TcpConnectionThrottle {
    pub(crate) fn new_with_pool_shard_amount(
        config: &Value,
        pool_shard_amount: usize,
    ) -> Result<Self, String> {
        let (max_connections_per_key, cleanup_interval_seconds) = parse_config(config)?;
        let state = TcpConnectionThrottleState::new(pool_shard_amount);
        state.set_cleanup_interval(cleanup_interval_seconds);
        Ok(Self {
            max_connections_per_key,
            cleanup_interval_seconds,
            state,
        })
    }

    pub(crate) fn with_shared_state(
        config: &Value,
        state: Arc<TcpConnectionThrottleState>,
    ) -> Result<Self, String> {
        let (max_connections_per_key, cleanup_interval_seconds) = parse_config(config)?;
        Ok(Self {
            max_connections_per_key,
            cleanup_interval_seconds,
            state,
        })
    }

    pub(crate) fn shared_state(&self) -> Arc<TcpConnectionThrottleState> {
        Arc::clone(&self.state)
    }

    pub(crate) fn cleanup_interval_seconds(&self) -> u64 {
        self.cleanup_interval_seconds
    }

    fn throttle_key(&self, ctx: &StreamConnectionContext) -> String {
        let mut proxy_key =
            String::with_capacity(ctx.proxy_namespace.len() + 1 + ctx.proxy_id.len());
        crate::config::db_backend::write_namespaced_runtime_key(
            &mut proxy_key,
            ctx.proxy_namespace.as_str(),
            ctx.proxy_id.as_str(),
        );
        match ctx.effective_identity() {
            Some(identity) => {
                let mut key = String::with_capacity(
                    "proxy::consumer:".len() + proxy_key.len() + identity.len(),
                );
                key.push_str("proxy:");
                key.push_str(&proxy_key);
                key.push_str(":consumer:");
                key.push_str(identity);
                key
            }
            None => {
                let canonical_ip =
                    crate::util::client_identity::canonical_client_ip_text(&ctx.client_ip);
                let mut key = String::with_capacity(
                    "proxy::ip:".len() + proxy_key.len() + canonical_ip.len(),
                );
                key.push_str("proxy:");
                key.push_str(&proxy_key);
                key.push_str(":ip:");
                key.push_str(&canonical_ip);
                key
            }
        }
    }
}

fn parse_config(config: &Value) -> Result<(u64, u64), String> {
    let object = config.as_object().ok_or_else(|| {
        format!("tcp_connection_throttle: config must be an object, got: {config}")
    })?;
    let max_connections_per_key = parse_required_u64(object, "max_connections_per_key")?;
    if max_connections_per_key == 0 {
        return Err(
            "tcp_connection_throttle: 'max_connections_per_key' must be greater than 0".to_string(),
        );
    }
    let cleanup_interval_seconds =
        parse_optional_u64(object, "cleanup_interval_seconds")?.unwrap_or(60);
    if cleanup_interval_seconds > MAX_CLEANUP_INTERVAL_SECONDS {
        return Err(format!(
            "tcp_connection_throttle: 'cleanup_interval_seconds' must be at most {MAX_CLEANUP_INTERVAL_SECONDS}"
        ));
    }
    reject_unknown_fields(object)?;
    Ok((max_connections_per_key, cleanup_interval_seconds))
}

fn reject_unknown_fields(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    let unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|field| {
            !matches!(
                *field,
                "max_connections_per_key" | "cleanup_interval_seconds"
            )
        })
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "tcp_connection_throttle: unknown config field(s): {}",
            unknown.join(", ")
        ))
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
        Some(self.state.active_counts.len())
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let Some((key, counter)) = self
            .state
            .admit(self.throttle_key(ctx), self.max_connections_per_key)
        else {
            return PluginResult::Reject {
                status_code: 429,
                body: r#"{"error":"TCP connection limit exceeded"}"#.into(),
                headers: HashMap::new(),
            };
        };

        let state = Arc::clone(&self.state);
        ctx.add_admission_permit(StreamAdmissionPermit::new(move || {
            state.release(key, counter);
        }));
        PluginResult::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::{TcpConnectionThrottle, TcpConnectionThrottleState};
    use crate::ConsumerIndex;
    use crate::config::types::BackendScheme;
    use crate::plugins::StreamConnectionContext;
    use dashmap::Map;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn throttle_key_scopes_by_proxy_namespace() {
        let plugin = TcpConnectionThrottle::new_with_pool_shard_amount(
            &json!({"max_connections_per_key": 1}),
            0,
        )
        .expect("throttle fixture must construct");
        let consumer_index = Arc::new(ConsumerIndex::new(&[]));
        let mut tenant_a = StreamConnectionContext::new(
            "10.0.0.1".to_string(),
            "10.0.0.1".to_string(),
            "shared-proxy".to_string(),
            Some("Shared Proxy".to_string()),
            15432,
            BackendScheme::Tcp,
            Arc::clone(&consumer_index),
        );
        tenant_a.proxy_namespace = "tenant-a".to_string();
        let mut tenant_b = StreamConnectionContext::new(
            "10.0.0.1".to_string(),
            "10.0.0.1".to_string(),
            "shared-proxy".to_string(),
            Some("Shared Proxy".to_string()),
            15432,
            BackendScheme::Tcp,
            consumer_index,
        );
        tenant_b.proxy_namespace = "tenant-b".to_string();

        assert_ne!(
            plugin.throttle_key(&tenant_a),
            plugin.throttle_key(&tenant_b),
            "proxy_namespace must distinguish throttle keys for the same proxy id"
        );
    }

    #[test]
    fn state_normalizes_pool_shard_amount_for_the_actual_counter_map() {
        for override_value in [0, 1, 3] {
            let state = TcpConnectionThrottleState::new(override_value);
            assert_eq!(
                state.active_counts._shard_count(),
                crate::util::sharding::pool_shard_amount(override_value)
            );
        }
    }
}

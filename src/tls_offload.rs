//! TLS handshake offload runtime for isolating CPU-intensive connection establishment.
//!
//! Creates dedicated single-threaded tokio runtimes for TLS handshakes, preventing
//! them from blocking the main event loop during connection storms (startup warmup,
//! backend failover, burst traffic). Connections are sharded by peer hash for TLS
//! session cache affinity.
//!
//! Inspired by Cloudflare Pingora's `connectors/offload.rs`, which found that
//! "scheduling overhead of multithread tokio runtime can be 50% of the on CPU time."

use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle as ThreadJoinHandle;
use tokio::runtime::Handle;
use tracing::{debug, warn};

/// Configuration for the TLS offload runtime.
#[derive(Debug, Clone)]
pub struct TlsOffloadConfig {
    /// Number of shards (groups of threads). Connections to the same peer
    /// hash to the same shard for TLS session cache affinity.
    pub shards: usize,
    /// Threads per shard. Total threads = shards * threads_per_shard.
    pub threads_per_shard: usize,
}

impl Default for TlsOffloadConfig {
    fn default() -> Self {
        // Default: 2 shards x 1 thread = 2 offload threads.
        // Conservative for most deployments; increase for TLS-heavy workloads.
        Self {
            shards: 2,
            threads_per_shard: 1,
        }
    }
}

/// Pool of single-threaded tokio runtimes for offloading TLS handshakes.
///
/// Each runtime runs on its own OS thread. Connections are sharded by peer hash
/// so that repeat connections to the same backend hit the same thread (improving
/// TLS session ticket reuse). Within a shard, requests are distributed randomly
/// across threads.
pub struct TlsOffloadRuntime {
    /// Handles to the offload runtimes. Length = shards * threads_per_shard.
    handles: Vec<Handle>,
    /// Driver threads that keep each current_thread runtime running.
    /// Each thread calls `Runtime::block_on(pending())` so the reactor
    /// processes spawned tasks. Dropped (joined) when the pool is dropped.
    _driver_threads: Vec<ThreadJoinHandle<()>>,
    /// Number of shards for peer-hash distribution.
    shards: usize,
    /// Threads per shard for intra-shard load balancing.
    threads_per_shard: usize,
}

impl TlsOffloadRuntime {
    /// Create a new offload runtime pool.
    ///
    /// Returns `None` if `shards` or `threads_per_shard` is 0 (disabled).
    pub fn new(config: TlsOffloadConfig) -> Option<Self> {
        if config.shards == 0 || config.threads_per_shard == 0 {
            return None;
        }

        let total = config.shards * config.threads_per_shard;
        let mut handles = Vec::with_capacity(total);
        let mut driver_threads = Vec::with_capacity(total);

        for i in 0..total {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    let handle = rt.handle().clone();
                    handles.push(handle);
                    // Spawn a dedicated OS thread that drives this current_thread runtime.
                    // Without this, the runtime's reactor never runs and spawned tasks stall.
                    let thread = std::thread::Builder::new()
                        .name(format!("tls-offload-{i}"))
                        .spawn(move || {
                            rt.block_on(std::future::pending::<()>());
                        });
                    match thread {
                        Ok(t) => {
                            driver_threads.push(t);
                            debug!("TLS offload thread {}/{} started", i + 1, total);
                        }
                        Err(e) => {
                            warn!("Failed to spawn TLS offload driver thread {}: {}", i, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to create TLS offload runtime {}: {}", i, e);
                    // Continue with fewer threads rather than failing entirely
                }
            }
        }

        if handles.is_empty() {
            warn!("No TLS offload runtimes created, falling back to main runtime");
            return None;
        }

        debug!(
            "TLS offload pool started: {} shards x {} threads = {} total",
            config.shards,
            config.threads_per_shard,
            handles.len()
        );

        Some(Self {
            handles,
            _driver_threads: driver_threads,
            shards: config.shards,
            threads_per_shard: config.threads_per_shard,
        })
    }

    /// Get a runtime handle for the given peer hash.
    ///
    /// Connections to the same peer are routed to the same shard for TLS session
    /// cache affinity. Within the shard, a random thread is selected for load
    /// balancing.
    pub fn get_handle(&self, peer_hash: u64) -> &Handle {
        let shard = (peer_hash as usize) % self.shards;
        let thread_in_shard = if self.threads_per_shard > 1 {
            // Simple counter-based selection within shard
            let counter = peer_hash.wrapping_mul(0x517cc1b727220a95);
            (counter as usize) % self.threads_per_shard
        } else {
            0
        };
        let index = shard * self.threads_per_shard + thread_in_shard;
        // Clamp to valid range (handles may be shorter if some failed to create)
        &self.handles[index % self.handles.len()]
    }

    /// Spawn a future on the offload runtime for the given peer.
    ///
    /// Use this for CPU-intensive operations like TLS handshakes that would
    /// otherwise block the main event loop.
    pub fn spawn<F>(&self, peer_hash: u64, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.get_handle(peer_hash).spawn(future)
    }
}

/// Global TLS offload runtime singleton.
static TLS_OFFLOAD: OnceLock<Option<Arc<TlsOffloadRuntime>>> = OnceLock::new();

/// Initialize the global TLS offload runtime.
///
/// Call once during startup after the main tokio runtime is created.
/// Subsequent calls are no-ops (OnceLock semantics).
pub fn init_tls_offload(config: TlsOffloadConfig) {
    TLS_OFFLOAD.get_or_init(|| TlsOffloadRuntime::new(config).map(Arc::new));
}

/// Get the global TLS offload runtime, if initialized and enabled.
pub fn get_tls_offload() -> Option<&'static Arc<TlsOffloadRuntime>> {
    TLS_OFFLOAD.get().and_then(|opt| opt.as_ref())
}

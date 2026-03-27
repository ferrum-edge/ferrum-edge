//! HTTP/3 configuration types

use std::time::Duration;

/// HTTP/3 server configuration
#[derive(Debug, Clone)]
pub struct Http3ServerConfig {
    /// Maximum concurrent bidirectional streams per connection
    pub max_concurrent_streams: u32,
    /// Connection idle timeout
    pub idle_timeout: Duration,

    // ── QUIC transport tuning ────────────────────────────────────────────
    //
    // Quinn's defaults (~48 KB stream window, 128 KB send window) are
    // conservative.  On modern networks they limit throughput similarly
    // to HTTP/2's small defaults.  These settings let operators raise
    // the limits to match their available bandwidth.
    /// Per-stream receive window in bytes.
    /// Controls how much data a peer can send on a single stream before
    /// the receiver must send a flow-control credit update.
    /// Default: 8 MiB (8_388_608).
    pub stream_receive_window: u64,

    /// Connection-level receive window in bytes.
    /// Aggregate budget shared across all concurrent streams.
    /// Should be ≥ stream_receive_window × expected_concurrency.
    /// Default: 32 MiB (33_554_432).
    pub receive_window: u64,

    /// Per-connection send window in bytes.
    /// Controls how much data can be in flight (sent but unacknowledged)
    /// across all streams on a single QUIC connection.
    /// Default: 8 MiB (8_388_608).
    pub send_window: u64,
}

impl Http3ServerConfig {
    /// Create from environment config
    pub fn from_env_config(env: &crate::config::EnvConfig) -> Self {
        Self {
            max_concurrent_streams: env.http3_max_streams,
            idle_timeout: Duration::from_secs(env.http3_idle_timeout),
            stream_receive_window: env.http3_stream_receive_window,
            receive_window: env.http3_receive_window,
            send_window: env.http3_send_window,
        }
    }
}

impl Default for Http3ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 1000,
            idle_timeout: Duration::from_secs(30),
            stream_receive_window: 8_388_608, // 8 MiB
            receive_window: 33_554_432,       // 32 MiB
            send_window: 8_388_608,           // 8 MiB
        }
    }
}

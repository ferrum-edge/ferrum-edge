//! HTTP/3 configuration types

use std::time::Duration;

use bytes::{Buf, Bytes};

/// Default value for the H3 response streaming coalesce-buffer initial capacity
/// and MIN upper bound (when `FERRUM_HTTP3_COALESCE_MAX_BYTES` is unset).
/// See `FERRUM_HTTP3_COALESCE_MAX_BYTES` for runtime tuning.
pub const H3_COALESCE_MAX_DEFAULT: usize = 32_768;

/// Absolute upper bound operators may set via `FERRUM_HTTP3_COALESCE_MAX_BYTES`.
/// Bounds per-stream memory regardless of configuration.
pub const H3_COALESCE_MAX_CAP: usize = 1_048_576;

/// Absolute lower bound for both MIN and MAX coalesce bytes. Values below this
/// erase the benefit of coalescing entirely.
pub const H3_COALESCE_MIN_FLOOR: usize = 1024;

/// Floor for the H3 response streaming flush interval in microseconds.
/// Values below this would cause the select-loop to flush on almost every poll
/// and erase the benefit of coalescing entirely.
pub const H3_FLUSH_INTERVAL_MIN_MICROS: u64 = 50;

/// Upper bound for the H3 response streaming flush interval in microseconds
/// (100 ms — anything higher is a latency bug, not a tuning knob).
pub const H3_FLUSH_INTERVAL_MAX_MICROS: u64 = 100_000;

/// QUIC minimum initial MTU (per quinn). Lower values are rejected by quinn.
pub const QUIC_INITIAL_MTU_MIN: u16 = 1200;

/// QUIC maximum initial MTU (per quinn — limited by the 16-bit varint space
/// after accounting for UDP/IP headers).
pub const QUIC_INITIAL_MTU_MAX: u16 = 65527;

/// Return true when an H3 response DATA chunk is already large enough to send
/// directly instead of copying it into the coalescing buffer first.
pub(crate) fn should_direct_send_response_chunk(
    buffered_bytes: usize,
    chunk_bytes: usize,
    coalesce_min_bytes: usize,
) -> bool {
    buffered_bytes == 0 && chunk_bytes >= coalesce_min_bytes
}

/// Copy the complete remaining H3 response DATA chunk into `Bytes`.
///
/// `recv_data()` returns `impl Buf`. h3-quinn yields contiguous `Bytes` today,
/// but using `remaining()` + `copy_to_bytes()` keeps accounting and forwarding
/// correct if a future implementation returns a chained/non-contiguous buffer.
pub(crate) fn copy_remaining_response_chunk<B>(chunk: &mut B) -> Bytes
where
    B: Buf,
{
    let chunk_len = chunk.remaining();
    chunk.copy_to_bytes(chunk_len)
}

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

    /// Initial QUIC path MTU in bytes (`TransportConfig::initial_mtu`).
    /// quinn's default is 1200 (the QUIC minimum), which forces ~9 packets
    /// for a 10 KiB payload. 1500 is safe on virtually all modern networks;
    /// quinn uses path-MTU black-hole detection to back off if a smaller MTU
    /// is required. Default: 1500. Legal range: [1200, 65527].
    pub initial_mtu: u16,
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
            initial_mtu: env.http3_initial_mtu,
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
            initial_mtu: 1500,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};

    use super::{copy_remaining_response_chunk, should_direct_send_response_chunk};

    #[test]
    fn direct_send_requires_empty_buffer_and_large_chunk() {
        assert!(should_direct_send_response_chunk(0, 32_768, 32_768));
        assert!(should_direct_send_response_chunk(0, 65_536, 32_768));
        assert!(!should_direct_send_response_chunk(1, 65_536, 32_768));
        assert!(!should_direct_send_response_chunk(0, 32_767, 32_768));
    }

    #[test]
    fn copy_remaining_response_chunk_handles_non_contiguous_bufs() {
        let mut chunk = Bytes::from_static(b"hello, ").chain(Bytes::from_static(b"h3"));

        let copied = copy_remaining_response_chunk(&mut chunk);

        assert_eq!(&copied[..], b"hello, h3");
        assert!(!chunk.has_remaining());
    }
}

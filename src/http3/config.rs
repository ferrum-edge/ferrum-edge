//! HTTP/3 configuration types

use std::time::Duration;

use bytes::{Buf, Bytes};

/// Default HTTP/3 per-stream receive window for backend (client) connections.
/// Larger than quinn's baseline for backend throughput.
pub const H3_STREAM_RECEIVE_WINDOW_DEFAULT: u64 = 8 * 1024 * 1024;

/// Default HTTP/3 connection-level receive window for backend connections.
pub const H3_RECEIVE_WINDOW_DEFAULT: u64 = 32 * 1024 * 1024;

/// Default HTTP/3 send window for backend connections.
pub const H3_SEND_WINDOW_DEFAULT: u64 = 8 * 1024 * 1024;

/// Conservative frontend H3 per-stream receive window for untrusted clients.
pub const H3_FRONTEND_STREAM_RECEIVE_WINDOW: u64 = 256 * 1024; // 256 KiB

/// Conservative frontend H3 connection receive window for untrusted clients.
pub const H3_FRONTEND_RECEIVE_WINDOW: u64 = 2 * 1024 * 1024; // 2 MiB

/// Conservative frontend H3 send window for untrusted clients.
pub const H3_FRONTEND_SEND_WINDOW: u64 = 2 * 1024 * 1024; // 2 MiB

/// Largest value encodable as a QUIC variable-length integer.
pub const QUIC_VARINT_MAX_U64: u64 = (1 << 62) - 1;

const _: () = assert!(H3_STREAM_RECEIVE_WINDOW_DEFAULT <= QUIC_VARINT_MAX_U64);
const _: () = assert!(H3_RECEIVE_WINDOW_DEFAULT <= QUIC_VARINT_MAX_U64);
const _: () = assert!(H3_SEND_WINDOW_DEFAULT <= QUIC_VARINT_MAX_U64);

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

/// Floor applied to the H3 receive-side field-section policy (issue #4261).
///
/// `FERRUM_MAX_HEADER_SIZE_BYTES` is a logical header-bytes limit that an
/// operator may set very low. The advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`
/// and the buffered-frame ceiling derived from it also have to leave room for
/// the peer's SETTINGS and GOAWAY frames on the control stream, so both are
/// floored here. Ferrum's own 431 check still enforces the configured value
/// exactly; this floor only decides when the connection is torn down instead.
pub const H3_MIN_FIELD_SECTION_SIZE: usize = 16 * 1024;

/// Multiplier from the advertised field-section policy to the receive-side
/// buffered non-`DATA` frame ceiling.
///
/// The ceiling has to sit ABOVE the advertised policy: a field section that
/// merely overshoots the operator's limit should still be QPACK-decoded and
/// answered with the graceful `431` in `src/http3/server.rs`, not met with a
/// connection-level abort. A QPACK-encoded HEADERS payload is smaller than the
/// RFC 9114 field-section accounting of the same headers (which adds 32 bytes
/// per field), so 2x leaves the 431 path reachable for any realistic overshoot
/// while still bounding what one stream can buffer.
const H3_BUFFERED_FRAME_LEN_HEADROOM: u64 = 2;

/// Absolute decoded-size cap for an H3 backend response field section.
///
/// QPACK accounts at least 32 bytes per decoded field, so keeping this below
/// `32 * 32_768` also keeps the decoded field count below `HeaderMap`'s fixed
/// 32,768-entry capacity even when the operator configures a very large request
/// header policy.
pub const H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP: u64 = 1024 * 1024 - 1;

/// The `SETTINGS_MAX_FIELD_SECTION_SIZE` the HTTP/3 frontend advertises, in
/// bytes, derived from `FERRUM_MAX_HEADER_SIZE_BYTES` (issue #4261).
///
/// Mirrors what the H1 and H2 frontends already do with the same policy value
/// (`http1_parser_max_buf_size` / `h2_parser_max_header_list_size`). Before
/// this, H3 advertised `VarInt::MAX` while enforcing the configured limit only
/// after a complete QPACK decode.
///
/// Clamped into the QUIC varint range: the value travels the wire as a varint,
/// so an unrepresentable one could not be advertised at all. Clamping only ever
/// NARROWS, never widens; [`validate_h3_field_section_limits`] refuses a
/// configuration where that clamp would silently change the operator's policy.
pub fn h3_max_field_section_size(max_header_size_bytes: usize) -> u64 {
    let floored = max_header_size_bytes.max(H3_MIN_FIELD_SECTION_SIZE);
    u64::try_from(floored)
        .unwrap_or(QUIC_VARINT_MAX_U64)
        .min(QUIC_VARINT_MAX_U64)
}

/// The receive-side ceiling, in bytes, on the DECLARED payload length of a
/// buffered non-`DATA` HTTP/3 frame (issue #4261).
///
/// Handed to the vendored h3 `server::builder().max_buffered_frame_len(...)`
/// and to every production pooled H3 backend-client builder.
/// A HEADERS, SETTINGS, GOAWAY, PUSH_PROMISE, or unknown frame declaring more
/// than this is refused with `H3_EXCESSIVE_LOAD` as soon as its length varint
/// is decoded, before any payload byte is buffered. `DATA` frames are never
/// bounded by it — request bodies stream and keep their existing body policy.
pub fn h3_max_buffered_frame_len(max_header_size_bytes: usize) -> u64 {
    h3_max_field_section_size(max_header_size_bytes)
        .saturating_mul(H3_BUFFERED_FRAME_LEN_HEADROOM)
        .min(QUIC_VARINT_MAX_U64)
}

/// Decoded field-section ceiling for responses received from H3 backends.
///
/// This is deliberately distinct from the frontend request-header policy: an
/// upstream response may legitimately be larger than the configured request
/// limit. It must nevertheless be finite because QPACK can expand a compact
/// encoded block into enough fields to exceed `http::HeaderMap`'s capacity.
/// Using the already-bounded non-`DATA` frame ceiling preserves that response
/// headroom while stopping hostile expansion during QPACK decoding.
pub fn h3_backend_response_max_field_section_size(max_header_size_bytes: usize) -> u64 {
    h3_max_buffered_frame_len(max_header_size_bytes).min(H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP)
}

/// Refuse a `FERRUM_MAX_HEADER_SIZE_BYTES` the HTTP/3 frontend could not
/// enforce as configured (issue #4261).
///
/// Both derived values are QUIC varints. A configured header limit above the
/// varint range would be silently clamped, so the advertised SETTINGS and the
/// buffered-frame ceiling would no longer be the operator's policy. That is a
/// configuration error, not something to absorb: the H1 and H2 frontends would
/// still enforce the configured value and the three frontends would disagree.
pub fn validate_h3_field_section_limits(max_header_size_bytes: usize) -> Result<(), String> {
    // The ceiling is the widest derived value, so bounding it bounds both.
    let representable = u64::try_from(max_header_size_bytes.max(H3_MIN_FIELD_SECTION_SIZE))
        .ok()
        .and_then(|floored| floored.checked_mul(H3_BUFFERED_FRAME_LEN_HEADROOM))
        .is_some_and(|ceiling| ceiling <= QUIC_VARINT_MAX_U64);
    if !representable {
        return Err(format!(
            "FERRUM_MAX_HEADER_SIZE_BYTES ({}) is too large for the HTTP/3 frontend: the \
             advertised SETTINGS_MAX_FIELD_SECTION_SIZE and the receive-side buffered-frame \
             ceiling derived from it must both fit in a QUIC variable-length integer (at most \
             {}).",
            max_header_size_bytes,
            QUIC_VARINT_MAX_U64 / H3_BUFFERED_FRAME_LEN_HEADROOM
        ));
    }
    Ok(())
}

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

/// Convert an operator-supplied QUIC flow-control window into a VarInt,
/// falling back to the compiled default if the supplied value exceeds QUIC's
/// legal varint range.
pub(crate) fn quic_varint_or_default(value: u64, default_value: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(value).unwrap_or_else(|_| {
        debug_assert!(default_value <= QUIC_VARINT_MAX_U64);
        quinn::VarInt::from_u64(default_value).unwrap_or(quinn::VarInt::MAX)
    })
}

/// HTTP/3 server configuration
#[derive(Debug, Clone)]
pub struct Http3ServerConfig {
    /// Maximum concurrent bidirectional streams per connection
    pub max_concurrent_streams: u32,
    /// Connection idle timeout exactly as `FERRUM_HTTP3_IDLE_TIMEOUT`
    /// configures it. This is the value the H3 **backend** pools use.
    pub idle_timeout: Duration,
    /// The QUIC `max_idle_timeout` the HTTP/3 **frontend** listener installs.
    ///
    /// Identical to [`Self::idle_timeout`] except when the RFC 9298 CONNECT-UDP
    /// profile is enabled, where it is raised to at least
    /// `FERRUM_HTTP3_CONNECT_UDP_IDLE_TIMEOUT_SECONDS`. A CONNECT-UDP tunnel
    /// lives on a stream of one QUIC connection and an idle tunnel generates no
    /// QUIC activity, so a smaller connection idle limit would close the tunnel
    /// before its own idle bound could ever be reached — with the shipped
    /// defaults, a 120-second tunnel terminated at 30 by a different
    /// gateway-owned timer. The derivation only ever raises, never lowers, and
    /// leaves the "0 disables the idle timer" semantic intact; see
    /// [`crate::config::EnvConfig::effective_http3_idle_timeout_seconds`].
    pub frontend_idle_timeout: Duration,
    /// Maximum time a QUIC handshake may take before the in-progress connection
    /// is aborted. Mirrors the TCP/TLS and DTLS frontend handshake bounds and
    /// is sourced from `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`.
    /// `Duration::ZERO` disables the bound (matches the "0 disables" semantic
    /// shared by the TCP/TLS and DTLS frontends).
    pub handshake_timeout: Duration,

    // ── QUIC transport tuning ────────────────────────────────────────────
    //
    // Quinn's defaults (~48 KB stream window, 128 KB send window) are
    // conservative.  On modern networks they limit throughput similarly
    // to HTTP/2's small defaults.  These settings let operators raise
    // the limits to match their available bandwidth.
    /// Per-stream receive window in bytes.
    /// Controls how much data a peer can send on a single stream before
    /// the receiver must send a flow-control credit update.
    /// Default: 16 MiB (16_777_216).
    pub stream_receive_window: u64,

    /// Connection-level receive window in bytes.
    /// Aggregate budget shared across all concurrent streams.
    /// Should be ≥ stream_receive_window × expected_concurrency.
    /// Default: 128 MiB (134_217_728).
    pub receive_window: u64,

    /// Per-connection send window in bytes.
    /// Controls how much data can be in flight (sent but unacknowledged)
    /// across all streams on a single QUIC connection.
    /// Default: 64 MiB (67_108_864).
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
            frontend_idle_timeout: Duration::from_secs(env.effective_http3_idle_timeout_seconds()),
            stream_receive_window: env.http3_stream_receive_window,
            receive_window: env.http3_receive_window,
            send_window: env.http3_send_window,
            initial_mtu: env.http3_initial_mtu,
            handshake_timeout: Duration::from_secs(env.frontend_tls_handshake_timeout_seconds),
        }
    }

    /// Whether the RFC 9298 CONNECT-UDP idle bound actually raised the
    /// frontend's QUIC idle timeout above the configured
    /// `FERRUM_HTTP3_IDLE_TIMEOUT`.
    ///
    /// The listener logs this so the derivation is never silent: an operator
    /// who set a smaller QUIC idle timeout is told which value the transport
    /// installed and why.
    pub fn connect_udp_raised_frontend_idle_timeout(&self) -> bool {
        self.frontend_idle_timeout > self.idle_timeout
    }
}

impl Default for Http3ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 1000,
            idle_timeout: Duration::from_secs(30),
            // CONNECT-UDP defaults to off, so the frontend value defaults to
            // the configured one.
            frontend_idle_timeout: Duration::from_secs(30),
            stream_receive_window: H3_FRONTEND_STREAM_RECEIVE_WINDOW,
            receive_window: H3_FRONTEND_RECEIVE_WINDOW,
            send_window: H3_FRONTEND_SEND_WINDOW,
            initial_mtu: 1500,
            // Default mirrors `EnvConfig::default().frontend_tls_handshake_timeout_seconds`
            // (10 seconds). `Duration::ZERO` here would silently disable the bound.
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};

    use super::{
        H3_RECEIVE_WINDOW_DEFAULT, copy_remaining_response_chunk, quic_varint_or_default,
        should_direct_send_response_chunk,
    };

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

    #[test]
    fn quic_varint_falls_back_when_value_exceeds_quic_range() {
        assert_eq!(
            quic_varint_or_default(u64::MAX, H3_RECEIVE_WINDOW_DEFAULT),
            quinn::VarInt::from_u64(H3_RECEIVE_WINDOW_DEFAULT).unwrap()
        );
    }

    #[test]
    fn quic_varint_fallback_does_not_truncate_large_defaults() {
        let default_above_u32 = u64::from(u32::MAX) + 1;

        assert_eq!(
            quic_varint_or_default(u64::MAX, default_above_u32),
            quinn::VarInt::from_u64(default_above_u32).unwrap()
        );
    }
}

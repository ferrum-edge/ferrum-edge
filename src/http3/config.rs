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

/// `http::HeaderMap`'s largest constructible capacity, in entries (issue #4538).
///
/// `HeaderMap::with_capacity(n)` is `try_with_capacity(n).expect(..)`, and
/// `try_with_capacity` computes `to_raw_capacity(n) = n + n / 3`, rounds it up
/// with `checked_next_power_of_two()`, and refuses once the result exceeds
/// `MAX_SIZE = 1 << 15`. So `24_576` -> raw `32_768` -> `32_768` (accepted) and
/// `24_577` -> raw `32_769` -> `65_536` (refused). The ceiling is 24,576
/// entries, NOT the 32,768 `MAX_SIZE` constant it is derived from.
///
/// The vendored h3 builds every request and response head with
/// `HeaderMap::with_capacity(headers.len())` on the RAW decoded field vector
/// (`vendor/h3-0.0.8-ferrum-patched/src/proto/headers.rs`, `impl
/// TryFrom<Vec<HeaderField>> for Header`), before any per-field validation and
/// before Ferrum's own 431 check. A decoded field count above this ceiling
/// therefore aborts the whole gateway process under `panic = "abort"`.
pub const H3_HEADER_MAP_MAX_FIELDS: u64 = 24_576;

/// Margin, in fields, held below [`H3_HEADER_MAP_MAX_FIELDS`].
///
/// QPACK's per-field accounting is a *minimum* of 32 bytes, so a byte cap
/// derived from it is already conservative; the margin covers pseudo-header
/// expansion in `Header::try_from` and any future change to the accounting
/// constant, and keeps the derived byte cap a round number.
const H3_FIELD_COUNT_MARGIN: u64 = 576;

/// QPACK `ESTIMATED_OVERHEAD_BYTES` — the RFC 9204 per-field accounting floor
/// (`vendor/h3-0.0.8-ferrum-patched/src/qpack/field.rs`). The QPACK decoder
/// bounds only the accumulated `mem_size`, never the field count, and each
/// field accounts `name.len() + value.len() + 32`, so the number of fields
/// handed to `Header::try_from` is exactly bounded by `floor(max_size / 32)`.
const H3_QPACK_PER_FIELD_ACCOUNTING_BYTES: u64 = 32;

/// Absolute decoded-size cap, in bytes, for ANY H3 field section — frontend
/// request policy and backend response policy alike (issue #4538).
///
/// Derived from the real bound rather than restated: at 32 accounted bytes per
/// field, `(24_576 - 576) * 32` = 768,000 bytes admits at most 24,000 decoded
/// fields, which is 576 below [`H3_HEADER_MAP_MAX_FIELDS`]. Every field section
/// the QPACK decoder can hand to `Header::try_from` is therefore constructible,
/// so the `expect` inside `HeaderMap::with_capacity` is unreachable from the
/// network.
pub const H3_FIELD_SECTION_SIZE_CAP: u64 =
    (H3_HEADER_MAP_MAX_FIELDS - H3_FIELD_COUNT_MARGIN) * H3_QPACK_PER_FIELD_ACCOUNTING_BYTES;

/// Absolute decoded-size cap for an H3 backend response field section.
///
/// The backend response policy is bounded by the same field-count ceiling as
/// the frontend request policy: a hostile or compromised upstream is as able to
/// emit 24,577 empty QPACK literals as an unauthenticated client is.
pub const H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP: u64 = H3_FIELD_SECTION_SIZE_CAP;

const _: () = assert!(H3_FIELD_SECTION_SIZE_CAP <= QUIC_VARINT_MAX_U64);
const _: () = assert!(H3_MIN_FIELD_SECTION_SIZE as u64 <= H3_FIELD_SECTION_SIZE_CAP);

/// The `SETTINGS_MAX_FIELD_SECTION_SIZE` the HTTP/3 frontend advertises, in
/// bytes, derived from `FERRUM_MAX_HEADER_SIZE_BYTES` (issue #4261).
///
/// Mirrors what the H1 and H2 frontends already do with the same policy value
/// (`http1_parser_max_buf_size` / `h2_parser_max_header_list_size`). Before
/// this, H3 advertised `VarInt::MAX` while enforcing the configured limit only
/// after a complete QPACK decode.
///
/// Clamped into the QUIC varint range: the value travels the wire as a varint,
/// so an unrepresentable one could not be advertised at all. Also capped at
/// [`H3_FIELD_SECTION_SIZE_CAP`] so the decoded field count stays below
/// [`H3_HEADER_MAP_MAX_FIELDS`] (issue #4538) — without that cap an
/// unauthenticated client could drive the vendored h3 into
/// `HeaderMap::with_capacity`'s `expect`, which is a process abort.
///
/// Both clamps only ever NARROW, never widen;
/// [`validate_h3_field_section_limits`] refuses a configuration where either
/// would silently change the operator's policy.
pub fn h3_max_field_section_size(max_header_size_bytes: usize) -> u64 {
    let floored = max_header_size_bytes.max(H3_MIN_FIELD_SECTION_SIZE);
    u64::try_from(floored)
        .unwrap_or(QUIC_VARINT_MAX_U64)
        .min(QUIC_VARINT_MAX_U64)
        .min(H3_FIELD_SECTION_SIZE_CAP)
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
/// encoded block into enough fields to exceed `http::HeaderMap`'s largest
/// constructible capacity ([`H3_HEADER_MAP_MAX_FIELDS`]). Using the
/// already-bounded non-`DATA` frame ceiling preserves that response headroom,
/// and [`H3_BACKEND_RESPONSE_FIELD_SECTION_SIZE_CAP`] stops hostile expansion
/// short of the field-count ceiling during QPACK decoding.
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
///
/// The same contract now covers the field-count bound (issue #4538): a header
/// policy above [`H3_FIELD_SECTION_SIZE_CAP`] is capped by
/// [`h3_max_field_section_size`] rather than advertised, for the same reason —
/// the advertised SETTINGS would no longer be the operator's policy. Whichever
/// of the two bounds is tighter decides; the field-count cap always is, so the
/// varint branch is kept only so the arithmetic reason survives a future change
/// to either constant.
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

    let within_field_count_bound = u64::try_from(max_header_size_bytes)
        .is_ok_and(|configured| configured <= H3_FIELD_SECTION_SIZE_CAP);
    if within_field_count_bound {
        return Ok(());
    }

    Err(format!(
        "FERRUM_MAX_HEADER_SIZE_BYTES ({max_header_size_bytes}) is too large for the HTTP/3 \
         frontend: it must be at most {H3_FIELD_SECTION_SIZE_CAP} bytes. QPACK accounts at \
         least {H3_QPACK_PER_FIELD_ACCOUNTING_BYTES} bytes per decoded field and bounds only \
         the accumulated size, so a larger field-section policy would admit more than \
         {H3_HEADER_MAP_MAX_FIELDS} decoded fields, which is more than `http::HeaderMap` can \
         be constructed with. Above this bound the advertised \
         SETTINGS_MAX_FIELD_SECTION_SIZE would have to be capped and would no longer be the \
         operator's policy."
    ))
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
    /// configures it. This is the value the H3 **backend** pools install on
    /// their `quinn::TransportConfig` (issue #4756); `Duration::ZERO` disables
    /// the idle timer (RFC 9000 §10.1). See
    /// [`H3BackendTransportParams::resolve`].
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
    //
    // The windows are split by TRUST PLANE (issue #4755). The `*_window`
    // fields below govern only the FRONTEND listener, which serves untrusted
    // clients and is therefore deliberately conservative; the
    // `backend_*_window` fields govern the gateway's own H3 connections to
    // upstreams. One triple for both planes meant that restoring backend
    // throughput also re-opened the frontend amplification exposure.
    /// Per-stream receive window in bytes for the **frontend** listener
    /// (`FERRUM_HTTP3_STREAM_RECEIVE_WINDOW`).
    /// Controls how much data a peer can send on a single stream before
    /// the receiver must send a flow-control credit update.
    /// Default: [`H3_FRONTEND_STREAM_RECEIVE_WINDOW`] (256 KiB).
    pub stream_receive_window: u64,

    /// Connection-level receive window in bytes for the **frontend** listener
    /// (`FERRUM_HTTP3_RECEIVE_WINDOW`).
    /// Aggregate budget shared across all concurrent streams.
    /// Should be ≥ stream_receive_window × expected_concurrency.
    /// Default: [`H3_FRONTEND_RECEIVE_WINDOW`] (2 MiB).
    pub receive_window: u64,

    /// Per-connection send window in bytes for the **frontend** listener
    /// (`FERRUM_HTTP3_SEND_WINDOW`).
    /// Controls how much data can be in flight (sent but unacknowledged)
    /// across all streams on a single QUIC connection.
    /// Default: [`H3_FRONTEND_SEND_WINDOW`] (2 MiB).
    pub send_window: u64,

    /// Per-stream receive window in bytes for **backend** pool connections
    /// (`FERRUM_HTTP3_BACKEND_STREAM_RECEIVE_WINDOW`).
    /// Default: [`H3_STREAM_RECEIVE_WINDOW_DEFAULT`] (8 MiB).
    pub backend_stream_receive_window: u64,

    /// Connection-level receive window in bytes for **backend** pool
    /// connections (`FERRUM_HTTP3_BACKEND_RECEIVE_WINDOW`). This is the
    /// aggregate governor for every multiplexed stream on one backend QUIC
    /// connection. Default: [`H3_RECEIVE_WINDOW_DEFAULT`] (32 MiB).
    pub backend_receive_window: u64,

    /// Per-connection send window in bytes for **backend** pool connections
    /// (`FERRUM_HTTP3_BACKEND_SEND_WINDOW`).
    /// Default: [`H3_SEND_WINDOW_DEFAULT`] (8 MiB).
    pub backend_send_window: u64,

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
            backend_stream_receive_window: env.http3_backend_stream_receive_window,
            backend_receive_window: env.http3_backend_receive_window,
            backend_send_window: env.http3_backend_send_window,
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
            backend_stream_receive_window: H3_STREAM_RECEIVE_WINDOW_DEFAULT,
            backend_receive_window: H3_RECEIVE_WINDOW_DEFAULT,
            backend_send_window: H3_SEND_WINDOW_DEFAULT,
            initial_mtu: 1500,
            // Default mirrors `EnvConfig::default().frontend_tls_handshake_timeout_seconds`
            // (10 seconds). `Duration::ZERO` here would silently disable the bound.
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

/// The QUIC transport parameters every HTTP/3 **backend** pool connection
/// installs (issues #4755 and #4756).
///
/// Resolved as plain data so the three backend constructors in
/// `crate::http3::client` share ONE derivation and cannot drift, and so the
/// resolved values are assertable: `quinn::TransportConfig`'s fields are
/// private, so "the backend pool carries the backend windows and the
/// configured idle timeout" is only checkable about the input otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H3BackendTransportParams {
    /// Initial QUIC path MTU (`FERRUM_HTTP3_INITIAL_MTU`, shared with the
    /// frontend listener — it is a path property, not a trust-plane budget).
    pub initial_mtu: u16,
    /// Per-stream receive window from
    /// `FERRUM_HTTP3_BACKEND_STREAM_RECEIVE_WINDOW`.
    pub stream_receive_window: quinn::VarInt,
    /// Connection-level receive window from `FERRUM_HTTP3_BACKEND_RECEIVE_WINDOW`.
    pub receive_window: quinn::VarInt,
    /// Connection-level send window from `FERRUM_HTTP3_BACKEND_SEND_WINDOW`.
    pub send_window: u64,
    /// `max_idle_timeout` from `FERRUM_HTTP3_IDLE_TIMEOUT`.
    ///
    /// `None` when the operator configured `0`, which disables the idle timer
    /// (RFC 9000 §10.1) — quinn treats `None` and `Some(0)` identically in
    /// `negotiate_max_idle_timeout`, and `None` is the representation that
    /// says so. Before issue #4756 the backend pools set nothing here at all,
    /// so quinn-proto's 30 s default applied and — because RFC 9000 §10.1
    /// negotiates the MINIMUM of the two endpoints' values — no larger
    /// configured timeout could ever take effect.
    pub max_idle_timeout: Option<quinn::IdleTimeout>,
}

impl H3BackendTransportParams {
    /// Derive the backend transport parameters from the H3 configuration.
    ///
    /// Fails only when the configured idle timeout cannot be encoded as a QUIC
    /// variable-length integer of milliseconds; the windows fall back to the
    /// compiled backend defaults through `quic_varint_or_default` exactly as
    /// the frontend listener's do.
    pub fn resolve(cfg: &Http3ServerConfig) -> Result<Self, anyhow::Error> {
        let max_idle_timeout: Option<quinn::IdleTimeout> = if cfg.idle_timeout.is_zero() {
            None
        } else {
            Some(
                quinn::IdleTimeout::try_from(cfg.idle_timeout)
                    .map_err(|e| anyhow::anyhow!("Invalid HTTP/3 backend idle timeout: {}", e))?,
            )
        };

        Ok(Self {
            initial_mtu: cfg.initial_mtu,
            stream_receive_window: quic_varint_or_default(
                cfg.backend_stream_receive_window,
                H3_STREAM_RECEIVE_WINDOW_DEFAULT,
            ),
            receive_window: quic_varint_or_default(
                cfg.backend_receive_window,
                H3_RECEIVE_WINDOW_DEFAULT,
            ),
            send_window: cfg.backend_send_window,
            max_idle_timeout,
        })
    }

    /// Install these parameters on a `quinn::TransportConfig`.
    pub fn apply(&self, transport_config: &mut quinn::TransportConfig) {
        transport_config.initial_mtu(self.initial_mtu);
        transport_config.stream_receive_window(self.stream_receive_window);
        transport_config.receive_window(self.receive_window);
        transport_config.send_window(self.send_window);
        transport_config.max_idle_timeout(self.max_idle_timeout);
    }
}

/// Build the `quinn::TransportConfig` shared by every H3 backend pool
/// connection.
///
/// The single construction site for backend QUIC transport tuning: the pooled
/// direct-backend constructor, the explicit-target/retry constructor, and the
/// standalone `Http3Client` all call it, so no backend dial can silently
/// inherit quinn's defaults again.
pub fn build_backend_transport_config(
    cfg: &Http3ServerConfig,
) -> Result<quinn::TransportConfig, anyhow::Error> {
    let mut transport_config = quinn::TransportConfig::default();
    H3BackendTransportParams::resolve(cfg)?.apply(&mut transport_config);
    Ok(transport_config)
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

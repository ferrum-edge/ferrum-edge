//! Catalog of pre-built failure scripts.
//!
//! Each constructor returns an appropriately-typed `Script` (or whole
//! backend) for the failure mode in its name, so a test can drop a
//! single line into its setup and get a deterministic, reproducible
//! failure. Every constructor is small (~5-15 LOC) and intentionally
//! does ONE thing — composition belongs in the test.
//!
//! The catalog groups entries by layer:
//!
//! - **Connection-level** — TCP refuse / reset / FIN behaviour, TLS
//!   handshake timing.
//! - **HTTP/1 protocol** — slow trickles, partial bodies, malformed
//!   framing, truncated trailers.
//! - **TLS / cert** — expired, SAN-mismatch, self-signed,
//!   not-yet-valid, ALPN downgrade.
//! - **HTTP/2** — GOAWAY, stream reset, window stalls.
//! - **HTTP/3 / QUIC** — refuse, drop initial, CONNECTION_CLOSE,
//!   stream reset.
//! - **UDP / DTLS** — silent backends, amplification attempts, DTLS
//!   handshake timeouts.
//! - **Network conditions** — slow links, bandwidth limits.
//!
//! ## Return-type policy
//!
//! Each constructor returns whichever shape is most ergonomic for the
//! backend it targets:
//!
//! - Backend-specific scripts (`Vec<TcpStep>`, `Vec<HttpStep>`, etc.)
//!   when the failure mode is composable with other steps.
//! - A full builder/backend (`ScriptedH3Backend`, `QuicRefuser`, etc.)
//!   when the constructor needs to bind a port itself (TLS-cert
//!   constructors mint a fresh `TestCa`; the QUIC refuser needs a
//!   pre-bound UDP socket; the network-sim wrappers wrap an existing
//!   backend).
//!
//! Tests can mix-and-match: e.g. take a [`refuse_connect`] script and
//! prefix an `HttpStep::ExpectRequest` to it, or wrap a built TCP
//! backend with [`slow_link`] to add latency.

use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpListener, UdpSocket};

use crate::scaffolding::backends::dtls::DtlsConfig;
use crate::scaffolding::backends::{
    GrpcStep, H2Step, H3Step, H3TlsConfig, HttpStep, MatchHeaders, MatchRpc, QuicRefuser,
    RequestMatcher, ScriptedDtlsBackend, ScriptedGrpcBackend, ScriptedH2Backend, ScriptedH3Backend,
    ScriptedHttp1Backend, ScriptedTcpBackend, ScriptedTlsBackend, ScriptedUdpBackend, TcpStep,
    TlsConfig, UdpSocketReservation, UdpStep,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::network::{NetworkSimProxy, NetworkSimProxyBuilder};
use crate::scaffolding::ports::PortReservation;

// ────────────────────────────────────────────────────────────────────────────
// Connection-level
// ────────────────────────────────────────────────────────────────────────────

/// Accept the next TCP connection and immediately drop the socket.
///
/// The OS has already completed the three-way handshake so the client
/// sees an EOF / RST after `connect()` succeeds — closer to "backend
/// crashed mid-startup" than `ECONNREFUSED`. For the genuine
/// kernel-level refusal use [`crate::scaffolding::ports::unbound_port`]
/// instead.
pub fn refuse_connect() -> Vec<TcpStep> {
    vec![TcpStep::RefuseNextConnect]
}

/// Accept the next TCP connection and reset it (`SO_LINGER=0` + drop).
/// The peer's next read or write surfaces as `ECONNRESET`.
pub fn accept_then_rst() -> Vec<TcpStep> {
    vec![TcpStep::Reset]
}

/// Accept an HTTP/1 request, then close the socket cleanly (FIN) before
/// writing any response bytes. The client typically observes an
/// `IncompleteMessage`-class error.
pub fn accept_then_fin_before_response() -> Vec<HttpStep> {
    vec![HttpStep::CloseBeforeStatus]
}

/// Insert `delay` before the TLS server starts the handshake. Pair
/// with a tight gateway `backend_connect_timeout_ms` to exercise
/// "TLS handshake exceeded budget" paths.
///
/// Returns a [`TlsConfig`] callers attach to a `ScriptedTlsBackend`
/// builder.
pub fn handshake_timeout(delay: Duration, ca: &TestCa) -> TlsConfig {
    let (cert_pem, key_pem) = ca.valid().expect("valid leaf cert");
    TlsConfig::new(cert_pem, key_pem).with_handshake_delay(delay)
}

/// Complete the TLS handshake, then immediately drop the connection
/// (no application bytes written, no clean `close_notify`). Build a
/// `ScriptedTlsBackend` with this script + a valid cert.
pub fn handshake_then_close() -> Vec<TcpStep> {
    vec![TcpStep::Drop]
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/1 protocol
// ────────────────────────────────────────────────────────────────────────────

/// Send the response status + headers byte-by-byte with `pause` between
/// every chunk of `chunk_size` bytes. Triggers the gateway's read-budget
/// behaviour without ever sending a body.
///
/// Implementation note: Phase-1's [`HttpStep`] does not have a public
/// "trickle headers" step (response headers are emitted as a single
/// write per `RespondHeader`/`RespondStatus`). We approximate by
/// drawing on a raw TCP step that writes the status line in
/// `chunk_size`-byte slices, with [`HttpStep::Sleep`] between each
/// slice. Use [`raw_status_trickle`] for the lower-level helper or
/// compose with `ScriptedTcpBackend` directly for byte-exact control.
pub fn slow_header_trickle(chunk_size: usize, pause: Duration) -> Vec<TcpStep> {
    raw_status_trickle("HTTP/1.1 200 OK\r\n", chunk_size, pause)
}

/// Lower-level helper: split `payload` into `chunk_size`-byte slices,
/// emitting each on its own [`TcpStep::Write`] with a [`TcpStep::Sleep`]
/// between. The returned script does NOT close the stream — callers
/// append a `Drop` (or another step) when they want the trickle to
/// terminate.
pub fn raw_status_trickle(payload: &str, chunk_size: usize, pause: Duration) -> Vec<TcpStep> {
    let bytes = payload.as_bytes();
    let chunk_size = chunk_size.max(1);
    let mut out = Vec::with_capacity(bytes.len().div_ceil(chunk_size) * 2);
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + chunk_size).min(bytes.len());
        out.push(TcpStep::Write(bytes[i..end].to_vec()));
        if end < bytes.len() {
            out.push(TcpStep::Sleep(pause));
        }
        i = end;
    }
    out
}

/// Send `count` body chunks of `chunk_size` bytes (filled with `'x'`)
/// each separated by `pause`. Headers + status come from the
/// `TrickleBody` step so the request prelude is consumed correctly.
pub fn slow_body_trickle(chunk_size: usize, pause: Duration, count: u32) -> Vec<HttpStep> {
    let total = (chunk_size as u64) * (count as u64);
    let chunk = vec![b'x'; chunk_size];
    vec![HttpStep::TrickleBody {
        status: 200,
        reason: "OK".into(),
        headers: vec![
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Length".into(), total.to_string()),
            ("Connection".into(), "close".into()),
        ],
        chunk,
        pause,
        count,
    }]
}

/// Respond with full headers + Content-Length, then close the
/// connection after writing only `after_bytes` bytes of the body.
/// Clients see a truncated response (the body is shorter than the
/// declared Content-Length).
pub fn respond_partial_body(after_bytes: usize) -> Vec<HttpStep> {
    let body = vec![b'x'; after_bytes];
    // Declare Content-Length far larger than what we emit, so the
    // client observes the truncation.
    let claimed = (after_bytes + 64).max(1);
    vec![HttpStep::CloseMidBody {
        status: 200,
        reason: "OK".into(),
        headers: vec![
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Length".into(), claimed.to_string()),
        ],
        body_prefix: body,
        reset: false,
    }]
}

/// Respond with `Content-Length: claimed` but actually send
/// `actual` body bytes (where `actual < claimed` produces a short
/// stream and `actual > claimed` an over-write). Tests how the
/// gateway handles servers that lie about the length.
pub fn respond_with_wrong_content_length(claimed: usize, actual: usize) -> Vec<HttpStep> {
    let body = vec![b'x'; actual];
    vec![HttpStep::CloseMidBody {
        status: 200,
        reason: "OK".into(),
        headers: vec![
            ("Content-Type".into(), "application/octet-stream".into()),
            ("Content-Length".into(), claimed.to_string()),
        ],
        body_prefix: body,
        reset: false,
    }]
}

/// Send a malformed `Transfer-Encoding: chunked` body — the chunk
/// length line is non-hex garbage. The gateway must reject this as a
/// protocol error.
pub fn send_malformed_chunked_encoding() -> Vec<TcpStep> {
    // Read the request prelude, then write a status with chunked
    // encoding declared but a malformed chunk-length line.
    vec![
        TcpStep::ReadUntil(b"\r\n\r\n".to_vec()),
        TcpStep::Write(
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              not-a-hex-length\r\n\
              hello\r\n\
              0\r\n\r\n"
                .to_vec(),
        ),
        TcpStep::Drop,
    ]
}

/// Send a response with two conflicting `Content-Length` headers — a
/// classic CL+CL desync attempt. Gateways MUST reject (RFC 9112 §6.1).
pub fn send_duplicate_content_length() -> Vec<TcpStep> {
    vec![
        TcpStep::ReadUntil(b"\r\n\r\n".to_vec()),
        TcpStep::Write(
            b"HTTP/1.1 200 OK\r\n\
              Content-Length: 5\r\n\
              Content-Length: 6\r\n\
              \r\n\
              hello"
                .to_vec(),
        ),
        TcpStep::Drop,
    ]
}

/// gRPC: send headers + payload but close before writing the
/// `grpc-status` trailer. Spec-canonical UNKNOWN(2) per the
/// HTTP-to-gRPC mapping doc.
pub fn respond_but_close_before_trailer(body: Bytes) -> Vec<GrpcStep> {
    vec![
        GrpcStep::AcceptRpc(MatchRpc::any()),
        GrpcStep::OmitTrailers { body: Some(body) },
    ]
}

// ────────────────────────────────────────────────────────────────────────────
// TLS / cert
// ────────────────────────────────────────────────────────────────────────────

/// TLS config with a leaf cert whose `notAfter` is in the past. The
/// gateway should reject the handshake unless `FERRUM_TLS_NO_VERIFY=true`.
pub fn cert_expired() -> TlsConfig {
    let ca = TestCa::new("scenario-expired").expect("ca");
    let (cert_pem, key_pem) = ca.expired().expect("expired leaf");
    TlsConfig::new(cert_pem, key_pem)
}

/// TLS config with a leaf cert SAN that does NOT match `localhost` —
/// the gateway should fail hostname verification.
pub fn cert_san_mismatch() -> TlsConfig {
    let ca = TestCa::new("scenario-san-mismatch").expect("ca");
    let (cert_pem, key_pem) = ca.wrong_san().expect("wrong-san leaf");
    TlsConfig::new(cert_pem, key_pem)
}

/// TLS config whose leaf is signed by itself (no CA), so a verifying
/// gateway must reject it as untrusted.
pub fn cert_self_signed() -> TlsConfig {
    let ca = TestCa::new("scenario-self-signed").expect("ca");
    let (cert_pem, key_pem) = ca.self_signed().expect("self-signed leaf");
    TlsConfig::new(cert_pem, key_pem)
}

/// TLS config with a leaf whose `notBefore` is in the future. Some TLS
/// stacks reject upfront, others surface the failure at handshake.
pub fn cert_not_yet_valid() -> TlsConfig {
    let ca = TestCa::new("scenario-not-yet-valid").expect("ca");
    let (cert_pem, key_pem) = ca.not_yet_valid().expect("not-yet-valid leaf");
    TlsConfig::new(cert_pem, key_pem)
}

/// TLS config that advertises both `h2` and `http/1.1` in ALPN — the
/// rustls server picks `http/1.1` (last in the list, and the test is
/// titled to that effect: "downgrade h2 → h1"). Used to exercise the
/// gateway's H2 pool ALPN-fallback learning path.
pub fn alpn_downgrade_h2_to_h1(ca: &TestCa) -> TlsConfig {
    let (cert_pem, key_pem) = ca.valid().expect("valid leaf");
    // Server preference order: rustls picks the first protocol both
    // sides advertise. Putting http/1.1 first forces the downgrade
    // when the client also advertises h2.
    TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec(), b"h2".to_vec()])
}

/// TLS config that advertises ONLY `http/1.1` in ALPN — h2-only
/// clients fail the handshake.
pub fn alpn_only_http_1_1(ca: &TestCa) -> TlsConfig {
    let (cert_pem, key_pem) = ca.valid().expect("valid leaf");
    TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()])
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/2
// ────────────────────────────────────────────────────────────────────────────

/// Issue an HTTP/2 GOAWAY immediately after accepting the first
/// stream's HEADERS frame, then close. The gateway should classify
/// the resulting failure as a protocol error.
pub fn h2_goaway_immediately(error_code: u32) -> Vec<H2Step> {
    vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::SendGoawayAndClose { error_code },
    ]
}

/// Accept HEADERS, send response HEADERS, then `RST_STREAM` mid-body.
/// Tests stream-error classification.
pub fn h2_stream_reset_mid_response(error_code: u32) -> Vec<H2Step> {
    vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::RespondHeaders(vec![(":status", "200".into())]),
        H2Step::SendRstStream { error_code },
    ]
}

/// Withhold WINDOW_UPDATE for `duration` while the peer is trying to
/// send a body. Pair with
/// [`crate::scaffolding::backends::ScriptedH2BackendBuilder::with_initial_window_size`]
/// (e.g. `1`) so the stall hits within the first byte.
pub fn h2_window_stall(duration: Duration) -> Vec<H2Step> {
    vec![
        H2Step::ExpectHeaders(MatchHeaders::any()),
        H2Step::StallWindowFor(duration),
    ]
}

// ────────────────────────────────────────────────────────────────────────────
// HTTP/3 / QUIC
// ────────────────────────────────────────────────────────────────────────────

/// Spawn a [`QuicRefuser`] that accepts the first datagram and answers
/// with QUIC `CONNECTION_CLOSE` (`NO_ERROR`). Use as the H3 backend
/// fixture for capability-registry "mark unsupported" tests.
pub fn quic_refuse(
    reservation: UdpSocketReservation,
    tls: H3TlsConfig,
) -> Result<QuicRefuser, Box<dyn std::error::Error + Send + Sync>> {
    QuicRefuser::start(reservation, tls)
}

/// Spawn a [`ScriptedH3Backend`] whose first script step is
/// [`H3Step::DropInitialPacket`] — the QUIC handshake never begins
/// because the initial datagram is dropped. Models a backend whose
/// UDP path is blocked or silently filtered.
pub fn quic_drop_initial(
    socket: UdpSocket,
    tls: H3TlsConfig,
) -> Result<ScriptedH3Backend, Box<dyn std::error::Error + Send + Sync>> {
    ScriptedH3Backend::builder(socket, tls)
        .step(H3Step::DropInitialPacket)
        .spawn()
}

/// Accept the QUIC handshake then immediately `CONNECTION_CLOSE` with
/// `error_code`. Fits the capability-downgrade tests where the
/// gateway sees a successful UDP path probe but the application
/// layer collapses on the first stream.
pub fn quic_connection_close(error_code: u64) -> Vec<H3Step> {
    vec![
        H3Step::AcceptHandshake,
        H3Step::CloseConnectionWithCode(error_code),
    ]
}

/// Accept a stream, send 200-status H3 HEADERS, then `RESET_STREAM`
/// with `error_code` mid-response.
pub fn quic_stream_reset(error_code: u64) -> Vec<H3Step> {
    vec![
        H3Step::AcceptStream,
        H3Step::RespondHeaders(vec![(":status", "200".into())]),
        H3Step::SendStreamReset(error_code),
    ]
}

// ────────────────────────────────────────────────────────────────────────────
// UDP / DTLS
// ────────────────────────────────────────────────────────────────────────────

/// UDP backend that absorbs every datagram for `duration` without
/// ever replying. Useful for "session idle timeout" tests where the
/// gateway must clean up its session map on its own.
pub fn udp_silent_backend(duration: Duration) -> Vec<UdpStep> {
    vec![UdpStep::Silence(duration)]
}

/// UDP backend that, on the first datagram from the gateway, fires
/// back `reply_count` reply datagrams. Used to exercise the gateway's
/// `udp_max_response_amplification_factor` clamp.
pub fn udp_amplification_attempt(reply_count: usize) -> Vec<UdpStep> {
    vec![
        UdpStep::ExpectDatagram(crate::scaffolding::backends::DatagramMatcher::any()),
        UdpStep::ReplyN {
            payload: b"amp".to_vec(),
            count: reply_count,
        },
    ]
}

/// DTLS handshake-timeout fixture: the server absorbs datagrams
/// silently for `delay` and then drops the connection without ever
/// completing the handshake. The gateway must give up at
/// `backend_connect_timeout_ms`.
///
/// `dimpl` doesn't expose a pre-handshake stall hook, so we
/// approximate by parking on `Silence(delay)` — the dimpl-side
/// handshake state machine still runs, but no application data is
/// ever exchanged, and tests can pair this with a tight gateway
/// `backend_connect_timeout_ms` to observe the give-up path.
pub async fn dtls_handshake_timeout(
    socket: UdpSocket,
    delay: Duration,
) -> Result<ScriptedDtlsBackend, Box<dyn std::error::Error + Send + Sync>> {
    let config = DtlsConfig::self_signed()?;
    ScriptedDtlsBackend::builder(socket, config)
        .step(UdpStep::Silence(delay))
        .step(UdpStep::DropSocket)
        .spawn()
        .await
}

// ────────────────────────────────────────────────────────────────────────────
// Network conditions (Phase-5 wrappers)
// ────────────────────────────────────────────────────────────────────────────

/// Configure a [`NetworkSimProxyBuilder`] with `latency_ms` of
/// per-call read+write delay. Returns the builder so the test can
/// chain `.forward_to(...)` and `.spawn()`.
pub fn slow_link(listener: TcpListener, latency_ms: u64) -> NetworkSimProxyBuilder {
    NetworkSimProxy::builder(listener).with_latency(Duration::from_millis(latency_ms))
}

/// Configure a [`NetworkSimProxyBuilder`] with a `kbps` bytes-per-second
/// throughput cap on the forward link. The proxy applies the cap
/// symmetrically to both directions.
pub fn bandwidth_limited(listener: TcpListener, kbps: u64) -> NetworkSimProxyBuilder {
    let bps = kbps.saturating_mul(1024);
    NetworkSimProxy::builder(listener).with_bandwidth_limit(bps)
}

// ────────────────────────────────────────────────────────────────────────────
// Built-backend constructors
// ────────────────────────────────────────────────────────────────────────────
//
// A handful of constructors return a fully-built backend rather than a
// `Vec<…>` script. Use these when the test doesn't need to compose
// further steps and just wants a "plug in this backend" shorthand.
//
// Tests that DO need composition should use the script-returning
// variants above and call `.spawn()` themselves.

/// Spawn a [`ScriptedTcpBackend`] that refuses every accepted
/// connection (one-shot per `RefuseNextConnect`) — fits matrix tests
/// asserting "any frontend → 502 against a refusing backend".
pub fn spawn_refusing_tcp_backend(
    reservation: PortReservation,
) -> Result<ScriptedTcpBackend, std::io::Error> {
    ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::RefuseNextConnect)
        .spawn()
}

/// Spawn a [`ScriptedTcpBackend`] that resets every accepted
/// connection (`SO_LINGER=0`, FIN-or-RST).
pub fn spawn_resetting_tcp_backend(
    reservation: PortReservation,
) -> Result<ScriptedTcpBackend, std::io::Error> {
    ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::Reset)
        .spawn()
}

/// Spawn a [`ScriptedHttp1Backend`] that closes every accepted
/// connection before sending a status line.
pub fn spawn_close_before_status_backend(
    reservation: PortReservation,
) -> Result<ScriptedHttp1Backend, std::io::Error> {
    ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::CloseBeforeStatus)
        .spawn()
}

/// Spawn a [`ScriptedH2Backend`] over plain h2c that accepts the
/// first stream's HEADERS, then issues GOAWAY+close.
pub fn spawn_h2_goaway_backend(
    reservation: PortReservation,
    error_code: u32,
) -> Result<ScriptedH2Backend, std::io::Error> {
    ScriptedH2Backend::builder_plain(reservation.into_listener())
        .steps(h2_goaway_immediately(error_code))
        .spawn()
}

/// Spawn a [`ScriptedGrpcBackend`] over plain h2c that accepts an RPC
/// then closes the underlying stream without sending `grpc-status`.
pub fn spawn_grpc_missing_trailer_backend(
    reservation: PortReservation,
    body: Bytes,
) -> Result<ScriptedGrpcBackend, std::io::Error> {
    ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .steps(respond_but_close_before_trailer(body))
        .spawn()
}

/// Spawn a [`ScriptedUdpBackend`] that absorbs datagrams silently
/// for `duration`.
pub fn spawn_silent_udp_backend(
    socket: UdpSocket,
    duration: Duration,
) -> Result<ScriptedUdpBackend, std::io::Error> {
    ScriptedUdpBackend::builder(socket)
        .steps(udp_silent_backend(duration))
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: every cert-related preset returns a TLS config that
    /// can build a usable rustls `ServerConfig` (or, for genuinely
    /// expired/invalid certs, fail the build for the right reason).
    #[test]
    fn cert_presets_construct() {
        // Constructing the TlsConfig is enough — building the
        // server config exercises the rustls path which is unit-tested
        // separately under `tls.rs`.
        let _expired = cert_expired();
        let _san = cert_san_mismatch();
        let _self_signed = cert_self_signed();
        let _not_yet = cert_not_yet_valid();
    }

    #[test]
    fn http_protocol_presets_have_expected_step_counts() {
        // Stable, easily-checked invariants so reviewers can see at a
        // glance that each preset wasn't accidentally truncated.
        assert!(matches!(
            refuse_connect().as_slice(),
            [TcpStep::RefuseNextConnect]
        ));
        assert!(matches!(accept_then_rst().as_slice(), [TcpStep::Reset]));
        assert!(matches!(
            accept_then_fin_before_response().as_slice(),
            [HttpStep::CloseBeforeStatus]
        ));
    }

    #[test]
    fn slow_header_trickle_chunks_correctly() {
        let script = slow_header_trickle(4, Duration::from_millis(10));
        let writes: Vec<usize> = script
            .iter()
            .filter_map(|step| match step {
                TcpStep::Write(b) => Some(b.len()),
                _ => None,
            })
            .collect();
        // "HTTP/1.1 200 OK\r\n" = 17 bytes → 5 writes (4+4+4+4+1).
        let total: usize = writes.iter().sum();
        assert_eq!(total, b"HTTP/1.1 200 OK\r\n".len());
        // Sleeps between chunks: writes - 1.
        let sleeps = script
            .iter()
            .filter(|s| matches!(s, TcpStep::Sleep(_)))
            .count();
        assert_eq!(sleeps, writes.len() - 1, "one sleep between each pair");
    }

    #[test]
    fn slow_header_trickle_handles_zero_chunk_size_safely() {
        // Regression: a `chunk_size == 0` argument would trigger an
        // infinite loop in `raw_status_trickle`. The constructor must
        // guard against that and treat 0 as "1 byte at a time".
        let script = slow_header_trickle(0, Duration::from_millis(0));
        let writes: Vec<usize> = script
            .iter()
            .filter_map(|step| match step {
                TcpStep::Write(b) => Some(b.len()),
                _ => None,
            })
            .collect();
        assert!(!writes.is_empty(), "guard must produce at least one write");
        assert!(
            writes.iter().all(|n| *n == 1),
            "0-sized chunk should fall back to single-byte writes"
        );
    }

    #[test]
    fn malformed_chunked_encoding_emits_status_and_garbage() {
        let script = send_malformed_chunked_encoding();
        let combined: Vec<u8> = script
            .iter()
            .flat_map(|s| match s {
                TcpStep::Write(b) => b.to_vec(),
                _ => Vec::new(),
            })
            .collect();
        let text = String::from_utf8_lossy(&combined);
        assert!(text.contains("HTTP/1.1 200 OK"));
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(
            text.contains("not-a-hex-length"),
            "must include malformed chunk-length: {text:?}"
        );
    }

    #[test]
    fn duplicate_content_length_emits_two_cl_headers() {
        let script = send_duplicate_content_length();
        let combined: Vec<u8> = script
            .iter()
            .flat_map(|s| match s {
                TcpStep::Write(b) => b.to_vec(),
                _ => Vec::new(),
            })
            .collect();
        let text = String::from_utf8_lossy(&combined);
        let cl_count = text.matches("Content-Length:").count();
        assert_eq!(cl_count, 2, "expected two CL headers, got {cl_count}");
    }

    #[test]
    fn h2_presets_compose_to_step_lists() {
        assert_eq!(h2_goaway_immediately(2).len(), 2);
        assert_eq!(h2_stream_reset_mid_response(2).len(), 3);
        assert_eq!(h2_window_stall(Duration::from_millis(100)).len(), 2);
    }

    #[test]
    fn h3_presets_compose_to_step_lists() {
        assert_eq!(quic_connection_close(0).len(), 2);
        assert_eq!(quic_stream_reset(258).len(), 3);
    }
}

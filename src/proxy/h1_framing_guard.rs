//! Wire-level HTTP/1 framing observations that must survive Hyper parsing.
//!
//! Hyper applies `Transfer-Encoding` precedence while it builds the request
//! `HeaderMap`. In Hyper 1.9, a `Content-Length` field received after
//! `Transfer-Encoding` is deliberately omitted, so an application-level CL+TE
//! guard cannot distinguish that wire shape from a TE-only request.
//!
//! [`H1FramingGuardIo`] observes bytes in place before Hyper sees them and
//! publishes one bit per complete HTTP/1 request head. It does not retain a
//! head, allocate per request, or inspect body payloads. A small framing state
//! machine skips fixed and chunked bodies so keep-alive and pipelined requests
//! remain aligned. Reads that can contain request heads expose at most 8 KiB
//! beyond a known body boundary; this hard-bounds the fixed signal ring's
//! producer lead without limiting reads wholly inside a body. The configured
//! Hyper head-buffer limit bounds work on an unterminated head.
//!
//! Three shapes that Hyper would reject during parse (conflicting
//! `Content-Length` values, HTTP/1.0 + `Transfer-Encoding`, invalid UTF-8 on
//! the request line) are identified here and answered with a precomputed
//! JSON `400` written directly to the socket. Hyper never sees those
//! requests. A well-formed head takes the same in-place observe path and the
//! same vectored writes as on `main`. Other Hyper parse failures the scanner
//! cannot name stay Hyper's empty-bodied `400`.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Parse-reject reasons the inbound scanner can name with confidence.
pub(super) const PARSE_HINT_NONE: u8 = 0;
pub(super) const PARSE_HINT_CONFLICTING_CONTENT_LENGTH: u8 = 1;
pub(super) const PARSE_HINT_HTTP10_TRANSFER_ENCODING: u8 = 2;

/// Request-line version token whose presence makes `Transfer-Encoding` a
/// protocol error. Length-bound so the window width cannot drift from it.
const HTTP_10_VERSION: &[u8] = b"HTTP/1.0";
pub(super) const PARSE_HINT_INVALID_REQUEST_TARGET_UTF8: u8 = 3;

const JSON_CONFLICTING_CONTENT_LENGTH: &str =
    r#"{"error":"Multiple Content-Length headers with conflicting values"}"#;
const JSON_HTTP10_TRANSFER_ENCODING: &str =
    r#"{"error":"HTTP/1.0 does not support Transfer-Encoding"}"#;
const JSON_MALFORMED_HTTP_REQUEST: &str = r#"{"error":"Malformed HTTP request"}"#;

const _: () = {
    assert!(JSON_CONFLICTING_CONTENT_LENGTH.len() == 67);
    assert!(JSON_HTTP10_TRANSFER_ENCODING.len() == 55);
    assert!(JSON_MALFORMED_HTTP_REQUEST.len() == 34);
};

const ENVELOPE_CONFLICTING_CONTENT_LENGTH: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 67\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"Multiple Content-Length headers with conflicting values\"}";
const ENVELOPE_HTTP10_TRANSFER_ENCODING: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 55\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"HTTP/1.0 does not support Transfer-Encoding\"}";
const ENVELOPE_MALFORMED_HTTP_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 34\r\nconnection: close\r\nx-gateway-error: request_error\r\n\r\n{\"error\":\"Malformed HTTP request\"}";

pub(super) fn envelope_for_hint(hint: u8) -> &'static [u8] {
    match hint {
        PARSE_HINT_CONFLICTING_CONTENT_LENGTH => ENVELOPE_CONFLICTING_CONTENT_LENGTH,
        PARSE_HINT_HTTP10_TRANSFER_ENCODING => ENVELOPE_HTTP10_TRANSFER_ENCODING,
        _ => ENVELOPE_MALFORMED_HTTP_REQUEST,
    }
}

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const OBSERVED_READ_CAP: usize = 8 * 1024;
const SIGNAL_WORDS: usize = 16;
const SIGNAL_CAPACITY: u64 = (SIGNAL_WORDS * u64::BITS as usize) as u64;
// Mirrored from hyper 1.9.0 `src/proto/h1/decode.rs`:
// `CHUNKED_EXTENSIONS_LIMIT` (line 20) and `TRAILER_LIMIT` (line 25).
// The safety invariant is one-directional: hyper must error at or before the
// guard disables observation. Hyper's server connection currently leaves
// `h1_max_header_size` unset, so `TRAILER_LIMIT` is independent of the head
// limit (`decode.rs:181` falls back to `TRAILER_LIMIT`). If a hyper 1.x bump
// populates that from `max_buf_size` (the TODO at `decode.rs:24`), hyper's
// trailer budget becomes 32 KiB while this guard would still disable at 16 KiB
// and fail-close the *next* keep-alive request. Re-check both constants on
// every hyper bump. Do not pin hyper solely to freeze these private limits —
// 1.x security updates must keep flowing.
const CHUNK_EXTENSION_LIMIT: usize = 16 * 1024;
const HYPER_TRAILER_LIMIT: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum H1FramingResult {
    /// No HTTP/1 observation ran for this request (H2/H3, the public test
    /// entry, or a handler that never installed the guard). Enforcement must
    /// treat this like [`Self::Clear`]: it is not a rejection. [`Self::Clear`]
    /// is reserved for a completed observation that saw no CL+TE conflict.
    #[default]
    NotObserved,
    /// The observer published a request-head decision and saw no CL+TE conflict.
    Clear,
    Conflict,
    ObserverFailed,
}

/// Connection-local queue of wire-level CL+TE decisions.
///
/// Leading empty lines produce no entries, matching httparse. The bound that
/// matters is the observer's own minimum complete head, `X\n\n` (3 bytes):
/// `observe_line_byte` sets `line_has_data`, the first `\n` clears
/// `request_line`, and the second `\n` takes the `!line_has_data &&
/// !request_line` branch and publishes. Hyper returns after parsing the first
/// head instead of issuing another read, and a boundary-crossing read exposes
/// at most 8 KiB after the body, so one prior partial head plus `8192 / 3`
/// complete heads can lead the consumer: at most 2,731 entries. That exceeds
/// the 1,024-entry ring, so wrap is possible while the observer remains
/// congruent. The capacity check in [`Self::push`] is therefore load-bearing,
/// not belt-and-braces; overflow is a sticky fail-closed `ObserverFailed`.
/// Capacity exhaustion, an observer/parser divergence, and a consumer
/// underflow are sticky fail-closed states.
///
/// The 16-word conflict ring is heap-allocated only when the scanner first
/// classifies the connection as HTTP/1, so an h2c preface match never pays
/// for it. TLS connections that negotiated ALPN `h2` skip this type entirely.
pub(super) struct H1FramingSignals {
    produced: AtomicU64,
    consumed: AtomicU64,
    conflicts: OnceLock<Box<[AtomicU64; SIGNAL_WORDS]>>,
    overflowed: AtomicBool,
    unknown: AtomicBool,
    observation_disabled: AtomicBool,
    parse_reject_hint: AtomicU8,
}

impl H1FramingSignals {
    fn new() -> Self {
        Self {
            produced: AtomicU64::new(0),
            consumed: AtomicU64::new(0),
            conflicts: OnceLock::new(),
            overflowed: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
            observation_disabled: AtomicBool::new(false),
            parse_reject_hint: AtomicU8::new(PARSE_HINT_NONE),
        }
    }

    fn store_parse_reject_hint(&self, hint: u8) {
        if hint == PARSE_HINT_NONE {
            return;
        }
        let _ = self.parse_reject_hint.compare_exchange(
            PARSE_HINT_NONE,
            hint,
            Ordering::Release,
            Ordering::Relaxed,
        );
    }

    fn take_parse_reject_hint(&self) -> u8 {
        self.parse_reject_hint
            .swap(PARSE_HINT_NONE, Ordering::AcqRel)
    }

    fn conflict_ring(&self) -> &[AtomicU64; SIGNAL_WORDS] {
        self.conflicts
            .get_or_init(|| Box::new(std::array::from_fn(|_| AtomicU64::new(0))))
    }

    fn mark_unknown(&self) {
        self.unknown.store(true, Ordering::Release);
        self.observation_disabled.store(true, Ordering::Release);
    }

    fn mark_overflowed(&self) {
        self.overflowed.store(true, Ordering::Release);
        self.observation_disabled.store(true, Ordering::Release);
    }

    pub(super) fn disable_observation(&self) {
        self.observation_disabled.store(true, Ordering::Release);
    }

    fn observation_disabled(&self) -> bool {
        self.observation_disabled.load(Ordering::Acquire)
    }

    fn push(&self, conflict: bool) -> bool {
        if self.observation_disabled() {
            return false;
        }
        let sequence = self.produced.load(Ordering::Relaxed);
        let consumed = self.consumed.load(Ordering::Acquire);
        if sequence.saturating_sub(consumed) >= SIGNAL_CAPACITY {
            self.mark_overflowed();
            return false;
        }

        let slot = sequence % SIGNAL_CAPACITY;
        let Some(word) = self.conflict_ring().get((slot / u64::BITS as u64) as usize) else {
            self.mark_unknown();
            return false;
        };
        let mask = 1u64 << (slot % u64::BITS as u64);
        if conflict {
            word.fetch_or(mask, Ordering::Relaxed);
        } else {
            word.fetch_and(!mask, Ordering::Relaxed);
        }
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.mark_overflowed();
            return false;
        };
        self.produced.store(next_sequence, Ordering::Release);
        true
    }

    pub(super) fn next_conflict(&self) -> H1FramingResult {
        if self.overflowed.load(Ordering::Acquire) || self.unknown.load(Ordering::Acquire) {
            return H1FramingResult::ObserverFailed;
        }

        let sequence = self.consumed.load(Ordering::Relaxed);
        if sequence >= self.produced.load(Ordering::Acquire) {
            self.mark_unknown();
            return H1FramingResult::ObserverFailed;
        }

        let slot = sequence % SIGNAL_CAPACITY;
        let Some(ring) = self.conflicts.get() else {
            self.mark_unknown();
            return H1FramingResult::ObserverFailed;
        };
        let Some(word) = ring.get((slot / u64::BITS as u64) as usize) else {
            self.mark_unknown();
            return H1FramingResult::ObserverFailed;
        };
        let mask = 1u64 << (slot % u64::BITS as u64);
        let conflict = word.load(Ordering::Relaxed) & mask != 0;
        let Some(next_sequence) = sequence.checked_add(1) else {
            self.mark_overflowed();
            return H1FramingResult::ObserverFailed;
        };
        self.consumed.store(next_sequence, Ordering::Release);
        if conflict {
            H1FramingResult::Conflict
        } else {
            H1FramingResult::Clear
        }
    }
}

enum ParseRejectWrite {
    Idle,
    Writing {
        envelope: &'static [u8],
        offset: usize,
    },
    Written,
}

impl ParseRejectWrite {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}

/// Transparent I/O adapter that observes HTTP/1 request framing before Hyper.
pub(super) struct H1FramingGuardIo<T> {
    inner: T,
    scanner: WireScanner,
    signals: Arc<H1FramingSignals>,
    parse_reject: ParseRejectWrite,
    /// Whether Hyper has already written response bytes on this connection.
    ///
    /// The parse-reject envelope is written straight to `inner` from inside
    /// `poll_read`, bypassing Hyper's write buffer. Hyper's HTTP/1 *server*
    /// reads the next request head while an earlier response is still being
    /// written (`should_read_first()` is true for servers, and the dispatch
    /// loop polls read before flush), so on a keep-alive connection under
    /// write backpressure a pipelined malformed request would splice the
    /// envelope into the middle of the previous response.
    ///
    /// The envelope is therefore armed only before the first response byte —
    /// the fresh-connection case, which is every real client that sends one
    /// malformed request. A malformed request pipelined behind a response
    /// falls back to Hyper's own empty-bodied `400`, the same documented
    /// residual as the parse failures the scanner cannot name.
    wrote_response_bytes: bool,
}

impl<T> H1FramingGuardIo<T> {
    pub(super) fn new(inner: T, max_head_bytes: usize) -> (Self, Arc<H1FramingSignals>) {
        let signals = Arc::new(H1FramingSignals::new());
        (
            Self {
                inner,
                scanner: WireScanner::new(max_head_bytes),
                signals: Arc::clone(&signals),
                parse_reject: ParseRejectWrite::Idle,
                wrote_response_bytes: false,
            },
            signals,
        )
    }
}

impl<T: AsyncWrite + Unpin> H1FramingGuardIo<T> {
    fn begin_parse_reject(&mut self, hint: u8) {
        if !self.parse_reject.is_idle() {
            return;
        }
        tracing::warn!(
            gateway_error = "request_error",
            parse_reject_hint = hint,
            "Rejected HTTP/1 request before Hyper parse"
        );
        self.signals.disable_observation();
        self.parse_reject = ParseRejectWrite::Writing {
            envelope: envelope_for_hint(hint),
            offset: 0,
        };
    }

    fn poll_write_envelope(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let (envelope, offset) = match self.parse_reject {
                ParseRejectWrite::Idle | ParseRejectWrite::Written => {
                    return Poll::Ready(Ok(()));
                }
                ParseRejectWrite::Writing { envelope, offset } => {
                    if offset >= envelope.len() {
                        self.parse_reject = ParseRejectWrite::Written;
                        return Poll::Ready(Ok(()));
                    }
                    (envelope, offset)
                }
            };
            let wrote = ready!(Pin::new(&mut self.inner).poll_write(cx, &envelope[offset..],))?;
            if wrote == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write HTTP/1 parse-reject envelope",
                )));
            }
            match &mut self.parse_reject {
                ParseRejectWrite::Writing { offset, .. } => {
                    *offset += wrote;
                }
                _ => return Poll::Ready(Ok(())),
            }
        }
    }

    fn poll_finish_parse_reject(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_write_envelope(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for H1FramingGuardIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.parse_reject.is_idle() {
            return this.poll_finish_parse_reject(cx);
        }
        this.scanner.disable_if_requested(&this.signals);
        let filled_before = buf.filled().len();
        let cap = this.scanner.read_cap(buf.remaining());

        let result = if cap < buf.remaining() {
            let (result, filled) = {
                let mut limited = buf.take(cap);
                let result = Pin::new(&mut this.inner).poll_read(cx, &mut limited);
                (result, limited.filled().len())
            };
            if let Poll::Ready(Ok(())) = &result {
                // SAFETY: the inner AsyncRead initialized every byte it added to
                // `limited`; `limited` borrows this exact unfilled prefix.
                unsafe {
                    buf.assume_init(filled);
                }
                buf.advance(filled);
            }
            result
        } else {
            Pin::new(&mut this.inner).poll_read(cx, buf)
        };

        if let Poll::Ready(Ok(())) = &result {
            this.scanner.disable_if_requested(&this.signals);
            if this.scanner.observation_active() {
                this.scanner
                    .observe(&buf.filled()[filled_before..], &this.signals);
            }
            if this.parse_reject.is_idle() {
                let hint = this.signals.take_parse_reject_hint();
                if hint != PARSE_HINT_NONE {
                    if this.wrote_response_bytes {
                        // See `wrote_response_bytes`: writing the envelope now
                        // would interleave it with an in-flight response.
                        tracing::debug!(
                            parse_reject_hint = hint,
                            "HTTP/1 parse reject after a response began; \
                             deferring to Hyper's empty 400"
                        );
                    } else {
                        buf.set_filled(filled_before);
                        this.begin_parse_reject(hint);
                        return this.poll_finish_parse_reject(cx);
                    }
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for H1FramingGuardIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.parse_reject.is_idle() {
            ready!(this.poll_write_envelope(cx))?;
            return Poll::Ready(Ok(buf.len()));
        }
        let wrote = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        if wrote > 0 {
            this.wrote_response_bytes = true;
        }
        Poll::Ready(Ok(wrote))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.parse_reject.is_idle() {
            ready!(this.poll_write_envelope(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.parse_reject.is_idle() {
            ready!(this.poll_write_envelope(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.parse_reject.is_idle() {
            ready!(this.poll_write_envelope(cx))?;
            let total = bufs.iter().map(|slice| slice.len()).sum();
            return Poll::Ready(Ok(total));
        }
        let wrote = ready!(Pin::new(&mut this.inner).poll_write_vectored(cx, bufs))?;
        if wrote > 0 {
            this.wrote_response_bytes = true;
        }
        Poll::Ready(Ok(wrote))
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// HTTP/1 observation wrapper, or the raw stream when ALPN already proved HTTP/2.
///
/// TLS connections that negotiated `h2` never install [`H1FramingGuardIo`], so
/// they do not allocate [`H1FramingSignals`]. `Observed` is boxed so a
/// passthrough HTTP/2 connection does not carry the scanner in the enum layout.
/// Plaintext still wraps because protocol detection happens on the first read
/// (h2c preface vs HTTP/1).
pub(super) enum MaybeH1FramingGuardIo<T> {
    Observed(Box<H1FramingGuardIo<T>>),
    Passthrough(T),
}

impl<T> MaybeH1FramingGuardIo<T> {
    pub(super) fn observed(inner: T, max_head_bytes: usize) -> (Self, Arc<H1FramingSignals>) {
        let (guard, signals) = H1FramingGuardIo::new(inner, max_head_bytes);
        (Self::Observed(Box::new(guard)), signals)
    }

    pub(super) fn passthrough(inner: T) -> Self {
        Self::Passthrough(inner)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeH1FramingGuardIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Observed(inner) => Pin::new(inner.as_mut()).poll_read(cx, buf),
            Self::Passthrough(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MaybeH1FramingGuardIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Observed(inner) => Pin::new(inner.as_mut()).poll_write(cx, buf),
            Self::Passthrough(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Observed(inner) => Pin::new(inner.as_mut()).poll_flush(cx),
            Self::Passthrough(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Observed(inner) => Pin::new(inner.as_mut()).poll_shutdown(cx),
            Self::Passthrough(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Observed(inner) => Pin::new(inner.as_mut()).poll_write_vectored(cx, bufs),
            Self::Passthrough(inner) => Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Observed(inner) => inner.is_write_vectored(),
            Self::Passthrough(inner) => inner.is_write_vectored(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Detect,
    Http1,
    Http2,
    Disabled,
}

struct WireScanner {
    protocol: Protocol,
    preface: [u8; H2_PREFACE.len()],
    preface_len: usize,
    h1: H1StreamScanner,
}

impl WireScanner {
    fn new(max_head_bytes: usize) -> Self {
        Self {
            protocol: Protocol::Detect,
            preface: [0; H2_PREFACE.len()],
            preface_len: 0,
            h1: H1StreamScanner::new(max_head_bytes),
        }
    }

    fn read_cap(&self, requested: usize) -> usize {
        if requested == 0 {
            return 0;
        }
        match self.protocol {
            Protocol::Detect => requested.min(OBSERVED_READ_CAP),
            Protocol::Http1 => self.h1.read_cap(requested),
            Protocol::Http2 | Protocol::Disabled => requested,
        }
    }

    fn observation_active(&self) -> bool {
        matches!(self.protocol, Protocol::Detect | Protocol::Http1)
    }

    fn disable_if_requested(&mut self, signals: &H1FramingSignals) {
        if self.observation_active() && signals.observation_disabled() {
            self.protocol = Protocol::Disabled;
        }
    }

    fn observe(&mut self, mut bytes: &[u8], signals: &H1FramingSignals) {
        if self.protocol == Protocol::Detect {
            let mut consumed = 0;
            while consumed < bytes.len() && self.protocol == Protocol::Detect {
                let byte = bytes[consumed];
                let Some(expected) = H2_PREFACE.get(self.preface_len).copied() else {
                    signals.mark_unknown();
                    self.protocol = Protocol::Disabled;
                    return;
                };
                let Some(slot) = self.preface.get_mut(self.preface_len) else {
                    signals.mark_unknown();
                    self.protocol = Protocol::Disabled;
                    return;
                };
                *slot = byte;
                self.preface_len += 1;
                consumed += 1;

                if byte != expected {
                    self.protocol = Protocol::Http1;
                    if !self.h1.observe(&self.preface[..self.preface_len], signals) {
                        signals.mark_unknown();
                        self.protocol = Protocol::Disabled;
                        return;
                    }
                } else if self.preface_len == H2_PREFACE.len() {
                    self.protocol = Protocol::Http2;
                    return;
                }
            }
            bytes = &bytes[consumed..];
        }

        if self.protocol == Protocol::Http1 && !self.h1.observe(bytes, signals) {
            signals.mark_unknown();
            self.protocol = Protocol::Disabled;
        }
    }
}

enum H1State {
    Head(HeadScanner),
    FixedBody(u64),
    Chunked(ChunkedScanner),
    Disabled,
}

struct H1StreamScanner {
    state: H1State,
    max_head_bytes: usize,
}

impl H1StreamScanner {
    fn new(max_head_bytes: usize) -> Self {
        Self {
            state: H1State::Head(HeadScanner::new(max_head_bytes)),
            max_head_bytes,
        }
    }

    fn read_cap(&self, requested: usize) -> usize {
        match &self.state {
            H1State::FixedBody(remaining) => body_boundary_read_cap(requested, *remaining),
            H1State::Chunked(ChunkedScanner {
                state: ChunkState::Data(remaining),
                ..
            }) => body_boundary_read_cap(requested, *remaining),
            H1State::Head(_) | H1State::Chunked(_) => requested.min(OBSERVED_READ_CAP),
            H1State::Disabled => requested,
        }
    }

    fn observe(&mut self, bytes: &[u8], signals: &H1FramingSignals) -> bool {
        let mut offset = 0;
        while offset < bytes.len() {
            let transition = match &mut self.state {
                H1State::Head(head) => {
                    let step = head.observe(bytes[offset], signals);
                    offset += 1;
                    match step {
                        HeadStep::Continue => None,
                        HeadStep::Complete(outcome) => {
                            if !signals.push(outcome.conflict) {
                                Some(H1State::Disabled)
                            } else {
                                Some(match outcome.framing {
                                    BodyFraming::None => {
                                        H1State::Head(HeadScanner::new(self.max_head_bytes))
                                    }
                                    BodyFraming::Fixed(length) => H1State::FixedBody(length),
                                    BodyFraming::Chunked => H1State::Chunked(ChunkedScanner::new()),
                                    BodyFraming::Invalid => H1State::Disabled,
                                })
                            }
                        }
                        HeadStep::Disable => Some(H1State::Disabled),
                    }
                }
                H1State::FixedBody(remaining) => {
                    let consumed = bytes
                        .len()
                        .saturating_sub(offset)
                        .min(u64_to_usize(*remaining));
                    *remaining -= consumed as u64;
                    offset += consumed;
                    if *remaining == 0 {
                        Some(H1State::Head(HeadScanner::new(self.max_head_bytes)))
                    } else {
                        None
                    }
                }
                H1State::Chunked(chunked) => {
                    let (consumed, step) = chunked.observe(&bytes[offset..]);
                    offset += consumed;
                    match step {
                        ChunkStep::Continue => None,
                        ChunkStep::Complete => {
                            Some(H1State::Head(HeadScanner::new(self.max_head_bytes)))
                        }
                        ChunkStep::Disable => Some(H1State::Disabled),
                    }
                }
                H1State::Disabled => return false,
            };

            if let Some(next) = transition {
                self.state = next;
            }
        }
        !matches!(&self.state, H1State::Disabled)
    }
}

fn body_boundary_read_cap(requested: usize, remaining: u64) -> usize {
    requested.min(u64_to_usize(remaining).saturating_add(OBSERVED_READ_CAP))
}

fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[derive(Clone, Copy)]
enum CurrentHeader {
    Name,
    ContentLength,
    Other,
}

#[derive(Clone, Copy)]
enum ContentLengthPhase {
    LeadingOws,
    Digits,
    TrailingOws,
    Invalid,
}

struct ContentLengthScanner {
    phase: ContentLengthPhase,
    value: u64,
}

impl ContentLengthScanner {
    fn new() -> Self {
        Self {
            phase: ContentLengthPhase::LeadingOws,
            value: 0,
        }
    }

    fn observe(&mut self, byte: u8) {
        self.phase = match (self.phase, byte) {
            (ContentLengthPhase::LeadingOws, b' ' | b'\t') => ContentLengthPhase::LeadingOws,
            (ContentLengthPhase::LeadingOws | ContentLengthPhase::Digits, b'0'..=b'9') => {
                match self
                    .value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                {
                    Some(value) => {
                        self.value = value;
                        ContentLengthPhase::Digits
                    }
                    None => ContentLengthPhase::Invalid,
                }
            }
            (ContentLengthPhase::Digits | ContentLengthPhase::TrailingOws, b' ' | b'\t') => {
                ContentLengthPhase::TrailingOws
            }
            _ => ContentLengthPhase::Invalid,
        };
    }

    fn finish(&self) -> Option<u64> {
        match self.phase {
            ContentLengthPhase::Digits | ContentLengthPhase::TrailingOws => Some(self.value),
            ContentLengthPhase::LeadingOws | ContentLengthPhase::Invalid => None,
        }
    }
}

struct RequestLineUtf8 {
    partial: [u8; 4],
    partial_len: u8,
    invalid: bool,
}

impl RequestLineUtf8 {
    fn new() -> Self {
        Self {
            partial: [0; 4],
            partial_len: 0,
            invalid: false,
        }
    }

    fn observe(&mut self, byte: u8) {
        if self.invalid {
            return;
        }
        let len = self.partial_len as usize;
        if len >= self.partial.len() {
            self.invalid = true;
            return;
        }
        self.partial[len] = byte;
        self.partial_len += 1;
        let slice = &self.partial[..self.partial_len as usize];
        match std::str::from_utf8(slice) {
            Ok(_) => self.partial_len = 0,
            Err(err) if err.error_len().is_none() => {}
            Err(_) => self.invalid = true,
        }
    }

    fn finish_ok(&self) -> bool {
        !self.invalid && self.partial_len == 0
    }
}

struct HeadScanner {
    max_bytes: usize,
    bytes_seen: usize,
    request_line: bool,
    line_has_data: bool,
    pending_cr: bool,
    current_header: CurrentHeader,
    name_len: usize,
    content_length_candidate: bool,
    transfer_encoding_candidate: bool,
    content_length_value: ContentLengthScanner,
    canonical_content_length: Option<u64>,
    content_length_valid: bool,
    seen_content_length: bool,
    seen_transfer_encoding: bool,
    conflict: bool,
    http10_request: bool,
    request_line_utf8: RequestLineUtf8,
    request_line_tail: [u8; 12],
    request_line_tail_len: usize,
}

impl HeadScanner {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            bytes_seen: 0,
            request_line: true,
            line_has_data: false,
            pending_cr: false,
            current_header: CurrentHeader::Name,
            name_len: 0,
            content_length_candidate: true,
            transfer_encoding_candidate: true,
            content_length_value: ContentLengthScanner::new(),
            canonical_content_length: None,
            content_length_valid: true,
            seen_content_length: false,
            seen_transfer_encoding: false,
            conflict: false,
            http10_request: false,
            request_line_utf8: RequestLineUtf8::new(),
            request_line_tail: [0; 12],
            request_line_tail_len: 0,
        }
    }

    fn observe(&mut self, byte: u8, signals: &H1FramingSignals) -> HeadStep {
        self.bytes_seen = self.bytes_seen.saturating_add(1);
        if self.bytes_seen > self.max_bytes {
            return HeadStep::Disable;
        }

        if self.pending_cr {
            self.pending_cr = false;
            if byte == b'\n' {
                return self.finish_line(signals);
            }
            self.observe_line_byte(b'\r');
            self.store_utf8_hint_if_invalid(signals);
        }

        match byte {
            b'\r' => {
                self.pending_cr = true;
                HeadStep::Continue
            }
            b'\n' => self.finish_line(signals),
            _ => {
                self.observe_line_byte(byte);
                self.store_utf8_hint_if_invalid(signals);
                HeadStep::Continue
            }
        }
    }

    fn observe_line_byte(&mut self, byte: u8) {
        self.line_has_data = true;
        if self.request_line {
            self.request_line_utf8.observe(byte);
            if self.request_line_tail_len < self.request_line_tail.len() {
                self.request_line_tail[self.request_line_tail_len] = byte;
                self.request_line_tail_len += 1;
            } else {
                self.request_line_tail.copy_within(1.., 0);
                if let Some(slot) = self.request_line_tail.last_mut() {
                    *slot = byte;
                }
            }
            return;
        }
        if self.conflict {
            return;
        }

        match self.current_header {
            CurrentHeader::Name if byte == b':' => {
                if self.content_length_candidate && self.name_len == b"content-length".len() {
                    self.current_header = CurrentHeader::ContentLength;
                    self.content_length_value = ContentLengthScanner::new();
                    self.seen_content_length = true;
                } else {
                    self.current_header = CurrentHeader::Other;
                    if self.transfer_encoding_candidate
                        && self.name_len == b"transfer-encoding".len()
                    {
                        self.seen_transfer_encoding = true;
                    }
                }
                self.conflict = self.seen_content_length && self.seen_transfer_encoding;
            }
            CurrentHeader::Name => {
                self.content_length_candidate &=
                    pattern_byte_matches(b"content-length", self.name_len, byte);
                self.transfer_encoding_candidate &=
                    pattern_byte_matches(b"transfer-encoding", self.name_len, byte);
                self.name_len = self.name_len.saturating_add(1);
            }
            CurrentHeader::ContentLength => self.content_length_value.observe(byte),
            CurrentHeader::Other => {}
        }
    }

    fn finish_line(&mut self, signals: &H1FramingSignals) -> HeadStep {
        if !self.line_has_data {
            if self.request_line {
                // httparse skips any run of CRLF or bare LF before the request
                // line, so an empty leading line is not a request head.
                return HeadStep::Continue;
            }
            if self.http10_request && self.seen_transfer_encoding {
                signals.store_parse_reject_hint(PARSE_HINT_HTTP10_TRANSFER_ENCODING);
            }
            let framing = if self.seen_transfer_encoding {
                BodyFraming::Chunked
            } else if !self.content_length_valid {
                BodyFraming::Invalid
            } else if let Some(length) = self.canonical_content_length {
                if length == 0 {
                    BodyFraming::None
                } else {
                    BodyFraming::Fixed(length)
                }
            } else {
                BodyFraming::None
            };
            return HeadStep::Complete(HeadOutcome {
                conflict: self.conflict,
                framing,
            });
        }

        if self.request_line {
            self.request_line = false;
            // `b"HTTP/1.0"` is 8 bytes: a 9-byte window can never compare
            // equal to it, so `windows(9)` silently made this always false.
            self.http10_request = self
                .request_line_tail
                .windows(HTTP_10_VERSION.len())
                .any(|window| window.eq_ignore_ascii_case(HTTP_10_VERSION));
            if !self.request_line_utf8.finish_ok() {
                signals.store_parse_reject_hint(PARSE_HINT_INVALID_REQUEST_TARGET_UTF8);
            }
        } else if matches!(self.current_header, CurrentHeader::ContentLength) && !self.conflict {
            match self.content_length_value.finish() {
                Some(value)
                    if self.canonical_content_length.is_none()
                        || self.canonical_content_length == Some(value) =>
                {
                    self.canonical_content_length = Some(value);
                }
                Some(_) => {
                    self.content_length_valid = false;
                    signals.store_parse_reject_hint(PARSE_HINT_CONFLICTING_CONTENT_LENGTH);
                }
                None => self.content_length_valid = false,
            }
        }

        if self.http10_request && self.seen_transfer_encoding {
            signals.store_parse_reject_hint(PARSE_HINT_HTTP10_TRANSFER_ENCODING);
        }

        self.line_has_data = false;
        self.current_header = CurrentHeader::Name;
        self.name_len = 0;
        self.content_length_candidate = true;
        self.transfer_encoding_candidate = true;
        self.request_line_tail_len = 0;
        HeadStep::Continue
    }

    fn store_utf8_hint_if_invalid(&self, signals: &H1FramingSignals) {
        if self.request_line && self.request_line_utf8.invalid {
            signals.store_parse_reject_hint(PARSE_HINT_INVALID_REQUEST_TARGET_UTF8);
        }
    }
}

fn pattern_byte_matches(pattern: &[u8], index: usize, byte: u8) -> bool {
    pattern
        .get(index)
        .is_some_and(|expected| expected.eq_ignore_ascii_case(&byte))
}

enum HeadStep {
    Continue,
    Complete(HeadOutcome),
    Disable,
}

struct HeadOutcome {
    conflict: bool,
    framing: BodyFraming,
}

enum BodyFraming {
    None,
    Fixed(u64),
    Chunked,
    Invalid,
}

#[derive(Clone, Copy)]
enum ChunkState {
    SizeStart,
    Size,
    SizeLws,
    Extension,
    SizeLf,
    Data(u64),
    DataCr,
    DataLf,
    EndCr,
    Trailer,
    TrailerLf,
    EndLf,
}

struct ChunkedScanner {
    state: ChunkState,
    chunk_size: u64,
    extension_bytes: usize,
    trailer_bytes: usize,
}

impl ChunkedScanner {
    fn new() -> Self {
        Self {
            state: ChunkState::SizeStart,
            chunk_size: 0,
            extension_bytes: 0,
            trailer_bytes: 0,
        }
    }

    fn observe(&mut self, bytes: &[u8]) -> (usize, ChunkStep) {
        let mut offset = 0;
        while offset < bytes.len() {
            if let ChunkState::Data(remaining) = self.state {
                let consumed = bytes
                    .len()
                    .saturating_sub(offset)
                    .min(u64_to_usize(remaining));
                offset += consumed;
                let remaining = remaining - consumed as u64;
                self.state = if remaining == 0 {
                    ChunkState::DataCr
                } else {
                    ChunkState::Data(remaining)
                };
                continue;
            }

            let byte = bytes[offset];
            offset += 1;
            let next = match self.state {
                ChunkState::SizeStart => match hex_value(byte) {
                    Some(value) => {
                        // Hyper's `ChunkedState::SizeStart` (decode.rs:355-377)
                        // accumulates `size = size * 16 + value`. Equivalent to
                        // this assignment because hyper's `chunk_len` is
                        // provably 0 at SizeStart (reset on each new chunk). If
                        // that ever changes, this must accumulate too.
                        self.chunk_size = u64::from(value);
                        Some(ChunkState::Size)
                    }
                    None => return (offset, ChunkStep::Disable),
                },
                ChunkState::Size => match byte {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        let Some(value) = hex_value(byte) else {
                            return (offset, ChunkStep::Disable);
                        };
                        let Some(size) = self
                            .chunk_size
                            .checked_mul(16)
                            .and_then(|size| size.checked_add(u64::from(value)))
                        else {
                            return (offset, ChunkStep::Disable);
                        };
                        self.chunk_size = size;
                        None
                    }
                    b' ' | b'\t' => Some(ChunkState::SizeLws),
                    b';' => Some(ChunkState::Extension),
                    b'\r' => Some(ChunkState::SizeLf),
                    _ => return (offset, ChunkStep::Disable),
                },
                ChunkState::SizeLws => match byte {
                    b' ' | b'\t' => None,
                    b';' => Some(ChunkState::Extension),
                    b'\r' => Some(ChunkState::SizeLf),
                    _ => return (offset, ChunkStep::Disable),
                },
                ChunkState::Extension => match byte {
                    b'\r' => Some(ChunkState::SizeLf),
                    b'\n' => return (offset, ChunkStep::Disable),
                    _ => {
                        self.extension_bytes = self.extension_bytes.saturating_add(1);
                        if self.extension_bytes >= CHUNK_EXTENSION_LIMIT {
                            return (offset, ChunkStep::Disable);
                        }
                        None
                    }
                },
                ChunkState::SizeLf => {
                    if byte != b'\n' {
                        return (offset, ChunkStep::Disable);
                    }
                    if self.chunk_size == 0 {
                        Some(ChunkState::EndCr)
                    } else {
                        Some(ChunkState::Data(self.chunk_size))
                    }
                }
                ChunkState::Data(_) => None,
                ChunkState::DataCr => {
                    if byte == b'\r' {
                        Some(ChunkState::DataLf)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::DataLf => {
                    if byte == b'\n' {
                        self.chunk_size = 0;
                        Some(ChunkState::SizeStart)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::EndCr => {
                    if byte == b'\r' {
                        Some(ChunkState::EndLf)
                    } else {
                        self.trailer_bytes = self.trailer_bytes.saturating_add(1);
                        Some(ChunkState::Trailer)
                    }
                }
                ChunkState::Trailer => {
                    self.trailer_bytes = self.trailer_bytes.saturating_add(1);
                    if self.trailer_bytes >= HYPER_TRAILER_LIMIT {
                        return (offset, ChunkStep::Disable);
                    }
                    if byte == b'\r' {
                        Some(ChunkState::TrailerLf)
                    } else {
                        None
                    }
                }
                ChunkState::TrailerLf => {
                    if byte == b'\n' {
                        Some(ChunkState::EndCr)
                    } else {
                        return (offset, ChunkStep::Disable);
                    }
                }
                ChunkState::EndLf => {
                    if byte == b'\n' {
                        return (offset, ChunkStep::Complete);
                    }
                    return (offset, ChunkStep::Disable);
                }
            };
            if let Some(next) = next {
                self.state = next;
            }
        }
        (offset, ChunkStep::Continue)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte + 10 - b'a'),
        b'A'..=b'F' => Some(byte + 10 - b'A'),
        _ => None,
    }
}

enum ChunkStep {
    Continue,
    Complete,
    Disable,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAX_HEAD_BYTES: usize = 32 * 1024;

    struct ScanOutcome {
        results: Vec<H1FramingResult>,
        overflowed: bool,
        unknown: bool,
        parse_reject_hint: u8,
    }

    fn scan(parts: &[&[u8]]) -> ScanOutcome {
        scan_with_max_head(TEST_MAX_HEAD_BYTES, parts)
    }

    fn scan_with_max_head(max_head_bytes: usize, parts: &[&[u8]]) -> ScanOutcome {
        let signals = H1FramingSignals::new();
        let mut scanner = WireScanner::new(max_head_bytes);
        for part in parts {
            scanner.observe(part, &signals);
        }

        let produced = signals.produced.load(Ordering::Acquire);
        let mut results = Vec::with_capacity(produced as usize);
        for _ in 0..produced {
            results.push(signals.next_conflict());
        }
        ScanOutcome {
            results,
            overflowed: signals.overflowed.load(Ordering::Acquire),
            unknown: signals.unknown.load(Ordering::Acquire),
            parse_reject_hint: signals.parse_reject_hint.load(Ordering::Acquire),
        }
    }

    #[test]
    fn classifies_basic_request_heads() {
        let cases: &[(&[u8], &[H1FramingResult])] = &[
            (b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", &[H1FramingResult::Clear]),
            (
                b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
                &[H1FramingResult::Conflict],
            ),
            (
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                &[H1FramingResult::Conflict],
            ),
            (
                b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                &[H1FramingResult::Clear],
            ),
            (
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\nhello!",
                &[H1FramingResult::Clear],
            ),
        ];

        for (wire, expected) in cases {
            let outcome = scan(&[*wire]);
            assert_eq!(outcome.results.as_slice(), *expected);
            assert!(!outcome.overflowed);
            assert!(!outcome.unknown);
        }
    }

    #[test]
    fn skips_leading_empty_lines_without_publishing_signals() {
        let request = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n";
        for prefix in [b"\r\n".as_slice(), b"\n", b"\r\n\n\r\n"] {
            let outcome = scan(&[prefix, request]);
            assert_eq!(outcome.results, [H1FramingResult::Conflict]);
            assert!(!outcome.overflowed);
            assert!(!outcome.unknown);
        }
    }

    #[test]
    fn leading_empty_line_run_cannot_exhaust_signal_ring() {
        let mut wire = vec![b'\n'; SIGNAL_CAPACITY as usize];
        wire.extend_from_slice(
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
        );
        let outcome = scan(&[&wire]);
        assert_eq!(outcome.results, [H1FramingResult::Conflict]);
        assert!(!outcome.overflowed);
        assert!(!outcome.unknown);
    }

    #[test]
    fn preserves_classification_across_every_split_boundary() {
        let request = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n6\r\nhello!\r\n0\r\n\r\n";
        for split in 0..=request.len() {
            let outcome = scan(&[&request[..split], &request[split..]]);
            assert_eq!(
                outcome.results,
                [H1FramingResult::Conflict],
                "split boundary {split}"
            );
            assert!(!outcome.overflowed, "split boundary {split}");
            assert!(!outcome.unknown, "split boundary {split}");
        }
    }

    #[test]
    fn classifies_pipelined_heads_in_order() {
        let wire = b"GET /one HTTP/1.1\r\nHost: a\r\n\r\nPOST /two HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n";
        let outcome = scan(&[wire]);
        assert_eq!(
            outcome.results,
            [H1FramingResult::Clear, H1FramingResult::Conflict]
        );
        assert!(!outcome.overflowed);
        assert!(!outcome.unknown);
    }

    #[test]
    fn tracks_chunked_body_with_trailers() {
        let wire = b"POST /one HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trace: done\r\n\r\n";
        let outcome = scan(&[wire]);
        assert_eq!(outcome.results, [H1FramingResult::Clear]);
        assert!(!outcome.overflowed);
        assert!(!outcome.unknown);
    }

    #[test]
    fn tracks_chunked_body_before_pipelined_request() {
        let wire = b"POST /one HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\nX-Trace: done\r\n\r\nPOST /two HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n";
        let outcome = scan(&[wire]);
        assert_eq!(
            outcome.results,
            [H1FramingResult::Clear, H1FramingResult::Conflict]
        );
        assert!(!outcome.overflowed);
        assert!(!outcome.unknown);
    }

    #[test]
    fn rejected_nonempty_chunk_keeps_pipelined_signal_counters_aligned() {
        let wire = b"POST /first HTTP/1.1\r\n\
                     Host: a\r\n\
                     Transfer-Encoding: chunked\r\n\
                     Content-Length: 6\r\n\
                     \r\n\
                     6\r\nhello!\r\n0\r\n\r\n\
                     GET /second HTTP/1.1\r\n\
                     Host: a\r\n\
                     \r\n";
        let signals = H1FramingSignals::new();
        let mut scanner = WireScanner::new(TEST_MAX_HEAD_BYTES);
        scanner.observe(wire, &signals);

        // The observer advances over the raw body independently of whether the
        // service polls Hyper's Incoming body. It publishes both heads before
        // either service invocation consumes its connection-local signal.
        assert_eq!(signals.produced.load(Ordering::Acquire), 2);
        assert_eq!(signals.consumed.load(Ordering::Acquire), 0);
        assert_eq!(signals.next_conflict(), H1FramingResult::Conflict);
        assert_eq!(signals.produced.load(Ordering::Acquire), 2);
        assert_eq!(signals.consumed.load(Ordering::Acquire), 1);
        assert_eq!(signals.next_conflict(), H1FramingResult::Clear);
        assert_eq!(
            signals.produced.load(Ordering::Acquire),
            signals.consumed.load(Ordering::Acquire)
        );
        assert!(!signals.overflowed.load(Ordering::Acquire));
        assert!(!signals.unknown.load(Ordering::Acquire));
    }

    #[test]
    fn trailer_budget_matches_hyper_when_head_limit_is_smaller() {
        let mut wire =
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: ".to_vec();
        wire.extend(std::iter::repeat_n(b'a', 9 * 1024));
        wire.extend_from_slice(b"\r\n\r\n");

        let outcome = scan_with_max_head(8 * 1024, &[&wire]);
        assert_eq!(outcome.results, [H1FramingResult::Clear]);
        assert!(!outcome.overflowed);
        assert!(!outcome.unknown);
    }

    #[test]
    fn body_boundary_reads_avoid_remainder_sized_short_reads() {
        let wholly_inside_body = body_boundary_read_cap(64 * 1024, 64 * 1024);
        assert_eq!(wholly_inside_body, 64 * 1024);

        let crossing_boundary = body_boundary_read_cap(64 * 1024, 1);
        assert_eq!(crossing_boundary, OBSERVED_READ_CAP + 1);
    }

    #[test]
    fn signal_overflow_and_consumer_underflow_fail_closed() {
        let overflowed = H1FramingSignals::new();
        for _ in 0..SIGNAL_CAPACITY {
            assert!(overflowed.push(false));
        }
        assert!(!overflowed.push(false));
        assert_eq!(overflowed.next_conflict(), H1FramingResult::ObserverFailed);

        let underflowed = H1FramingSignals::new();
        assert_eq!(underflowed.next_conflict(), H1FramingResult::ObserverFailed);
        assert!(underflowed.unknown.load(Ordering::Acquire));
        assert_eq!(underflowed.next_conflict(), H1FramingResult::ObserverFailed);
    }

    #[test]
    fn scanner_disable_marks_observation_unknown() {
        let signals = H1FramingSignals::new();
        let mut scanner = WireScanner::new(TEST_MAX_HEAD_BYTES);
        scanner.observe(
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nZ",
            &signals,
        );
        assert!(matches!(scanner.protocol, Protocol::Disabled));
        assert!(signals.unknown.load(Ordering::Acquire));
        assert_eq!(signals.next_conflict(), H1FramingResult::ObserverFailed);
    }

    #[test]
    fn requested_upgrade_disable_is_not_an_observer_failure() {
        let signals = H1FramingSignals::new();
        let mut scanner = WireScanner::new(TEST_MAX_HEAD_BYTES);
        scanner.observe(
            b"GET /chat HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            &signals,
        );
        assert!(matches!(scanner.protocol, Protocol::Http1));
        assert_eq!(signals.next_conflict(), H1FramingResult::Clear);

        signals.disable_observation();
        scanner.disable_if_requested(&signals);
        scanner.observe(
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n",
            &signals,
        );
        assert!(matches!(scanner.protocol, Protocol::Disabled));
        assert_eq!(scanner.read_cap(64 * 1024), 64 * 1024);
        assert_eq!(signals.produced.load(Ordering::Acquire), 1);
        assert_eq!(signals.consumed.load(Ordering::Acquire), 1);
        assert!(!signals.overflowed.load(Ordering::Acquire));
        assert!(!signals.unknown.load(Ordering::Acquire));
    }

    #[test]
    fn parse_reject_hints_cover_known_hyper_parse_shapes() {
        let conflicting = scan(&[
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 0\r\n\r\n",
        ]);
        assert_eq!(
            conflicting.parse_reject_hint,
            PARSE_HINT_CONFLICTING_CONTENT_LENGTH
        );

        let http10_te = scan(&[b"GET / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"]);
        assert_eq!(
            http10_te.parse_reject_hint,
            PARSE_HINT_HTTP10_TRANSFER_ENCODING
        );

        let latin1_target = scan(&[b"GET /\xE9 HTTP/1.1\r\nHost: a\r\n\r\n"]);
        assert_eq!(
            latin1_target.parse_reject_hint,
            PARSE_HINT_INVALID_REQUEST_TARGET_UTF8
        );
    }

    #[test]
    fn valid_utf8_request_target_is_not_a_parse_reject() {
        let cafe = scan(&[b"GET /caf\xC3\xA9 HTTP/1.1\r\nHost: a\r\n\r\n"]);
        assert_eq!(cafe.parse_reject_hint, PARSE_HINT_NONE);
        assert_eq!(cafe.results, [H1FramingResult::Clear]);
    }

    #[test]
    fn handler_layer_shapes_do_not_publish_parse_reject_hints() {
        let cl_te = scan(&[
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n",
        ]);
        assert_eq!(cl_te.parse_reject_hint, PARSE_HINT_NONE);
        assert_eq!(cl_te.results, [H1FramingResult::Conflict]);

        let dup_host = scan(&[b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"]);
        assert_eq!(dup_host.parse_reject_hint, PARSE_HINT_NONE);
        assert_eq!(dup_host.results, [H1FramingResult::Clear]);
    }

    #[test]
    fn parse_reject_envelopes_match_check_protocol_headers_bodies() {
        fn envelope_body(envelope: &[u8]) -> &[u8] {
            envelope
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|idx| &envelope[idx + 4..])
                .expect("envelope must include a body")
        }

        let conflicting = envelope_for_hint(PARSE_HINT_CONFLICTING_CONTENT_LENGTH);
        assert_eq!(
            envelope_body(conflicting),
            JSON_CONFLICTING_CONTENT_LENGTH.as_bytes()
        );
        let conflicting_text = std::str::from_utf8(conflicting).expect("utf-8 envelope");
        assert!(conflicting_text.contains("content-type: application/json"));
        assert!(conflicting_text.contains("x-gateway-error: request_error"));
        assert!(conflicting_text.contains("connection: close"));

        let http10_te = envelope_for_hint(PARSE_HINT_HTTP10_TRANSFER_ENCODING);
        assert_eq!(
            envelope_body(http10_te),
            JSON_HTTP10_TRANSFER_ENCODING.as_bytes()
        );

        let malformed = envelope_for_hint(PARSE_HINT_INVALID_REQUEST_TARGET_UTF8);
        assert_eq!(
            envelope_body(malformed),
            JSON_MALFORMED_HTTP_REQUEST.as_bytes()
        );
    }

    /// Minimal duplex used to drive `H1FramingGuardIo` directly: `reads` are
    /// handed out one chunk per `poll_read`, and everything written lands in
    /// `written` so a test can prove exactly what reached the socket.
    struct MockIo {
        reads: std::collections::VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockIo {
        fn new(reads: &[&[u8]]) -> Self {
            Self {
                reads: reads.iter().map(|chunk| chunk.to_vec()).collect(),
                written: Vec::new(),
            }
        }
    }

    impl AsyncRead for MockIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.reads.pop_front() {
                buf.put_slice(&chunk);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    const CONFLICTING_CL_HEAD: &[u8] =
        b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";

    /// Read the guard once per queued chunk and report what reached the socket.
    fn drive(io_reads: &[&[u8]], preceding_response: Option<&[u8]>) -> Vec<u8> {
        let (mut guard, _signals) =
            H1FramingGuardIo::new(MockIo::new(io_reads), TEST_MAX_HEAD_BYTES);
        let mut cx = Context::from_waker(std::task::Waker::noop());

        if let Some(response) = preceding_response {
            let wrote = Pin::new(&mut guard).poll_write(&mut cx, response);
            assert!(matches!(wrote, Poll::Ready(Ok(n)) if n == response.len()));
        }

        let mut storage = [0u8; 4096];
        for _ in 0..io_reads.len() {
            let mut buf = ReadBuf::new(&mut storage);
            let _ = Pin::new(&mut guard).poll_read(&mut cx, &mut buf);
        }
        guard.inner.written
    }

    #[test]
    fn parse_reject_envelope_is_written_on_a_fresh_connection() {
        let written = drive(&[CONFLICTING_CL_HEAD], None);
        assert_eq!(
            written, ENVELOPE_CONFLICTING_CONTENT_LENGTH,
            "a malformed first request must get the JSON envelope"
        );
    }

    #[test]
    fn parse_reject_envelope_is_withheld_once_a_response_has_begun() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let written = drive(&[CONFLICTING_CL_HEAD], Some(response));
        assert_eq!(
            written, response,
            "the envelope must never be spliced into an in-flight response; a \
             malformed request pipelined behind one falls back to Hyper's 400"
        );
    }
}

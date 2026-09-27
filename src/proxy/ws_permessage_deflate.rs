//! Gateway-terminated RFC 7692 `permessage-deflate` (issue #5769, option b).
//!
//! A proxy with `websocket_permessage_deflate: terminate` negotiates the
//! extension on each leg on its own: the gateway answers the client's offer
//! itself and sends the backend its own offer. Every message is inflated before
//! the shared frame relay parses it, so frame and body-inspecting plugins (the
//! WAF WebSocket scanner included) always see plaintext, and it is re-deflated
//! toward whichever leg negotiated compression after every plugin has run.
//!
//! The pieces:
//!
//! - **Negotiation.** [`offer_termination`] answers the client's offer and
//!   replaces the backend offer with [`BACKEND_OFFER`];
//!   [`TerminationHandshake::complete`] validates the backend's answer and
//!   yields the per-leg [`DeflateLegConfig`]s.
//! - **Inflate.** [`PermessageDeflateIo`] sits beneath a leg's WebSocket framer
//!   and rewrites each compressed wire frame into the uncompressed frame the
//!   framer expects, keeping the wire fragmentation (so fragment metering and
//!   the incomplete-message bounds count real frames). Every other frame is
//!   forwarded byte-for-byte, so the framer still enforces RFC 6455: RSV1 on a
//!   control or continuation frame, RSV2/RSV3, masking, and opcode errors fail
//!   the connection exactly as they would without the extension.
//! - **Deflate.** [`PermessageDeflateEncoder`] compresses each outgoing Text or
//!   Binary message into one RSV1 frame. Control frames are never compressed.
//!
//! Decompression is bounded: a compressed wire frame may not exceed the leg's
//! frame ceiling, one frame may not inflate past it, and a message may not
//! inflate past the decompressed-message ceiling
//! (`FERRUM_WEBSOCKET_PERMESSAGE_DEFLATE_MAX_MESSAGE_BYTES`, never above the
//! parser's reassembled-message ceiling). Inflation stops one byte past the
//! limit, so no buffer grows beyond its ceiling, and the relay closes the leg
//! with 1009. The decoder keeps a fixed 32 KiB LZ77 window (the RFC 7692
//! maximum, `*_max_window_bits=15`), so per-leg memory is fixed apart from
//! those bounded buffers.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data as OpData, OpCode};
use tokio_tungstenite::tungstenite::protocol::frame::{CloseFrame, Frame};
use tokio_tungstenite::tungstenite::protocol::{Message, Role};

/// The RFC 7692 extension token.
pub const PERMESSAGE_DEFLATE: &str = "permessage-deflate";

/// The offer a `terminate` proxy sends to its backend.
///
/// No parameters: the gateway's compressor is never window-limited by the
/// backend (RFC 7692 §7.1.2.2 forbids `client_max_window_bits` in an answer to
/// an offer that did not carry it), and the backend chooses its own context
/// takeover and window, which the gateway's decoder always accepts.
pub const BACKEND_OFFER: &str = PERMESSAGE_DEFLATE;

/// Largest LZ77 window RFC 7692 allows (`*_max_window_bits=15`, 32 KiB).
pub const MAX_WINDOW_BITS: u8 = 15;
const MIN_WINDOW_BITS: u8 = 8;

/// RFC 7692 §7.2.1: the empty stored block a sync flush ends with, which the
/// sender strips and the receiver appends back.
const DEFLATE_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Raw bytes read from the transport per read call, and the inflate output
/// step. Both are per-leg scratch, not per-message buffers.
const SCRATCH_BYTES: usize = 16 * 1024;

const FIN: u8 = 0x80;
const RSV1: u8 = 0x40;
const RSV2_RSV3: u8 = 0x30;
const OPCODE_MASK: u8 = 0x0f;
const OPCODE_CONTINUATION: u8 = 0x0;
const OPCODE_TEXT: u8 = 0x1;
const OPCODE_BINARY: u8 = 0x2;
const OPCODE_CONTROL_BIT: u8 = 0x8;

/// How the gateway compresses toward one leg that negotiated the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateLegConfig {
    /// The gateway resets its compressor after every message to this peer.
    pub outbound_no_context_takeover: bool,
    /// The LZ77 window every back-reference toward this peer must stay within.
    pub outbound_max_window_bits: u8,
}

/// The gateway's answer to a client offer it accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientDeflateAgreement {
    /// The `Sec-WebSocket-Extensions` value returned to the client.
    pub response: String,
    /// How the gateway compresses toward the client.
    pub leg: DeflateLegConfig,
}

/// Parameters of one `permessage-deflate` offer or answer element.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DeflateParams {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    /// `Some(None)`: present without a value (offer-only form).
    client_max_window_bits: Option<Option<u8>>,
}

/// Split a `Sec-WebSocket-Extensions` value into its list elements (RFC 6455
/// §9.1), respecting quoted strings. Empty elements are skipped; an
/// unterminated quoted string yields `None`.
fn split_extension_list(value: &str) -> Option<Vec<&str>> {
    let mut elements = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quotes = false;
            }
            continue;
        }
        match byte {
            b'"' => in_quotes = true,
            b',' => {
                let element = value[start..index].trim();
                if !element.is_empty() {
                    elements.push(element);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if in_quotes {
        return None;
    }
    let element = value[start..].trim();
    if !element.is_empty() {
        elements.push(element);
    }
    Some(elements)
}

/// A parameter value, unquoted. A quoted-string may not contain escapes or
/// quotes: every RFC 7692 value is a plain decimal integer.
fn unquote_param_value(value: &str) -> Option<&str> {
    let inner = match value.strip_prefix('"') {
        Some(rest) => rest.strip_suffix('"')?,
        None => value,
    };
    if inner.is_empty() || inner.contains(['"', '\\']) {
        return None;
    }
    Some(inner)
}

/// RFC 7692 §7.1.2: a decimal integer 8..=15 without leading zeros.
fn parse_window_bits(value: &str) -> Option<u8> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) || value.starts_with('0') {
        return None;
    }
    let bits: u8 = value.parse().ok()?;
    (MIN_WINDOW_BITS..=MAX_WINDOW_BITS)
        .contains(&bits)
        .then_some(bits)
}

/// Parse one extension element. `None` when it is not `permessage-deflate`;
/// `Some(None)` when it is but its parameters are invalid (RFC 7692 §7:
/// unknown or duplicate parameters and out-of-range values).
fn parse_deflate_element(element: &str) -> Option<Option<DeflateParams>> {
    let mut parts = element.split(';');
    let name = parts.next().unwrap_or_default().trim();
    if !name.eq_ignore_ascii_case(PERMESSAGE_DEFLATE) {
        return None;
    }
    Some(parse_deflate_params(parts))
}

fn parse_deflate_params<'a>(parts: impl Iterator<Item = &'a str>) -> Option<DeflateParams> {
    let mut params = DeflateParams::default();
    let mut seen = [false; 4];
    for part in parts {
        let part = part.trim();
        let (key, value) = match part.split_once('=') {
            Some((key, value)) => (key.trim(), Some(unquote_param_value(value.trim())?)),
            None => (part, None),
        };
        let slot = if key.eq_ignore_ascii_case("server_no_context_takeover") {
            0
        } else if key.eq_ignore_ascii_case("client_no_context_takeover") {
            1
        } else if key.eq_ignore_ascii_case("server_max_window_bits") {
            2
        } else if key.eq_ignore_ascii_case("client_max_window_bits") {
            3
        } else {
            return None;
        };
        if std::mem::replace(&mut seen[slot], true) {
            return None;
        }
        match slot {
            0 => {
                if value.is_some() {
                    return None;
                }
                params.server_no_context_takeover = true;
            }
            1 => {
                if value.is_some() {
                    return None;
                }
                params.client_no_context_takeover = true;
            }
            2 => params.server_max_window_bits = Some(parse_window_bits(value?)?),
            _ => {
                params.client_max_window_bits = Some(match value {
                    Some(value) => Some(parse_window_bits(value)?),
                    None => None,
                });
            }
        }
    }
    Some(params)
}

/// Accept the first valid `permessage-deflate` element of a client offer.
///
/// The answer echoes `server_no_context_takeover` and `server_max_window_bits`
/// when offered (RFC 7692 §7.1.1.1 and §7.1.2.1 oblige the server to honor
/// them) and never asks the client to limit itself: the gateway decoder always
/// runs a full 32 KiB window. Invalid elements are declined and the next one is
/// tried; `None` means no acceptable element.
pub fn negotiate_client_offer(offer: &str) -> Option<ClientDeflateAgreement> {
    for element in split_extension_list(offer)? {
        let Some(Some(params)) = parse_deflate_element(element) else {
            continue;
        };
        let mut response = String::from(PERMESSAGE_DEFLATE);
        if params.server_no_context_takeover {
            response.push_str("; server_no_context_takeover");
        }
        if let Some(bits) = params.server_max_window_bits {
            response.push_str("; server_max_window_bits=");
            response.push_str(&bits.to_string());
        }
        return Some(ClientDeflateAgreement {
            response,
            leg: DeflateLegConfig {
                outbound_no_context_takeover: params.server_no_context_takeover,
                outbound_max_window_bits: params.server_max_window_bits.unwrap_or(MAX_WINDOW_BITS),
            },
        });
    }
    None
}

/// Validate the backend's answer to [`BACKEND_OFFER`] (RFC 7692 §7).
///
/// Exactly one `permessage-deflate` element with known, non-duplicate,
/// in-range parameters is accepted. `client_max_window_bits` is refused because
/// the gateway did not offer it. An invalid answer must fail the connection, so
/// the caller refuses the upgrade.
pub fn parse_backend_answer(answer: &str) -> Result<DeflateLegConfig, &'static str> {
    let elements = split_extension_list(answer).ok_or("malformed extension list")?;
    let [element] = elements.as_slice() else {
        return Err("expected exactly one permessage-deflate element");
    };
    let params = match parse_deflate_element(element) {
        Some(Some(params)) => params,
        Some(None) => return Err("invalid permessage-deflate parameters"),
        None => return Err("unexpected extension"),
    };
    if params.client_max_window_bits.is_some() {
        return Err("client_max_window_bits was not offered");
    }
    Ok(DeflateLegConfig {
        outbound_no_context_takeover: params.client_no_context_takeover,
        outbound_max_window_bits: MAX_WINDOW_BITS,
    })
}

/// The negotiation state of one `terminate` upgrade between the client answer
/// and the backend answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminationHandshake {
    client: Option<ClientDeflateAgreement>,
}

/// Both legs' outcome for one `terminate` upgrade.
#[derive(Debug, Default)]
pub struct NegotiatedTermination {
    /// `Sec-WebSocket-Extensions` value for the client response, if the
    /// client leg negotiated the extension.
    pub client_response: Option<String>,
    /// The relay configuration; `None` when neither leg negotiated.
    pub session: Option<WsDeflateTermination>,
}

/// Start a `terminate` upgrade: answer the client's offer (from the
/// plugin-sanitized request headers) and put [`BACKEND_OFFER`] in place of any
/// extension header bound for the backend.
///
/// An offer the client nominated as hop-by-hop through `Connection` is not
/// accepted, matching the passthrough gate.
pub fn offer_termination(
    client_offer: Option<&str>,
    offer_is_connection_listed: bool,
    backend_headers: &mut Vec<(String, String)>,
) -> TerminationHandshake {
    backend_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("sec-websocket-extensions"));
    backend_headers.push((
        "sec-websocket-extensions".to_string(),
        BACKEND_OFFER.to_string(),
    ));
    let client = match client_offer {
        Some(offer) if !offer_is_connection_listed => negotiate_client_offer(offer),
        _ => None,
    };
    TerminationHandshake { client }
}

impl TerminationHandshake {
    /// The client leg's agreement, if the client offered an acceptable element.
    pub fn client_agreement(&self) -> Option<&ClientDeflateAgreement> {
        self.client.as_ref()
    }

    /// Finish negotiation with the backend's `permessage-deflate` answer
    /// (`None` when it declined). An invalid answer is an error.
    pub fn complete(
        self,
        backend_answer: Option<&str>,
        max_decompressed_message_bytes: usize,
    ) -> Result<NegotiatedTermination, &'static str> {
        let backend = backend_answer.map(parse_backend_answer).transpose()?;
        let client_leg = self.client.as_ref().map(|agreement| agreement.leg);
        Ok(NegotiatedTermination {
            client_response: self.client.map(|agreement| agreement.response),
            session: WsDeflateTermination::new(client_leg, backend, max_decompressed_message_bytes),
        })
    }
}

/// A terminated session's per-leg configuration, handed to the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsDeflateTermination {
    /// The client leg negotiated the extension.
    pub client: Option<DeflateLegConfig>,
    /// The backend leg negotiated the extension.
    pub backend: Option<DeflateLegConfig>,
    /// `FERRUM_WEBSOCKET_PERMESSAGE_DEFLATE_MAX_MESSAGE_BYTES`; `0` means the
    /// parser's reassembled-message ceiling.
    pub max_decompressed_message_bytes: usize,
}

impl WsDeflateTermination {
    /// `None` unless at least one leg negotiated the extension, so a
    /// `terminate` proxy whose peers both declined keeps the ordinary relay.
    pub fn new(
        client: Option<DeflateLegConfig>,
        backend: Option<DeflateLegConfig>,
        max_decompressed_message_bytes: usize,
    ) -> Option<Self> {
        (client.is_some() || backend.is_some()).then_some(Self {
            client,
            backend,
            max_decompressed_message_bytes,
        })
    }

    /// The decompressed-message ceiling under a parser message ceiling.
    fn message_ceiling(&self, parser_max_message_bytes: usize) -> usize {
        match self.max_decompressed_message_bytes {
            0 => parser_max_message_bytes,
            configured => configured.min(parser_max_message_bytes),
        }
    }

    /// Put the inflate adapters beneath both framers and build the outbound
    /// encoders.
    ///
    /// Both legs are wrapped (a leg that did not negotiate forwards bytes
    /// untouched) and type-erased, so every frontend/backend transport pair
    /// shares one monomorphization of the relay for terminated sessions. The
    /// backend framer is rebuilt at the handshake's frame boundary with its
    /// original configuration; bytes the backend coalesced with its handshake
    /// response are replayed through the adapter first.
    pub(crate) async fn wrap<C, B>(
        self,
        client_io: C,
        backend: WebSocketStream<B>,
        client_max_frame_bytes: usize,
        client_max_message_bytes: usize,
    ) -> TerminatedWsStreams
    where
        C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let config = *backend.get_config();
        let (backend_io, residual) = backend.into_inner_with_read_buffer();
        let backend_message_bytes = config.max_message_size.unwrap_or(client_max_message_bytes);
        let backend_limits = self.backend.map(|_| InflateLimits {
            max_frame_bytes: config.max_frame_size.unwrap_or(client_max_frame_bytes),
            max_message_bytes: self.message_ceiling(backend_message_bytes),
        });
        let client_limits = self.client.map(|_| InflateLimits {
            max_frame_bytes: client_max_frame_bytes,
            max_message_bytes: self.message_ceiling(client_max_message_bytes),
        });
        let backend_io: BoxedWsIo = Box::new(backend_io);
        let backend = WebSocketStream::from_raw_socket(
            PermessageDeflateIo::new(backend_io, residual, backend_limits),
            Role::Client,
            Some(config),
        )
        .await;
        let client_io: BoxedWsIo = Box::new(client_io);
        TerminatedWsStreams {
            client_io: PermessageDeflateIo::new(client_io, Bytes::new(), client_limits),
            backend,
            to_client: self.client.map(PermessageDeflateEncoder::new),
            to_backend: self.backend.map(PermessageDeflateEncoder::new),
        }
    }
}

/// A byte transport erased to one type for the terminated relay.
pub(crate) trait WsTransport: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> WsTransport for T {}

pub(crate) type BoxedWsIo = Box<dyn WsTransport>;

/// Output of [`WsDeflateTermination::wrap`].
pub(crate) struct TerminatedWsStreams {
    pub(crate) client_io: PermessageDeflateIo<BoxedWsIo>,
    pub(crate) backend: WebSocketStream<PermessageDeflateIo<BoxedWsIo>>,
    pub(crate) to_client: Option<PermessageDeflateEncoder>,
    pub(crate) to_backend: Option<PermessageDeflateEncoder>,
}

/// Transforms each relayed message just before it is written to a leg.
///
/// The ordinary relay uses [`PlainOutbound`], which is the identity and
/// compiles away; only terminated sessions compress.
pub trait WsOutboundCodec: Send + 'static {
    fn encode(&mut self, message: Message) -> Message;
}

/// The identity codec for sessions that do not terminate compression.
pub struct PlainOutbound;

impl WsOutboundCodec for PlainOutbound {
    #[inline(always)]
    fn encode(&mut self, message: Message) -> Message {
        message
    }
}

impl WsOutboundCodec for Option<PermessageDeflateEncoder> {
    #[inline]
    fn encode(&mut self, message: Message) -> Message {
        match self {
            Some(encoder) => encoder.encode_message(message),
            None => message,
        }
    }
}

/// Compresses outgoing messages toward one leg (RFC 7692 §7.2.1).
pub struct PermessageDeflateEncoder {
    compress: Compress,
    reset_after_message: bool,
    /// Largest message that may be compressed; `None` means any.
    max_compressible_bytes: Option<usize>,
}

impl fmt::Debug for PermessageDeflateEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PermessageDeflateEncoder")
            .field("reset_after_message", &self.reset_after_message)
            .field("max_compressible_bytes", &self.max_compressible_bytes)
            .finish()
    }
}

impl PermessageDeflateEncoder {
    pub fn new(leg: DeflateLegConfig) -> Self {
        // The pure-Rust DEFLATE backend always uses a 32 KiB window. When the
        // peer limited the gateway to a smaller one, the compressor starts
        // fresh for every message and only messages no longer than that window
        // are compressed: a back-reference can then never reach further than
        // the window. Larger messages go out uncompressed, which RFC 7692
        // permits for any message.
        let window_limited = leg.outbound_max_window_bits < MAX_WINDOW_BITS;
        Self {
            compress: Compress::new(Compression::default(), false),
            reset_after_message: leg.outbound_no_context_takeover || window_limited,
            max_compressible_bytes: window_limited.then(|| 1usize << leg.outbound_max_window_bits),
        }
    }

    /// Compress one message payload, or `None` to send it uncompressed.
    ///
    /// An uncompressed message never touches the compressor, so skipping one
    /// is always safe under context takeover. A compressor fault resets the
    /// compressor before the message goes out uncompressed, so later messages
    /// never reference history the peer did not receive.
    pub fn compress_payload(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let exceeds_window = self
            .max_compressible_bytes
            .is_some_and(|max| payload.len() > max);
        if payload.is_empty() || exceeds_window {
            return None;
        }
        let compressed = self.deflate_sync(payload);
        if compressed.is_none() || self.reset_after_message {
            self.compress.reset();
        }
        compressed
    }

    fn deflate_sync(&mut self, payload: &[u8]) -> Option<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 64);
        let start_in = self.compress.total_in();
        loop {
            if out.capacity() - out.len() < 64 {
                out.reserve(out.capacity().max(1024));
            }
            let before_in = self.compress.total_in();
            let before_out = out.len();
            let consumed = usize::try_from(before_in - start_in).ok()?;
            self.compress
                .compress_vec(&payload[consumed..], &mut out, FlushCompress::Sync)
                .ok()?;
            let consumed = usize::try_from(self.compress.total_in() - start_in).ok()?;
            // The sync flush is complete once every input byte is consumed and
            // the compressor stopped short of filling the output.
            if consumed == payload.len() && out.len() < out.capacity() {
                break;
            }
            if self.compress.total_in() == before_in && out.len() == before_out {
                return None;
            }
        }
        if !out.ends_with(&DEFLATE_TAIL) {
            return None;
        }
        out.truncate(out.len() - DEFLATE_TAIL.len());
        Some(out)
    }

    /// Compress a Text or Binary message into one RSV1 frame. Control frames
    /// and messages [`Self::compress_payload`] declines pass through unchanged.
    pub fn encode_message(&mut self, message: Message) -> Message {
        let (opcode, compressed) = match &message {
            Message::Text(text) => (OpData::Text, self.compress_payload(text.as_bytes())),
            Message::Binary(data) => (OpData::Binary, self.compress_payload(data)),
            _ => return message,
        };
        let Some(compressed) = compressed else {
            return message;
        };
        let mut frame = Frame::message(compressed, OpCode::Data(opcode), true);
        frame.header_mut().rsv1 = true;
        Message::Frame(frame)
    }
}

/// A decompression limit or corrupt-input failure on one leg. It reaches the
/// relay as the `io::Error` source of the framer's read error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermessageDeflateFault {
    /// A compressed wire frame declared more than the frame ceiling.
    CompressedFrameTooLarge { size: u64, max: usize },
    /// One frame inflated past the frame ceiling.
    DecompressedFrameTooLarge { max: usize },
    /// A message inflated past the decompressed-message ceiling.
    DecompressedMessageTooLarge { max: usize },
    /// The compressed payload is not a valid DEFLATE stream.
    InvalidCompressedData,
}

impl fmt::Display for PermessageDeflateFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompressedFrameTooLarge { size, max } => write!(
                f,
                "permessage-deflate frame of {size} bytes exceeds the {max}-byte frame limit"
            ),
            Self::DecompressedFrameTooLarge { max } => write!(
                f,
                "permessage-deflate frame inflates past the {max}-byte frame limit"
            ),
            Self::DecompressedMessageTooLarge { max } => write!(
                f,
                "permessage-deflate message inflates past the {max}-byte message limit"
            ),
            Self::InvalidCompressedData => f.write_str("invalid permessage-deflate data"),
        }
    }
}

impl std::error::Error for PermessageDeflateFault {}

impl From<PermessageDeflateFault> for io::Error {
    fn from(fault: PermessageDeflateFault) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, fault)
    }
}

impl PermessageDeflateFault {
    /// Stable log label.
    pub fn kind(self) -> &'static str {
        match self {
            Self::CompressedFrameTooLarge { .. } => "deflate_compressed_frame",
            Self::DecompressedFrameTooLarge { .. } => "deflate_decompressed_frame",
            Self::DecompressedMessageTooLarge { .. } => "deflate_decompressed_message",
            Self::InvalidCompressedData => "deflate_invalid_data",
        }
    }

    /// Whether the fault is a size limit (Close 1009) rather than corrupt
    /// input (Close 1007).
    pub fn is_size_limit(self) -> bool {
        !matches!(self, Self::InvalidCompressedData)
    }

    /// The bounded, non-secret Close published to both peers.
    pub fn close_frame(self) -> CloseFrame {
        let (code, reason) = match self {
            Self::CompressedFrameTooLarge { .. } => (CloseCode::Size, "compressed frame too large"),
            Self::DecompressedFrameTooLarge { .. } => {
                (CloseCode::Size, "decompressed frame too large")
            }
            Self::DecompressedMessageTooLarge { .. } => {
                (CloseCode::Size, "decompressed message too large")
            }
            Self::InvalidCompressedData => (CloseCode::Invalid, "invalid compressed data"),
        };
        CloseFrame {
            code,
            reason: reason.into(),
        }
    }
}

/// The decompression fault behind a framer read error, if any.
pub fn permessage_deflate_fault(
    error: &tokio_tungstenite::tungstenite::Error,
) -> Option<PermessageDeflateFault> {
    let tokio_tungstenite::tungstenite::Error::Io(error) = error else {
        return None;
    };
    error
        .get_ref()?
        .downcast_ref::<PermessageDeflateFault>()
        .copied()
}

/// Inflate bounds for one leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InflateLimits {
    /// Largest compressed wire frame, and largest inflated frame.
    pub max_frame_bytes: usize,
    /// Largest inflated message.
    pub max_message_bytes: usize,
}

/// The transport beneath one leg's WebSocket framer in a terminated session.
///
/// With inflate limits, compressed frames read from `inner` are rewritten into
/// uncompressed frames (see the module docs); without, reads pass through.
/// Writes always pass through: outbound compression happens in the relay.
pub struct PermessageDeflateIo<S> {
    inner: S,
    /// Pass-through leg: bytes recovered from a replaced framer, served first.
    prefix: Bytes,
    reader: Option<Box<InflateReader>>,
}

impl<S> PermessageDeflateIo<S> {
    /// `prefix` holds bytes already read from `inner` (for example, frames the
    /// backend coalesced with its handshake response); they are decoded before
    /// anything read later.
    pub fn new(inner: S, prefix: Bytes, inflate: Option<InflateLimits>) -> Self {
        match inflate {
            Some(limits) => Self {
                inner,
                prefix: Bytes::new(),
                reader: Some(Box::new(InflateReader::new(limits, &prefix))),
            },
            None => Self {
                inner,
                prefix,
                reader: None,
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PermessageDeflateIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(reader) = this.reader.as_deref_mut() {
            return reader.poll_read(&mut this.inner, cx, buf);
        }
        if !this.prefix.is_empty() {
            let take = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..take]);
            this.prefix.advance(take);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PermessageDeflateIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// A parsed RFC 6455 frame header.
struct WireHeader {
    first: u8,
    masked: bool,
    mask: [u8; 4],
    payload_len: u64,
    header_len: usize,
}

fn parse_wire_header(buf: &[u8]) -> Option<WireHeader> {
    let [first, second, ..] = *buf else {
        return None;
    };
    let masked = second & 0x80 != 0;
    let (payload_len, mut header_len) = match second & 0x7f {
        126 => {
            let bytes = buf.get(2..4)?;
            (u64::from(u16::from_be_bytes([bytes[0], bytes[1]])), 4)
        }
        127 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(buf.get(2..10)?);
            (u64::from_be_bytes(bytes), 10)
        }
        short => (u64::from(short), 2),
    };
    let mut mask = [0u8; 4];
    if masked {
        mask.copy_from_slice(buf.get(header_len..header_len + 4)?);
        header_len += 4;
    }
    Some(WireHeader {
        first,
        masked,
        mask,
        payload_len,
        header_len,
    })
}

/// Header of a rewritten frame. A masked frame keeps its mask bit (so the
/// framer still enforces RFC 6455 §5.1 in both directions) with an all-zero
/// key, because its payload is already unmasked.
fn encode_wire_header(first: u8, masked: bool, payload_len: usize) -> Bytes {
    let mut header = BytesMut::with_capacity(14);
    header.put_u8(first);
    let mask_bit = if masked { 0x80 } else { 0 };
    if payload_len < 126 {
        header.put_u8(mask_bit | payload_len as u8);
    } else if let Ok(len) = u16::try_from(payload_len) {
        header.put_u8(mask_bit | 126);
        header.put_u16(len);
    } else {
        header.put_u8(mask_bit | 127);
        header.put_u64(payload_len as u64);
    }
    if masked {
        header.put_slice(&[0; 4]);
    }
    header.freeze()
}

fn unmask(payload: &mut [u8], mask: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
}

#[derive(Debug, Clone, Copy)]
enum ReadState {
    /// Waiting for a complete frame header.
    Header,
    /// Forwarding the rest of an untouched frame's payload.
    Verbatim { remaining: u64 },
    /// Collecting a compressed frame's payload.
    Compressed {
        first: u8,
        masked: bool,
        mask: [u8; 4],
        len: usize,
    },
}

enum InflateStop {
    Overflow,
    Invalid,
}

struct InflateReader {
    decompress: Decompress,
    /// A BFINAL block ended the DEFLATE stream inside the current message.
    stream_ended: bool,
    /// Transport bytes not yet transcoded. Holds at most one compressed frame
    /// (bounded by the frame ceiling) plus one read.
    raw: BytesMut,
    /// Transcoded bytes for the framer.
    out: VecDeque<Bytes>,
    scratch: Box<[u8]>,
    state: ReadState,
    /// A fragmented data message is in progress.
    in_message: bool,
    /// The in-progress message is compressed (RSV1 on its first frame).
    compressed_message: bool,
    /// Bytes the in-progress compressed message has inflated to so far.
    message_inflated: usize,
    limits: InflateLimits,
    eof: bool,
    fault: Option<PermessageDeflateFault>,
}

impl InflateReader {
    fn new(limits: InflateLimits, prefix: &[u8]) -> Self {
        Self {
            decompress: Decompress::new(false),
            stream_ended: false,
            raw: BytesMut::from(prefix),
            out: VecDeque::new(),
            scratch: vec![0u8; SCRATCH_BYTES].into_boxed_slice(),
            state: ReadState::Header,
            in_message: false,
            compressed_message: false,
            message_inflated: 0,
            limits,
            eof: false,
            fault: None,
        }
    }

    fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(front) = self.out.front_mut() {
                let take = front.len().min(buf.remaining());
                buf.put_slice(&front[..take]);
                front.advance(take);
                if front.is_empty() {
                    self.out.pop_front();
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(fault) = self.fault {
                return Poll::Ready(Err(fault.into()));
            }
            match self.transcode() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(fault) => {
                    self.fault = Some(fault);
                    return Poll::Ready(Err(fault.into()));
                }
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            let mut read_buf = ReadBuf::new(&mut self.scratch);
            match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        self.eof = true;
                    } else {
                        self.raw.extend_from_slice(filled);
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Advance the transcoder. `Ok(true)` after any progress, `Ok(false)` when
    /// more transport bytes are needed.
    fn transcode(&mut self) -> Result<bool, PermessageDeflateFault> {
        match self.state {
            ReadState::Header => self.transcode_header(),
            ReadState::Verbatim { remaining } => {
                if self.raw.is_empty() {
                    return Ok(false);
                }
                let take = usize::try_from(remaining)
                    .unwrap_or(usize::MAX)
                    .min(self.raw.len());
                self.out.push_back(self.raw.split_to(take).freeze());
                let remaining = remaining - take as u64;
                self.state = if remaining == 0 {
                    ReadState::Header
                } else {
                    ReadState::Verbatim { remaining }
                };
                Ok(true)
            }
            ReadState::Compressed {
                first,
                masked,
                mask,
                len,
            } => {
                if self.raw.len() < len {
                    self.raw.reserve(len - self.raw.len());
                    return Ok(false);
                }
                let mut payload = self.raw.split_to(len);
                if masked {
                    unmask(&mut payload, mask);
                }
                let fin = first & FIN != 0;
                let inflated = self.inflate_frame(&payload, fin)?;
                self.out
                    .push_back(encode_wire_header(first & !RSV1, masked, inflated.len()));
                if !inflated.is_empty() {
                    self.out.push_back(Bytes::from(inflated));
                }
                if fin {
                    self.finish_compressed_message();
                }
                self.state = ReadState::Header;
                Ok(true)
            }
        }
    }

    fn transcode_header(&mut self) -> Result<bool, PermessageDeflateFault> {
        let Some(header) = parse_wire_header(&self.raw) else {
            return Ok(false);
        };
        let head = self.raw.split_to(header.header_len).freeze();
        let opcode = header.first & OPCODE_MASK;
        let fin = header.first & FIN != 0;
        let rsv1 = header.first & RSV1 != 0;
        // RFC 7692 §6.1: only the first frame of a data message may carry
        // RSV1. A control frame, a continuation, RSV2/RSV3, a reserved opcode,
        // or a data frame arriving mid-message reaches the framer unchanged
        // and fails the connection there, exactly as without the extension.
        let compressed = if header.first & RSV2_RSV3 != 0 || opcode & OPCODE_CONTROL_BIT != 0 {
            false
        } else if opcode == OPCODE_CONTINUATION {
            if rsv1 || !self.in_message {
                false
            } else {
                if fin {
                    self.in_message = false;
                }
                self.compressed_message
            }
        } else if opcode == OPCODE_TEXT || opcode == OPCODE_BINARY {
            if self.in_message {
                false
            } else {
                self.in_message = !fin;
                self.compressed_message = rsv1;
                self.message_inflated = 0;
                rsv1
            }
        } else {
            false
        };
        if !compressed {
            self.out.push_back(head);
            if header.payload_len > 0 {
                self.state = ReadState::Verbatim {
                    remaining: header.payload_len,
                };
            }
            return Ok(true);
        }
        let len = match usize::try_from(header.payload_len) {
            Ok(len) if len <= self.limits.max_frame_bytes => len,
            _ => {
                return Err(PermessageDeflateFault::CompressedFrameTooLarge {
                    size: header.payload_len,
                    max: self.limits.max_frame_bytes,
                });
            }
        };
        self.state = ReadState::Compressed {
            first: header.first,
            masked: header.masked,
            mask: header.mask,
            len,
        };
        Ok(true)
    }

    /// Inflate one compressed frame within the frame and message ceilings.
    fn inflate_frame(
        &mut self,
        payload: &[u8],
        fin: bool,
    ) -> Result<Vec<u8>, PermessageDeflateFault> {
        let message_room = self
            .limits
            .max_message_bytes
            .saturating_sub(self.message_inflated);
        let limit = message_room.min(self.limits.max_frame_bytes);
        let mut inflated = Vec::new();
        let mut result = self.inflate_into(payload, &mut inflated, limit);
        if result.is_ok() && fin && !self.stream_ended {
            result = self.inflate_into(&DEFLATE_TAIL, &mut inflated, limit);
        }
        match result {
            Ok(()) => {
                self.message_inflated += inflated.len();
                Ok(inflated)
            }
            Err(InflateStop::Invalid) => Err(PermessageDeflateFault::InvalidCompressedData),
            Err(InflateStop::Overflow) if message_room <= self.limits.max_frame_bytes => {
                Err(PermessageDeflateFault::DecompressedMessageTooLarge {
                    max: self.limits.max_message_bytes,
                })
            }
            Err(InflateStop::Overflow) => Err(PermessageDeflateFault::DecompressedFrameTooLarge {
                max: self.limits.max_frame_bytes,
            }),
        }
    }

    /// Inflate `input` onto `out`, stopping as soon as `out` exceeds `limit`
    /// (so it never holds more than `limit + 1` bytes).
    fn inflate_into(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<(), InflateStop> {
        if self.stream_ended {
            // Anything after a BFINAL block inside the same message.
            return if input.is_empty() {
                Ok(())
            } else {
                Err(InflateStop::Invalid)
            };
        }
        let mut offset = 0usize;
        loop {
            let room = limit.saturating_sub(out.len()).saturating_add(1);
            let chunk = room.min(self.scratch.len());
            let before_in = self.decompress.total_in();
            let before_out = self.decompress.total_out();
            let status = self
                .decompress
                .decompress(
                    &input[offset..],
                    &mut self.scratch[..chunk],
                    FlushDecompress::None,
                )
                .map_err(|_| InflateStop::Invalid)?;
            let consumed = usize::try_from(self.decompress.total_in() - before_in)
                .map_err(|_| InflateStop::Invalid)?;
            let produced = usize::try_from(self.decompress.total_out() - before_out)
                .map_err(|_| InflateStop::Invalid)?;
            offset += consumed;
            out.extend_from_slice(&self.scratch[..produced]);
            if out.len() > limit {
                return Err(InflateStop::Overflow);
            }
            if status == Status::StreamEnd {
                self.stream_ended = true;
                return if offset == input.len() {
                    Ok(())
                } else {
                    Err(InflateStop::Invalid)
                };
            }
            if offset == input.len() && produced < chunk {
                return Ok(());
            }
            if consumed == 0 && produced == 0 {
                // No progress with input left: the stream cannot advance.
                return Err(InflateStop::Invalid);
            }
        }
    }

    fn finish_compressed_message(&mut self) {
        // The peer's compressor may keep its LZ77 window across messages
        // (context takeover), so the decoder does too. Keeping it when the
        // peer resets is harmless. Only a BFINAL block ends the stream, after
        // which the decoder must start over.
        if self.stream_ended {
            self.decompress.reset(false);
            self.stream_ended = false;
        }
        self.compressed_message = false;
        self.message_inflated = 0;
    }
}

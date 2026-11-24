//! gRPC / gRPC-Web message framing for WAF body inspection.
//!
//! A gRPC request or response body is not a document: it is a sequence of
//! length-prefixed messages (`flag(1) || u32be(length) || payload`), and the
//! `+json` codecs (`application/grpc+json`, `application/grpc-web+json`) carry
//! one JSON document PER MESSAGE behind that envelope. Scanning the framed bytes
//! as one body made every `body_json_path` rule a no-op (the 5-byte prefix makes
//! the whole stream invalid JSON) and let a compressed message (flag bit 0 set
//! under a declared `grpc-encoding`) reach the backend as opaque octets that no
//! text rule could read.
//!
//! [`split_messages`] recovers the message payloads of a body whose media type
//! is framed gRPC, without copying them (gRPC-Web **text** bodies are
//! base64-decoded first, through the same total decoder the `grpc_web` plugin
//! uses). The wire bytes are never rewritten: the backend still receives
//! exactly what the client sent.
//!
//! A governed gRPC body is NEVER scanned as one document again. Every complete
//! message that precedes a framing defect is returned for inspection — a
//! streaming RPC handler consumes those messages as they arrive, before it
//! ever reads the defect — and the defect itself (an unknown flag, a truncated
//! header, a frame overrunning the body, an undecodable gRPC-Web text body) is
//! reported as [`GrpcUninspectable::MalformedFraming`] so the caller refuses
//! it under an enforcing body policy. Bytes cut off by the WAF's own
//! `max_scan_bytes` prefix scan are not a defect: the partial final message is
//! inspected as far as it was retained, and the truncation is already
//! reported as `waf.scan_truncated`.

use std::borrow::Cow;
use std::ops::Range;

/// Most non-empty messages one framed body is inspected as. Each message costs
/// one full body-rule pass, so the count is bounded independently of
/// `max_scan_bytes` (a 1 MiB body could otherwise hold ~200k tiny messages). A
/// body with more is reported as uninspectable; the first messages up to the
/// cap are still scanned.
pub(super) const MAX_INSPECTED_GRPC_MESSAGES: usize = 1024;

/// Bit 0 of the frame flag: the payload is compressed with the request's
/// `grpc-encoding`.
const FLAG_COMPRESSED: u8 = 0x01;

/// Bit 7 of the frame flag: a gRPC-Web trailer frame.
const FLAG_TRAILER: u8 = 0x80;

/// Why a framed gRPC body cannot be fully inspected message by message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrpcUninspectable {
    /// At least one non-empty message carries the compressed flag. The WAF does
    /// not decode `grpc-encoding`, so that payload is opaque to every rule.
    CompressedMessage,
    /// The bytes after the last complete message are not a well-formed frame
    /// (unknown flag, truncated header, frame overrunning the body), or a
    /// gRPC-Web text body is not decodable base64.
    MalformedFraming,
    /// More than [`MAX_INSPECTED_GRPC_MESSAGES`] non-empty messages.
    TooManyMessages,
}

impl GrpcUninspectable {
    /// Fixed-cardinality `waf.body_uninspected` value. Never derived from body
    /// content.
    pub(super) fn as_metadata_value(self) -> &'static str {
        match self {
            GrpcUninspectable::CompressedMessage => "grpc_compressed",
            GrpcUninspectable::MalformedFraming => "grpc_malformed_framing",
            GrpcUninspectable::TooManyMessages => "grpc_message_count",
        }
    }
}

/// One inspectable message of a framed gRPC body.
#[derive(Clone, Copy)]
pub(super) struct GrpcPayload<'m> {
    /// The message payload (frame header stripped).
    pub(super) bytes: &'m [u8],
    /// A gRPC-Web trailer frame (`0x80`): header text, not a message document.
    pub(super) trailer: bool,
    /// False only for the final message the WAF's own `max_scan_bytes` window
    /// cut short: its retained prefix is scanned as text, but it is not a
    /// complete document.
    pub(super) complete: bool,
}

/// A retained message: its payload range and how it may be read.
struct MessageRange {
    range: Range<usize>,
    trailer: bool,
    complete: bool,
}

/// The message payloads of one framed gRPC body.
pub(super) struct GrpcMessages<'a> {
    /// The bytes the frames were parsed from: the body itself, or the decoded
    /// transport of a gRPC-Web text body.
    source: Cow<'a, [u8]>,
    /// The inspectable (uncompressed, non-empty) messages, in wire order.
    messages: Vec<MessageRange>,
    uninspectable: Option<GrpcUninspectable>,
    /// A gRPC-Web text body: its wire bytes are base64, which no backend reads
    /// as JSON.
    text: bool,
}

impl GrpcMessages<'_> {
    /// The first reason some part of this body cannot be inspected, if any.
    pub(super) fn uninspectable(&self) -> Option<GrpcUninspectable> {
        self.uninspectable
    }

    /// Whether the wire body is gRPC-Web text (base64).
    pub(super) fn is_text(&self) -> bool {
        self.text
    }

    /// Each inspectable message, in wire order.
    pub(super) fn payloads(&self) -> impl Iterator<Item = GrpcPayload<'_>> + '_ {
        self.messages.iter().filter_map(move |message| {
            self.source
                .get(message.range.clone())
                .map(|bytes| GrpcPayload {
                    bytes,
                    trailer: message.trailer,
                    complete: message.complete,
                })
        })
    }
}

/// Split a framed gRPC / gRPC-Web body into its message payloads.
///
/// Returns `None` only when `content_type` is not a framed gRPC media type.
/// Native gRPC admits the `0x00` / `0x01` flags; gRPC-Web also admits its
/// `0x80` / `0x81` trailer frames, whose payload is header text and is
/// inspected like a message. `truncated` says the WAF itself cut `body` to
/// `max_scan_bytes`, so a frame (or base64 group) running into the end of it
/// is a scan-window boundary rather than a client defect.
pub(super) fn split_messages<'a>(
    body: &'a [u8],
    content_type: Option<&str>,
    truncated: bool,
) -> Option<GrpcMessages<'a>> {
    let content_type = content_type?;
    if !crate::plugins::utils::body_transform::is_framed_grpc_content_type(content_type) {
        return None;
    }
    let grpc_web = crate::plugins::grpc_web::is_grpc_web_content_type(content_type);
    let text = crate::plugins::grpc_web::is_grpc_web_text(content_type);
    let source: Cow<'a, [u8]> = if text {
        // A retained prefix may end inside a 4-character base64 group; only
        // whole groups are decodable, and the cut group is past the window.
        let encoded = if truncated {
            let whole = body.len() - body.len() % 4;
            body.get(..whole).unwrap_or(body)
        } else {
            body
        };
        match crate::plugins::grpc_web::decode_grpc_web_text_body(encoded) {
            Some(decoded) => Cow::Owned(decoded),
            None if encoded.is_empty() => Cow::Borrowed(&[]),
            None => {
                return Some(GrpcMessages {
                    source: Cow::Borrowed(&[]),
                    messages: Vec::new(),
                    uninspectable: Some(GrpcUninspectable::MalformedFraming),
                    text,
                });
            }
        }
    } else {
        Cow::Borrowed(body)
    };
    let (messages, uninspectable) = frame_ranges(&source, grpc_web, truncated);
    Some(GrpcMessages {
        source,
        messages,
        uninspectable,
        text,
    })
}

type FrameRanges = (Vec<MessageRange>, Option<GrpcUninspectable>);

/// Parse frames from the start of `data`, keeping every complete message that
/// precedes the first defect. The first uninspectable reason found wins.
fn frame_ranges(data: &[u8], grpc_web: bool, truncated: bool) -> FrameRanges {
    let mut messages = Vec::new();
    let mut uninspectable: Option<GrpcUninspectable> = None;
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(header) = pos
            .checked_add(5)
            .and_then(|header_end| data.get(pos..header_end))
        else {
            // Fewer than five bytes left: a cut header at the scan window is
            // the window's edge; anything else is a truncated frame.
            if !truncated {
                note(&mut uninspectable, GrpcUninspectable::MalformedFraming);
            }
            break;
        };
        let flag = header[0];
        let known_flag = match flag {
            0x00 | 0x01 => true,
            0x80 | 0x81 => grpc_web,
            _ => false,
        };
        if !known_flag {
            note(&mut uninspectable, GrpcUninspectable::MalformedFraming);
            break;
        }
        let declared = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let header_end = pos + 5;
        let end = usize::try_from(declared)
            .ok()
            .and_then(|length| header_end.checked_add(length));
        match end {
            Some(end) if end <= data.len() => {
                push_message(
                    &mut messages,
                    &mut uninspectable,
                    flag,
                    header_end..end,
                    true,
                );
                pos = end;
            }
            _ if truncated => {
                // The message runs past the retained window: inspect what was
                // retained of it, exactly as a prefix scan inspects a body.
                push_message(
                    &mut messages,
                    &mut uninspectable,
                    flag,
                    header_end..data.len(),
                    false,
                );
                break;
            }
            _ => {
                note(&mut uninspectable, GrpcUninspectable::MalformedFraming);
                break;
            }
        }
    }
    (messages, uninspectable)
}

/// Keep one message payload for inspection, or record why it cannot be.
fn push_message(
    messages: &mut Vec<MessageRange>,
    uninspectable: &mut Option<GrpcUninspectable>,
    flag: u8,
    range: Range<usize>,
    complete: bool,
) {
    if range.is_empty() {
        return;
    }
    if flag & FLAG_COMPRESSED != 0 {
        note(uninspectable, GrpcUninspectable::CompressedMessage);
    } else if messages.len() < MAX_INSPECTED_GRPC_MESSAGES {
        messages.push(MessageRange {
            range,
            trailer: flag & FLAG_TRAILER != 0,
            complete,
        });
    } else {
        note(uninspectable, GrpcUninspectable::TooManyMessages);
    }
}

/// Record `reason` unless an earlier reason was already recorded.
fn note(slot: &mut Option<GrpcUninspectable>, reason: GrpcUninspectable) {
    if slot.is_none() {
        *slot = Some(reason);
    }
}

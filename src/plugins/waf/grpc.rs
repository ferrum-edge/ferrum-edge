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
//! exactly what the client sent. A body that is not a total, well-formed frame
//! sequence is not split, and the caller scans it as one document exactly as
//! before — such a body is not something a gRPC server accepts as an RPC.

use std::borrow::Cow;
use std::ops::Range;

/// Most non-empty messages one framed body is inspected as. Each message costs
/// one full body-rule pass, so the count is bounded independently of
/// `max_scan_bytes` (a 1 MiB body could otherwise hold ~200k tiny messages). A
/// body with more is reported as uninspectable rather than partially scanned.
pub(super) const MAX_INSPECTED_GRPC_MESSAGES: usize = 1024;

/// Bit 0 of the frame flag: the payload is compressed with the request's
/// `grpc-encoding`.
const FLAG_COMPRESSED: u8 = 0x01;

/// Why a well-framed gRPC body cannot be inspected message by message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrpcUninspectable {
    /// At least one non-empty message carries the compressed flag. The WAF does
    /// not decode `grpc-encoding`, so that payload is opaque to every rule.
    CompressedMessage,
    /// More than [`MAX_INSPECTED_GRPC_MESSAGES`] non-empty messages.
    TooManyMessages,
}

impl GrpcUninspectable {
    /// Fixed-cardinality `waf.body_uninspected` value. Never derived from body
    /// content.
    pub(super) fn as_metadata_value(self) -> &'static str {
        match self {
            GrpcUninspectable::CompressedMessage => "grpc_compressed",
            GrpcUninspectable::TooManyMessages => "grpc_message_count",
        }
    }
}

/// The message payloads of one framed gRPC body.
pub(super) struct GrpcMessages<'a> {
    /// The bytes the frames were parsed from: the body itself, or the decoded
    /// transport of a gRPC-Web text body.
    source: Cow<'a, [u8]>,
    /// Payload ranges of the inspectable (uncompressed, non-empty) messages.
    ranges: Vec<Range<usize>>,
    uninspectable: Option<GrpcUninspectable>,
}

impl GrpcMessages<'_> {
    /// Whether some message of this body cannot be inspected.
    pub(super) fn uninspectable(&self) -> Option<GrpcUninspectable> {
        self.uninspectable
    }

    /// Each inspectable message payload, in wire order.
    pub(super) fn payloads(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.ranges
            .iter()
            .filter_map(move |range| self.source.get(range.clone()))
    }
}

/// Split a framed gRPC / gRPC-Web body into its message payloads.
///
/// Returns `None` when `content_type` is not a framed gRPC media type, or when
/// the bytes are not a total, well-formed frame sequence (the caller then scans
/// the body as one document, as it always did). Native gRPC admits only the
/// `0x00` / `0x01` flags; gRPC-Web also admits its `0x80` / `0x81` trailer
/// frames, whose payload is header text and is inspected like a message.
pub(super) fn split_messages<'a>(
    body: &'a [u8],
    content_type: Option<&str>,
) -> Option<GrpcMessages<'a>> {
    let content_type = content_type?;
    if !crate::plugins::utils::body_transform::is_framed_grpc_content_type(content_type) {
        return None;
    }
    let grpc_web = crate::plugins::grpc_web::is_grpc_web_content_type(content_type);
    let source: Cow<'a, [u8]> = if crate::plugins::grpc_web::is_grpc_web_text(content_type) {
        Cow::Owned(crate::plugins::grpc_web::decode_grpc_web_text_body(body)?)
    } else {
        Cow::Borrowed(body)
    };
    let (ranges, uninspectable) = frame_ranges(&source, grpc_web)?;
    Some(GrpcMessages {
        source,
        ranges,
        uninspectable,
    })
}

type FrameRanges = (Vec<Range<usize>>, Option<GrpcUninspectable>);

fn frame_ranges(data: &[u8], grpc_web: bool) -> Option<FrameRanges> {
    if data.is_empty() {
        return None;
    }
    let mut ranges = Vec::new();
    let mut compressed = false;
    let mut too_many = false;
    let mut pos = 0usize;
    while pos < data.len() {
        let header_end = pos.checked_add(5)?;
        let header = data.get(pos..header_end)?;
        let flag = header[0];
        let known_flag = match flag {
            0x00 | 0x01 => true,
            0x80 | 0x81 => grpc_web,
            _ => false,
        };
        if !known_flag {
            return None;
        }
        let declared = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = usize::try_from(declared).ok()?;
        let end = header_end.checked_add(length)?;
        if end > data.len() {
            return None;
        }
        if length > 0 {
            if flag & FLAG_COMPRESSED != 0 {
                compressed = true;
            } else if ranges.len() < MAX_INSPECTED_GRPC_MESSAGES {
                ranges.push(header_end..end);
            } else {
                too_many = true;
            }
        }
        pos = end;
    }
    let uninspectable = if compressed {
        Some(GrpcUninspectable::CompressedMessage)
    } else if too_many {
        Some(GrpcUninspectable::TooManyMessages)
    } else {
        None
    };
    Some((ranges, uninspectable))
}

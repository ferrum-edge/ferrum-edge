//! Bounded, incremental extraction of authoritative AI token usage from
//! streaming provider responses.
//!
//! Buffering a whole model stream to read the terminal usage block is a
//! resource-exhaustion primitive: a client can hold many slow or never-ending
//! streams open while the gateway retains every byte, and incremental delivery
//! is destroyed for all of them (GHSA-q2r2-6r7h-f69x). This module gives an
//! accounting plugin the opposite shape — it *observes* bytes as they pass
//! through and retains only a fixed-size reassembly window plus the last
//! extracted usage snapshot, so per-stream state is O(1) in the stream length.
//!
//! Two wire formats are supported, matching the provider-native request shapes
//! `ai_rate_limiter` already classifies and reserves against
//! (GHSA-rxj9-f483-g53f):
//!
//! * [`StreamUsageFormat::Sse`] — `text/event-stream`. Covers OpenAI/Mistral
//!   root `usage`, Anthropic `message_start` / `message_delta`, Cohere v2
//!   `message-end`, Google Gemini `GenerateContentResponse.usageMetadata`
//!   (`streamGenerateContent?alt=sse`), and native TGI terminal
//!   `details.generated_tokens`. Provider selection and field extraction are
//!   delegated to [`super::ai_providers`] so the streaming and buffered paths
//!   cannot report different numbers for the same document.
//! * [`StreamUsageFormat::AwsEventStream`] —
//!   `application/vnd.amazon.eventstream`, the documented content type of
//!   Bedrock `InvokeModelWithResponseStream` and `ConverseStream`. Both the
//!   base64 `bytes` envelope (carrying `amazon-bedrock-invocationMetrics`) and
//!   the ConverseStream `metadata` event's `usage` block are decoded.
//!
//! ## Fail-closed posture
//!
//! The scanner never invents a count. [`StreamUsageScanner::authoritative_usage`]
//! returns `Some` only after an explicit provider usage container was parsed and
//! yielded at least one numeric field. Malformed framing, an oversized event, a
//! truncated tail, or a stream that simply never reported usage all leave it
//! `None`, which is what lets the caller apply its configured unmetered posture
//! exactly once instead of silently charging zero. All token arithmetic here is
//! *checked*: a sum that would overflow `u64` yields no total rather than a
//! saturated one.
//!
//! Damage is reported separately by [`StreamUsageScanner::malformed`], and it is
//! deliberately ordering-sensitive in *both* formats. A candidate record the
//! scanner could not decode marks the stream damaged; only a later explicit
//! authoritative usage record clears that mark, because such a record restates
//! the provider's complete cumulative counts and therefore proves nothing the
//! damage hid is still missing. Damage *after* the last authoritative usage
//! record is never cleared, so a stream whose tail was corrupted or truncated
//! can never present as a clean terminal stream and charge the older snapshot.
//!
//! ## Integrity of the AWS framing
//!
//! `application/vnd.amazon.eventstream` is HTTP *body* framing, not something the
//! HTTP transport validates. Its two documented CRC-32s — one over the eight
//! prelude bytes and one over the complete message except its own trailing
//! checksum — are therefore verified here before any declared length is honored
//! or any payload is trusted, and a mismatch fails the scan closed.
//!
//! The bounded header block is then walked in full. A frame that declares *none*
//! of the reserved headers keeps the documented compatibility path for provider
//! variants that frame a bare JSON payload. Once any of `:message-type`,
//! `:event-type`, or `:exception-type` is present the frame speaks that
//! vocabulary, and usage is authoritative only for the fully specified shape:
//! `:message-type` exactly `event`, `:event-type` exactly `chunk` or `metadata`,
//! and no `:exception-type`. A reserved header encoded with a non-`STRING` value
//! type, or declared twice, is ambiguous framing and fails closed rather than
//! being ignored as absent.
//!
//! Within a frame that *is* allowed to carry usage, the payload is a usage
//! candidate, so the same ordering-safe invariant applies: a payload (or an
//! explicit base64 `bytes` envelope's inner document) that is not a decodable
//! JSON object, and a usage container whose fields cannot be read as counts,
//! invalidate any older snapshot for settlement until a later valid
//! authoritative record recovers it. An ordinary `chunk` carrying model content
//! and no usage container is *not* damage; a `metadata` event that reported no
//! usage is, because that event kind exists to report it. CRC, prelude, header,
//! oversize, and base64 framing failures remain hard malformed/halted instead.

use serde_json::Value;

use super::ai_providers::{AiProvider, AiTokenUsage, detect_sse_provider, extract_response_usage};

/// Largest single SSE line the scanner will reassemble before giving up on it.
///
/// Provider usage events are a few hundred bytes; 64 KiB is far above any real
/// event while still bounding the per-stream reassembly buffer. A line beyond
/// this is dropped (the bytes themselves still stream to the client untouched)
/// and the stream is marked malformed, so it can never be mistaken for a
/// usage-free-but-well-formed stream.
pub const MAX_SSE_LINE_BYTES: usize = 64 * 1024;

/// Largest AWS event-stream message the scanner will reassemble.
///
/// The AWS framing allows messages up to 16 MiB, but Bedrock usage/metadata
/// messages are tiny. Capping at 256 KiB bounds per-stream state; a larger
/// declared message marks the stream malformed rather than allocating for it.
pub const MAX_EVENT_STREAM_MESSAGE_BYTES: usize = 256 * 1024;

/// Bytes of an AWS event-stream message that are framing rather than payload:
/// the 12-byte prelude (total length, headers length, prelude CRC) plus the
/// trailing 4-byte message CRC.
const EVENT_STREAM_OVERHEAD_BYTES: usize = 16;

/// Length of the AWS event-stream prelude that must be buffered before the
/// declared message length is known.
const EVENT_STREAM_PRELUDE_BYTES: usize = 12;

/// Bytes of the prelude that the prelude CRC-32 covers: the total length and
/// the headers length, but not the checksum itself.
const EVENT_STREAM_PRELUDE_CHECKED_BYTES: usize = 8;

/// Width of each of the two AWS event-stream CRC-32 fields.
const EVENT_STREAM_CRC_BYTES: usize = 4;

/// The documented Bedrock streaming media type.
const AWS_EVENT_STREAM_CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";

/// Reserved AWS event-stream header naming the frame's kind.
const EVENT_STREAM_MESSAGE_TYPE_HEADER: &str = ":message-type";

/// Reserved AWS event-stream header naming the modelled event within a frame.
const EVENT_STREAM_EVENT_TYPE_HEADER: &str = ":event-type";

/// Reserved AWS event-stream header naming a modelled service exception.
const EVENT_STREAM_EXCEPTION_TYPE_HEADER: &str = ":exception-type";

/// The only `:message-type` that carries a modelled response event; `exception`
/// and `error` frames are terminal failures, not usage authorities.
const EVENT_STREAM_EVENT_MESSAGE_TYPE: &str = "event";

/// `InvokeModelWithResponseStream`'s model event, whose terminal frame carries
/// `amazon-bedrock-invocationMetrics` inside the base64 `bytes` envelope. Every
/// other frame of that API is an ordinary content chunk.
const EVENT_STREAM_CHUNK_EVENT_TYPE: &str = "chunk";

/// `ConverseStream`'s terminal accounting event, whose payload carries `usage`.
/// Unlike `chunk`, a `metadata` event exists to report usage, so one that
/// reports none is a damaged candidate rather than ordinary content.
const EVENT_STREAM_METADATA_EVENT_TYPE: &str = "metadata";

/// Bedrock event kinds whose payload documents a usage container.
///
/// Every other modelled event (`messageStart`, `contentBlockDelta`,
/// `messageStop`, …) is content framing and must never mint usage.
const USAGE_BEARING_EVENT_TYPES: [&str; 2] = [
    EVENT_STREAM_CHUNK_EVENT_TYPE,
    EVENT_STREAM_METADATA_EVENT_TYPE,
];

/// The AWS event-stream header value type for a UTF-8 string (`STRING`). Every
/// reserved header this scanner reads is documented as a string, so one encoded
/// with any other type is malformed rather than merely unrecognized.
const EVENT_STREAM_STRING_VALUE_TYPE: u8 = 7;

/// The AWS event-stream header value type for opaque bytes (`BYTE_ARRAY`). It
/// shares the string encoding's 16-bit length prefix.
const EVENT_STREAM_BYTE_ARRAY_VALUE_TYPE: u8 = 6;

/// CRC-32 (IEEE, the algorithm the AWS event-stream framing specifies) of a
/// byte range, using the hardware-assisted implementation so verification stays
/// off the slow path for large messages.
fn event_stream_crc32(bytes: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn be_u32(bytes: &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// The reserved AWS event-stream headers this scanner needs in order to decide
/// whether a frame may mint usage. Non-reserved headers are walked (so the block
/// is fully validated) but not retained.
#[derive(Debug, Default)]
struct EventStreamHeaders<'a> {
    message_type: Option<&'a str>,
    event_type: Option<&'a str>,
    exception_type: Option<&'a str>,
}

impl EventStreamHeaders<'_> {
    /// Whether the frame declared any of the reserved headers at all.
    fn declares_reserved_vocabulary(&self) -> bool {
        self.message_type.is_some() || self.event_type.is_some() || self.exception_type.is_some()
    }

    /// Whether this frame's kind permits its payload to be read as an
    /// authoritative usage record.
    ///
    /// A frame that declares *none* of the reserved headers keeps the
    /// documented compatibility path: several supported provider variants frame
    /// a bare JSON payload without the Bedrock reserved header vocabulary at
    /// all, and refusing those would silently unmeter them.
    ///
    /// Once *any* reserved header is present the frame is speaking that
    /// vocabulary, and a partial declaration is ambiguous rather than
    /// permissive. Usage is then authoritative only for the fully specified,
    /// documented usage-bearing shape: `:message-type` exactly `event`,
    /// `:event-type` exactly `chunk` or `metadata`, and no `:exception-type`.
    /// A missing `:message-type` or missing `:event-type` therefore fails
    /// closed, as do exception, error, content, and unknown event kinds.
    fn may_carry_usage(&self) -> bool {
        if !self.declares_reserved_vocabulary() {
            return true;
        }
        if self.exception_type.is_some() {
            return false;
        }
        if self.message_type != Some(EVENT_STREAM_EVENT_MESSAGE_TYPE) {
            return false;
        }
        matches!(self.event_type, Some(kind) if USAGE_BEARING_EVENT_TYPES.contains(&kind))
    }

    /// Whether this frame is the `ConverseStream` accounting event.
    fn is_metadata_event(&self) -> bool {
        self.event_type == Some(EVENT_STREAM_METADATA_EVENT_TYPE)
    }
}

/// Whether a header name is one of the reserved headers whose value decides
/// whether the frame may mint usage.
fn is_reserved_header_name(name: &str) -> bool {
    matches!(
        name,
        EVENT_STREAM_MESSAGE_TYPE_HEADER
            | EVENT_STREAM_EVENT_TYPE_HEADER
            | EVENT_STREAM_EXCEPTION_TYPE_HEADER
    )
}

/// Walk one complete AWS event-stream header block, returning the reserved
/// headers it declared.
///
/// Returns `None` for any block that cannot be walked exactly to its end: a
/// zero-length or non-UTF-8 header name, an unknown value type (whose width is
/// unknown, so nothing after it can be located), a length that runs past the
/// block, a reserved header encoded with a non-`STRING` value type (its meaning
/// is then ambiguous, and silently ignoring it would let a partial declaration
/// mint usage), or a repeated reserved header. Every bound is checked, so a
/// hostile block can only fail closed.
fn parse_event_stream_headers(bytes: &[u8]) -> Option<EventStreamHeaders<'_>> {
    let mut headers = EventStreamHeaders::default();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let name_length = usize::from(*bytes.get(cursor)?);
        cursor = cursor.checked_add(1)?;
        if name_length == 0 {
            return None;
        }
        let name = bytes.get(cursor..cursor.checked_add(name_length)?)?;
        let name = std::str::from_utf8(name).ok()?;
        cursor = cursor.checked_add(name_length)?;

        let value_type = *bytes.get(cursor)?;
        cursor = cursor.checked_add(1)?;

        // Every reserved header is documented as a `STRING`. Encoded as a bool,
        // an integer, a byte array, a timestamp, or a UUID its value is not the
        // kind name this scanner has to compare against, so the frame's kind is
        // ambiguous. Failing closed here — rather than walking past it as if the
        // header were absent — is what stops a wrong-typed `:message-type` or
        // `:event-type` from falling through to the headerless compatibility
        // path and minting usage. It also settles the duplicate case for every
        // type and order: the first wrong-typed occurrence already refuses the
        // block, so a valid duplicate behind it can never be read.
        if is_reserved_header_name(name) && value_type != EVENT_STREAM_STRING_VALUE_TYPE {
            return None;
        }

        // Value widths are the documented AWS event-stream header value types:
        // 0/1 BOOL_TRUE/BOOL_FALSE (no bytes), 2 BYTE, 3 SHORT, 4 INTEGER,
        // 5 LONG, 6 BYTE_ARRAY, 7 STRING, 8 TIMESTAMP, 9 UUID.
        let fixed_width = match value_type {
            0 | 1 => 0usize,
            2 => 1,
            3 => 2,
            4 => 4,
            5 => 8,
            8 => 8,
            9 => 16,
            EVENT_STREAM_BYTE_ARRAY_VALUE_TYPE | EVENT_STREAM_STRING_VALUE_TYPE => {
                // Length-prefixed: a 16-bit big-endian length then the bytes.
                let declared = bytes.get(cursor..cursor.checked_add(2)?)?;
                let value_length = usize::from(u16::from_be_bytes([declared[0], declared[1]]));
                cursor = cursor.checked_add(2)?;
                let value = bytes.get(cursor..cursor.checked_add(value_length)?)?;
                cursor = cursor.checked_add(value_length)?;
                if value_type == EVENT_STREAM_STRING_VALUE_TYPE {
                    let slot = match name {
                        EVENT_STREAM_MESSAGE_TYPE_HEADER => Some(&mut headers.message_type),
                        EVENT_STREAM_EVENT_TYPE_HEADER => Some(&mut headers.event_type),
                        EVENT_STREAM_EXCEPTION_TYPE_HEADER => Some(&mut headers.exception_type),
                        _ => None,
                    };
                    if let Some(slot) = slot {
                        // A repeated reserved header makes the frame's kind
                        // ambiguous, so it is damaged framing.
                        if slot.is_some() {
                            return None;
                        }
                        *slot = Some(std::str::from_utf8(value).ok()?);
                    }
                }
                continue;
            }
            // An undefined value type has an unknown width, so nothing after it
            // can be located.
            _ => return None,
        };
        let value_end = cursor.checked_add(fixed_width)?;
        if value_end > bytes.len() {
            return None;
        }
        cursor = value_end;
    }
    Some(headers)
}

/// True for the AWS event-stream media type, ignoring parameters and case.
pub fn is_aws_event_stream_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|essence| essence.eq_ignore_ascii_case(AWS_EVENT_STREAM_CONTENT_TYPE))
}

/// Wire framing a [`StreamUsageScanner`] should decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamUsageFormat {
    /// `text/event-stream`.
    Sse,
    /// `application/vnd.amazon.eventstream` (AWS Bedrock).
    AwsEventStream,
}

impl StreamUsageFormat {
    /// Select a decoder for a response content type, or `None` when the
    /// representation carries no format this scanner can meter.
    pub fn for_content_type(content_type: &str) -> Option<Self> {
        if super::body_transform::is_event_stream_content_type(content_type) {
            return Some(Self::Sse);
        }
        if is_aws_event_stream_content_type(content_type) {
            return Some(Self::AwsEventStream);
        }
        None
    }
}

/// Incremental, bounded usage extractor for one streaming response.
///
/// Feed every chunk through [`Self::observe`] and call [`Self::finish`] once at
/// end of stream. The scanner is observational: it never holds back, rewrites,
/// or reorders bytes, and the caller forwards each chunk downstream unchanged.
#[derive(Debug)]
pub struct StreamUsageScanner {
    format: StreamUsageFormat,
    /// Operator-pinned provider, or `None` for `auto` detection.
    fixed_provider: Option<AiProvider>,
    /// Reassembly window. For SSE this is the current line; for the AWS framing
    /// it is the current message.
    buffer: Vec<u8>,
    /// SSE only: a `\r` was seen at the end of the previous chunk and its
    /// `\n` partner may open the next one.
    pending_cr: bool,
    /// SSE only: the current line already exceeded [`MAX_SSE_LINE_BYTES`] and
    /// its remaining bytes are being discarded up to the next newline.
    discarding_line: bool,
    /// Latest merged usage snapshot from explicit provider usage containers.
    usage: Option<AiTokenUsage>,
    /// Provider inferred from the first event that identified one, so later
    /// events of the same stream stay on one provider's field vocabulary.
    detected_provider: Option<AiProvider>,
    /// Set when framing/reassembly failed in a way that could have hidden a
    /// usage record. Fail-closed callers must not treat such a stream as a
    /// clean "provider reported nothing". Once set it is never cleared.
    malformed: bool,
    /// Set when a *candidate* record could not be decoded — a non-UTF-8 `data:`
    /// line, a data record that is not a JSON object, a truncated tail, or a
    /// usage-bearing AWS event frame whose payload (or `bytes` envelope's inner
    /// document) is not a decodable JSON object or whose usage container held no
    /// readable count.
    ///
    /// Unlike [`Self::malformed`] this is cleared by a later explicit
    /// authoritative usage record, because such a record restates the
    /// provider's complete cumulative counts. Damage that is still outstanding
    /// at end of stream is reported as malformed, so syntax damage *after* the
    /// last usage snapshot can never be settled as a clean terminal stream.
    damaged_since_usage: bool,
    /// Set once framing is unrecoverable; no further bytes are parsed.
    halted: bool,
}

impl StreamUsageScanner {
    /// Create a scanner for one response.
    ///
    /// `fixed_provider` pins extraction to the operator's configured provider;
    /// `None` selects per-event auto-detection.
    pub fn new(format: StreamUsageFormat, fixed_provider: Option<AiProvider>) -> Self {
        Self {
            format,
            fixed_provider,
            buffer: Vec::new(),
            pending_cr: false,
            discarding_line: false,
            usage: None,
            detected_provider: None,
            malformed: false,
            damaged_since_usage: false,
            halted: false,
        }
    }

    /// The authoritative usage snapshot, if the provider explicitly reported
    /// one.
    ///
    /// `None` covers every fail-closed case alike: no usage event, malformed or
    /// oversized framing, and a truncated tail.
    pub fn authoritative_usage(&self) -> Option<&AiTokenUsage> {
        self.usage.as_ref()
    }

    /// Whether framing was damaged, exceeded a bound, or left an undecodable
    /// candidate record outstanding after the last authoritative usage record.
    pub fn malformed(&self) -> bool {
        self.malformed || self.damaged_since_usage
    }

    /// Observe the next chunk of response bytes. The chunk is not retained.
    pub fn observe(&mut self, chunk: &[u8]) {
        if self.halted {
            return;
        }
        match self.format {
            StreamUsageFormat::Sse => self.observe_sse(chunk),
            StreamUsageFormat::AwsEventStream => self.observe_event_stream(chunk),
        }
    }

    /// Flush any complete trailing record at end of stream.
    ///
    /// A trailing SSE line with no terminating newline is still a complete
    /// record for line-oriented providers, so it is parsed. A partially
    /// received AWS message is *not* completable and marks the stream
    /// malformed, so a truncated stream can never present as usage-free.
    pub fn finish(&mut self) {
        if self.halted {
            return;
        }
        match self.format {
            StreamUsageFormat::Sse => {
                if !self.discarding_line && !self.buffer.is_empty() {
                    let line = std::mem::take(&mut self.buffer);
                    self.consume_sse_line(&line);
                    self.buffer = line;
                    self.buffer.clear();
                }
                self.discarding_line = false;
                self.pending_cr = false;
            }
            StreamUsageFormat::AwsEventStream => {
                if !self.buffer.is_empty() {
                    // Bytes remain that never formed a complete message.
                    self.malformed = true;
                }
            }
        }
        self.buffer = Vec::new();
    }

    // ---- SSE ------------------------------------------------------------

    fn observe_sse(&mut self, chunk: &[u8]) {
        for &byte in chunk {
            if self.pending_cr {
                self.pending_cr = false;
                self.end_sse_line();
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.pending_cr = true,
                b'\n' => self.end_sse_line(),
                _ => {
                    if self.discarding_line {
                        continue;
                    }
                    if self.buffer.len() >= MAX_SSE_LINE_BYTES {
                        // An event this large is not a provider usage record.
                        // Drop the rest of the line but remember that some
                        // content was not inspectable.
                        self.buffer.clear();
                        self.discarding_line = true;
                        self.malformed = true;
                        continue;
                    }
                    self.buffer.push(byte);
                }
            }
        }
    }

    fn end_sse_line(&mut self) {
        if self.discarding_line {
            self.discarding_line = false;
            self.buffer.clear();
            return;
        }
        // Reuse the allocation across lines: take the buffer, parse, then put
        // the (cleared) allocation back so a long stream performs no per-line
        // allocation.
        let line = std::mem::take(&mut self.buffer);
        self.consume_sse_line(&line);
        self.buffer = line;
        self.buffer.clear();
    }

    fn consume_sse_line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else {
            // `text/event-stream` is UTF-8 by definition. A `data:` line that
            // is not is a candidate record this scanner cannot decode, so it
            // damages the scan rather than being silently skipped — the usage
            // event it would have carried is now unaccounted for. Bytes on any
            // other line are not a candidate at all, and every byte still
            // reaches the client unchanged either way.
            if line.starts_with(b"data:") {
                self.damaged_since_usage = true;
            }
            return;
        };
        let Some(rest) = text.strip_prefix("data:") else {
            // Comments (`: keep-alive`), `event:`, `id:`, `retry:`, blank event
            // separators, and any other SSE field are not usage candidates.
            return;
        };
        let data = rest.trim();
        if data.is_empty() || data == "[DONE]" {
            // An empty data record and the OpenAI sentinel are ordinary,
            // well-formed stream syntax.
            return;
        }
        let Ok(json) = serde_json::from_str::<Value>(data) else {
            // A non-empty data record that is not JSON is either damaged or
            // truncated. Either way it could have been the terminal usage
            // event, so the stream is no longer provably clean.
            self.damaged_since_usage = true;
            return;
        };
        if !json.is_object() {
            // Every supported provider stream event is a JSON object. A scalar
            // or array is not the provider event shape this scanner decodes.
            self.damaged_since_usage = true;
            return;
        }
        self.consume_event_json(&json);
    }

    /// Extract usage from one decoded stream event, across every supported
    /// provider event shape.
    fn consume_event_json(&mut self, json: &Value) {
        // Anthropic reports the prompt count inside `message_start`'s nested
        // `message` object and the completion count on the flat `message_delta`
        // event; OpenAI Responses reports on `response.completed`'s nested
        // `response`. Unwrap those envelopes exactly as the buffered extractor
        // does so both paths agree.
        let event_type = json.get("type").and_then(Value::as_str);
        let payload = match event_type {
            Some("response.completed") => match json.get("response") {
                Some(response) => response,
                None => return,
            },
            // Other `response.*` events (failed/incomplete/in-progress) are not
            // usage authorities.
            Some(kind) if kind.starts_with("response.") => return,
            Some("message_start") => json.get("message").unwrap_or(json),
            _ => json,
        };

        let Some(provider) = self
            .fixed_provider
            .or_else(|| detect_sse_provider(payload))
            .or(self.detected_provider)
        else {
            return;
        };
        self.detected_provider.get_or_insert(provider);

        let extracted = extract_response_usage(payload, provider);
        self.merge(extracted);
    }

    /// Record one extracted usage snapshot, returning whether it was an
    /// authoritative cumulative usage record (and therefore cleared outstanding
    /// candidate damage).
    fn merge(&mut self, extracted: AiTokenUsage) -> bool {
        if extracted.prompt_tokens.is_none()
            && extracted.completion_tokens.is_none()
            && extracted.total_tokens.is_none()
        {
            // Not a usage-bearing event. Never record an authoritative
            // snapshot for it.
            return false;
        }
        match &mut self.usage {
            Some(current) => current.merge_cumulative(extracted),
            None => self.usage = Some(extracted),
        }
        // An explicit authoritative usage record supersedes earlier candidate
        // damage: supported providers report cumulative counts, so this record
        // restates everything a skipped record could have carried. Damage that
        // arrives *after* this point is never cleared.
        self.damaged_since_usage = false;
        true
    }

    // ---- AWS event stream ----------------------------------------------

    fn observe_event_stream(&mut self, chunk: &[u8]) {
        let mut remaining = chunk;
        while !remaining.is_empty() {
            // Fill the prelude first so the declared total length is known
            // before any capacity is committed to the message body.
            if self.buffer.len() < EVENT_STREAM_PRELUDE_BYTES {
                let want = EVENT_STREAM_PRELUDE_BYTES - self.buffer.len();
                let take = want.min(remaining.len());
                self.buffer.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
                if self.buffer.len() < EVENT_STREAM_PRELUDE_BYTES {
                    return;
                }
            }

            let Some(total_length) = self.declared_message_length() else {
                self.halt_malformed();
                return;
            };

            if self.buffer.len() < total_length {
                let want = total_length - self.buffer.len();
                let take = want.min(remaining.len());
                self.buffer.extend_from_slice(&remaining[..take]);
                remaining = &remaining[take..];
                if self.buffer.len() < total_length {
                    return;
                }
            }

            let message = std::mem::take(&mut self.buffer);
            self.consume_event_stream_message(&message, total_length);
            if self.halted {
                return;
            }
            self.buffer = message;
            self.buffer.clear();
        }
    }

    /// Validate and return the declared total message length from a buffered
    /// prelude, or `None` when the framing is unusable.
    ///
    /// The prelude CRC-32 is verified here — before the declared length is
    /// honored — so a corrupted or forged length can never drive reassembly.
    fn declared_message_length(&self) -> Option<usize> {
        let total_length = be_u32(self.buffer.get(..4)?)? as usize;
        let headers_length = be_u32(self.buffer.get(4..8)?)? as usize;
        let declared_crc = be_u32(self.buffer.get(8..EVENT_STREAM_PRELUDE_BYTES)?)?;

        // The prelude checksum covers exactly the two length fields.
        let checked = self.buffer.get(..EVENT_STREAM_PRELUDE_CHECKED_BYTES)?;
        if event_stream_crc32(checked) != declared_crc {
            return None;
        }

        // A message must at least cover its own framing, must fit the retained
        // bound, and its headers must fit inside it. Any violation means the
        // byte stream is not the framing it claims to be.
        if total_length < EVENT_STREAM_OVERHEAD_BYTES
            || total_length > MAX_EVENT_STREAM_MESSAGE_BYTES
            || headers_length > total_length.saturating_sub(EVENT_STREAM_OVERHEAD_BYTES)
        {
            return None;
        }
        Some(total_length)
    }

    fn halt_malformed(&mut self) {
        self.malformed = true;
        self.halted = true;
        self.buffer = Vec::new();
    }

    fn consume_event_stream_message(&mut self, message: &[u8], total_length: usize) {
        // The message CRC-32 covers everything from the first prelude byte up to
        // (but excluding) the checksum itself. Verify it before reading headers
        // or payload: without it nothing in this frame is trustworthy, and the
        // HTTP transport does not check application framing.
        let checked_end = total_length.saturating_sub(EVENT_STREAM_CRC_BYTES);
        let Some(checked) = message.get(..checked_end) else {
            self.halt_malformed();
            return;
        };
        let Some(declared_crc) = message.get(checked_end..total_length).and_then(be_u32) else {
            self.halt_malformed();
            return;
        };
        if event_stream_crc32(checked) != declared_crc {
            self.halt_malformed();
            return;
        }

        let Some(headers_length) = message.get(4..8).and_then(be_u32) else {
            self.halt_malformed();
            return;
        };
        let payload_start = EVENT_STREAM_PRELUDE_BYTES.saturating_add(headers_length as usize);
        if payload_start > checked_end {
            self.halt_malformed();
            return;
        }
        let Some(header_block) = message.get(EVENT_STREAM_PRELUDE_BYTES..payload_start) else {
            self.halt_malformed();
            return;
        };
        let Some(payload) = message.get(payload_start..checked_end) else {
            self.halt_malformed();
            return;
        };

        // A header block that cannot be walked exactly to its end is damaged
        // framing, not merely an unrecognized frame: the payload boundary the
        // prelude declared is no longer corroborated by anything.
        let Some(headers) = parse_event_stream_headers(header_block) else {
            self.halt_malformed();
            return;
        };
        if !headers.may_carry_usage() {
            // A well-framed exception/error frame, a content event
            // (`messageStart`, `contentBlockDelta`, …), an unknown event kind,
            // or an incomplete reserved-header declaration. Framing is intact,
            // so keep scanning, but nothing here may mint authoritative usage
            // and nothing here is a usage candidate that could have been
            // damaged.
            return;
        }

        // This frame's headers say it is one of the two usage-bearing kinds (or
        // it is the headerless compatibility shape), so its payload IS a usage
        // candidate. A payload that cannot be decoded is therefore exactly the
        // ordering-sensitive damage the SSE path already models: it may have
        // been the provider's terminal restatement, so any older snapshot stops
        // being settleable until a later valid authoritative record recovers it.
        let outcome = if payload.is_empty() {
            EventPayloadOutcome::Damaged
        } else {
            match serde_json::from_slice::<Value>(payload) {
                // Every supported provider event is a JSON object.
                Ok(json) if json.is_object() => self.consume_bedrock_payload(&json, true),
                Ok(_) | Err(_) => EventPayloadOutcome::Damaged,
            }
        };

        match outcome {
            // `merge` already cleared any outstanding damage.
            EventPayloadOutcome::Usage => {}
            // An ordinary `chunk` carrying model content and no usage container
            // is the normal case for `InvokeModelWithResponseStream` and is not
            // damage. A `metadata` event exists to report usage, so one that
            // reported none is a candidate this scanner could not read.
            EventPayloadOutcome::Content => {
                if headers.is_metadata_event() {
                    self.damaged_since_usage = true;
                }
            }
            EventPayloadOutcome::Damaged => self.damaged_since_usage = true,
        }
    }

    /// Extract Bedrock usage from one decoded event payload.
    ///
    /// `InvokeModelWithResponseStream` wraps each model chunk as
    /// `{"bytes":"<base64>"}`; the inner document carries
    /// `amazon-bedrock-invocationMetrics` on the terminal chunk. `ConverseStream`
    /// instead emits a `metadata` event whose payload carries `usage` directly.
    /// `unwrap_envelope` is false on the recursive call so a hostile payload
    /// cannot drive unbounded nesting.
    ///
    /// The returned [`EventPayloadOutcome`] tells the frame layer whether this
    /// payload produced an authoritative record, was ordinary provider content,
    /// or was a candidate the scanner could not read.
    fn consume_bedrock_payload(
        &mut self,
        json: &Value,
        unwrap_envelope: bool,
    ) -> EventPayloadOutcome {
        let mut recorded_usage = false;
        let mut damaged = false;

        let metrics = json.get("amazon-bedrock-invocationMetrics");
        if let Some(metrics) = metrics {
            let prompt = metrics.get("inputTokenCount").and_then(Value::as_u64);
            let completion = metrics.get("outputTokenCount").and_then(Value::as_u64);
            // An explicit metrics container whose fields are absent, negative,
            // fractional, or otherwise not readable as counts is ambiguous, not
            // content: it is the terminal accounting record, unreadable.
            if self.merge(AiTokenUsage {
                prompt_tokens: prompt,
                completion_tokens: completion,
                total_tokens: match (prompt, completion) {
                    (Some(prompt), Some(completion)) => prompt.checked_add(completion),
                    _ => None,
                },
                model: None,
                // Deliberately unlabelled: see `consume_bedrock_payload`'s note
                // on why event-stream snapshots carry no provider tag.
                provider: None,
            }) {
                recorded_usage = true;
            } else {
                damaged = true;
            }
        }

        // ConverseStream `metadata` events, and any other payload carrying a
        // recognizable usage container, go through the shared extractor.
        //
        // The resulting snapshot is deliberately stripped of its provider tag.
        // One Bedrock stream legitimately mixes vocabularies — the outer
        // envelope is Bedrock while the inner model document can be an
        // Anthropic `message_start` / `message_delta` pair — and
        // `AiTokenUsage::merge_cumulative` refuses to merge two snapshots whose
        // providers disagree. Keeping the tag would therefore silently discard
        // the terminal `amazon-bedrock-invocationMetrics` for exactly the
        // provider combination Bedrock is most often used with. The counts are
        // what this scanner exists to report; the tag is not consumed by the
        // caller's `count_mode` resolution.
        let provider = self
            .fixed_provider
            .or_else(|| detect_sse_provider(json))
            .or(self.detected_provider)
            .unwrap_or(AiProvider::Bedrock);
        self.detected_provider.get_or_insert(provider);
        let mut extracted = extract_response_usage(json, provider);
        extracted.provider = None;
        if self.merge(extracted) {
            recorded_usage = true;
        } else if metrics.is_none() && declares_usage_container(json) {
            // A usage-shaped payload whose container produced no readable count
            // is a usage record this scanner could not decode. (Skipped when an
            // `amazon-bedrock-invocationMetrics` container was present, because
            // that container was already judged above and a valid one must not
            // be second-guessed by an unrelated vocabulary.)
            damaged = true;
        }

        if !unwrap_envelope {
            return EventPayloadOutcome::resolve(recorded_usage, damaged);
        }
        let Some(encoded) = json.get("bytes").and_then(Value::as_str) else {
            return EventPayloadOutcome::resolve(recorded_usage, damaged);
        };
        // An oversized or non-base64 envelope is framing this scanner cannot
        // reconstruct at all, so it stays a hard malformed scan rather than
        // ordering-sensitive damage.
        if encoded.len() > MAX_EVENT_STREAM_MESSAGE_BYTES {
            self.malformed = true;
            return EventPayloadOutcome::Damaged;
        }
        use base64::Engine as _;
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            // An undecodable envelope could have carried the terminal metrics.
            self.malformed = true;
            return EventPayloadOutcome::Damaged;
        };
        // The envelope decoded, so its contents WERE a usage candidate. Inner
        // bytes that are not a JSON object are a candidate record this scanner
        // could not read — ordering-sensitive damage, not a silent skip.
        match serde_json::from_slice::<Value>(&decoded) {
            Ok(inner) if inner.is_object() => match self.consume_bedrock_payload(&inner, false) {
                EventPayloadOutcome::Usage => recorded_usage = true,
                EventPayloadOutcome::Damaged => damaged = true,
                EventPayloadOutcome::Content => {}
            },
            Ok(_) | Err(_) => damaged = true,
        }
        EventPayloadOutcome::resolve(recorded_usage, damaged)
    }
}

/// How one decoded AWS event payload settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventPayloadOutcome {
    /// An authoritative usage record was extracted.
    Usage,
    /// Ordinary provider content that declared no usage container.
    Content,
    /// A usage candidate the scanner could not decode, or a usage container
    /// whose fields could not be read as counts.
    Damaged,
}

impl EventPayloadOutcome {
    /// Damage wins over a usage record found in the same payload: if one
    /// container of a frame was unreadable, the frame cannot prove it restated
    /// everything the provider reported.
    fn resolve(recorded_usage: bool, damaged: bool) -> Self {
        match (damaged, recorded_usage) {
            (true, _) => Self::Damaged,
            (false, true) => Self::Usage,
            (false, false) => Self::Content,
        }
    }
}

/// Whether a decoded payload declares an explicit provider usage container.
///
/// This distinguishes ordinary provider content — a model text delta, a
/// `messageStop`, an envelope with nothing else in it — from a record that
/// announced usage but whose fields could not be read as counts. Only the
/// latter is damage.
fn declares_usage_container(json: &Value) -> bool {
    json.get("usage").is_some()
        || json.get("usageMetadata").is_some()
        || json.get("inputTextTokenCount").is_some()
        || json
            .get("meta")
            .and_then(|meta| meta.get("tokens"))
            .is_some()
}

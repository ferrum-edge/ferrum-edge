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
//! exactly once instead of silently charging zero.

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

/// The documented Bedrock streaming media type.
const AWS_EVENT_STREAM_CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";

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
    /// clean "provider reported nothing".
    malformed: bool,
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

    /// Whether framing was damaged or exceeded a bound while scanning.
    pub fn malformed(&self) -> bool {
        self.malformed
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
        let Ok(line) = std::str::from_utf8(line) else {
            // Non-UTF-8 in a text/event-stream line cannot be a provider usage
            // record; the bytes still reach the client unchanged.
            return;
        };
        let data = if let Some(rest) = line.strip_prefix("data:") {
            rest.trim()
        } else {
            return;
        };
        if data.is_empty() || data == "[DONE]" {
            return;
        }
        let Ok(json) = serde_json::from_str::<Value>(data) else {
            return;
        };
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

    fn merge(&mut self, extracted: AiTokenUsage) {
        if extracted.prompt_tokens.is_none()
            && extracted.completion_tokens.is_none()
            && extracted.total_tokens.is_none()
        {
            // Not a usage-bearing event. Never record an authoritative
            // snapshot for it.
            return;
        }
        match &mut self.usage {
            Some(current) => current.merge_cumulative(extracted),
            None => self.usage = Some(extracted),
        }
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
    fn declared_message_length(&self) -> Option<usize> {
        let total_length = u32::from_be_bytes([
            *self.buffer.first()?,
            *self.buffer.get(1)?,
            *self.buffer.get(2)?,
            *self.buffer.get(3)?,
        ]) as usize;
        let headers_length = u32::from_be_bytes([
            *self.buffer.get(4)?,
            *self.buffer.get(5)?,
            *self.buffer.get(6)?,
            *self.buffer.get(7)?,
        ]) as usize;

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
        let headers_length = match message.get(4..8) {
            Some(bytes) => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize,
            None => {
                self.halt_malformed();
                return;
            }
        };
        let payload_start = EVENT_STREAM_PRELUDE_BYTES.saturating_add(headers_length);
        let payload_end = total_length.saturating_sub(4);
        if payload_start > payload_end {
            self.halt_malformed();
            return;
        }
        let Some(payload) = message.get(payload_start..payload_end) else {
            self.halt_malformed();
            return;
        };
        if payload.is_empty() {
            return;
        }
        let Ok(json) = serde_json::from_slice::<Value>(payload) else {
            // A non-JSON payload (for example a raw content chunk) is simply
            // not a usage record. Framing is still intact, so keep scanning.
            return;
        };
        self.consume_bedrock_payload(&json, true);
    }

    /// Extract Bedrock usage from one decoded event payload.
    ///
    /// `InvokeModelWithResponseStream` wraps each model chunk as
    /// `{"bytes":"<base64>"}`; the inner document carries
    /// `amazon-bedrock-invocationMetrics` on the terminal chunk. `ConverseStream`
    /// instead emits a `metadata` event whose payload carries `usage` directly.
    /// `unwrap_envelope` is false on the recursive call so a hostile payload
    /// cannot drive unbounded nesting.
    fn consume_bedrock_payload(&mut self, json: &Value, unwrap_envelope: bool) {
        if let Some(metrics) = json.get("amazon-bedrock-invocationMetrics") {
            let prompt = metrics.get("inputTokenCount").and_then(Value::as_u64);
            let completion = metrics.get("outputTokenCount").and_then(Value::as_u64);
            self.merge(AiTokenUsage {
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
            });
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
        self.merge(extracted);

        if !unwrap_envelope {
            return;
        }
        let Some(encoded) = json.get("bytes").and_then(Value::as_str) else {
            return;
        };
        if encoded.len() > MAX_EVENT_STREAM_MESSAGE_BYTES {
            self.malformed = true;
            return;
        }
        use base64::Engine as _;
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            // An undecodable envelope could have carried the terminal metrics.
            self.malformed = true;
            return;
        };
        let Ok(inner) = serde_json::from_slice::<Value>(&decoded) else {
            return;
        };
        self.consume_bedrock_payload(&inner, false);
    }
}
